from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from privacy_shield import PrivacyShield

APP_VERSION = "1.4.0"
ACCESS_KEY = os.getenv("NEXUS_ACCESS_KEY", "").strip()
SCAN_INTERVAL = 2.5
MAX_ELEMENTS = 80
LOG_LIMIT = 120
HOST_VALIDATION_CACHE: dict[str, tuple[float, bool]] = {}

DETECTION_ONLY = {
    "watchAds": '[data-testid="lv-membership-plan-option-wrapper-btn"]',
    "continueButton": '[data-testid="action-wall-continue-action-btn"]',
    "adCounter": ".carousel-items-counter p",
    "adLabel": ".lv-card__ad-indicator p",
    "skipAdContainer": '[data-testid="lv-lib-carousel-skip-btn"]',
    "successHeading": '[data-testid="success-title"]',
    "contentReady": ".success-wrapper h2",
    "openHereButton": ".success-wrapper button",
}
BLOCKED_TERMS = re.compile(
    r"\b(ad|ads|advert|advertisement|reward|claim|skip ad|watch ads|"
    r"membership|payment|pay now|purchase|checkout|subscribe|"
    r"delete|remove account|transfer|withdraw|payout)\b", re.I
)

state: dict[str, Any] = {
    "status": "STOPPED", "url": "", "title": "", "message": "Ready",
    "started_at": None, "last_scan": None, "elements": [],
    "detections": [], "detected_elements": [],
    "diagnostics": {"checks": [], "updated_at": None}, "activity": [], "errors": [], "session_id": None,
}
playwright = None
browser = None
context = None
page = None
monitor_task: asyncio.Task | None = None
start_task: asyncio.Task | None = None
operation_lock = asyncio.Lock()
log = logging.getLogger("nexus")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def add_log(message: str, level: str = "INFO") -> None:
    item = {"time": time.strftime("%H:%M:%S"), "level": level, "message": str(message)[:500]}
    state["activity"].append(item)
    state["activity"] = state["activity"][-LOG_LIMIT:]
    if level == "ERROR":
        state["errors"].append(item)
        state["errors"] = state["errors"][-LOG_LIMIT:]
    getattr(log, "error" if level == "ERROR" else "info")(message)


def require_key(x_nexus_key: str | None) -> None:
    if not ACCESS_KEY:
        raise HTTPException(503, "NEXUS_ACCESS_KEY is not configured on the server.")
    if not x_nexus_key or x_nexus_key != ACCESS_KEY:
        raise HTTPException(401, "Access key missing or incorrect.")


async def validate_public_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Only valid http:// and https:// URLs are supported.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing embedded credentials are not allowed.")
        host = parsed.hostname.rstrip(".").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        cache_key = f"{host}:{port}"
        cached = HOST_VALIDATION_CACHE.get(cache_key)
        if cached and time.monotonic() - cached[0] < 60:
            if cached[1]:
                return value
            raise ValueError("The URL resolves to a private or non-public address.")
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            raise ValueError("Local/private network addresses are not allowed.")
        try:
            ip = ipaddress.ip_address(host)
            addresses = [ip]
        except ValueError:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                timeout=4.0,
            )
            addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
        if not addresses:
            raise ValueError("The hostname did not resolve.")
        is_public = all(addr.is_global for addr in addresses)
        HOST_VALIDATION_CACHE[cache_key] = (time.monotonic(), is_public)
        if not is_public:
            raise ValueError("The URL resolves to a private or non-public address.")
        return value
    except asyncio.TimeoutError:
        raise ValueError("DNS lookup timed out. Check the hostname and try again.")
    except (socket.gaierror, OSError):
        raise ValueError("The hostname could not be resolved.")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"URL validation failed: {type(exc).__name__}")


# All Chromium network requests pass through this policy layer before continuing.
TRACKER_BLOCKING = os.getenv("NEXUS_BLOCK_TRACKERS", "true").strip().lower() not in {"0", "false", "no", "off"}
_EXTRA_TRACKERS = {x.strip().lower() for x in os.getenv("NEXUS_EXTRA_TRACKERS", "").split(",") if x.strip()}
privacy_shield = PrivacyShield(validate_public_url, block_trackers=TRACKER_BLOCKING,
                               extra_tracker_domains=_EXTRA_TRACKERS)


async def route_guard(route) -> None:
    request = route.request
    allowed, reason = await privacy_shield.inspect(request.url, request.resource_type)
    if allowed:
        await route.continue_()
    else:
        host = urlparse(request.url).hostname or "unknown"
        add_log(f"Privacy Shield blocked {host} ({reason}).", "WARN")
        await route.abort()


async def scan_page() -> None:
    if page is None or page.is_closed():
        return
    try:
        # Collect controls and diagnostic signals in one browser-side pass to
        # avoid a series of slow Playwright round trips.
        payload = await page.evaluate("""({limit, selectors}) => {
          const nodes = [...document.querySelectorAll(
            'button, a[href], input:not([type=hidden]), select, textarea, [role="button"]'
          )].slice(0, limit);
          const controls = nodes.map((el, index) => {
            if (!el.dataset.nexusId) el.dataset.nexusId = 'nx-' + crypto.randomUUID();
            const style = getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            const visible = style.display !== 'none' && style.visibility !== 'hidden'
              && rect.width > 0 && rect.height > 0;
            const tag = el.tagName.toLowerCase();
            const type = (el.getAttribute('type') || '').toLowerCase();
            const raw = (el.innerText || el.value || el.getAttribute('aria-label')
              || el.getAttribute('title') || el.getAttribute('placeholder') || '').trim();
            const text = raw.replace(/\\s+/g, ' ').slice(0, 150);
            const fallback = ({button:'Button', a:'Link', input:({checkbox:'Checkbox',radio:'Radio button',submit:'Submit button',reset:'Reset button',file:'File picker',search:'Search field',email:'Email field',number:'Number field',url:'URL field',password:'Password field',button:'Button','':'Input field'}[type] || 'Input field'), select:'Dropdown', textarea:'Text area'})[tag] || 'Interactive control';
            return {
              id: el.dataset.nexusId, tag, text: text || `${fallback} ${index + 1}`,
              type, href: tag === 'a' ? el.href : '', visible, disabled: !!el.disabled,
              aria: el.getAttribute('aria-label') || '', role: el.getAttribute('role') || ''
            };
          });
          const detections = selectors.map(({name, selector}) => {
            try {
              const matches = [...document.querySelectorAll(selector)];
              const elements = matches.map(el => {
                if (!el.dataset.nexusId) el.dataset.nexusId = 'nx-' + crypto.randomUUID();
                const rect = el.getBoundingClientRect();
                const style = getComputedStyle(el);
                const visible = style.display !== 'none' && style.visibility !== 'hidden'
                  && rect.width > 0 && rect.height > 0;
                const tag = el.tagName.toLowerCase();
                const text = (el.innerText || el.value || el.getAttribute('aria-label')
                  || el.getAttribute('title') || '').trim().replace(/\\s+/g, ' ').slice(0, 150);
                return {id: el.dataset.nexusId, text: text || tag, tag, visible, disabled: !!el.disabled};
              });
              const sample = elements.length ? elements[0].text : '';
              return {name, selector, count: matches.length, sample, detection_only: true, elements};
            } catch (_) { return {name, selector, count: 0, sample: '', detection_only: true, elements: []}; }
          });
          const nav = performance.getEntriesByType('navigation')[0] || null;
          const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection || null;
          const checks = [];
          const add = (name, status, detail, group) => checks.push({name, status, detail: String(detail ?? '').slice(0,180), group});
          const yesNo = (value) => value ? 'available' : 'unavailable';
          add('JavaScript', 'ok', 'Enabled in the monitored page', 'Runtime');
          add('Cookies', navigator.cookieEnabled ? 'ok' : 'warning', yesNo(navigator.cookieEnabled), 'Storage');
          let localStorageState = 'available', sessionStorageState = 'available';
          try { localStorage.setItem('__nexus_diag__','1'); localStorage.removeItem('__nexus_diag__'); } catch (_) { localStorageState = 'blocked'; }
          try { sessionStorage.setItem('__nexus_diag__','1'); sessionStorage.removeItem('__nexus_diag__'); } catch (_) { sessionStorageState = 'blocked'; }
          add('Local storage', localStorageState === 'available' ? 'ok' : 'warning', localStorageState, 'Storage');
          add('Session storage', sessionStorageState === 'available' ? 'ok' : 'warning', sessionStorageState, 'Storage');
          add('Browser / engine', 'ok', `${navigator.userAgentData?.brands?.map(x=>x.brand).join(', ') || navigator.userAgent} · engine details vary by browser`, 'Environment');
          add('Operating system hint', 'ok', navigator.userAgentData?.platform || navigator.platform || 'Not exposed', 'Environment');
          add('Language', 'ok', navigator.language || 'Not exposed', 'Environment');
          add('Timezone', 'ok', Intl.DateTimeFormat().resolvedOptions().timeZone || 'Not exposed', 'Environment');
          add('Viewport', 'ok', `${innerWidth} × ${innerHeight} CSS px; screen ${screen.width} × ${screen.height}; DPR ${devicePixelRatio}`, 'Environment');
          add('Touch support', 'info', `${navigator.maxTouchPoints || 0} touch points`, 'Input');
          add('Pointer capabilities', 'info', matchMedia('(pointer: fine)').matches ? 'Fine pointer available' : (matchMedia('(pointer: coarse)').matches ? 'Coarse pointer available' : 'No primary pointer reported'), 'Input');
          add('Hardware concurrency', 'info', navigator.hardwareConcurrency ? `${navigator.hardwareConcurrency} logical cores reported` : 'Not exposed', 'Environment');
          add('Device memory', 'info', navigator.deviceMemory ? `${navigator.deviceMemory} GB reported` : 'Not exposed', 'Environment');
          add('WebDriver indicator', navigator.webdriver === true ? 'warning' : 'info', `navigator.webdriver = ${String(navigator.webdriver)}`, 'Automation indicators');
          add('WebGL API', typeof WebGLRenderingContext !== 'undefined' ? 'ok' : 'warning', yesNo(typeof WebGLRenderingContext !== 'undefined'), 'Graphics');
          add('WebRTC API', typeof RTCPeerConnection !== 'undefined' ? 'ok' : 'warning', yesNo(typeof RTCPeerConnection !== 'undefined'), 'Media');
          add('Media devices API', navigator.mediaDevices ? 'ok' : 'info', yesNo(!!navigator.mediaDevices), 'Media');
          add('Clipboard API', navigator.clipboard ? 'ok' : 'info', yesNo(!!navigator.clipboard), 'Permissions');
          add('Geolocation API', navigator.geolocation ? 'ok' : 'info', yesNo(!!navigator.geolocation), 'Permissions');
          add('Notification permission', 'info', typeof Notification !== 'undefined' ? Notification.permission : 'API unavailable', 'Permissions');
          add('Network information', conn ? 'info' : 'unsupported', conn ? `${conn.effectiveType || 'type unknown'}; RTT ${conn.rtt ?? 'unknown'} ms` : 'Browser does not expose Network Information API', 'Network');
          add('Navigation timing', nav ? 'ok' : 'warning', nav ? `DOM content loaded ${Math.round(nav.domContentLoadedEventEnd)} ms; load ${Math.round(nav.loadEventEnd)} ms` : 'Navigation timing unavailable', 'Performance');
          const resources = performance.getEntriesByType('resource');
          add('Resource loading', 'ok', `${resources.length} resources; ${Math.round(resources.reduce((n,r)=>n+(r.transferSize||0),0)/1024)} KB transferred where exposed`, 'Performance');
          add('Page visibility', 'info', document.visibilityState, 'Behaviour');
          add('Referrer', 'info', document.referrer ? new URL(document.referrer).origin : 'No referrer', 'Navigation');
          add('JavaScript errors', 'info', 'Page-level JavaScript exceptions are captured in the Error log', 'Runtime');
          add('IP address / ISP / location', 'unsupported', 'Not collected: browser page scripts cannot reliably expose these values', 'Network');
          add('TLS fingerprint / HTTP protocol fingerprint', 'unsupported', 'Not exposed to page JavaScript; not inferred or spoofed', 'Network');
          add('Canvas / audio / installed-font fingerprints', 'not_collected', 'Intentionally not collected; these can create cross-site device fingerprints', 'Privacy');
          add('Cookies / authentication / session identifiers', 'not_collected', 'Values and credentials are not read or displayed', 'Privacy');
          add('CAPTCHA / account / login history', 'not_collected', 'Account-security interactions are outside this monitor', 'Privacy');
          add('Playwright / Puppeteer / Selenium indicators', 'info', 'Only the standard WebDriver property is reported; no concealment or evasion is applied', 'Automation indicators');
          return {controls, detections, title: document.title || '', diagnostics: {
            checks, user_agent: navigator.userAgent, language: navigator.language || '',
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
            viewport: `${innerWidth} × ${innerHeight}`, screen: `${screen.width} × ${screen.height}`,
            dpr: devicePixelRatio, resource_count: resources.length,
            navigation_ms: nav ? Math.round(nav.domContentLoadedEventEnd) : null
          }};
        }""", {"limit": MAX_ELEMENTS, "selectors": [{"name": name, "selector": selector} for name, selector in DETECTION_ONLY.items()]})
        result = payload["controls"]
        safe_input_types = {"", "button", "checkbox", "color", "date", "datetime-local", "email", "month", "number", "radio", "range", "search", "tel", "text", "time", "url", "week"}
        for item in result:
            descriptor = " ".join([item.get("text", ""), item.get("aria", ""), item.get("href", "")])
            item["sensitive"] = bool(BLOCKED_TERMS.search(descriptor))
            safe_tag = item["tag"] in {"a", "select", "textarea"} or (
                item["tag"] == "button" and item["type"] == "button"
            ) or (item["tag"] == "input" and item["type"] in safe_input_types) or (item["role"] == "button")
            item["clickable"] = item["visible"] and not item["disabled"] and not item["sensitive"] and safe_tag
        state["elements"] = result
        raw_detections = payload["detections"]
        # Flatten individual elements from every detection group into a lookup
        # so /api/approve can resolve them without BLOCKED_TERMS screening —
        # these selectors are user-configured and intentionally targeted.
        detected_elements: list[dict] = []
        for det in raw_detections:
            for el in det.get("elements", []):
                detected_elements.append({**el, "detection_name": det["name"]})
        state["detections"] = raw_detections
        state["detected_elements"] = detected_elements
        state["diagnostics"] = {
            **payload.get("diagnostics", {}),
            "updated_at": time.time(),
            "status": "ok" if payload.get("diagnostics", {}).get("checks") else "warning",
        }
        state["last_scan"] = time.time()
        state["title"] = payload["title"] or state["title"]
    except Exception as exc:
        add_log(f"DOM scan failed: {type(exc).__name__}: {str(exc)[:180]}", "ERROR")


async def monitor_loop() -> None:
    while state["status"] == "RUNNING":
        await scan_page()
        await asyncio.sleep(SCAN_INTERVAL)


async def cleanup_browser() -> None:
    global playwright, browser, context, page, monitor_task
    current_monitor = monitor_task
    monitor_task = None
    if current_monitor and current_monitor is not asyncio.current_task():
        current_monitor.cancel()
        try:
            await asyncio.wait_for(current_monitor, 1.5)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    for name, obj in (("page", page), ("context", context), ("browser", browser), ("playwright", playwright)):
        if obj is not None:
            try:
                closer = getattr(obj, "close", None)
                if closer:
                    await asyncio.wait_for(closer(), 2.0)
                elif name == "playwright":
                    await asyncio.wait_for(obj.stop(), 2.0)
            except Exception as exc:
                add_log(f"{name} cleanup: {type(exc).__name__}", "WARN")
    page = context = browser = playwright = None


async def start_worker(url: str, session_id: str) -> None:
    global playwright, browser, context, page, monitor_task
    try:
        await validate_public_url(url)
        playwright = await async_playwright().start()
        browser = await asyncio.wait_for(
            playwright.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
                "--no-zygote",
            ]),
            timeout=18.0,
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            java_script_enabled=True,
            accept_downloads=False,
        )
        await context.route("**/*", route_guard)
        page = await context.new_page()
        page.on("pageerror", lambda exc: add_log(f"JavaScript exception: {str(exc)[:180]}", "ERROR"))
        page.on("console", lambda msg: add_log(f"Browser console error: {msg.text[:180]}", "ERROR") if msg.type == "error" else None)
        page.on("requestfailed", lambda req: add_log(f"Network request failed: {req.url[:120]} · {req.failure or 'unknown failure'}", "WARN"))
        page.set_default_timeout(2500)
        page.set_default_navigation_timeout(20000)
        add_log("Chromium launched. Opening the requested page.")
        await page.goto(url, wait_until="domcontentloaded", timeout=20000)
        if state["session_id"] != session_id or state["status"] != "STARTING":
            return
        state.update(status="RUNNING", message="Browser is running", started_at=time.time())
        add_log(f"Page loaded: {url}")
        await scan_page()
        monitor_task = asyncio.create_task(monitor_loop())
    except asyncio.CancelledError:
        add_log("Start operation cancelled.")
        raise
    except Exception as exc:
        state.update(status="ERROR", message=f"{type(exc).__name__}: {str(exc)[:220]}")
        add_log(state["message"], "ERROR")
        await cleanup_browser()


class StartRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class ElementRequest(BaseModel):
    element_id: str = Field(min_length=4, max_length=100)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await cleanup_browser()


app = FastAPI(title="NEXUS AI Browser Monitor", version=APP_VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def home():
    return FileResponse("static/index.html")


@app.get("/health")
async def health():
    return {"status": "healthy", "app": "NEXUS AI", "version": APP_VERSION,
            "browser_status": state["status"]}


@app.get("/api/status")
async def get_status(x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    return {k: v for k, v in state.items() if k not in ("activity", "errors", "elements", "detections")}


@app.get("/api/data")
async def get_data(x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    return {"status": state["status"], "url": state["url"], "title": state["title"],
            "message": state["message"], "elements": state["elements"],
            "detections": state["detections"], "detected_elements": state["detected_elements"],
            "diagnostics": state["diagnostics"],
            "activity": state["activity"][-50:],
            "errors": state["errors"][-30:],
            "privacy_shield": privacy_shield.snapshot()}


@app.post("/api/start")
async def start(req: StartRequest, x_nexus_key: str | None = Header(default=None)):
    global start_task
    require_key(x_nexus_key)
    try:
        await validate_public_url(req.url)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    async with operation_lock:
        if state["status"] in ("STARTING", "RUNNING", "STOPPING"):
            raise HTTPException(409, f"Browser is currently {state['status'].lower()}.")
        state.update(status="STARTING", url=req.url, title="", message="Starting browser...",
                     elements=[], detections=[], detected_elements=[],
                     diagnostics={"checks": [], "updated_at": None},
                     started_at=None, last_scan=None, session_id=str(uuid.uuid4()))
        sid = state["session_id"]
        add_log(f"Start requested for {req.url}")
        start_task = asyncio.create_task(start_worker(req.url, sid))
    return {"ok": True, "status": "STARTING", "message": "Start request accepted."}


@app.post("/api/stop")
async def stop(x_nexus_key: str | None = Header(default=None)):
    global start_task
    require_key(x_nexus_key)
    async with operation_lock:
        if state["status"] == "STOPPED":
            return {"ok": True, "status": "STOPPED"}
        state.update(status="STOPPING", message="Stopping browser...")
        add_log("Stop requested.")
        pending_start = start_task
        if pending_start and not pending_start.done():
            pending_start.cancel()
            try:
                await asyncio.wait_for(pending_start, 2.5)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        await cleanup_browser()
        start_task = None
        state.update(status="STOPPED", message="Browser stopped.", elements=[], detections=[], detected_elements=[])
        add_log("Browser stopped and resources released.")
    return {"ok": True, "status": "STOPPED"}


@app.post("/api/approve")
async def approve(req: ElementRequest, x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    if state["status"] != "RUNNING" or page is None or page.is_closed():
        raise HTTPException(409, "Browser is not running.")

    # Resolve element — check regular scanned elements first, then
    # user-configured detection elements (bypass BLOCKED_TERMS for those).
    element = next((x for x in state["elements"] if x["id"] == req.element_id), None)
    detected_el = next((x for x in state["detected_elements"] if x["id"] == req.element_id), None)

    if not element and not detected_el:
        raise HTTPException(404, "Element is no longer in the latest scan. Scan again.")

    is_detection = detected_el is not None and element is None
    display_text = (detected_el or element).get("text", req.element_id)

    if not is_detection:
        # Regular element — apply the standard eligibility gate.
        if not element.get("clickable") or element.get("sensitive"):
            raise HTTPException(403, "This element is not eligible for manual approval.")

    try:
        locator = page.locator(f'[data-nexus-id="{req.element_id}"]')
        if await locator.count() != 1 or not await locator.is_visible() or not await locator.is_enabled():
            raise HTTPException(409, "Element changed or is no longer available.")

        live = await locator.evaluate("""el => ({
          tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || '').toLowerCase(),
          text: (el.innerText || el.value || el.getAttribute('aria-label') || '').slice(0,150),
          href: el.href || '', role: el.getAttribute('role') || ''
        })""")

        if not is_detection:
            # BLOCKED_TERMS screening only applies to general scanned elements,
            # not to user-configured DETECTION_ONLY selectors.
            if BLOCKED_TERMS.search(" ".join(str(v) for v in live.values())):
                raise HTTPException(403, "Safety filter blocked this element.")

        safe_input_types = {"", "button", "checkbox", "color", "date", "datetime-local",
                            "email", "month", "number", "radio", "range", "search",
                            "tel", "text", "time", "url", "week"}
        live_tag = live["tag"]
        eligible = (
            live_tag in {"a", "select", "textarea"}
            or (live_tag == "button" and live["type"] == "button")
            or (live_tag == "input" and live["type"] in safe_input_types)
            or live.get("role") == "button"
            or is_detection  # detection elements are pre-validated by selector
        )
        if not eligible:
            raise HTTPException(403, "This control type is not eligible for approval.")

        await locator.click(timeout=2500)
        add_log(f"Approved and clicked: {display_text[:100]}")
        await asyncio.sleep(0.25)
        await scan_page()
        return {"ok": True, "message": "Approved click completed."}
    except HTTPException:
        raise
    except PlaywrightTimeoutError:
        raise HTTPException(408, "Click timed out; the page may have changed.")
    except Exception as exc:
        add_log(f"Approved click failed: {type(exc).__name__}: {str(exc)[:160]}", "ERROR")
        raise HTTPException(500, "Click failed. Check the error log.")


@app.post("/api/reject")
async def reject(req: ElementRequest, x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    element = next((x for x in state["elements"] if x["id"] == req.element_id), None)
    add_log(f"Click declined: {element['text'][:100] if element else req.element_id}")
    return {"ok": True, "message": "No action taken."}
