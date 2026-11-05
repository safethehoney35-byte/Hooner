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
from playwright.async_api import async_playwright, Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError
from privacy_shield import PrivacyShield

APP_VERSION = "1.7.0"
ACCESS_KEY = os.getenv("NEXUS_ACCESS_KEY", "").strip()
SCAN_INTERVAL = 0.7  # lightweight DOM-version check; full scans are event-driven
MAX_ELEMENTS = 80
LOG_LIMIT = 240
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
    r"\b(payment|pay now|purchase|checkout|"
    r"delete|remove account|transfer|withdraw|payout|"
    r"ad|ads|advertisement|reward|rewards)\b", re.I
)
SAFE_INPUT_TYPES = {"", "button", "checkbox", "color", "date", "datetime-local", "email", "month", "number", "radio", "range", "search", "tel", "text", "time", "url", "week"}
# These predefined selectors identify Linkvertise ad/reward flow targets or
# status markers. Keep them visible and reviewable, but never turn them into
# automated click targets. Ordinary page controls still use the normal policy.
RESTRICTED_DETECTION_ACTIONS = {
    "watchAds": "Ad-view / reward-flow target; automated interaction is disabled.",
    "continueButton": "Ad-gated continuation target; automated interaction is disabled.",
    "adCounter": "Informational ad counter; it is not an action control.",
    "adLabel": "Informational ad label; it is not an action control.",
    "skipAdContainer": "Ad-skip target; automated interaction is disabled.",
    "successHeading": "Status heading; it is informational, not an action control.",
    "contentReady": "Content-ready signal; it is informational, not an action control.",
    "openHereButton": "Ad-gated destination target; automated interaction is disabled.",
}


def detection_approval_policy(detection_names: list[str], clickable: bool) -> tuple[bool, str]:
    """Keep configured ad-flow selectors observable without making them click bypasses."""
    restricted = [name for name in detection_names if name in RESTRICTED_DETECTION_ACTIONS]
    if restricted:
        return False, " ".join(RESTRICTED_DETECTION_ACTIONS[name] for name in restricted)
    if not clickable:
        return False, "This match is not a visible, enabled, supported interactive control."
    return True, "Eligible for individual review."

state: dict[str, Any] = {
    "status": "STOPPED", "url": "", "title": "", "message": "Ready",
    "started_at": None, "last_scan": None, "elements": [],
    "detections": [], "detected_elements": [],
    "diagnostics": {"checks": [], "updated_at": None}, "activity": [], "errors": [], "events": [], "session_id": None,
}
playwright = None
browser = None
context = None
page = None
monitor_task: asyncio.Task | None = None
last_dom_version: int | None = None
last_full_scan_at = 0.0
start_task: asyncio.Task | None = None
operation_lock = asyncio.Lock()
approval_lock = asyncio.Lock()
log = logging.getLogger("nexus")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def add_log(message: str, level: str = "INFO", *, event_type: str = "LOG", status: str = "INFO", event_id: str | None = None) -> dict[str, Any]:
    """Record one real server/browser event for the UI and Render logs."""
    event_id = event_id or uuid.uuid4().hex[:10].upper()
    item = {
        "id": event_id,
        "time": time.strftime("%H:%M:%S"),
        "timestamp": time.time(),
        "level": level,
        "event_type": event_type,
        "status": status,
        "message": str(message)[:500],
    }
    state["activity"].append(item)
    state["activity"] = state["activity"][-LOG_LIMIT:]
    state["events"].append(item)
    state["events"] = state["events"][-LOG_LIMIT:]
    if level == "ERROR" or status == "FAILED":
        state["errors"].append(item)
        state["errors"] = state["errors"][-LOG_LIMIT:]
    log_method = log.error if level == "ERROR" or status == "FAILED" else log.warning if level == "WARN" else log.info
    log_method("event_id=%s event=%s status=%s %s", event_id, event_type, status, message)
    return item


def playwright_error_detail(exc: Exception, limit: int = 1100) -> str:
    """Preserve Playwright's actionable call log instead of logging only its first line."""
    raw = str(exc) or type(exc).__name__
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    useful = [line for line in lines if any(token in line.lower() for token in (
        "waiting for", "locator resolved", "intercepts pointer", "not visible", "not enabled",
        "not stable", "scroll", "element is", "retrying", "call log", "timeout"
    ))]
    detail = " | ".join(useful[-8:] if useful else lines[-6:])
    return detail[:limit]


async def inspect_click_target(locator) -> str:
    """Return a compact live DOM hit-test explanation without interacting with the page."""
    try:
        info = await asyncio.wait_for(locator.evaluate("""el => {
          const r = el.getBoundingClientRect();
          const x = Math.max(0, Math.min(innerWidth - 1, r.left + r.width / 2));
          const y = Math.max(0, Math.min(innerHeight - 1, r.top + r.height / 2));
          const top = document.elementFromPoint(x, y);
          const style = getComputedStyle(el);
          return {
            rect: `${Math.round(r.width)}x${Math.round(r.height)} at ${Math.round(r.left)},${Math.round(r.top)}`,
            display: style.display, visibility: style.visibility, pointerEvents: style.pointerEvents,
            disabled: !!el.disabled,
            hitTarget: top ? `${top.tagName.toLowerCase()}${top.id ? '#' + top.id : ''}` : 'none',
            covered: !!(top && top !== el && !el.contains(top))
          };
        }"""), timeout=1.5)
        return "Live target: " + "; ".join(f"{k}={v}" for k, v in info.items())
    except Exception as exc:
        return f"Live target inspection unavailable: {type(exc).__name__}."


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
    global last_dom_version, last_full_scan_at
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
              type, href: tag === 'a' ? (() => { try { const u = new URL(el.href); u.search = ''; u.hash = ''; return u.href; } catch (_) { return ''; } })() : '', visible, disabled: !!el.disabled,
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
                const type = (el.getAttribute('type') || '').toLowerCase();
                const aria = el.getAttribute('aria-label') || '';
                const role = el.getAttribute('role') || '';
                const rawHref = tag === 'a' ? el.href : '';
                const href = (() => { try { const u = new URL(rawHref); u.search = ''; u.hash = ''; return u.href; } catch (_) { return ''; } })();
                const text = (el.innerText || el.value || aria || el.getAttribute('title') || '')
                  .trim().replace(/\\s+/g, ' ').slice(0, 150);
                return {id: el.dataset.nexusId, text: text || tag, tag, type, href, aria, role, visible, disabled: !!el.disabled};
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
          return {controls, detections, title: document.title || '', dom_version: window.__nexusDomVersion || 0, diagnostics: {
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
        raw_detections = payload["detections"]
        signal_ids = {el["id"] for det in raw_detections for el in det.get("elements", [])}
        # Keep predefined selector matches out of the general list. They appear
        # once, by friendly selector name, in the separate Awaiting Elements panel.
        result = [item for item in result if item["id"] not in signal_ids]
        state["elements"] = result
        # Flatten configured selector matches by DOM id. The UI can show one
        # decision row per unique match; server-side policy still decides whether
        # a match is eligible for any interaction.
        detected_by_id: dict[str, dict] = {}
        for det in raw_detections:
            unique_elements = []
            seen_in_group: set[str] = set()
            for el in det.get("elements", []):
                if el["id"] in seen_in_group:
                    continue
                seen_in_group.add(el["id"])
                unique_elements.append(el)
                entry = detected_by_id.setdefault(el["id"], {**el, "detection_names": []})
                if det["name"] not in entry["detection_names"]:
                    entry["detection_names"].append(det["name"])
            det["elements"] = unique_elements
            det["count"] = len(unique_elements)

        for entry in detected_by_id.values():
            descriptor = " ".join(str(entry.get(k, "")) for k in ("text", "aria", "href"))
            entry["sensitive"] = bool(BLOCKED_TERMS.search(descriptor))
            tag, control_type, role = entry.get("tag", ""), entry.get("type", ""), entry.get("role", "")
            safe_tag = tag in {"a", "select", "textarea"} or (tag == "button" and control_type in {"", "button"}) or (tag == "input" and control_type in SAFE_INPUT_TYPES) or role == "button"
            entry["clickable"] = bool(entry.get("visible") and not entry.get("disabled") and not entry["sensitive"] and safe_tag)
            entry["approval_allowed"], entry["approval_reason"] = detection_approval_policy(
                entry["detection_names"], entry["clickable"]
            )

        # Copy the flattened, deduplicated approval metadata back into each
        # selector group so the UI can render one row per actual DOM element.
        for det in raw_detections:
            for el in det.get("elements", []):
                merged = detected_by_id.get(el["id"], {})
                for key in ("type", "href", "aria", "role", "sensitive", "clickable", "approval_allowed", "approval_reason", "detection_names"):
                    if key in merged:
                        el[key] = merged[key]
        state["detections"] = raw_detections
        state["detected_elements"] = list(detected_by_id.values())
        state["diagnostics"] = {
            **payload.get("diagnostics", {}),
            "updated_at": time.time(),
            "status": "ok" if payload.get("diagnostics", {}).get("checks") else "warning",
        }
        state["last_scan"] = time.time()
        last_full_scan_at = time.monotonic()
        # Version is captured in the same page evaluation as the scan, so a
        # mutation immediately after it remains detectable on the next check.
        last_dom_version = payload.get("dom_version")
        state["title"] = payload["title"] or state["title"]
        summary = (len(result), tuple((d["name"], d["count"]) for d in raw_detections))
        if state.get("scan_summary") != summary:
            state["scan_summary"] = summary
            add_log(f"Page scan updated: {len(result)} unique controls; {sum(d['count'] for d in raw_detections)} predefined matches.", event_type="PAGE_SCAN", status="WORKED")
    except Exception as exc:
        add_log(f"DOM scan failed: {type(exc).__name__}: {str(exc)[:180]}", "ERROR", event_type="PAGE_SCAN", status="FAILED")


async def monitor_loop() -> None:
    """Rescan after real DOM changes; use a slow fallback for layout-only changes."""
    global last_dom_version
    pending_change_at: float | None = None
    while state["status"] == "RUNNING":
        try:
            if page is None or page.is_closed():
                break
            version = await page.evaluate("() => window.__nexusDomVersion || 0")
            now = time.monotonic()
            if last_dom_version is None:
                last_dom_version = version
            elif version != last_dom_version:
                last_dom_version = version
                pending_change_at = now
            # Wait for a short quiet period so a framework's burst of DOM writes
            # becomes one scan instead of dozens of expensive scans.
            quiet_ready = pending_change_at is not None and now - pending_change_at >= 0.35
            fallback_due = now - last_full_scan_at >= 8.0
            if quiet_ready or fallback_due:
                await scan_page()
                pending_change_at = None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            add_log(f"Continuous monitor check failed: {type(exc).__name__}: {str(exc)[:140]}", "WARN", event_type="DOM_MONITOR", status="UNCERTAIN")
            await asyncio.sleep(1.5)
            continue
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
        add_log("Validating requested public URL.", event_type="URL_VALIDATION", status="RUNNING")
        await validate_public_url(url)
        add_log("Public URL validation passed.", event_type="URL_VALIDATION", status="WORKED")
        add_log("Starting Playwright and Chromium.", event_type="BROWSER_START", status="RUNNING")
        playwright = await async_playwright().start()
        browser = await asyncio.wait_for(
            playwright.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
                "--no-zygote",
            ]),
            timeout=18.0,
        )
        add_log("Chromium process launched successfully.", event_type="BROWSER_START", status="WORKED")
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            java_script_enabled=True,
            accept_downloads=False,
        )
        await context.route("**/*", route_guard)
        page = await context.new_page()
        # Observe meaningful DOM mutations inside the page. data-nexus-id is
        # deliberately excluded so our own scan annotations do not retrigger it.
        await page.add_init_script("""(() => {
          if (window.__nexusObserverInstalled) return;
          window.__nexusObserverInstalled = true;
          window.__nexusDomVersion = 0;
          const start = () => {
            if (!document.documentElement || window.__nexusObserver) return;
            window.__nexusObserver = new MutationObserver(records => {
              if (records.some(r => r.type === 'childList' || r.type === 'characterData' ||
                ['class','style','hidden','disabled','href','type','role','aria-label','aria-hidden'].includes(r.attributeName))) {
                window.__nexusDomVersion++;
              }
            });
            window.__nexusObserver.observe(document.documentElement, {
              subtree: true, childList: true, characterData: true, attributes: true,
              attributeFilter: ['class','style','hidden','disabled','href','type','role','aria-label','aria-hidden']
            });
          };
          if (document.documentElement) start();
          else document.addEventListener('DOMContentLoaded', start, {once:true});
        })();""")
        page.on("pageerror", lambda exc: add_log(f"JavaScript exception: {str(exc)[:180]}", "ERROR", event_type="PAGE_JS_ERROR", status="FAILED"))
        page.on("console", lambda msg: add_log(f"Browser console error: {msg.text[:180]}", "ERROR", event_type="CONSOLE_ERROR", status="FAILED") if msg.type == "error" else None)
        page.on("requestfailed", lambda req: add_log(f"Network request failed: {urlparse(req.url).hostname or 'unknown host'} · {req.resource_type} · {req.failure or 'unknown failure'}", "WARN", event_type="NETWORK_REQUEST", status="FAILED"))
        page.on("request", lambda req: add_log(f"Navigation request started: {req.method} {urlparse(req.url).hostname or 'unknown host'}", event_type="NETWORK_REQUEST", status="RUNNING") if req.is_navigation_request() else None)
        async def record_navigation_finished(req):
            if req.is_navigation_request():
                try:
                    response = await req.response()
                    code = response.status if response else "no response"
                    status = "WORKED" if response and response.ok else "FAILED"
                    level = "INFO" if status == "WORKED" else "WARN"
                    add_log(f"Navigation request finished: {urlparse(req.url).hostname or 'unknown host'} · HTTP {code}", level, event_type="NETWORK_REQUEST", status=status)
                except Exception as exc:
                    add_log(f"Navigation response unavailable: {type(exc).__name__}", "WARN", event_type="NETWORK_REQUEST", status="UNCERTAIN")
        page.on("requestfinished", lambda req: asyncio.create_task(record_navigation_finished(req)))
        page.set_default_timeout(7000)
        page.set_default_navigation_timeout(20000)
        add_log("Opening requested page; waiting for DOMContentLoaded.", event_type="PAGE_NAVIGATION", status="RUNNING")
        await page.goto(url, wait_until="domcontentloaded", timeout=20000)
        if state["session_id"] != session_id or state["status"] != "STARTING":
            return
        state.update(status="RUNNING", message="Browser is running", started_at=time.time())
        page_title = await page.title()
        add_log(f"Page DOM loaded: {urlparse(page.url).hostname or 'website'} · title={page_title[:100]}", event_type="PAGE_NAVIGATION", status="WORKED")
        await scan_page()
        monitor_task = asyncio.create_task(monitor_loop())
    except asyncio.CancelledError:
        add_log("Start operation cancelled.")
        raise
    except Exception as exc:
        state.update(status="ERROR", message=f"{type(exc).__name__}: {str(exc)[:220]}")
        add_log(state["message"], "ERROR", event_type="BROWSER_START", status="FAILED")
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
            "activity": state["activity"][-80:],
            "events": state["events"][-100:],
            "errors": state["errors"][-50:],
            "privacy_shield": privacy_shield.snapshot()}


@app.post("/api/start")
async def start(req: StartRequest, x_nexus_key: str | None = Header(default=None)):
    global start_task, last_dom_version, last_full_scan_at
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
                     diagnostics={"checks": [], "updated_at": None}, scan_summary=None,
                     started_at=None, last_scan=None, session_id=str(uuid.uuid4()))
        last_dom_version = None
        last_full_scan_at = 0.0
        sid = state["session_id"]
        add_log(f"Start request accepted for {urlparse(req.url).hostname or 'website'}.", event_type="START_REQUEST", status="WORKED")
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
        add_log("Stop requested by operator.", event_type="BROWSER_STOP", status="RUNNING")
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
        add_log("Browser stopped and browser resources released.", event_type="BROWSER_STOP", status="WORKED")
    return {"ok": True, "status": "STOPPED"}


async def _approve_locked(req: ElementRequest, x_nexus_key: str | None):
    require_key(x_nexus_key)
    action_id = uuid.uuid4().hex[:10].upper()
    if state["status"] != "RUNNING" or page is None or page.is_closed():
        add_log("Approval rejected: browser is not running.", "WARN", event_type="APPROVAL", status="FAILED", event_id=action_id)
        raise HTTPException(409, "Browser is not running.")

    element = next((x for x in state["elements"] if x["id"] == req.element_id), None)
    is_predefined = False
    if element is None:
        element = next((x for x in state["detected_elements"] if x["id"] == req.element_id), None)
        is_predefined = element is not None
    if not element:
        add_log(f"Approval {action_id}: element is no longer in the latest scan.", "WARN", event_type="APPROVAL", status="FAILED", event_id=action_id)
        raise HTTPException(404, "Element is no longer in the latest scan. Scan again.")
    display_text = element.get("text", req.element_id)
    if is_predefined and not element.get("approval_allowed"):
        reason = element.get("approval_reason") or "This predefined match is informational or restricted."
        add_log(f"Predefined approval blocked for {display_text[:80]} ({', '.join(element.get('detection_names', []))}): {reason}", "WARN", event_type="APPROVAL", status="FAILED", event_id=action_id)
        raise HTTPException(403, reason)
    if not element.get("clickable") or element.get("sensitive"):
        add_log(f"Approval {action_id} blocked by eligibility/safety rules: {display_text[:100]}.", "WARN", event_type="APPROVAL", status="FAILED", event_id=action_id)
        raise HTTPException(403, "This element is not eligible for manual approval.")

    phase = "preflight"
    try:
        locator = page.locator(f'[data-nexus-id="{req.element_id}"]')
        count = await locator.count()
        if count != 1 or not await locator.is_visible() or not await locator.is_enabled():
            raise HTTPException(409, "Element changed or is no longer available. Scan again.")

        live = await locator.evaluate("""el => ({
          tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || '').toLowerCase(),
          text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0,150),
          href: el.href || '', role: el.getAttribute('role') || '',
          checked: 'checked' in el ? !!el.checked : null,
          ariaPressed: el.getAttribute('aria-pressed'),
          ariaExpanded: el.getAttribute('aria-expanded')
        })""")
        descriptor = " ".join(str(v) for v in live.values())
        if BLOCKED_TERMS.search(descriptor):
            add_log(f"Approval {action_id} blocked by live safety re-check: {display_text[:100]}.", "WARN", event_type="APPROVAL", status="FAILED", event_id=action_id)
            raise HTTPException(403, "Safety filter blocked this element.")

        live_tag = live["tag"]
        eligible = (
            live_tag in {"a", "select", "textarea"}
            or (live_tag == "button" and live["type"] in {"", "button"})
            or (live_tag == "input" and live["type"] in SAFE_INPUT_TYPES)
            or live.get("role") == "button"
        )
        if not eligible:
            raise HTTPException(403, "This control type is not eligible for approval.")

        before_url = page.url
        before_state = {"checked": live.get("checked"), "ariaPressed": live.get("ariaPressed"), "ariaExpanded": live.get("ariaExpanded")}
        add_log(f"Approval {action_id} accepted for: {display_text[:100]}.", event_type="APPROVAL", status="RUNNING", event_id=action_id)
        add_log(f"Checking click actionability for {display_text[:100]}.", event_type="CLICK_PREFLIGHT", status="RUNNING", event_id=action_id)
        await locator.scroll_into_view_if_needed(timeout=2500)
        await locator.click(trial=True, timeout=3000, no_wait_after=True)
        target_detail = await inspect_click_target(locator)
        add_log(f"Click preflight passed for {display_text[:100]}. {target_detail}", event_type="CLICK_PREFLIGHT", status="WORKED", event_id=action_id)

        phase = "click"
        add_log(f"Dispatching click for {display_text[:100]}.", event_type="CLICK", status="RUNNING", event_id=action_id)
        await locator.click(timeout=5000, no_wait_after=True)
        add_log(f"Playwright click completed for {display_text[:100]}.", event_type="CLICK", status="WORKED", event_id=action_id)

        # Verify only concrete, observable postconditions. A completed click alone is not proof
        # that the website accepted or completed its business action.
        verification = "UNVERIFIED"
        evidence: list[str] = ["Playwright locator.click() completed."]
        try:
            # Give genuine navigation a short observation window without treating
            # arbitrary DOM churn as proof that a website action succeeded.
            for _ in range(6):
                if page is None or page.is_closed() or page.url != before_url:
                    break
                await asyncio.sleep(0.2)
            if page is None or page.is_closed():
                verification = "OBSERVED"
                evidence.append("The browser page closed after the click.")
            else:
                after_url = page.url
                if after_url != before_url:
                    verification = "OBSERVED"
                    evidence.append("The page URL changed after the click.")
                else:
                    try:
                        after_state = await asyncio.wait_for(locator.evaluate("""el => ({
                          checked: 'checked' in el ? !!el.checked : null,
                          ariaPressed: el.getAttribute('aria-pressed'),
                          ariaExpanded: el.getAttribute('aria-expanded')
                        })"""), timeout=1.2)
                        for key, label in (("checked", "checked state"), ("ariaPressed", "aria-pressed state"), ("ariaExpanded", "expanded state")):
                            if before_state.get(key) is not None and after_state.get(key) != before_state.get(key):
                                verification = "OBSERVED"
                                evidence.append(f"The control's {label} changed.")
                    except Exception:
                        try:
                            if await locator.count() == 0:
                                verification = "OBSERVED"
                                evidence.append("The original element was removed from the DOM.")
                        except Exception:
                            pass
        except Exception as verify_exc:
            evidence.append(f"Post-click observation unavailable: {type(verify_exc).__name__}.")

        status = "EFFECT_OBSERVED" if verification == "OBSERVED" else "CLICK_DISPATCHED"
        result_message = "Click completed and a browser-side change was observed." if verification == "OBSERVED" else "Click completed; the website effect could not be verified from available evidence."
        add_log(f"Approval {action_id} result: {status}. Evidence: {' '.join(evidence)}", event_type="ACTION_RESULT", status="WORKED" if verification == "OBSERVED" else "UNCERTAIN", event_id=action_id)
        await scan_page()
        return {"ok": True, "action_id": action_id, "status": status, "verification": verification, "evidence": evidence, "message": result_message}
    except HTTPException as exc:
        add_log(f"Approval {action_id} failed: {exc.detail}", "WARN", event_type="ACTION_RESULT", status="FAILED", event_id=action_id)
        raise
    except PlaywrightTimeoutError as exc:
        detail = playwright_error_detail(exc)
        target_detail = await inspect_click_target(locator) if "locator" in locals() else "Live target inspection unavailable."
        if phase == "preflight":
            message = f"Click was NOT sent: Playwright could not confirm the target was actionable. {detail} {target_detail}"
            add_log(f"Approval {action_id} preflight timed out; no click was sent. {message}", "WARN", event_type="ACTION_RESULT", status="FAILED", event_id=action_id)
            raise HTTPException(409, f"CLICK_NOT_SENT: {message} Ref: {action_id}")
        message = f"Playwright did not confirm click completion. The outcome is uncertain; NEXUS did not retry. {detail} {target_detail}"
        add_log(f"Approval {action_id} click outcome uncertain: {message}", "WARN", event_type="ACTION_RESULT", status="UNCERTAIN", event_id=action_id)
        raise HTTPException(408, f"OUTCOME_UNCERTAIN: {message} Ref: {action_id}")
    except PlaywrightError as exc:
        detail = playwright_error_detail(exc)
        target_detail = await inspect_click_target(locator) if "locator" in locals() else "Live target inspection unavailable."
        if phase == "preflight":
            message = f"Click was NOT sent: Playwright preflight failed. {detail} {target_detail}"
            add_log(f"Approval {action_id} preflight failed; no click was sent. {message}", "WARN", event_type="ACTION_RESULT", status="FAILED", event_id=action_id)
            raise HTTPException(409, f"CLICK_NOT_SENT: {message} Ref: {action_id}")
        message = f"Playwright could not confirm click completion. Outcome is uncertain; NEXUS did not retry. {detail} {target_detail}"
        add_log(f"Approval {action_id} click outcome uncertain: {message}", "WARN", event_type="ACTION_RESULT", status="UNCERTAIN", event_id=action_id)
        raise HTTPException(408, f"OUTCOME_UNCERTAIN: {message} Ref: {action_id}")
    except Exception as exc:
        add_log(f"Approval {action_id} failed: {type(exc).__name__}: {str(exc)[:200]}", "ERROR", event_type="ACTION_RESULT", status="FAILED", event_id=action_id)
        raise HTTPException(500, f"Click failed. Check activity logs. Ref: {action_id}")


@app.post("/api/approve")
async def approve(req: ElementRequest, x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    if approval_lock.locked():
        raise HTTPException(409, "Another approval is already being processed. Please wait for its result.")
    async with approval_lock:
        return await _approve_locked(req, x_nexus_key)



@app.post("/api/reject")
async def reject(req: ElementRequest, x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    element = next((x for x in state["elements"] if x["id"] == req.element_id), None)
    if element is None:
        element = next((x for x in state["detected_elements"] if x["id"] == req.element_id), None)
    label = element.get("text", req.element_id) if element else req.element_id
    selector_names = ", ".join(element.get("detection_names", [])) if element else ""
    action_id = uuid.uuid4().hex[:10].upper()
    add_log(f"Operator declined action for: {label[:100]} {f'[{selector_names}]' if selector_names else ''}. No browser interaction was sent.", event_type="APPROVAL_REJECTED", status="WORKED", event_id=action_id)
    return {"ok": True, "action_id": action_id, "status": "REJECTED", "message": "Declined. No browser action was sent."}
