from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright, Error as PlaywrightError
from privacy_shield import PrivacyShield

APP_VERSION = "2.1.0"
ACCESS_KEY = os.getenv("NEXUS_ACCESS_KEY", "").strip()
MAX_ACTIONS = 5000
LOG_LIMIT = 240
HOST_VALIDATION_CACHE: dict[str, tuple[float, bool]] = {}

state: dict[str, Any] = {
    "status": "STOPPED", "url": "", "title": "", "message": "Ready",
    "started_at": None, "actions_total": 0, "actions_done": 0,
    "success": 0, "failed": 0, "current_action": None,
    "diagnostics": {}, "activity": [], "errors": [], "events": [],
    "session_id": None, "replay_running": False, "verified": 0,
    "action_results": [], "run_started_at": None, "run_elapsed_ms": 0,
}
playwright = browser = context = page = None
replay_task: asyncio.Task | None = None
start_task: asyncio.Task | None = None
operation_lock = asyncio.Lock()
stop_event = asyncio.Event()
log = logging.getLogger("nexus")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def add_log(message: str, level: str = "INFO", *, event_type: str = "LOG", status: str = "INFO") -> None:
    item = {"id": uuid.uuid4().hex[:10].upper(), "time": time.strftime("%H:%M:%S"),
            "timestamp": time.time(), "level": level, "event_type": event_type,
            "status": status, "message": str(message)[:500]}
    state["activity"].append(item); state["activity"] = state["activity"][-LOG_LIMIT:]
    state["events"].append(item); state["events"] = state["events"][-LOG_LIMIT:]
    if level == "ERROR" or status == "FAILED":
        state["errors"].append(item); state["errors"] = state["errors"][-LOG_LIMIT:]
    (log.error if level == "ERROR" or status == "FAILED" else log.warning if level == "WARN" else log.info)(
        "event_id=%s event=%s status=%s %s", item["id"], event_type, status, message)


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
        cached = HOST_VALIDATION_CACHE.get(f"{host}:{port}")
        if cached and time.monotonic() - cached[0] < 60:
            if cached[1]: return value
            raise ValueError("The URL resolves to a private or non-public address.")
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            raise ValueError("Local/private network addresses are not allowed.")
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), 4)
            addresses = [ipaddress.ip_address(x[4][0]) for x in infos]
        public = bool(addresses) and all(x.is_global for x in addresses)
        HOST_VALIDATION_CACHE[f"{host}:{port}"] = (time.monotonic(), public)
        if not public: raise ValueError("The URL resolves to a private or non-public address.")
        return value
    except asyncio.TimeoutError:
        raise ValueError("DNS lookup timed out.")
    except (socket.gaierror, OSError):
        raise ValueError("The hostname could not be resolved.")
    except ValueError:
        raise


TRACKER_BLOCKING = os.getenv("NEXUS_BLOCK_TRACKERS", "true").strip().lower() not in {"0", "false", "no", "off"}
privacy_shield = PrivacyShield(validate_public_url, block_trackers=TRACKER_BLOCKING,
    extra_tracker_domains={x.strip().lower() for x in os.getenv("NEXUS_EXTRA_TRACKERS", "").split(",") if x.strip()})


async def route_guard(route) -> None:
    allowed, reason = await privacy_shield.inspect(route.request.url, route.request.resource_type)
    if allowed:
        await route.continue_()
    else:
        add_log(f"Privacy Shield blocked {urlparse(route.request.url).hostname or 'unknown'} ({reason}).",
                "WARN", event_type="NETWORK_REQUEST", status="BLOCKED")
        await route.abort()


async def browser_diagnostics() -> dict[str, Any]:
    if page is None or page.is_closed(): return {}
    data = await page.evaluate("""() => {
      const nav=performance.getEntriesByType('navigation')[0]||null;
      const resources=performance.getEntriesByType('resource');
      const checks=[];
      const add=(name,status,detail)=>checks.push({name,status,detail:String(detail)});
      add('Current page','ok',location.href);
      add('Page title','info',document.title||'Untitled');
      add('JavaScript','ok','Enabled');
      add('Cookies',navigator.cookieEnabled?'ok':'warning',navigator.cookieEnabled?'Available':'Disabled');
      add('Browser', 'ok', navigator.userAgent);
      add('Language','info',navigator.language||'Unknown');
      add('Timezone','info',Intl.DateTimeFormat().resolvedOptions().timeZone||'Unknown');
      add('Viewport','info',innerWidth+' × '+innerHeight);
      add('Page visibility','info',document.visibilityState);
      add('Navigation timing',nav?'ok':'warning',nav?Math.round(nav.domContentLoadedEventEnd)+' ms DOM ready':'Not available');
      add('Resource loading','ok',resources.length+' resources observed');
      add('Page JavaScript errors','info','Captured in activity/error logs');
      return {title:document.title||'',checks,resource_count:resources.length,
        navigation_ms:nav?Math.round(nav.domContentLoadedEventEnd):null,
        user_agent:navigator.userAgent,language:navigator.language||'',
        timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||''};
    }""")
    data["updated_at"] = time.time()
    return data


async def cleanup_browser() -> None:
    global playwright, browser, context, page
    for name, obj in (("page", page), ("context", context), ("browser", browser), ("playwright", playwright)):
        if obj is not None:
            try:
                closer = getattr(obj, "close", None)
                if closer: await asyncio.wait_for(closer(), 3)
                elif name == "playwright": await asyncio.wait_for(obj.stop(), 3)
            except Exception as exc:
                add_log(f"{name} cleanup: {type(exc).__name__}", "WARN")
    page = context = browser = playwright = None


async def launch_browser(url: str) -> None:
    global playwright, browser, context, page
    await validate_public_url(url)
    add_log("Launching Chromium.", event_type="BROWSER_START", status="RUNNING")
    playwright = await async_playwright().start()
    browser = await asyncio.wait_for(playwright.chromium.launch(headless=True, args=[
        "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--no-zygote"]), 20)
    context = await browser.new_context(viewport={"width":1280,"height":800}, java_script_enabled=True)
    await context.route("**/*", route_guard)
    page = await context.new_page()
    page.on("pageerror", lambda exc: add_log(f"Page JavaScript error: {str(exc)[:220]}",
        "ERROR", event_type="PAGE_JS_ERROR", status="FAILED"))
    page.on("console", lambda msg: add_log(f"Console error: {msg.text[:220]}",
        "ERROR", event_type="CONSOLE_ERROR", status="FAILED") if msg.type == "error" else None)
    page.on("requestfailed", lambda req: add_log(
        f"Request failed: {urlparse(req.url).hostname or 'unknown'} · {req.failure or 'unknown'}",
        "WARN", event_type="NETWORK_REQUEST", status="FAILED"))
    add_log("Opening requested website.", event_type="PAGE_NAVIGATION", status="RUNNING")
    response = await page.goto(url, wait_until="domcontentloaded", timeout=60000)
    try: await page.wait_for_load_state("load", timeout=12000)
    except Exception: add_log("Page load event did not finish within 12 seconds; continuing with live page.",
                               "WARN", event_type="PAGE_LOADING", status="UNCERTAIN")
    state["title"] = await page.title()
    state["diagnostics"] = await browser_diagnostics()
    add_log(f"Website loaded: {state['title'] or page.url} · HTTP {response.status if response else 'unknown'}",
            event_type="PAGE_LOADING", status="WORKED")
    state.update(status="READY", message="Website ready. Load a JSON recording to replay.")


def fingerprint_matches(el: dict, target: dict) -> bool:
    for key, attr in (("tag","tag"),("id","id"),("testId","data-testid"),
                      ("ariaLabel","aria-label"),("name","name")):
        expected = target.get(key)
        if expected and str(el.get(attr) or "").lower() != str(expected).lower(): return False
    expected_text = " ".join(str(target.get("text") or "").split())
    actual_text = " ".join(str(el.get("text") or "").split())
    if expected_text and expected_text not in actual_text: return False
    return True


async def resolve_target(action: dict):
    target = action.get("target") or {}
    selectors = []
    if target.get("selector"): selectors.append(str(target["selector"]))
    if target.get("id"): selectors.append("#" + str(target["id"]).replace('"', '\\"'))
    if target.get("testId"): selectors.append('[data-testid="' + str(target["testId"]).replace('"','\\"') + '"]')
    if target.get("ariaLabel"): selectors.append('[aria-label="' + str(target["ariaLabel"]).replace('"','\\"') + '"]')
    if target.get("name"): selectors.append('[name="' + str(target["name"]).replace('"','\\"') + '"]')
    for selector in dict.fromkeys(selectors):
        try:
            loc = page.locator(selector)
            count = await loc.count()
            if count == 1:
                info = await loc.evaluate("""el=>({tag:el.tagName.toLowerCase(),id:el.id,
                  testId:el.getAttribute('data-testid'),ariaLabel:el.getAttribute('aria-label'),
                  name:el.getAttribute('name'),text:(el.innerText||el.textContent||el.value||'').replace(/\\s+/g,' ').trim(),
                  visible:!!(el.getClientRects().length)&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none',
                  disabled:!!el.disabled||el.getAttribute('aria-disabled')==='true'})""")
                if fingerprint_matches(info, target) and info["visible"] and not info["disabled"]:
                    return loc, None
            elif count > 1:
                continue
        except Exception:
            continue
    return None, "Target not present or fingerprint did not match"


async def execute_action(action: dict, number: int) -> tuple[bool, str]:
    if action.get("type") != "click":
        return False, f"Unsupported action type: {action.get('type')}"
    action_url = action.get("url")
    if action_url:
        try:
            expected = urlparse(action_url)
            current = urlparse(page.url)
            if expected.scheme not in ("http","https") or expected.netloc != current.netloc:
                return False, "Recorded action origin does not match current page"
        except Exception:
            return False, "Invalid recorded action URL"
    delay = min(max(int(action.get("gapMs") or 0), 0), 30000)
    if delay: await asyncio.sleep(delay)
    deadline = time.monotonic() + 12
    last_reason = "Target not present"
    while time.monotonic() < deadline and not stop_event.is_set():
        locator, reason = await resolve_target(action)
        if locator is not None:
            try:
                await locator.scroll_into_view_if_needed(timeout=1500)
                await locator.click(timeout=3500, no_wait_after=True)
                return True, "Click dispatched"
            except Exception as exc:
                last_reason = str(exc).splitlines()[0][:180]
        else:
            last_reason = reason or last_reason
        await asyncio.sleep(0.3)
    return False, "Timed out waiting for recorded target: " + last_reason


async def observe_page_response(before: dict[str, Any], wait_ms: int = 900) -> dict[str, Any]:
    """Collect observable browser evidence after a dispatched click.

    This is evidence of a page response, not proof that the intended business
    operation completed. A mutation alone can be unrelated page activity.
    """
    await asyncio.sleep(wait_ms / 1000)
    if page is None or page.is_closed():
        return {"observed": False, "signals": ["page_closed"]}
    try:
        after = await page.evaluate("""() => ({url:location.href,title:document.title,
          textLength:(document.body?.innerText||'').length,
          readyState:document.readyState,
          mutationCount:window.__nexusMutationCount||0})""")
    except Exception as exc:
        return {"observed": False, "signals": ["snapshot_error:" + type(exc).__name__]}
    signals = []
    if after.get("url") != before.get("url"): signals.append("url_changed")
    if after.get("title") != before.get("title"): signals.append("title_changed")
    if after.get("textLength") != before.get("textLength"): signals.append("page_text_length_changed")
    if after.get("mutationCount", 0) > 0: signals.append("dom_mutation_observed")
    return {"observed": bool(signals), "signals": signals, "after": after}


async def page_snapshot() -> dict[str, Any]:
    return await page.evaluate("""() => {
      window.__nexusMutationCount = 0;
      if (!window.__nexusObserver) {
        window.__nexusObserver = new MutationObserver(records => {
          window.__nexusMutationCount = (window.__nexusMutationCount || 0) + records.length;
        });
        window.__nexusObserver.observe(document.documentElement, {
          subtree:true, childList:true, attributes:true, characterData:true
        });
      }
      return {url:location.href,title:document.title,
        textLength:(document.body?.innerText||'').length,
        readyState:document.readyState,mutationCount:0};
    }""")


async def run_replay(actions: list[dict]) -> None:
    """Run strictly in recorded order. Never scan ahead for a later target."""
    started = time.monotonic()
    state.update(status="REPLAYING", replay_running=True, actions_total=len(actions),
                 actions_done=0, success=0, verified=0, failed=0,
                 current_action=None, action_results=[], run_started_at=time.time(),
                 run_elapsed_ms=0)
    add_log(f"Replay started: {len(actions)} actions; strict recorded order enabled.",
            event_type="REPLAY_START", status="RUNNING")
    try:
        for index, action in enumerate(actions):
            if stop_event.is_set(): break
            number = index + 1
            state["current_action"] = number
            action_started = time.monotonic()
            target = action.get("target") or {}
            target_label = (target.get("text") or target.get("ariaLabel") or
                            target.get("id") or target.get("selector") or target.get("tag") or "unknown target")
            result = {"number": number, "target": str(target_label)[:120],
                      "selector": str(target.get("selector") or "")[:240],
                      "status": "DETECTING", "detected": False,
                      "dispatched": False, "response_observed": False,
                      "signals": [], "elapsed_ms": 0, "url": page.url if page else ""}
            state["action_results"].append(result)
            add_log(f"Action {number}/{len(actions)}: looking for {target_label!s:.100}.",
                    event_type="ACTION_DETECT", status="RUNNING")
            # Respect the recorder's inter-click gap, with a hard upper bound.
            delay = min(max(int(action.get("gapMs") or 0), 0), 30000)
            if delay:
                add_log(f"Action {number}: recorded delay {delay} ms.",
                        event_type="ACTION_WAIT", status="INFO")
                await asyncio.sleep(delay / 1000)
                if stop_event.is_set(): break
            deadline = time.monotonic() + 12
            locator = None
            last_reason = "Target not present"
            while time.monotonic() < deadline and not stop_event.is_set():
                locator, reason = await resolve_target(action)
                if locator is not None: break
                last_reason = reason or last_reason
                await asyncio.sleep(0.3)
            if stop_event.is_set():
                result["status"] = "STOPPED"
                break
            if locator is None:
                result["status"] = "FAILED_NOT_DETECTED"
                result["error"] = last_reason
                state["failed"] += 1
                state["actions_done"] += 1
                result["elapsed_ms"] = round((time.monotonic()-action_started)*1000)
                add_log(f"Action {number}: NOT DETECTED; stopped in sequence. {last_reason}.",
                        "WARN", event_type="ACTION_DETECT", status="FAILED")
                # Fail closed: do not execute later actions out of order.
                break
            result["detected"] = True
            result["status"] = "DETECTED"
            add_log(f"Action {number}: target uniquely detected and fingerprint matched.",
                    event_type="ACTION_DETECT", status="WORKED")
            try:
                await locator.scroll_into_view_if_needed(timeout=2500)
                # Re-resolve immediately before dispatch to avoid stale elements.
                fresh, reason = await resolve_target(action)
                if fresh is None:
                    raise RuntimeError("Target changed before click: " + str(reason))
                before = await page_snapshot()
                await fresh.click(timeout=5000, no_wait_after=True)
                result["dispatched"] = True
                result["status"] = "DISPATCHED"
                state["success"] += 1  # means browser click input dispatched, not task completed
                add_log(f"Action {number}: Playwright click dispatched to verified target.",
                        event_type="ACTION_CLICK_DISPATCHED", status="WORKED")
                evidence = await observe_page_response(before, 1000)
                result["response_observed"] = evidence["observed"]
                result["signals"] = evidence["signals"]
                result["after_url"] = (evidence.get("after") or {}).get("url", page.url)
                if evidence["observed"]:
                    result["status"] = "RESPONSE_OBSERVED"
                    state["verified"] += 1
                    add_log(f"Action {number}: page response signal(s): {', '.join(evidence['signals'])}.",
                            event_type="ACTION_RESPONSE", status="WORKED")
                else:
                    result["status"] = "DISPATCHED_NO_RESPONSE_EVIDENCE"
                    add_log(f"Action {number}: click dispatched, but no generic page-response signal was observed. This is not a verified task success.",
                            "WARN", event_type="ACTION_RESPONSE", status="UNCERTAIN")
            except Exception as exc:
                result["status"] = "FAILED_CLICK"
                result["error"] = str(exc).splitlines()[0][:200]
                state["failed"] += 1
                add_log(f"Action {number}: click failed: {result['error']}.",
                        "ERROR", event_type="ACTION_CLICK", status="FAILED")
                state["actions_done"] += 1
                result["elapsed_ms"] = round((time.monotonic()-action_started)*1000)
                break
            result["elapsed_ms"] = round((time.monotonic()-action_started)*1000)
            result["url"] = page.url if page and not page.is_closed() else "page closed"
            state["actions_done"] += 1
            state["run_elapsed_ms"] = round((time.monotonic()-started)*1000)
            add_log(f"Action {number} finished: {result['status']} in {result['elapsed_ms']} ms.",
                    event_type="ACTION_FINISH", status="WORKED" if result["dispatched"] else "FAILED")
            # Small pacing delay prevents a tight burst; recorded gaps remain authoritative.
            await asyncio.sleep(0.35)
    except Exception as exc:
        add_log(f"Replay engine error: {type(exc).__name__}: {str(exc)[:220]}",
                "ERROR", event_type="REPLAY_ERROR", status="FAILED")
        state["message"] = str(exc)[:300]
    finally:
        state["run_elapsed_ms"] = round((time.monotonic()-started)*1000)
        state["replay_running"] = False
        state["current_action"] = None
        state["status"] = "READY" if page and not page.is_closed() else "STOPPED"
        if stop_event.is_set():
            state["message"] = "Replay stopped by user."
        elif state["failed"]:
            state["message"] = "Replay halted at first failed action; later actions were not attempted."
        else:
            state["message"] = "Replay sequence finished. Check response evidence per action."
        add_log(state["message"] + f" Dispatched {state['success']} · response signals {state['verified']} · failed {state['failed']} · elapsed {state['run_elapsed_ms']} ms.",
                event_type="REPLAY_FINISH", status="WORKED" if not state["failed"] else "UNCERTAIN")


class StartRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class ReplayRequest(BaseModel):
    actions: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_ACTIONS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    stop_event.set()
    if replay_task and not replay_task.done():
        replay_task.cancel()
    await cleanup_browser()


app = FastAPI(title="NEXUS Replay Engine", version=APP_VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def home():
    return FileResponse("static/index.html")


@app.get("/health")
async def health():
    return {"status":"healthy","app":"NEXUS Replay Engine","version":APP_VERSION,"browser_status":state["status"]}


@app.get("/api/data")
async def get_data(x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    return {**state, "privacy_shield":privacy_shield.snapshot()}


@app.post("/api/start")
async def start(req: StartRequest, x_nexus_key: str | None = Header(default=None)):
    global start_task
    require_key(x_nexus_key)
    try: await validate_public_url(req.url)
    except ValueError as exc: raise HTTPException(400, str(exc))
    async with operation_lock:
        if state["status"] in ("STARTING","RUNNING","REPLAYING","STOPPING"):
            raise HTTPException(409, f"Browser is currently {state['status'].lower()}.")
        await cleanup_browser()
        stop_event.clear()
        state.update(status="STARTING",url=req.url,title="",message="Opening website...",
                     actions_total=0,actions_done=0,success=0,verified=0,failed=0,current_action=None,
                     action_results=[],run_elapsed_ms=0,diagnostics={},started_at=time.time(),session_id=str(uuid.uuid4()))
        try:
            await launch_browser(req.url)
        except Exception as exc:
            await cleanup_browser()
            state.update(status="ERROR",message=f"Browser start failed: {str(exc)[:250]}")
            add_log(state["message"],"ERROR",event_type="BROWSER_START",status="FAILED")
            raise HTTPException(502,state["message"])
    return {"ok":True,"status":"READY","message":"Website loaded."}


@app.post("/api/replay")
async def replay(req: ReplayRequest, x_nexus_key: str | None = Header(default=None)):
    global replay_task
    require_key(x_nexus_key)
    if page is None or page.is_closed() or state["status"] not in ("READY",):
        raise HTTPException(409,"Open a website before starting replay.")
    if replay_task and not replay_task.done():
        raise HTTPException(409,"Replay is already running.")
    stop_event.clear()
    replay_task = asyncio.create_task(run_replay(req.actions))
    return {"ok":True,"status":"REPLAYING","actions":len(req.actions)}


@app.post("/api/stop")
async def stop(x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    stop_event.set()
    if replay_task and not replay_task.done():
        try: await asyncio.wait_for(asyncio.shield(replay_task), 3)
        except asyncio.TimeoutError: replay_task.cancel()
    await cleanup_browser()
    state.update(status="STOPPED",message="Browser stopped.",replay_running=False)
    add_log("Browser and replay stopped; resources released.",event_type="BROWSER_STOP",status="WORKED")
    return {"ok":True,"status":"STOPPED"}


@app.get("/api/diagnostics")
async def diagnostics(x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    if page is None or page.is_closed(): return state["diagnostics"]
    state["diagnostics"] = await browser_diagnostics()
    return state["diagnostics"]
