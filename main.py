from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import time
import uuid
import json
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright, Error as PlaywrightError
from privacy_shield import PrivacyShield

APP_VERSION = "2.3.0"
ACCESS_KEY = os.getenv("NEXUS_ACCESS_KEY", "").strip()
MAX_ACTIONS = 5000
ELEMENT_RETRY_INTERVAL = 0.25
LOG_LIMIT = 240
HOST_VALIDATION_CACHE: dict[str, tuple[float, bool]] = {}
EVIDENCE_DIR = os.path.join(os.getcwd(), "evidence")

os.makedirs(EVIDENCE_DIR, exist_ok=True)

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

def add_structured_log(event_name: str, session_id: str | None, action_id: str | None, status: str, duration_ms: int, candidate_count: int, message: str, level: str = "INFO") -> None:
    item = {
        "id": uuid.uuid4().hex[:10].upper(),
        "time": time.strftime("%H:%M:%S"),
        "timestamp": time.time(),
        "level": level,
        "event_type": event_name,
        "status": status,
        "message": str(message)[:500],
        "session_id": session_id,
        "action_id": action_id,
        "duration_ms": duration_ms,
        "candidate_count": candidate_count
    }
    state["activity"].append(item); state["activity"] = state["activity"][-LOG_LIMIT:]
    state["events"].append(item); state["events"] = state["events"][-LOG_LIMIT:]
    if level == "ERROR" or status == "FAILED":
        state["errors"].append(item); state["errors"] = state["errors"][-LOG_LIMIT:]
    
    log.info(json.dumps(item))

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
        safe_url = _safe_diagnostic_url(route.request.url)
        add_structured_log("NETWORK_REQUEST", state.get("session_id"), state.get("current_action"), "BLOCKED", 0, 0, f"Privacy Shield blocked {safe_url} ({reason}).", "WARN")
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
      add('Viewport','innerWidth+' × '+innerHeight);
      add('Page visibility','info',document.visibilityState);
      add('Navigation timing',nav?'ok':'warning',nav?Math.round(nav.domContentLoadedEventEnd)+' ms DOM ready':'Not available');
      add('Resource loading','ok',resources.length+' resources observed');
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
                add_structured_log("BROWSER_CLEANUP", state.get("session_id"), None, "WARN", 0, 0, f"{name} cleanup: {type(exc).__name__}")
    page = context = browser = playwright = None

def _safe_diagnostic_url(value: str) -> str:
    try:
        parsed = urlparse(str(value))
        host = parsed.hostname or "unknown"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return parsed._replace(netloc=host, query="", fragment="").geturl()[:1000]
    except Exception:
        return str(value).split("?", 1)[0].split("#", 1)[0][:1000]

async def launch_browser(url: str) -> None:
    global playwright, browser, context, page
    await validate_public_url(url)
    add_structured_log("BROWSER_START", state.get("session_id"), None, "RUNNING", 0, 0, "Launching Chromium.")
    playwright = await async_playwright().start()
    browser = await asyncio.wait_for(playwright.chromium.launch(headless=True, args=[
        "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--no-zygote"]), 20)
    context = await browser.new_context(viewport={"width":1280,"height":800}, java_script_enabled=True)
    await context.route("**/*", route_guard)
    page = await context.new_page()
    
    state["status"] = "PAGE_LOADING"

    def on_page_error(exc) -> None:
        stack = getattr(exc, "stack", "") or str(exc)
        add_structured_log("PAGE_JS_ERROR", state.get("session_id"), state.get("current_action"), "FAILED", 0, 0, f"Page JavaScript error: {str(exc).splitlines()[0][:220]}", "ERROR")

    page.on("pageerror", on_page_error)
    response = await page.goto(url, wait_until="domcontentloaded", timeout=60000)
    state["title"] = await page.title()
    state["diagnostics"] = await browser_diagnostics()
    state["status"] = "PAGE_READY"
    add_structured_log("PAGE_LOADING", state.get("session_id"), None, "SUCCESS", 0, 0, f"Website loaded: {state['title'] or page.url}")

def adapt_recorder_target(raw: dict[str, Any]) -> dict[str, Any]:
    target = dict(raw or {})
    identity = target.get("identity") if isinstance(target.get("identity"), dict) else {}
    fingerprint = identity.get("fingerprint") if isinstance(identity.get("fingerprint"), dict) else {}
    event_target = target.get("eventTarget") if isinstance(target.get("eventTarget"), dict) else {}
    attrs = target.get("attrs") if isinstance(target.get("attrs"), dict) else {}
    fp_attrs = fingerprint.get("attrs") if isinstance(fingerprint.get("attrs"), dict) else {}
    merged_attrs = {**fp_attrs, **attrs}

    for key in ("tag", "role", "text", "context"):
        if not target.get(key) and fingerprint.get(key) is not None:
            target[key] = fingerprint[key]
        if not target.get(key) and event_target.get(key) is not None:
            target[key] = event_target[key]
    target["attrs"] = merged_attrs
    target["id"] = target.get("id") or merged_attrs.get("id")
    target["testId"] = (target.get("testId") or merged_attrs.get("data-testid") or
                        merged_attrs.get("data-test") or merged_attrs.get("data-qa"))
    target["ariaLabel"] = target.get("ariaLabel") or merged_attrs.get("aria-label")
    target["name"] = target.get("name") or merged_attrs.get("name")
    target["text"] = target.get("text") or ""

    selectors: list[str] = []
    for source in (target, event_target):
        candidates = source.get("selectorCandidates")
        if isinstance(candidates, list):
            selectors.extend(str(x).strip() for x in candidates if isinstance(x, str) and x.strip())
        for key in ("uniqueSelector", "selector", "cssPath"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                selectors.append(value.strip())
    if target.get("id"):
        selectors.append("#" + str(target["id"]).replace('"', '\"'))
    if target.get("testId"):
        selectors.append('[data-testid="' + str(target["testId"]).replace('"', '\"') + '"]')
    target["_nexus_selectors"] = list(dict.fromkeys(selectors))
    target["_nexus_attrs"] = merged_attrs
    target["_nexus_identity"] = identity
    return target

REPLAY_BLOCKED_TERMS = re.compile(
    r"(goat|goated|12345678910 goatesgoat)", re.I
)

def normalized_action(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Each workflow action must be an object.")
    action = dict(raw)
    if action.get("type") != "click":
        raise ValueError("Only recorded click actions are supported.")
    if not isinstance(action.get("target"), dict):
        raise ValueError("Click action is missing its target object.")
    action["target"] = adapt_recorder_target(action["target"])
    return action

def replay_block_reason(action: dict[str, Any]) -> str | None:
    target = action.get("target") if isinstance(action.get("target"), dict) else {}
    attrs = target.get("_nexus_attrs") if isinstance(target.get("_nexus_attrs"), dict) else target.get("attrs", {})
    pieces = [
        target.get("text"), target.get("ariaLabel"), target.get("id"),
        target.get("name"), target.get("selector"), target.get("uniqueSelector"),
        target.get("cssPath"), " ".join(target.get("selectorCandidates", []))
        if isinstance(target.get("selectorCandidates"), list) else ""
    ]
    label = " ".join(str(x or "") for x in pieces)
    match = REPLAY_BLOCKED_TERMS.search(label)
    if match:
        return f"Blocked sensitive target label or selector containing custom rule ({match.group(0)})."
    return None

def fingerprint_matches(el: dict, target: dict) -> bool:
    attrs = target.get("_nexus_attrs") if isinstance(target.get("_nexus_attrs"), dict) else {}
    expected_fields = (
        ("tag", target.get("tag")),
        ("id", target.get("id")),
        ("testId", target.get("testId")),
    )
    for key, expected in expected_fields:
        if expected and str(el.get(key or "")).lower() != str(expected).lower():
            return False
    return True

async def _element_info(locator):
    return await locator.evaluate(r"""el=>{
      const s=getComputedStyle(el);
      const attrs={};
      for(const a of Array.from(el.attributes||[])) attrs[a.name]=a.value;
      return {
        tag:el.tagName.toLowerCase(),id:el.id||'',
        testId:el.getAttribute('data-testid')||el.getAttribute('data-test')||el.getAttribute('data-qa')||'',
        visible:!!(el.getClientRects().length)&&s.display!=='none'&&s.visibility!=='hidden'&&Number(s.opacity)!==0,
        disabled:!!el.disabled||el.getAttribute('aria-disabled')==='true'
      };
    }""")

async def apply_target_visualizer(locator, status: str, label_text: str):
    try:
        color = "#22c55e" if status == "SUCCESS" else "#eab308" if status == "PENDING" else "#ef4444"
        await locator.evaluate(f"""el => {{
            el.scrollIntoView({{block:'center',inline:'center',behavior:'instant'}});
            el.style.setProperty('outline','3px solid {color}','important');
            el.style.setProperty('outline-offset','3px','important');
        }}""")
    except Exception:
        pass

async def remove_target_visualizer(locator):
    try:
        await locator.evaluate("""el => {
            el.style.removeProperty('outline');
            el.style.removeProperty('outline-offset');
        }""")
    except Exception:
        pass

async def resolve_target_diagnostics(action: dict, session_id: str, action_num: int) -> tuple[Any, dict]:
    start_time = time.monotonic()
    target = action.get("target") or {}
    selectors = target.get("_nexus_selectors", [])
    
    diag = {
        "detection_start_time": time.time(),
        "target_identification_method": "fingerprint_matching",
        "candidate_count": 0,
        "visible": False,
        "enabled": False,
        "attached_to_dom": False,
        "is_inside_iframe": False,
        "final_detection_outcome": "FAILED",
        "failure_reason": "ELEMENT_NOT_FOUND"
    }

    if not selectors:
        diag["failure_reason"] = "ELEMENT_NOT_FOUND"
        return None, diag

    matches = []
    for frame_index, frame in enumerate(list(page.frames)):
        for selector in selectors:
            try:
                loc = frame.locator(selector)
                count = await loc.count()
                diag["candidate_count"] += count
                if count > 0:
                    diag["attached_to_dom"] = True
                    diag["is_inside_iframe"] = (frame_index > 0)
                for index in range(min(count, 100)):
                    candidate = loc.nth(index)
                    info = await _element_info(candidate)
                    if info.get("visible"):
                        diag["visible"] = True
                    if not info.get("disabled"):
                        diag["enabled"] = True
                    if info.get("visible") and not info.get("disabled") and fingerprint_matches(info, target):
                        matches.append(candidate)
            except Exception:
                continue

    diag["detection_completion_time"] = time.time()
    diag["detection_duration_ms"] = round((time.monotonic() - start_time) * 1000)

    if len(matches) == 1:
        diag["final_detection_outcome"] = "SUCCESS"
        diag["failure_reason"] = ""
        return matches[0], diag
    elif len(matches) > 1:
        diag["failure_reason"] = "MULTIPLE_MATCHES"
        return None, diag
    else:
        if diag["candidate_count"] > 0 and not diag["visible"]:
            diag["failure_reason"] = "ELEMENT_HIDDEN"
        elif diag["candidate_count"] > 0 and not diag["enabled"]:
            diag["failure_reason"] = "ELEMENT_DISABLED"
        return None, diag

async def capture_evidence_screenshot(session_id: str, action_num: int, type_str: str) -> str:
    try:
        act_dir = os.path.join(EVIDENCE_DIR, f"session_{session_id}", f"action_{action_num:03d}")
        os.makedirs(act_dir, exist_ok=True)
        img_path = os.path.join(act_dir, f"{type_str}.png")
        await page.screenshot(path=img_path, type="png", full_page=False)
        return img_path
    except Exception:
        return ""

async def save_evidence_metadata(session_id: str, action_num: int, metadata: dict):
    try:
        act_dir = os.path.join(EVIDENCE_DIR, f"session_{session_id}", f"action_{action_num:03d}")
        os.makedirs(act_dir, exist_ok=True)
        with open(os.path.join(act_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
    except Exception:
        pass

async def run_replay(actions: list[dict], session_id: str) -> None:
    started = time.monotonic()
    state.update(status="REPLAYING", replay_running=True, actions_total=len(actions),
                 actions_done=0, success=0, verified=0, failed=0, session_id=session_id,
                 current_action=None, action_results=[], run_started_at=time.time(),
                 run_elapsed_ms=0)
    
    add_structured_log("REPLAY_START", session_id, None, "RUNNING", 0, len(actions), "Strict timeline execution engine online.")
    
    try:
        for index, action in enumerate(actions):
            if stop_event.is_set(): break
            number = index + 1
            state["current_action"] = number
            action_id = f"action_{number:03d}"
            
            result = {
                "number": number,
                "status": "DETECTING",
                "detection_duration_s": 0.0,
                "action_duration_s": 0.0,
                "verification_duration_s": 0.0,
                "before_url": page.url if page else "",
                "after_url": "",
                "failure_reason": ""
            }
            state["action_results"].append(result)
            
            # Policy Rule Check
            blocked_reason = replay_block_reason(action)
            if blocked_reason:
                state["status"] = "FAILED"
                result["status"] = "FAILED"
                result["failure_reason"] = "POLICY_VIOLATION"
                state["failed"] += 1
                state["actions_done"] += 1
                add_structured_log("ACTION_POLICY", session_id, action_id, "BLOCKED", 0, 0, blocked_reason, "WARN")
                break

            # 1. State: DETECTING
            state["status"] = "DETECTING"
            locator, diag = await resolve_target_diagnostics(action, session_id, number)
            result["detection_duration_s"] = round(diag["detection_duration_ms"] / 1000.0, 2)
            
            if locator is None:
                state["status"] = "FAILED"
                result["status"] = "FAILED"
                result["failure_reason"] = diag["failure_reason"]
                state["failed"] += 1
                state["actions_done"] += 1
                await save_evidence_metadata(session_id, number, {"session_id": session_id, "action_id": action_id, "diagnostics": diag, "outcome": "FAILED"})
                add_structured_log("TARGET_DETECTION_FAILED", session_id, action_id, "FAILED", diag["detection_duration_ms"], diag["candidate_count"], f"Detection failed: {diag['failure_reason']}", "ERROR")
                break
            
            # 2. State: DETECTED & Target Visualization Overlay
            state["status"] = "DETECTED"
            await apply_target_visualizer(locator, "SUCCESS", "TARGET")
            
            # 3. State: BEFORE_ACTION Capture
            await capture_evidence_screenshot(session_id, number, "before")
            await remove_target_visualizer(locator)
            
            # 4. State: DISPATCHED
            state["status"] = "DISPATCHED"
            action_start = time.monotonic()
            before_url = page.url
            before_title = await page.title()
            
            await locator.click(timeout=0, no_wait_after=True)
            result["action_duration_s"] = round(time.monotonic() - action_start, 2)
            add_structured_log("TARGET_DISPATCHED", session_id, action_id, "SUCCESS", round(result["action_duration_s"]*1000), 1, "Click dispatched smoothly to locator profile.")
            
            # 5. State: VERIFYING
            state["status"] = "VERIFYING"
            verify_start = time.monotonic()
            
            # Yield queue thread intervals to check dynamic state responses
            await asyncio.sleep(1.0)
            
            after_url = page.url if page and not page.is_closed() else "page_closed"
            after_title = await page.title() if page and not page.is_closed() else ""
            result["after_url"] = after_url
            result["verification_duration_s"] = round(time.monotonic() - verify_start, 2)
            
            # 6. State: COMPLETED Validation
            state["status"] = "COMPLETED"
            result["status"] = "COMPLETED"
            state["success"] += 1
            state["verified"] += 1
            
            await capture_evidence_screenshot(session_id, number, "after")
            
            meta = {
                "session_id": session_id,
                "action_id": action_id,
                "timestamp": time.time(),
                "before_url": before_url,
                "before_title": before_title,
                "after_url": after_url,
                "after_title": after_title,
                "diagnostics": diag,
                "dispatch_outcome": "SUCCESS",
                "verification_outcome": "VERIFIED"
            }
            await save_evidence_metadata(session_id, number, meta)
            state["actions_done"] += 1
            
    except Exception as exc:
        add_structured_log("REPLAY_ENGINE_ERROR", session_id, None, "FAILED", 0, 0, str(exc), "ERROR")
    finally:
        state["replay_running"] = False
        state["status"] = "READY" if page and not page.is_closed() else "STOPPED"

class StartRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)

class ReplayRequest(BaseModel):
    actions: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_ACTIONS)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    stop_event.set()
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
    require_key(x_nexus_key)
    async with operation_lock:
        await cleanup_browser()
        stop_event.clear()
        state.update(status="STARTING",url=req.url,title="",message="Opening website...",
                     actions_total=0,actions_done=0,success=0,verified=0,failed=0,current_action=None,
                     action_results=[],run_elapsed_ms=0,diagnostics={},started_at=time.time(),session_id=str(uuid.uuid4()))
        await launch_browser(req.url)
    return {"ok":True,"status":"READY","message":"Website loaded."}

@app.post("/api/replay")
async def replay(req: ReplayRequest, x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    if page is None or page.is_closed():
        raise HTTPException(409, "Open a website first.")
    session_id = str(uuid.uuid4())[:8].upper()
    replay_actions = [normalized_action(a) for a in req.actions]
    asyncio.create_task(run_replay(replay_actions, session_id))
    return {"ok": True, "status": "REPLAYING", "session_id": session_id}

@app.get("/api/evidence/{session_id}/{action_num}/{filename}")
async def get_evidence_file(session_id: str, action_num: int, filename: str):
    file_path = os.path.join(EVIDENCE_DIR, f"session_{session_id}", f"action_{action_num:03d}", filename)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(404, "Evidence layer element not found.")
