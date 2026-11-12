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
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright, Error as PlaywrightError

APP_VERSION = "2.3.0"
ACCESS_KEY = os.getenv("NEXUS_ACCESS_KEY", "").strip()
MAX_ACTIONS = 5000
ELEMENT_RETRY_INTERVAL = 0.25  # responsive, low-CPU target polling
ELEMENT_WAIT_TIMEOUT_SECONDS = max(3, min(120, int(os.getenv("NEXUS_ELEMENT_WAIT_SECONDS", "20"))))
MAX_SELECTOR_CANDIDATES = 250
LOG_LIMIT = 240
HOST_VALIDATION_CACHE: dict[str, tuple[float, bool]] = {}

state: dict[str, Any] = {
    "status": "STOPPED", "url": "", "title": "", "message": "Ready",
    "started_at": None, "actions_total": 0, "actions_done": 0,
    "success": 0, "failed": 0, "current_action": None,
    "diagnostics": {}, "activity": [], "errors": [], "events": [],
    "detection_metrics": {"attempts": 0, "elapsed_ms": 0, "last_scan_ms": 0},
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


def add_log(message: str, level: str = "INFO", *, event_type: str = "LOG",
            status: str = "INFO", details: dict[str, Any] | None = None) -> None:
    item = {"id": uuid.uuid4().hex[:10].upper(), "time": time.strftime("%H:%M:%S"),
            "timestamp": time.time(), "level": level, "event_type": event_type,
            "status": status, "message": str(message)[:500]}
    if details:
        item["details"] = {str(k)[:60]: str(v)[:1200] for k, v in list(details.items())[:12]}
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


async def route_public_url_guard(route) -> None:
    """Keep SSRF protection for every browser request without tracker blocking."""
    request_url = route.request.url
    try:
        await validate_public_url(request_url)
    except ValueError as exc:
        safe_url = _safe_diagnostic_url(request_url)
        add_log(f"Blocked non-public or invalid network request {safe_url}: {exc}",
                "WARN", event_type="NETWORK_REQUEST", status="BLOCKED",
                details={"url": safe_url, "resource_type": route.request.resource_type,
                         "decision": "BLOCKED", "reason": str(exc)})
        await route.abort()
        return
    await route.continue_()


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


def _safe_diagnostic_url(value: str) -> str:
    try:
        parsed = urlparse(str(value))
        host = parsed.hostname or "unknown"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return parsed._replace(netloc=host, query="", fragment="").geturl()[:1000]
    except Exception:
        return str(value).split("?", 1)[0].split("#", 1)[0][:1000]


async def _record_response(response) -> None:
    try:
        request = response.request
        resource_type = request.resource_type
        status_code = response.status
        headers = response.headers or {}
        content_type = headers.get("content-type", "missing").split(";", 1)[0].strip().lower()
        url = _safe_diagnostic_url(response.url)
        is_script = resource_type == "script"
        if not is_script and status_code < 400:
            return
        details = {"url": url, "resource_type": resource_type,
                   "http_status": status_code, "content_type": content_type}
        if is_script:
            accepted = {"application/javascript", "text/javascript",
                        "application/ecmascript", "text/ecmascript",
                        "application/x-javascript"}
            if content_type not in accepted:
                add_log(f"Script response has unexpected MIME type: {url} · HTTP {status_code} · {content_type}.",
                        "ERROR", event_type="SCRIPT_MIME_MISMATCH", status="FAILED",
                        details=details)
                return
        add_log(f"HTTP {status_code} response: {url} · {resource_type} · {content_type}.",
                "ERROR" if status_code >= 400 else "INFO",
                event_type="RESOURCE_RESPONSE", status="FAILED" if status_code >= 400 else "INFO",
                details=details)
    except Exception as exc:
        add_log(f"Could not record response diagnostics: {type(exc).__name__}.",
                "WARN", event_type="DIAGNOSTIC_HANDLER", status="UNCERTAIN")


async def launch_browser(url: str) -> None:
    global playwright, browser, context, page
    await validate_public_url(url)
    add_log("Launching Chromium.", event_type="BROWSER_START", status="RUNNING")
    playwright = await async_playwright().start()
    browser = await asyncio.wait_for(playwright.chromium.launch(headless=True, args=[
        "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--no-zygote"]), 20)
    context = await browser.new_context(viewport={"width":1280,"height":800}, java_script_enabled=True)
    page = await context.new_page()

    def on_page_error(exc) -> None:
        stack = getattr(exc, "stack", "") or str(exc)
        add_log(f"Page JavaScript error: {str(exc).splitlines()[0][:220]}",
                "ERROR", event_type="PAGE_JS_ERROR", status="FAILED",
                details={"message": str(exc), "stack": stack[:4000], "page_url": _safe_diagnostic_url(page.url)})

    def on_console(msg) -> None:
        if msg.type != "error":
            return
        location = getattr(msg, "location", {}) or {}
        add_log(f"Console error: {msg.text[:220]}",
                "ERROR", event_type="CONSOLE_ERROR", status="FAILED",
                details={"message": msg.text, "url": _safe_diagnostic_url(location.get("url", "")),
                         "line": location.get("lineNumber", ""), "column": location.get("columnNumber", ""),
                         "page_url": _safe_diagnostic_url(page.url)})

    def on_request_failed(req) -> None:
        failure = getattr(req, "failure", None)
        add_log(f"Request failed: {_safe_diagnostic_url(req.url)} · {failure or 'unknown'}",
                "WARN", event_type="NETWORK_REQUEST", status="FAILED",
                details={"url": _safe_diagnostic_url(req.url), "resource_type": req.resource_type,
                         "method": req.method, "failure": failure or "unknown",
                         "page_url": _safe_diagnostic_url(page.url)})

    page.on("pageerror", on_page_error)
    page.on("console", on_console)
    page.on("requestfailed", on_request_failed)
    page.on("response", lambda response: asyncio.create_task(_record_response(response)))
    add_log("Opening requested website.", event_type="PAGE_NAVIGATION", status="RUNNING")
    response = await page.goto(url, wait_until="domcontentloaded", timeout=60000)
    # Avoid waiting for images, fonts and third-party resources after DOM is ready.
    # Late targets are resolved on demand by wait_for_recorded_target().
    state["title"] = await page.title()
    state["diagnostics"] = await browser_diagnostics()
    add_log(f"Website loaded: {state['title'] or page.url} · HTTP {response.status if response else 'unknown'}",
            event_type="PAGE_LOADING", status="WORKED")
    state.update(status="READY", message="Website ready. Load a JSON recording to replay.")


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
    if target.get("ariaLabel"):
        selectors.append('[aria-label="' + str(target["ariaLabel"]).replace('"', '\"') + '"]')
    if target.get("name"):
        selectors.append('[name="' + str(target["name"]).replace('"', '\"') + '"]')
    target["_nexus_selectors"] = list(dict.fromkeys(selectors))
    target["_nexus_attrs"] = merged_attrs
    target["_nexus_identity"] = identity
    return target


# 🎯 REPLAY BLOCKED TERMS MODIFIED ACCORDING TO USER REQUIREMENTS
REPLAY_BLOCKED_TERMS = re.compile(
    r"\b(goat|goated|12345678910 goatesgoat)\b", re.I
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
    try:
        gap_ms = int(action.get("gapMs") or 0)
    except (TypeError, ValueError, OverflowError):
        gap_ms = 0
    action["gapMs"] = min(600_000, max(0, gap_ms))
    return action


def replay_block_reason(action: dict[str, Any]) -> str | None:
    target = action.get("target") if isinstance(action.get("target"), dict) else {}
    attrs = target.get("_nexus_attrs") if isinstance(target.get("_nexus_attrs"), dict) else target.get("attrs", {})
    pieces = [
        target.get("text"), target.get("ariaLabel"), target.get("id"),
        target.get("name"), target.get("selector"), target.get("uniqueSelector"),
        target.get("cssPath"), " ".join(target.get("selectorCandidates", []))
        if isinstance(target.get("selectorCandidates"), list) else "",
        attrs.get("data-testid"), attrs.get("data-test"), attrs.get("data-qa"),
        attrs.get("aria-label"), attrs.get("href"),
    ]
    label = " ".join(str(x or "") for x in pieces)
    match = REPLAY_BLOCKED_TERMS.search(label)
    if match:
        return f"Blocked sensitive target label or selector containing custom rules ({match.group(0)})."
    return None


def _normal_text(value: Any) -> str:
    return " ".join(str(value or "").split()).casefold()


async def inspect_workflow_targets(actions: list[dict]) -> list[dict]:
    reports = []
    for number, action in enumerate(actions, 1):
        scan_started = time.monotonic()
        target = adapt_recorder_target(action.get("target") or {})
        selectors = target.get("_nexus_selectors", [])
        candidates, seen = [], set()
        for frame_index, frame in enumerate(list(page.frames)):
            for selector in selectors:
                try:
                    loc = frame.locator(selector)
                    count = min(await loc.count(), MAX_SELECTOR_CANDIDATES)
                    for idx in range(count):
                        el = loc.nth(idx)
                        info = await _element_info(el)
                        key = (frame_index, info.get("domPath"))
                        if key in seen:
                            continue
                        seen.add(key)
                        if fingerprint_matches(info, target):
                            candidates.append({"frame": frame_index, "selector": selector, "index": idx,
                                               **info, "fingerprint_match": True,
                                               "context_score": _context_score(info, target)})
                except Exception:
                    continue
        eligible = [c for c in candidates if c["visible"] and not c["disabled"]]
        if len(eligible) > 1:
            best_score = max(c["context_score"] for c in eligible)
            best = [c for c in eligible if c["context_score"] == best_score]
            if best_score > 0 and len(best) == 1:
                eligible = best
        highlighted = False
        if len(eligible) == 1:
            c = eligible[0]
            try:
                frame = page.frames[c["frame"]]
                loc = frame.locator(c["selector"]).nth(c["index"])
                await loc.evaluate("""el => {
                  el.scrollIntoView({block:'center',inline:'center',behavior:'instant'});
                  el.style.setProperty('outline','3px solid #22c55e','important');
                  el.style.setProperty('outline-offset','3px','important');
                }""")
                highlighted = True
            except Exception:
                pass
        reports.append({
            "number": number,
            "scan_elapsed_ms": round((time.monotonic() - scan_started) * 1000),
            "label": str(target.get("text") or target.get("ariaLabel") or target.get("id") or target.get("tag") or "target")[:100],
            "candidate_count": len(candidates),
            "visible_enabled_count": len(eligible),
            "unique_target": len(eligible) == 1,
            "highlighted": highlighted,
            "candidates": [{k:v for k,v in c.items() if k not in ("index", "ancestors", "attrs")} for c in candidates[:12]],
            "message": ("Unique visible candidate highlighted" if highlighted else
                        "No visible candidate" if not eligible else
                        "Multiple visible candidates; no element highlighted")
        })
    return reports


def fingerprint_matches(el: dict, target: dict) -> bool:
    """Tolerant, weighted PEI matching.

    A few independent signals can identify a target; stale classes or changed
    optional attributes no longer veto an otherwise good match. The minimum
    score and anchor requirement prevent tag-only/weak matches from clicking.
    Ambiguous matches are still rejected by resolve_target().
    """
    attrs = target.get("_nexus_attrs") if isinstance(target.get("_nexus_attrs"), dict) else {}
    live_attrs = el.get("attrs") if isinstance(el.get("attrs"), dict) else {}
    score = 0
    strong_anchor = False

    # Strong identity signals. Missing or changed values reduce the score,
    # rather than making the whole fingerprint fail immediately.
    identity_fields = (
        ("id", target.get("id") or attrs.get("id"), 10),
        ("testId", target.get("testId") or attrs.get("data-testid") or attrs.get("data-test") or attrs.get("data-qa"), 10),
        ("ariaLabel", target.get("ariaLabel") or attrs.get("aria-label"), 8),
        ("name", target.get("name") or attrs.get("name"), 7),
    )
    for key, expected, weight in identity_fields:
        if expected:
            actual = el.get(key)
            if actual and _normal_text(actual) == _normal_text(expected):
                score += weight
                strong_anchor = True

    expected_tag = _normal_text(target.get("tag"))
    actual_tag = _normal_text(el.get("tag"))
    tag_match = bool(expected_tag and actual_tag and expected_tag == actual_tag)
    if tag_match:
        score += 2

    expected_role = _normal_text(target.get("role") or attrs.get("role"))
    actual_role = _normal_text(el.get("role"))
    if expected_role and actual_role and expected_role == actual_role:
        score += 3

    expected_text = _normal_text(target.get("text"))
    actual_text = _normal_text(el.get("text"))
    text_match = False
    if expected_text and actual_text:
        if expected_text == actual_text:
            score += 7
            text_match = True
        elif len(expected_text) >= 3 and expected_text in actual_text:
            score += 5
            text_match = True
        elif len(actual_text) >= 3 and actual_text in expected_text:
            score += 3
            text_match = True

    # Optional attributes: matching adds evidence; changed values do not veto
    # other independent matches (dynamic hrefs/placeholders are common).
    for attr_name, weight in (("type", 3), ("placeholder", 4), ("title", 3),
                              ("alt", 3), ("href", 4)):
        expected = attrs.get(attr_name)
        actual = live_attrs.get(attr_name)
        if expected and actual and _normal_text(expected) == _normal_text(actual):
            score += weight

    expected_classes = set(str(attrs.get("class") or "").split())
    actual_classes = set(str(live_attrs.get("class") or "").split())
    if expected_classes and actual_classes:
        score += min(2, len(expected_classes & actual_classes))

    expected_data = attrs.get("dataAttributes") if isinstance(attrs.get("dataAttributes"), dict) else {}
    data_matches = 0
    for key, value in expected_data.items():
        actual = live_attrs.get("data-" + str(key).removeprefix("data-"))
        if actual is not None and _normal_text(actual) == _normal_text(value):
            data_matches += 1
    score += min(4, data_matches * 2)

    # Do not accept generic elements based only on a tag/role or one weak
    # attribute. Require either a strong identity, or text + tag, or several
    # independent secondary signals.
    has_anchor = strong_anchor or (text_match and tag_match) or score >= 10
    return score >= 7 and has_anchor


def _context_score(el: dict, target: dict) -> int:
    expected_context = target.get("context") if isinstance(target.get("context"), dict) else {}
    expected = expected_context.get("ancestors") if isinstance(expected_context.get("ancestors"), list) else []
    actual = el.get("ancestors") if isinstance(el.get("ancestors"), list) else []
    score = 0
    for i, ancestor in enumerate(expected[:4]):
        if i >= len(actual):
            break
        got = actual[i]
        if ancestor.get("tag") and ancestor.get("tag") == got.get("tag"):
            score += 3
        if ancestor.get("id") and ancestor.get("id") == got.get("id"):
            score += 12
        exp_text = _normal_text(ancestor.get("text"))
        got_text = _normal_text(got.get("text"))
        if exp_text and len(exp_text) <= 100 and exp_text == got_text:
            score += 2
    return score


async def _element_info(locator):
    return await locator.evaluate(r"""el=>{
      const s=getComputedStyle(el);
      const attrs={};
      for(const a of Array.from(el.attributes||[])) attrs[a.name]=a.value;
      const ancestors=[]; let p=el.parentElement;
      const path=[]; let node=el;
      while(node && node.nodeType===1){
        const siblings=node.parentElement ? Array.from(node.parentElement.children).filter(x=>x.tagName===node.tagName) : [node];
        path.unshift(node.tagName.toLowerCase()+':'+siblings.indexOf(node));
        node=node.parentElement;
      }
      while(p && ancestors.length<6){
        ancestors.push({tag:p.tagName.toLowerCase(),id:p.id||'',text:(p.innerText||p.textContent||'').replace(/\s+/g,' ').trim().slice(0,160)});
        p=p.parentElement;
      }
      const implicitRole = el.getAttribute('role') || ({BUTTON:'button',A:'link',SELECT:'combobox',TEXTAREA:'textbox',INPUT:({button:'button',submit:'button',checkbox:'checkbox',radio:'radio',search:'searchbox',email:'textbox',text:'textbox',url:'textbox',tel:'textbox',number:'spinbutton'})[el.type]||'textbox'})[el.tagName] || '';
      return {domPath:path.join('>'),tag:el.tagName.toLowerCase(),id:el.id||'',role:implicitRole,
        testId:el.getAttribute('data-testid')||el.getAttribute('data-test')||el.getAttribute('data-qa')||'',
        ariaLabel:el.getAttribute('aria-label')||'',name:el.getAttribute('name')||'',
        text:(el.innerText||el.textContent||el.value||el.getAttribute('aria-label')||'').replace(/\s+/g,' ').trim(),
        attrs,ancestors,
        visible:!!(el.getClientRects().length)&&s.display!=='none'&&s.visibility!=='hidden'&&Number(s.opacity)!==0,
        disabled:!!el.disabled||el.getAttribute('aria-disabled')==='true'};
    }""")


async def resolve_target(action: dict):
    target = adapt_recorder_target(action.get("target") or {})
    selectors = target.get("_nexus_selectors", [])
    if not selectors:
        return None, "Recording contains no usable selector or CSS path"
    matches = []
    seen = set()
    for frame_index, frame in enumerate(list(page.frames)):
        for selector in selectors:
            try:
                loc = frame.locator(selector)
                count = min(await loc.count(), MAX_SELECTOR_CANDIDATES)
                for index in range(count):
                    candidate = loc.nth(index)
                    info = await _element_info(candidate)
                    key = (frame_index, info.get("domPath"))
                    if key in seen:
                        continue
                    seen.add(key)
                    if info.get("visible") and not info.get("disabled") and fingerprint_matches(info, target):
                        matches.append((candidate, _context_score(info, target), frame_index, selector, info))
            except Exception:
                continue
    if not matches:
        return None, "No visible, enabled element currently matches the recorded PEI identity"
    unique = {}
    for item in matches:
        loc, score, frame_index, selector, info = item
        key = (frame_index, info.get("domPath"))
        if key not in unique or score > unique[key][1]:
            unique[key] = item
    matches = list(unique.values())
    if len(matches) == 1:
        return matches[0][0], None
    best_score = max(x[1] for x in matches)
    best = [x for x in matches if x[1] == best_score]
    if best_score > 0 and len(best) == 1:
        return best[0][0], None
    return None, f"Ambiguous recorded identity: {len(matches)} visible matching elements; refusing to guess"


async def _wait_recorded_gap(action: dict) -> bool:
    raw = action.get("gapMs", 0)
    try:
        delay_ms = max(0, int(raw or 0))
    except (TypeError, ValueError, OverflowError):
        delay_ms = 0
    if not delay_ms:
        return not stop_event.is_set()
    add_log(f"Respecting recorded inter-action gap: {delay_ms} ms.",
            event_type="ACTION_WAIT", status="INFO")
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=delay_ms / 1000)
        return False
    except asyncio.TimeoutError:
        return not stop_event.is_set()


async def wait_for_recorded_target(action: dict):
    last_reason = "Target not present yet"
    attempts = 0
    started = time.monotonic()
    while not stop_event.is_set():
        if page is None or page.is_closed():
            return None, "Browser page closed while waiting for the recorded target"
        scan_started = time.monotonic()
        locator, reason = await resolve_target(action)
        scan_ms = round((time.monotonic() - scan_started) * 1000)
        attempts += 1
        last_reason = reason or last_reason
        state["detection_metrics"] = {
            "attempts": attempts,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "last_scan_ms": scan_ms,
        }
        if locator is not None:
            return locator, None
        if time.monotonic() - started >= ELEMENT_WAIT_TIMEOUT_SECONDS:
            return None, (f"Target was not found after {ELEMENT_WAIT_TIMEOUT_SECONDS}s "
                          f"({attempts} scans). Last result: {last_reason}")
        # Keep cancellation responsive without repeatedly hammering the DOM.
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=ELEMENT_RETRY_INTERVAL)
        except asyncio.TimeoutError:
            pass
    return None, "Replay stopped while waiting for the recorded target: " + last_reason


async def execute_action(action: dict, number: int) -> tuple[bool, str]:
    if action.get("type") != "click":
        return False, f"Unsupported action type: {action.get('type')}"
    action_url = action.get("url")
    if action_url:
        try:
            expected = urlparse(action_url)
            current = urlparse(page.url)
            if expected.scheme not in ("http", "https") or expected.netloc != current.netloc:
                return False, "Recorded action origin does not match current page"
        except Exception:
            return False, "Invalid recorded action URL"
    if not await _wait_recorded_gap(action):
        return False, "Replay stopped during recorded gap"
    locator, reason = await wait_for_recorded_target(action)
    if locator is None:
        return False, reason or "Replay stopped before target was found"
    try:
        await locator.scroll_into_view_if_needed(timeout=0)
        await locator.click(timeout=0, no_wait_after=True)
        return True, "Click dispatched to recorded target"
    except Exception as exc:
        return False, str(exc).splitlines()[0][:220]


async def observe_page_response(before: dict[str, Any], wait_ms: int = 900) -> dict[str, Any]:
    if wait_ms > 0:
        await asyncio.sleep(wait_ms / 1000)
    else:
        await asyncio.sleep(0)
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
    started = time.monotonic()
    state.update(status="REPLAYING", replay_running=True, actions_total=len(actions),
                 actions_done=0, success=0, verified=0, failed=0,
                 current_action=None, action_results=[], run_started_at=time.time(),
                 run_elapsed_ms=0)
    add_log(f"Replay started: {len(actions)} actions; strict recorded order enabled.",
            event_type="REPLAY_START", status="RUNNING")
    try:
        first_url = actions[0].get("url") if actions else None
        if first_url:
            recorded = urlparse(str(first_url))
            current = urlparse(page.url)
            if recorded.scheme in ("http", "https") and recorded.netloc == current.netloc and page.url != first_url:
                add_log("Opening the first action's recorded page URL.",
                        event_type="PAGE_NAVIGATION", status="RUNNING")
                response = await page.goto(str(first_url), wait_until="domcontentloaded", timeout=60000)
                add_log(f"Recorded page ready · HTTP {response.status if response else 'unknown'}.",
                        event_type="PAGE_NAVIGATION", status="WORKED")
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
                      "signals": [], "elapsed_ms": 0,
                      "gap_ms": max(0, int(action.get("gapMs") or 0)),
                      "url": page.url if page else ""}
            state["action_results"].append(result)
            add_log(f"Action {number}/{len(actions)}: looking for {target_label!s:.100}.",
                    event_type="ACTION_DETECT", status="RUNNING")
            blocked_reason = replay_block_reason(action)
            if blocked_reason:
                result["status"] = "BLOCKED_BY_POLICY"
                result["error"] = blocked_reason
                state["failed"] += 1
                state["actions_done"] += 1
                result["elapsed_ms"] = round((time.monotonic()-action_started)*1000)
                add_log(f"Action {number}: {blocked_reason}",
                        "WARN", event_type="ACTION_POLICY", status="BLOCKED")
                break
            if not await _wait_recorded_gap(action):
                result["status"] = "STOPPED"
                break
            state["detection_metrics"] = {"attempts": 0, "elapsed_ms": 0, "last_scan_ms": 0}
            locator, last_reason = await wait_for_recorded_target(action)
            result["detection"] = dict(state["detection_metrics"])
            if stop_event.is_set():
                result["status"] = "STOPPED"
                result["error"] = last_reason
                break
            if locator is None:
                result["status"] = "FAILED_NOT_DETECTED"
                result["error"] = last_reason or "Browser page unavailable"
                state["failed"] += 1
                state["actions_done"] += 1
                result["elapsed_ms"] = round((time.monotonic()-action_started)*1000)
                add_log(f"Action {number}: target unavailable. {result['error']}.",
                        "WARN", event_type="ACTION_DETECT", status="FAILED")
                break
            result["detected"] = True
            result["status"] = "DETECTED"
            add_log(f"Action {number}: target uniquely detected and fingerprint matched.",
                    event_type="ACTION_DETECT", status="WORKED")
            try:
                await locator.scroll_into_view_if_needed(timeout=0)
                fresh, reason = await resolve_target(action)
                if fresh is None:
                    raise RuntimeError("Target changed before click: " + str(reason))
                before = await page_snapshot()
                await fresh.click(timeout=0, no_wait_after=True)
                result["dispatched"] = True
                result["status"] = "DISPATCHED"
                state["success"] += 1
                add_log(f"Action {number}: Playwright click dispatched to verified target.",
                        event_type="ACTION_CLICK_DISPATCHED", status="WORKED")
                evidence = await observe_page_response(before, 0)
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
    return {"status":"healthy","app":"NEXUS Replay Engine","version":APP_VERSION,"recorder_compatibility":["nexus-recorder-3.x","pei-v3.2"],"browser_status":state["status"]}


@app.get("/api/data")
async def get_data(x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    return state


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
                     action_results=[],run_elapsed_ms=0,diagnostics={},
                     detection_metrics={"attempts":0,"elapsed_ms":0,"last_scan_ms":0},
                     started_at=time.time(),session_id=str(uuid.uuid4()))
        try:
            await launch_browser(req.url)
        except Exception as exc:
            await cleanup_browser()
            state.update(status="ERROR",message=f"Browser start failed: {str(exc)[:250]}")
            add_log(state["message"],"ERROR",event_type="BROWSER_START",status="FAILED")
            raise HTTPException(502,state["message"])
    return {"ok":True,"status":"READY","message":"Website loaded."}


@app.post("/api/inspect")
async def inspect_workflow(req: ReplayRequest, x_nexus_key: str | None = Header(default=None)):
    require_key(x_nexus_key)
    if page is None or page.is_closed() or state["status"] not in ("READY", "REPLAYING"):
        raise HTTPException(409, "Open a website before inspecting workflow targets.")
    if state["replay_running"]:
        raise HTTPException(409, "Cannot inspect while replay is running.")
    for index, action in enumerate(req.actions, 1):
        if not isinstance(action, dict) or action.get("type") != "click" or not isinstance(action.get("target"), dict):
            raise HTTPException(422, f"Action {index} must be a click action with a target object.")
    try:
        reports = await inspect_workflow_targets([normalized_action(a) for a in req.actions])
        return {"ok": True, "inspection": reports}
    except Exception as exc:
        add_log(f"Workflow inspection failed: {type(exc).__name__}: {str(exc)[:180]}",
                "ERROR", event_type="WORKFLOW_INSPECT", status="FAILED")
        raise HTTPException(500, "Workflow inspection failed. Check the activity log.")


@app.post("/api/replay")
async def replay(req: ReplayRequest, x_nexus_key: str | None = Header(default=None)):
    global replay_task
    require_key(x_nexus_key)
    if page is None or page.is_closed() or state["status"] != "READY":
        raise HTTPException(409, "Open a website and wait until it is READY before replaying.")
    if replay_task and not replay_task.done():
        raise HTTPException(409, "A replay is already running.")
    current_origin = urlparse(page.url)
    for index, action in enumerate(req.actions, 1):
        if not isinstance(action, dict) or action.get("type") != "click" or not isinstance(action.get("target"), dict):
            raise HTTPException(422, f"Action {index} must be a click action with a target object.")
        recorded_url = action.get("url")
        if recorded_url:
            parsed = urlparse(str(recorded_url))
            if parsed.scheme not in ("http", "https") or parsed.netloc != current_origin.netloc:
                raise HTTPException(422, f"Action {index} was recorded on a different website origin.")
    stop_event.clear()
    replay_actions = [normalized_action(a) for a in req.actions]
    replay_task = asyncio.create_task(run_replay(replay_actions), name="nexus-replay")
    add_log(f"Replay queued: {len(req.actions)} validated click actions.",
            event_type="REPLAY_QUEUED", status="RUNNING")
    return {"ok": True, "status": "REPLAYING", "actions": len(req.actions),
            "message": "Replay started in recorded order."}


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
