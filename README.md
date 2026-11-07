# NEXUS Replay Engine 2.3.0

NEXUS is a single-session Playwright browser replay service with:
- Recorder V3.x JSON import and workflow preview
- PEI target normalization, selector fallback, fingerprint and ancestor-context matching
- Read-only workflow inspection with candidate counts and ambiguity reporting
- Strict sequential replay with recorded inter-action gaps
- Separate detection, click-dispatch, and observable page-response evidence
- Live activity/error logs and browser diagnostics
- API-key protection and Privacy Shield request filtering

Replay refuses to guess when a target is ambiguous. Known ad/reward-flow, payment,
financial-transfer, and destructive targets are blocked from replay; they can still
be inspected. A click dispatch or generic DOM mutation is not proof that a website
operation completed.

## Approval and safety model

Every supported interaction is presented for explicit approval. NEXUS never clicks automatically. Ordinary links, non-submit buttons, dropdowns, text areas, and safe input controls can be reviewed. Password/file inputs and form-submit/reset buttons are excluded. Payment, ad, reward, account deletion, transfer, and withdrawal-related controls remain blocked. Ad/reward signals are informational and are not action buttons.

Approval is still a real browser interaction: approving a link can navigate away, and approving a checkbox can change its state. Review the label and destination before confirming.

## Improving startup and scan speed on Render

- Render Free services can sleep when idle; the first request after sleep has cold-start delay. A paid always-on instance avoids that sleep delay, but costs more.
- Keep one instance: this app owns one in-memory browser session and is not multi-instance safe.
- Use a region geographically close to your users and target sites where practical.
- Keep dependencies lean and avoid adding large Python packages unless needed.
- The scanner gathers controls and page signals in one browser-side evaluation instead of many sequential Playwright calls. A page-side `MutationObserver` flags meaningful DOM changes; NEXUS waits for a 350 ms quiet period before rescanning, so a burst of framework updates becomes one scan. A lightweight 700 ms version check notices changes, with an 8-second fallback scan for layout or visibility changes that do not produce observed mutations.
- If target pages are heavy, their own load time dominates. `domcontentloaded` is intentionally used rather than waiting for every image and ad to finish.
- The UI polls backend state every 1.8 seconds; that is separate from page scanning. DOM changes trigger scans independently. The monitor covers the main page document, not the internals of cross-origin iframes.
- Avoid multiple browser sessions on the Free tier; Chromium memory is usually the limiting factor.

## Render deployment

1. Back up your current repository, then replace the project files with this version.
2. Push the updated files to GitHub and deploy the existing Docker service in Render.
3. Set `NEXUS_ACCESS_KEY` in Render Environment to a long, unique secret.
4. Keep the service on one instance.
5. Confirm `https://YOUR-SERVICE/health` returns healthy.
6. Open the service URL and enter the same `NEXUS_ACCESS_KEY`.

No additional Render start command is required: Dockerfile runs `uvicorn main:app` and uses Render's `$PORT`.

## Local run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
export NEXUS_ACCESS_KEY='replace-with-a-long-random-secret'
uvicorn main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000.

## API

- `GET /health` — public health check
- `GET /api/status` — authenticated status
- `GET /api/data` — authenticated controls and logs
- `POST /api/start` — `{"url":"https://example.com"}`
- `POST /api/stop`
- `POST /api/approve` — `{"element_id":"..."}`
- `POST /api/reject` — `{"element_id":"..."}`

Authenticated requests require `X-Nexus-Key: <NEXUS_ACCESS_KEY>`.

## Operational notes

- Browser starts only when requested and closes on Stop or app shutdown.
- Start returns `STARTING`; the worker transitions to `RUNNING` or `ERROR`.
- URL validation rejects localhost and non-public IP destinations. Network requests are checked as well.
- This is a single-process, single-session app. Do not scale it to multiple instances without shared session coordination.

## Privacy Shield 1.2

All Chromium page requests are routed through `privacy_shield.py` before they are continued. The shield:
- Rejects invalid, localhost, private, and non-public destinations (the existing SSRF guard).
- Blocks a conservative list of known third-party tracker hosts by default.
- Records allowed/blocked counts and a bounded event log (host, resource type, decision; no query strings).
- Exposes its current mode and recent decisions through the authenticated `GET /api/data` response under `privacy_shield`.

Configuration:
- `NEXUS_BLOCK_TRACKERS=true` (default): block the bundled tracker host list.
- `NEXUS_BLOCK_TRACKERS=false`: audit/allow public requests without tracker blocking.
- `NEXUS_EXTRA_TRACKERS=tracker.example,another.example`: add exact tracker domains/subdomains to block.

This is an in-browser request policy/interceptor, **not** a forward proxy, VPN, IP anonymizer, or fingerprint spoofer. The website sees the public IP of the machine/network running Chromium. On a hosted Render deployment that is normally the hosting egress IP; on a local deployment it is normally the user's network public IP. DNS/WebRTC leak testing and fingerprint protection are not implemented by this module. Tracker blocking can affect some site features; set `NEXUS_BLOCK_TRACKERS=false` if compatibility problems occur.


## Browser Diagnostics (v1.5.0)

The dashboard now includes a **Browser diagnostics** panel. It reports browser capabilities and page/runtime measurements after the first scan, including JavaScript and storage availability, browser/OS hints, language and timezone, viewport and device-pixel ratio, touch/pointer support, selected browser APIs, WebDriver visibility, navigation timing, resource counts, and page visibility.

Each check is labelled `ok`, `info`, `warning`, `unsupported`, or `not collected`. Use the filter to focus on warnings or unsupported checks. Uncaught page JavaScript exceptions are added to the Error log.

### Privacy and technical boundaries

- Diagnostic values are observations from the monitored browser context, not a spoofed browser profile.
- IP address, ISP, precise location, TLS-level fingerprints, HTTP/2/3 fingerprints, account/login history, CAPTCHA outcomes, session identifiers, authentication values, canvas/audio fingerprints, and installed-font fingerprints are not collected.
- `navigator.webdriver` is reported as exposed by the browser; NEXUS does not conceal or rewrite automation indicators.
- Some APIs are browser-dependent and may return unavailable or limited data.
- Navigation and resource timing use the standard Performance API. The page is still navigated at `domcontentloaded`; Playwright documents `networkidle` as discouraged for this kind of wait because pages can keep network activity open.
- Existing Privacy Shield request policy remains unchanged. Tracker blocking can prevent selected third-party resources from loading; set `NEXUS_BLOCK_TRACKERS=false` in Render if you need audit-only request handling.

### Verification performed for this package

- Python source compilation: passed.
- Existing safety unit tests: 3 passed.
- Dashboard JavaScript syntax check (`node --check`): passed.
- A live Render deployment and real third-party website session were not run from this build environment; verify those after deployment.


## v1.4.0 dashboard layout

- The dashboard opens on a compact **Diagnostics** tab with browser checks, Activity, and Errors.
- The **Browser** tab contains the URL field, Start/Stop controls, detected elements, and read-only selector signals.
- Detected elements remain inspection-only until the operator selects **Review** and explicitly confirms YES in the approval dialog. NO declines the action.
- The existing manual approval endpoint, selector detection, safety eligibility checks, public-URL validation, privacy shield, and browser startup/navigation flow are preserved.
- Runtime diagnostics also record uncaught page JavaScript exceptions, browser `console.error` messages, and failed network requests. Network request failures are warnings; JavaScript exceptions and console errors appear in the Error log.


Dashboard and execution visibility (v1.5.0)
The dashboard has a responsive browser view with a larger URL field, a unique detected-controls list, and a separate Awaiting Elements panel. Predefined matches are flattened by DOM ID so the same page element is listed once even if multiple selectors match it. Each match row displays its individual YES/NO decision controls. YES is disabled for the bundled Linkvertise ad/reward-flow selectors and informational status markers; NO records the operator's decline. This preserves the safety boundary instead of converting ad-gate or reward markers into automated clicks.

The Live Execution panel is populated from backend events, not client-side simulated timers. Events include start requests, URL validation, Chromium launch, page navigation, page scans when their results change, navigation request outcomes, approval decisions, click dispatch, and errors. Event IDs can be searched in Render service logs. The server retains a bounded in-memory activity history; Render logs are the server-side diagnostic record.

Approval results distinguish a completed Playwright click from an observed page effect. Before a click, NEXUS scrolls the target into view and runs Playwright's non-interacting trial click to check actionability. If this preflight times out, the action is explicitly reported as NOT SENT and the Playwright call log plus a live hit-test snapshot are recorded. If the real click operation times out after dispatch begins, the outcome is reported as UNCERTAIN and NEXUS does not retry automatically. Render logs retain the diagnostic detail and a shared action ID. A changed URL, changed checkbox/ARIA state, or removed original element may be recorded as an observed page change; a completed click without a clear postcondition is reported as click dispatched / unverified, not as a successful website transaction. Each approval is re-checked against the current DOM and safety rules immediately before interaction.


## Approval diagnostics (v1.7.0)
The approval path is serialized so concurrent YES requests cannot race the single browser session. Each action performs a scroll-into-view and `locator.click(trial=True)` preflight before the real click. Preflight failures report that no click was sent and include Playwright's actionable call-log lines and a current DOM hit-test summary (bounding box, pointer-events, and center hit target). A timeout after the actual click call begins is marked `UNCERTAIN`; the system does not blindly retry because the page may already have received the click.

The eight bundled Linkvertise selectors are still displayed as individual, deduplicated matches. Their YES controls are disabled because they represent ad-view, ad-skip, ad-gated continuation/destination, or informational status targets. NO decisions are recorded. Normal page controls continue to use the individual approval flow subject to the same safety checks.


## Replay Engine 2.3.0 notes

- `/api/inspect` and `/api/replay` both normalize recorder actions through
  `normalized_action`; the previous build referenced this missing function.
- The normalizer preserves PEI target identity and clamps recorded gaps to 10 minutes.
- Replay policy blocks labels/selectors containing ad, reward, payment, purchase,
  account deletion, transfer, withdrawal, or payout terms.
- Verification commands:
  `python -m unittest test_safety tests.test_safety -v`
  and `node --check` on the inline script in `static/index.html`.
- A live Render deployment and real third-party website session were not run here.
