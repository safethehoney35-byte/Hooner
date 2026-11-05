# NEXUS AI Browser Monitor 1.1

A lightweight, single-session Playwright browser monitor with:
- URL input and Start/Stop state machine
- Cleaner visible-control labels and page-signal summaries
- Explicit Yes/No approval before supported control interactions
- Activity and error logs
- Ad/reward selector signals for visibility only
- API access key protection

## Approval and safety model

Every supported interaction is presented for explicit approval. NEXUS never clicks automatically. Ordinary links, non-submit buttons, dropdowns, text areas, and safe input controls can be reviewed. Password/file inputs and form-submit/reset buttons are excluded. Payment, ad, reward, account deletion, transfer, and withdrawal-related controls remain blocked. Ad/reward signals are informational and are not action buttons.

Approval is still a real browser interaction: approving a link can navigate away, and approving a checkbox can change its state. Review the label and destination before confirming.

## Improving startup and scan speed on Render

- Render Free services can sleep when idle; the first request after sleep has cold-start delay. A paid always-on instance avoids that sleep delay, but costs more.
- Keep one instance: this app owns one in-memory browser session and is not multi-instance safe.
- Use a region geographically close to your users and target sites where practical.
- Keep dependencies lean and avoid adding large Python packages unless needed.
- The scanner now gathers controls and page signals in one browser-side evaluation instead of many sequential Playwright calls. Its polling interval is 2.5 seconds to reduce CPU/network churn while keeping the UI responsive.
- If target pages are heavy, their own load time dominates. `domcontentloaded` is intentionally used rather than waiting for every image and ad to finish.
- Avoid aggressive polling or multiple browser sessions on the Free tier; Chromium memory is usually the limiting factor.

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


## Browser Diagnostics (v1.4.0)

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
