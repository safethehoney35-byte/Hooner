"""NEXUS Privacy Shield: inspect browser requests before they leave Chromium.

This is a request-policy layer, not an IP anonymizer or fingerprint spoofer.
It blocks non-public destinations and optionally blocks known tracker hosts.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from urllib.parse import urlparse
from typing import Awaitable, Callable


# Conservative starter list. Extend through NEXUS_BLOCKED_TRACKER_DOMAINS;
# avoid broad parent domains because they can host essential site resources.
DEFAULT_TRACKERS = {
    "google-analytics.com",
    "www.google-analytics.com",
    "googletagmanager.com",
    "connect.facebook.net",
    "pixel.facebook.com",
    "bat.bing.com",
}


class PrivacyShield:
    def __init__(self, public_url_validator: Callable[[str], Awaitable[str]], *,
                 block_trackers: bool = True, extra_tracker_domains: set[str] | None = None,
                 event_limit: int = 100):
        self.validate_public_url = public_url_validator
        self.block_trackers = block_trackers
        self.tracker_domains = set(DEFAULT_TRACKERS)
        self.tracker_domains.update(d.lower().strip(".") for d in (extra_tracker_domains or set()) if d.strip())
        self.counts: Counter[str] = Counter()
        self.events = deque(maxlen=event_limit)

    def _is_tracker(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == domain or host.endswith("." + domain) for domain in self.tracker_domains)

    def _record(self, decision: str, reason: str, host: str, resource_type: str) -> None:
        self.counts[decision] += 1
        self.events.append({
            "time": time.strftime("%H:%M:%S"),
            "decision": decision,
            "reason": reason,
            "host": host[:180],
            "resource_type": resource_type[:40],
        })

    async def inspect(self, url: str, resource_type: str = "other") -> tuple[bool, str]:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        try:
            await self.validate_public_url(url)
        except Exception:
            self._record("blocked", "non_public_or_invalid_destination", host, resource_type)
            return False, "non_public_or_invalid_destination"

        if self.block_trackers and self._is_tracker(host):
            self._record("blocked", "known_tracker_domain", host, resource_type)
            return False, "known_tracker_domain"

        self._record("allowed", "passed_policy", host, resource_type)
        return True, "passed_policy"

    def snapshot(self) -> dict:
        return {
            "enabled": True,
            "mode": "tracker_blocking" if self.block_trackers else "audit_only",
            "allowed": self.counts["allowed"],
            "blocked": self.counts["blocked"],
            "events": list(self.events)[-40:],
        }
