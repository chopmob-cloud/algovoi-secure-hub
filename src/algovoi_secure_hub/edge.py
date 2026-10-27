"""AlgoVoi Secure Hub — Edge layer.

An in-process edge filter that sits outermost in the middleware stack and
provides three independent, opt-in controls:

  * HMAC pre-auth token (``X-AlgoVoi-Edge-Token`` header) — allows a
    reverse-proxy / CDN to attach a shared secret so origin-direct requests
    are rejected before they reach any authentication logic.
  * Per-IP sliding-window rate limiting (``AHUB_EDGE_RPM``) — a coarser,
    connection-level ceiling that complements the finer per-endpoint RPM
    limits already in service.py.
  * Geo-blocklist (``AHUB_EDGE_GEO_BLOCK``) — rejects requests whose
    ``X-Country-Code`` header (set by a trusted reverse proxy) matches an
    ISO 3166-1 alpha-2 code in the blocklist.

Each control is independently disabled when its env-var is absent or empty,
so a deployment that needs only the token pays no overhead for the others.

Stats are exposed via the admin-gated GET /v1/edge/stats endpoint wired in
service.py.
"""
from __future__ import annotations

import hmac
import os
import threading
import time
from collections import defaultdict
from typing import Any

_EDGE_TOKEN: str = os.environ.get("AHUB_EDGE_TOKEN", "").strip()
_EDGE_RPM: int = int(os.environ.get("AHUB_EDGE_RPM", "0") or "0")
_GEO_BLOCK_RAW: str = os.environ.get("AHUB_EDGE_GEO_BLOCK", "").strip().upper()
_GEO_BLOCKLIST: frozenset[str] = (
    frozenset(c.strip() for c in _GEO_BLOCK_RAW.split(",") if c.strip())
    if _GEO_BLOCK_RAW else frozenset()
)

EDGE_ENABLED: bool = bool(_EDGE_TOKEN or _EDGE_RPM or _GEO_BLOCKLIST)

_EDGE_LOCK = threading.Lock()
# {ip: (window_start_monotonic, count_in_window)}
_EDGE_BUCKETS: dict[str, tuple[float, int]] = {}
_STATS: dict[str, int] = defaultdict(int)


def _client_ip(request) -> str:
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")
    if forwarded and forwarded[0].strip():
        return forwarded[0].strip()
    return getattr(request.client, "host", None) or "unknown"


def _check_token(request) -> bool:
    if not _EDGE_TOKEN:
        return True
    provided = request.headers.get("x-algovoi-edge-token", "")
    return bool(provided and hmac.compare_digest(provided, _EDGE_TOKEN))


def _check_geo(request) -> bool:
    if not _GEO_BLOCKLIST:
        return True
    country = request.headers.get("x-country-code", "").strip().upper()
    return country not in _GEO_BLOCKLIST


def _check_rate(ip: str) -> bool:
    if not _EDGE_RPM:
        return True
    now = time.monotonic()
    with _EDGE_LOCK:
        if ip not in _EDGE_BUCKETS and len(_EDGE_BUCKETS) >= 50_000:
            cutoff = now - 60.0
            expired = [k for k, (ts, _) in _EDGE_BUCKETS.items() if ts < cutoff]
            for k in expired:
                _EDGE_BUCKETS.pop(k, None)
            if len(_EDGE_BUCKETS) >= 50_000:
                oldest = min(_EDGE_BUCKETS, key=lambda k: _EDGE_BUCKETS[k][0])
                _EDGE_BUCKETS.pop(oldest, None)
        started, count = _EDGE_BUCKETS.get(ip, (now, 0))
        if now - started >= 60.0:
            started, count = now, 0
        if count >= _EDGE_RPM:
            _EDGE_BUCKETS[ip] = (started, count)
            return False
        _EDGE_BUCKETS[ip] = (started, count + 1)
        return True


def edge_stats() -> dict[str, Any]:
    """Return a snapshot of edge-layer state for GET /v1/edge/stats."""
    now = time.monotonic()
    with _EDGE_LOCK:
        active = sum(1 for ts, _ in _EDGE_BUCKETS.values() if now - ts < 60.0)
        limited = sum(
            1 for ts, count in _EDGE_BUCKETS.values()
            if now - ts < 60.0 and _EDGE_RPM and count >= _EDGE_RPM
        )
    return {
        "enabled": EDGE_ENABLED,
        "token_required": bool(_EDGE_TOKEN),
        "rpm_limit": _EDGE_RPM or None,
        "geo_blocklist": sorted(_GEO_BLOCKLIST),
        "active_ip_buckets": active,
        "rate_limited_ips": limited,
        "counters": dict(_STATS),
    }


async def edge_middleware(request, call_next):
    """ASGI middleware: edge token → geo → rate, in that order."""
    if not EDGE_ENABLED:
        return await call_next(request)

    ip = _client_ip(request)

    if not _check_token(request):
        _STATS["token_rejected"] += 1
        from starlette.responses import Response
        return Response(status_code=401, content="edge token required")

    if not _check_geo(request):
        _STATS["geo_blocked"] += 1
        from starlette.responses import Response
        return Response(status_code=403, content="region not permitted")

    if not _check_rate(ip):
        _STATS["rate_limited"] += 1
        from starlette.responses import Response
        return Response(status_code=429, headers={"Retry-After": "60"}, content="edge rate limit exceeded")

    _STATS["allowed"] += 1
    return await call_next(request)
