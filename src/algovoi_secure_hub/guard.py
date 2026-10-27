"""AlgoVoi Secure Hub — Guard (runtime anomaly detection).

Tracks per-tenant request rates with a one-minute sliding window and an
EWMA (exponentially-weighted moving average) baseline.  When a tenant's
observed rate exceeds ``baseline + ANOMALY_FACTOR × stdev`` the anomaly
score increments; once it reaches ``CIRCUIT_TRIP`` the circuit breaker
opens and subsequent requests from that tenant are rejected until the
cool-down period (``CIRCUIT_RESET_S``) expires.

Tenant identity is resolved from (in priority order):
  1. ``X-AlgoVoi-Tenant`` header
  2. ``X-Tenant-Id`` header
  3. Client IP address (fallback)

An operator can also set a fixed per-tenant RPM cap via
``POST /v1/guard/policy``, which bypasses the EWMA logic and enforces a
hard ceiling instead; setting cap_rpm to null removes the cap.

All state is in-process (no Redis dependency), so a multi-worker deployment
should set ``AHUB_GUARD_ENABLED=0`` and implement Guard in the upstream
reverse proxy or a shared cache layer.

Enable with AHUB_GUARD_ENABLED=1.

Endpoints (admin-gated, wired in service.py):
  GET  /v1/guard/status  — live anomaly scores, tripped circuits
  POST /v1/guard/policy  — set / clear a fixed per-tenant RPM cap
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from typing import Any

GUARD_ENABLED: bool = os.environ.get("AHUB_GUARD_ENABLED", "").strip().lower() not in (
    "", "0", "false", "no"
)
_ANOMALY_FACTOR: float = float(os.environ.get("AHUB_GUARD_ANOMALY_FACTOR", "5.0"))
_CIRCUIT_TRIP: int = int(os.environ.get("AHUB_GUARD_CIRCUIT_TRIP", "5"))
_CIRCUIT_RESET_S: int = int(os.environ.get("AHUB_GUARD_CIRCUIT_RESET_S", "300"))
_EWMA_ALPHA: float = float(os.environ.get("AHUB_GUARD_EWMA_ALPHA", "0.1"))

_GUARD_LOCK = threading.Lock()

# Per-tenant EWMA state
_BASELINE: dict[str, float] = {}       # EWMA mean of per-minute counts
_BASELINE_VAR: dict[str, float] = {}   # EWMA variance

# Per-tenant runtime state
_WINDOW: dict[str, tuple[float, int]] = {}  # (window_start, count_this_minute)
_ANOMALY_SCORE: dict[str, int] = {}
_CIRCUIT_OPEN: dict[str, float] = {}   # tenant -> monotonic time when opened
_POLICY_CAP: dict[str, int] = {}       # admin-set hard RPM cap

_STATS: dict[str, int] = defaultdict(int)


def _tenant_id(request) -> str:
    for header in ("x-algovoi-tenant", "x-tenant-id"):
        val = request.headers.get(header, "").strip()
        if val:
            return val[:64]
    return getattr(request.client, "host", None) or "unknown"


def _update_ewma(tenant: str, count: int) -> tuple[float, float]:
    """Update the EWMA baseline; return (mean, stdev)."""
    alpha = _EWMA_ALPHA
    if tenant not in _BASELINE:
        _BASELINE[tenant] = float(count)
        _BASELINE_VAR[tenant] = 0.0
        return float(count), 0.0
    mean = _BASELINE[tenant]
    var = _BASELINE_VAR[tenant]
    delta = count - mean
    new_mean = mean + alpha * delta
    new_var = (1 - alpha) * (var + alpha * delta * delta)
    _BASELINE[tenant] = new_mean
    _BASELINE_VAR[tenant] = new_var
    return new_mean, new_var ** 0.5


def _check_guard(tenant: str) -> bool:
    """Return False when the circuit is open and the tenant should be blocked."""
    now = time.monotonic()
    with _GUARD_LOCK:
        # Auto-reset after cool-down
        if tenant in _CIRCUIT_OPEN:
            if now - _CIRCUIT_OPEN[tenant] >= _CIRCUIT_RESET_S:
                del _CIRCUIT_OPEN[tenant]
                _ANOMALY_SCORE.pop(tenant, None)
            else:
                _STATS["circuit_blocked"] += 1
                return False

        # Fixed operator cap overrides EWMA logic
        if tenant in _POLICY_CAP:
            started, count = _WINDOW.get(tenant, (now, 0))
            if now - started >= 60.0:
                started, count = now, 0
            if count >= _POLICY_CAP[tenant]:
                _STATS["policy_capped"] += 1
                return False
            _WINDOW[tenant] = (started, count + 1)
            _STATS["allowed"] += 1
            return True

        # Sliding-window count + anomaly detection
        started, count = _WINDOW.get(tenant, (now, 0))
        if now - started >= 60.0:
            # Window expired: evaluate anomaly against last window's count
            mean, stdev = _update_ewma(tenant, count)
            threshold = mean + _ANOMALY_FACTOR * max(stdev, 1.0)
            if count > threshold:
                score = _ANOMALY_SCORE.get(tenant, 0) + 1
                _ANOMALY_SCORE[tenant] = score
                _STATS["anomaly_hit"] += 1
                if score >= _CIRCUIT_TRIP:
                    _CIRCUIT_OPEN[tenant] = now
                    _STATS["circuit_tripped"] += 1
                    return False
            started, count = now, 0

        _WINDOW[tenant] = (started, count + 1)

    _STATS["allowed"] += 1
    return True


def guard_stats() -> dict[str, Any]:
    """Return a live snapshot for GET /v1/guard/status."""
    now = time.monotonic()
    with _GUARD_LOCK:
        all_tenants = sorted(
            set(_BASELINE) | set(_CIRCUIT_OPEN) | set(_POLICY_CAP)
        )
        tenants = []
        for tenant in all_tenants:
            open_at = _CIRCUIT_OPEN.get(tenant)
            circuit_open = open_at is not None and (now - open_at < _CIRCUIT_RESET_S)
            tenants.append({
                "tenant": tenant,
                "baseline_rpm": round(_BASELINE.get(tenant, 0.0), 2),
                "anomaly_score": _ANOMALY_SCORE.get(tenant, 0),
                "circuit_open": circuit_open,
                "policy_cap_rpm": _POLICY_CAP.get(tenant),
            })
    return {
        "enabled": GUARD_ENABLED,
        "anomaly_factor": _ANOMALY_FACTOR,
        "circuit_trip_threshold": _CIRCUIT_TRIP,
        "circuit_reset_seconds": _CIRCUIT_RESET_S,
        "ewma_alpha": _EWMA_ALPHA,
        "tenants": tenants,
        "counters": dict(_STATS),
    }


def guard_set_policy(tenant: str, cap_rpm: int | None) -> None:
    """Set or clear a per-tenant RPM cap and reset any open circuit for that tenant."""
    with _GUARD_LOCK:
        if cap_rpm is None:
            _POLICY_CAP.pop(tenant, None)
        else:
            _POLICY_CAP[tenant] = cap_rpm
        _CIRCUIT_OPEN.pop(tenant, None)
        _ANOMALY_SCORE.pop(tenant, None)
