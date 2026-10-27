"""Example substrate-2 addon — the minimal thing you copy to bolt a new service
into the AlgoVoi Secure Hub.

Run it with two env vars and it joins automatically:

    S2_HUB_URL=http://s2cp:8094 S2_HUB_ALLOW_INSECURE=1 S2_HUB_REGISTRATION_TOKEN=<scoped registration token> S2_HUB_NAME=example-addon uvicorn addon_app:app --port 9000

On startup it (1) pulls the issuer trust set from the control plane and
(2) self-registers, so it appears in the control plane's posture. The only hard
requirement on an addon is a /health endpoint; consuming the trust set is optional.

This whole file is the template — copy it, drop your logic into the handler, set the
two env vars, and the addon is bridged. A non-Python addon just makes the same two
HTTP calls (one GET /v1/issuer-pks, one POST /v1/services) and exposes /health.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import time
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException

HUB = os.environ.get("S2_HUB_URL", "").strip().rstrip("/")
REGISTRATION_TOKEN = os.environ.get("S2_HUB_REGISTRATION_TOKEN", "").strip()
NAME = os.environ.get("S2_HUB_NAME", "example-addon")
SELF_URL = os.environ.get("S2_HUB_SELF_URL", "http://example-addon:9000")

STANDALONE = os.environ.get("S2_HUB_STANDALONE", "").strip().lower() in {"1", "true", "yes"}
_DID_RE = re.compile(r"^did:[a-z0-9]+:[A-Za-z0-9._:%/-]{1,240}$")
_MAX_HUB_RESPONSE = 1_048_576
_MAX_HUB_DURATION = 5.0


def _validated_hub() -> str:
    parsed = urlparse(HUB)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise RuntimeError("S2_HUB_URL must be an http(s) URL without credentials, query or fragment")
    if parsed.scheme == "http":
        if os.environ.get("S2_HUB_ALLOW_INSECURE", "").strip().lower() not in {"1", "true", "yes"}:
            raise RuntimeError("S2_HUB_URL must use HTTPS unless S2_HUB_ALLOW_INSECURE=1 is explicitly set for an isolated network")
        host = parsed.hostname.lower()
        if host not in {"localhost", "s2cp"}:
            try:
                address = ipaddress.ip_address(host)
            except ValueError as exc:
                raise RuntimeError("insecure hub URLs are limited to localhost, s2cp or private IP addresses") from exc
            if not (address.is_private or address.is_loopback) or address.is_link_local or address.is_reserved or address.is_unspecified:
                raise RuntimeError("insecure hub URLs are limited to private or local addresses")
    return HUB


_issuer_pks: dict[str, str] = {}


def _read_bounded(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + _MAX_HUB_DURATION
    for chunk in response.iter_bytes():
        if time.monotonic() > deadline:
            raise RuntimeError("control-plane response exceeded the configured duration")
        total += len(chunk)
        if total > _MAX_HUB_RESPONSE:
            raise RuntimeError("control-plane response exceeds the configured limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _hub_get(path: str):
    with httpx.Client(timeout=5.0, trust_env=False, follow_redirects=False) as client:
        with client.stream("GET", _validated_hub() + path) as response:
            response.raise_for_status()
            return json.loads(_read_bounded(response))


def _hub_post(path: str, body: dict) -> int:
    with httpx.Client(timeout=5.0, trust_env=False, follow_redirects=False) as client:
        with client.stream(
            "POST", _validated_hub() + path, json=body,
            headers={"Authorization": "Bearer " + REGISTRATION_TOKEN},
        ) as response:
            response.raise_for_status()
            _read_bounded(response)
            return response.status_code


_hub_ready = (not HUB) and STANDALONE
_registered = False
_last_trust_refresh = 0.0
_last_registration = 0.0
_TRUST_MAX_AGE = 60.0


def _clear_bridge_state() -> None:
    global _issuer_pks, _hub_ready, _registered, _last_trust_refresh, _last_registration
    _issuer_pks = {}
    _hub_ready = False
    _registered = False
    _last_trust_refresh = 0.0
    _last_registration = 0.0


def _refresh_trust() -> None:
    global _issuer_pks, _last_trust_refresh
    if not HUB:
        if not STANDALONE:
            raise RuntimeError("S2_HUB_URL is required unless S2_HUB_STANDALONE=1")
        _last_trust_refresh = time.monotonic()
        return
    try:
        trust = _hub_get("/v1/issuer-pks")
        if not isinstance(trust, dict) or not trust:
            raise RuntimeError("control plane returned an empty issuer trust set")
        validated: dict[str, str] = {}
        for did, value in trust.items():
            did_s, value_s = str(did), str(value)
            if not _DID_RE.fullmatch(did_s):
                raise RuntimeError("control plane returned an invalid issuer DID")
            try:
                key = base64.b64decode(value_s, validate=True)
            except Exception as exc:
                raise RuntimeError("control plane returned invalid issuer key material") from exc
            if len(key) != 1793 or base64.b64encode(key).decode("ascii") != value_s:
                raise RuntimeError("control plane returned invalid issuer key material")
            validated[did_s] = value_s
    except Exception:
        _clear_bridge_state()
        raise
    _issuer_pks = validated
    _last_trust_refresh = time.monotonic()


def _ensure_bridge() -> None:
    global _hub_ready, _registered, _last_registration
    try:
        _refresh_trust()
        if HUB:
            if not REGISTRATION_TOKEN:
                raise RuntimeError("S2_HUB_REGISTRATION_TOKEN is required when S2_HUB_URL is configured; admin fallback is disabled")
            _hub_post("/v1/services", {"name": NAME, "type": "addon",
                                       "base_url": SELF_URL, "health_path": "/health"})
            _registered = True
            _last_registration = time.monotonic()
        _hub_ready = True
    except Exception:
        _clear_bridge_state()
        raise


if HUB:
    try:
        _ensure_bridge()
    except Exception:
        _hub_ready = False

app = FastAPI(title=NAME)


@app.get("/health")
async def health() -> dict:
    trust_stale = HUB and (
        not _issuer_pks or time.monotonic() - _last_trust_refresh > _TRUST_MAX_AGE
    )
    registration_stale = HUB and (
        not _registered or time.monotonic() - _last_registration > _TRUST_MAX_AGE
    )
    if HUB and (not _hub_ready or trust_stale or registration_stale):
        try:
            await asyncio.to_thread(_ensure_bridge)
        except Exception as exc:
            _clear_bridge_state()
            raise HTTPException(status_code=503, detail="control-plane trust bridge is degraded") from exc
    if not _hub_ready or (HUB and (
        not _issuer_pks
        or time.monotonic() - _last_trust_refresh > _TRUST_MAX_AGE
        or not _registered
        or time.monotonic() - _last_registration > _TRUST_MAX_AGE
    )):
        raise HTTPException(status_code=503, detail="control-plane trust bridge is degraded")
    return {"status": "ok", "service": NAME, "issuer_count": len(_issuer_pks)}


@app.post("/do-something")
async def do_something() -> dict:
    global _hub_ready
    try:
        await asyncio.to_thread(_ensure_bridge)
    except Exception as exc:
        _hub_ready = False
        raise HTTPException(status_code=503, detail="control-plane trust bridge is degraded") from exc
    return {"ok": True, "trusted_issuers": list(_issuer_pks)}
