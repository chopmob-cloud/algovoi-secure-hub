"""Bolt-on template: register algovoi-agent-guard into algovoi-secure-hub.

algovoi-agent-guard is a spend-mandate *library* — human-signed spend caps with
offline-verifiable receipts — and ships no HTTP surface of its own. This wrapper
exposes the hub bolt-in contract (GET /health) where health reflects a live
enforcement self-check of the embedded guard: an honest charge ALLOWs, a settled
charge_id replay is DENIED, and a forged human countersign is DENIED. It then
registers the service so the hub can probe it and aggregate it into /v1/posture.

    pip install algovoi-agent-guard fastapi uvicorn httpx
    export S2_HUB_URL=http://localhost:8094
    export S2_HUB_REGISTRATION_TOKEN=<scoped token bound to algovoi-agent-guard>
    export S2_HUB_SELF_URL=http://algovoi-agent-guard:9000
    uvicorn agent_guard_addon:app --host 0.0.0.0 --port 9000

The only hard requirement on a bolt-on is GET /health. Registration is
POST /v1/services {name, type, base_url, health_path}. An addon (type="addon")
needs a scoped, name-bound registration token; an operator holding the admin
bearer may register type="security-app" instead. Never give a bolt-on the admin
bearer. See examples/addon_app.py for the generic, dependency-free template.

This is the spend-authority guard, distinct from the keystone-agent behaviour
guard (verify_agent_guard / behaviour_ref) and from the hub's own anomaly /
circuit-breaker Guard middleware.
"""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse

NAME = os.environ.get("S2_HUB_NAME", "algovoi-agent-guard")
HUB = os.environ.get("S2_HUB_URL", "http://s2cp:8094").rstrip("/")
SELF_URL = os.environ.get("S2_HUB_SELF_URL", "http://algovoi-agent-guard:9000").rstrip("/")
TOKEN = os.environ.get("S2_HUB_REGISTRATION_TOKEN", "")
ALLOW_INSECURE = os.environ.get("S2_HUB_ALLOW_INSECURE", "").lower() in {"1", "true", "yes"}
STANDALONE = os.environ.get("S2_HUB_STANDALONE", "").lower() in {"1", "true", "yes"}

_MAX_HUB_RESPONSE = 1_048_576
_MAX_HUB_DURATION = 5.0

app = FastAPI(title="algovoi-agent-guard secure-hub bolt-on")
_hub_state = {"ok": False, "issuer_count": 0, "error": ""}

_NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
_EXPIRES = "2026-11-23T09:00:00Z"
_AGENT_REF = "sha256:" + "b3" * 32


def _validated_hub() -> str:
    if not HUB:
        raise RuntimeError("S2_HUB_URL is required")
    parsed = urlparse(HUB)
    host = parsed.hostname
    if (parsed.scheme not in {"http", "https"} or not host or parsed.username is not None
            or parsed.password is not None or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment):
        raise RuntimeError("S2_HUB_URL must be a credential-free HTTP(S) origin")
    if parsed.scheme == "http":
        try:
            private = ipaddress.ip_address(host).is_private
        except ValueError:
            private = False
        if not (ALLOW_INSECURE or host == "localhost" or host.endswith(".localhost")
                or host in {"s2cp", "secure-hub"} or private):
            raise RuntimeError("S2_HUB_REGISTRATION_TOKEN requires an https hub URL")
    return HUB


def guard_self_check() -> dict:
    """Exercise the embedded guard: honest ALLOW, replay DENY, countersign-forgery DENY."""
    from algovoi_agent_guard import keys, mandate, intent
    from algovoi_agent_guard.guard import Guard
    from algovoi_agent_guard.ledger import Ledger

    human_priv, _ = keys.generate_keypair()
    agent_priv, _ = keys.generate_keypair()
    env = mandate.issue_mandate(
        payer="0x00000000000000000000000000000000DEADBEEF", cap="1000",
        period="monthly", payee="vendor-1", scope=["inference"],
        max_per_charge="250", human_priv=human_priv, now=_NOW)
    with tempfile.TemporaryDirectory() as d:
        lg = Ledger(os.path.join(d, "ledger.jsonl"))
        g = Guard(env, lg, _AGENT_REF, now_fn=lambda: _NOW)

        def mk(cid):
            return intent.make_intent(charge_id=cid, mandate_ref=env["mandate_ref"],
                                      payee="vendor-1", amount=100, at=_NOW, scope="inference")

        i = mk("c-1")
        r = g.decide(i, intent.approve(g._gref("ALLOW"), i, human_priv, _EXPIRES))
        i2 = mk("c-1")
        r2 = g.decide(i2, intent.approve(g._gref("ALLOW"), i2, human_priv, _EXPIRES))
        i3 = mk("c-2")
        r3 = g.decide(i3, intent.approve(g._gref("ALLOW"), i3, agent_priv, _EXPIRES))
    return {
        "honest_allow": r["verdict"] == "ALLOW",
        "replay_denied": r2["verdict"] == "DENY" and "policy: replay" in r2["reasons"],
        "countersign_forgery_denied": r3["verdict"] == "DENY"
        and any(x.startswith("countersign:") for x in r3["reasons"]),
    }


def _hub_request(method, path, *, headers=None, body=None):
    url = _validated_hub() + path
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    data = None if body is None else json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=0)
    timeout = httpx.Timeout(_MAX_HUB_DURATION)
    with httpx.Client(follow_redirects=False, trust_env=False, limits=limits, timeout=timeout) as c:
        with c.stream(method, url, headers=hdrs, content=data) as r:
            raw = bytearray()
            for chunk in r.iter_bytes():
                raw.extend(chunk)
                if len(raw) > _MAX_HUB_RESPONSE:
                    raise RuntimeError("hub response exceeded the bounded read limit")
            text = bytes(raw).decode("utf-8")
            try:
                parsed = json.loads(text) if text else {}
            except json.JSONDecodeError as exc:
                raise RuntimeError("hub returned invalid JSON") from exc
            return r.status_code, parsed


def register() -> bool:
    if STANDALONE:
        _hub_state.update(ok=True, error="")
        return True
    if not TOKEN:
        _hub_state.update(ok=False, error="S2_HUB_REGISTRATION_TOKEN is required")
        return False
    try:
        code, _ = _hub_request("GET", "/v1/issuer-pks")
        if code != 200:
            raise RuntimeError(f"issuer discovery returned HTTP {code}")
        code, _ = _hub_request(
            "POST", "/v1/services",
            headers={"Authorization": f"Bearer {TOKEN}"},
            body={"name": NAME, "type": "addon", "base_url": SELF_URL, "health_path": "/health"})
        if code not in {200, 201}:
            raise RuntimeError(f"service registration returned HTTP {code}")
        _hub_state.update(ok=True, error="")
        return True
    except (httpx.HTTPError, RuntimeError, ValueError, UnicodeError) as exc:
        _hub_state.update(ok=False, error=str(exc))
        return False


@app.get("/health")
def health():
    try:
        checks = guard_self_check()
    except Exception as exc:  # guard import/enforcement failure -> unhealthy
        return JSONResponse({"status": "error", "service": NAME, "error": str(exc)}, status_code=503)
    if not all(checks.values()):
        return JSONResponse({"status": "error", "service": NAME, "self_check": checks}, status_code=503)
    if not _hub_state["ok"]:
        return JSONResponse({"status": "degraded", "service": NAME, "self_check": checks}, status_code=503)
    return {"status": "ok", "service": NAME, "self_check": checks, "issuer_count": _hub_state["issuer_count"]}


@app.on_event("startup")
def startup():
    register()