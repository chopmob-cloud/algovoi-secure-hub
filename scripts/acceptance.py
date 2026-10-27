#!/usr/bin/env python3
"""Self-contained acceptance test for the AlgoVoi Secure Hub.

Proves, on the delivered image with NO configuration:
  1. Bootstrap     — starts healthy with an empty registry; admin token auto-generated.
  2. Trust hub     — register issuers; the trust set is served in all three shapes the
                     federation/ZK services consume ({did:pk_b64}, the canonical
                     /.well-known/atb-keys.json, and per-issuer docs).
  3. Bridge+addons — register the three substrate-2 services and a bolt-on addon; they
                     appear in the service list / posture.
  4. Audit         — every trust change is appended to the HMAC-chained log.
  5. Guards        — admin endpoints reject without the bearer token; bad keys rejected.

    docker run --rm algovoi-secure-hub:clean python scripts/acceptance.py

Exit 0 = all green.
"""
from __future__ import annotations

import base64
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        _failures.append(name)


def main() -> int:
    os.environ["AHUB_DATA_DIR"] = tempfile.mkdtemp()
    os.environ.pop("AHUB_ADMIN_TOKEN", None)
    addon_token = "addon-" + base64.urlsafe_b64encode(os.urandom(24)).decode()
    os.environ["AHUB_REGISTRATION_TOKENS"] = '{"my-addon":"' + addon_token + '"}'
    import app.main as m
    from fastapi.testclient import TestClient

    c = TestClient(m.app)
    admin = {"Authorization": "Bearer " + m._ADMIN_TOKEN}

    print("STEP 1 - bootstrap (no config) -> healthy, empty registry")
    h = c.get("/health").json()
    check("service healthy", h["status"] == "ok")
    check("admin token auto-generated", isinstance(m._ADMIN_TOKEN, str) and len(m._ADMIN_TOKEN) > 20)
    check("empty registry on first run", h["issuer_count"] == 0 and h["service_count"] == 0)

    print("STEP 2 - issuer trust registry + the three hub shapes")
    dids = []
    for i in range(2):
        did = f"did:web:issuer-{i}.example"
        pk_b64 = base64.b64encode(os.urandom(1793)).decode()  # CP length-validates the Falcon key
        r = c.post("/v1/issuers", json={"did": did, "public_key_b64": pk_b64}, headers=admin)
        check(f"issuer {i} registered", r.status_code == 200 and bool(r.json().get("kid")))
        dids.append((did, pk_b64))
    pks = c.get("/v1/issuer-pks").json()
    check("/v1/issuer-pks serves the {did:pk} map (federation/zkp)", len(pks) == 2 and pks[dids[0][0]] == dids[0][1])
    wk = c.get("/.well-known/atb-keys.json").json()
    check("/.well-known/atb-keys.json canonical doc (atb verifier hub_resolver)",
          wk.get("issuer") == dids[0][0] and wk["keys"][0]["public_key_b64"] == dids[0][1])
    per = c.get(f"/issuers/{dids[1][0]}/atb-keys.json").json()
    check("per-issuer atb-keys.json", per["keys"][0]["public_key_b64"] == dids[1][1])

    print("STEP 3 - bridge the three services + bolt on an addon")
    three = [
        ("federation-validator", "federation", "http://federation-validator:8092"),
        ("zkp-receipt", "zkp-receipt", "http://zkp-receipt:8093"),
        ("atb-credential-verifier", "atb-verifier", "http://atb-verifier:8095"),
    ]
    for name, typ, url in three:
        r = c.post("/v1/services", json={"name": name, "type": typ, "base_url": url}, headers=admin)
        check(f"bridged {name}", r.status_code == 200)
    addon_headers = {"Authorization": "Bearer " + addon_token}
    addon_response = c.post("/v1/services", json={"name": "my-addon", "type": "addon", "base_url": "http://my-addon:9000"}, headers=addon_headers)
    check("admin token rejected for addon registration", c.post("/v1/services", json={"name": "admin-addon", "type": "addon", "base_url": "http://admin-addon:9000"}, headers=admin).status_code == 403)
    check("scoped addon registration", addon_response.status_code == 200)
    # /v1/services exposes internal service base URLs (operational topology), so it stays admin-gated —
    # unlike the public trust-key reads (issuer-pks / atb-keys) that bridged consumers fetch without admin.
    svcs = c.get("/v1/services", headers=admin).json()
    check("three services + 1 addon registered", len(svcs["services"]) == 4)
    check("default bridge names the built-in substrate services", set(svcs["default_bridge"]) ==
          {"federation-validator", "zkp-receipt", "atb-credential-verifier", "policy-bridge"})

    print("STEP 3b - substrate-neutral adapter registry")
    substrates = [
        {"name": "open-substrate", "family": "open-substrate", "version": "1",
         "adapter": "canonical-evidence", "base_url": "http://127.0.0.1:1",
         "capabilities": ["refs", "offline-verify"]},
        {"name": "substrate-2", "family": "substrate-2", "version": "2",
         "adapter": "algovoi-secure-hub", "base_url": "http://127.0.0.1:2",
         "capabilities": ["federation", "zkp", "keystone"]},
        {"name": "payment-rails", "family": "payment-rails", "version": "1",
         "adapter": "payment-rails", "base_url": "http://127.0.0.1:3",
         "capabilities": ["x402", "mpp", "ap2", "a2a"]},
    ]
    for sub in substrates:
        r = c.post("/v1/substrates", json=sub, headers=admin)
        check(f"registered {sub['name']}", r.status_code == 200)
    subs = c.get("/v1/substrates", headers=admin).json()["substrates"]
    check("all substrate families visible", {s["family"] for s in subs} >=
          {"open-substrate", "substrate-2", "payment-rails"})
    posture = c.get("/v1/posture", headers=admin).json()
    check("substrate posture included", {s["name"] for s in posture["substrates"]} >=
          {"open-substrate", "substrate-2", "payment-rails"})

    print("STEP 4 - signed audit of every trust change")
    aud = c.get("/v1/audit", headers=admin).json()
    check("audit HMAC-chained, 9 changes logged (2 issuer + 4 service + 3 substrate)",
          aud["chained"] and len(aud["entries"]) == 9)

    print("STEP 5 - guards")
    check("admin endpoint rejects without the bearer token",
          c.post("/v1/issuers", json={"did": "x", "public_key_b64": "AA"}).status_code == 401)
    bad = c.post("/v1/issuers", json={"did": "did:web:bad", "public_key_b64": base64.b64encode(b"short").decode()}, headers=admin)
    check("malformed issuer key rejected", bad.status_code == 400)

    print("STEP 5b - auth split: public trust reads open, admin reads/writes gated")
    # The trust-key consumption GETs a bridged service needs must NOT require the admin token
    # (they expose only published public keys / DIDs — the trust anchors).
    check("/v1/issuer-pks readable without admin", c.get("/v1/issuer-pks").status_code == 200)
    check("/.well-known/atb-keys.json readable without admin",
          c.get("/.well-known/atb-keys.json").status_code == 200)
    check("per-issuer atb-keys.json readable without admin",
          c.get(f"/issuers/{dids[0][0]}/atb-keys.json").status_code == 200)
    # Sensitive reads (audit log, operational topology) and writes stay behind the admin token,
    # so a consumer never needs the full admin credential.
    check("/v1/audit rejects without admin", c.get("/v1/audit").status_code == 401)
    check("/v1/services (internal topology) rejects without admin",
          c.get("/v1/services").status_code == 401)
    check("POST /v1/services rejects without admin",
          c.post("/v1/services", json={"name": "z", "type": "addon", "base_url": "http://z:1"}).status_code == 401)

    print()
    if _failures:
        print(f"RESULT: FAIL - {len(_failures)} check(s): {', '.join(_failures)}")
        return 1
    print("RESULT: ALL GREEN - lean AlgoVoi Secure Hub: bootstrap + issuer-trust hub "
          "(3 consumption shapes) + service bridge + addon bolt-on + signed audit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
