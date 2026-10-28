"""TDD coverage for the substrate-neutral control-plane registry."""
from __future__ import annotations

import asyncio
import os
import pathlib
import secrets
import shutil
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

# Configure the package before importing the app: the service initialises its
# persistent store at import time.
_DATA_DIR = pathlib.Path(__file__).parent / ".tmp-control-plane"
if _DATA_DIR.exists():
    shutil.rmtree(_DATA_DIR)
_DATA_DIR.mkdir()
os.environ["AHUB_DATA_DIR"] = str(_DATA_DIR)
os.environ.pop("AHUB_DB", None)
os.environ["AHUB_ADMIN_TOKEN"] = secrets.token_urlsafe(32)
os.environ["AHUB_AUDIT_KEY"] = secrets.token_urlsafe(32)
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from app.main import _ADMIN_TOKEN, app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_headers():
    return {"Authorization": f"Bearer {_ADMIN_TOKEN}"}


def test_all_substrate_families_register_and_persist(client, admin_headers):
    registrations = [
        {
            "name": "open-substrate",
            "family": "open-substrate",
            "version": "1",
            "adapter": "canonical-evidence",
            "base_url": "http://127.0.0.1:1",
            "capabilities": ["refs", "offline-verify"],
        },
        {
            "name": "substrate-2",
            "family": "substrate-2",
            "version": "2",
            "adapter": "algovoi-secure-hub",
            "base_url": "http://127.0.0.1:2",
            "capabilities": ["federation", "zkp", "keystone"],
        },
        {
            "name": "payment-rails",
            "family": "payment-rails",
            "version": "1",
            "adapter": "payment-rails",
            "base_url": "http://127.0.0.1:3",
            "capabilities": ["x402", "mpp", "ap2", "a2a"],
        },
    ]

    for payload in registrations:
        response = client.post("/v1/substrates", json=payload, headers=admin_headers)
        assert response.status_code == 200, response.text

    response = client.get("/v1/substrates", headers=admin_headers)
    assert response.status_code == 200
    substrates = response.json()["substrates"]
    names = {item["name"] for item in substrates}
    assert {"open-substrate", "substrate-2", "payment-rails"} <= names
    payment = next(item for item in substrates if item["name"] == "payment-rails")
    assert payment["capabilities"] == ["x402", "mpp", "ap2", "a2a"]

    # The registry is durable: a fresh Store load sees the same entries.
    from algovoi_secure_hub.store import Store

    fresh = Store(dsn=f"sqlite:///{_DATA_DIR / 'control-plane.db'}")
    assert {"open-substrate", "substrate-2", "payment-rails"} <= set(fresh.substrates_load())


def test_substrate_registry_is_admin_only(client, admin_headers):
    payload = {
        "name": "unauthorised",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://127.0.0.1:4",
    }
    assert client.get("/v1/substrates").status_code == 401
    assert client.post("/v1/substrates", json=payload).status_code == 401
    assert client.delete("/v1/substrates/unauthorised").status_code == 401

    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    assert client.delete("/v1/substrates/unauthorised", headers=admin_headers).status_code == 200


def test_audit_failure_is_degraded_and_blocks_mutation(client, admin_headers, monkeypatch):
    import base64
    import algovoi_secure_hub.service as service

    monkeypatch.setattr(service, "_verify_audit_chain", lambda entries: False)
    assert client.get("/health").json()["status"] == "degraded"
    payload = {"did": "did:web:blocked.example", "public_key_b64": base64.b64encode(b"x" * 1793).decode()}
    response = client.post("/v1/issuers", json=payload, headers=admin_headers)
    assert response.status_code == 503
    assert "did:web:blocked.example" not in client.get("/v1/issuers").text
    monkeypatch.undo()
    service._refresh_persisted_state()


def test_legacy_service_registration_uses_same_url_hardening(client, admin_headers):
    base = {"name": "legacy", "type": "addon", "base_url": "http://127.0.0.1:99999", "health_path": "/health"}
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    base["base_url"] = "http://127.0.0.1:20"
    base["health_path"] = "/health/%2e%2e/admin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    base["health_path"] = "/health/%252e%252e/admin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    base["health_path"] = "/health/..%2fadmin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    from urllib.parse import quote
    encoded = ".."
    for _ in range(33):
        encoded = quote(encoded, safe="")
    base["health_path"] = f"/health/{encoded}/admin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    base["base_url"] = "http://127.0.0.1:20/%2e%2e/admin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422


def test_substrate_registration_rejects_unsafe_or_ambiguous_values(client, admin_headers):
    base = {
        "name": "bad substrate",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "file:///etc/passwd",
    }
    response = client.post("/v1/substrates", json=base, headers=admin_headers)
    assert response.status_code == 422

    base["name"] = "credentialed-target"
    base["base_url"] = "https://user:secret@example.com"
    response = client.post("/v1/substrates", json=base, headers=admin_headers)
    assert response.status_code == 422

    base["name"] = "bad-port"
    base["base_url"] = "http://127.0.0.1:99999"
    response = client.post("/v1/substrates", json=base, headers=admin_headers)
    assert response.status_code == 422

    base["name"] = "whitespace-url"
    base["base_url"] = "  http://127.0.0.1:11/  "
    response = client.post("/v1/substrates", json=base, headers=admin_headers)
    assert response.status_code == 200
    stored = client.get("/v1/substrates", headers=admin_headers).json()["substrates"]
    item = next(item for item in stored if item["name"] == "whitespace-url")
    assert item["base_url"] == "http://127.0.0.1:11"


def test_https_posture_targets_fail_closed_without_dns_rebinding_window(client, admin_headers):
    payload = {
        "name": "https-target",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "https://example.com",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    posture = client.get("/v1/posture", headers=admin_headers).json()
    item = next(item for item in posture["substrates"] if item["name"] == "https-target")
    assert item["up"] is False
    assert "HTTPS" in item["detail"]


def test_substrate_only_failure_is_degraded_in_panel(client, admin_headers):
    payload = {
        "name": "panel-down-substrate",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://127.0.0.1:12",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    panel = client.get("/", headers=admin_headers)
    assert panel.status_code == 200
    assert "Service degraded" in panel.text
    assert "Healthy targets" in panel.text
    assert "0/" in panel.text


def test_package_version_is_consistent():
    from algovoi_secure_hub import __version__

    assert __version__ == "0.3.5"


def test_pinned_probe_preserves_base_url_path_prefix(monkeypatch):
    import socket as _socket
    from algovoi_secure_hub import service

    monkeypatch.setattr(
        _socket,
        "getaddrinfo",
        lambda *a, **kw: [(_socket.AF_INET, _socket.SOCK_STREAM, _socket.IPPROTO_TCP, "", ("10.0.0.1", 13))],
    )
    target = service._resolve_posture_target("http://svc-internal:13/prefix", "/health")
    assert target is not None
    assert target[0].endswith("/prefix/health")


def test_pinned_probe_preserves_explicit_port_in_host_header(monkeypatch):
    import socket as _socket
    from algovoi_secure_hub import service

    monkeypatch.setattr(
        _socket,
        "getaddrinfo",
        lambda *a, **kw: [(_socket.AF_INET, _socket.SOCK_STREAM, _socket.IPPROTO_TCP, "", ("10.0.0.2", 8092))],
    )
    target = service._resolve_posture_target("http://svc-internal:8092/prefix", "/health")
    assert target is not None
    assert target[1] == "svc-internal:8092"


def test_audit_chain_verification_detects_tampering():
    from algovoi_secure_hub.service import _AUDIT_KEY, _verify_audit_chain
    import hashlib
    import hmac
    import json

    body = {"seq": 0, "action": "policy_bind", "detail": {"subject_ref": "x", "policy_ref": "y"}, "prev": ""}
    mac = hmac.new(_AUDIT_KEY, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    entry = {**body, "mac": mac}
    assert _verify_audit_chain([entry]) is True
    tampered = {**entry, "detail": {"x": 2}}
    assert _verify_audit_chain([tampered]) is False
    assert _verify_audit_chain([{"seq": 0, "action": "test", "detail": None, "prev": "", "mac": ""}]) is False


def test_http_panel_login_sets_secure_cookie_by_default(client):
    response = client.post("/login", data={"password": _ADMIN_TOKEN}, follow_redirects=False)
    assert response.status_code == 303
    assert "Secure" in response.headers["set-cookie"]


def test_posture_and_panel_expose_registered_substrates(client, admin_headers):
    payload = {
        "name": "posture-substrate",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://127.0.0.1:9",
        "health_path": "/health",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200

    posture = client.get("/v1/posture", headers=admin_headers).json()
    assert "substrates" in posture
    item = next(item for item in posture["substrates"] if item["name"] == "posture-substrate")
    assert item["up"] is False

    panel = client.get("/", headers=admin_headers)
    assert panel.status_code == 200
    assert "Substrates" in panel.text
    assert "posture-substrate" in panel.text


def test_posture_blocks_link_local_metadata_targets(client, admin_headers):
    payload = {
        "name": "metadata-target",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://169.254.169.254",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    assert client.get("/v1/posture").status_code == 401
    posture = client.get("/v1/posture", headers=admin_headers).json()
    item = next(item for item in posture["substrates"] if item["name"] == "metadata-target")
    assert item["up"] is False
    assert item["detail"].startswith("blocked:")


def test_substrate_changes_are_audited(client, admin_headers):
    payload = {
        "name": "audited-substrate",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://127.0.0.1:10",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    assert client.delete("/v1/substrates/audited-substrate", headers=admin_headers).status_code == 200
    audit = client.get("/v1/audit", headers=admin_headers).json()["entries"]
    actions = [entry["action"] for entry in audit]
    assert "substrate_register" in actions
    assert "substrate_remove" in actions


def test_pinned_probe_rejects_cloud_metadata_special_addresses(monkeypatch):
    import socket
    import algovoi_secure_hub.service as service

    cases = {
        "100.100.100.200": "100.100.100.200",
        "fd00:ec2::254": "fd00:ec2::254",
        "mapped-metadata": "::ffff:100.100.100.200",
        "mapped-azure": "::ffff:168.63.129.16",
    }

    for hostname, address in cases.items():
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *args, _address=address, **kwargs: [(socket.AF_INET6 if ":" in _address else socket.AF_INET,
                                                          socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (_address, 80))],
        )
        assert service._resolve_posture_target(f"http://{hostname}", "/health") is None


def test_malformed_database_import_serves_degraded_health(tmp_path):
    data_dir = tmp_path / "broken-data"
    data_dir.mkdir()
    (data_dir / "control-plane.db").write_bytes(b"not a sqlite database")
    root = pathlib.Path(__file__).parents[1]
    env = os.environ.copy()
    env.update({
        "AHUB_DATA_DIR": str(data_dir),
        "AHUB_ADMIN_TOKEN": secrets.token_urlsafe(32),
        "AHUB_AUDIT_KEY": secrets.token_urlsafe(32),
        "PYTHONPATH": f"{root / 'src'}:{root}",
    })
    stub = (
        "import sys, types; "
        "_m=types.ModuleType('substrate2'); "
        "_pb=types.ModuleType('substrate2.policy_binding'); "
        "_pb.policy_ref=lambda d:'r'; _pb.policy_bound_ref=lambda s,p:'r'; "
        "_m.policy_binding=_pb; "
        "sys.modules['substrate2']=_m; sys.modules['substrate2.policy_binding']=_pb; "
    )
    code = (
        stub
        + "from fastapi.testclient import TestClient; "
        "from app.main import app; "
        "r=TestClient(app).get('/health'); "
        "assert r.status_code == 503 and r.json()['audit_integrity'] is False"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=root, env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr or result.stdout


def test_addon_health_fails_closed_when_trust_refresh_is_stale(monkeypatch):
    import examples.addon_app as addon
    from fastapi import HTTPException

    addon.HUB = "http://s2cp"
    addon._hub_ready = True
    addon._registered = True
    now = __import__("time").monotonic()
    addon._last_registration = now
    addon._last_trust_refresh = now - addon._TRUST_MAX_AGE - 1
    addon._issuer_pks = {"did:web:issuer": "A" * 2392}

    def fail_refresh():
        raise RuntimeError("trust refresh failed")

    monkeypatch.setattr(addon, "_ensure_bridge", fail_refresh)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(addon.health())
    assert exc.value.status_code == 503
    assert addon._hub_ready is False
    assert addon._issuer_pks == {}


def test_migration_refuses_invalid_current_state(monkeypatch, tmp_path):
    import scripts.migrate_legacy_audit as migration

    anchor = tmp_path / "audit_anchor.json"
    anchor.write_text("{}", encoding="utf-8")

    class FakeStore:
        def audit_load(self):
            return []

        def state_load(self):
            return {"issuers": {"did:web:bad": {"pk_b64": "bad"}}, "services": {},
                    "substrates": {}, "policy": None, "keystone": None}

        def audit_append(self, *args):
            raise AssertionError("invalid state must not be appended")

    monkeypatch.setattr(migration, "_store", FakeStore())
    monkeypatch.setattr(migration, "_verify_audit_chain", lambda entries: True)
    monkeypatch.setattr(migration, "_audit_anchor_ok", lambda entries, bootstrap_allowed: True)
    monkeypatch.setenv("AHUB_DATA_DIR", str(tmp_path))
    anchor.write_text('{"seq": -1, "mac": ""}', encoding="utf-8")
    assert migration.main([]) != 0


def test_parseable_wrong_schema_import_serves_degraded_health(tmp_path):
    import sqlite3

    data_dir = tmp_path / "wrong-schema"
    data_dir.mkdir()
    conn = sqlite3.connect(data_dir / "control-plane.db")
    try:
        conn.execute("CREATE TABLE issuers (did TEXT PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()
    root = pathlib.Path(__file__).parents[1]
    env = os.environ.copy()
    env.update({
        "AHUB_DATA_DIR": str(data_dir),
        "AHUB_ADMIN_TOKEN": secrets.token_urlsafe(32),
        "AHUB_AUDIT_KEY": secrets.token_urlsafe(32),
        "PYTHONPATH": f"{root / 'src'}:{root}",
    })
    stub = (
        "import sys, types; "
        "_m=types.ModuleType('substrate2'); "
        "_pb=types.ModuleType('substrate2.policy_binding'); "
        "_pb.policy_ref=lambda d:'r'; _pb.policy_bound_ref=lambda s,p:'r'; "
        "_m.policy_binding=_pb; "
        "sys.modules['substrate2']=_m; sys.modules['substrate2.policy_binding']=_pb; "
    )
    code = (
        stub
        + "from fastapi.testclient import TestClient; "
        "from app.main import app; "
        "r=TestClient(app).get('/health'); "
        "assert r.status_code == 503 and r.json()['audit_integrity'] is False"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=root, env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr or result.stdout


def test_recognized_null_kv_state_is_degraded(client, admin_headers):
    import algovoi_secure_hub.service as service

    conn = service._store._conn()
    try:
        cur = conn.cursor()
        p = service._store._ph
        cur.execute(f"INSERT OR REPLACE INTO kv (k, v) VALUES ({p}, {p})", ("active_policy", "null"))
        conn.commit()
    finally:
        conn.close()
    try:
        response = client.get("/health")
        assert response.status_code == 503
        assert response.json()["audit_integrity"] is False
    finally:
        conn = service._store._conn()
        try:
            cur = conn.cursor()
            p = service._store._ph
            cur.execute(f"DELETE FROM kv WHERE k = {p}", ("active_policy",))
            conn.commit()
        finally:
            conn.close()
        service._refresh_persisted_state()


def test_scoped_addon_token_cannot_change_existing_registration(client, admin_headers, monkeypatch):
    import algovoi_secure_hub.service as service

    token = secrets.token_urlsafe(32)
    monkeypatch.setattr(service, "_REGISTRATION_TOKEN", token)
    monkeypatch.setattr(service, "_REGISTRATION_NAME", "scoped-addon")
    body = {"name": "scoped-addon", "type": "addon", "base_url": "http://127.0.0.1:31"}
    scoped_headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/v1/services", json=body, headers=scoped_headers).status_code == 200
    before = len(client.get("/v1/audit", headers=admin_headers).json()["entries"])
    changed = {**body, "base_url": "http://127.0.0.1:32"}
    response = client.post("/v1/services", json=changed, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 409
    after = len(client.get("/v1/audit", headers=admin_headers).json()["entries"])
    assert after == before


def test_registration_urls_have_bounded_lengths(client, admin_headers):
    body = {"name": "long-url", "type": "addon", "base_url": "http://127.0.0.1/" + "a" * 2050}
    assert client.post("/v1/services", json=body, headers=admin_headers).status_code == 422
    body = {"name": "long-path", "type": "addon", "base_url": "http://127.0.0.1", "health_path": "/" + "a" * 600}
    assert client.post("/v1/services", json=body, headers=admin_headers).status_code == 422


def test_migration_replay_check_receives_fresh_state(monkeypatch, tmp_path):
    import scripts.migrate_legacy_audit as migration

    state = {"issuers": {}, "services": {}, "substrates": {}, "policy": None,
             "keystone": None, "kv_keys": set()}
    called = {}

    class FakeStore:
        def audit_load(self):
            return []

        def state_load(self):
            return state

        def state_reconcile_with_audit(self, expected_state, expected_audit, detail, audit_key):
            called["reconcile"] = (expected_state, expected_audit, detail)
            return {"seq": 0, "mac": "tail"}

    def check(entries, current_state=None):
        called["state"] = current_state
        return True

    monkeypatch.setattr(migration, "_store", FakeStore())
    monkeypatch.setattr(migration, "_verify_audit_chain", lambda entries: True)
    monkeypatch.setattr(migration, "_audit_anchor_ok", lambda entries, bootstrap_allowed: True)
    monkeypatch.setattr(migration, "_audit_state_matches", check)
    monkeypatch.setattr(migration, "_write_audit_anchor", lambda entries: None)
    monkeypatch.setenv("AHUB_DATA_DIR", str(tmp_path))
    (tmp_path / "audit_anchor.json").write_text('{"seq": -1, "mac": ""}', encoding="utf-8")
    assert migration.main([]) == 0
    assert called["state"] == {key: state[key] for key in ("issuers", "services", "substrates", "policy", "keystone")}
    assert called["reconcile"][0] == {key: state[key] for key in ("issuers", "services", "substrates", "policy", "keystone")}


def test_migration_refuses_unproven_current_state_without_explicit_hash(monkeypatch, tmp_path):
    import scripts.migrate_legacy_audit as migration

    class FakeStore:
        def audit_load(self):
            return []

        def state_load(self):
            return {"issuers": {}, "services": {}, "substrates": {}, "policy": None,
                    "keystone": None, "kv_keys": set()}

        def audit_append(self, *args):
            raise AssertionError("unapproved state must not be appended")

    monkeypatch.setattr(migration, "_store", FakeStore())
    monkeypatch.setattr(migration, "_verify_audit_chain", lambda entries: True)
    monkeypatch.setattr(migration, "_audit_anchor_ok", lambda entries, bootstrap_allowed: True)
    monkeypatch.setattr(migration, "_audit_state_matches", lambda entries, current_state=None: False)
    monkeypatch.setenv("AHUB_DATA_DIR", str(tmp_path))
    (tmp_path / "audit_anchor.json").write_text('{"seq": -1, "mac": ""}', encoding="utf-8")
    assert migration.main([]) != 0


def test_atomic_reconciliation_rejects_stale_state_or_audit(tmp_path):
    from algovoi_secure_hub.store import Store

    store = Store(dsn=f"sqlite:///{tmp_path / 'reconcile.db'}")
    snapshot = {"issuers": {}, "services": {}, "substrates": {}, "policy": None, "keystone": None}
    key = secrets.token_bytes(32)
    first = store.state_reconcile_with_audit(snapshot, [], snapshot, key)
    assert first["seq"] == 0
    with pytest.raises(RuntimeError, match="state or audit changed"):
        store.state_reconcile_with_audit(snapshot, [], snapshot, key)


def test_scoped_store_registration_is_immutable_inside_transaction(tmp_path):
    from algovoi_secure_hub.store import Store

    store = Store(dsn=f"sqlite:///{tmp_path / 'scoped.db'}")
    key = secrets.token_bytes(32)
    first = {"name": "addon", "type": "addon", "base_url": "http://127.0.0.1:41",
             "health_path": "/health", "registered_at": 1}
    store.service_register_with_audit(
        "addon", "addon", first["base_url"], first["health_path"], 1,
        "service_register", first, key, immutable=True,
    )
    changed = {**first, "base_url": "http://127.0.0.1:42"}
    with pytest.raises(RuntimeError, match="scoped registration is immutable"):
        store.service_register_with_audit(
            "addon", "addon", changed["base_url"], changed["health_path"], 1,
            "service_register", changed, key, immutable=True,
        )


def test_public_trust_read_reloads_integrity_once_per_request(client, monkeypatch):
    import algovoi_secure_hub.service as service

    original = service._refresh_persisted_state
    calls = 0

    def counted_refresh():
        nonlocal calls
        calls += 1
        return original()

    monkeypatch.setattr(service, "_refresh_persisted_state", counted_refresh)
    response = client.get("/v1/issuer-pks")
    assert response.status_code == 200
    assert calls == 1


def test_public_trust_reads_have_a_process_rate_limit(client, monkeypatch):
    import algovoi_secure_hub.service as service

    monkeypatch.setattr(service, "_PUBLIC_TRUST_RPM", 1)
    service._RATE_BUCKETS.clear()
    assert client.get("/v1/issuer-pks").status_code == 200
    assert client.get("/v1/issuer-pks").status_code == 429


def test_health_reads_have_a_process_rate_limit(client, monkeypatch):
    import algovoi_secure_hub.service as service

    monkeypatch.setattr(service, "_HEALTH_RPM", 1)
    service._RATE_BUCKETS.clear()
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 429


def test_identical_issuer_retry_is_idempotent(client, admin_headers):
    import base64

    payload = {"did": "did:web:idempotent-issuer", "public_key_b64": base64.b64encode(secrets.token_bytes(1793)).decode()}
    first = client.post("/v1/issuers", json=payload, headers=admin_headers)
    assert first.status_code == 200
    before = len(client.get("/v1/audit", headers=admin_headers).json()["entries"])
    second = client.post("/v1/issuers", json=payload, headers=admin_headers)
    assert second.status_code == 200
    assert second.json().get("unchanged") is True
    after = len(client.get("/v1/audit", headers=admin_headers).json()["entries"])
    assert after == before


def test_bridge_e2e_script_is_strict_and_checks_expected_services():
    script = (pathlib.Path(__file__).parents[1] / "scripts" / "bridge_e2e.sh").read_text()
    assert 'docker rm -f "$c"' in script and '|| true' in script
    assert 'docker network rm "$NET"' in script and '|| true' in script
    assert "curl -fsS" in script
    assert "| head -c" not in script
    assert "federation-validator" in script
    assert "zkp-receipt" in script
