# SPDX-License-Identifier: Apache-2.0
"""AlgoVoi Secure Hub.

A lean, self-hosted control plane for the substrate-2 federation + ZK-proof
services. It does exactly three things, and nothing of the monolith:

  1. Issuer trust registry — the single source of truth for which issuer DIDs
     map to which Falcon-1024 public keys. The federation + ZK services pull
     their trust set from here instead of each being configured independently.
  2. Service bridge — registers the substrate-2 services (federation-validator,
     zkp-receipt, atb-credential-verifier) and any bolt-on addon, and reports a
     unified health posture across them.
  3. Signed audit — every trust change is appended to an HMAC-chained log.

It serves the trust set in every shape the three services already consume:
  - GET /v1/issuer-pks                 -> {did: pk_b64}  (federation/zkp ISSUER_PKS)
  - GET /.well-known/atb-keys.json     -> canonical doc for the primary issuer
  - GET /issuers/{did}/atb-keys.json   -> canonical doc per issuer (hub_resolver)

Bootstraps clean: a bare `docker run` generates its admin token + audit key and
comes up healthy with an empty registry. No monolith, no DB required, air-gap
capable.
"""
from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess  # nosec B404 - Windows ACL inspection uses a fixed system utility
import tempfile
import threading
import time

# Backward-compatible migration: legacy S2CP_* names populate AHUB_* only when
# the canonical Secure Hub variable is absent. New deployments should use AHUB_*.
for _legacy_key, _legacy_value in list(os.environ.items()):
    if _legacy_key.startswith("S2CP_"):
        os.environ.setdefault("AHUB_" + _legacy_key[5:], _legacy_value)

from contextlib import contextmanager
from urllib.parse import unquote, urlparse
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from substrate2.policy_binding import policy_bound_ref, policy_ref

from algovoi_secure_hub import __version__
from algovoi_secure_hub.edge import edge_middleware, edge_stats
from algovoi_secure_hub.guard import GUARD_ENABLED, guard_middleware, guard_set_policy, guard_stats
from algovoi_secure_hub.panel import render_panel
from algovoi_secure_hub.store import Store
from algovoi_secure_hub.waf import waf_middleware, waf_stats

_FALCON1024_PK_LEN = 1793
_IETF_ANCHOR = "draft-hopley-x402-canonicalisation-jcs-v1-04"

# The substrate-2 capabilities this control plane bridges by default. The first three
# are external services (registered with a base_url + /health); "policy-bridge" is a
# built-in capability served by this control plane itself (see /v1/policy). Addons
# register on top of these at runtime via POST /v1/services.
_DEFAULT_SERVICES = ("federation-validator", "zkp-receipt", "atb-credential-verifier", "policy-bridge")


def _bounded_limit(env_name: str, default: int, ceiling: int) -> int:
    try:
        value = int(os.environ.get(env_name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{env_name} must be an integer") from exc
    if not 1 <= value <= ceiling:
        raise RuntimeError(f"{env_name} must be between 1 and {ceiling}")
    return value


_MAX_AUDIT_ENTRIES = _bounded_limit("AHUB_MAX_AUDIT_ENTRIES", 100_000, 1_000_000)
_MAX_ISSUERS = _bounded_limit("AHUB_MAX_ISSUERS", 10_000, 100_000)
_MAX_SERVICES = _bounded_limit("AHUB_MAX_SERVICES", 4_096, 100_000)
_MAX_SUBSTRATES = _bounded_limit("AHUB_MAX_SUBSTRATES", 4_096, 100_000)
_MAX_TRUST_RESPONSE_BYTES = _bounded_limit("AHUB_MAX_TRUST_RESPONSE_BYTES", 8 * 1024 * 1024, 64 * 1024 * 1024)
_POSTURE_TOTAL_SECONDS = 30.0
_PUBLIC_TRUST_RPM = _bounded_limit("AHUB_PUBLIC_TRUST_RPM", 600, 100_000)
_HEALTH_RPM = _bounded_limit("AHUB_HEALTH_RPM", 600, 100_000)
_LOGIN_RPM = _bounded_limit("AHUB_LOGIN_RPM", 10, 1_000)
_RATE_LOCK = threading.Lock()
_RATE_BUCKETS: dict[tuple[str, str], tuple[float, int]] = {}
_AUDIT_REQUEST_VALIDATED = contextvars.ContextVar("ahub_audit_request_validated", default=False)


def _data_dir() -> str:
    return os.environ.get("AHUB_DATA_DIR", "/app/data")


def _path(name: str) -> str:
    return os.path.join(_data_dir(), name)


# ── Bootstrap: admin token + audit key, generated and persisted on first run ──

def _validate_secret_file_security(path: str, file_name: str, info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{file_name} must be a private regular file")
    if os.name != "nt":
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError(f"{file_name} must be a private regular file")
        return
    icacls = shutil.which("icacls")
    if not icacls:
        raise RuntimeError(f"unable to verify Windows ACL for {file_name}")
    result = subprocess.run(
        [icacls, path], capture_output=True, text=True, check=False  # nosec B603 - fixed system ACL utility and literal path
    )
    if result.returncode != 0:
        raise RuntimeError(f"unable to verify Windows ACL for {file_name}")
    acl_lines = result.stdout.splitlines()[1:]
    forbidden = ("everyone:", "authenticated users:", "builtin\\users:", "users:")
    if any(any(marker in line.casefold() for marker in forbidden) for line in acl_lines):
        raise RuntimeError(f"{file_name} must not be readable by broad Windows principals")


def _bootstrap_secret(env_name: str, file_name: str) -> str:
    def valid(value: str, source: str) -> str:
        if len(value) < 16 or len(set(value)) < 8:
            raise RuntimeError(f"{source} must contain at least 16 characters with varied entropy")
        lowered = value.casefold()
        if any(
            all((ord(window[index]) - ord(window[index - 1])) % 26 == 1 for index in range(1, len(window)))
            for start in range(len(lowered) - 7)
            for window in (lowered[start:start + 8],)
        ):
            raise RuntimeError(f"{source} must not be a predictable sequence")
        half = len(value) // 2
        if len(value) % 2 == 0 and value[:half] * 2 == value:
            raise RuntimeError(f"{source} must not be a repeated pattern")
        return value

    val = os.environ.get(env_name, "").strip()
    if val:
        return valid(val, env_name)
    path = _path(file_name)
    try:
        os.makedirs(_data_dir(), exist_ok=True)
        fd = -1
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if os.name == "nt":
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
                if attrs == 0xFFFFFFFF or attrs & 0x400:
                    raise RuntimeError(f"{file_name} must not be a Windows reparse point")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd_existing = os.open(path, flags)
            try:
                info = os.fstat(fd_existing)
                _validate_secret_file_security(path, file_name, info)
                with os.fdopen(fd_existing, encoding="utf-8") as fh:
                    fd_existing = -1
                    return valid(fh.read().strip(), file_name)
            finally:
                if fd_existing != -1:
                    os.close(fd_existing)
        val = secrets.token_urlsafe(32)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(val)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise RuntimeError(f"unable to secure {file_name}") from exc
        _validate_secret_file_security(path, file_name, os.stat(path))
        return valid(val, file_name)
    except OSError as exc:
        raise RuntimeError(f"unable to securely persist {file_name}") from exc


_ADMIN_TOKEN = _bootstrap_secret("AHUB_ADMIN_TOKEN", "admin_token")
_AUDIT_KEY = _bootstrap_secret("AHUB_AUDIT_KEY", "audit_key").encode()
if hmac.compare_digest(_ADMIN_TOKEN.encode(), _AUDIT_KEY):
    raise RuntimeError("AHUB_ADMIN_TOKEN and AHUB_AUDIT_KEY must be distinct")
# Derive a dedicated session-signing key so a compromised audit key cannot forge sessions.
_SESSION_KEY = hmac.new(_AUDIT_KEY, b"ahub-session-signing-v1", hashlib.sha256).digest()


def _verify_audit_chain(entries: list[dict]) -> bool:
    try:
        previous_mac = ""
        for expected_seq, entry in enumerate(entries):
            if (not isinstance(entry, dict) or entry.get("_malformed_detail")
                    or not isinstance(entry.get("action"), str)
                    or entry.get("action") not in _AUDIT_ACTIONS
                    or entry.get("seq") != expected_seq
                    or entry.get("prev") != previous_mac
                    or not isinstance(entry.get("detail"), dict)):
                return False
            body = {"seq": entry["seq"], "action": entry["action"],
                    "detail": entry["detail"], "prev": entry["prev"]}
            expected_mac = hmac.new(
                _AUDIT_KEY, json.dumps(body, sort_keys=True).encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(entry.get("mac", ""), expected_mac):
                return False
            previous_mac = entry["mac"]
        return True
    except (KeyError, TypeError, ValueError):
        return False




_AUDIT_ANCHOR_FILE = "audit_anchor.json"
_AUDIT_ACTIONS = frozenset({
    "issuer_add", "issuer_revoke", "service_register", "service_remove",
    "substrate_register", "substrate_remove", "policy_set", "policy_bind",
    "keystone_attestor_set", "state_reconcile",
})


def _audit_tail(entries: list[dict]) -> tuple[int, str]:
    if not entries:
        return -1, ""
    return int(entries[-1]["seq"]), str(entries[-1]["mac"])


@contextmanager
def _anchor_lock():
    path = _path("audit_anchor.lock")
    os.makedirs(_data_dir(), exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    fh = os.fdopen(fd, "r+b", buffering=0)
    try:
        fh.seek(0, os.SEEK_END)
        if fh.tell() == 0:
            fh.write(b"0")
            fh.flush()
        fh.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def _write_audit_anchor(entries: list[dict]) -> None:
    path = _path(_AUDIT_ANCHOR_FILE)
    os.makedirs(_data_dir(), exist_ok=True)
    seq, mac = _audit_tail(entries)
    with _anchor_lock():
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                existing = json.load(fh)
            if type(existing.get("seq")) is not int or type(existing.get("mac")) is not str:
                raise RuntimeError("audit anchor is malformed")
            if existing["seq"] > seq or (existing["seq"] == seq and existing["mac"] != mac):
                raise RuntimeError("audit anchor would move backwards")
        fd, tmp = tempfile.mkstemp(prefix=".audit-anchor-", dir=_data_dir(), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"seq": seq, "mac": mac}, fh, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _audit_anchor_ok(entries: list[dict], *, bootstrap_allowed: bool) -> bool:
    path = _path(_AUDIT_ANCHOR_FILE)
    if not os.path.exists(path):
        if not bootstrap_allowed:
            return False
        _write_audit_anchor(entries)
        return True
    advance = False
    try:
        with _anchor_lock():
            with open(path, encoding="utf-8") as fh:
                anchor = json.load(fh)
            if type(anchor.get("seq")) is not int or anchor["seq"] < -1:
                return False
            if type(anchor.get("mac")) is not str:
                return False
            current_seq, current_mac = _audit_tail(entries)
            if anchor["seq"] > current_seq:
                return False
            if anchor["seq"] == current_seq:
                if current_seq == -1 and not bootstrap_allowed:
                    return False
                return anchor["mac"] == current_mac
            if anchor["seq"] == -1:
                advance = bootstrap_allowed and not entries and anchor["mac"] == ""
            else:
                advance = (anchor["seq"] < len(entries)
                           and entries[anchor["seq"]].get("mac") == anchor["mac"])
        if not advance:
            return False
        _write_audit_anchor(entries)
        return True
    except (OSError, TypeError, ValueError, KeyError, AttributeError, json.JSONDecodeError):
        return False


def _validate_replay_snapshot(issuers: dict, services: dict, substrates: dict,
                              policy: dict | None, keystone: dict | None) -> None:
    import base64
    if not isinstance(issuers, dict) or not isinstance(services, dict) or not isinstance(substrates, dict):
        raise ValueError("replay snapshot registries must be objects")
    for did, record in issuers.items():
        if not isinstance(did, str) or not isinstance(record, dict) or set(record) != {"pk_b64", "kid", "added_at"}:
            raise ValueError("invalid issuer replay snapshot")
        _validate_did(did)
        if type(record["added_at"]) is not int or not isinstance(record["pk_b64"], str):
            raise ValueError("invalid issuer replay snapshot")
        decoded = base64.b64decode(record["pk_b64"], validate=True)
        if (len(decoded) != _FALCON1024_PK_LEN
                or base64.b64encode(decoded).decode("ascii") != record["pk_b64"]
                or _kid(decoded) != record["kid"]):
            raise ValueError("invalid issuer replay snapshot")
    for name, record in services.items():
        if not isinstance(name, str) or not isinstance(record, dict) or type(record.get("registered_at")) is not int:
            raise ValueError("invalid service replay snapshot")
        ServiceIn(name=name, **record)
    for name, record in substrates.items():
        if not isinstance(name, str) or not isinstance(record, dict) or type(record.get("registered_at")) is not int:
            raise ValueError("invalid substrate replay snapshot")
        SubstrateIn(name=name, **record)
    if policy is not None:
        if (not isinstance(policy, dict) or set(policy) != {"document", "policy_ref", "label", "set_at"}
                or not isinstance(policy["document"], dict) or not isinstance(policy["label"], str)
                or type(policy["set_at"]) is not int or policy_ref(policy["document"]) != policy["policy_ref"]):
            raise ValueError("invalid policy replay snapshot")
    if keystone is not None:
        if not isinstance(keystone, dict) or set(keystone) != {"did", "jwk", "kid", "set_at"} or type(keystone["set_at"]) is not int:
            raise ValueError("invalid Keystone replay snapshot")
        _validate_keystone_attestor(keystone["did"], keystone["jwk"], keystone["kid"])


def _audit_state_matches(entries: list[dict], current_state: dict | None = None) -> bool:
    """Replay authenticated registry snapshots so DB rows cannot drift silently."""
    issuers: dict[str, dict] = {}
    services: dict[str, dict] = {}
    substrates: dict[str, dict] = {}
    policy: dict | None = None
    keystone: dict | None = None
    active_policy_ref: str | None = None
    legacy_incomplete = False
    reconciled = False
    if current_state is None:
        current_state = {
            "issuers": _issuers, "services": _services, "substrates": _substrates,
            "policy": _policy, "keystone": _keystone_attestor,
        }
    current_issuers = current_state["issuers"]
    current_services = current_state["services"]
    current_substrates = current_state["substrates"]
    current_policy = current_state["policy"]
    current_keystone = current_state["keystone"]
    try:
        for entry in entries:
            action, detail = entry["action"], entry["detail"]
            if action == "state_reconcile":
                if set(detail) != {"issuers", "services", "substrates", "policy", "keystone"}:
                    return False
                _validate_replay_snapshot(detail["issuers"], detail["services"], detail["substrates"], detail["policy"], detail["keystone"])
                issuers = detail["issuers"]
                services = detail["services"]
                substrates = detail["substrates"]
                policy = detail.get("policy")
                keystone = detail.get("keystone")
                active_policy_ref = policy.get("policy_ref") if policy else None
                reconciled = True
                legacy_incomplete = False
            elif action == "issuer_add":
                if set(detail) != {"did", "pk_b64", "kid", "added_at"}:
                    if reconciled:
                        return False
                    legacy_incomplete = True
                    continue
                _validate_replay_snapshot({detail["did"]: {k: detail[k] for k in ("pk_b64", "kid", "added_at")}}, {}, {}, None, None)
                issuers[detail["did"]] = {k: detail[k] for k in ("pk_b64", "kid", "added_at")}
            elif action == "issuer_revoke":
                if detail["did"] not in issuers:
                    return False
                if set(detail) != {"did", "pk_b64", "kid", "added_at"}:
                    return False
                snapshot = {k: detail[k] for k in ("pk_b64", "kid", "added_at")}
                if issuers[detail["did"]] != snapshot:
                    return False
                issuers.pop(detail["did"])
            elif action == "service_register":
                required = {"name", "type", "base_url", "health_path", "registered_at"}
                if set(detail) != required:
                    if reconciled:
                        return False
                    legacy_incomplete = True
                    continue
                ServiceIn(name=detail["name"], type=detail["type"], base_url=detail["base_url"], health_path=detail["health_path"])
                if type(detail["registered_at"]) is not int:
                    return False
                services[detail["name"]] = {k: detail[k] for k in ("type", "base_url", "health_path", "registered_at")}
            elif action == "service_remove":
                if detail["name"] not in services:
                    return False
                if set(detail) != {"name", "type", "base_url", "health_path", "registered_at"}:
                    return False
                snapshot = {k: detail[k] for k in ("type", "base_url", "health_path", "registered_at")}
                if services[detail["name"]] != snapshot:
                    return False
                services.pop(detail["name"])
            elif action == "substrate_register":
                required = {"name", "family", "version", "adapter", "base_url", "health_path", "capabilities", "policy_ref", "registered_at"}
                if set(detail) != required:
                    if reconciled:
                        return False
                    legacy_incomplete = True
                    continue
                SubstrateIn(name=detail["name"], family=detail["family"], version=detail["version"], adapter=detail["adapter"], base_url=detail["base_url"], health_path=detail["health_path"], capabilities=detail["capabilities"], policy_ref=detail["policy_ref"])
                if type(detail["registered_at"]) is not int:
                    return False
                substrates[detail["name"]] = {k: detail[k] for k in required if k != "name"}
            elif action == "substrate_remove":
                if detail["name"] not in substrates:
                    return False
                required_snapshot = {"name", "family", "version", "adapter", "base_url", "health_path", "capabilities", "policy_ref", "registered_at"}
                if set(detail) != required_snapshot:
                    return False
                snapshot = {k: detail[k] for k in required_snapshot if k != "name"}
                if substrates[detail["name"]] != snapshot:
                    return False
                substrates.pop(detail["name"])
            elif action == "policy_set":
                if set(detail) != {"policy_ref", "label", "set_at"}:
                    if reconciled:
                        return False
                    legacy_incomplete = True
                    continue
                if (not isinstance(detail["policy_ref"], str)
                        or not re.fullmatch(r"sha256:[0-9a-f]{64}", detail["policy_ref"])
                        or not isinstance(detail["label"], str) or type(detail["set_at"]) is not int):
                    return False
                policy = {k: detail[k] for k in ("policy_ref", "label", "set_at")}
                active_policy_ref = detail["policy_ref"]
            elif action == "policy_bind":
                required = {"subject_ref", "policy_ref", "bound_ref"}
                if set(detail) != required:
                    if reconciled:
                        return False
                    legacy_incomplete = True
                    continue
                if detail["policy_ref"] != active_policy_ref:
                    return False
                if policy_bound_ref(detail["subject_ref"], detail["policy_ref"]) != detail["bound_ref"]:
                    return False
            elif action == "keystone_attestor_set":
                if set(detail) != {"did", "jwk", "kid", "set_at"}:
                    if reconciled:
                        return False
                    legacy_incomplete = True
                    continue
                if type(detail["set_at"]) is not int:
                    return False
                _validate_keystone_attestor(detail["did"], detail["jwk"], detail["kid"])
                keystone = {k: detail[k] for k in ("did", "jwk", "kid", "set_at")}
        import base64
        for did, record in current_issuers.items():
            if set(record) != {"pk_b64", "kid", "added_at"} or type(record["added_at"]) is not int:
                return False
            _validate_did(did)
            decoded = base64.b64decode(record["pk_b64"], validate=True)
            if (len(decoded) != _FALCON1024_PK_LEN
                    or base64.b64encode(decoded).decode("ascii") != record["pk_b64"]
                    or _kid(decoded) != record["kid"]):
                return False
        for name, record in current_services.items():
            if set(record) != {"type", "base_url", "health_path", "registered_at"} or type(record["registered_at"]) is not int:
                return False
            ServiceIn(name=name, **record)
        for name, record in current_substrates.items():
            if set(record) != {"family", "version", "adapter", "base_url", "health_path", "capabilities", "policy_ref", "registered_at"} or type(record["registered_at"]) is not int:
                return False
            SubstrateIn(name=name, **record)
        if legacy_incomplete and not reconciled:
            return False
        if issuers != current_issuers or services != current_services or substrates != current_substrates:
            return False
        if policy is None:
            if current_policy is not None:
                return False
        elif current_policy is None or any(current_policy.get(k) != v for k, v in policy.items()):
            return False
        if current_keystone is not None:
            if set(current_keystone) != {"did", "jwk", "kid", "set_at"}:
                return False
            _validate_keystone_attestor(current_keystone["did"], current_keystone["jwk"], current_keystone["kid"])
        if keystone is None:
            return current_keystone is None
        return current_keystone is not None and all(current_keystone.get(k) == v for k, v in keystone.items())
    except (KeyError, TypeError, ValueError):
        return False


def _policy_bind_count(entries: list[dict]) -> int:
    count = 0
    for entry in entries:
        if entry["action"] in {"policy_set", "state_reconcile"}:
            count = 0
        elif entry["action"] == "policy_bind":
            count += 1
    return count



# Persistence: SQLite by default, PostgreSQL when AHUB_DB is set. The working set
# is held in memory (fast reads) and written through to the store (durable).
try:
    _store = Store()
except Exception:  # noqa: BLE001
    _store = None
    _INITIAL_STATE_OK = False
_INITIAL_STATE_OK = _store is not None
try:
    _initial_state = _store.state_load()
    _issuers: dict[str, dict] = _initial_state["issuers"]
    _services: dict[str, dict] = _initial_state["services"]
    _substrates: dict[str, dict] = _initial_state["substrates"]
    _audit: list[dict] = _initial_state["audit"]
    _policy: dict | None = _initial_state["policy"]
    _keystone_attestor: dict | None = _initial_state["keystone"]
    _INITIAL_KV_KEYS = _initial_state["kv_keys"]
except Exception:  # noqa: BLE001
    _INITIAL_STATE_OK = False
    _issuers, _services, _substrates, _audit = {}, {}, {}, []
    _policy, _keystone_attestor, _INITIAL_KV_KEYS = None, None, set()
_AUDIT_INTEGRITY_OK = _INITIAL_STATE_OK and _verify_audit_chain(_audit)
_policy_bound_count = 0


def _audit_append(action: str, detail: dict) -> None:
    global _AUDIT_INTEGRITY_OK, _audit
    _require_audit_integrity()
    entry = _store.audit_append(action, detail, _AUDIT_KEY)
    try:
        _audit = _store.audit_load()
        _write_audit_anchor(_audit)
        _refresh_persisted_state()
    except Exception as exc:
        _audit.append(entry)
        _AUDIT_INTEGRITY_OK = False
        raise HTTPException(status_code=503, detail="audit commit verification failed") from exc


def _audit_committed(entry: dict[str, Any]) -> None:
    global _AUDIT_INTEGRITY_OK, _audit
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            _audit = _store.audit_load()
            _write_audit_anchor(_audit)
            _refresh_persisted_state()
            if not _AUDIT_INTEGRITY_OK:
                raise RuntimeError("persisted state exceeded an integrity limit")
            return
        except Exception as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(0.01 * (attempt + 1))
                continue
    _audit.append(entry)
    _AUDIT_INTEGRITY_OK = False
    raise HTTPException(status_code=503, detail="audit commit verification failed") from last_exc


def _refresh_persisted_state() -> None:
    global _issuers, _services, _substrates, _audit, _policy, _keystone_attestor, _AUDIT_INTEGRITY_OK, _policy_bound_count
    state = _store.state_load()
    _issuers = state["issuers"]
    _services = state["services"]
    _substrates = state["substrates"]
    _policy = state["policy"]
    _keystone_attestor = state["keystone"]
    _audit = state["audit"]
    bootstrap_allowed = not (_audit or _issuers or _services or _substrates or _policy or _keystone_attestor or state["kv_keys"])
    kv_keys = set(state["kv_keys"])
    kv_ok = (
        kv_keys.issubset({"active_policy", "keystone_attestor"})
        and not ("active_policy" in kv_keys and _policy is None)
        and not ("keystone_attestor" in kv_keys and _keystone_attestor is None)
    )
    size_ok = (
        len(_audit) <= _MAX_AUDIT_ENTRIES
        and len(_issuers) <= _MAX_ISSUERS
        and len(_services) <= _MAX_SERVICES
        and len(_substrates) <= _MAX_SUBSTRATES
    )
    audit_ok = (
        _verify_audit_chain(_audit)
        and _audit_anchor_ok(_audit, bootstrap_allowed=bootstrap_allowed)
        and _audit_state_matches(_audit, {
            "issuers": _issuers, "services": _services, "substrates": _substrates,
            "policy": _policy, "keystone": _keystone_attestor,
        })
        and kv_ok
        and size_ok
    )
    policy_ok = True
    if _policy is not None:
        try:
            if set(_policy) != {"document", "policy_ref", "label", "set_at"} or type(_policy["set_at"]) is not int:
                policy_ok = False
            else:
                policy_ok = policy_ref(_policy["document"]) == _policy.get("policy_ref")
        except (KeyError, TypeError, ValueError):
            policy_ok = False
    _AUDIT_INTEGRITY_OK = audit_ok and policy_ok
    _policy_bound_count = _policy_bind_count(_audit) if _AUDIT_INTEGRITY_OK else 0


def _require_admin(authorization: str | None) -> None:
    token = authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else None
    if not token or not hmac.compare_digest(token, _ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="admin bearer token required")




_REGISTRATION_TOKEN = os.environ.get("AHUB_REGISTRATION_TOKEN", "")
_REGISTRATION_NAME = os.environ.get("AHUB_REGISTRATION_NAME", "").strip()
try:
    _REGISTRATION_TOKENS = json.loads(os.environ.get("AHUB_REGISTRATION_TOKENS", "{}"))
    if not isinstance(_REGISTRATION_TOKENS, dict) or any(not isinstance(k, str) or not isinstance(v, str) or not k or not v for k, v in _REGISTRATION_TOKENS.items()):
        raise ValueError
except (TypeError, ValueError, json.JSONDecodeError) as exc:
    raise RuntimeError("AHUB_REGISTRATION_TOKENS must be a JSON object mapping service names to tokens") from exc
if len(set(_REGISTRATION_TOKENS.values())) != len(_REGISTRATION_TOKENS):
    raise RuntimeError("AHUB_REGISTRATION_TOKENS values must be unique")
def _validate_registration_credential(value: str, source: str) -> None:
    if len(value) < 16 or len(set(value)) < 8:
        raise RuntimeError(f"{source} must contain at least 16 characters with varied entropy")


if _REGISTRATION_TOKEN:
    _validate_registration_credential(_REGISTRATION_TOKEN, "AHUB_REGISTRATION_TOKEN")
for _registration_name, _registration_value in _REGISTRATION_TOKENS.items():
    _validate_registration_credential(_registration_value, f"AHUB_REGISTRATION_TOKENS[{_registration_name!r}]")
if hmac.compare_digest(_REGISTRATION_TOKEN, _ADMIN_TOKEN) or _REGISTRATION_TOKEN in _REGISTRATION_TOKENS.values() or any(hmac.compare_digest(token, _ADMIN_TOKEN) for token in _REGISTRATION_TOKENS.values()):
    raise RuntimeError("registration credentials must not equal the admin token")
if _REGISTRATION_TOKEN and not _REGISTRATION_NAME:
    raise RuntimeError("AHUB_REGISTRATION_NAME is required with AHUB_REGISTRATION_TOKEN")


def _require_service_registration(authorization: str | None, name: str | None = None, type_: str | None = None) -> bool:
    token = authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else None
    if not token:
        raise HTTPException(status_code=401, detail="service registration bearer token required")
    if hmac.compare_digest(token, _ADMIN_TOKEN):
        if type_ == "addon":
            raise HTTPException(status_code=403, detail="addon registration requires a scoped registration token")
        return True
    if type_ != "addon":
        raise HTTPException(status_code=403, detail="scoped registration tokens may only register type 'addon'")
    if _REGISTRATION_TOKEN and hmac.compare_digest(token, _REGISTRATION_TOKEN) and name == _REGISTRATION_NAME:
        return False
    if name and name in _REGISTRATION_TOKENS and hmac.compare_digest(token, _REGISTRATION_TOKENS[name]):
        return False
    raise HTTPException(status_code=401, detail="service registration bearer token required")


def _kid(pk_bytes: bytes) -> str:
    return hashlib.sha256(pk_bytes).hexdigest()[:16]


def _require_audit_integrity() -> None:
    if _AUDIT_REQUEST_VALIDATED.get():
        return
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            _refresh_persisted_state()
            if _AUDIT_INTEGRITY_OK:
                return
        except Exception as exc:
            last_error = exc
        if attempt < 4:
            time.sleep(0.01 * (attempt + 1))
    raise HTTPException(status_code=503, detail="audit chain integrity failure") from last_error

def _atb_keys_doc(did: str) -> dict:
    rec = _issuers[did]
    return {
        "issuer": did,
        "ietf_anchor": _IETF_ANCHOR,
        "keys": [{
            "alg": "Falcon-1024",
            "kid": rec["kid"],
            "public_key_b64": rec["pk_b64"],
            "public_key_pqclean_b64": rec["pk_b64"],
            "use": "sig",
            "key_size_bytes": _FALCON1024_PK_LEN,
        }],
    }


app = FastAPI(
    title="AlgoVoi Secure Hub",
    description="Issuer-trust hub + service bridge for the substrate-2 federation and ZK-proof services.",
    version=__version__,
    docs_url="/docs",
    redoc_url=None,
)


# Keystone settings-panel integration is intentionally not mounted here. The available
# algovoi-keystone-control package exposes a standalone ASGI app, not a compatible
# make_router/KeystoneControl API. The control plane's audited Keystone attestor API
# below remains the supported integration surface.
_kc = None


# ── Login gate: themed sign-in + session cookie for browsers, Bearer token for API clients ──
from fastapi import Form as _Form
from starlette.responses import RedirectResponse as _Redirect, Response as _Response
from algovoi_secure_hub.panel import render_login as _render_login

_SESSION_COOKIE = "ahub_session"
_SESSION_TTL_S = 86_400
# SECURITY (2026-08-19): the panel session cookie was a STATIC HMAC that never changed — a leaked cookie was
# valid indefinitely and could not be revoked server-side without rotating the audit key (which also breaks
# audit MACs). It is now a self-contained EXPIRING signed token ``<exp>.<hmac(audit_key, exp)>``, so the
# server rejects it once ``exp`` passes (no shared state needed; multi-worker safe).
_AUTH_OPEN = {"/health", "/login", "/logout"}


def _make_session(now_s: int, ttl_s: int = _SESSION_TTL_S) -> str:
    exp = now_s + ttl_s
    mac = hmac.new(_SESSION_KEY, f"s2cp-session-v2|{exp}".encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{mac}"


def _session_ok(cookie: str, now_s: int) -> bool:
    try:
        exp_str, mac = cookie.split(".", 1)
        exp = int(exp_str)
    except Exception:  # noqa: BLE001
        return False
    if now_s >= exp:
        return False
    expected = hmac.new(_SESSION_KEY, f"s2cp-session-v2|{exp}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)
# SECURITY (2026-08-19): the read-only trust-consumption endpoints expose ONLY published public keys and
# DIDs (the trust anchors bridged consumers are documented to fetch — FEDERATION_ISSUER_PKS, the atb hub
# doc, etc.). Gating them behind the admin token forced every consumer to hold the FULL admin credential
# (which also grants writes to the PQ trust root) — a large blast radius. These GETs are public; all WRITE
# endpoints (POST/DELETE issuers, policy, services, keystone-attestor) stay admin-gated, so the trust root
# cannot be MODIFIED without admin, and the richer admin reads (audit, policy, services, posture, panel)
# stay gated too.
_PUBLIC_TRUST_PATHS = {"/v1/issuers", "/v1/issuer-pks", "/.well-known/atb-keys.json"}


def _is_public_trust_path(path: str) -> bool:
    if path in _PUBLIC_TRUST_PATHS:
        return True
    # per-issuer key document: /issuers/{did}/atb-keys.json (did may itself contain slashes)
    return path.startswith("/issuers/") and path.endswith("/atb-keys.json")


def _is_authed(request) -> bool:
    c = request.cookies.get(_SESSION_COOKIE)
    if c and _session_ok(c, int(time.time())):
        return True
    auth = request.headers.get("authorization", "")
    return auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].strip(), _ADMIN_TOKEN)


def _request_rate_allowed(request, bucket: str, limit: int) -> bool:
    client_host = getattr(request.client, "host", None) or "unknown"
    key = (bucket, client_host)
    now = time.monotonic()
    with _RATE_LOCK:
        if key not in _RATE_BUCKETS and len(_RATE_BUCKETS) >= 10_000:
            # Single pass: evict expired buckets first, then fall back to oldest.
            cutoff = now - 60.0
            expired = [k for k, (started, _) in _RATE_BUCKETS.items() if started < cutoff]
            for k in expired:
                _RATE_BUCKETS.pop(k, None)
            if len(_RATE_BUCKETS) >= 10_000:
                oldest = min(_RATE_BUCKETS, key=lambda k: _RATE_BUCKETS[k][0])
                _RATE_BUCKETS.pop(oldest, None)
        started, count = _RATE_BUCKETS.get(key, (now, 0))
        if now - started >= 60.0:
            started, count = now, 0
        if count >= limit:
            _RATE_BUCKETS[key] = (started, count)
            return False
        _RATE_BUCKETS[key] = (started, count + 1)
        return True


@app.middleware("http")
async def _security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; "
        "img-src 'self' data:; frame-ancestors 'none'"
    )
    return response


@app.middleware("http")
async def _login_gate(request, call_next):
    # Public trust reads are GET-only; they are unavailable while the trust root is degraded.
    public_read = request.method in ("GET", "HEAD") and _is_public_trust_path(request.url.path)
    if request.url.path == "/health" and request.method in ("GET", "HEAD"):
        if not _request_rate_allowed(request, "health", _HEALTH_RPM):
            return _Response(status_code=429, headers={"Retry-After": "60"}, content="health rate limit exceeded")
    if request.url.path == "/login" and request.method == "POST":
        if not _request_rate_allowed(request, "login", _LOGIN_RPM):
            return _Response(status_code=429, headers={"Retry-After": "60"}, content="login rate limit exceeded")
    if request.url.path in _AUTH_OPEN:
        return await call_next(request)
    if public_read:
        if not _request_rate_allowed(request, "trust", _PUBLIC_TRUST_RPM):
            return _Response(status_code=429, headers={"Retry-After": "60"}, content="public trust read rate limit exceeded")
        try:
            _refresh_persisted_state()
        except Exception:
            return _Response(status_code=503, content="audit chain integrity failure")
        if not _AUDIT_INTEGRITY_OK:
            return _Response(status_code=503, content="audit chain integrity failure")
        validation_token = _AUDIT_REQUEST_VALIDATED.set(True)
        try:
            response = await call_next(request)
        finally:
            _AUDIT_REQUEST_VALIDATED.reset(validation_token)
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        seq, mac = _audit_tail(_audit)
        response.headers["X-AHUB-Audit-Tail"] = f"{seq}:{mac}"
        return response
    authenticated = _is_authed(request)
    if (not authenticated and request.method == "POST" and request.url.path == "/v1/services"
            and request.headers.get("authorization", "").startswith("Bearer ")):
        _tok = request.headers["authorization"][7:].strip()
        # Compare against every token unconditionally (no short-circuit) to avoid timing
        # side-channels that reveal how many or which tokens are configured.
        _results = [hmac.compare_digest(_tok, _REGISTRATION_TOKEN)] if _REGISTRATION_TOKEN else []
        _results += [hmac.compare_digest(_tok, v) for v in _REGISTRATION_TOKENS.values()]
        _tok_ok = any(_results)
        if _tok_ok:
            authenticated = True
    if authenticated:
        if request.method not in ("GET", "HEAD"):
            try:
                _require_audit_integrity()
            except HTTPException as exc:
                return _Response(status_code=exc.status_code, content=exc.detail)
        return await call_next(request)
    if "text/html" in request.headers.get("accept", ""):
        return _Redirect("/login", status_code=303)
    return _Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})


# ── Security middleware stack (Edge → WAF → Guard, outermost-first) ─────────────────
# Starlette applies @app.middleware("http") in LIFO order: the last decorator
# registered is the outermost wrapper (first to receive the request).  To get
# Edge outermost → WAF → Guard → existing _login_gate → _security_headers we
# register Guard first (innermost of the three), WAF next, Edge last.

@app.middleware("http")
async def _guard_filter(request, call_next):
    return await guard_middleware(request, call_next)


@app.middleware("http")
async def _waf_filter(request, call_next):
    return await waf_middleware(request, call_next)


@app.middleware("http")
async def _edge_filter(request, call_next):
    return await edge_middleware(request, call_next)


@app.get("/login", response_class=HTMLResponse)
async def login_page(e: int = 0) -> HTMLResponse:
    return HTMLResponse(_render_login(error=bool(e)))


@app.post("/login")
async def login_submit(password: Annotated[str, _Form()] = "") -> Any:
    if hmac.compare_digest(password, _ADMIN_TOKEN):
        r = _Redirect("/", status_code=303)
        secure_cookie = os.environ.get("AHUB_COOKIE_SECURE", "1").strip().lower() not in {"0", "false", "no"}
        r.set_cookie(_SESSION_COOKIE, _make_session(int(time.time())), httponly=True, secure=secure_cookie,
                     samesite="lax", max_age=_SESSION_TTL_S)
        return r
    return _Redirect("/login?e=1", status_code=303)


@app.get("/logout")
async def logout() -> Any:
    r = _Redirect("/login", status_code=303)
    r.delete_cookie(_SESSION_COOKIE)
    return r


# ── Models ──────────────────────────────────────────────────────────────────────────

_DID_RE = re.compile(r"^did:[a-z0-9]+:[A-Za-z0-9._:%/-]{1,240}$")


def _validate_did(value: str) -> str:
    value = value.strip()
    if not _DID_RE.fullmatch(value):
        raise ValueError("did must be a bounded canonical DID without control characters")
    return value


class IssuerIn(BaseModel):
    did: str = Field(..., description="Issuer DID, e.g. did:web:bench.example")
    public_key_b64: str = Field(..., description="Falcon-1024 public key, base64 standard.")

    @field_validator("did")
    @classmethod
    def validate_did(cls, value: str) -> str:
        return _validate_did(value)


def _validate_decoded_path(path: str, field: str) -> str:
    decoded = path.replace("\\", "/")
    for _ in range(32):
        next_value = unquote(decoded).replace("\\", "/")
        if next_value == decoded:
            break
        decoded = next_value
    else:
        raise ValueError(f"{field} contains excessive URL encoding")
    if any(segment == ".." for segment in decoded.split("/")):
        raise ValueError(f"{field} must not contain traversal segments")
    return decoded


def _validate_http_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("base_url port must be between 0 and 65535") from exc
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("base_url must be an http(s) URL without credentials, query or fragment")
    if port is not None and not (0 < port <= 65535):
        raise ValueError("base_url port must be between 1 and 65535")
    _validate_decoded_path(parsed.path, "base_url")
    return value.rstrip("/")


def _validate_health_path(value: str) -> str:
    value = value.strip()
    if not value.startswith("/") or "?" in value or "#" in value:
        raise ValueError("health_path must be an absolute path without query or fragment")
    _validate_decoded_path(value, "health_path")
    return value


class ServiceIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    type: str = Field("addon", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", description="federation | zkp-receipt | atb-verifier | addon | ...")
    base_url: str = Field(..., max_length=2048, description="Service base URL, e.g. http://federation-validator:8092")
    health_path: str = Field("/health", max_length=512)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return _validate_http_url(value)

    @field_validator("health_path")
    @classmethod
    def validate_health_path(cls, value: str) -> str:
        return _validate_health_path(value)


_SUBSTRATE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")


class SubstrateIn(BaseModel):
    name: str = Field(..., description="Stable adapter registration name.")
    family: str = Field(..., description="Substrate family, e.g. open-substrate or substrate-2.")
    version: str = Field(..., description="Protocol/substrate version.")
    adapter: str = Field(..., description="Named adapter implementing the control-plane contract.")
    base_url: str = Field(..., max_length=2048, description="Health endpoint base URL.")
    health_path: str = Field("/health", max_length=512)
    capabilities: list[str] = Field(default_factory=list, max_length=64)
    policy_ref: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @staticmethod
    def _token(value: str, field: str) -> str:
        value = value.strip()
        if not _TOKEN_RE.fullmatch(value):
            raise ValueError(f"{field} contains unsupported characters")
        return value

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()
        if not _SUBSTRATE_NAME_RE.fullmatch(value):
            raise ValueError("name must use lowercase letters, digits, '.', '_' or '-' and start with a letter/digit")
        return value

    @field_validator("family", "version", "adapter")
    @classmethod
    def validate_tokens(cls, value: str, info) -> str:
        return cls._token(value, info.field_name)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return _validate_http_url(value)

    @field_validator("health_path")
    @classmethod
    def validate_health_path(cls, value: str) -> str:
        return _validate_health_path(value)

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, values: list[str]) -> list[str]:
        cleaned = [cls._token(value, "capability") for value in values]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("capabilities must be unique")
        return cleaned


class PolicyIn(BaseModel):
    document: dict = Field(..., description="The policy/ruleset/mandate snapshot (any JSON object).")
    label: str = Field("", description="Human label, e.g. 'aml.transfer/v1' (informational only).")


class BindIn(BaseModel):
    subject_ref: str = Field(..., description='A frozen subject ref ("sha256:<hex>") — a binding_ref or retention_chain_ref.')


def _validate_keystone_attestor(did: str, jwk: dict, kid: str) -> None:
    if not re.fullmatch(r"did:key:z[1-9A-HJ-NP-Za-km-z]+", did):
        raise ValueError("did must be a base58btc did:key")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    encoded = did[9:]
    number = 0
    for char in encoded:
        number = number * 58 + alphabet.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    leading = len(encoded) - len(encoded.lstrip("1"))
    raw = b"\x00" * leading + raw
    if raw[:2] != b"\xed\x01" or len(raw[2:]) != 32:
        raise ValueError("did:key must encode an Ed25519 public key")
    if not isinstance(kid, str) or not _TOKEN_RE.fullmatch(kid):
        raise ValueError("kid contains unsupported characters")
    if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x"} or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("jwk must be an Ed25519 OKP public key")
    if "d" in jwk or not isinstance(jwk.get("x"), str):
        raise ValueError("jwk must contain only the public x coordinate")
    import base64
    try:
        x = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    except Exception as exc:
        raise ValueError("jwk x is not valid base64url") from exc
    if base64.urlsafe_b64encode(x).rstrip(b"=").decode("ascii") != jwk["x"]:
        raise ValueError("jwk x is not canonical base64url")
    if len(x) != 32 or x != raw[2:]:
        raise ValueError("jwk x does not match the did:key public key")


class KeystoneAttestorIn(BaseModel):
    did: str = Field(..., description="The keystone attestor did:key (Ed25519).")
    jwk: dict = Field(..., description="The attestor public JWK (OKP/Ed25519), as published at the attestor jwks.")
    kid: str = Field(..., description="Key id; matches the published jwks kid.")

    @model_validator(mode="after")
    def validate_binding(self):
        _validate_keystone_attestor(self.did, self.jwk, self.kid)
        return self


def _policy_view() -> dict:
    """The policy-bridge posture block (built-in capability, always present)."""
    if not _policy:
        return {"active": False, "bound_count": _policy_bound_count}
    return {"active": True, "policy_ref": _policy["policy_ref"], "label": _policy.get("label", ""),
            "set_at": _policy.get("set_at"), "bound_count": _policy_bound_count}


def _keystone_view() -> dict:
    """The keystone posture block (built-in capability, always present). The hub distributes the
    keystone attestor key so a bridged service trusts keystone signatures as AlgoVoi; one
    Ed25519 key, evidence rendered as keystone_evidence / JWS / VC / PEF / TAP / ZK."""
    if not _keystone_attestor:
        return {"active": False}
    return {"active": True, "attestor_did": _keystone_attestor["did"],
            "kid": _keystone_attestor["kid"], "set_at": _keystone_attestor.get("set_at"),
            "evidence_formats": ["keystone_evidence", "jws", "vc", "pef", "tap", "zkp"]}


# ── Health ──────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> Any:
    try:
        _refresh_persisted_state()
    except Exception:
        body = {"status": "degraded", "service": "algovoi-secure-hub", "version": __version__, "audit_integrity": False}
        return JSONResponse(body, status_code=503)
    body = {
        "status": "ok" if _AUDIT_INTEGRITY_OK else "degraded",
        "service": "algovoi-secure-hub",
        "version": __version__,
        "issuer_count": len(_issuers),
        "service_count": len(_services),
        "substrate_count": len(_substrates),
        "audit_entries": len(_audit),
        "audit_integrity": _AUDIT_INTEGRITY_OK,
    }
    return JSONResponse(body, status_code=200 if _AUDIT_INTEGRITY_OK else 503)


# ── Issuer trust registry (admin) ──────────────────────────────────────────────────

@app.post("/v1/issuers")
async def add_issuer(body: IssuerIn, authorization: Annotated[str | None, Header()] = None) -> dict:
    _require_admin(authorization)
    _require_audit_integrity()
    try:
        import base64
        pk = base64.b64decode(body.public_key_b64, validate=True)
        if base64.b64encode(pk).decode("ascii") != body.public_key_b64:
            raise ValueError("non-canonical base64")
    except Exception:
        raise HTTPException(status_code=400, detail="public_key_b64 is not valid base64")
    if len(pk) != _FALCON1024_PK_LEN:
        raise HTTPException(status_code=400, detail=f"public key must be {_FALCON1024_PK_LEN} bytes (got {len(pk)})")
    added_at = _issuers.get(body.did, {}).get("added_at", int(time.time()))
    rec = {"pk_b64": body.public_key_b64, "kid": _kid(pk), "added_at": added_at}
    detail = {"did": body.did, **rec}
    try:
        entry = _store.issuer_add_with_audit(
            body.did, rec["pk_b64"], rec["kid"], rec["added_at"], "issuer_add", detail, _AUDIT_KEY
        )
    except ValueError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=409, detail="issuer changed concurrently") from exc
    except RuntimeError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if entry is None:
        _refresh_persisted_state()
        return {"did": body.did, "kid": _issuers[body.did]["kid"], "issuer_count": len(_issuers), "unchanged": True}
    _issuers[body.did] = rec
    _audit_committed(entry)
    return {"did": body.did, "kid": rec["kid"], "issuer_count": len(_issuers)}


@app.delete("/v1/issuers/{did:path}")
async def revoke_issuer(did: str, authorization: Annotated[str | None, Header()] = None) -> dict:
    _require_admin(authorization)
    _require_audit_integrity()
    if did not in _issuers:
        raise HTTPException(status_code=404, detail="unknown issuer")
    previous = _issuers[did]
    detail = {"did": did, **previous}
    try:
        entry = _store.issuer_remove_with_audit(did, "issuer_revoke", detail, _AUDIT_KEY)
    except KeyError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=404, detail="unknown issuer") from exc
    except RuntimeError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _audit_committed(entry)
    _refresh_persisted_state()
    return {"did": did, "revoked": True, "issuer_count": len(_issuers)}


@app.get("/v1/issuers")
async def list_issuers() -> dict:
    _require_audit_integrity()
    return {"issuers": [{"did": d, "kid": r["kid"], "added_at": r["added_at"]} for d, r in _issuers.items()]}


# ── Hub: trust set in the shapes the three services consume ────────────────────────────

@app.get("/v1/issuer-pks")
async def issuer_pks() -> dict[str, str]:
    """{did: pk_b64} — load this as FEDERATION_ISSUER_PKS / ZKP_RECEIPT_ISSUER_PKS,
    or as the atb-credential-verifier multi-hub allowlist."""
    _require_audit_integrity()
    payload = {d: r["pk_b64"] for d, r in _issuers.items()}
    if len(json.dumps(payload, separators=(",", ":")).encode("utf-8")) > _MAX_TRUST_RESPONSE_BYTES:
        raise HTTPException(status_code=503, detail="issuer trust response exceeds the configured limit")
    return payload


@app.get("/.well-known/atb-keys.json")
async def well_known_atb_keys() -> JSONResponse:
    """Canonical ATB hub doc for the primary (first-registered) issuer — the shape
    the atb-credential-verifier hub_resolver fetches."""
    _require_audit_integrity()
    if not _issuers:
        raise HTTPException(status_code=404, detail="no issuers registered")
    primary = min(_issuers, key=lambda did: (_issuers[did].get("added_at", 0), did))
    return JSONResponse(_atb_keys_doc(primary))


@app.get("/issuers/{did:path}/atb-keys.json")
async def issuer_atb_keys(did: str) -> JSONResponse:
    _require_audit_integrity()
    if did not in _issuers:
        raise HTTPException(status_code=404, detail="unknown issuer")
    return JSONResponse(_atb_keys_doc(did))


# ── Service bridge + addon bolt-in ────────────────────────────────────────────────────

@app.post("/v1/services")
async def register_service(body: ServiceIn, authorization: Annotated[str | None, Header()] = None) -> dict:
    """Register a substrate-2 service or bolt-on addon so it appears in the
    posture and shares the issuer trust set. This is the addon mechanism."""
    is_admin = _require_service_registration(authorization, body.name, body.type)
    _require_audit_integrity()
    _refresh_persisted_state()
    if not is_admin and body.name in _services:
        current = _services[body.name]
        if (current["type"], current["base_url"], current["health_path"]) != (
            body.type, body.base_url, body.health_path
        ):
            raise HTTPException(status_code=409, detail="scoped registration cannot change an existing service")
    svc = {
        "type": body.type, "base_url": body.base_url.rstrip("/"),
        "health_path": body.health_path, "registered_at": int(time.time()),
    }
    detail = {"name": body.name, **svc}
    try:
        entry = _store.service_register_with_audit(
            body.name, svc["type"], svc["base_url"], svc["health_path"], svc["registered_at"],
            "service_register", detail, _AUDIT_KEY, immutable=not is_admin,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail="stale service registration") from exc
    if entry is None:
        _refresh_persisted_state()
        return {"name": body.name, "service_count": len(_services), "unchanged": True}
    _services[body.name] = svc
    _audit_committed(entry)
    return {"name": body.name, "service_count": len(_services)}


@app.get("/v1/services")
async def list_services() -> dict:
    _require_audit_integrity()
    return {"services": [{"name": n, **v} for n, v in _services.items()],
            "default_bridge": list(_DEFAULT_SERVICES)}


@app.delete("/v1/services/{name}")
async def remove_service(name: str, authorization: Annotated[str | None, Header()] = None) -> dict:
    _require_admin(authorization)
    _require_audit_integrity()
    if name not in _services:
        raise HTTPException(status_code=404, detail="unknown service")
    detail = {"name": name, **_services[name]}
    try:
        entry = _store.service_remove_with_audit(name, "service_remove", detail, _AUDIT_KEY)
    except KeyError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=404, detail="unknown service") from exc
    except RuntimeError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _audit_committed(entry)
    _refresh_persisted_state()
    return {"name": name, "removed": True, "service_count": len(_services)}


# ── Substrate-neutral adapter registry ────────────────────────────────────────────

@app.post("/v1/substrates")
async def register_substrate(body: SubstrateIn,
                             authorization: Annotated[str | None, Header()] = None) -> dict:
    """Register a substrate adapter without changing the substrate's evidence contract."""
    global _audit, _AUDIT_INTEGRITY_OK
    _require_admin(authorization)
    _require_audit_integrity()
    record = body.model_dump()
    record["registered_at"] = int(time.time())
    detail = {"name": body.name, **record}
    try:
        entry = _store.substrate_register_with_audit(body.name, record, "substrate_register", detail, _AUDIT_KEY)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail="stale substrate registration") from exc
    if entry is None:
        _refresh_persisted_state()
        return {"name": body.name, "family": body.family, "version": body.version,
                "adapter": body.adapter, "substrate_count": len(_substrates), "unchanged": True}
    _substrates[body.name] = record
    _audit_committed(entry)
    return {"name": body.name, "family": body.family, "version": body.version,
            "adapter": body.adapter, "substrate_count": len(_substrates)}


@app.delete("/v1/substrates/{name}")
async def remove_substrate(name: str,
                           authorization: Annotated[str | None, Header()] = None) -> dict:
    global _audit, _AUDIT_INTEGRITY_OK
    _require_admin(authorization)
    _require_audit_integrity()
    if name not in _substrates:
        raise HTTPException(status_code=404, detail="unknown substrate")
    record = _substrates[name]
    detail = {"name": name, **record}
    try:
        entry = _store.substrate_remove_with_audit(name, "substrate_remove", detail, _AUDIT_KEY)
    except KeyError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=404, detail="unknown substrate") from exc
    except RuntimeError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _audit_committed(entry)
    _refresh_persisted_state()
    return {"name": name, "removed": True, "substrate_count": len(_substrates)}


@app.get("/v1/substrates")
async def list_substrates() -> dict:
    _require_audit_integrity()
    return {"substrates": [{"name": name, **record} for name, record in _substrates.items()]}


def _probe_targets(targets: dict[str, dict], *, kind: str) -> list[dict]:
    """Return serialisable target metadata; probes are performed by posture()."""
    return [
        {"name": name, "kind": kind, "family": rec.get("family"), "version": rec.get("version"),
         "adapter": rec.get("adapter"), "url": rec["base_url"] + rec["health_path"],
         "capabilities": rec.get("capabilities", []), "policy_ref": rec.get("policy_ref")}
        for name, rec in targets.items()
    ]


def _probe_address_allowed(ip: ipaddress._BaseAddress) -> bool:
    """Reject special-purpose destinations while allowing private service networks."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    blocked = (
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("100.100.100.0/24"),
        ipaddress.ip_network("168.63.129.16/32"),
        ipaddress.ip_network("fd00:ec2::/64"),
    )
    return not (
        ip.is_link_local
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or any(ip.version == network.version and ip in network for network in blocked)
    )


def _resolve_posture_target(base_url: str, health_path: str) -> tuple[str, str | None] | None:
    """Resolve an HTTP target once and return a rebind-safe ``(fetch_url, host_header)``.

    HTTPS is deliberately rejected until a transport can pin the validated address
    while retaining hostname-based TLS SNI and certificate verification.
    """
    try:
        p = urlparse(base_url)
    except Exception:  # noqa: BLE001
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    # HTTPS requires a transport that pins the validated address while retaining
    # hostname-based TLS SNI/certificate verification. Fail closed until that
    # transport is present; never validate one address and fetch another.
    if p.scheme == "https":
        return None
    try:
        port = p.port or 80
    except ValueError:
        return None

    try:
        infos = socket.getaddrinfo(p.hostname, port, proto=socket.IPPROTO_TCP)
    except Exception:  # noqa: BLE001
        return None
    pinned_ip = None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not _probe_address_allowed(ip):
            return None
        pinned_ip = info[4][0]
    if pinned_ip is None:
        return None
    if p.scheme == "http":
        host_port = f"[{pinned_ip}]:{port}" if ":" in pinned_ip else f"{pinned_ip}:{port}"
        prefix = p.path.rstrip("/")
        suffix = health_path if health_path.startswith("/") else f"/{health_path}"
        target_path = f"{prefix}{suffix}" if prefix else suffix
        explicit_port = p.port is not None
        host_header = p.hostname
        if explicit_port:
            host_header = f"[{host_header}]:{port}" if ":" in host_header else f"{host_header}:{port}"
        return f"http://{host_port}{target_path}", host_header


async def _resolve_posture_target_async(base_url: str, health_path: str) -> tuple[str, str | None] | None:
    try:
        async with asyncio.timeout(3.0):
            return await asyncio.to_thread(_resolve_posture_target, base_url, health_path)
    except (TimeoutError, OSError, ValueError):
        return None


_MAX_PROBE_RESPONSE = 1_048_576


async def _probe_health(client, url: str, host_header: str | None, timeout_seconds: float = 3.0) -> tuple[int, object]:
    chunks: list[bytes] = []
    total = 0
    async with asyncio.timeout(timeout_seconds):
        async with client.stream("GET", url, headers={"Host": host_header} if host_header else None) as response:
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > _MAX_PROBE_RESPONSE:
                    raise RuntimeError("posture response exceeds the configured limit")
                chunks.append(chunk)
            body = b"".join(chunks)
            try:
                detail = json.loads(body)
            except Exception:
                detail = body[:120].decode("utf-8", errors="replace")
            return response.status_code, detail


@app.get("/v1/posture")
async def posture() -> dict:
    """Poll every registered service's health and report a unified posture across
    the federation + ZK services (and any bolted-on addons)."""
    _require_audit_integrity()
    # This endpoint is admin-gated because it consumes persisted topology.
    # The SSRF guard below still blocks unsafe link-local and metadata targets.
    import httpx
    out = []
    substrates_out = []
    deadline = time.monotonic() + _POSTURE_TOTAL_SECONDS
    async with httpx.AsyncClient(timeout=3.0, trust_env=False, follow_redirects=False) as client:
        for name, svc in _services.items():
            url = svc["base_url"] + svc["health_path"]
            entry = {"name": name, "type": svc["type"], "url": url}
            budget = deadline - time.monotonic()
            target = await _resolve_posture_target_async(svc["base_url"], svc["health_path"]) if budget > 0 else None
            if target is None:
                entry["up"] = False
                entry["detail"] = (
                    "blocked: HTTPS posture probing requires pinned TLS transport"
                    if urlparse(svc["base_url"]).scheme == "https"
                    else "blocked: probe target is not a public host"
                )
                out.append(entry)
                continue
            fetch_url, host_header = target
            try:
                status_code, detail = await _probe_health(
                    client, fetch_url, host_header,
                    timeout_seconds=max(0.01, min(3.0, deadline - time.monotonic())),
                )
                entry["up"] = status_code == 200
                entry["detail"] = detail
            except Exception as exc:
                entry["up"] = False
                entry["detail"] = f"unreachable: {type(exc).__name__}"
            out.append(entry)
        for name, substrate in _substrates.items():
            url = substrate["base_url"] + substrate["health_path"]
            entry = {
                "name": name, "family": substrate["family"], "version": substrate["version"],
                "adapter": substrate["adapter"], "url": url,
                "capabilities": substrate.get("capabilities", []),
                "policy_ref": substrate.get("policy_ref"),
            }
            budget = deadline - time.monotonic()
            target = await _resolve_posture_target_async(substrate["base_url"], substrate["health_path"]) if budget > 0 else None
            if target is None:
                entry["up"] = False
                entry["detail"] = (
                    "blocked: HTTPS posture probing requires pinned TLS transport"
                    if urlparse(substrate["base_url"]).scheme == "https"
                    else "blocked: probe target is not a public host"
                )
                substrates_out.append(entry)
                continue
            fetch_url, host_header = target
            try:
                status_code, detail = await _probe_health(
                    client, fetch_url, host_header,
                    timeout_seconds=max(0.01, min(3.0, deadline - time.monotonic())),
                )
                entry["up"] = status_code == 200
                entry["detail"] = detail
            except Exception as exc:
                entry["up"] = False
                entry["detail"] = f"unreachable: {type(exc).__name__}"
            substrates_out.append(entry)
    return {
        "issuer_count": len(_issuers),
        "services": out,
        "substrates": substrates_out,
        "policy_bridge": _policy_view(),
        "keystone": _keystone_view(),
        "all_up": bool(out or substrates_out) and all(e["up"] for e in [*out, *substrates_out]),
    }


# ── Policy bridge (built-in, default) ──────────────────────────────────────────────

@app.get("/v1/policy")
async def get_policy() -> dict:
    """The active policy snapshot's content hash (policy_ref) + label. Admin-authenticated
    read because it consumes persisted policy state."""
    _require_audit_integrity()
    return _policy_view()


@app.post("/v1/policy")
async def set_policy(body: PolicyIn, authorization: Annotated[str | None, Header()] = None) -> dict:
    """Set the active policy snapshot. Computes its content-addressed ``policy_ref``
    (substrate2.policy_binding) and persists it; records seal under this ref so a
    later silent rotation is detectable. Admin only."""
    global _policy, _policy_bound_count
    _require_admin(authorization)
    _require_audit_integrity()
    try:
        ref = policy_ref(body.document)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"invalid policy document: {exc}")
    new_policy = {"document": body.document, "policy_ref": ref, "label": body.label,
                  "set_at": int(time.time())}
    detail = {"policy_ref": ref, "label": body.label, "set_at": new_policy["set_at"]}
    try:
        entry = _store.kv_set_with_audit("active_policy", new_policy, "policy_set", detail, _AUDIT_KEY)
    except RuntimeError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    _policy = new_policy
    _policy_bound_count = 0
    _audit_committed(entry)
    return {"policy_ref": ref, "label": body.label, "active": True}


@app.post("/v1/policy/bind")
async def bind_policy(body: BindIn, authorization: Annotated[str | None, Header()] = None) -> dict:
    """Bind a frozen subject_ref to the active policy → ``policy_bound_ref``. The bound
    ref recomputes only under the exact active policy bytes (rotation-detectable). Admin only."""
    global _policy_bound_count
    _require_admin(authorization)
    _require_audit_integrity()
    if not _policy:
        raise HTTPException(status_code=409, detail="no active policy; POST /v1/policy first")
    bound_policy_ref = _policy["policy_ref"]
    try:
        bound = policy_bound_ref(body.subject_ref, bound_policy_ref)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc))
    try:
        entry = _store.policy_bind_with_audit(
            body.subject_ref, bound_policy_ref,
            {"subject_ref": body.subject_ref, "policy_ref": bound_policy_ref, "bound_ref": bound}, _AUDIT_KEY,
        )
    except RuntimeError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _policy_bound_count += 1
    _audit_committed(entry)
    return {"policy_bound_ref": bound, "policy_ref": bound_policy_ref, "subject_ref": body.subject_ref}


# ── Keystone attestor trust (federation: attestor-key trust + posture) ────────────

@app.get("/v1/keystone-attestor")
async def get_keystone_attestor() -> dict:
    """The keystone attestor key (did:key + JWK + kid) for a bridged service to PIN, so it
    trusts keystone signatures as AlgoVoi. No secret: the signing seed stays server-side."""
    _require_audit_integrity()
    if not _keystone_attestor:
        raise HTTPException(status_code=404, detail="no keystone attestor configured")
    return _keystone_attestor


@app.post("/v1/keystone-attestor")
async def set_keystone_attestor(body: KeystoneAttestorIn,
                                authorization: Annotated[str | None, Header()] = None) -> dict:
    """Register the keystone attestor key the hub distributes for pinning (admin only). This is
    the federation attestor-key-trust binding: keystone evidence verifies as AlgoVoi across every
    bridged service that pins this key, and it shows in /v1/posture under \"keystone\"."""
    global _keystone_attestor
    _require_admin(authorization)
    _require_audit_integrity()
    new_attestor = {"did": body.did, "jwk": body.jwk, "kid": body.kid, "set_at": int(time.time())}
    detail = {"did": body.did, "kid": body.kid, "jwk": body.jwk, "set_at": new_attestor["set_at"]}
    try:
        entry = _store.kv_set_with_audit("keystone_attestor", new_attestor, "keystone_attestor_set", detail, _AUDIT_KEY)
    except RuntimeError as exc:
        _refresh_persisted_state()
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    _keystone_attestor = new_attestor
    _audit_committed(entry)
    return {"did": body.did, "kid": body.kid, "active": True}


# ── Web control panel (default, read-only) ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def control_panel() -> HTMLResponse:
    """Default web control panel: live posture across every bridged service +
    attributes, the issuer trust set, and the policy bridge. Read-only."""
    posture_data = await posture()
    return HTMLResponse(render_panel(
        version=__version__,
        issuers=[{"did": d, "kid": r["kid"], "added_at": r["added_at"]} for d, r in _issuers.items()],
        services=posture_data["services"],
        substrates=posture_data["substrates"],
        audit_entries=len(_audit),
        policy=_policy_view(),
        all_up=posture_data["all_up"],
        keystone_steps=_kc.overview() if _kc else None,
    ))


# ── Audit ──────────────────────────────────────────────────────────────────────────

@app.get("/v1/audit")
async def audit(
    authorization: Annotated[str | None, Header()] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    _require_admin(authorization)
    try:
        _refresh_persisted_state()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="audit chain integrity failure") from exc
    if not _AUDIT_INTEGRITY_OK:
        raise HTTPException(status_code=503, detail="audit chain integrity failure")
    limit = max(1, min(limit, 1_000))
    offset = max(0, offset)
    return {"entries": _audit[offset: offset + limit], "total": len(_audit), "offset": offset, "limit": limit, "chained": True}


# ── Edge / WAF / Guard stats and policy ────────────────────────────────────────────

@app.get("/v1/edge/stats")
async def get_edge_stats(authorization: Annotated[str | None, Header()] = None) -> dict:
    """Live counters for the Edge layer (token rejections, geo blocks, rate limits)."""
    _require_admin(authorization)
    return edge_stats()


@app.get("/v1/waf/stats")
async def get_waf_stats(authorization: Annotated[str | None, Header()] = None) -> dict:
    """Live counters for the WAF (blocked requests per rule, oversized bodies)."""
    _require_admin(authorization)
    return waf_stats()


@app.get("/v1/guard/status")
async def get_guard_status(authorization: Annotated[str | None, Header()] = None) -> dict:
    """Live anomaly scores, circuit-breaker state, and per-tenant EWMA baselines."""
    _require_admin(authorization)
    return guard_stats()


class GuardPolicyIn(BaseModel):
    tenant: str = Field(..., min_length=1, max_length=64,
                        description="Tenant identifier as resolved by the Guard layer.")
    cap_rpm: int | None = Field(default=None, ge=1, le=100_000,
                                description="Fixed RPM ceiling; null removes the cap.")


@app.post("/v1/guard/policy")
async def set_guard_policy(body: GuardPolicyIn,
                           authorization: Annotated[str | None, Header()] = None) -> dict:
    """Set or clear a fixed per-tenant RPM cap and reset any open circuit breaker.

    When cap_rpm is null the operator cap is removed and the tenant reverts to
    EWMA-based anomaly detection.  Requires Guard to be enabled
    (AHUB_GUARD_ENABLED=1)."""
    _require_admin(authorization)
    if not GUARD_ENABLED:
        raise HTTPException(status_code=409, detail="Guard is not enabled (set AHUB_GUARD_ENABLED=1)")
    guard_set_policy(body.tenant, body.cap_rpm)
    return {"tenant": body.tenant, "cap_rpm": body.cap_rpm, "active": body.cap_rpm is not None}


def main() -> None:
    import uvicorn
    # The control plane is a reverse-proxied CONTAINER service (fronted by nginx; container port not
    # published to the public). Read-only trust endpoints are public by design; admin/audit/topology
    # writes require AHUB_ADMIN_TOKEN. Binding all interfaces inside the container is intended — a
    # self-hoster overrides AHUB_BIND=127.0.0.1:8094 for a local-only run.
    bind = os.environ.get("AHUB_BIND", "0.0.0.0:8094")  # nosec B104 - reverse-proxied container bind
    host, _, port = bind.partition(":")
    uvicorn.run(app, host=host, port=int(port or "8094"))
