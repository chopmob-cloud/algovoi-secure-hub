"""DSN-backed persistence for the AlgoVoi Secure Hub.

SQLite by default (stdlib, a single file, air-gap friendly). Set ``AHUB_DB`` to a
``postgresql://...`` DSN to use PostgreSQL instead (optional ``[postgres]`` extra)
— the SQL is the same and the switch is pure configuration, so a deployment can
start on SQLite and be moved to Postgres later without a rewrite.

Four small tables: issuers, services, substrates and audit, plus the singleton kv table. The control plane keeps its working
set in memory and writes through to the store, so reads stay fast and the data is
durable across restarts.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

# Backward-compatible migration: legacy S2CP_* names populate AHUB_* only when
# the canonical Secure Hub variable is absent. New deployments should use AHUB_*.
for _legacy_key, _legacy_value in list(os.environ.items()):
    if _legacy_key.startswith("S2CP_"):
        os.environ.setdefault("AHUB_" + _legacy_key[5:], _legacy_value)

from typing import Any

from substrate2.policy_binding import policy_bound_ref, policy_ref  # type: ignore[reportMissingImports]


def _default_dsn() -> str:
    dsn = os.environ.get("AHUB_DB", "").strip()
    if dsn:
        return dsn
    data_dir = os.environ.get("AHUB_DATA_DIR", "/app/data")
    os.makedirs(data_dir, exist_ok=True)
    # Four slashes: sqlite:// + absolute /path
    return "sqlite:///" + os.path.join(data_dir, "control-plane.db")



_AUDIT_ACTIONS = frozenset({
    "issuer_add", "issuer_revoke", "service_register", "service_remove",
    "substrate_register", "substrate_remove", "policy_set", "policy_bind",
    "keystone_attestor_set", "state_reconcile",
})


def _store_limit(name: str, default: int, ceiling: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not 1 <= value <= ceiling:
        raise RuntimeError(f"{name} must be between 1 and {ceiling}")
    return value


_MAX_AUDIT_ENTRIES = _store_limit("AHUB_MAX_AUDIT_ENTRIES", 100_000, 1_000_000)
_MAX_ISSUERS = _store_limit("AHUB_MAX_ISSUERS", 10_000, 100_000)
_MAX_SERVICES = _store_limit("AHUB_MAX_SERVICES", 4_096, 100_000)
_MAX_SUBSTRATES = _store_limit("AHUB_MAX_SUBSTRATES", 4_096, 100_000)


def _require_exact_detail(detail: dict[str, Any], expected: set[str], values: dict[str, Any]) -> None:
    if set(detail) != expected or any(detail[key] != value for key, value in values.items()):
        raise ValueError("audit detail does not exactly match the state mutation")


class Store:
    def __init__(self, dsn: str | None = None) -> None:
        self._dsn = dsn or _default_dsn()
        self._sqlite = self._dsn.startswith("sqlite:")
        self._sqlite_path = self._dsn[len("sqlite:///"):] if self._sqlite else None
        self._ph = "?" if self._sqlite else "%s"
        self._init()

    # ── Connection (SQLite stdlib, or psycopg for Postgres) ──────────────────
    def _conn(self):
        if self._sqlite:
            import sqlite3
            return sqlite3.connect(self._sqlite_path)
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "AHUB_DB is a PostgreSQL DSN but psycopg is not installed; "
                "install the extra: pip install 'algovoi-secure-hub[postgres]'"
            ) from exc
        return psycopg.connect(self._dsn)

    def _all(self, sql: str) -> list[tuple]:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(sql)
            return cur.fetchall()
        finally:
            conn.close()

    def _init(self) -> None:
        ddl = [
            "CREATE TABLE IF NOT EXISTS issuers (did TEXT PRIMARY KEY, pk_b64 TEXT NOT NULL, "
            "kid TEXT NOT NULL, added_at BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS services (name TEXT PRIMARY KEY, type TEXT NOT NULL, "
            "base_url TEXT NOT NULL, health_path TEXT NOT NULL, registered_at BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS substrates (name TEXT PRIMARY KEY, family TEXT NOT NULL, "
            "version TEXT NOT NULL, adapter TEXT NOT NULL, base_url TEXT NOT NULL, "
            "health_path TEXT NOT NULL, capabilities TEXT NOT NULL, policy_ref TEXT, "
            "registered_at BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS audit (seq BIGINT PRIMARY KEY, action TEXT NOT NULL, "
            "detail TEXT NOT NULL, prev TEXT NOT NULL, mac TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
        ]
        conn = self._conn()
        try:
            cur = conn.cursor()
            for stmt in ddl:
                cur.execute(stmt)
            conn.commit()
        finally:
            conn.close()

    def state_load(self) -> dict[str, Any]:
        """Load all control-plane state from one repeatable snapshot."""
        conn = self._conn()
        try:
            cur = conn.cursor()
            if self._sqlite:
                cur.execute("BEGIN")
            else:
                cur.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            issuers = {
                r[0]: {"pk_b64": r[1], "kid": r[2], "added_at": r[3]}
                for r in cur.execute("SELECT did, pk_b64, kid, added_at FROM issuers").fetchall()
            }
            services = {
                r[0]: {"type": r[1], "base_url": r[2], "health_path": r[3], "registered_at": r[4]}
                for r in cur.execute("SELECT name, type, base_url, health_path, registered_at FROM services").fetchall()
            }
            substrates = {
                r[0]: {"family": r[1], "version": r[2], "adapter": r[3], "base_url": r[4],
                       "health_path": r[5], "capabilities": json.loads(r[6]), "policy_ref": r[7], "registered_at": r[8]}
                for r in cur.execute("SELECT name, family, version, adapter, base_url, health_path, capabilities, policy_ref, registered_at FROM substrates").fetchall()
            }
            kv = {r[0]: json.loads(r[1]) for r in cur.execute("SELECT k, v FROM kv").fetchall()}
            for required_key in ("active_policy", "keystone_attestor"):
                if required_key in kv and kv[required_key] is None:
                    raise ValueError(f"{required_key} cannot be JSON null")
            audit = []
            for r in cur.execute("SELECT seq, action, detail, prev, mac FROM audit ORDER BY seq").fetchall():
                try:
                    detail = json.loads(r[2]); malformed = not isinstance(detail, dict)
                except (TypeError, json.JSONDecodeError):
                    detail = None; malformed = True
                entry = {"seq": r[0], "action": r[1], "detail": detail, "prev": r[3], "mac": r[4]}
                if malformed: entry["_malformed_detail"] = True
                audit.append(entry)
            conn.commit()
            return {"issuers": issuers, "services": services, "substrates": substrates,
                    "policy": kv.get("active_policy"), "keystone": kv.get("keystone_attestor"),
                    "audit": audit, "kv_keys": set(kv)}
        except Exception:
            conn.rollback(); raise
        finally:
            conn.close()

    def issuers_load(self) -> dict[str, dict]:
        return {
            r[0]: {"pk_b64": r[1], "kid": r[2], "added_at": r[3]}
            for r in self._all("SELECT did, pk_b64, kid, added_at FROM issuers")
        }

    def issuer_add(self, did: str, pk_b64: str, kid: str, added_at: int) -> None:
        raise RuntimeError("unaudited issuer mutation disabled; use issuer_add_with_audit")

    def issuer_remove(self, did: str) -> None:
        raise RuntimeError("unaudited issuer mutation disabled; use issuer_remove_with_audit")

    def issuer_add_with_audit(self, did: str, pk_b64: str, kid: str, added_at: int,
                              action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any] | None:
        if action != "issuer_add":
            raise ValueError("issuer_add_with_audit requires issuer_add action")
        _require_exact_detail(detail, {"did", "pk_b64", "kid", "added_at"}, {"did": did, "pk_b64": pk_b64, "kid": kid})
        conn = self._conn()
        try:
            cur = conn.cursor(); self._begin_serialized(cur); p = self._ph
            cur.execute(f"SELECT pk_b64, kid, added_at FROM issuers WHERE did = {p}", (did,))  # nosec B608 - internal placeholder; value is bound
            existing = cur.fetchone()
            if existing is not None and tuple(existing) == (pk_b64, kid, detail["added_at"]):
                conn.rollback()
                return None
            if existing is None:
                cur.execute("SELECT COUNT(*) FROM issuers")
                if int(cur.fetchone()[0]) >= _MAX_ISSUERS:
                    raise RuntimeError("issuer capacity reached")
            actual_added_at = existing[2] if existing else added_at
            if detail["added_at"] != actual_added_at:
                raise ValueError("issuer_add detail timestamp does not match the durable mutation")
            if self._sqlite:
                cur.execute(f"INSERT OR REPLACE INTO issuers (did, pk_b64, kid, added_at) VALUES ({p}, {p}, {p}, {p})", (did, pk_b64, kid, actual_added_at))
            else:
                cur.execute(f"INSERT INTO issuers (did, pk_b64, kid, added_at) VALUES ({p}, {p}, {p}, {p}) ON CONFLICT (did) DO UPDATE SET pk_b64=EXCLUDED.pk_b64, kid=EXCLUDED.kid, added_at=EXCLUDED.added_at", (did, pk_b64, kid, actual_added_at))  # nosec B608 - internal SQL template; all values are bound
            entry = self._audit_append_cursor(cur, action, {**detail, "added_at": actual_added_at}, audit_key)
            conn.commit(); return entry
        except Exception:
            conn.rollback(); raise
        finally:
            conn.close()

    def issuer_remove_with_audit(self, did: str, action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        if action != "issuer_revoke":
            raise ValueError("issuer_remove_with_audit requires issuer_revoke action")
        _require_exact_detail(detail, {"did", "pk_b64", "kid", "added_at"}, {"did": did})
        conn = self._conn()
        try:
            cur = conn.cursor(); self._begin_serialized(cur)
            cur.execute(f"SELECT pk_b64, kid, added_at FROM issuers WHERE did = {self._ph}", (did,))  # nosec B608 - internal placeholder; value is bound
            current = cur.fetchone()
            if current is None:
                raise KeyError("unknown issuer")
            expected = (detail.get("pk_b64"), detail.get("kid"), detail.get("added_at"))
            if tuple(current) != expected:
                raise RuntimeError("issuer changed concurrently")
            cur.execute(f"DELETE FROM issuers WHERE did = {self._ph}", (did,))  # nosec B608 - only the internal placeholder is interpolated; value is bound
            if cur.rowcount != 1:
                raise KeyError("unknown issuer")
            entry = self._audit_append_cursor(cur, action, detail, audit_key)
            conn.commit(); return entry
        except Exception:
            conn.rollback(); raise
        finally:
            conn.close()

    # ── Services ─────────────────────────────────────────────────────────────
    def services_load(self) -> dict[str, dict]:
        return {
            r[0]: {"type": r[1], "base_url": r[2], "health_path": r[3], "registered_at": r[4]}
            for r in self._all("SELECT name, type, base_url, health_path, registered_at FROM services")
        }

    def service_register(self, name: str, type_: str, base_url: str, health_path: str, registered_at: int) -> None:
        raise RuntimeError("unaudited service mutation disabled; use service_register_with_audit")

    def service_remove(self, name: str) -> None:
        raise RuntimeError("unaudited service mutation disabled; use service_remove_with_audit")

    def service_register_with_audit(self, name: str, type_: str, base_url: str, health_path: str,
                                    registered_at: int, action: str, detail: dict[str, Any], audit_key: bytes,
                                    *, immutable: bool = False) -> dict[str, Any] | None:
        if action != "service_register":
            raise ValueError("service_register_with_audit requires service_register action")
        _require_exact_detail(detail, {"name", "type", "base_url", "health_path", "registered_at"},
                              {"name": name, "type": type_, "base_url": base_url, "health_path": health_path, "registered_at": registered_at})
        conn = self._conn()
        try:
            cur = conn.cursor(); self._begin_serialized(cur); p = self._ph
            cur.execute(f"SELECT type, base_url, health_path, registered_at FROM services WHERE name = {p}", (name,))  # nosec B608 - internal placeholder; value is bound
            current = cur.fetchone()
            if current is not None:
                if tuple(current[:3]) == (type_, base_url, health_path):
                    conn.rollback()
                    return None
                if immutable:
                    raise RuntimeError("scoped registration is immutable")
                if int(current[3]) > registered_at:
                    raise RuntimeError("stale service registration")
            else:
                cur.execute("SELECT COUNT(*) FROM services")
                if int(cur.fetchone()[0]) >= _MAX_SERVICES:
                    raise RuntimeError("service capacity reached")
            cols = "(name, type, base_url, health_path, registered_at)"; vals = f"({p}, {p}, {p}, {p}, {p})"
            args = (name, type_, base_url, health_path, registered_at)
            if self._sqlite:
                cur.execute(f"INSERT OR REPLACE INTO services {cols} VALUES {vals}", args)
            else:
                cur.execute(f"INSERT INTO services {cols} VALUES {vals} ON CONFLICT (name) DO UPDATE SET type=EXCLUDED.type, base_url=EXCLUDED.base_url, health_path=EXCLUDED.health_path, registered_at=EXCLUDED.registered_at", args)  # nosec B608 - internal SQL template; all values are bound
            entry = self._audit_append_cursor(cur, action, detail, audit_key)
            conn.commit(); return entry
        except Exception:
            conn.rollback(); raise
        finally:
            conn.close()

    def service_remove_with_audit(self, name: str, action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        if action != "service_remove":
            raise ValueError("service_remove_with_audit requires service_remove action")
        _require_exact_detail(detail, {"name", "type", "base_url", "health_path", "registered_at"},
                              {"name": name})
        conn = self._conn()
        try:
            cur = conn.cursor(); self._begin_serialized(cur)
            cur.execute(f"SELECT type, base_url, health_path, registered_at FROM services WHERE name = {self._ph}", (name,))  # nosec B608 - internal placeholder; value is bound
            current = cur.fetchone()
            if current is None:
                raise KeyError("unknown service")
            expected = tuple(detail.get(k) for k in ("type", "base_url", "health_path", "registered_at"))
            if tuple(current) != expected:
                raise RuntimeError("service changed concurrently")
            cur.execute(f"DELETE FROM services WHERE name = {self._ph}", (name,))  # nosec B608 - only the internal placeholder is interpolated; value is bound
            if cur.rowcount != 1:
                raise KeyError("unknown service")
            entry = self._audit_append_cursor(cur, action, detail, audit_key)
            conn.commit(); return entry
        except Exception:
            conn.rollback(); raise
        finally:
            conn.close()

    def substrates_load(self) -> dict[str, dict]:
        return {
            r[0]: {
                "family": r[1], "version": r[2], "adapter": r[3],
                "base_url": r[4], "health_path": r[5],
                "capabilities": json.loads(r[6]), "policy_ref": r[7], "registered_at": r[8],
            }
            for r in self._all(
                "SELECT name, family, version, adapter, base_url, health_path, "
                "capabilities, policy_ref, registered_at FROM substrates"
            )
        }

    def substrate_register(self, name: str, record: dict[str, Any]) -> None:
        raise RuntimeError("unaudited substrate mutation disabled; use substrate_register_with_audit")

    def _begin_serialized(self, cur) -> None:
        if self._sqlite:
            cur.execute("BEGIN IMMEDIATE")
        else:
            cur.execute("SELECT pg_advisory_xact_lock(735104219)")

    def _audit_append_cursor(self, cur, action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        if action not in _AUDIT_ACTIONS:
            raise ValueError("unknown audit action")
        cur.execute("SELECT COUNT(*) FROM audit")
        if int(cur.fetchone()[0]) >= _MAX_AUDIT_ENTRIES:
            raise RuntimeError("audit capacity reached")
        cur.execute("SELECT seq, mac FROM audit ORDER BY seq DESC LIMIT 1")
        previous = cur.fetchone()
        seq = (int(previous[0]) + 1) if previous else 0
        prev = previous[1] if previous else ""
        body = {"seq": seq, "action": action, "detail": detail, "prev": prev}
        mac = hmac.new(audit_key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        entry = {**body, "mac": mac}
        p = self._ph
        cur.execute(
            f"INSERT INTO audit (seq, action, detail, prev, mac) VALUES ({p}, {p}, {p}, {p}, {p})",  # nosec B608 - only the internal placeholder is interpolated; all values are bound
            (seq, action, json.dumps(detail, sort_keys=True), prev, mac),
        )
        return entry

    def substrate_register_with_audit(self, name: str, record: dict[str, Any],
                                      action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any] | None:
        if action != "substrate_register":
            raise ValueError("substrate_register_with_audit requires substrate_register action")
        expected_detail = {"name", "family", "version", "adapter", "base_url", "health_path", "capabilities", "policy_ref", "registered_at"}
        _require_exact_detail(detail, expected_detail, {"name": name, **record})
        conn = self._conn()
        try:
            cur = conn.cursor()
            self._begin_serialized(cur)
            p = self._ph
            cur.execute(f"SELECT family, version, adapter, base_url, health_path, capabilities, policy_ref, registered_at FROM substrates WHERE name = {p}", (name,))  # nosec B608 - internal placeholder; value is bound
            current = cur.fetchone()
            if current is not None:
                current_record = {"family": current[0], "version": current[1], "adapter": current[2], "base_url": current[3], "health_path": current[4], "capabilities": json.loads(current[5]), "policy_ref": current[6], "registered_at": current[7]}
                if all(current_record[key] == record[key] for key in current_record if key != "registered_at"):
                    conn.rollback()
                    return None
                if int(current_record["registered_at"]) > int(record["registered_at"]):
                    raise RuntimeError("stale substrate registration")
            else:
                cur.execute("SELECT COUNT(*) FROM substrates")
                if int(cur.fetchone()[0]) >= _MAX_SUBSTRATES:
                    raise RuntimeError("substrate capacity reached")
            cols = "(name, family, version, adapter, base_url, health_path, capabilities, policy_ref, registered_at)"
            vals = "(" + ", ".join([p] * 9) + ")"
            args = (
                name, record["family"], record["version"], record["adapter"], record["base_url"],
                record["health_path"], json.dumps(record["capabilities"], sort_keys=True),
                record.get("policy_ref"), record["registered_at"],
            )
            if self._sqlite:
                cur.execute(f"INSERT OR REPLACE INTO substrates {cols} VALUES {vals}", args)
            else:
                cur.execute(
                    f"INSERT INTO substrates {cols} VALUES {vals} ON CONFLICT (name) DO UPDATE SET "  # nosec B608 - column names and placeholders are internal constants; values are bound
                    "family=EXCLUDED.family, version=EXCLUDED.version, adapter=EXCLUDED.adapter, "
                    "base_url=EXCLUDED.base_url, health_path=EXCLUDED.health_path, "
                    "capabilities=EXCLUDED.capabilities, policy_ref=EXCLUDED.policy_ref, "
                    "registered_at=EXCLUDED.registered_at", args,
                )
            entry = self._audit_append_cursor(cur, action, detail, audit_key)
            conn.commit()
            return entry
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def substrate_remove_with_audit(self, name: str, action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        if action != "substrate_remove":
            raise ValueError("substrate_remove_with_audit requires substrate_remove action")
        _require_exact_detail(detail, {"name", "family", "version", "adapter", "base_url", "health_path", "capabilities", "policy_ref", "registered_at"}, {"name": name})
        conn = self._conn()
        try:
            cur = conn.cursor()
            self._begin_serialized(cur)
            cur.execute(
                f"SELECT family, version, adapter, base_url, health_path, capabilities, policy_ref, registered_at "
                f"FROM substrates WHERE name = {self._ph}", (name,)  # nosec B608 - internal placeholder; value is bound
            )
            current = cur.fetchone()
            if current is None:
                raise KeyError("unknown substrate")
            actual = (current[0], current[1], current[2], current[3], current[4],
                      json.loads(current[5]), current[6], current[7])
            expected = tuple(detail.get(k) for k in (
                "family", "version", "adapter", "base_url", "health_path", "capabilities", "policy_ref", "registered_at"))
            if actual != expected:
                raise RuntimeError("substrate changed concurrently")
            cur.execute(f"DELETE FROM substrates WHERE name = {self._ph}", (name,))  # nosec B608 - only the internal placeholder is interpolated; value is bound
            if cur.rowcount != 1:
                raise KeyError("unknown substrate")
            entry = self._audit_append_cursor(cur, action, detail, audit_key)
            conn.commit()
            return entry
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def audit_load(self) -> list[dict]:
        entries = []
        for r in self._all("SELECT seq, action, detail, prev, mac FROM audit ORDER BY seq"):
            try:
                detail = json.loads(r[2])
                malformed = not isinstance(detail, dict)
            except (TypeError, json.JSONDecodeError):
                detail = None
                malformed = True
            entry = {"seq": r[0], "action": r[1], "detail": detail, "prev": r[3], "mac": r[4]}
            if malformed:
                entry["_malformed_detail"] = True
            entries.append(entry)
        return entries

    def audit_append(self, action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        """Append the explicit state-reconcile event using database-backed sequencing."""
        if action != "state_reconcile":
            raise ValueError("audit_append is reserved for state_reconcile")
        if (set(detail) != {"issuers", "services", "substrates", "policy", "keystone"}
                or not isinstance(detail["issuers"], dict)
                or not isinstance(detail["services"], dict)
                or not isinstance(detail["substrates"], dict)
                or (detail["policy"] is not None and not isinstance(detail["policy"], dict))
                or (detail["keystone"] is not None and not isinstance(detail["keystone"], dict))):
            raise ValueError("state_reconcile detail schema mismatch")
        conn = self._conn()
        try:
            cur = conn.cursor()
            self._begin_serialized(cur)
            entry = self._audit_append_cursor(cur, action, detail, audit_key)
            conn.commit()
            return entry
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def state_reconcile_with_audit(self, expected_state: dict[str, Any], expected_audit: list[dict],
                                   detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        """Append reconciliation only if state and audit are unchanged since validation."""
        if set(expected_state) != {"issuers", "services", "substrates", "policy", "keystone"}:
            raise ValueError("expected reconciliation state schema mismatch")
        if detail != expected_state:
            raise ValueError("reconciliation detail must equal the validated state")
        conn = self._conn()
        try:
            cur = conn.cursor()
            self._begin_serialized(cur)
            actual_issuers = {
                r[0]: {"pk_b64": r[1], "kid": r[2], "added_at": r[3]}
                for r in cur.execute("SELECT did, pk_b64, kid, added_at FROM issuers").fetchall()
            }
            actual_services = {
                r[0]: {"type": r[1], "base_url": r[2], "health_path": r[3], "registered_at": r[4]}
                for r in cur.execute("SELECT name, type, base_url, health_path, registered_at FROM services").fetchall()
            }
            actual_substrates = {
                r[0]: {"family": r[1], "version": r[2], "adapter": r[3], "base_url": r[4],
                       "health_path": r[5], "capabilities": json.loads(r[6]), "policy_ref": r[7],
                       "registered_at": r[8]}
                for r in cur.execute(
                    "SELECT name, family, version, adapter, base_url, health_path, capabilities, policy_ref, registered_at FROM substrates"
                ).fetchall()
            }
            kv = {r[0]: json.loads(r[1]) for r in cur.execute("SELECT k, v FROM kv").fetchall()}
            for required_key in ("active_policy", "keystone_attestor"):
                if required_key in kv and kv[required_key] is None:
                    raise ValueError(f"{required_key} cannot be JSON null")
            actual_state = {
                "issuers": actual_issuers, "services": actual_services, "substrates": actual_substrates,
                "policy": kv.get("active_policy"), "keystone": kv.get("keystone_attestor"),
            }
            actual_audit = []
            for row in cur.execute("SELECT seq, action, detail, prev, mac FROM audit ORDER BY seq").fetchall():
                try:
                    parsed = json.loads(row[2])
                    malformed = not isinstance(parsed, dict)
                except (TypeError, json.JSONDecodeError):
                    parsed = None
                    malformed = True
                entry = {"seq": row[0], "action": row[1], "detail": parsed, "prev": row[3], "mac": row[4]}
                if malformed:
                    entry["_malformed_detail"] = True
                actual_audit.append(entry)
            canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
            if canonical(actual_state) != canonical(expected_state) or canonical(actual_audit) != canonical(expected_audit):
                raise RuntimeError("state or audit changed during reconciliation")
            entry = self._audit_append_cursor(cur, "state_reconcile", detail, audit_key)
            conn.commit()
            return entry
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _one(self, sql: str, params: tuple) -> tuple | None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            return cur.fetchone()
        finally:
            conn.close()

    def kv_get(self, key: str) -> Any | None:
        row = self._one(f"SELECT v FROM kv WHERE k = {self._ph}", (key,))  # nosec B608 - parameterized query; only the portable placeholder (self._ph) is interpolated, values are bound
        return json.loads(row[0]) if row else None

    def kv_delete(self, key: str) -> None:
        raise RuntimeError("unaudited KV mutation disabled; use kv_delete_with_audit")

    def kv_set_with_audit(self, key: str, value: Any, action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        expected = {"active_policy": "policy_set", "keystone_attestor": "keystone_attestor_set"}.get(key)
        if expected is None or action != expected:
            raise ValueError("kv_set_with_audit requires the key-specific audit action")
        if not isinstance(value, dict):
            raise ValueError("audited KV values must be objects")
        if key == "active_policy":
            if (set(value) != {"document", "policy_ref", "label", "set_at"}
                    or not isinstance(value["document"], dict) or not isinstance(value["label"], str)
                    or type(value["set_at"]) is not int or policy_ref(value["document"]) != value["policy_ref"]):
                raise ValueError("active_policy value schema mismatch")
            _require_exact_detail(detail, {"policy_ref", "label", "set_at"}, {"policy_ref": value["policy_ref"], "label": value["label"], "set_at": value["set_at"]})
        else:
            if set(value) != {"did", "jwk", "kid", "set_at"} or type(value["set_at"]) is not int:
                raise ValueError("keystone_attestor value schema mismatch")
            _require_exact_detail(detail, {"did", "kid", "jwk", "set_at"}, {"did": value["did"], "kid": value["kid"], "jwk": value["jwk"], "set_at": value["set_at"]})
        conn = self._conn()
        try:
            cur = conn.cursor(); self._begin_serialized(cur); p = self._ph
            payload = json.dumps(value, sort_keys=True)
            if self._sqlite:
                cur.execute(f"INSERT OR REPLACE INTO kv (k, v) VALUES ({p}, {p})", (key, payload))
            else:
                cur.execute(f"INSERT INTO kv (k, v) VALUES ({p}, {p}) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v", (key, payload))  # nosec B608 - internal SQL template; all values are bound
            entry = self._audit_append_cursor(cur, action, detail, audit_key)
            conn.commit(); return entry
        except Exception:
            conn.rollback(); raise
        finally:
            conn.close()

    def policy_bind_with_audit(self, subject_ref: str, expected_policy_ref: str,
                               detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        _require_exact_detail(detail, {"subject_ref", "policy_ref", "bound_ref"}, {"subject_ref": subject_ref, "policy_ref": expected_policy_ref})
        conn = self._conn()
        try:
            cur = conn.cursor(); self._begin_serialized(cur)
            cur.execute(f"SELECT v FROM kv WHERE k = {self._ph}", ("active_policy",))  # nosec B608 - internal placeholder; key is bound
            row = cur.fetchone()
            current = json.loads(row[0]) if row else None
            if not current or current.get("policy_ref") != expected_policy_ref:
                raise RuntimeError("active policy changed during binding")
            actual_bound_ref = policy_bound_ref(subject_ref, expected_policy_ref)
            if detail["bound_ref"] != actual_bound_ref:
                raise ValueError("policy binding reference does not match the canonical subject/policy binding")
            entry = self._audit_append_cursor(cur, "policy_bind", detail, audit_key)
            conn.commit(); return entry
        except Exception:
            conn.rollback(); raise
        finally:
            conn.close()

    def kv_delete_with_audit(self, key: str, action: str, detail: dict[str, Any], audit_key: bytes) -> dict[str, Any]:
        raise RuntimeError("generic KV deletion disabled; use a key-specific audited operation")

    def kv_set(self, key: str, value: Any) -> None:
        raise RuntimeError("unaudited KV mutation disabled; use kv_set_with_audit")
