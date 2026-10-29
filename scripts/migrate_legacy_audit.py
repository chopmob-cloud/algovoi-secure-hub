"""Explicitly reconcile legacy audit snapshots before upgrading the control plane.

Run with the production AHUB_DATA_DIR and AHUB_AUDIT_KEY while the service is stopped:
    python scripts/migrate_legacy_audit.py

The script refuses a broken HMAC chain, invalid persisted state, an unanchored
history, or a current state that cannot be replay-proven. If legacy events are
incomplete, the operator must review the validated state and pass its exact
printed SHA-256 with ``--approve-state-hash`` before a reconciliation event can
be written. This prevents a merely authenticated audit log from promoting
unvalidated database contents into authenticated state.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys

from algovoi_secure_hub.service import (
    _audit_key,
    _audit_anchor_ok,
    _audit_state_matches,
    _audit_tail,
    _store,
    _validate_replay_snapshot,
    _verify_audit_chain,
    _write_audit_anchor,
)


def _snapshot(state: dict) -> dict:
    return {
        "issuers": state["issuers"],
        "services": state["services"],
        "substrates": state["substrates"],
        "policy": state["policy"],
        "keystone": state["keystone"],
    }


def _state_hash(snapshot: dict) -> str:
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _candidate_reconcile_entry(entries: list[dict], snapshot: dict) -> dict:
    seq = int(entries[-1]["seq"]) + 1 if entries else 0
    previous = str(entries[-1]["mac"]) if entries else ""
    body = {"seq": seq, "action": "state_reconcile", "detail": snapshot, "prev": previous}
    mac = hmac.new(_audit_key(), json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    return {**body, "mac": mac}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--approve-state-hash",
        help="explicitly approve a validated current-state SHA-256 when legacy replay is incomplete",
    )
    args = parser.parse_args(argv)

    if _store is None:
        print("REFUSED: control-plane store could not be opened", file=sys.stderr)
        return 4
    entries = _store.audit_load()
    if not _verify_audit_chain(entries):
        print("REFUSED: existing audit chain is invalid", file=sys.stderr)
        return 2
    state = _store.state_load()
    snapshot = _snapshot(state)
    try:
        _validate_replay_snapshot(
            snapshot["issuers"], snapshot["services"], snapshot["substrates"],
            snapshot["policy"], snapshot["keystone"],
        )
    except (TypeError, ValueError, KeyError) as exc:
        print(f"REFUSED: persisted state failed semantic validation: {exc}", file=sys.stderr)
        return 4
    if set(state.get("kv_keys", set())) - {"active_policy", "keystone_attestor"}:
        print("REFUSED: persisted state contains unknown KV keys", file=sys.stderr)
        return 4
    if ("active_policy" in state.get("kv_keys", set()) and snapshot["policy"] is None) or (
        "keystone_attestor" in state.get("kv_keys", set()) and snapshot["keystone"] is None
    ):
        print("REFUSED: recognized persisted KV state cannot be JSON null", file=sys.stderr)
        return 4

    anchor_path = os.path.join(os.environ.get("AHUB_DATA_DIR", "/app/data"), "audit_anchor.json")
    if not os.path.exists(anchor_path):
        print("REFUSED: an existing audit database must have audit_anchor.json", file=sys.stderr)
        return 3
    if not _audit_anchor_ok(entries, bootstrap_allowed=False):
        print("REFUSED: existing audit anchor does not match the audit tail", file=sys.stderr)
        return 3

    current_hash = _state_hash(snapshot)
    candidate = _candidate_reconcile_entry(entries, snapshot)
    if not _audit_state_matches([*entries, candidate], snapshot):
        print("REFUSED: audit history cannot be reconciled to the validated current state", file=sys.stderr)
        return 4
    if not _audit_state_matches(entries, snapshot):
        if args.approve_state_hash != current_hash:
            print(
                "REFUSED: current state is not replay-proven; review it and rerun with "
                f"--approve-state-hash {current_hash}",
                file=sys.stderr,
            )
            return 4
        print("APPROVED: operator supplied the exact validated current-state hash", file=sys.stderr)

    detail = snapshot
    try:
        entry = _store.state_reconcile_with_audit(snapshot, entries, detail, _audit_key())
    except (RuntimeError, ValueError) as exc:
        print(f"REFUSED: persisted state or audit changed during reconciliation: {exc}", file=sys.stderr)
        return 4
    new_entries = _store.audit_load()
    _write_audit_anchor(new_entries)
    print(f"RECONCILED seq={entry['seq']} tail={_audit_tail(new_entries)[0]} state_hash={current_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
