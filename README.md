# algovoi-secure-hub

> **License:** AlgoVoi Commercial License v1.0 — evaluation use only.

AlgoVoi Secure Hub is a self-hosted, substrate-neutral security and trust hub. It provides issuer trust distribution, service/add-on registration, health posture, policy and attestor coordination, and a durable HMAC-chained audit log. It does not replace the canonical evidence, settlement, compliance, or payment contracts owned by the security applications that bolt into it.

## What it does

- **Issuer trust registry:** one source of truth for issuer DID → Falcon-1024 public key mappings.
- **Universal service bridge:** registers security applications, substrate adapters, and bolt-on services through one language-agnostic HTTP contract.
- **Posture:** probes registered `/health` endpoints with bounded, fail-closed SSRF protections.
- **Policy and attestor coordination:** publishes content-addressed policy references and the pinned Keystone attestor public key.
- **Signed audit:** every trust and topology mutation is committed with an HMAC-chained audit entry and persisted-state verification.
- **Edge / WAF / Guard:** three independent, opt-in middleware layers that sit in front of every request (see below).

The registry coordinates metadata and posture only; it does not canonicalise, settle, or mutate a security application's evidence.

## Security middleware layers

Three middleware modules are built into the hub and sit in front of all traffic in this order: **Edge → WAF → Guard → login gate**. Each is disabled by default; set the corresponding environment variable to activate it.

### Edge (`AHUB_EDGE_*`)

The outermost layer. Blocks origin-direct requests before they reach any authentication logic.

| Feature | Env var | Description |
|---|---|---|
| HMAC pre-auth token | `AHUB_EDGE_TOKEN` | Reverse proxy attaches a shared secret via `X-AlgoVoi-Edge-Token`; requests without the correct token receive **401**. |
| Per-IP rate limit | `AHUB_EDGE_RPM` | Sliding-window requests-per-minute ceiling per client IP. Excess requests receive **429** with `Retry-After: 60`. |
| Geo-blocklist | `AHUB_EDGE_GEO_BLOCK` | Comma-separated ISO 3166-1 alpha-2 codes (e.g. `CN,RU`). Checked against the `X-Country-Code` header set by a trusted reverse proxy; blocked countries receive **403**. |

Stats: `GET /v1/edge/stats` (admin bearer required).

### WAF (`AHUB_WAF_ENABLED=1`)

Stateless pattern-matching firewall. Scans the URL path and query string on every request, and the JSON/text body on POST/PUT/PATCH requests.

| Rule family | Coverage |
|---|---|
| `sqli-*` | UNION SELECT, stacked queries, Boolean injection, SQL comment + DML |
| `xss-*` | Script tags, inline event handlers, `javascript:` URIs, `data:text/html` |
| `cmdi-*` | Shell pipe/chain, backtick substitution, `$(…)` substitution |
| `pt-*` | Directory traversal (`../`), percent-encoded traversal |
| `ssrf-*` | Cloud metadata IPs/hostnames (`169.254.169.254`, `metadata.google`), loopback URLs in body |
| `pi-*` | Prompt-injection phrases, `[SYSTEM]` tags, XML instruction tags, LLM jailbreak patterns |

Blocked requests receive **400**. Oversized bodies (default 1 MiB, override with `AHUB_WAF_MAX_BODY`) receive **413**.

Stats: `GET /v1/waf/stats` (admin bearer required).

### Guard (`AHUB_GUARD_ENABLED=1`)

Runtime anomaly detection with a per-tenant EWMA baseline and a circuit breaker.

Tenant identity is resolved from (in priority order): `X-AlgoVoi-Tenant` header → `X-Tenant-Id` header → client IP.

| Feature | Env var | Default |
|---|---|---|
| Anomaly threshold | `AHUB_GUARD_ANOMALY_FACTOR` | `5.0` σ above baseline |
| Circuit trip threshold | `AHUB_GUARD_CIRCUIT_TRIP` | `5` anomaly hits |
| Circuit reset | `AHUB_GUARD_CIRCUIT_RESET_S` | `300` seconds |
| EWMA learning rate | `AHUB_GUARD_EWMA_ALPHA` | `0.1` |

When the circuit opens, the tenant receives **429** with `Retry-After: 60` until the cool-down expires.

An operator can also set a hard per-tenant RPM cap that bypasses the EWMA logic:

```http
POST /v1/guard/policy
Authorization: Bearer <admin-token>
Content-Type: application/json

{"tenant": "acme-corp", "cap_rpm": 500}
```

Pass `"cap_rpm": null` to remove the cap.

Status: `GET /v1/guard/status` (admin bearer required).

> **Multi-worker note:** Guard state is in-process. In a multi-worker deployment set `AHUB_GUARD_ENABLED=0` and implement anomaly detection in the upstream reverse proxy or a shared cache layer.

## Verified compatible AlgoVoi security applications

These applications were exercised against a live Secure Hub on VM2. Each registered successfully and appeared in `/v1/services`:

| Application | Registration shape | Trust integration |
|---|---|---|
| `algovoi-federation-validator` | `self_register` | `/v1/issuer-pks` |
| `algovoi-zkp-receipt` | `self_register` | `/v1/issuer-pks` |
| `algovoi-atb-credential-verifier` | `self_register` | `/v1/issuer-pks`, ATB hub documents |
| `algovoi-retention-chain` | `self_register` | service bridge |
| `algovoi-command-center` | `register` | service bridge |
| `algovoi-compliance-gate` | `register` | service bridge |
| `algovoi-records-vault` | `register` | service bridge |
| `algovoi-retention-app` | `register_into_s2_from_env` / `_post_register` | service bridge |

The VM2 run covered 19 integration checks: all eight applications registered, a generic addon registered with a name-bound scoped token, the admin token was rejected for addon registration, posture reported a live health stub, issuer trust was fetched through a real client, and audit guards held. Any other security application can bolt in if it exposes `/health` and makes the same POST request; no Python SDK is required.

## Bolt-in contract

1. Expose `GET /health`, returning 200 only while the application's Secure Hub bridge is healthy (or explicit standalone mode is enabled).
2. Register with:

```http
POST /v1/services
Authorization: Bearer <name-bound-scoped-token>
Content-Type: application/json

{"name":"my-security-app","type":"security-app","base_url":"http://my-security-app:8000","health_path":"/health"}
```

3. Refresh public issuer trust from `GET /v1/issuer-pks`, returning `{did: pk_b64}`. ATB consumers may use `/.well-known/atb-keys.json` or `/issuers/{did}/atb-keys.json`.
4. Use `/v1/posture` and `/v1/services` only with the admin bearer; public trust reads are deliberately narrower and rate-limited.

`examples/addon_app.py` is a complete Python template. Non-Python applications make the same HTTP calls and expose `/health`.

## Trust endpoints

| Endpoint | Shape | Consumers |
|---|---|---|
| `GET /v1/issuer-pks` | `{did: pk_b64}` | federation-validator, zkp-receipt, ATB clients |
| `GET /.well-known/atb-keys.json` | canonical hub document | ATB hub resolver |
| `GET /issuers/{did}/atb-keys.json` | per-issuer document | multi-hub deployments |

## Configuration

`AHUB_*` is the canonical Secure Hub environment namespace. The previous `S2CP_*` namespace remains accepted as a migration alias where applicable.

| Variable | Purpose |
|---|---|
| `AHUB_DATA_DIR` | SQLite data and generated secrets directory |
| `AHUB_DB` | Optional PostgreSQL DSN; SQLite is the default |
| `AHUB_ADMIN_TOKEN` | Admin bearer; generated securely when absent |
| `AHUB_AUDIT_KEY` | HMAC audit key; generated securely when absent |
| `AHUB_REGISTRATION_TOKENS` | JSON name → scoped registration token map |
| `AHUB_REGISTRATION_TOKEN` / `AHUB_REGISTRATION_NAME` | Single scoped registration credential |
| `AHUB_BIND` | Bind address, default `0.0.0.0:8094` |
| `AHUB_EDGE_TOKEN` | Edge: HMAC pre-auth token |
| `AHUB_EDGE_RPM` | Edge: per-IP requests-per-minute ceiling |
| `AHUB_EDGE_GEO_BLOCK` | Edge: comma-separated ISO country codes to block |
| `AHUB_WAF_ENABLED` | WAF: set to `1` to enable |
| `AHUB_WAF_MAX_BODY` | WAF: maximum inspected body size in bytes (default 1048576) |
| `AHUB_GUARD_ENABLED` | Guard: set to `1` to enable |
| `AHUB_GUARD_ANOMALY_FACTOR` | Guard: σ multiplier for anomaly threshold (default 5.0) |
| `AHUB_GUARD_CIRCUIT_TRIP` | Guard: anomaly hits before circuit opens (default 5) |
| `AHUB_GUARD_CIRCUIT_RESET_S` | Guard: circuit breaker cool-down in seconds (default 300) |
| `AHUB_GUARD_EWMA_ALPHA` | Guard: EWMA learning rate (default 0.1) |

Existing applications may continue using their current `S2_HUB_*` or `CCC_HUB_*` client variables. Those clients call the same Secure Hub endpoints; no application logic or evidence contract needs to change.

## Substrate-neutral registry

Register any substrate family or security adapter without changing its canonical evidence contract:

```bash
curl -X POST http://localhost:8094/v1/substrates \
  -H "Authorization: Bearer ${AHUB_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"payment-rails","family":"payment-rails","version":"1",\
       "adapter":"payment-rails","base_url":"http://payment-rails:8090",\
       "capabilities":["x402","mpp","ap2","a2a"]}'
```

## Security boundary

Administrative writes require the admin bearer. Addon registration requires a unique, name-bound scoped credential and never accepts the admin bearer. Posture probes disable proxy and redirect use, stream responses with byte and wall-clock caps, pin HTTP resolution, and fail closed for HTTPS until TLS-preserving address pinning is available. Private service networks are allowed, but special-purpose metadata ranges are rejected. Public trust and health reads are bounded by per-client rate limits and persisted-state/response-size caps.

## Persistence and migration

SQLite is the default (stdlib, one file, air-gap friendly). Set `AHUB_DB` to a `postgresql://...` DSN for PostgreSQL (`pip install '.[postgres]'`). Established databases require a matching `audit_anchor.json`; run migration with the service stopped and the same `AHUB_DATA_DIR` and `AHUB_AUDIT_KEY`:

```bash
PYTHONPATH=src python scripts/migrate_legacy_audit.py
```

Do not use reconciliation to override a broken HMAC chain or mismatched anchor; restore both from a trusted backup instead.

## Validation

```bash
python -m pytest tests/test_substrate_registry.py -q --confcutdir=tests
python scripts/acceptance.py
```
