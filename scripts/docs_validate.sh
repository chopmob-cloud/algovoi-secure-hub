#!/bin/sh
set -eu
# Runs INSIDE a clean python:3.11-slim container = a customer's box.
# Follows the Substrate 2 Addons docs page literally (its exact commands, curl calls
# and endpoints) and checks each works as written.
P=0; F=0
ok(){ echo "  [PASS] $1"; P=$((P+1)); }
no(){ echo "  [FAIL] $1"; F=$((F+1)); }

apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl >/dev/null 2>&1
cp /in/bundle.algv /in/algovoi_unbundle.py /in/licence.key /tmp/; cd /tmp

echo "== DOC: install the bundle =="
pip install -q cryptography pqcrypto rfc8785 fastapi uvicorn httpx
python algovoi_unbundle.py --license @licence.key --install bundle.algv >/dev/null 2>&1 && ok "unbundle --install" || no "unbundle --install"
for c in algovoi-secure-hub algovoi-federation-validator algovoi-zkp-receipt algovoi-atb-credential-verifier; do
  command -v "$c" >/dev/null 2>&1 && ok "console command: $c" || no "missing $c"
done

echo "== DOC: start the control plane (AHUB_DATA_DIR=./data) =="
FED_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ZKP_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ATB_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ADDON_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
export AHUB_REGISTRATION_TOKENS="{\"federation-validator\":\"$FED_REG_TOKEN\",\"zkp-receipt\":\"$ZKP_REG_TOKEN\",\"atb-credential-verifier\":\"$ATB_REG_TOKEN\",\"my-addon\":\"$ADDON_REG_TOKEN\"}"
AHUB_DATA_DIR=./data algovoi-secure-hub >/tmp/cp.log 2>&1 &
sleep 5
[ -f ./data/admin_token ] && ok "admin token at <AHUB_DATA_DIR>/admin_token" || no "admin_token path"
[ -f ./data/control-plane.db ] && ok "SQLite control-plane.db in the data dir" || no "sqlite db"
TOKEN=$(cat ./data/admin_token)
PK=$(python -c "import os,base64;print(base64.b64encode(os.urandom(1793)).decode())")

echo "== DOC: register an issuer (documented curl) =="
curl -sf -X POST http://localhost:8094/v1/issuers -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"did\":\"did:web:your-issuer\",\"public_key_b64\":\"$PK\"}" >/dev/null && ok "POST /v1/issuers" || no "POST /v1/issuers"

echo "== DOC: control plane API table =="
curl -sf http://localhost:8094/health >/dev/null && ok "GET /health" || no "GET /health"
curl -sf http://localhost:8094/v1/issuer-pks | grep -q did:web:your-issuer && ok "GET /v1/issuer-pks" || no "GET /v1/issuer-pks"
curl -sf http://localhost:8094/.well-known/atb-keys.json | grep -q did:web:your-issuer && ok "GET /.well-known/atb-keys.json" || no "well-known"
curl -sf -H "Authorization: Bearer $TOKEN" http://localhost:8094/v1/audit >/dev/null && ok "GET /v1/audit (admin)" || no "GET /v1/audit"
curl -sf -H "Authorization: Bearer $TOKEN" http://localhost:8094/v1/posture >/dev/null && ok "GET /v1/posture (admin)" || no "GET /v1/posture"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8094/v1/services -H 'Content-Type: application/json' -d '{"name":"x","type":"addon","base_url":"http://x:1"}')" = "401" ] && ok "admin endpoints reject without token (matches (admin) marking)" || no "admin gating"

echo "== DOC: bridge the services (S2_HUB_URL + S2_HUB_TOKEN + S2_HUB_SELF_URL) =="
S2_HUB_URL=http://localhost:8094 S2_HUB_TOKEN=$FED_REG_TOKEN S2_HUB_SELF_URL=http://localhost:8092 algovoi-federation-validator     >/tmp/f.log 2>&1 &
S2_HUB_URL=http://localhost:8094 S2_HUB_TOKEN=$ZKP_REG_TOKEN S2_HUB_SELF_URL=http://localhost:8093 algovoi-zkp-receipt             >/tmp/z.log 2>&1 &
S2_HUB_URL=http://localhost:8094 S2_HUB_TOKEN=$ATB_REG_TOKEN S2_HUB_SELF_URL=http://localhost:8095 algovoi-atb-credential-verifier >/tmp/a.log 2>&1 &
sleep 9
PO=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8094/v1/posture)
echo "$PO" | grep -q federation-validator && echo "$PO" | grep -q '"zkp-receipt"' && echo "$PO" | grep -q atb-credential-verifier && ok "all three bridged services appear in /v1/posture" || no "posture bridge"
echo "$PO" | grep -q '"all_up":true' && ok "posture all_up true" || no "all_up"

echo "== DOC: add a custom addon (the two documented HTTP calls) =="
curl -sf http://localhost:8094/v1/issuer-pks >/dev/null && ok "addon call 1: GET /v1/issuer-pks" || no "issuer-pks"
curl -sf -X POST http://localhost:8094/v1/services -H "Authorization: Bearer $ADDON_REG_TOKEN" -H "Content-Type: application/json" -d '{"name":"my-addon","type":"addon","base_url":"http://localhost:9000"}' >/dev/null && curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8094/v1/services | grep -q my-addon && ok "addon call 2: POST /v1/services registers it" || no "services register"

echo ""
echo "===== DOCS VALIDATION: $P passed, $F failed ====="
if [ "$F" -ne 0 ]; then
  echo "DISCREPANCIES FOUND" >&2
  exit 1
fi
echo "DOCUMENTATION 100% ACCURATE"
