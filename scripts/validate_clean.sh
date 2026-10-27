#!/bin/bash
set -euo pipefail
# Clean-VM retest of the whole substrate-2 product: federation-validator,
# zkp-receipt, and the control plane. Wipes the slate, rebuilds every image from
# scratch (--no-cache, as a fresh VM would), then runs every self-proving test and
# the live bridge + drop-in flows. Prints a single PASS/FAIL summary.
FED=algovoi-federation-validator:clean
ZKP=algovoi-zkp-receipt:clean
CP=algovoi-secure-hub:clean
NET=s2-validate
PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "===== CLEAN SLATE ====="
docker rm -f s2cp federation-validator zkp-receipt atb-credential-verifier retention-chain >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
docker volume rm s2cp-data >/dev/null 2>&1 || true
docker rmi -f $FED $ZKP $CP >/dev/null 2>&1 || true
if [ "${AHUB_PRUNE_BUILDER_CACHE:-0}" = "1" ]; then docker builder prune -af; fi
echo "wiped images + containers + build cache"

echo "===== FROM-SCRATCH BUILDS (--no-cache) ====="
cd /root/fedval-clean   && docker build --no-cache -t $FED . >/tmp/bf.log 2>&1 && ok "federation built clean" || { no "federation build"; tail -4 /tmp/bf.log; }
cd /root/zkprcpt-clean  && docker build --no-cache -t $ZKP . >/tmp/bz.log 2>&1 && ok "zkp-receipt built clean" || { no "zkp build"; tail -4 /tmp/bz.log; }
cd /root/s2cp           && docker build --no-cache -t $CP . >/tmp/bc.log 2>&1 && ok "control-plane built clean" || { no "cp build"; tail -4 /tmp/bc.log; }

echo "===== ACCEPTANCE (each service self-proves) ====="
docker run --rm $FED python scripts/acceptance.py 2>/dev/null | grep -q "ALL GREEN" && ok "federation acceptance" || no "federation acceptance"
docker run --rm $ZKP python scripts/acceptance.py 2>/dev/null | grep -q "ALL GREEN" && ok "zkp-receipt acceptance" || no "zkp-receipt acceptance"
docker run --rm $CP  python scripts/acceptance.py 2>/dev/null | grep -q "ALL GREEN" && ok "control-plane acceptance (16 checks)" || no "control-plane acceptance"

echo "===== CONTROL PLANE PERSISTENCE (SQLite survives restart) ====="
docker volume create s2cp-data >/dev/null
docker run -d --name v-cp -v s2cp-data:/app/data $CP >/dev/null; sleep 4
TOKEN=$(docker exec v-cp cat /app/data/admin_token)
PK=$(docker exec v-cp python -c "import os,base64;print(base64.b64encode(os.urandom(1793)).decode())")
docker exec v-cp curl -s -X POST localhost:8094/v1/issuers -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"did\":\"did:web:v\",\"public_key_b64\":\"$PK\"}" >/dev/null
docker rm -f v-cp >/dev/null 2>&1
docker run -d --name v-cp2 -v s2cp-data:/app/data $CP >/dev/null; sleep 4
docker exec v-cp2 curl -s localhost:8094/health | grep -q '"issuer_count":1' && ok "issuer survived restart (SQLite)" || no "persistence"
docker rm -f v-cp2 >/dev/null 2>&1; docker volume rm s2cp-data >/dev/null 2>&1

echo "===== LIVE BRIDGE + DROP-IN (CP coordinates federation + zkp; addon joins with 2 env vars) ====="
docker network create $NET >/dev/null
FED_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ZKP_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
REG_JSON="{\"federation-validator\":\"$FED_REG_TOKEN\",\"zkp-receipt\":\"$ZKP_REG_TOKEN\"}"
docker run -d --name s2cp --network $NET -e AHUB_REGISTRATION_TOKENS="$REG_JSON" $CP >/dev/null; sleep 4
TOKEN=$(docker exec s2cp cat /app/data/admin_token)
PK=$(docker exec s2cp python -c "import os,base64;print(base64.b64encode(os.urandom(1793)).decode())")
docker exec s2cp curl -s -X POST localhost:8094/v1/issuers -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"did\":\"did:web:hub\",\"public_key_b64\":\"$PK\"}" >/dev/null
# both services join with per-service registration tokens, never the admin token
docker run -d --name federation-validator --network $NET -e S2_HUB_URL=http://s2cp:8094 -e S2_HUB_TOKEN=$FED_REG_TOKEN $FED >/dev/null
docker run -d --name zkp-receipt --network $NET -e S2_HUB_URL=http://s2cp:8094 -e S2_HUB_TOKEN=$ZKP_REG_TOKEN $ZKP >/dev/null
sleep 8
docker exec federation-validator curl -s localhost:8092/health | grep -q '"issuer_count":1' && ok "federation live-pulled trust from hub" || no "federation trust-pull"
SVCS=$(docker exec s2cp sh -c "curl -s -H 'Authorization: Bearer $TOKEN' localhost:8094/v1/services")
echo "$SVCS" | grep -q "federation-validator" && echo "$SVCS" | grep -q '"zkp-receipt"' && ok "both services self-registered" || no "self-register"
docker exec s2cp sh -c "curl -s -H 'Authorization: Bearer $TOKEN' localhost:8094/v1/posture" | grep -q '"all_up":true' && ok "CP posture all_up across both" || no "posture"
docker rm -f s2cp federation-validator zkp-receipt atb-credential-verifier retention-chain >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true

echo ""
echo "===== SUMMARY: $PASS passed, $FAIL failed ====="
if [ "$FAIL" -ne 0 ]; then
  echo "CLEAN-VM RETEST: FAILURES PRESENT" >&2
  exit 1
fi
echo "CLEAN-VM RETEST: 100% GREEN"
