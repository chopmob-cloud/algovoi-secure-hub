#!/bin/bash
set -euo pipefail
# Clean-VM retest of the FULL substrate-2 set including atb-credential-verifier:
# wipe, rebuild all five from scratch (--no-cache), run every acceptance test,
# CP persistence, and bridge all four services into the control plane at once.
FED=algovoi-federation-validator:clean
ZKP=algovoi-zkp-receipt:clean
ATB=algovoi-atb-credential-verifier:clean
RET=algovoi-retention-chain:clean
CP=algovoi-secure-hub:clean
NET=s2-val4
PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "===== CLEAN SLATE ====="
docker rm -f s2cp federation-validator zkp-receipt atb-credential-verifier retention-chain >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
docker volume rm s2cp-data >/dev/null 2>&1 || true
docker rmi -f $FED $ZKP $ATB $RET $CP >/dev/null 2>&1 || true
if [ "${AHUB_PRUNE_BUILDER_CACHE:-0}" = "1" ]; then docker builder prune -af; fi
echo "wiped"

echo "===== FROM-SCRATCH BUILDS (--no-cache) ====="
cd /root/fedval-clean  && docker build --no-cache -t $FED . >/tmp/bf.log 2>&1 && ok "federation built"  || { no "federation build"; tail -4 /tmp/bf.log; }
cd /root/zkprcpt-clean && docker build --no-cache -t $ZKP . >/tmp/bz.log 2>&1 && ok "zkp-receipt built" || { no "zkp build"; tail -4 /tmp/bz.log; }
cd /root/atbv-clean    && docker build --no-cache -t $ATB . >/tmp/ba.log 2>&1 && ok "atb-verifier built" || { no "atb build"; tail -4 /tmp/ba.log; }
cd /root/retchain-clean && docker build --no-cache -t $RET . >/tmp/br.log 2>&1 && ok "retention built" || { no "retention build"; tail -4 /tmp/br.log; }
cd /root/s2cp          && docker build --no-cache -t $CP . >/tmp/bc.log 2>&1 && ok "control-plane built" || { no "cp build"; tail -4 /tmp/bc.log; }

echo "===== ACCEPTANCE (each service self-proves) ====="
docker run --rm $FED python scripts/acceptance.py 2>/dev/null | grep -q "ALL GREEN" && ok "federation acceptance" || no "federation acceptance"
docker run --rm $ZKP python scripts/acceptance.py 2>/dev/null | grep -q "ALL GREEN" && ok "zkp-receipt acceptance" || no "zkp-receipt acceptance"
docker run --rm $ATB python scripts/acceptance.py 2>/dev/null | grep -q "ALL GREEN" && ok "atb-verifier acceptance" || no "atb-verifier acceptance"
docker run --rm $RET python scripts/acceptance.py 2>/dev/null | grep -q "ALL GREEN" && ok "retention acceptance" || no "retention acceptance"
docker run --rm $CP  python scripts/acceptance.py 2>/dev/null | grep -q "ALL GREEN" && ok "control-plane acceptance" || no "control-plane acceptance"

echo "===== CONTROL PLANE PERSISTENCE ====="
docker volume create s2cp-data >/dev/null
docker run -d --name v-cp -v s2cp-data:/app/data $CP >/dev/null; sleep 4
TOKEN=$(docker exec v-cp cat /app/data/admin_token)
PK=$(docker exec v-cp python -c "import os,base64;print(base64.b64encode(os.urandom(1793)).decode())")
docker exec v-cp curl -s -X POST localhost:8094/v1/issuers -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"did\":\"did:web:v\",\"public_key_b64\":\"$PK\"}" >/dev/null
docker rm -f v-cp >/dev/null 2>&1
docker run -d --name v-cp2 -v s2cp-data:/app/data $CP >/dev/null; sleep 4
docker exec v-cp2 curl -s localhost:8094/health | grep -q '"issuer_count":1' && ok "SQLite persistence across restart" || no "persistence"
docker rm -f v-cp2 >/dev/null 2>&1; docker volume rm s2cp-data >/dev/null 2>&1

echo "===== BRIDGE ALL FOUR SERVICES (drop-in, 2 env vars each) ====="
docker network create $NET >/dev/null
FED_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ZKP_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ATB_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
RET_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
REG_JSON="{\"federation-validator\":\"$FED_REG_TOKEN\",\"zkp-receipt\":\"$ZKP_REG_TOKEN\",\"atb-credential-verifier\":\"$ATB_REG_TOKEN\",\"retention-chain\":\"$RET_REG_TOKEN\"}"
docker run -d --name s2cp --network $NET -e AHUB_REGISTRATION_TOKENS="$REG_JSON" $CP >/dev/null; sleep 4
TOKEN=$(docker exec s2cp cat /app/data/admin_token)
PK=$(docker exec s2cp python -c "import os,base64;print(base64.b64encode(os.urandom(1793)).decode())")
docker exec s2cp curl -s -X POST localhost:8094/v1/issuers -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"did\":\"did:web:h\",\"public_key_b64\":\"$PK\"}" >/dev/null
docker run -d --name federation-validator    --network $NET -e S2_HUB_URL=http://s2cp:8094 -e S2_HUB_TOKEN=$FED_REG_TOKEN $FED >/dev/null
docker run -d --name zkp-receipt             --network $NET -e S2_HUB_URL=http://s2cp:8094 -e S2_HUB_TOKEN=$ZKP_REG_TOKEN $ZKP >/dev/null
docker run -d --name atb-credential-verifier --network $NET -e S2_HUB_URL=http://s2cp:8094 -e S2_HUB_TOKEN=$ATB_REG_TOKEN $ATB >/dev/null
docker run -d --name retention-chain         --network $NET -e S2_HUB_URL=http://s2cp:8094 -e S2_HUB_TOKEN=$RET_REG_TOKEN $RET >/dev/null
sleep 9
P=$(docker exec s2cp sh -c "curl -s -H 'Authorization: Bearer $TOKEN' localhost:8094/v1/posture")
echo "$P" | grep -q "federation-validator" && echo "$P" | grep -q '"zkp-receipt"' && echo "$P" | grep -q "atb-credential-verifier" && echo "$P" | grep -q "retention-chain" && ok "all four self-registered" || no "self-register"
echo "$P" | grep -q '"all_up":true' && ok "posture all_up across all four" || no "posture"
docker rm -f s2cp federation-validator zkp-receipt atb-credential-verifier retention-chain >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true

echo ""
echo "===== SUMMARY: $PASS passed, $FAIL failed ====="
if [ "$FAIL" -ne 0 ]; then
  echo "RETEST: FAILURES PRESENT" >&2
  exit 1
fi
echo "FULL SET (4 services + control plane) CLEAN-VM RETEST: 100% GREEN"
