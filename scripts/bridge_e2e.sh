#!/bin/bash
set -euo pipefail
# Live bridge proof: the lean AlgoVoi Secure Hub coordinating the ACTUAL
# running federation-validator + zkp-receipt services over a docker network.
CP=algovoi-secure-hub:clean
FED=algovoi-federation-validator:clean
ZKP=algovoi-zkp-receipt:clean
NET=s2-bridge

cleanup() {
  for c in s2cp federation-validator zkp-receipt; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" >/dev/null

echo "STEP 1 - start the lean CP + the two substrate-2 services on one network (all bootstrap clean)"
docker run -d --name s2cp --network "$NET" "$CP" >/dev/null
docker run -d --name federation-validator --network "$NET" -e FEDERATION_ISSUER_PKS='{}' "$FED" >/dev/null
docker run -d --name zkp-receipt --network "$NET" "$ZKP" >/dev/null
sleep 8
TOKEN=$(docker exec s2cp cat /app/data/admin_token)

echo "STEP 2 - register an issuer in the trust hub + bridge the two running services"
PK=$(docker exec s2cp python -c "import os,base64;print(base64.b64encode(os.urandom(1793)).decode())")
docker exec s2cp curl -fsS -X POST localhost:8094/v1/issuers -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"did\":\"did:web:bridge-issuer\",\"public_key_b64\":\"$PK\"}" >/dev/null
docker exec s2cp curl -fsS -X POST localhost:8094/v1/services -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"federation-validator","type":"federation","base_url":"http://federation-validator:8092"}' >/dev/null
docker exec s2cp curl -fsS -X POST localhost:8094/v1/services -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"zkp-receipt","type":"zkp-receipt","base_url":"http://zkp-receipt:8093"}' >/dev/null

echo "STEP 3 - federation-validator pulls its trust set from the CP hub (the bridge in action)"
TRUST=$(docker exec federation-validator sh -c 'curl -fsS http://s2cp:8094/v1/issuer-pks')
python3 - "$TRUST" <<'PY'
import json
import sys
trust = json.loads(sys.argv[1])
assert trust, "issuer trust set is empty"
assert "did:web:bridge-issuer" in trust, "expected issuer missing"
print(json.dumps(trust, sort_keys=True))
PY

echo "STEP 4 - CP posture: polls the real /health of both bridged services"
POSTURE=$(docker exec s2cp sh -c "curl -fsS -H 'Authorization: Bearer $TOKEN' localhost:8094/v1/posture")
python3 - "$POSTURE" <<'PY'
import json
import sys
posture = json.loads(sys.argv[1])
assert posture.get("all_up") is True, posture
services = {item["name"] for item in posture.get("services", [])}
expected = {"federation-validator", "zkp-receipt"}
assert expected <= services, (expected, services)
assert all(item.get("up") is True for item in posture["services"] if item["name"] in expected), posture
print(json.dumps(posture, indent=2, sort_keys=True))
PY


echo "[PASS] CP bridges both expected services and posture is all_up"
echo done
