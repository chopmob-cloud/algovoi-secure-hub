#!/bin/sh
# Runs INSIDE a clean python:3.11-slim container = a customer's box.
# Installs Substrate-2 purely from the delivered bundle (no source, no images),
# then runs all five services and bridges the four into the control plane.
set -e
cp /in/bundle.algv /in/algovoi_unbundle.py /in/licence.key /tmp/
cd /tmp

echo "=== step 1: install runtime deps (INSTALL.txt step 1) ==="
pip install -q cryptography pqcrypto rfc8785 fastapi uvicorn httpx

echo "=== step 2: verify licence + decrypt + install the wheels (offline) ==="
python algovoi_unbundle.py --license @licence.key --out ./algovoi --install bundle.algv >/tmp/unbundle.log 2>&1
tail -3 /tmp/unbundle.log

echo "=== installed console commands ==="
missing=0
for c in algovoi-secure-hub algovoi-federation-validator algovoi-zkp-receipt algovoi-atb-credential-verifier algovoi-retention-chain; do
  if command -v "$c" >/dev/null 2>&1; then echo "  ok   $c"; else echo "  MISS $c"; missing=1; fi
done
if [ "$missing" -ne 0 ]; then echo "required console command missing" >&2; exit 1; fi

echo "=== step 3: start the control plane ==="
mkdir -p /tmp/cpd
FED_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ZKP_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ATB_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
RET_REG_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
export AHUB_REGISTRATION_TOKENS="{\"federation-validator\":\"$FED_REG_TOKEN\",\"zkp-receipt\":\"$ZKP_REG_TOKEN\",\"atb-credential-verifier\":\"$ATB_REG_TOKEN\",\"retention-chain\":\"$RET_REG_TOKEN\"}"
AHUB_DATA_DIR=/tmp/cpd algovoi-secure-hub >/tmp/cp.log 2>&1 &
sleep 5
python -c "import urllib.request; print('  control-plane /health:', urllib.request.urlopen('http://localhost:8094/health',timeout=5).read().decode())"

TOKEN=$(cat /tmp/cpd/admin_token); export TOKEN
PK=$(python -c "import os,base64;print(base64.b64encode(os.urandom(1793)).decode())"); export PK
python -c "import urllib.request,json,os; urllib.request.urlopen(urllib.request.Request('http://localhost:8094/v1/issuers',data=json.dumps({'did':'did:web:demo','public_key_b64':os.environ['PK']}).encode(),headers={'Authorization':'Bearer '+os.environ['TOKEN'],'Content-Type':'application/json'},method='POST'),timeout=5); print('  issuer registered')"

echo "=== step 4: start the four services, bridged to the control plane ==="
export S2_HUB_URL=http://localhost:8094
S2_HUB_TOKEN=$FED_REG_TOKEN S2_HUB_SELF_URL=http://localhost:8092 algovoi-federation-validator      >/tmp/fed.log 2>&1 &
S2_HUB_TOKEN=$ZKP_REG_TOKEN S2_HUB_SELF_URL=http://localhost:8093 algovoi-zkp-receipt               >/tmp/zkp.log 2>&1 &
S2_HUB_TOKEN=$ATB_REG_TOKEN S2_HUB_SELF_URL=http://localhost:8095 algovoi-atb-credential-verifier   >/tmp/atb.log 2>&1 &
S2_HUB_TOKEN=$RET_REG_TOKEN S2_HUB_SELF_URL=http://localhost:8096 algovoi-retention-chain           >/tmp/ret.log 2>&1 &
sleep 9

echo "=== control plane posture (services bridged?) ==="
python -c "import urllib.request,json,os,sys; d=json.load(urllib.request.urlopen(urllib.request.Request('http://localhost:8094/v1/posture',headers={'Authorization':'Bearer '+os.environ['TOKEN']}),timeout=5)); [print('  ',s['name'],'->','UP' if s['up'] else 'down') for s in d['services']]; print('  all_up:', d['all_up']); sys.exit(0 if d.get('all_up') is True else 1)"
echo "DONE"
