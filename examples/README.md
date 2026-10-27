# Bolting an addon into the AlgoVoi Secure Hub

An **addon** is any service that wants to share the control plane's issuer trust set
and appear in its posture. The integration contract is deliberately tiny — no SDK,
no shared library, language-agnostic:

1. **Expose a `/health` endpoint**. It must return 200 only while the control-plane bridge is healthy (or explicit standalone mode is enabled).
2. **Set the hub URL, an isolated-network override for HTTP examples, and a scoped registration token**; the addon self-registers + refreshes trust:
   - `S2_HUB_URL` — the control plane URL
   - `S2_HUB_ALLOW_INSECURE=1` — only for the isolated HTTP example; use HTTPS otherwise
   - `S2_HUB_REGISTRATION_TOKEN` — scoped to the configured addon name
3. **Refresh trust before business operations** from `GET <hub>/v1/issuer-pks` → `{did: pk_b64}`; a failed or empty response is degraded.

`addon_app.py` is the **complete template**: copy it, drop your logic into the handler,
build, and run with the two env vars. The same pattern (the `hub_client.py` module) is
what federation-validator, zkp-receipt and atb-credential-verifier use. A non-Python
addon just makes the same two HTTP calls (one `GET /v1/issuer-pks`, one `POST /v1/services`)
and exposes `/health`.

## Try it

```bash
# build the example addon
docker build -t example-addon .

# with the control plane (s2cp) running on a shared network:
docker run -d --name example-addon --network <net> \
  -e S2_HUB_URL=http://s2cp:8094 \
  -e S2_HUB_ALLOW_INSECURE=1 \
  -e S2_HUB_REGISTRATION_TOKEN=<scoped registration token> \
  -e S2_HUB_NAME=example-addon \
  example-addon

# it now appears in the control plane posture:
TOKEN=$(docker exec s2cp cat /app/data/admin_token)
docker exec s2cp curl -s -H "Authorization: Bearer ${TOKEN}" localhost:8094/v1/posture
```

For a non-isolated deployment, use an HTTPS hub URL and omit `S2_HUB_ALLOW_INSECURE`. Configure the scoped token on the control plane with `AHUB_REGISTRATION_TOKEN` and `AHUB_REGISTRATION_NAME`.
