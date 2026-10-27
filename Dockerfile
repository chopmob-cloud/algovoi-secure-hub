# AlgoVoi Secure Hub — lean issuer-trust hub + service bridge.
#
# GET  /health                       liveness + counts
# POST /v1/issuers                   register an issuer DID -> Falcon PK (admin)
# GET  /v1/issuer-pks                {did: pk_b64} for the federation/ZK services
# GET  /.well-known/atb-keys.json    canonical hub doc (atb-credential-verifier)
# POST /v1/services                  bolt on a service/addon
# GET  /v1/posture                   unified health across the bridged services
#
# Build context: algovoi-secure-hub/
FROM python:3.11-slim

LABEL org.opencontainers.image.title="AlgoVoi Secure Hub"
LABEL org.opencontainers.image.description="Issuer-trust hub + service bridge for the substrate-2 federation and ZK-proof services."
LABEL org.opencontainers.image.vendor="AlgoVoi"
LABEL org.opencontainers.image.version="0.3.5"

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY app ./app
COPY scripts ./scripts

RUN pip install --no-cache-dir -e ".[serve]"

# Create the data dir owned by appuser so a fresh mounted volume inherits that
# ownership (the SQLite DB + bootstrap secrets live here).
RUN adduser --disabled-password --gecos "" appuser && mkdir -p /app/data && chown -R appuser /app
USER appuser

VOLUME ["/app/data"]

ENV PYTHONUNBUFFERED=1
ENV AHUB_BIND=0.0.0.0:8094

EXPOSE 8094

HEALTHCHECK --interval=15s --timeout=5s --start-period=8s --retries=3 \
  CMD curl -sf http://localhost:8094/health || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host $(echo $AHUB_BIND | cut -d: -f1) --port $(echo $AHUB_BIND | cut -d: -f2) --log-level info"]
