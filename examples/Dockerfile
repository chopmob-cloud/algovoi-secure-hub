# Example substrate-2 addon — copy addon_app.py, add your logic, build, run with
# S2_HUB_URL + S2_HUB_REGISTRATION_TOKEN and it bolts into the control plane.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir "fastapi>=0.111,<1.0" "uvicorn[standard]>=0.29,<1.0" "httpx>=0.27,<1.0"
COPY addon_app.py .

EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD curl -sf http://localhost:9000/health || exit 1
CMD ["uvicorn", "addon_app:app", "--host", "0.0.0.0", "--port", "9000"]
