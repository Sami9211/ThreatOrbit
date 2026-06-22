# Digest-pinned base image (see dashboard_api/Dockerfile); Dependabot keeps it current.
FROM python:3.11-slim@sha256:ae52c5bef62a6bdd42cd1e8dffef86b9cd284bde9427da79839de7a4b983e7ca
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
# Install from the hash-pinned lockfile (reproducible, tamper-evident builds).
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
# The service uses absolute package imports (from log_api.…), so the code
# must live at /app/log_api and run as a package from /app.
COPY . /app/log_api/

# Run as an unprivileged user (matches dashboard_api hardening); /data holds the
# SQLite DB and is the only writable path the app needs.
RUN useradd --system --no-create-home --uid 10001 app \
    && mkdir -p /data && chown app:app /data
USER app

ENV PYTHONUNBUFFERED=1 LOG_DB_PATH=/data/log_api.db
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Single worker: analysis results are persisted to the DB (so they're shared),
# but the metrics counters are still in-process — keep one worker until those are
# externalised, then this can scale.
CMD ["uvicorn", "log_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
