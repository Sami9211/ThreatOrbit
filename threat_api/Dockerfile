# Digest-pinned base image (see dashboard_api/Dockerfile); Dependabot keeps it current.
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
# Install from the hash-pinned lockfile (reproducible, tamper-evident builds).
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
# The service uses absolute package imports (from threat_api.…), so the code
# must live at /app/threat_api and run as a module from /app.
COPY . /app/threat_api/

# Run as an unprivileged user (matches dashboard_api hardening); /data holds the
# SQLite DB and is the only writable path the app needs.
RUN useradd --system --no-create-home --uid 10001 app \
    && mkdir -p /data && chown app:app /data
USER app

# THREAT_API_BOOT triggers init/IOC-restore/scheduler at import time (gunicorn
# imports the module rather than running __main__). DB_PATH lives on the volume.
ENV PYTHONUNBUFFERED=1 THREAT_API_BOOT=1 DB_PATH=/data/threat_api.db
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Production WSGI server (gunicorn), NOT Flask's dev server. Single worker:
# threat_api keeps rate-limit state in memory and runs one fetch scheduler, so it
# must stay a single process until that state is externalised.
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "1", "--timeout", "120", "threat_api.main:app"]
