# Base image pinned by digest (supply-chain integrity): the tag is mutable, the
# digest is not, so a build can't silently pick up a re-pushed base. Dependabot's
# docker ecosystem bumps both the tag and the digest when a new image ships.
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

WORKDIR /app
# Install from the hash-pinned lockfile (reproducible, tamper-evident builds);
# requirements.txt stays the human-edited input. Regenerate the lock with
# pip-compile --generate-hashes when requirements.txt changes.
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY . /app/dashboard_api/

# Run as an unprivileged user (Tier-1 hardening): the only writable path is
# the data volume, owned by the app user.
RUN useradd --system --no-create-home --uid 10001 app \
    && mkdir -p /data && chown app:app /data
USER app

ENV PYTHONUNBUFFERED=1 DASHBOARD_DB_PATH=/data/dashboard.db
VOLUME ["/data"]
EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8002/health')" || exit 1

CMD ["uvicorn", "dashboard_api.main:app", "--host", "0.0.0.0", "--port", "8002"]
