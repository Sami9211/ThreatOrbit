# Base image pinned by digest (supply-chain integrity): the tag is mutable, the
# digest is not, so a build can't silently pick up a re-pushed base. Dependabot's
# docker ecosystem bumps both the tag and the digest when a new image ships.
FROM python:3.14-slim@sha256:44dd04494ee8f3b538294360e7c4b3acb87c8268e4d0a4828a6500b1eff50061

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
