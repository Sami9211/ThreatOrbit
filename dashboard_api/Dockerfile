FROM python:3.11-slim

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
