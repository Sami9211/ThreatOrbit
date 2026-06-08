FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/dashboard_api/

ENV PYTHONUNBUFFERED=1 DASHBOARD_DB_PATH=/data/dashboard.db
VOLUME ["/data"]
EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8002/health')" || exit 1

CMD ["uvicorn", "dashboard_api.main:app", "--host", "0.0.0.0", "--port", "8002"]
