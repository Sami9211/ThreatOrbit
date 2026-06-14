# Digest-pinned base image (see dashboard_api/Dockerfile); Dependabot keeps it current.
FROM python:3.11-slim@sha256:ae52c5bef62a6bdd42cd1e8dffef86b9cd284bde9427da79839de7a4b983e7ca
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# The service uses absolute package imports (from log_api.…), so the code
# must live at /app/log_api and run as a package from /app.
COPY . /app/log_api/
EXPOSE 8000
CMD ["uvicorn", "log_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
