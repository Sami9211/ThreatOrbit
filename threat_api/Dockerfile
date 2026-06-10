FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# The service uses absolute package imports (from threat_api.…), so the code
# must live at /app/threat_api and run as a module from /app.
COPY . /app/threat_api/
EXPOSE 8000
CMD ["python", "-m", "threat_api.main"]
