FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 20 -r requirements.txt

COPY src/ /app/src/

ENV PYTHONPATH=/app/src

EXPOSE 8092

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8092/health')" || exit 1

CMD ["sh", "-c", "python src/main.py & exec uvicorn api:app --host 0.0.0.0 --port 8092"]
