FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*

RUN useradd -m chael
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 20 -r requirements.txt

COPY src/ .

RUN mkdir -p /data && chown -R chael:chael /data /app
USER chael

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:' + __import__('os').environ.get('API_PORT', '8004') + '/health')" || exit 1

CMD ["python", "main.py"]
