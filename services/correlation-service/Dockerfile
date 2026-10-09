FROM python:3.11-slim

RUN useradd -m chael
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

RUN chown -R chael:chael /app
USER chael

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:' + __import__('os').environ.get('API_PORT', '8000') + '/health')" || exit 1

CMD ["python", "main.py"]