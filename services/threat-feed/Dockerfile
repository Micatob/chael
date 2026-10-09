FROM python:3.11-slim

RUN useradd -m chael
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

RUN chown -R chael:chael /app
USER chael

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen('http://localhost:'+os.environ.get('API_PORT','8090')+'/health')" || exit 1

CMD ["python", "main.py"]
