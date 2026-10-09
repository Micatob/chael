FROM python:3.11-slim

RUN useradd -m chael
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py docker_monitor.py registry_monitor.py auto_update.py cis_benchmark.py vuln_scanner.py yara_scanner.py ./

RUN chown -R chael:chael /app
USER chael

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import os; exit(0 if os.environ.get('CHAEL_SIEM_URL') else 1)" || exit 1

ENTRYPOINT ["python", "agent.py"]
