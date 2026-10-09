FROM python:3.11-slim as base

RUN useradd -m chael
WORKDIR /app

# Pre-download MITRE ATT&CK data at build time (zero runtime dependency)
RUN python << 'PYEOF'
import urllib.request, json
url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
try:
    req = urllib.request.Request(url, headers={'User-Agent': 'ChaelSIEM/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    cache = {}
    for obj in data.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        ext = obj.get('external_references', [{}])[0] if obj.get('external_references') else {}
        tid = ext.get('external_id', '')
        if not tid:
            continue
        kill_chain = obj.get('kill_chain_phases', [])
        tactic = kill_chain[0].get('phase_name', '').replace('-', ' ').title() if kill_chain else ''
        cache[tid] = {'technique': tid, 'name': obj.get('name', ''), 'tactic': tactic, 'url': f'https://attack.mitre.org/techniques/{tid}/'}
    with open('enterprise-attack.json', 'w') as f:
        json.dump(cache, f)
    print(f'Pre-loaded {len(cache)} MITRE ATT&CK techniques')
except Exception as e:
    print(f'MITRE pre-load skipped: {e}')
    with open('enterprise-attack.json', 'w') as f:
        f.write('{}')
PYEOF

FROM base

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 20 -r requirements.txt

COPY src/ .

RUN chown -R chael:chael /app
USER chael

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:' + __import__('os').environ.get('API_PORT', '8000') + '/health')" || exit 1

CMD ["python", "main.py"]