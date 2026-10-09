# CHAEL SIEM — Microservices Security Analytics Platform

**Chael SIEM** is a modern, containerized Security Information and Event Management platform built with FastAPI, OpenSearch, and Nginx. It provides real-time log ingestion, correlation-based threat detection, incident management, and SOAR automation.

---

## Architecture

| Service | Role | Internal Port | External Port |
|---------|------|---------------|---------------|
| **Gateway (Nginx)** | API reverse proxy & routing | 8000 / 8443 | **8001** (HTTP), **8443** (HTTPS) |
| **Frontend (React)** | Analyst dashboard UI | 80 | **3000** |
| **Identity Service** | JWT authentication, agent registry | 8004 | **8004** |
| **Log Ingestion** | Raw log receipt & normalization | 8080 | **8080** |
| **Correlation Service** | Real-time threat detection & rule engine | 8081 | — |
| **Incident Management** | Incident lifecycle & analytics | 8082 | — |
| **SOAR Service** | Automated response playbooks | 8083 | — |
| **ML Analytics** | UEBA anomaly detection | 8084 | — |
| **Threat Feed** | IOC polling & enrichment | 8090 | — |
| **Sigma Converter** | Sigma → Chael rule conversion | 8091 | — |
| **Data Archiver** | Retention & backup/restore | 8092 | — |
| **AI Assistant** | Analyst co-pilot (opt-in, BYOK) | 8093 | — |
| **Flow Collector** | NetFlow ingest (UDP) | 8085 | **2055/udp** |
| **OpenSearch** | Log & incident storage | 9200 | **9200** (admin) |
| **Redis** | Distributed state cache | 6379 | **6379** |
| **Prometheus** | Metrics & scraping | 9090 | **9090** |

---

## Quick Start

### Prerequisites
- Docker Desktop (4+ GB RAM, 2+ CPUs)
- No port conflicts on 8001, 8443, 3000, 9200, 6379, 9090, 2055/udp

### Start All Services

**Windows one-command deploy (new here — start with this):**

```powershell
# From the project root (copies .env.example -> .env on first run, then starts everything):
.\deploy.ps1
```

The script checks Docker, creates `.env` if missing, brings the stack up, waits for
the gateway, and prints your URLs + default login. After first boot:
1. Open http://localhost:3000 — log in as `admin` (password = `ADMIN_PASSWORD` in `.env`).
2. Change `ADMIN_PASSWORD` + `OPENSEARCH_PASSWORD` in `.env`, then
   `docker compose up -d --no-build --force-recreate identity-service` to apply.
3. Deploy an agent on an endpoint (see `AGENT_DEPLOYMENT.md`) — telemetry starts flowing.
4. Optional depth: threat-intel keys, SMTP digest (`SMTP_HOST` + `SMTP_TO`), approver account.
   Every optional key is documented in `.env.example`; anything unset simply stays disabled.

```bash
# From the project root (manual path):
docker-compose up -d
```

The stack initializes in two stages:

1. **Infrastructure** (OpenSearch, Redis) starts first.
2. **Application services** start once OpenSearch health check passes (~2 minutes).

### Verify Health

```bash
# Gateway health (public, no auth)
curl http://localhost:8001/health

# Identity service (public, no auth)
curl http://localhost:8001/api/auth/health
```

Protected endpoints need a JWT — log in first, then pass the token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ChaelSIEMStrongPass1!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

for svc in logs correlation incidents soar; do
  curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/$svc/health
  echo
done
# Sigma / analytics extras:
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/sigma/health; echo
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/analytics/health; echo
```

All responses should include `"status": "healthy"`. The dashboard is at http://localhost:3000.

### Access UIs

- **Analyst dashboard (React)**: http://localhost:3000
- **Prometheus**: http://localhost:9090
- **OpenSearch API (admin)**: https://localhost:9200
  - Username: `admin`
  - Password: value of `OPENSEARCH_PASSWORD` in `.env`
- Grafana dashboards + provisioning live under `monitoring/` (no Grafana container is wired into `docker-compose.yml` yet — optional).

---

## API Reference

All APIs are accessible through the **Gateway** at `http://localhost:8001/api/<service>/...` (HTTPS on `:8443`).

### Authentication
- Routes: `POST /api/auth/login`, `POST /api/auth/validate`
- Default admin credentials: `admin` / `ChaelSIEMStrongPass1!` (change in production!)

### Agent Registration & Verification
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/agent/auto-register` | None | Auto-register a new agent |
| POST | `/api/auth/agent/register` | ADMIN | Register agent (admin-initiated) |
| POST | `/api/auth/agent/verify` | None | Verify agent credentials, get JWT |
| GET | `/api/auth/agent/{id}/config` | ADMIN/AGENT | Get agent configuration |
| POST | `/api/auth/agent/{id}/heartbeat` | None | Agent heartbeat (updates last_seen) |
| GET | `/api/auth/agents` | ADMIN | List all agents |
| DELETE | `/api/auth/agent/{id}` | ADMIN | Revoke an agent |
| DELETE | `/api/auth/agent/{id}/hard` | ADMIN | Permanently delete an agent |
| POST | `/api/auth/agent/{id}/rotate` | ADMIN | Rotate agent API key |

### Log Ingestion (`/api/logs/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ingest` | Submit normalized log (JSON body: `NormalizedLog`) |
| POST | `/raw/{source_type}` | Submit raw log (auto-normalized) |
| GET | `/` | List logs (pagination, filtering) |
| GET | `/export?format=json|csv` | Bulk export |

### Correlation (`/api/correlation/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/process` | Submit log for correlation detection |

### Incidents (`/api/incidents/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | List active incidents |
| POST | `/create` | Create incident (called by correlation) |
| POST | `/{incident_id}/investigate` | Perform forensic investigation |

### Analytics (`/api/analytics/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/overview` | Dashboard stats (total logs, active incidents, trends) |

### SOAR (`/api/soar/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/trigger` | Execute automated response playbook |
| POST | `/approve/{incident_id}/{action_id}` | Manually approve a SOAR action |

---

## Agent Deployment

See `AGENT_DEPLOYMENT.md` for full agent deployment guide.

## Detection Workflow

```
Agent ──▶ Gateway (:8001/:8443) ──▶ Log Ingestion ──▶ Incidents ──▶ SOAR
              │                          │                 │
              │                     Stage B (pre-index      ▼
              │                     counting)          Dashboard :3000
              │                          │
              │                     Stage C (dedup +
              │                     fatigue) + rules
              ▼                          ▼
        JWT via Identity          OpenSearch (:9200)
        Redis counters            Prometheus (:9090)
```

1. **Ingest** — agents ship logs to `POST /api/logs/ingest` (normalized) or `/api/logs/raw/{source}` (auto-normalized). Auth-failure logs are **never deduplicated** so brute-force signals survive.
2. **Correlate** — 5+ SSH auth failures from one IP in 60s → MEDIUM incident (risk 65); 15+ → HIGH (risk 85). Internal ranges (10/8, 172.16/12, 192.168/16) are whitelisted from alerting by default (`config.yaml`).
3. **Investigate** — `POST /api/incidents/{id}/investigate` returns MITRE mapping, IOC enrichment, and a false-positive checklist.
4. **Respond** — `POST /api/soar/trigger` runs playbooks (log + audit + notifications).

> **Note:** status/severity/host filters use `match` queries because the indices are dynamically mapped (`text` + `keyword`). Alert fatigue counts only *fired* alerts (max 50/source/hour, 5-min per-rule cooldown).

**Quick deploy (Linux):**
```bash
python agent.py --siem-url http://<siem-host>:8001 --agent-name $(hostname) --mode linux-syslog
```

**Quick deploy (Windows, as Admin):**
```powershell
.\deploy-agent.ps1 -SiemUrl "http://<siem-host>:8001"
```

The agent auto-registers with the SIEM. No pre-generated keys needed.

---

## Testing

**Quick test - ingest a sample log:**

```bash
# 1. Ingest (needs JWT — log in first, see Verify Health)
curl -X POST http://localhost:8001/api/logs/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "host": "web-server-01",
    "source": "auth",
    "log_type": "auth",
    "severity": "HIGH",
    "message": "Failed password for root from 203.0.113.9 port 5222 ssh2",
    "metadata": {"event_type": "ssh_failed_password", "src_ip": "203.0.113.9", "user": "root"}
  }'
```

Send 5+ failures like that within a minute, then query incidents: `curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/incidents/`

---

## Development

### Service Entry Points

Each service's `src/main.py` launches uvicorn. For local debugging:

```bash
cd services/log-ingestion-service
python -m uvicorn api.main:app --reload --port 8080
```

### Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `0.0.0.0` | Bind address |
| `API_PORT` | service-specific | Port number |
| `OPENSEARCH_HOST` | `opensearch` | OpenSearch node |
| `OPENSEARCH_PORT` | `9200` | Port |
| `OPENSEARCH_USER` | `admin` | Username |
| `OPENSEARCH_PASSWORD` | `ChaelSIEMStrongPass1!` | Password |
| `STORAGE_TYPE` | `opensearch` | `opensearch` or `local` |
| `JWT_SECRET` | (auto-generated) | JWT signing secret |

---

## Troubleshooting

### Services not starting
- Ensure OpenSearch is healthy: `docker compose logs opensearch`
- Check container logs: `docker compose logs <service-name>`
- Verify port availability: `netstat -ano | findstr :8001`

### Agent not registering
- Check agent logs for connection errors
- Verify gateway is running: `curl http://localhost:8001/health`
- Ensure identity service is up: `curl http://localhost:8001/api/auth/health`
- Agent heartbeat is at `POST /api/auth/agent/{id}/heartbeat` (no auth needed)

### Correlations not triggering
- SSH brute-force needs `metadata.event_type=ssh_failed_password` + `src_ip` set (the `/raw/{source}` normalizers set these automatically; manual `/ingest` calls must include them).
- Internal ranges (10/8, 172.16/12, 192.168/16) are alert-whitelisted by default — test with a public-looking IP.
- Counters live in Redis; 5 failures/60s → MEDIUM incident.

---

## Project Structure

```
/chael/
├── docker-compose.yml
├── .env
├── services/
│   ├── gateway/               # Nginx reverse proxy
│   ├── identity-service/      # Auth/JWT + agent registry (SQLite)
│   ├── log-ingestion-service/ # Log receipt & normalization
│   ├── correlation-service/   # Real-time detection
│   ├── incident-management-service/  # Incidents & analytics
│   └── soar-service/          # Automated response
├── services/agent/            # Remote log forwarding agent
└── frontend/                  # React dashboard (MISSING)
```

---

## Security Notes

- Agent credentials (API keys) are stored as SHA-256 hashes, never plaintext
- Agent registration uses SQLite with WAL mode for concurrent access
- Password comparison uses constant-time `hmac.compare_digest()` to prevent timing attacks
- Auth middleware allows unauthenticated access only to: health checks, agent auto-register, agent verify, and agent heartbeat endpoints
- StorageFactory singletons are thread-safe with double-checked locking

---

**Last Updated:** 2026-09-01
**Maintainers:** Chael SIEM Team
**License:** Proprietary
