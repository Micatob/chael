# Chael SIEM — Dual-Track Distribution Strategy
Standalone SIEM (orgs) + Lightweight Agent (everyone else pulls as monitoring)

Last updated: 2026-10-16. Source of truth from STATE.md / SESSION.md / ROADMAP.md / HUNTING_ROADMAP.md. No Docker was touched for this doc.

## 1. Verdict: possible, and not terrible — if you split it correctly

Your friend's VS Code extension pattern works for *dev tools*. Chael is a defensive SIEM (not offensive), so it is actually *easier* to distribute than his tool — no abuse review, no offensive-use flag.

But do NOT ship the whole SIEM as a VS Code extension. Correct split:

- **Track A — Chael Standalone (unchanged):** `docker-compose.yml` stack (gateway :8001/:8443, frontend :3000, identity/log-ingestion/correlation/incident/soar/ml/threat-feed/flow/sigma/archiver/ai-assistant + OpenSearch + Redis + Prometheus). This stays the org self-hosted SOC.
- **Track B — Chael Agent / Shipper (new packaging):** the thing in `services/agent/agent.py` (~1133 lines) + `response.py` + `pre_filter.py` + `yara_scanner.py` + `registry_monitor.py` + `cis_benchmark.py` + `vuln_scanner.py` + `deploy-agent.ps1/.sh`. It already auto-registers (`POST /api/auth/agent/auto-register` → verify → heartbeat → ingest), self-heals (key preservation, mark-online, reconnect loop), and does task-pull containment. That is the only piece you publish to marketplaces. It phones home to any Track A server.

VS Code extension = thin adapter over Track B, not a replacement for it.

## 2. What Chael is still missing (from past sessions, code-complete vs live)

### 2a. Code done, NOT live — rebuild when box cool (from STATE.md top)
1. Perf pass (4 images): incident-mgmt trims `source_logs`→3-preview + `log_count`, SOAR history `?limit=` (dashboard polls 20), ai-assistant parallel snapshot + 20s TTL cache, frontend uses `log_count`. Needs `incident-mgmt + soar + ai-assistant + frontend` rebuild + `--force-recreate`.
2. Registration hardening `84ee9ab` was pushed but live containers were still on OLD images at last check (unauth mark-online 404 not 401, dry-run 405 not 200). Needs the 4-image rebuild in STATE.md.

### 2b. User actions only (assistant cannot do)
- Restart endpoint agent — `total_logs` was 0, Agents list 0 at last save. If your post-save test showed ONLINE + logs, tell me and this is done (STATE.md just stale — Docker off so I can't re-verify live).
- [x] 2026-10-16 KEYS KEPT per user decision — Groq + AbuseIPDB + Gemini stay. They work; rotation was hygiene-only (chat-history exposure, never committed to git). No new keys needed.
- Change `ADMIN_PASSWORD` (still `ChaelSIEMStrongPass1!`), create `APPROVER_USERNAME`/`APPROVER_PASSWORD` + `ANALYST_*` to activate RBAC split (ANALYST triggers, ADMIN/APPROVER approves, no self-approval).
- Wire EDR or re-run `deploy-agent.ps1` so `response.py` polling goes live; or set `EDR_PROVIDER` + keys.

### 2c. Ranked next (ROADMAP.md order, still open)
1. **Live endpoint proof** — remote isolate drill + triage upload from real host. Validates 80% of shipped features.
2. **IOC auto-block** — high-confidence threat-feed IOCs → firewall block via existing approval gate.
3. **SLA escalation alerts** — P1/P2 breach timers into notification channels (tiers in `config.yaml` exist, alerting not wired).
4. **Playbook dry-run + versioning** — partially landed in `84ee9ab` (dry-run + versions + rollback endpoints at code level), needs live verify + UI.
5. **Full disk/memory imaging Phase 2** — plumbing landed (image-chunk/complete 12MB/chunk, 4GB cap, SHA-256 seal + `collect_memory/collect_disk_image` loud-fail), acquisition + WORM store + restore drill missing.
6. **MFA TOTP** (SSO deferred, needs IdP decision).
7. **HA story** — `docker-compose.cluster.yml` exists, needs documented 3-node procedure + backlog-replay proof.
8. **Compliance depth** — beyond keyword mapping: config snapshots, access reviews, auditor export packs.
9. **Detection depth** — Suricata/Zeek parsers, longer-window correlations, curated Sigma pack tuned per-env (converter + `deploy-bulk` exist, FP tuning missing).
10. **Agent config editor** in Agents page (backend already serves per-agent config).
11. **STIX/TAXII ingest** for threat-feed.
12. **Backup/restore drills** — restore-to-staging proof, not just backup jobs.

### 2d. Hunting deferred (HUNTING_ROADMAP.md)
- Retro-IOC sweep (new feed IOCs vs last 7–30d `chaelsiem-logs-*`, Redis `swept:ioc:*` guard).
- Server-side saved hunts (`chaelsiem-saved-hunts` index + `GET/POST/DELETE /api/incidents/hunts`) to replace `localStorage`.

## 3. Where Chael Agent can live (ranked by effort/return)

### Tier 0 — Do first (zero new code, just publish what you have)
1. **Docker Hub / GHCR `chael-agent`** — you already have `services/agent/Dockerfile` + `profiles: [agent]`. `docker pull chael/agent` + `pip install chael-agent`. Lowest friction for homelab/SOC try-outs.
2. **PyPI `chael-agent`** — `requirements.txt` is tiny (requests, psutil, watchdog, yara, cryptography, pyyaml). `pipx install chael-agent` → `chael-agent --siem-url ...`. Enables all below.
3. **PowerShell Gallery + `winget` + Chocolatey (Windows)** — wrap existing `deploy-agent.ps1` (`irm <siem>:8001/api/agent/download/deploy-agent.ps1 | iex` already works via gateway). Publish as `Install-Script ChaelAgent`, `winget install chael.agent`, `choco install chael-agent`. This is where 90% of your endpoints are.
4. **apt/yum repo + Homebrew tap + Snap Store** — same Python agent, `apt install chael-agent`, `brew install chael/tap/chael-agent`, `snap install chael-agent --classic`. Covers Linux servers + Mac laptops.

### Tier 1 — High leverage (thin wrappers, big reach)
5. **VS Code Extension (OpenVSX + VS Marketplace) — YES but scoped.** Call it `Chael Sentinel for Code`. It must NOT pretend to be system SIEM. What it CAN do well: workspace file-integrity (new/changed exec, `.env`/key leak via existing `pre_filter.py` allowlists), YARA scan on save (reuse `yara_scanner.py`), terminal command risk hint (opt-in), one-click "Ship workspace logs to my Chael" pointing at user's Track A server. What it CANNOT do: Windows Event Log 4625/4688, Sysmon, kernel, boot persistence — that needs the companion Python service (extension downloads/offers `deploy-agent.ps1` link). This is a funnel, not the sensor. Effort: small (TypeScript webview + calls `http://siem:8001/api/logs/raw/vscode` — add one normalizer in log-ingestion).
6. **JetBrains Marketplace plugin** — same adapter as #5 for IntelliJ/PyCharm. Reuse logic.
7. **GitHub Action + GitLab component (`chael/log-shipper`)** — CI ships build/audit logs to SIEM per-run. Zero privilege issues, huge visibility for supply-chain hunting. Effort: tiny (wrap `agent.py --mode tail`).
8. **Ansible Galaxy / Chef Supermarket / Puppet Forge (`chael.agent`)** — SOCs deploy to 100s of hosts with one role. You already support systemd + Scheduled Task; just package it.
9. **Helm chart + ArtifactHub** — `helm install chael-agent` as DaemonSet with `/var/log` mount. K8s shops expect this, not `docker compose --profile agent`.

### Tier 2 — Cloud / enterprise procurement (later, when hardening done)
10. **AWS / Azure / GCP Marketplace (AMI + container offer)** — Track A as AMI ("Chael SIEM in a box"), Track B as VM extension (Azure Custom Script / AWS SSM Distributor package). Requires MFA, signed images, backup/restore proof (#6, #12 above) before auditors accept it.
11. **Tailscale / WireGuard / Radmin-ready bundle** — you already document Scenarios B–D in `AGENT_DEPLOYMENT.md`. Ship `chael-agent --siem-url http://100.x:8001` presets. Solves NAT without exposing :8001 publicly.
12. **Syslog/CEF/LEEF forwarder mode** — let Splunk/QRadar/Sentinel/Elastic users pull Chael Agent as a sidecar that *also* forwards to their incumbent. Turns competitors into channels. Effort: small (`syslog_forward` block already in `config.yaml`, just wire sender in agent).

### Explicit non-goals (don't bother)
- Browser extension as SIEM sensor (no host logs, store review pain).
- Mobile app / MDM agent (different sandbox, no Event Log equivalent).
- Full SIEM in VS Code webworker (memory/CPU caps kill OpenSearch; keep server server-side).
- Replacing EDR/XDR (ROADMAP.md non-goal — orchestrate CrowdStrike/SentinelOne/Defender via `EDR_PROVIDER`, don't clone them).

## 4. Minimal work to unlock Tier 0+1 (no Docker needed)

1. Pin `services/agent/requirements.txt` + add `pyproject.toml` (`[project] name=chael-agent`, entry point `chael-agent=agent:main`) → PyPI ready.
2. Split agent into `collector` (needs admin) vs `sender` (user-space, VS Code-safe) so the extension can run without elevation.
3. Add one log-ingestion normalizer `POST /api/logs/raw/vscode` + `raw/ci` (extension + GitHub Action need a typed source; avoids stuffing everything through `tail`).
4. Sign `deploy-agent.ps1` + publish versioned zip at `GET /api/agent/download/*` (gateway already serves `/opt/chael/agent-files`; add SHA-256 manifest for store reviews).
5. VS Code ext skeleton: `package.json` (commands: `chael.connect`, `chael.scanWorkspace`, `chael.shipLogs`), webview for SIEM URL + agent status (reuse `GET /api/auth/agents` + `GET /api/logs/stats`), bundled `pre_filter.py` regexes for secret detection. No Python dependency inside the ext — shell out to installed Track B or pure-TS fallback.

## 5. Suggested sequencing

- This week (no Docker): PyPI + versioned download manifest + `raw/vscode` + `raw/ci` normalizers (code-only, verify with `pytest`, like perf pass).
- Next cool-box session: live rebuild (Section 2a) + endpoint agent restart + `total_logs > 0` proof FIRST — don't publish an agent nobody has proven E2E.
- Then: winget/choco/brew + VS Code ext (funnel) + GitHub Action + Ansible role.
- Last: cloud marketplaces after MFA + HA + backup-restore drill (auditor blockers).
