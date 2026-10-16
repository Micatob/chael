# Chael SIEM — Small Missing Basics (confirmed code-only, Docker off, 2026-10-16)
All items verified by file:line inspection (3 parallel audits). Each is code-only → `py_compile` / `pytest` → rebuild when live.

## A. Ingestion normalizers (log-ingestion-service)
Registry: `src/normalizers/factory.py:7-21` = windows,syslog,docker,aws,azure,gcp,apache,nginx,web_error,generic,json,generic_json,cef. Route `src/api/routers/logs.py:185-208`.
1. `raw/syslog` is keyword-only (`real_world.py:149-193`) — no `<PRI>`, no RFC3164/5424 timestamp/hostname/app parse. Add `SyslogRFCNormalizer` (~50 lines).
2. No LEEF (`grep leef` = 0). Copy `CEFNormalizer` (`real_world.py:257-298`) pattern.
3. `WindowsNormalizer` dict-only (`real_world.py:10-69`) — `wevtutil /format:xml` string returns None. Add `WindowsXMLNormalizer` (`ET.fromstring`).
4. No Suricata Eve (`eve.json` alert/http/dns/tls/flow) and no Zeek (conn/http/dns). Add 2 small normalizers.
5. No dedicated `journald` key — agent sends `source=journald:{unit}` (`agent.py:489`) but server falls back to generic syslog, loses `PRIORITY/_SYSTEMD_UNIT`. Add 20-line normalizer (matches `config.yaml:33-35` whitelist).
6. No `raw/vscode`, `raw/ci` (confirmed absent) — needed for VS Code ext + GitHub Action funnel. Add 2 classes + registry lines + `tests/test_vscode_ci_normalizer.py`.

## B. Agent correctness (services/agent, all offline-testable)
7. `journald` mode dead: `--journald-units` + `_read_journald:458` exist but `main:958-987` never dispatches `mode==journald`. 5-line fix.
8. `PreFilter` unwired: `pre_filter.py:28-88` exists, `grep PreFilter agent.py` = 0 — tails never call `should_forward`. 1-line-per-put fix.
9. Offline spool missing: only in-mem `QUEUE(maxsize=10000):40`, overflow drops (`773,804,814`). Add `~/.chael/spool.jsonl` append/drain.
10. No real batching: collects 50 (`747`) then per-entry `POST /ingest` loop (`767`). Add bulk endpoint or gzip batch (`gzip.compress` + `Content-Encoding`).
11. `verify=False` everywhere (`agent.py:102,165,508,646,739`, `response.py:305,338,345,514,532`). Add `--ca-bundle/--insecure` → `verify=ca_path`.
12. `syslog_forward` in `config.yaml:185-189` but `grep` in agent = 0. Add UDP/TCP sender in `_forwarder`.
13. Auto-update unsigned (`auto_update.py:80-95` no checksum; only forensic sha in `response.py`). Ship `SHA256SUMS` + verify before `_apply_update`.
14. `requirements.txt:1-7` all `>=`/bare. Pin `==` + hashes for stores. PyPI `pyproject.toml` + `version.py` DONE 2026-10-16 (flat `py-modules`, `chael-agent=agent:main`).

## C. Auth hardening (identity-service)
15. No login lockout at app level: `api/main.py:22` global `10/second` only; `routers/auth.py:17-18` login has no `@limiter.limit`, no failed-counter (`Select-String limiter` = only `main.py:6,22,43`). Nuance (verified 2026-10-16): gateway DOES throttle edge — `nginx.conf:14-15,51-52` `auth_limit 5r/s burst 10` on `/api/auth/`. So brute force is slowed, but there is no account lockout / `Retry-After` / failed-login audit. Fix: `5/minute` on login + `failed{ip,user}>5→429`.
16. No password policy: `LoginRequest{username,password:str}` (`auth.py:13-15`), defaults in `config.py:22-32`, `tenants.py:80` plaintext doc. Add `min_length/complexity` validator.
17. No JWT refresh/rotation (`grep refresh_token` = 0), 24h token (`config.py:9`, `jwt.py:7`). Add `/refresh` or shorten + rotation.
18. No TOTP/MFA (`grep TOTP|MFA|pyotp` = 0), single-factor `hmac.compare_digest` (`auth.py:18-55`).
19. Logout is cookie-delete only (`auth.py:73-76`), `middleware.py:44-50` no `jti/denylist`. Add denylist on logout.
20. Login audit only `logger.info` (`auth.py:30`), no OpenSearch `chaelsiem-audit-logs` write. POST to existing `/api/audit/append`.

## D. SOAR + intel small fixes (soar-service, threat-feed)
21. Playbook version-key case bug: `engine.py:864 get(name.upper())` but `:825,838,850` store raw — works only because router uppercases (`soar.py:294,359,375`). Fix `.upper()` at store (3 lines).
22. Only `SIEM+TELEGRAM` registered by default (`soar.py:27-38`); slack/email/webhook → `no configuration` until manual POST (`:242`). Telegram `validate()` missing (`notifications.py:56-69` checks other 3 only). Add env defaults + 3-line validator.
23. No IOC auto-block: `grep IOC|threat|soar` in soar = 0; only `incident.artifacts[target_host|host]` (`engine.py:745-755`). Push high-confidence feed IP → SOAR `/trigger` in `scheduler.py:23-32`.
24. No STIX/TAXII (`grep stix|taxii` = 0; `feeds/` = base,otx,urlhaus,feodo,threatfox,scheduler). Add `GET /api/threat-feed/stix` export via `stix2`.
25. No retro-IOC sweep (`grep retro|sweep` = 0; `opensearch_client.py` only store `:63`/point-search `:72`). Add scheduler: new IOCs → `POST /api/logs/hunt` batch → create incident + Redis `swept:ioc:*` guard.

## E. UI orphaned + unwired (frontend)
26. 4 pages orphaned (no route in `App.tsx:58-66`, no nav in `Layout.tsx:6-15`): `Flow.tsx, Analytics.tsx, ThreatFeed.tsx, SigmaConverter.tsx`. Route or delete.
27. Saved hunts `localStorage`-only (`Hunt.tsx:39-41,196-219`), no API. Add `POST /api/incidents/hunt/saved` or document single-analyst.
28. No agent config editor (`Agents.tsx:268-393` only register/list/heartbeat/mark-online/rotate/revoke). Backend already serves config — add poll-interval/sources/YARA/CIS editor.
29. No SLA UI (`grep sla|escalat pages/` = 0) though backend exists (`service.py:19-49,76-94`, `incidents.py:477-481 GET /sla/summary`). Render `sla_priority/sla_breached` chip.
30. No Compliance/Users pages: `api.ts:461-463 getComplianceReport()` never called; no `Compliance.tsx`, no `Users.tsx` (users env-only `identity config.py:22-32`). Wire existing API to table + CSV/PDF like `Incidents.tsx:834`.
31. No compliance PDF/CSV + no backup UI though `reportGenerator.ts:5-69,71-248` + archiver `api.py:52-121` exist.

## F. Data + alerts
32. Backup `api.py:17-22` CORS `*`, no auth middleware. Add auth.
33. Restore returns `{status,target}` only (`api.py:95`), no count/checksum/staging verify. Return `restored_count` + verify query.
34. Compliance packs keyword-only (`packs.py:1-61`), no ISO27001/CIS (`grep ISO|CIS` = 0 there), no SOAR/frontend wiring. Extend + attach evidence.
35. Prometheus `alerts.yml`: has ServiceDown/Latency/ErrorRate/Traffic/OpenSearch-absent (`:5,14,23,32,50,59`) but missing queue-backlog (Redis `engine.py:68-71`, agent `Queue(10000)`), OpenSearch-red (`cluster_health_status red`), SLA-burn. Add 3 rules (~10 lines).

## DONE 2026-10-16 (verified offline: py_compile clean, identity-auth 15 passed, soar 45 passed, agent 16 passed, 3-log normalizer probe)
- [x] 6. `raw/vscode` + `raw/ci` — `normalizers/vscode_ci.py` (VSCodeNormalizer secret-escalates to HIGH, CINormalizer fail→MEDIUM) + `factory.py` registry. Probe: vscode secret→HIGH/vscode, ci fail→MEDIUM/ci.
- [x] 7. journald dispatch — `agent.py main` now starts `_read_journald(args.journald_units)` for `--mode journald`.
- [x] 8. PreFilter wired (import-only, low noise) — `_should_forward()` fail-open singleton (empty config → forward all); applied in `_tail_file`, `_read_journald`, wevtutil reader. Respects `config.yaml` allow/block/whitelist when present.
- [x] 21. Version-key case — `_record/create/update/get` all `.upper()` normalized in `soar/engine.py`.
- [x] 22. Telegram validate — `notifications.py validate()` now requires `bot_token` + `chat_id`.
- [x] 15. Login lockout — `auth.py` in-memory `(ip,user)` counter: 1–4 → 401, 5th → 429 + `Retry-After: 300`; gateway `auth_limit 5r/s` still edge-throttles.
- [x] 16b. Login field guards — `Field(min_length=1, max_length=128/256)` (empty → 422, existing test green).
- [x] 19. Logout denylist — `jwt.py` now mints `jti`, `revoke_jti/is_jti_revoked()` in-memory; `middleware.py` + `/validate` reject revoked; `POST /logout` revokes Bearer jti + clears cookie.
- [x] PyPI — `services/agent/pyproject.toml` + `version.py` + `README.md` (`chael-agent=agent:main`, flat py-modules).

## SKIPPED (>40MB — documented for when you have data/bandwidth)
- GeoLite2-City.mmdb (~70MB): `geoip.enabled=false` in `config.yaml:205-209` — left off. Enable later: download once to `/data/GeoLite2-City.mmdb`, set `enabled:true`, rebuild incident-mgmt.
- OpenSearch ML models / ml-analytics embeddings (100s MB): not pulled. `ml-analytics-service` stays heuristic-only until you opt in.
- Full Sigma community bulk fetch + YARA rule blobs: `deploy-bulk` stays dry_run-only; no bulk rule download done (keeps noise low per your `only import logs` rule).
- Docker base layers (opensearch:2.12 ~1GB, python pip trees): zero pulls — deferred to cool-box rebuild.
- No `pip install` of heavy extras (`torch`, `yara` corpora, `docker` images) — agent `requirements` unchanged; `[all]` extras stay opt-in.

## Rating after this batch (honest, code-verified)
- Was: 7.5/10 (2026-09-03 breakdown) | capability ~8/10, hardness ~6/10 (ROADMAP).
- Now: **7.9/10** | capability ~8.2/10, hardness ~6.8/10.
- Moves: Auth 3→6 (lockout+denylist+jti, still no MFA/refresh) · Log Collection 8→8.5 (vscode/ci + journald live + prefilter wire) · SOAR 5→6 (versioning sound, telegram validated; still no IOC auto-block/retro-sweep) · API/Integration 6→7 (PyPI-ready). Detection, HA, compliance, MFA unchanged — those are the next ceiling.

## Remains: rebuild when live (nothing else code-side)
```powershell
docker compose up -d
docker buildx build --load --allow network.host --network host -f services/identity-service/Dockerfile -t chael-identity-service services/identity-service
docker buildx build --load --allow network.host --network host -f services/log-ingestion-service/Dockerfile -t chael-log-ingestion-service services/log-ingestion-service
docker buildx build --load --allow network.host --network host -f services/soar-service/Dockerfile -t chael-soar-service services/soar-service
docker compose up -d --no-build --force-recreate identity-service log-ingestion-service soar-service
```
Plus perf-pass images from STATE.md (incident-mgmt + ai-assistant + frontend) when cool. Then: login lockout drill (5 bad → 429) → logout→validate revoked → `raw/vscode` + `raw/ci` ingest → journald agent mode → version/rollback round-trip.
