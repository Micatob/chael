# Chael SIEM — Threat Hunting Roadmap (deferred)

Built already: one-click hunt packs + incident-filter packs (`Hunt.tsx` `HUNT_PACKS`),
AI Copilot "Run this query" loop (`AICopilot.tsx` → `POST /api/logs/hunt`),
and hunt-hits → incident creation on both pages.

## 3. Retro-IOC sweep (new IOCs vs historical logs) — DEFERRED

**Problem:** Threat feeds (`threat-feed` service: ThreatFox, URLhaus, Feodo, OTX)
only match *future* logs. An IOC learned today never gets checked against the
last 7–30 days, so dwell time goes unnoticed.

**Design:**
- On each feed poll cycle, collect new IOC values (IPs, domains, hashes).
- Fan out `POST /api/logs/hunt` queries per IOC (batch 20, `size: 20`) against
  `chaelsiem-logs-*` over the retention window.
- On hits: `POST /api/incidents/create` with
  `artifacts: {hunt_pack: 'retro-ioc', ioc, feed}` + risk 75, then notify via
  existing SOAR `DATA_EXFILTRATION`/`C2_COMMUNICATION` routing.
- Guardrails: reuse `AlertFatigueManager` (cooldown per IOC, cap sweeps/hour);
  skip RFC1918 values; cache swept IOCs in Redis (`swept:ioc:<value>`, TTL 24h)
  so re-polls don't re-fire.

**Effort:** medium — one scheduler module in `threat-feed`, no schema changes.

## 4. Server-side saved hunts (shared across analysts) — DEFERRED

**Problem:** Saved hunts live in `localStorage` (`chael-saved-hunts`): per-browser,
unshared, unaudited, lost on cache clear.

**Design:**
- New OpenSearch index `chaelsiem-saved-hunts`:
  `{hunt_id, name, kind: logs|incidents, dsl|filters, technique, author,
  created_at, updated_at, run_count}`.
- Endpoints on log-ingestion (logs-kind) or incident-management
  (incidents-kind) — recommend one home: `incident-management-service`:
  `GET/POST/DELETE /api/incidents/hunts`, `POST /api/incidents/hunts/{id}/run`.
- `Hunt.tsx`: replace `localStorage` block with API calls; show author +
  run count; ADMIN-only delete of others' hunts.
- Migrate: on first load, push any `localStorage` hunts to the API once,
  then clear the key.

**Effort:** medium — one index + CRUD router + Hunt page swap.
