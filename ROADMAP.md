# Chael SIEM — Roadmap

Capability: ~8/10. Enterprise-hardness: ~6/10. This file lists what moves each,
ranked by impact per effort. Items land here only after verification — see
`HUNTING_ROADMAP.md` for the threat-hunting track.

## Recently shipped (live, verified)
- Evidence locker: hash-sealed seizure, custody transfers, re-hash verify, legal hold
  that blocks close + purge.
- Remote containment without EDR: agent task-pull (isolate/unisolate/block/unblock),
  approval-gated, verified PENDING → DONE.
- Real eradication dispatch: kill_process / quarantine_file / delete_persistence /
  collect_triage as agent tasks (nothing simulated; failures are loud).
- Triage bundles: host snapshot → zip → SHA-256 → uploaded as evidence.
- RBAC split: ANALYST triggers, ADMIN/APPROVER approves, no self-approval (403 live).
- Durable SOAR queues in Redis (approvals + tasks survive restarts).
- Log forensics: sub-threshold/internal telemetry retained + tagged, per-log SHA-256
  seal + `/verify`, JSON/CEF normalizers, PowerShell `-EncodedCommand` decode.
- Sigma bulk deploy (`deploy-bulk`, dry_run review) + daily/weekly SMTP digests.
- One-command Windows deploy (`deploy.ps1`), tamper-evident audit log.

## Next (ranked)
1. **Live endpoint proof** — needs an agent shipping first: remote isolate drill,
   triage upload from a real host, `total_logs > 0` sustained. (Validates 80% of the above.)
2. **IOC auto-block** — high-confidence threat-feed IOCs auto-queued as firewall blocks
   through the existing approval gate.
3. **SLA escalation alerts** — P1/P2 breach timers into notification channels (tiers configured).
4. **Playbook dry-run + versioning** — test a playbook against a canary incident before live use.
5. **Full disk/memory imaging** — Phase 2 behind the triage bundle (agent acquisition,
   chunked upload, WORM store).
6. **MFA (TOTP) for logins** — SSO deferred behind it; needs an IdP decision first.
7. **HA story** — `docker-compose.cluster.yml` exists; needs a documented, tested 3-node
   procedure + backlog-replay proof after outages.
8. **Compliance depth** — control evidence beyond keyword mapping (collect config snapshots,
   access reviews, export packs auditors accept).
9. **Detection depth** — Suricata/Zeek parsers, longer-window correlations, curated Sigma
   pack loaded + tuned (converter supports it; needs FP tuning per environment).
10. **Agent config editor** in the Agents page (backend already serves per-agent config).
11. **STIX/TAXII ingest** for the threat feed.
12. **Backup/restore drills** — scheduled restore-to-staging proof, not just backup jobs.

## Non-goals
- Replacing EDR/XDR products — Chael orchestrates endpoints and EDR APIs, it is not one.
- Cloud-scale multi-tenancy — single-org, self-hosted SOC is the target.
