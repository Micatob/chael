"""
SOAR (Security Orchestration, Automation, and Response) Engine.
Executes automated actions based on incident risk scores and playbooks.
Dispatches notifications for each executed action through registered channels.
"""
import json
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
import uuid

from config import settings
from soar.actions import FirewallBlocker, HostIsolator
from soar.notifications import (
    NotificationService,
    NotificationPriority,
    NotificationChannel,
    NotificationRequest,
    NotificationResult,
)

logger = logging.getLogger(__name__)


class SOARAction:
    """Represents a single automated action within a SOAR playbook."""

    def __init__(self, name: str, params: Dict[str, Any]):
        self.action_id = str(uuid.uuid4())
        self.name = name
        self.params = params
        self.status = "PENDING"
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "name": self.name,
            "params": self.params,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SOARAction":
        action = cls(data.get("name", ""), data.get("params", {}) or {})
        action.action_id = data.get("action_id", action.action_id)
        action.status = data.get("status", "PENDING")
        return action


class SOAREngine:
    """
    Security Orchestration, Automation, and Response (SOAR) engine.
    Executes automated actions based on incident risk scores and playbooks.
    Dispatches notifications for each executed action through registered channels.
    """

    def __init__(self, notification_service: NotificationService = None, redis_client=None):
        self.firewall = FirewallBlocker(backend_name=settings.FIREWALL_BACKEND)
        self.isolator = HostIsolator(
            backend_name=settings.HOST_ISOLATION_BACKEND,
            edr_provider=settings.EDR_PROVIDER if settings.EDR_PROVIDER else None,
        )
        # Durable state: approval queue + agent tasks live in Redis so a
        # restart never drops a pending containment. Falls back to memory.
        self._redis = redis_client if redis_client is not None else self._connect_redis()
        self._pending_key = "chael:soar:pending"
        self._tasks_key = "chael:soar:agent_tasks"
        self._playbooks_key = "chael:soar:custom_playbooks"
        self._versions_key = "chael:soar:playbook_versions"
        # Playbook definitions: name → list of action definitions
        self.playbooks = {
            "BRUTE_FORCE": [
                {"action": "block_ip", "params": {"duration_minutes": 60}},
                {"action": "notify_admin", "params": {"channel": "slack"}},
                {"action": "audit_log", "params": {"category": "automated_response"}},
            ],
            "CRITICAL": [
                {"action": "isolate_host", "params": {"duration_minutes": 120}},
                {"action": "block_ip", "params": {"duration_minutes": 0}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "high"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "audit_log", "params": {"category": "critical_response"}},
            ],
            "REPEATED_ERRORS": [
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "audit_log", "params": {"category": "repeated_errors"}},
            ],
            "MALWARE_DETECTED": [
                {"action": "isolate_host", "params": {"duration_minutes": 0}},
                {"action": "block_ip", "params": {"duration_minutes": 0}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "critical"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "notify_admin", "params": {"channel": "telegram"}},
                {"action": "audit_log", "params": {"category": "malware_response"}},
            ],
            "PRIVILEGE_ESCALATION": [
                {"action": "block_ip", "params": {"duration_minutes": 120}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "high"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "audit_log", "params": {"category": "privilege_escalation_response"}},
            ],
            "DATA_EXFILTRATION": [
                {"action": "isolate_host", "params": {"duration_minutes": 0}},
                {"action": "block_ip", "params": {"duration_minutes": 0}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "critical"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "notify_admin", "params": {"channel": "telegram"}},
                {"action": "audit_log", "params": {"category": "exfiltration_response"}},
            ],
            "PORT_SCAN": [
                {"action": "block_ip", "params": {"duration_minutes": 30}},
                {"action": "notify_admin", "params": {"channel": "slack"}},
                {"action": "audit_log", "params": {"category": "scan_response"}},
            ],
            "ACCOUNT_LOCKOUT": [
                {"action": "notify_admin", "params": {"channel": "slack"}},
                {"action": "audit_log", "params": {"category": "lockout_response"}},
            ],
            "SUSPICIOUS_POWERSHELL": [
                {"action": "block_ip", "params": {"duration_minutes": 60}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "high"}},
                {"action": "audit_log", "params": {"category": "powershell_response"}},
            ],
            "DEFAULT": [
                {"action": "log_incident", "params": {}},
                {"action": "audit_log", "params": {"category": "incident_logged"}},
            ],
            "KERBEROS_ATTACK": [
                {"action": "isolate_host", "params": {"duration_minutes": 120}},
                {"action": "block_ip", "params": {"duration_minutes": 120}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "critical"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "audit_log", "params": {"category": "kerberos_response"}},
            ],
            "LATERAL_MOVEMENT": [
                {"action": "isolate_host", "params": {"duration_minutes": 120}},
                {"action": "block_ip", "params": {"duration_minutes": 120}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "critical"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "audit_log", "params": {"category": "lateral_movement_response"}},
            ],
            "ACCOUNT_COMPROMISE": [
                {"action": "block_ip", "params": {"duration_minutes": 120}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "high"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "audit_log", "params": {"category": "account_compromise_response"}},
            ],
            "C2_COMMUNICATION": [
                {"action": "isolate_host", "params": {"duration_minutes": 0}},
                {"action": "block_ip", "params": {"duration_minutes": 0}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "critical"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "notify_admin", "params": {"channel": "telegram"}},
                {"action": "audit_log", "params": {"category": "c2_response"}},
            ],
            "PERSISTENCE": [
                {"action": "isolate_host", "params": {"duration_minutes": 120}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "high"}},
                {"action": "notify_admin", "params": {"channel": "email"}},
                {"action": "audit_log", "params": {"category": "persistence_response"}},
            ],
            "DNS_TUNNELING": [
                {"action": "isolate_host", "params": {"duration_minutes": 120}},
                {"action": "block_ip", "params": {"duration_minutes": 0}},
                {"action": "notify_admin", "params": {"channel": "slack", "priority": "high"}},
                {"action": "audit_log", "params": {"category": "dns_tunneling_response"}},
            ],
        }
        # Track pending actions: (incident_id, action_id) → action record
        self._pending_actions: Dict[tuple, Dict] = {}
        # Notification service for dispatching alerts across channels
        self.notification_service = notification_service
        # Action execution history for audit purposes
        self._execution_history: List[Dict[str, Any]] = []
        # Custom playbooks (user-defined)
        self._custom_playbooks: Dict[str, List[Dict[str, Any]]] = {}
        # Version history per custom playbook: name → [{version, actions,
        # created_at, created_by}]. v1 is the create payload; every update
        # appends. Rollback restores a prior version as a NEW version (audit
        # trail is append-only — history is never rewritten).
        self._playbook_versions: Dict[str, List[Dict[str, Any]]] = {}
        # Agent response tasks: task_id → task record. Agents poll
        # GET /agent/tasks and report back — this is how remote endpoints
        # get contained when no EDR is configured.
        self._agent_tasks: Dict[str, Dict[str, Any]] = {}
        # Restore durable queue state (a restart must not drop containments)
        self._restore_state()

    # ── Durable state (Redis with in-memory fallback) ────────────────
    # Negative cache: a dead Redis costs one slow DNS lookup per minute,
    # not one per engine init (Windows getaddrinfo has no usable timeout).
    _redis_dead_until = 0.0

    def _connect_redis(self):
        import time as _time
        if str(getattr(settings, "SOAR_REDIS_ENABLED", "true")).lower() in ("0", "false", "no", "off"):
            return None
        if _time.time() < SOAREngine._redis_dead_until:
            return None
        try:
            import redis as redis_module
            client = redis_module.Redis(
                host=settings.REDIS_HOST, port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD or None,
                socket_timeout=3, socket_connect_timeout=3, decode_responses=True,
            )
            client.ping()
            logger.info("SOAR state: Redis connected (%s:%s)", settings.REDIS_HOST, settings.REDIS_PORT)
            return client
        except Exception as e:
            SOAREngine._redis_dead_until = _time.time() + 60
            logger.warning("SOAR state: Redis unavailable, using memory only (%s)", e)
            return None

    def _persist_state(self):
        if not self._redis:
            return
        try:
            pending = {f"{i}:{a}": json.dumps({
                "incident_id": i,
                "action": v["action"].to_dict(),
                "status": v.get("status", "PENDING"),
                "created_at": v.get("created_at", ""),
                "requires_approval": v.get("requires_approval", False),
                "requested_by": v.get("requested_by", ""),
            }, default=str) for (i, a), v in self._pending_actions.items()}
            self._redis.delete(self._pending_key)
            if pending:
                self._redis.hset(self._pending_key, mapping=pending)
            tasks = {tid: json.dumps(t, default=str) for tid, t in self._agent_tasks.items()}
            self._redis.delete(self._tasks_key)
            if tasks:
                self._redis.hset(self._tasks_key, mapping=tasks)
            if self._custom_playbooks:
                self._redis.hset(self._playbooks_key, mapping={
                    name: json.dumps(actions, default=str)
                    for name, actions in self._custom_playbooks.items()
                })
            if self._playbook_versions:
                self._redis.hset(self._versions_key, mapping={
                    name: json.dumps(history, default=str)
                    for name, history in self._playbook_versions.items()
                })
        except Exception as e:
            logger.warning("SOAR state persist failed: %s", e)

    def _restore_state(self):
        if not self._redis:
            return
        try:
            for field, raw in self._redis.hgetall(self._pending_key).items():
                try:
                    data = json.loads(raw)
                    incident_id, _, action_id = field.partition(":")
                    self._pending_actions[(data.get("incident_id", incident_id), data.get("action", {}).get("action_id", action_id))] = {
                        "incident_id": data.get("incident_id", incident_id),
                        "action": SOARAction.from_dict(data.get("action", {})),
                        "status": data.get("status", "PENDING"),
                        "created_at": data.get("created_at", ""),
                        "requires_approval": data.get("requires_approval", False),
                        "requested_by": data.get("requested_by", ""),
                    }
                except Exception:
                    continue
            for _, raw in self._redis.hgetall(self._tasks_key).items():
                try:
                    task = json.loads(raw)
                    if task.get("task_id"):
                        self._agent_tasks[task["task_id"]] = task
                except Exception:
                    continue
            for name, raw in self._redis.hgetall(self._playbooks_key).items():
                try:
                    if name not in self.playbooks:
                        self._custom_playbooks[name] = json.loads(raw)
                except Exception:
                    continue
            for name, raw in self._redis.hgetall(self._versions_key).items():
                try:
                    if name not in self.playbooks:
                        self._playbook_versions[name] = json.loads(raw)
                except Exception:
                    continue
            if self._pending_actions or self._agent_tasks:
                logger.info("SOAR state restored: %d pending, %d tasks",
                            len(self._pending_actions), len(self._agent_tasks))
        except Exception as e:
            logger.warning("SOAR state restore failed: %s", e)

    # High-impact actions wait for human approval instead of auto-executing.
    # isolate_host always gates; block_ip gates only when indefinite (duration 0).
    @staticmethod
    def _requires_approval(action_def: Dict[str, Any]) -> bool:
        name = action_def.get("action", "")
        params = action_def.get("params", {}) or {}
        if name == "isolate_host":
            return True
        if name == "block_ip" and int(params.get("duration_minutes", 60) or 0) == 0:
            return True
        return False

    def trigger(self, incident, requested_by: str = "system") -> List[Dict[str, Any]]:
        """
        Execute SOAR playbook based on incident.
        Low-impact actions (notify/audit/log, time-boxed blocks) auto-execute.
        High-impact actions (isolate, indefinite block) stay PENDING until a
        human approves via POST /approve — they are NOT executed here.
        requested_by is the triggering analyst (RBAC: approver must differ).

        Returns:
            List of execution results for each action performed.
        """
        actions = self._determine_playbook(incident)
        results = []

        logger.info(
            "Triggering SOAR playbook for incident %s: %d action(s) to execute",
            incident.incident_id, len(actions)
        )

        for action_def in actions:
            action = SOARAction(action_def["action"], action_def.get("params", {}))

            # High-impact: queue for approval, do not execute yet.
            if self._requires_approval(action_def):
                key = (incident.incident_id, action.action_id)
                self._pending_actions[key] = {
                    "incident_id": incident.incident_id,
                    "action": action,
                    "status": "PENDING",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "requires_approval": True,
                    "requested_by": requested_by,
                }
                results.append({
                    "action_id": action.action_id,
                    "name": action.name,
                    "status": "PENDING",
                    "incident_id": incident.incident_id,
                    "params": dict(action.params) if action.params else {},
                    "requires_approval": True,
                    "requested_by": requested_by,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                logger.info(
                    "Action '%s' queued for approval for incident %s",
                    action.name, incident.incident_id
                )
                continue

            # Low-impact: auto-execute, then mark pending entry resolved so the
            # approval queue only shows genuinely awaiting actions.
            key = (incident.incident_id, action.action_id)
            self._pending_actions[key] = {
                "incident_id": incident.incident_id,
                "action": action,
                "status": "PENDING",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "requested_by": requested_by,
            }

            # Execute the action
            result = self._execute_action(action, incident)
            results.append(result)

            # Resolved — remove from PENDING queue (audit stays in history)
            self._pending_actions[key]["status"] = result.get("status", "EXECUTED")

            # Dispatch notifications for this action
            self._dispatch_notifications(action, result, incident)

            logger.info(
                "Action '%s' completed for incident %s: status=%s",
                action.name, incident.incident_id, result["status"]
            )

        # Severe incident + known host → auto-collect a forensics triage bundle
        # from the endpoint (read-only; the agent uploads it as evidence).
        # Deduped: never two outstanding triage tasks for the same host.
        try:
            risk = getattr(incident, "risk_score", 0) or 0
            host = ((getattr(incident, "artifacts", None) or {}).get("host", "")) or ""
            if risk >= 70 and host:
                outstanding = any(
                    t.get("action") == "collect_triage"
                    and (t.get("hostname", "") or "").lower() == host.lower()
                    and t.get("status") in ("PENDING", "ACKED")
                    for t in self._agent_tasks.values()
                )
                if not outstanding:
                    triage = self.queue_agent_task(
                        "collect_triage", host, incident_id=incident.incident_id,
                        hostname=host, requested_by=requested_by)
                    results.append({
                        "action_id": triage["task_id"],
                        "name": "agent:collect_triage",
                        "status": "QUEUED",
                        "incident_id": incident.incident_id,
                        "params": {"host": host},
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
        except Exception as e:
            logger.warning("Auto-triage queue failed: %s", e)

        self._persist_state()
        return results

    def approve_action(self, incident_id: str, action_id: str, incident=None, approved_by: str = "admin") -> bool:
        """
        Approve a PENDING high-impact SOAR action and execute it once.
        Already-resolved actions are NOT re-executed (prevents double block/isolate).

        Returns:
            True if approval succeeded, False otherwise
        """
        key = (incident_id, action_id)
        if key not in self._pending_actions:
            logger.warning("Action %s not found in pending actions for %s", action_id, incident_id)
            return False

        pending = self._pending_actions[key]
        if pending.get("status") != "PENDING":
            # Already approved/rejected/executed — idempotent, no re-execution.
            logger.info("[SOAR] Action %s already %s for %s — skip re-execution",
                        action_id, pending.get("status"), incident_id)
            return True

        pending["status"] = "APPROVED"
        pending["approved_by"] = approved_by
        pending["approved_at"] = datetime.now(timezone.utc).isoformat()
        action = pending["action"]
        action.status = "APPROVED"

        logger.info("[SOAR] Action %s approved for incident %s by %s", action_id, incident_id, approved_by)

        if incident is not None:
            result = self._execute_action(action, incident, actor=approved_by)
            self._dispatch_notifications(action, result, incident, approved=True)

        self._persist_state()
        return True

    def reject_action(self, incident_id: str, action_id: str, rejected_by: str = "admin") -> bool:
        """Deny a PENDING action — it will never execute. Audit-logged."""
        key = (incident_id, action_id)
        if key not in self._pending_actions:
            logger.warning("Reject: action %s not found for %s", action_id, incident_id)
            return False
        pending = self._pending_actions[key]
        if pending.get("status") != "PENDING":
            return True
        pending["status"] = "REJECTED"
        pending["rejected_by"] = rejected_by
        pending["rejected_at"] = datetime.now(timezone.utc).isoformat()
        pending["action"].status = "REJECTED"
        self._execution_history.append({
            "action_id": action_id,
            "name": pending["action"].name,
            "status": "REJECTED",
            "incident_id": incident_id,
            "params": dict(pending["action"].params) if pending["action"].params else {},
            "rejected_by": rejected_by,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("[SOAR] Action %s rejected for incident %s by %s", action_id, incident_id, rejected_by)
        self._persist_state()
        return True

    def _determine_playbook(self, incident) -> List[Dict[str, Any]]:
        """
        Select the appropriate playbook based on incident characteristics.

        Priority:
        1. Malware detection (YARA, mimikatz, cobaltstrike, etc.)
        2. Data exfiltration indicators
        3. Privilege escalation
        4. Brute force detection
        5. Critical severity
        6. Port scanning
        7. Account lockout
        8. Suspicious PowerShell
        9. Repeated error patterns
        10. Default (log only)
        """
        desc = incident.description.lower() if incident.description else ""
        artifacts = incident.artifacts or {}
        attack_type = artifacts.get("attack_type", "") or artifacts.get("rule", "")

        if any(kw in desc for kw in ["kerberoast", "as-rep", "asrep", "golden ticket", "silver ticket", "forged ticket", "4769", "4771", "t1558"]):
            logger.info("Selected KERBEROS_ATTACK playbook for incident %s", incident.incident_id)
            return self.playbooks["KERBEROS_ATTACK"]
        elif any(kw in desc for kw in ["lateral movement", "pass-the-hash", "pass the hash", "rdp lateral", "4778", "t1021", "t1550"]):
            logger.info("Selected LATERAL_MOVEMENT playbook for incident %s", incident.incident_id)
            return self.playbooks["LATERAL_MOVEMENT"]
        elif any(kw in desc for kw in ["successful login after", "fail_then_success", "account compromise", "impossible travel"]):
            logger.info("Selected ACCOUNT_COMPROMISE playbook for incident %s", incident.incident_id)
            return self.playbooks["ACCOUNT_COMPROMISE"]
        elif any(kw in desc for kw in ["c2", "command and control", "beacon", "reverse shell", "t1071"]):
            logger.info("Selected C2_COMMUNICATION playbook for incident %s", incident.incident_id)
            return self.playbooks["C2_COMMUNICATION"]
        elif any(kw in desc for kw in ["dns tunneling", "dns tunnel", "t1071.004"]):
            logger.info("Selected DNS_TUNNELING playbook for incident %s", incident.incident_id)
            return self.playbooks["DNS_TUNNELING"]
        elif any(kw in desc for kw in ["persistence", "scheduled task", "4698", "new service", "registry run", "t1053", "t1543", "t1547"]):
            logger.info("Selected PERSISTENCE playbook for incident %s", incident.incident_id)
            return self.playbooks["PERSISTENCE"]
        elif attack_type in ("kerberoasting", "asrep_roasting", "golden_ticket_suspect", "silver_ticket_suspect", "kerberos_bruteforce"):
            logger.info("Selected KERBEROS_ATTACK playbook for incident %s", incident.incident_id)
            return self.playbooks["KERBEROS_ATTACK"]
        elif attack_type in ("lateral_movement", "pass_the_hash_suspect", "lateral_movement_rdp", "lateral_movement_smb", "multi_fail_then_success"):
            logger.info("Selected LATERAL_MOVEMENT playbook for incident %s", incident.incident_id)
            return self.playbooks["LATERAL_MOVEMENT"]
        elif attack_type in ("dns_tunneling", "dns_tunneling_suspect", "c2_beacon_suspect", "reverse_shell"):
            logger.info("Selected C2_COMMUNICATION playbook for incident %s", incident.incident_id)
            return self.playbooks["C2_COMMUNICATION"]
        elif attack_type in ("persistence_schtask", "persistence_service", "registry_persistence", "new_service"):
            logger.info("Selected PERSISTENCE playbook for incident %s", incident.incident_id)
            return self.playbooks["PERSISTENCE"]
        elif any(kw in desc for kw in ["malware", "yara", "mimikatz", "cobaltstrike", "cobalt strike", "ransomware"]):
            logger.info("Selected MALWARE_DETECTED playbook for incident %s", incident.incident_id)
            return self.playbooks["MALWARE_DETECTED"]
        elif any(kw in desc for kw in ["exfiltrat", "data leak", "data theft"]) or attack_type == "data_exfiltration":
            logger.info("Selected DATA_EXFILTRATION playbook for incident %s", incident.incident_id)
            return self.playbooks["DATA_EXFILTRATION"]
        elif any(kw in desc for kw in ["privilege escalation", "priv esc", "escalat"]) or attack_type == "privilege_escalation":
            logger.info("Selected PRIVILEGE_ESCALATION playbook for incident %s", incident.incident_id)
            return self.playbooks["PRIVILEGE_ESCALATION"]
        elif "brute force" in desc or attack_type == "brute_force":
            logger.info("Selected BRUTE_FORCE playbook for incident %s", incident.incident_id)
            return self.playbooks["BRUTE_FORCE"]
        elif "critical" in desc or attack_type == "critical":
            logger.info("Selected CRITICAL playbook for incident %s", incident.incident_id)
            return self.playbooks["CRITICAL"]
        elif any(kw in desc for kw in ["port scan", "nmap", "scanner", "network scan"]) or attack_type == "port_scan":
            logger.info("Selected PORT_SCAN playbook for incident %s", incident.incident_id)
            return self.playbooks["PORT_SCAN"]
        elif any(kw in desc for kw in ["lockout", "account locked"]) or attack_type == "account_lockout":
            logger.info("Selected ACCOUNT_LOCKOUT playbook for incident %s", incident.incident_id)
            return self.playbooks["ACCOUNT_LOCKOUT"]
        elif any(kw in desc for kw in ["powershell", "ps1", "suspicious execution"]) or attack_type == "suspicious_powershell":
            logger.info("Selected SUSPICIOUS_POWERSHELL playbook for incident %s", incident.incident_id)
            return self.playbooks["SUSPICIOUS_POWERSHELL"]
        elif "repeated" in desc or attack_type == "repeated_errors":
            logger.info("Selected REPEATED_ERRORS playbook for incident %s", incident.incident_id)
            return self.playbooks["REPEATED_ERRORS"]
        else:
            logger.info("Selected DEFAULT playbook for incident %s", incident.incident_id)
            return self.playbooks["DEFAULT"]

    def _determine_priority(self, incident) -> NotificationPriority:
        """Determine notification priority based on incident risk score."""
        score = getattr(incident, "risk_score", 0) or 0
        if score >= 90:
            return NotificationPriority.CRITICAL
        elif score >= 70:
            return NotificationPriority.HIGH
        elif score >= 40:
            return NotificationPriority.MEDIUM
        return NotificationPriority.LOW

    def _dispatch_notifications(
        self,
        action: SOARAction,
        action_result: Dict[str, Any],
        incident,
        approved: bool = False,
    ) -> List[NotificationResult]:
        """
        Dispatch notifications for a completed SOAR action across all
        registered channels.

        Notification strategy:
        - SIEM (OpenSearch): Always sent for every action (audit trail)
        - Webhook: Sent for blocking and isolation actions
        - Slack: Sent for notify_admin actions targeting Slack
        - Email: Sent for notify_admin actions targeting email
        """
        if not self.notification_service:
            logger.debug("No notification service configured, skipping notifications")
            return []

        status = action_result.get("status", "unknown")
        priority = self._determine_priority(incident)

        # Build context for notifications
        if approved:
            title = f"Manually Approved Action: {action.name}"
        else:
            title = f"Action Executed: {action.name}"

        # Sanitize params - remove sensitive data from notifications
        safe_params = {
            k: v
            for k, v in (action.params or {}).items()
            if k not in ("password", "token", "secret", "api_key")
        }

        message = (
            f"SOAR automated action '{action.name}' "
            f"{'approved and executed' if approved else 'executed'} "
            f"for incident {incident.incident_id}.\n\n"
            f"Status: {status}\n"
            f"Action ID: {action.action_id}\n"
            f"Parameters: {json.dumps(safe_params, default=str)}\n"
            f"Description: {incident.description or 'N/A'}\n"
            f"Risk Score: {incident.risk_score}"
        )

        metadata = {
            "action_id": action.action_id,
            "action_name": action.name,
            "status": status,
            "approved": approved,
            "risk_score": incident.risk_score,
            "artifacts": json.dumps(incident.artifacts, default=str),
        }

        results = []

        # 1. Always send to SIEM for audit trail
        try:
            siem_req = NotificationRequest(
                channel=NotificationChannel.SIEM,
                title=title,
                message=message,
                priority=priority,
                incident_id=incident.incident_id,
                action_name=action.name,
                action_status=status,
                metadata=metadata,
            )
            result = self.notification_service.send_notification(siem_req)
            results.append(result)
            if not result.success:
                logger.warning(
                    f"SIEM notification failed for incident {incident.incident_id}: {result.error}"
                )
        except Exception as e:
            logger.error("SIEM notification error: %s", e, exc_info=True)

        # 2. Dispatch based on action type
        artifacts = incident.artifacts or {}

        if action.name == "block_ip":
            try:
                webhook_req = NotificationRequest(
                    channel=NotificationChannel.WEBHOOK,
                    title=title,
                    message=message,
                    priority=priority,
                    incident_id=incident.incident_id,
                    action_name=action.name,
                    action_status=status,
                    metadata={
                        **metadata,
                        "target_ip": artifacts.get("target_host", "unknown"),
                    },
                )
                result = self.notification_service.send_notification(webhook_req)
                results.append(result)
            except Exception as e:
                logger.error("Webhook notification error for block_ip: %s", e, exc_info=True)

        elif action.name == "isolate_host":
            try:
                webhook_req = NotificationRequest(
                    channel=NotificationChannel.WEBHOOK,
                    title=title,
                    message=message,
                    priority=NotificationPriority.CRITICAL,
                    incident_id=incident.incident_id,
                    action_name=action.name,
                    action_status=status,
                    metadata={
                        **metadata,
                        "target_host": artifacts.get("host", "unknown"),
                    },
                )
                result = self.notification_service.send_notification(webhook_req)
                results.append(result)
            except Exception as e:
                logger.error("Webhook notification error for isolate_host: %s", e, exc_info=True)

        elif action.name == "notify_admin":
            channel = action.params.get("channel", "slack")
            try:
                if channel == "slack":
                    slack_req = NotificationRequest(
                        channel=NotificationChannel.SLACK,
                        title=title,
                        message=message,
                        priority=priority,
                        incident_id=incident.incident_id,
                        action_name=action.name,
                        action_status=status,
                        metadata=metadata,
                    )
                    result = self.notification_service.send_notification(slack_req)
                    results.append(result)
                elif channel == "telegram":
                    telegram_req = NotificationRequest(
                        channel=NotificationChannel.TELEGRAM,
                        title=title,
                        message=message,
                        priority=priority,
                        incident_id=incident.incident_id,
                        action_name=action.name,
                        action_status=status,
                        metadata=metadata,
                    )
                    result = self.notification_service.send_notification(telegram_req)
                    results.append(result)
                elif channel == "email":
                    email_req = NotificationRequest(
                        channel=NotificationChannel.EMAIL,
                        title=title,
                        message=message,
                        priority=priority,
                        incident_id=incident.incident_id,
                        action_name=action.name,
                        action_status=status,
                        metadata=metadata,
                    )
                    result = self.notification_service.send_notification(email_req)
                    results.append(result)
            except Exception as e:
                logger.error("Notification error for notify_admin (%s): %s", channel, e, exc_info=True)

        elif action.name in ("log_incident", "audit_log"):
            # SIEM already captured above, no additional channels needed
            pass

        return results

    def _execute_action(self, action, incident, actor: str = "system") -> Dict[str, Any]:
        """
        Execute a SOAR action using the appropriate integration backend.
        Supports real firewall blocking (iptables, netsh, ufw) and host isolation
        (Windows Firewall, iptables, EDR APIs), with automatic fallback to
        simulated execution when backends are unavailable.
        """
        try:
            if action.name == "block_ip":
                ip = incident.artifacts.get("target_host", "unknown")
                duration = action.params.get("duration_minutes", 60)
                result = self.firewall.block_ip(ip, duration)
                action.status = "EXECUTED" if result.get("success") else "FAILED"

            elif action.name == "isolate_host":
                host = incident.artifacts.get("host", "unknown")
                duration = action.params.get("duration_minutes", 120)
                result = self.isolator.isolate(host, duration)
                action.status = "EXECUTED" if result.get("success") else "FAILED"

            elif action.name == "unisolate_host":
                host = incident.artifacts.get("host", action.params.get("host", "unknown"))
                result = self.isolator.unisolate(host)
                action.status = "EXECUTED" if result.get("success") else "FAILED"

            elif action.name == "unblock_ip":
                ip = incident.artifacts.get("target_host", action.params.get("ip", "unknown"))
                result = self.firewall.unblock_ip(ip)
                action.status = "EXECUTED" if result.get("success") else "FAILED"

            elif action.name == "notify_admin":
                channel = action.params.get("channel", "slack")
                priority = action.params.get("priority", "normal")
                logger.info("Notifying admin via %s (priority: %s) - Incident: %s", channel, priority, incident.incident_id)
                action.status = "EXECUTED"

            elif action.name == "log_incident":
                logger.info("Logging incident %s to audit trail", incident.incident_id)
                action.status = "EXECUTED"

            elif action.name == "audit_log":
                category = action.params.get("category", "general")
                logger.info("Writing audit log entry (category: %s) for incident %s", category, incident.incident_id)
                action.status = "EXECUTED"

            else:
                logger.warning("Unknown action: %s", action.name)
                action.status = "FAILED"

        except Exception as e:
            logger.error("Action %s failed: %s", action.name, e)
            action.status = "FAILED"

        result = {
            "action_id": action.action_id,
            "name": action.name,
            "status": action.status,
            "incident_id": incident.incident_id,
            "params": dict(action.params) if action.params else {},
            "actor": actor,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Track in execution history
        self._execution_history.append(result)

        return result

    def get_pending_actions(self, incident_id: str = None) -> List[Dict[str, Any]]:
        """Retrieve pending actions, optionally filtered by incident."""
        if incident_id:
            return [
                v
                for k, v in self._pending_actions.items()
                if k[0] == incident_id and v["status"] == "PENDING"
            ]
        return [v for v in self._pending_actions.values() if v["status"] == "PENDING"]

    def get_execution_history(self) -> List[Dict[str, Any]]:
        """Return the full action execution history."""
        return self._execution_history.copy()

    def get_playbooks(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return all available playbooks (built-in + custom)."""
        all_playbooks = dict(self.playbooks)
        all_playbooks.update(self._custom_playbooks)
        return all_playbooks

    def _record_playbook_version(self, name: str, actions: List[Dict[str, Any]], created_by: str = "admin") -> int:
        history = self._playbook_versions.setdefault(name, [])
        version = (history[-1]["version"] + 1) if history else 1
        history.append({
            "version": version,
            "actions": [dict(a) for a in actions],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": created_by,
        })
        if len(history) > 20:
            del history[:len(history) - 20]
        return version

    def create_custom_playbook(self, name: str, actions: List[Dict[str, Any]], created_by: str = "admin") -> bool:
        """Create a custom playbook with the given actions (records v1)."""
        if name in self.playbooks:
            return False  # Cannot override built-in playbooks
        if name in self._custom_playbooks:
            return False  # Already exists — use update (which versions)
        self._custom_playbooks[name] = actions
        self._record_playbook_version(name, actions, created_by)
        logger.info("Created custom playbook: %s with %d actions", name, len(actions))
        self._persist_state()
        return True

    def update_custom_playbook(self, name: str, actions: List[Dict[str, Any]], created_by: str = "admin") -> bool:
        """Update an existing custom playbook (appends a new version)."""
        if name in self.playbooks:
            return False  # Cannot modify built-in playbooks
        if name not in self._custom_playbooks:
            return False
        self._custom_playbooks[name] = actions
        self._record_playbook_version(name, actions, created_by)
        logger.info("Updated custom playbook: %s", name)
        self._persist_state()
        return True

    def get_playbook_versions(self, name: str) -> List[Dict[str, Any]]:
        """Version history for a custom playbook (oldest → newest)."""
        return [dict(v) for v in self._playbook_versions.get(name.upper(), [])]

    def rollback_playbook(self, name: str, version: int, created_by: str = "admin") -> bool:
        """Restore a prior version as a NEW version (history append-only)."""
        name = (name or "").upper()
        if name in self.playbooks or name not in self._custom_playbooks:
            return False
        for v in self._playbook_versions.get(name, []):
            if v.get("version") == int(version):
                self._custom_playbooks[name] = [dict(a) for a in v["actions"]]
                self._record_playbook_version(name, self._custom_playbooks[name], created_by)
                logger.info("Rolled back playbook %s to v%s (as new version)", name, version)
                self._persist_state()
                return True
        return False

    def dry_run_playbook(self, incident: Dict[str, Any], playbook: str = "",
                         actions: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Evaluate a playbook against a canary incident WITHOUT executing
        anything: no firewall/EDR calls, no notifications, no queue writes.
        Returns the resolved action list with approval gating + a verdict."""
        from models.schema import Incident as _Incident
        try:
            inc = _Incident(**incident)
        except Exception as e:
            raise ValueError(f"Invalid incident payload: {e}")
        if actions:
            resolved = [dict(a) for a in actions]
            source = "adhoc"
        else:
            pname = (playbook or "").upper()
            if pname:
                resolved = [dict(a) for a in self.get_playbook(pname)]
                if not resolved:
                    raise ValueError(f"Unknown playbook '{playbook}'")
                source = pname
            else:
                resolved = self._determine_playbook(inc)
                source = "auto-selected"
        plan = []
        gated = 0
        for a in resolved:
            gate = self._requires_approval(a)
            gated += 1 if gate else 0
            plan.append({
                "action": a.get("action", ""),
                "params": a.get("params", {}) or {},
                "requires_approval": gate,
                "would_execute": "after-approval" if gate else "immediately",
            })
        return {
            "playbook": source,
            "incident_id": inc.incident_id,
            "actions_total": len(plan),
            "gated_actions": gated,
            "auto_actions": len(plan) - gated,
            "plan": plan,
            "verdict": "safe-to-test" if not gated else "needs-approver",
        }

    def delete_custom_playbook(self, name: str) -> bool:
        """Delete a custom playbook."""
        if name in self.playbooks:
            return False  # Cannot delete built-in playbooks
        if name not in self._custom_playbooks:
            return False
        del self._custom_playbooks[name]
        logger.info("Deleted custom playbook: %s", name)
        return True

    def get_playbook(self, name: str) -> List[Dict[str, Any]]:
        """Get a specific playbook by name."""
        if name in self.playbooks:
            return self.playbooks[name]
        return self._custom_playbooks.get(name, [])

    # ── Agent response tasks (remote contain / recover) ──────────────
    # isolate/unisolate/block/unblock = containment; kill_process /
    # quarantine_file / delete_persistence = eradication; collect_triage =
    # forensics (auto-queued on severe incidents, read-only, needs no approval).
    VALID_AGENT_ACTIONS = ("isolate", "unisolate", "block", "unblock",
                           "kill_process", "quarantine_file",
                           "delete_persistence", "collect_triage",
                           "collect_memory", "collect_disk_image")

    def queue_agent_task(self, action: str, target: str, incident_id: str = "",
                         agent_id: str = "", hostname: str = "",
                         requested_by: str = "admin",
                         duration_minutes: int = 0) -> Dict[str, Any]:
        """Queue a containment task for an endpoint agent to pull."""
        action = (action or "").strip().lower()
        if action not in self.VALID_AGENT_ACTIONS:
            raise ValueError(f"Unknown agent action '{action}'. Use: {list(self.VALID_AGENT_ACTIONS)}")
        if not (target or "").strip():
            raise ValueError("Missing 'target' (host or IP)")
        task_id = str(uuid.uuid4())
        task = {
            "task_id": task_id,
            "action": action,
            "target": target.strip(),
            "incident_id": incident_id or "",
            "agent_id": agent_id or "",
            "hostname": hostname or "",
            "duration_minutes": int(duration_minutes or 0),
            "status": "PENDING",
            "requested_by": requested_by,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "acked_at": None,
            "result": None,
        }
        self._agent_tasks[task_id] = task
        logger.info("[SOAR] Agent task queued: %s %s for %s (incident %s)",
                    action, target, agent_id or hostname or "any-agent", incident_id)
        self._persist_state()
        return task

    def get_agent_tasks(self, agent_id: str = "", hostname: str = "") -> List[Dict[str, Any]]:
        """Tasks an agent should execute. Untargeted tasks go to any agent;
        targeted ones only match their agent_id/hostname."""
        out = []
        for task in self._agent_tasks.values():
            if task.get("status") != "PENDING":
                continue
            ta, th = task.get("agent_id", ""), task.get("hostname", "")
            if ta and agent_id and ta != agent_id:
                continue
            if th and hostname and th.lower() != hostname.lower():
                continue
            if (ta or th) and not (agent_id or hostname):
                continue
            out.append(task)
        return out

    def ack_agent_task(self, task_id: str, agent_id: str = "") -> bool:
        task = self._agent_tasks.get(task_id)
        if not task or task.get("status") != "PENDING":
            return False
        task["status"] = "ACKED"
        task["acked_at"] = datetime.now(timezone.utc).isoformat()
        if agent_id:
            task["agent_id"] = task.get("agent_id") or agent_id
        self._persist_state()
        return True

    def report_agent_task(self, task_id: str, success: bool, detail: str = "",
                          agent_id: str = "") -> bool:
        task = self._agent_tasks.get(task_id)
        if not task:
            return False
        task["status"] = "DONE" if success else "FAILED"
        task["result"] = {"success": bool(success), "detail": detail or "",
                          "reported_at": datetime.now(timezone.utc).isoformat(),
                          "agent_id": agent_id or task.get("agent_id", "")}
        self._execution_history.append({
            "action_id": task_id,
            "name": f"agent:{task['action']}",
            "status": "EXECUTED" if success else "FAILED",
            "incident_id": task.get("incident_id", ""),
            "params": {"target": task.get("target", ""), "agent_id": task.get("agent_id", "")},
            "actor": task.get("agent_id", "agent"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("[SOAR] Agent task %s %s by %s: %s",
                    task_id, task["status"], agent_id, (detail or "")[:120])
        self._persist_state()
        return True