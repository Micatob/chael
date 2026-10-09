"""
SOAR (Security Orchestration, Automation, and Response) Engine.
Embedded in the log-ingestion-service to process correlated incidents
and execute automated response playbooks with notification dispatch.
"""
import json
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone
import uuid

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


class SOAREngine:
    """
    Security Orchestration, Automation, and Response (SOAR) engine.
    Executes automated actions based on incident risk scores and playbooks.
    Dispatches notifications for each executed action through registered channels.
    """

    def __init__(self, notification_service: NotificationService = None):
        # Playbook definitions: name -> list of action definitions
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
            "DEFAULT": [
                {"action": "log_incident", "params": {}},
                {"action": "audit_log", "params": {"category": "incident_logged"}},
            ],
        }
        # Track pending actions: (incident_id, action_id) -> action record
        self._pending_actions: Dict[tuple, Dict] = {}
        # Notification service for dispatching alerts across channels
        self.notification_service = notification_service
        # Action execution history for audit purposes
        self._execution_history: List[Dict[str, Any]] = []

    def _get_incident_id(self, incident) -> str:
        if isinstance(incident, dict):
            return incident.get("incident_id", "unknown")
        return getattr(incident, "incident_id", "unknown")

    def trigger(self, incident) -> List[Dict[str, Any]]:
        """
        Execute SOAR playbook based on incident.
        Selects the appropriate playbook, creates actions, executes them,
        and dispatches notifications for each completed action.

        Returns:
            List of execution results for each action performed.
        """
        incident_id = self._get_incident_id(incident)
        actions = self._determine_playbook(incident)
        results = []

        logger.info(
            "Triggering SOAR playbook for incident %s: %d action(s) to execute",
            incident_id,
            len(actions),
        )

        for action_def in actions:
            action = SOARAction(action_def["action"], action_def.get("params", {}))

            key = (incident_id, action.action_id)
            self._pending_actions[key] = {
                "incident_id": incident_id,
                "action": action,
                "status": "PENDING",
            }

            # Execute the action
            result = self._execute_action(action, incident)
            results.append(result)

            # Dispatch notifications for this action
            self._dispatch_notifications(action, result, incident)

            logger.info(
                "Action '%s' completed for incident %s: status=%s",
                action.name,
                incident_id,
                result["status"],
            )

        return results

    def approve_action(self, incident_id: str, action_id: str, incident=None) -> bool:
        """
        Manually approve a pending SOAR action.
        Re-executes the action if an incident object is provided, and dispatches
        approval notifications.
        """
        key = (incident_id, action_id)
        if key not in self._pending_actions:
            logger.warning("Action %s not found in pending actions for %s", action_id, incident_id)
            return False

        pending = self._pending_actions[key]
        pending["status"] = "APPROVED"
        action = pending["action"]
        action.status = "APPROVED"

        logger.info("[SOAR] Action %s approved for incident %s", action_id, incident_id)

        if incident:
            result = self._execute_action(action, incident)
            self._dispatch_notifications(action, result, incident, approved=True)

        return True

    def _determine_playbook(self, incident) -> List[Dict[str, Any]]:
        """
        Select the appropriate playbook based on incident characteristics.
        """
        desc = incident.description.lower() if incident.description else ""
        artifacts = incident.artifacts or {}

        if "brute force" in desc or artifacts.get("attack_type") == "brute_force":
            logger.info("Selected BRUTE_FORCE playbook for incident %s", incident.incident_id)
            return self.playbooks["BRUTE_FORCE"]
        elif "critical" in desc:
            logger.info("Selected CRITICAL playbook for incident %s", incident.incident_id)
            return self.playbooks["CRITICAL"]
        elif "repeated" in desc:
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
        """
        if not self.notification_service:
            logger.debug("No notification service configured, skipping notifications")
            return []

        status = action_result.get("status", "unknown")
        priority = self._determine_priority(incident)

        # Build context for notifications
        if approved:
            title = "Manually Approved Action: " + action.name
        else:
            title = "Action Executed: " + action.name

        # Sanitize params - remove sensitive data from notifications
        safe_params = {
            k: v
            for k, v in (action.params or {}).items()
            if k not in ("password", "token", "secret", "api_key")
        }

        message = (
            "SOAR automated action '" + action.name + "' "
            + ("approved and executed" if approved else "executed")
            + " for incident " + incident.incident_id + ".\n\n"
            "Status: " + status + "\n"
            "Action ID: " + action.action_id + "\n"
            "Parameters: " + json.dumps(safe_params, default=str) + "\n"
            "Description: " + (incident.description or "N/A") + "\n"
            "Risk Score: " + str(incident.risk_score)
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
                    "SIEM notification failed for incident %s: %s",
                    incident.incident_id,
                    result.error,
                )
        except Exception as e:
            logger.error("SIEM notification error: %s", e)

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
                    metadata={**metadata, "target_ip": artifacts.get("target_host", "unknown")},
                )
                result = self.notification_service.send_notification(webhook_req)
                results.append(result)
            except Exception as e:
                logger.error("Webhook notification error for block_ip: %s", e)

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
                    metadata={**metadata, "target_host": artifacts.get("host", "unknown")},
                )
                result = self.notification_service.send_notification(webhook_req)
                results.append(result)
            except Exception as e:
                logger.error("Webhook notification error for isolate_host: %s", e)

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
                logger.error("Notification error for notify_admin (%s): %s", channel, e)

        elif action.name in ("log_incident", "audit_log"):
            # SIEM already captured above, no additional channels needed
            pass

        return results

    def _execute_action(self, action, incident) -> Dict[str, Any]:
        """
        Simulate or execute a SOAR action.
        In production, this integrates with firewalls, EDR, SIEM, and other security tools.
        """
        try:
            if action.name == "block_ip":
                ip = incident.artifacts.get("target_host", "unknown")
                duration = action.params.get("duration_minutes", 60)
                logger.info("Blocking IP %s for %d minutes", ip, duration)
                action.status = "EXECUTED"

            elif action.name == "isolate_host":
                host = incident.artifacts.get("host", "unknown")
                duration = action.params.get("duration_minutes", 120)
                logger.info("Isolating host %s for %d minutes", host, duration)
                action.status = "EXECUTED"

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