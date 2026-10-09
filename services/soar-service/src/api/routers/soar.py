"""
SOAR API Router - Exposes SOAR engine endpoints for triggering and managing automated responses.
"""
import json
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends

from models.schema import Incident
from soar.engine import SOAREngine
from soar.notifications import (
    NotificationService,
    NotificationConfig,
    NotificationChannel,
)
from auth.middleware import require_roles

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize notification service with default configurations
notification_service = NotificationService()

# Register default notification channel configs from environment or defaults
# These can be overridden via the /config endpoint
_default_notification_configs = [
    NotificationConfig(
        channel=NotificationChannel.SIEM,
        enabled=True,
        config={"index_name": "chaelsiem-audit-logs"},
    ),
    NotificationConfig(
        channel=NotificationChannel.TELEGRAM,
        enabled=True,
        config={},
    ),
]

for config in _default_notification_configs:
    try:
        notification_service.register_config(config)
    except ValueError as e:
        logger.warning("Failed to register notification config for %s: %s", config.channel, e)

# Initialize SOAR engine with notification service
soar_engine = SOAREngine(notification_service=notification_service)


@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "soar-service"}


@router.post("/trigger", status_code=200, dependencies=[Depends(require_roles(["ADMIN", "ANALYST"]))])
async def trigger_soar(incident_data: dict, user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))):
    """
    Trigger SOAR actions for an incident.
    Accepts an incident payload, validates it, and executes the matching playbook.
    Returns the list of executed actions with their results.
    """
    try:
        incident = Incident(**incident_data)
        results = soar_engine.trigger(incident, requested_by=user.get("username", "admin"))
        return {
            "status": "triggered",
            "incident_id": incident.incident_id,
            "actions_executed": len(results),
            "results": results,
        }
    except Exception as e:
        logger.error("Error triggering SOAR: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def _pending_or_404(incident_id: str, action_id: str) -> dict:
    pending = soar_engine._pending_actions.get((incident_id, action_id))
    if not pending or pending.get("status") != "PENDING":
        raise HTTPException(
            status_code=404,
            detail=f"Pending action {action_id} not found for incident {incident_id}",
        )
    return pending


@router.post("/approve/{incident_id}/{action_id}", dependencies=[Depends(require_roles(["ADMIN", "APPROVER"]))])
async def approve_action(incident_id: str, action_id: str, user: dict = Depends(require_roles(["ADMIN", "APPROVER"]))):
    """
    Approve a PENDING high-impact SOAR action. Executes exactly once;
    already-resolved actions are acknowledged without re-execution.
    Separation of duties: the analyst who triggered may not approve.
    """
    try:
        me = user.get("username", "admin")
        pending = _pending_or_404(incident_id, action_id)
        if (pending.get("requested_by") or "") == me:
            raise HTTPException(
                status_code=403,
                detail=f"Separation of duties: {me} triggered this action — a different approver must approve it.",
            )
        # Reconstruct minimal incident for notification context
        incident_data = {"incident_id": incident_id, "risk_score": 0, "source_logs": []}
        incident = Incident(**incident_data)
        success = soar_engine.approve_action(incident_id, action_id, incident=incident, approved_by=me)
        if success:
            return {"status": "approved", "incident_id": incident_id, "action_id": action_id,
                    "approved_by": me}
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Pending action {action_id} not found for incident {incident_id}",
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error approving action: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reject/{incident_id}/{action_id}", dependencies=[Depends(require_roles(["ADMIN", "APPROVER"]))])
async def reject_action(incident_id: str, action_id: str, user: dict = Depends(require_roles(["ADMIN", "APPROVER"]))):
    """Deny a PENDING action — it will never execute. Audit-logged. Self-reject is allowed."""
    try:
        me = user.get("username", "admin")
        _pending_or_404(incident_id, action_id)
        success = soar_engine.reject_action(incident_id, action_id, rejected_by=me)
        if success:
            return {"status": "rejected", "incident_id": incident_id, "action_id": action_id}
        raise HTTPException(
            status_code=404,
            detail=f"Pending action {action_id} not found for incident {incident_id}",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error rejecting action: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pending")
async def get_all_pending_actions():
    """Global approval queue — all PENDING actions across incidents."""
    try:
        pending = soar_engine.get_pending_actions()
        return {
            "pending_actions": [
                {
                    "incident_id": v.get("incident_id", ""),
                    "action_id": v["action"].action_id,
                    "name": v["action"].name,
                    "params": v["action"].params,
                    "status": v["status"],
                    "created_at": v.get("created_at", ""),
                    "requires_approval": v.get("requires_approval", True),
                    "requested_by": v.get("requested_by", ""),
                }
                for v in pending
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pending/{incident_id}")
async def get_pending_actions(incident_id: str):
    """Get all pending actions for a specific incident."""
    try:
        pending = soar_engine.get_pending_actions(incident_id)
        return {
            "incident_id": incident_id,
            "pending_actions": [
                {
                    "action_id": v["action"].action_id,
                    "name": v["action"].name,
                    "params": v["action"].params,
                    "status": v["status"],
                    "created_at": v.get("created_at", ""),
                    "requires_approval": v.get("requires_approval", True),
                    "requested_by": v.get("requested_by", ""),
                }
                for v in pending
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_execution_history():
    """Get the full action execution history."""
    try:
        if notification_service._opensearch_client:
            response = notification_service._opensearch_client.search(
                index="chaelsiem-audit-logs",
                body={
                    "query": {
                        "range": {"timestamp": {"gte": "now-30d"}}
                    },
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": 200,
                    "_source": ["action_id", "name", "status", "incident_id", "timestamp", "error", "actor", "approved_by"],
                },
                ignore_unavailable=True
            )
            history = [hit["_source"] for hit in response.get("hits", {}).get("hits", [])]
            return {"history": history}
        
        # Fallback to in-memory history
        history = soar_engine.get_execution_history()
        return {"history": history[-200:]}
    except Exception as e:
        logger.error("Error fetching execution history: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhook/receive", status_code=200)
async def receive_webhook(payload: dict):
    """
    Receive inbound webhooks from external systems (ticketing, SOAR platforms, etc.).
    Accepted payload formats:
      Generic: {"event": "alert", "incident_id": "...", "action": "block_ip", ...}
      Generic: {"alert": {...}, "action": "isolate_host"}
    Logs the webhook and returns acknowledgment.
    """
    logger.info("Received webhook: event=%s incident=%s", payload.get("event"), payload.get("incident_id"))
    try:
        opensearch_resp = notification_service._opensearch_client.index(
            index="chaelsiem-webhooks",
            body={
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": payload,
                "source_ip": "",  # Would come from request.client
            },
            refresh=False,
        )
    except Exception:
        pass
    return {"status": "received", "event": payload.get("event", "unknown")}

@router.post("/config/notification", dependencies=[Depends(require_roles(["ADMIN"]))])
async def register_notification_channel(config: dict):
    """
    Register or update a notification channel configuration.
    Accepts: channel (str), enabled (bool), config (dict with channel-specific fields).
    """
    try:
        channel_name = config.get("channel")
        if not channel_name:
            raise HTTPException(status_code=400, detail="Missing 'channel' field")

        channel = NotificationChannel(channel_name)
        notification_config = NotificationConfig(
            channel=channel,
            enabled=config.get("enabled", True),
            config=config.get("config", {}),
        )
        notification_service.register_config(notification_config)
        return {
            "status": "registered",
            "channel": channel.value,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/playbooks")
async def list_playbooks():
    """List all available playbooks (built-in + custom)."""
    try:
        playbooks = soar_engine.get_playbooks()
        result = {}
        for name, actions in playbooks.items():
            result[name] = {
                "name": name,
                "actions": actions,
                "is_custom": name not in soar_engine.playbooks,
            }
        return {"playbooks": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/playbooks", status_code=201, dependencies=[Depends(require_roles(["ADMIN"]))])
async def create_playbook(data: dict):
    """Create a custom playbook. Cannot override built-in playbooks."""
    try:
        name = data.get("name", "").upper().strip()
        actions = data.get("actions", [])
        if not name or not actions:
            raise HTTPException(status_code=400, detail="Name and actions are required")
        success = soar_engine.create_custom_playbook(name, actions)
        if not success:
            raise HTTPException(status_code=409, detail=f"Cannot override built-in playbook '{name}'")
        return {"status": "created", "name": name, "actions_count": len(actions)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/playbooks/{name}", dependencies=[Depends(require_roles(["ADMIN"]))])
async def update_playbook(name: str, data: dict):
    """Update a custom playbook."""
    try:
        actions = data.get("actions", [])
        if not actions:
            raise HTTPException(status_code=400, detail="Actions are required")
        success = soar_engine.update_custom_playbook(name.upper(), actions)
        if not success:
            raise HTTPException(status_code=404, detail=f"Custom playbook '{name}' not found or is built-in")
        return {"status": "updated", "name": name.upper()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/playbooks/{name}", dependencies=[Depends(require_roles(["ADMIN"]))])
async def delete_playbook(name: str):
    """Delete a custom playbook."""
    try:
        success = soar_engine.delete_custom_playbook(name.upper())
        if not success:
            raise HTTPException(status_code=404, detail=f"Custom playbook '{name}' not found or is built-in")
        return {"status": "deleted", "name": name.upper()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Contain recovery (local backends) ─────────────────────────────────
@router.post("/unisolate", dependencies=[Depends(require_roles(["ADMIN"]))])
async def unisolate_host(data: dict):
    """Release local host isolation (netsh/iptables/EDR). For remote
    endpoints use POST /agent/tasks with action=unisolate instead."""
    host = (data.get("host") or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="Missing 'host'")
    try:
        result = soar_engine.isolator.unisolate(host)
        soar_engine._execution_history.append({
            "action_id": f"unisolate-{host}", "name": "unisolate_host",
            "status": "EXECUTED" if result.get("success") else "FAILED",
            "incident_id": data.get("incident_id", ""), "params": {"host": host},
            "actor": "admin", "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"status": "released" if result.get("success") else "failed", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unblock", dependencies=[Depends(require_roles(["ADMIN"]))])
async def unblock_ip(data: dict):
    """Remove a local firewall block. Remote endpoints: agent task unblock."""
    ip = (data.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip'")
    try:
        result = soar_engine.firewall.unblock_ip(ip)
        soar_engine._execution_history.append({
            "action_id": f"unblock-{ip}", "name": "unblock_ip",
            "status": "EXECUTED" if result.get("success") else "FAILED",
            "incident_id": data.get("incident_id", ""), "params": {"ip": ip},
            "actor": "admin", "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"status": "released" if result.get("success") else "failed", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Agent response tasks (remote contain / recover) ──────────────────
@router.post("/agent/tasks", status_code=201, dependencies=[Depends(require_roles(["ADMIN"]))])
async def queue_agent_task(data: dict):
    """Queue a containment task for an endpoint agent.
    Body: {action: isolate|unisolate|block|unblock, target, incident_id?,
           agent_id?, hostname?, duration_minutes?}"""
    try:
        task = soar_engine.queue_agent_task(
            action=data.get("action", ""), target=data.get("target", ""),
            incident_id=data.get("incident_id", ""), agent_id=data.get("agent_id", ""),
            hostname=data.get("hostname", ""), duration_minutes=data.get("duration_minutes", 0),
        )
        return {"status": "queued", "task": task}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agent/tasks", dependencies=[Depends(require_roles(["ADMIN", "AGENT"]))])
async def poll_agent_tasks(agent_id: str = "", hostname: str = ""):
    """Agent long-poll: pending tasks for this agent/host. Auto-acks on delivery."""
    try:
        tasks = soar_engine.get_agent_tasks(agent_id=agent_id, hostname=hostname)
        for t in tasks:
            soar_engine.ack_agent_task(t["task_id"], agent_id=agent_id)
        return {"tasks": tasks}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agent/tasks/{task_id}/result", dependencies=[Depends(require_roles(["ADMIN", "AGENT"]))])
async def report_task_result(task_id: str, data: dict):
    """Agent reports execution outcome: {success: bool, detail?: str, agent_id?: str}."""
    try:
        ok = soar_engine.report_agent_task(
            task_id, bool(data.get("success", False)),
            detail=data.get("detail", ""), agent_id=data.get("agent_id", ""),
        )
        if not ok:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
        return {"status": "recorded", "task_id": task_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agent/tasks/all", dependencies=[Depends(require_roles(["ADMIN"]))])
async def list_all_agent_tasks():
    """Analyst view: every queued task with PENDING/ACKED/DONE/FAILED state."""
    return {"tasks": list(soar_engine._agent_tasks.values())}
