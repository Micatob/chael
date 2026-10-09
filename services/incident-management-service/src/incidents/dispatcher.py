"""Real mitigation dispatch: incident actions become SOAR agent tasks.

Nothing here is simulated. A mitigation request is translated to an agent
task (contain or eradicate), queued in SOAR over HTTP with a service JWT,
and the task id is returned so the analyst can track PENDING → DONE.
If SOAR is unreachable the call FAILS loudly — never fake SUCCESS.
"""
import json
import logging
import time
import urllib.request
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# action_type → (agent action, target_kind)
ACTION_MAP = {
    "BLOCK_IP": ("block", "ip"),
    "UNBLOCK_IP": ("unblock", "ip"),
    "ISOLATE_HOST": ("isolate", "host"),
    "QUARANTINE_HOST": ("isolate", "host"),
    "UNISOLATE_HOST": ("unisolate", "host"),
    "KILL_PROCESS": ("kill_process", "host"),
    "QUARANTINE_FILE": ("quarantine_file", "host"),
    "DELETE_PERSISTENCE": ("delete_persistence", "host"),
    "COLLECT_TRIAGE": ("collect_triage", "host"),
}

_service_token = ""
_service_token_at = 0.0


def _service_jwt(identity_url: str, username: str, password: str) -> str:
    """Short-lived service JWT via identity admin creds (12h cache)."""
    global _service_token, _service_token_at
    if _service_token and (time.time() - _service_token_at) < 12 * 3600:
        return _service_token
    if not password:
        raise RuntimeError("ADMIN_PASSWORD not configured — cannot dispatch to SOAR")
    try:
        req = urllib.request.Request(
            identity_url.rstrip("/") + "/api/auth/login",
            data=json.dumps({"username": username, "password": password}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            _service_token = json.load(resp)["access_token"]
            _service_token_at = time.time()
            return _service_token
    except Exception as e:
        raise RuntimeError(f"Service auth to identity failed: {e}")


def dispatch_to_soar(action_type: str, target: str, incident_id: str,
                     requested_by: str, params: Optional[Dict[str, Any]],
                     soar_url: str, identity_url: str,
                     username: str, password: str) -> Dict[str, Any]:
    action_type = (action_type or "").upper().strip()
    if action_type not in ACTION_MAP:
        raise ValueError(
            f"Unsupported mitigation '{action_type}'. Supported: {sorted(ACTION_MAP)}")
    if not (target or "").strip():
        raise ValueError("Missing 'target'")
    agent_action, kind = ACTION_MAP[action_type]
    body = {
        "action": agent_action,
        "target": target.strip(),
        "incident_id": incident_id,
        "requested_by": requested_by,
        "duration_minutes": (params or {}).get("duration_minutes", 0),
    }
    # host-pinned when the target is a host; IP blocks stay untargeted
    # unless the analyst pins them.
    if kind == "host" and not (params or {}).get("agent_id"):
        body["hostname"] = target.strip()
    if (params or {}).get("agent_id"):
        body["agent_id"] = params["agent_id"]
    # eradication specifics ride along for the agent executor
    for key in ("process", "pid", "path", "persistence_kind", "persistence_name"):
        if (params or {}).get(key):
            body[key] = params[key]

    token = _service_jwt(identity_url, username, password)
    try:
        req = urllib.request.Request(
            soar_url.rstrip("/") + "/api/soar/agent/tasks",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            queued = json.load(resp)
            task = queued.get("task", {})
            logger.info("Mitigation dispatched: %s %s → task %s",
                        action_type, target, task.get("task_id"))
            return {"status": "QUEUED", "action": action_type,
                    "target": target.strip(), "task_id": task.get("task_id"),
                    "task_status": task.get("status", "PENDING")}
    except Exception as e:
        logger.error("SOAR dispatch failed: %s", e)
        raise RuntimeError(f"SOAR unreachable — action NOT executed: {e}")
