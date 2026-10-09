from typing import Dict, Any, List
from datetime import datetime, timezone
from models.schema import MitigationAction
from config import settings
from .dispatcher import dispatch_to_soar
import logging

logger = logging.getLogger(__name__)

class MitigationEngine:
    """
    Real mitigation: every action is dispatched as a SOAR agent task
    (queued → agent executes → reports DONE/FAILED). Nothing is simulated;
    dispatch failures raise instead of returning fake SUCCESS.
    """

    async def execute(self, action: MitigationAction, incident_id: str = "") -> Dict[str, Any]:
        logger.info(f"Dispatching mitigation: {action.action_type} on {action.target}")
        queued = dispatch_to_soar(
            action_type=action.action_type,
            target=action.target,
            incident_id=incident_id,
            requested_by=action.executed_by or "analyst",
            params=getattr(action, "params", None) or {},
            soar_url=settings.SOAR_SERVICE_URL,
            identity_url=settings.IDENTITY_SERVICE_URL,
            username=settings.ADMIN_USERNAME,
            password=settings.ADMIN_PASSWORD,
        )
        return {
            "status": "QUEUED",
            "action": action.action_type,
            "target": action.target,
            "task_id": queued.get("task_id"),
            "task_status": queued.get("task_status", "PENDING"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": (f"Queued in SOAR as task {queued.get('task_id')}. "
                        f"Track PENDING → DONE in SOAR Endpoint Response. "
                        f"Reason: {action.reason}"),
        }
