"""Audit log API: append + verify hash chain."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, Optional
from storage.factory import get_storage_client
from audit.chain import AuditChain

router = APIRouter()


class AuditInput(BaseModel):
    actor: str = "analyst"
    action: str
    resource_type: str = ""
    resource_id: str = ""
    details: Dict[str, Any] = {}


@router.post("/append")
async def append_audit(data: AuditInput):
    storage = get_storage_client()
    prev = storage.latest_audit_hash() if hasattr(storage, "latest_audit_hash") else "CHAEL-GENESIS"
    entry = AuditChain().build_entry(
        actor=data.actor, action=data.action,
        resource_type=data.resource_type, resource_id=data.resource_id,
        details=data.details, prev_hash=prev,
    )
    if hasattr(storage, "append_audit"):
        storage.append_audit(entry)
    return {"status": "appended", "entry": entry}


@router.get("/")
async def list_audit(limit: int = 200, action: Optional[str] = None):
    storage = get_storage_client()
    entries = storage.get_audit(limit=limit, action=action) if hasattr(storage, "get_audit") else []
    return {"total": len(entries), "entries": entries}


@router.get("/verify")
async def verify_chain(limit: int = 1000):
    storage = get_storage_client()
    entries = storage.get_audit(limit=limit) if hasattr(storage, "get_audit") else []
    # The audit index also holds legacy SOAR notification docs (channel/title
    # schema, no seal). Only chain-format entries carry entry_hash — verify
    # those; count the rest as legacy presence evidence, not breakage.
    chained = [e for e in (entries or []) if e.get("entry_hash")]
    result = AuditChain.verify(chained)
    result["total"] = len(entries or [])
    result["chained"] = len(chained)
    result["legacy"] = len(entries or []) - len(chained)
    return result
