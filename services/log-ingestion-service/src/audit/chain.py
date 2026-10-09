"""Tamper-evident audit log with hash chaining (SOC2/CC7.2, PCI-DSS Req 10 parity)."""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def canonical(entry: Dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(prev_hash: str, entry: Dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical(entry)).encode("utf-8")).hexdigest()


class AuditChain:
    """Appends audit events with prev_hash chaining; verify() detects tampering."""

    GENESIS = "CHAEL-GENESIS"

    def __init__(self, storage=None):
        self.storage = storage

    def build_entry(
        self,
        actor: str,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        details: Optional[Dict[str, Any]] = None,
        prev_hash: str = GENESIS,
    ) -> Dict[str, Any]:
        body = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
            "prev_hash": prev_hash,
        }
        body["entry_hash"] = entry_hash(prev_hash, {k: v for k, v in body.items() if k != "entry_hash"})
        return body

    @staticmethod
    def verify(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify a time-ordered list of entries. Returns {ok, checked, broken_at}."""
        prev = AuditChain.GENESIS
        for i, e in enumerate(sorted(entries, key=lambda x: x.get("timestamp", ""))):
            expected = entry_hash(prev, {k: v for k, v in e.items() if k != "entry_hash"})
            if e.get("prev_hash") != prev or e.get("entry_hash") != expected:
                return {"ok": False, "checked": i, "broken_at": e.get("timestamp"), "total": len(entries)}
            prev = e["entry_hash"]
        return {"ok": True, "checked": len(entries), "total": len(entries)}
