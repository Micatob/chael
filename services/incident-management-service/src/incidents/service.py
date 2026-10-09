from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
import os
from models.schema import Incident, SLAPriority, SLA_TARGETS, VALID_TRANSITIONS
from .repository import IncidentRepository
from .investigation import InvestigationEngine
from .mitigation import MitigationEngine
from models.schema import Incident, MitigationAction

class IncidentService:
    """
    Business logic layer for incident management.
    """
    def __init__(self, repo: IncidentRepository, engine: InvestigationEngine, mitigation_engine: MitigationEngine):
        self.repo = repo
        self.engine = engine
        self.mitigation_engine = mitigation_engine

    def _calculate_sla_priority(self, risk_score: int) -> SLAPriority:
        """Calculate SLA priority based on risk score."""
        if risk_score >= 90:
            return SLAPriority.P1
        elif risk_score >= 70:
            return SLAPriority.P2
        elif risk_score >= 40:
            return SLAPriority.P3
        return SLAPriority.P4

    def _set_sla_deadlines(self, incident_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Set SLA deadlines based on priority."""
        risk_score = incident_dict.get("risk_score", 0)
        priority = self._calculate_sla_priority(risk_score)
        targets = SLA_TARGETS[priority.value]
        created_at = datetime.fromisoformat(incident_dict["timestamp"].replace("Z", "+00:00")) if isinstance(incident_dict["timestamp"], str) else incident_dict.get("timestamp", datetime.now(timezone.utc))

        incident_dict["sla_priority"] = priority.value
        incident_dict["sla_response_deadline"] = (created_at + timedelta(hours=targets["response_hours"])).isoformat()
        incident_dict["sla_resolve_deadline"] = (created_at + timedelta(hours=targets["resolve_hours"])).isoformat()
        return incident_dict

    def _check_sla_breach(self, incident_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Check if SLA has been breached."""
        now = datetime.now(timezone.utc)
        resolve_deadline = incident_dict.get("sla_resolve_deadline")
        if resolve_deadline and incident_dict.get("status") not in ("RESOLVED", "FALSE_POSITIVE"):
            deadline = datetime.fromisoformat(resolve_deadline.replace("Z", "+00:00")) if isinstance(resolve_deadline, str) else resolve_deadline
            if now > deadline:
                incident_dict["sla_breached"] = True
        return incident_dict

    def create_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new incident with SLA tracking."""
        incident_dict = self._set_sla_deadlines(incident_data)
        # Seed timeline with creation event + MITRE passthrough
        incident_dict.setdefault("timeline", []).append({
            "event_id": __import__("uuid").uuid4().hex[:8],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": "system",
            "action": "created",
            "details": {"risk_score": incident_dict.get("risk_score", 0)},
        })
        artifacts = incident_dict.get("artifacts", {}) or {}
        if artifacts.get("mitre_attack") and not incident_dict.get("mitre_attack"):
            incident_dict["mitre_attack"] = artifacts.get("mitre_attack")
        incident = Incident(**incident_dict)
        self.repo.create(incident)
        return incident_dict

    def list_active_threats(self) -> List[Dict[str, Any]]:
        """Return all open/investigating/triaged/contained incidents (server-side filtered)."""
        incidents = []
        for status in ("OPEN", "TRIAGED", "INVESTIGATING", "CONTAINED"):
            incidents += self.repo.get_all(status=status)
        return [self._check_sla_breach(inc) for inc in incidents]

    def get_sla_summary(self) -> Dict[str, Any]:
        """Get SLA compliance summary across all active incidents."""
        active = self.list_active_threats()
        total = len(active)
        breached = sum(1 for inc in active if inc.get("sla_breached"))
        by_priority = {}
        for inc in active:
            p = inc.get("sla_priority", "P4")
            if p not in by_priority:
                by_priority[p] = {"total": 0, "breached": 0}
            by_priority[p]["total"] += 1
            if inc.get("sla_breached"):
                by_priority[p]["breached"] += 1
        return {
            "total_active": total,
            "total_breached": breached,
            "compliance_rate": round((1 - breached / total) * 100, 1) if total > 0 else 100.0,
            "by_priority": by_priority,
        }

    def perform_investigation(self, incident_id: str) -> Dict[str, Any]:
        """Run full investigation on an incident and update its status."""
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        results = self.engine.analyze(incident)
        incident["investigation_results"] = results
        if incident.get("status") == "OPEN":
            incident["status"] = "INVESTIGATING"
        # Mark SLA response time
        if not incident.get("sla_responded_at"):
            incident["sla_responded_at"] = datetime.now(timezone.utc).isoformat()
        incident.setdefault("timeline", []).append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": "forensic-engine",
            "action": "investigation",
            "details": {"summary": str(results)[:500]},
        })
        self.repo.create(Incident(**incident))
        return results

    async def perform_mitigation(self, incident_id: str, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a mitigation action and log it to the incident history."""
        incident_dict = self.repo.get_by_id(incident_id)
        if not incident_dict:
            raise ValueError(f"Incident {incident_id} not found")
            
        action = MitigationAction(**action_data)
        result = await self.mitigation_engine.execute(action, incident_id=incident_id)
        
        # Log to history
        if "mitigation_history" not in incident_dict:
            incident_dict["mitigation_history"] = []
        
        incident_dict["mitigation_history"].append(result)
        incident_dict.setdefault("timeline", []).append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": action_data.get("executed_by", "analyst"),
            "action": "mitigation",
            "details": result,
        })
        self.repo.create(Incident(**incident_dict))
        
        return result

    # ── Case workbench ──────────────────────────────────────────────
    def transition_status(self, incident_id: str, new_status: str, actor: str = "analyst", reason: str = "") -> Dict[str, Any]:
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        current = (incident.get("status") or "OPEN").upper()
        target = (new_status or "").upper()
        allowed = VALID_TRANSITIONS.get(current, [])
        if target not in allowed:
            raise ValueError(f"Invalid transition {current} -> {target}. Allowed: {allowed}")
        if incident.get("legal_hold") and target in ("RESOLVED", "CLOSED"):
            raise ValueError("Incident is under legal hold — release the hold before closing")
        incident["status"] = target
        now = datetime.now(timezone.utc).isoformat()
        if target in ("TRIAGED", "INVESTIGATING", "CONTAINED") and not incident.get("sla_responded_at"):
            incident["sla_responded_at"] = now
        if target in ("RESOLVED", "CLOSED", "FALSE_POSITIVE") and not incident.get("sla_resolved_at"):
            incident["sla_resolved_at"] = now
        incident.setdefault("timeline", []).append({
            "timestamp": now, "actor": actor, "action": "status_change",
            "details": {"from": current, "to": target, "reason": reason},
        })
        self.repo.create(Incident(**incident))
        return incident

    def add_note(self, incident_id: str, body: str, author: str = "analyst", visibility: str = "internal") -> Dict[str, Any]:
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        import uuid
        note = {
            "note_id": str(uuid.uuid4()),
            "author": author,
            "body": body,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "visibility": visibility,
        }
        incident.setdefault("notes", []).append(note)
        incident.setdefault("timeline", []).append({
            "timestamp": note["created_at"], "actor": author, "action": "note_added",
            "details": {"note_id": note["note_id"], "preview": body[:140]},
        })
        self.repo.create(Incident(**incident))
        return note

    def get_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        return sorted(incident.get("timeline", []), key=lambda e: e.get("timestamp", ""))

    # ── Evidence locker (simple chain-of-custody) ─────────────────────
    @staticmethod
    def _evidence_hash(ev: Dict[str, Any]) -> str:
        import hashlib
        import json
        canonical = json.dumps(
            {k: ev.get(k, "") for k in ("type", "title", "description", "sha256", "collector", "source_host")},
            sort_keys=True, separators=(",", ":"), default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def add_evidence(self, incident_id: str, data: Dict[str, Any], actor: str = "analyst") -> Dict[str, Any]:
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        import uuid
        now = datetime.now(timezone.utc).isoformat()
        ev = {
            "evidence_id": str(uuid.uuid4()),
            "type": (data.get("type") or "note").strip().lower(),
            "title": (data.get("title") or "").strip(),
            "description": (data.get("description") or "").strip(),
            "sha256": (data.get("sha256") or "").strip().lower(),
            "collector": data.get("collector") or actor,
            "source_host": data.get("source_host") or "",
            "created_at": now,
            "custody": [{"timestamp": now, "from": "", "to": data.get("collector") or actor,
                         "reason": "seized", "actor": actor}],
            "verified": False,
            "verified_at": None,
        }
        if not ev["title"]:
            raise ValueError("Missing 'title'")
        ev["seal_hash"] = self._evidence_hash(ev)
        incident.setdefault("evidence", []).append(ev)
        incident.setdefault("timeline", []).append({
            "timestamp": now, "actor": actor, "action": "evidence_seized",
            "details": {"evidence_id": ev["evidence_id"], "title": ev["title"][:140], "sha256": ev["sha256"][:32]},
        })
        self.repo.create(Incident(**incident))
        return ev

    def transfer_evidence(self, incident_id: str, evidence_id: str, data: Dict[str, Any], actor: str = "analyst") -> Dict[str, Any]:
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        now = datetime.now(timezone.utc).isoformat()
        for ev in incident.get("evidence", []):
            if ev.get("evidence_id") == evidence_id:
                hop = {"timestamp": now, "from": data.get("from") or ev.get("custody", [{}])[-1].get("to", ""),
                       "to": (data.get("to") or "").strip(), "reason": (data.get("reason") or "").strip(),
                       "actor": actor}
                if not hop["to"]:
                    raise ValueError("Missing 'to' (new custodian)")
                ev.setdefault("custody", []).append(hop)
                ev["verified"] = False  # custody change resets verification
                incident.setdefault("timeline", []).append({
                    "timestamp": now, "actor": actor, "action": "evidence_transfer",
                    "details": {"evidence_id": evidence_id, "from": hop["from"], "to": hop["to"]},
                })
                self.repo.create(Incident(**incident))
                return ev
        raise ValueError(f"Evidence {evidence_id} not found")

    def verify_evidence(self, incident_id: str, evidence_id: str, actor: str = "analyst") -> Dict[str, Any]:
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        now = datetime.now(timezone.utc).isoformat()
        for ev in incident.get("evidence", []):
            if ev.get("evidence_id") == evidence_id:
                ok = self._evidence_hash(ev) == ev.get("seal_hash", "")
                ev["verified"] = bool(ok)
                ev["verified_at"] = now if ok else None
                incident.setdefault("timeline", []).append({
                    "timestamp": now, "actor": actor, "action": "evidence_verified",
                    "details": {"evidence_id": evidence_id, "ok": ok},
                })
                self.repo.create(Incident(**incident))
                return {"evidence_id": evidence_id, "ok": ok, "verified_at": ev["verified_at"]}
        raise ValueError(f"Evidence {evidence_id} not found")

    # Triage bundles land here (mount a volume on EVIDENCE_DIR in production;
    # without one, bundles live as long as the container does).
    EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", "/tmp/chael-evidence")
    MAX_BUNDLE_BYTES = 25 * 1024 * 1024

    def register_bundle(self, incident_id: str, filename: str, data: bytes,
                        actor: str = "agent") -> Dict[str, Any]:
        import hashlib
        safe = os.path.basename(filename or "bundle.zip")[:120] or "bundle.zip"
        if len(data) > self.MAX_BUNDLE_BYTES:
            raise ValueError(f"Bundle too large ({len(data)} bytes, max {self.MAX_BUNDLE_BYTES})")
        sha = hashlib.sha256(data).hexdigest()
        dest_dir = os.path.join(self.EVIDENCE_DIR, incident_id)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, safe)
        with open(dest, "wb") as fh:
            fh.write(data)
        return self.add_evidence(incident_id, {
            "type": "triage",
            "title": f"Triage bundle {safe}",
            "description": f"{len(data)} bytes at {dest}",
            "sha256": sha,
            "collector": actor,
        }, actor=actor)

    def set_legal_hold(self, incident_id: str, held: bool, actor: str = "analyst") -> Dict[str, Any]:
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        incident["legal_hold"] = bool(held)
        incident.setdefault("timeline", []).append({
            "timestamp": datetime.now(timezone.utc).isoformat(), "actor": actor,
            "action": "legal_hold_set" if held else "legal_hold_released", "details": {},
        })
        self.repo.create(Incident(**incident))
        return {"incident_id": incident_id, "legal_hold": incident["legal_hold"]}

    def export_jira(self, incident_id: str) -> Dict[str, Any]:
        """Build a Jira-ready payload (user pastes or auto-pushes via webhook)."""
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        artifacts = incident.get("artifacts", {}) or {}
        return {
            "fields": {
                "project": {"key": "SEC"},
                "summary": f"[{incident.get('risk_score')}] {incident.get('description', '')[:200]}",
                "description": (
                    f"Incident {incident_id}\nRisk: {incident.get('risk_score')}\n"
                    f"Status: {incident.get('status')}\nHost: {artifacts.get('host')}\n"
                    f"MITRE: {incident.get('mitre_attack') or artifacts.get('mitre_attack')}\n"
                    f"Timeline events: {len(incident.get('timeline', []))}\n"
                    f"Notes: {len(incident.get('notes', []))}"
                ),
                "issuetype": {"name": "Task"},
                "priority": {"name": "Highest" if (incident.get("risk_score") or 0) >= 90 else "High" if (incident.get("risk_score") or 0) >= 70 else "Medium"},
                "labels": ["siem", "chael", *(incident.get("mitre_attack") or []), *(incident.get("tags") or [])],
            },
            "incident_id": incident_id,
        }

    def export_thehive(self, incident_id: str) -> Dict[str, Any]:
        """Build a TheHive case-ready payload."""
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        artifacts = incident.get("artifacts", {}) or {}
        return {
            "title": incident.get("description", f"Incident {incident_id}")[:200],
            "description": f"Chael SIEM incident {incident_id} (risk {incident.get('risk_score')})",
            "severity": 3 if (incident.get("risk_score") or 0) >= 90 else 2 if (incident.get("risk_score") or 0) >= 40 else 1,
            "tlp": 2,
            "tags": ["chael-siem", *(incident.get("mitre_attack") or artifacts.get("mitre_attack") or [])],
            "artifacts": artifacts,
            "tasks": [
                {"title": "Triage & scope", "description": "Confirm affected hosts"},
                {"title": "Contain", "description": "Isolate host / block IOC"},
                {"title": "Eradicate & recover", "description": "Remove persistence, reset creds"},
            ],
            "incident_id": incident_id,
        }
