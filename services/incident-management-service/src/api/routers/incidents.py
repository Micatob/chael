from fastapi import APIRouter, HTTPException, Depends, Response, File, Form, UploadFile
from typing import List, Dict, Any
from incidents.repository import IncidentRepository
from incidents.service import IncidentService
from incidents.investigation import InvestigationEngine
from incidents.mitigation import MitigationEngine
from storage.factory import get_storage_client
from models.schema import Incident
from auth.middleware import require_roles
import csv
import io
from datetime import datetime, timezone
from incidents.investigation import _extract_ips, _extract_cves, _extract_hashes, _extract_domains, _enrich_iocs, _source_status, enrich_single_ioc

router = APIRouter()

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "incident-management-service"}

def get_incident_service():
    storage = get_storage_client()
    repo = IncidentRepository()
    engine = InvestigationEngine(storage)
    mitigation_engine = MitigationEngine()
    return IncidentService(repo, engine, mitigation_engine)

@router.post("/create", status_code=201, dependencies=[Depends(require_roles(["ADMIN", "ANALYST"]))])
async def create_incident(incident: Incident, service: IncidentService = Depends(get_incident_service)):
    """Create a new incident from correlation service."""
    try:
        created = service.repo.create(incident)
        return created
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create incident: {str(e)}")

@router.get("/", response_model=List[Dict[str, Any]])
async def get_incidents(service: IncidentService = Depends(get_incident_service)):
    """Fetch incidents through the service layer."""
    return service.list_active_threats()

@router.post("/{incident_id}/investigate")
async def investigate_incident(incident_id: str, service: IncidentService = Depends(get_incident_service)):
    """
    Perform deep forensic investigation using the Service Layer.
    """
    try:
        return service.perform_investigation(incident_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Forensic Error: {str(e)}")

@router.post("/{incident_id}/mitigate", dependencies=[Depends(require_roles(["ADMIN", "ANALYST"]))])
async def mitigate_incident(
    incident_id: str,
    action_data: Dict[str, Any],
    service: IncidentService = Depends(get_incident_service)
):
    """
    Dispatch a REAL mitigation action (queued as a SOAR agent task).
    Nothing is simulated: unsupported types → 400, SOAR unreachable → 502.
    """
    try:
        return await service.perform_mitigation(incident_id, action_data)
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Mitigation Execution Error: {str(e)}")

@router.post("/{incident_id}/update")
async def update_incident_status(
    incident_id: str, 
    status_data: Dict[str, str], 
    service: IncidentService = Depends(get_incident_service)
):
    """Update incident status manually with state-machine validation."""
    status = (status_data.get("status") or "").upper()
    if not status:
        raise HTTPException(status_code=400, detail="Missing 'status' field")
    try:
        incident = service.transition_status(
            incident_id, status,
            actor=status_data.get("actor", "analyst"),
            reason=status_data.get("reason", ""),
        )
        return {"status": "success", "incident_id": incident_id, "new_status": incident["status"]}
    except ValueError as e:
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)


@router.get("/{incident_id}")
async def get_incident_by_id(incident_id: str, service: IncidentService = Depends(get_incident_service)):
    incident = service.repo.get_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


@router.post("/{incident_id}/notes")
async def add_case_note(incident_id: str, data: Dict[str, Any], service: IncidentService = Depends(get_incident_service)):
    """Analyst collaboration: append a case note (timeline auto-updated)."""
    body = (data.get("body") or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Missing 'body'")
    try:
        note = service.add_note(incident_id, body, author=data.get("author", "analyst"), visibility=data.get("visibility", "internal"))
        return {"status": "added", "note": note}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{incident_id}/timeline")
async def get_case_timeline(incident_id: str, service: IncidentService = Depends(get_incident_service)):
    try:
        return {"incident_id": incident_id, "timeline": service.get_timeline(incident_id)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{incident_id}/evidence")
async def list_evidence(incident_id: str, service: IncidentService = Depends(get_incident_service)):
    incident = service.repo.get_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return {"incident_id": incident_id, "legal_hold": bool(incident.get("legal_hold", False)),
            "evidence": incident.get("evidence", [])}


@router.post("/{incident_id}/evidence")
async def seize_evidence(incident_id: str, data: Dict[str, Any], service: IncidentService = Depends(get_incident_service)):
    try:
        ev = service.add_evidence(incident_id, data, actor=data.get("actor", "analyst"))
        return {"status": "seized", "evidence": ev}
    except ValueError as e:
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)


@router.post("/{incident_id}/evidence/{evidence_id}/transfer")
async def transfer_evidence(incident_id: str, evidence_id: str, data: Dict[str, Any],
                            service: IncidentService = Depends(get_incident_service)):
    try:
        ev = service.transfer_evidence(incident_id, evidence_id, data, actor=data.get("actor", "analyst"))
        return {"status": "transferred", "evidence": ev}
    except ValueError as e:
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)


@router.post("/{incident_id}/evidence/{evidence_id}/verify")
async def verify_evidence(incident_id: str, evidence_id: str, data: Dict[str, Any] = None,
                          service: IncidentService = Depends(get_incident_service)):
    try:
        actor = (data or {}).get("actor", "analyst")
        return service.verify_evidence(incident_id, evidence_id, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{incident_id}/evidence/bundle",
             dependencies=[Depends(require_roles(["ADMIN", "ANALYST", "AGENT"]))])
async def upload_bundle(incident_id: str, bundle: UploadFile = File(...),
                        service: IncidentService = Depends(get_incident_service)):
    """Agent triage-bundle upload (zip, ≤25MB): stored + hash-sealed as evidence."""
    try:
        data = await bundle.read()
        ev = service.register_bundle(incident_id, bundle.filename or "bundle.zip",
                                     data, actor="agent")
        return {"status": "stored", "evidence": ev, "bytes": len(data)}
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{incident_id}/evidence/image-chunk",
              dependencies=[Depends(require_roles(["ADMIN", "AGENT"]))])
async def upload_image_chunk(incident_id: str, upload_id: str = Form(""), chunk_index: int = Form(0),
                             chunk: UploadFile = File(...),
                             service: IncidentService = Depends(get_incident_service)):
    """Forensic image chunk upload (phase 2 behind triage bundles): the agent
    streams ≤10MB chunks; the server stages them until image-complete seals
    the evidence. Staging without completion expires with the container."""
    import os as _os
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9_-]{1,64}", upload_id or ""):
        raise HTTPException(status_code=400, detail="Invalid 'upload_id'")
    if chunk_index < 0 or chunk_index > 999999:
        raise HTTPException(status_code=400, detail="Invalid 'chunk_index'")
    incident = service.repo.get_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    data = await chunk.read()
    if len(data) > 12 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Chunk too large (max 12MB)")
    stage = _os.path.join(service.EVIDENCE_DIR, incident_id, f".upload_{upload_id}")
    _os.makedirs(stage, exist_ok=True)
    with open(_os.path.join(stage, f"chunk_{chunk_index:06d}"), "wb") as fh:
        fh.write(data)
    return {"status": "staged", "upload_id": upload_id,
            "chunk_index": chunk_index, "bytes": len(data)}


@router.post("/{incident_id}/evidence/image-complete",
              dependencies=[Depends(require_roles(["ADMIN", "AGENT"]))])
async def complete_image_upload(incident_id: str, data: Dict[str, Any],
                                service: IncidentService = Depends(get_incident_service)):
    """Reassemble staged chunks (ordered), SHA-256 verify, seal as evidence."""
    import hashlib as _hashlib
    import os as _os
    import re as _re
    upload_id = (data.get("upload_id") or "")
    filename = _os.path.basename(data.get("filename") or "image.bin")[:120]
    kind = (data.get("kind") or "disk-image").strip().lower()
    if kind not in ("disk-image", "memory"):
        raise HTTPException(status_code=400, detail="kind must be disk-image|memory")
    if not _re.fullmatch(r"[A-Za-z0-9_-]{1,64}", upload_id):
        raise HTTPException(status_code=400, detail="Invalid 'upload_id'")
    expected_sha = (data.get("sha256") or "").lower()
    if not _re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise HTTPException(status_code=400, detail="Missing/invalid 'sha256'")
    incident = service.repo.get_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    stage = _os.path.join(service.EVIDENCE_DIR, incident_id, f".upload_{upload_id}")
    if not _os.path.isdir(stage):
        raise HTTPException(status_code=404, detail="Upload staging not found")
    parts = sorted(p for p in _os.listdir(stage) if p.startswith("chunk_"))
    if not parts:
        raise HTTPException(status_code=400, detail="No chunks staged")
    max_bytes = 4 * 1024 * 1024 * 1024
    h = _hashlib.sha256()
    size = 0
    dest_dir = _os.path.join(service.EVIDENCE_DIR, incident_id)
    dest = _os.path.join(dest_dir, filename)
    with open(dest, "wb") as out:
        for p in parts:
            with open(_os.path.join(stage, p), "rb") as fh:
                while True:
                    blk = fh.read(4 * 1024 * 1024)
                    if not blk:
                        break
                    size += len(blk)
                    if size > max_bytes:
                        out.close()
                        _os.remove(dest)
                        raise HTTPException(status_code=400, detail="Image exceeds 4GB cap")
                    h.update(blk)
                    out.write(blk)
    if h.hexdigest() != expected_sha:
        _os.remove(dest)
        raise HTTPException(status_code=400, detail="SHA-256 mismatch — image rejected")
    import shutil as _shutil
    _shutil.rmtree(stage, ignore_errors=True)
    ev = service.add_evidence(incident_id, {
        "type": kind,
        "title": f"Forensic image {filename}",
        "description": f"{size} bytes in {len(parts)} chunks at {dest}",
        "sha256": expected_sha,
        "collector": data.get("collector", "agent"),
    }, actor=data.get("collector", "agent"))
    return {"status": "sealed", "evidence": ev, "bytes": size, "chunks": len(parts)}


@router.post("/{incident_id}/hold", dependencies=[Depends(require_roles(["ADMIN"]))])
async def set_hold(incident_id: str, data: Dict[str, Any], service: IncidentService = Depends(get_incident_service)):
    try:
        return service.set_legal_hold(incident_id, bool(data.get("legal_hold", True)),
                                      actor=data.get("actor", "admin"))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/holds/active")
async def active_holds(service: IncidentService = Depends(get_incident_service)):
    """Incidents under legal hold — purge must refuse while this is non-empty."""
    try:
        incidents = service.repo.get_all()
        held = [i.get("incident_id") for i in incidents if i.get("legal_hold")]
        return {"holds": held, "count": len(held)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{incident_id}/export/jira")
async def export_to_jira(incident_id: str, service: IncidentService = Depends(get_incident_service)):
    try:
        return service.export_jira(incident_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{incident_id}/export/thehive")
async def export_to_thehive(incident_id: str, service: IncidentService = Depends(get_incident_service)):
    try:
        return service.export_thehive(incident_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/export/csv")
async def export_incidents_csv(service: IncidentService = Depends(get_incident_service)):
    incidents = service.repo.get_all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["incident_id", "timestamp", "severity", "risk_score", "status", "description", "host", "attack_type"])
    for inc in incidents:
        artifacts = inc.get("artifacts", {}) or {}
        writer.writerow([
            inc.get("incident_id", ""),
            inc.get("timestamp", ""),
            "HIGH" if (inc.get("risk_score") or 0) >= 70 else "MEDIUM" if (inc.get("risk_score") or 0) >= 40 else "LOW",
            inc.get("risk_score", ""),
            inc.get("status", ""),
            inc.get("description", ""),
            artifacts.get("host", artifacts.get("target_host", "")),
            artifacts.get("attack_type", artifacts.get("event_type", "")),
        ])
    csv_content = output.getvalue()
    output.close()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=incidents_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"},
    )


@router.post("/{incident_id}/external-hunt")
async def external_threat_hunt(incident_id: str, service: IncidentService = Depends(get_incident_service)):
    """
    Hunt for threat intelligence on an incident from external sources.
    Always returns locally extracted IOCs + live free-source enrichment
    (ip-api geo, NVD CVE). Keyed sources (VT/AbuseIPDB/Shodan/OTX/GreyNoise)
    run when their keys are configured — see `source_status` in the response.
    """
    try:
        incident = service.repo.get_by_id(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

        source_logs = incident.get("source_logs", [])
        all_messages = " ".join(
            log.get("message", "") for log in source_logs if isinstance(log, dict)
        )

        ips = _extract_ips(all_messages)
        cves = _extract_cves(all_messages)
        hashes = _extract_hashes(all_messages)
        domains = _extract_domains(all_messages)

        enrichment = {}
        try:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                future = executor.submit(_enrich_iocs, ips, cves, hashes, domains)
                enrichment = future.result(timeout=15)
        except (concurrent.futures.TimeoutError, Exception):
            enrichment = {}

        found = len(enrichment) > 0
        status = _source_status()
        keyed_live = [k for k, v in status["keyed"].items() if v]
        return {
            "incident_id": incident_id,
            "found": found,
            "hunt_timestamp": datetime.now(timezone.utc).isoformat(),
            "iocs_extracted": {
                "ip_addresses": ips[:10],
                "cve_ids": cves[:5],
                "hashes": hashes[:5],
                "domains": domains[:5],
            },
            "external_intel": enrichment,
            "source_status": status,
            "sources_live": ["ip-api", "internetdb", "nvd", "cvedb"] + keyed_live,
            "confirm_note": ("Free sources (ip-api geo, Shodan InternetDB exposure, NVD + "
                             "Shodan CVEDB) are live. "
                             + (f"Keyed sources live: {', '.join(keyed_live)}. "
                                if keyed_live else
                                "Add VT_API_KEY/SHODAN_API_KEY/OTX_API_KEY/GREYNOISE_API_KEY to .env for full confirmation. ")
                             + "Confirm malicious verdicts with 2+ sources before containment."),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"External threat hunt failed: {str(e)}")


@router.get("/enrich/status")
async def enrich_status():
    """Which external intel sources are live (free vs keyed). No incident needed."""
    status = _source_status()
    keyed_live = [k for k, v in status["keyed"].items() if v]
    return {"sources_live": ["ip-api", "internetdb", "nvd", "cvedb"] + keyed_live, **status}


@router.get("/enrich/ioc")
async def enrich_ioc(itype: str = "", value: str = ""):
    """Live single-IOC lookup for the Hunt page (ip, domain, hash, cve).

    Example: GET /api/incidents/enrich/ioc?itype=ip&value=8.8.8.8
    Always tries free sources; keyed sources run when configured.
    """
    t = (itype or "").strip().lower()
    v = (value or "").strip()
    if not t or not v:
        raise HTTPException(status_code=400, detail="Provide ?itype=ip|domain|hash|cve&value=<ioc>")
    if len(v) > 500:
        raise HTTPException(status_code=400, detail="value too long")
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            fut = ex.submit(enrich_single_ioc, t, v)
            return fut.result(timeout=15)
    except concurrent.futures.TimeoutError:
        raise HTTPException(status_code=504, detail="External lookup timed out — try again or use reference links")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IOC lookup failed: {str(e)}")


@router.get("/export/compliance")
async def export_compliance_report(service: IncidentService = Depends(get_incident_service)):
    """Generate a compliance report mapping incidents to PCI-DSS, HIPAA, SOC2, NIST-800-53."""
    try:
        from compliance.packs import build_compliance_report
        incidents = service.repo.get_all()
        return build_compliance_report(incidents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate compliance report: {str(e)}")


@router.get("/export/compliance/{framework}")
async def export_compliance_framework(framework: str, service: IncidentService = Depends(get_incident_service)):
    """Framework-scoped report: /export/compliance/PCI-DSS | HIPAA | SOC2 | NIST-800-53."""
    try:
        from compliance.packs import build_compliance_report
        incidents = service.repo.get_all()
        report = build_compliance_report(incidents)
        key = framework.upper()
        if key not in report["frameworks"]:
            raise HTTPException(status_code=404, detail=f"Unknown framework {framework}. Use PCI-DSS, HIPAA, SOC2, NIST-800-53")
        return {"framework": key, "report": report["frameworks"][key], "summary": report["summary"]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sla/summary")
async def get_sla_summary(service: IncidentService = Depends(get_incident_service)):
    """Get SLA compliance summary across all active incidents."""
    try:
        return service.get_sla_summary()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{incident_id}/assign", dependencies=[Depends(require_roles(["ADMIN"]))])
async def assign_incident(incident_id: str, data: dict, service: IncidentService = Depends(get_incident_service)):
    """Assign an incident to an analyst."""
    try:
        repo = service.repo
        incident = repo.get_by_id(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
        incident["assigned_to"] = data.get("assigned_to", "")
        repo.create(Incident(**incident))
        return {"status": "assigned", "incident_id": incident_id, "assigned_to": incident["assigned_to"]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
