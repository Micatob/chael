import logging
import hashlib
import time
import re
from fastapi import APIRouter, HTTPException, BackgroundTasks, Body, Query, WebSocket, WebSocketDisconnect, Depends, Request
from models.schema import NormalizedLog
from storage.factory import get_storage_client
from detection.correlation import CorrelationEngine, RuleEngine
from soar.engine import SOAREngine
from normalizers.factory import NormalizerFactory
from auth.middleware import require_roles
from typing import List, Dict, Any, Optional
import json
from datetime import datetime, timezone as dt_timezone

logger = logging.getLogger(__name__)

router = APIRouter()
opensearch = get_storage_client()
correlation_engine = CorrelationEngine()
rule_engine = RuleEngine(correlation_engine)
soar_engine = SOAREngine()

# ── Stage C: Deduplication cache ──────────────────────────────────────────
_DEDUP_CACHE: Dict[str, Dict] = {}
_DEDUP_WINDOW_SECONDS = 60

def _is_duplicate(log: NormalizedLog) -> bool:
    # Auth failures must NEVER be deduped: repeated identical messages are the
    # brute-force signal itself (counter lives in the correlation engine).
    meta = log.metadata or {}
    event_id = meta.get("event_id") or meta.get("EventID")
    if (event_id in (4625, 4740)
            or meta.get("event_type") in ("ssh_failed_password", "ssh_invalid_user")
            or meta.get("auth_result") == "failure"):
        return False
    key = hashlib.md5(
        f"{log.host}:{log.source}:{log.message[:500]}:{meta.get('src_ip', '')}:{meta.get('user', '')}:{meta.get('event_type', '')}".encode()
    ).hexdigest()
    now = time.time()
    last_seen = _DEDUP_CACHE.get(key, {}).get("ts", 0)
    if last_seen and (now - last_seen) < _DEDUP_WINDOW_SECONDS:
        _DEDUP_CACHE[key]["count"] = _DEDUP_CACHE[key].get("count", 1) + 1
        return True
    _DEDUP_CACHE[key] = {"ts": now, "count": 1}
    if len(_DEDUP_CACHE) > 2000:
        cutoff = now - _DEDUP_WINDOW_SECONDS
        expired = [k for k, v in _DEDUP_CACHE.items() if v.get("ts", 0) < cutoff]
        for k in expired:
            _DEDUP_CACHE.pop(k, None)
    return False

# ── WebSocket clients for real-time log streaming ────────────────────────
_ws_clients: List[WebSocket] = []

YARA_INDEX = "chaelsiem-yara-events"


def canonical_log_hash(log_dict: dict) -> str:
    """Stable SHA-256 over the immutable core of a log (integrity seal)."""
    core = {
        "timestamp": str(log_dict.get("timestamp", "")),
        "host": log_dict.get("host", ""),
        "source": log_dict.get("source", ""),
        "severity": str(log_dict.get("severity", "")),
        "message": log_dict.get("message", ""),
        "metadata": {k: v for k, v in (log_dict.get("metadata") or {}).items()
                     if k not in ("log_hash",)},
    }
    return hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()

async def _handle_syslog_message(message: str, address: tuple = None):
    """Callback for syslog receiver - normalizes and ingests syslog messages."""
    try:
        normalizer = NormalizerFactory.get("syslog")
        raw = {"message": message, "host": address[0] if address else "unknown"}
        normalized = normalizer.normalize(raw)
        if normalized:
            await process_log_background(normalized)
    except Exception as e:
        logger.warning("Syslog callback error: %s", e)

async def _broadcast_log(log_dict: dict):
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_json(log_dict)
        except Exception:
            dead.append(ws)
    for ws in dead:
        try:
            await ws.close()
        except Exception:
            pass
        _ws_clients.remove(ws)

# ── Heartbeat tracking ───────────────────────────────────────────────────
HEARTBEAT_INDEX = "chaelsiem-source-heartbeats"

async def _record_heartbeat(hostname: str, source_type: str, status: str = "online", metadata: dict = None):
    try:
        opensearch.client.index(
            index=HEARTBEAT_INDEX,
            body={
                "hostname": hostname,
                "source_type": source_type,
                "status": status,
                "timestamp": datetime.now(dt_timezone.utc).isoformat(),
                "metadata": metadata or {},
            },
            refresh=False,
        )
    except Exception as e:
        logger.warning("Failed to record heartbeat: %s", e)

async def process_log_background(log: NormalizedLog):
    try:
        # Stage B: Correlation-based filtering — tag noise, but STORE it
        if not correlation_engine._should_index(log):
            logger.debug("Stage B: dropped log from %s (%s)", log.host, log.message[:80])
            return

        # Integrity seal (chain-of-custody for raw telemetry)
        try:
            log.metadata["log_hash"] = canonical_log_hash(log.model_dump())
        except Exception:
            pass

        # 1. Index the log
        opensearch.index_log(log)

        # 2. Broadcast to WebSocket clients
        try:
            await _broadcast_log({
                "event": "log:ingested",
                "data": log.model_dump(),
            })
        except Exception:
            pass

        # 3. Run correlation rules through the rule engine (Stage C: dedup + alert fatigue)
        incident = rule_engine.process_log(log)

        # 4. If incident found, index it and trigger SOAR
        if incident:
            logger.info("Incident triggered: %s", incident.description)
            incident.tenant_id = log.tenant_id
            opensearch.index_incident(incident)
            soar_engine.trigger(incident)
            try:
                await _broadcast_log({
                    "event": "incident:created",
                    "data": incident.model_dump(),
                })
            except Exception:
                pass
    except Exception as e:
        logger.error("Error in backend log processing: %s", e)

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "log-ingestion-service"}

@router.post("/ingest", status_code=202)
async def ingest_log(log: NormalizedLog, background_tasks: BackgroundTasks, request: Request):
    """Normalized ingestion."""
    user = getattr(request.state, "user", None)
    if user:
        agent_id = user.get("id")
        if agent_id:
            log.metadata["agent_id"] = agent_id
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        log.tenant_id = tenant_id
    # Deduplicate: skip if same log was recently ingested
    if _is_duplicate(log):
        return {"status": "deduplicated"}
    background_tasks.add_task(process_log_background, log)
    return {"status": "queued"}

@router.post("/raw/{source_type}", status_code=202)
async def ingest_raw(source_type: str, raw_payload: Dict[str, Any] = Body(...), background_tasks: BackgroundTasks = None, request: Request = None):
    """Raw ingestion from collectors (Windows, Syslog)."""
    normalizer = NormalizerFactory.get(source_type)
    if not normalizer:
        raise HTTPException(status_code=400, detail=f"Source {source_type} not supported")
    
    try:
        normalized = normalizer.normalize(raw_payload)
        if normalized:
            user = getattr(request.state, "user", None)
            if user:
                agent_id = user.get("id")
                if agent_id:
                    normalized.metadata["agent_id"] = agent_id
            tenant_id = getattr(request.state, "tenant_id", None)
            if tenant_id:
                normalized.tenant_id = tenant_id
            background_tasks.add_task(process_log_background, normalized)
    except Exception as e:
        logger.warning("Normalization failed for %s: %s", source_type, e)
        
    return {"status": "queued"}

@router.get("/", response_model=List[Dict[str, Any]])
async def list_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    host: Optional[str] = None,
    source: Optional[str] = None,
    sort_by: str = Query("timestamp", regex="^(timestamp|severity|host|source)$"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    fields: Optional[str] = Query(None, description="Comma-separated field names to return"),
):
    """Get logs with advanced filtering, pagination, and sorting."""
    field_list = [f.strip() for f in fields.split(",")] if fields else None
    return opensearch.get_logs_filtered(
        limit=limit,
        offset=offset,
        search=search,
        severity=severity,
        host=host,
        source=source,
        sort_by=sort_by,
        sort_order=sort_order,
        fields=field_list,
    )

@router.get("/export", response_model=Dict[str, Any])
async def export_logs(
    search: Optional[str] = None,
    severity: Optional[str] = None,
    host: Optional[str] = None,
    source: Optional[str] = None,
    format: str = Query("json", regex="^(json|csv)$")
):
    """Export logs in JSON or CSV format."""
    logs = opensearch.get_logs_filtered(
        limit=10000,  # Reasonable limit for export
        offset=0,
        search=search,
        severity=severity,
        host=host,
        source=source,
        sort_by="timestamp",
        sort_order="desc"
    )

    if format == "json":
        return {
            "data": logs,
            "exported_at": datetime.now(dt_timezone.utc).isoformat(),
            "total_records": len(logs)
        }
    else:
        # CSV format
        if logs:
            headers = ["timestamp", "host", "source", "severity", "message", "metadata"]
            csv_data = [",".join(f'"{str(log.get(h, ""))}"' for h in headers) for log in logs]
            csv_content = ",".join(headers) + "\n" + "\n".join(csv_data)
            return {"csv": csv_content}
        return {"csv": ""}

@router.post("/hunt", response_model=Dict[str, Any])
async def advanced_hunt(query: Dict[str, Any] = Body(...), limit: int = Query(100, ge=1, le=1000)):
    """
    Execute advanced threat hunting queries using OpenSearch DSL.
    Supports complex queries like aggregations, nested queries, etc.
    """
    try:
        # Add size limit to query if not specified
        if "size" not in query:
            query["size"] = limit

        response = opensearch.client.search(index=opensearch.log_index, body=query)
        return {
            "hits": [hit["_source"] for hit in response["hits"]["hits"]],
            "total": response["hits"]["total"]["value"] if "total" in response["hits"] else len(response["hits"]["hits"]),
            "took": response["took"],
            "query": query
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Query execution failed: {str(e)}")

@router.websocket("/ws")
async def log_websocket(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.append(websocket)
    logger.info("WebSocket client connected (%d total)", len(_ws_clients))
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(_ws_clients))


@router.post("/heartbeat", status_code=200)
async def log_source_heartbeat(payload: dict):
    hostname = payload.get("hostname", "unknown")
    source_type = payload.get("source_type", "agent")
    status = payload.get("status", "online")
    metadata = payload.get("metadata", {})
    await _record_heartbeat(hostname, source_type, status, metadata)
    return {"status": "acknowledged", "hostname": hostname}


@router.get("/sources", response_model=List[Dict[str, Any]])
async def list_sources():
    try:
        resp = opensearch.client.search(
            index=HEARTBEAT_INDEX,
            body={
                "size": 1000,
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}],
            },
            _source=["hostname", "source_type", "status", "timestamp"],
        )
        seen = {}
        for hit in resp.get("hits", {}).get("hits", []):
            src = hit["_source"]
            hostname = src.get("hostname")
            if hostname and hostname not in seen:
                seen[hostname] = src
        return list(seen.values())
    except Exception:
        return []


@router.post("/yara/events", status_code=202)
async def ingest_yara_events(batch: List[dict], background_tasks: BackgroundTasks):
    """Batch ingest YARA scan events from agent."""
    count = 0
    for event in batch:
        try:
            try:
                opensearch.client.index(index=YARA_INDEX, body=event, refresh=False)
            except Exception:
                pass
            log_event = NormalizedLog(
                host=event.get("host", "unknown"),
                source="yara_scanner",
                log_type="yara",
                severity=event.get("severity", "HIGH"),
                message=event.get("message", ""),
                metadata=event.get("metadata", {}),
            )
            background_tasks.add_task(process_log_background, log_event)
            count += 1
        except Exception as e:
            logger.warning("Failed to index YARA event: %s", e)
    return {"status": "queued", "events_ingested": count}

@router.get("/yara/events", response_model=List[Dict[str, Any]])
async def list_yara_events(
    limit: int = Query(100, ge=1, le=1000),
    host: Optional[str] = None,
    rule_name: Optional[str] = None,
    severity: Optional[str] = None,
):
    """Get YARA events with filtering."""
    try:
        must = []
        if host:
            must.append({"term": {"host.keyword": host}})
        if rule_name:
            must.append({"term": {"metadata.yara_rule_name.keyword": rule_name}})
        if severity:
            must.append({"term": {"severity": severity}})
        query = {
            "size": limit,
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        try:
            resp = opensearch.client.search(index=YARA_INDEX, body=query)
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        except AttributeError:
            logger.warning("OpenSearch client not available for YARA query")
            return []
    except Exception as e:
        logger.warning("YARA events query failed: %s", e)
        return []

@router.get("/yara/stats", response_model=Dict[str, Any])
async def get_yara_stats():
    """Get YARA statistics for dashboard."""
    try:
        try:
            resp = opensearch.client.search(
                index=YARA_INDEX,
                body={
                    "size": 0,
                    "query": {"match_all": {}},
                    "aggs": {
                        "by_rule": {"terms": {"field": "metadata.yara_rule_name.keyword", "size": 20}},
                        "by_host": {"terms": {"field": "host.keyword", "size": 50}},
                        "by_severity": {"terms": {"field": "severity", "size": 10}},
                    },
                },
            )
            aggs = resp.get("aggregations", {})
            return {
                "by_rule_name": {
                    b["key"]: b["doc_count"] for b in aggs.get("by_rule", {}).get("buckets", [])
                },
                "by_host": {
                    b["key"]: b["doc_count"] for b in aggs.get("by_host", {}).get("buckets", [])
                },
                "by_severity": {
                    b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])
                },
                "total_events": resp["hits"]["total"]["value"] if "total" in resp["hits"] else 0,
            }
        except AttributeError:
            logger.warning("OpenSearch client not available for YARA stats")
            return {"by_rule_name": {}, "by_host": {}, "by_severity": {}, "total_events": 0}
    except Exception as e:
        logger.warning("YARA stats query failed: %s", e)
        return {"by_rule_name": {}, "by_host": {}, "by_severity": {}, "total_events": 0}

@router.get("/stats", response_model=Dict[str, Any])
async def get_logs_stats():
    """Get logs statistics for dashboard using OpenSearch aggregations (no full table scan)."""
    try:
        query = {
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "by_host": {"terms": {"field": "host", "size": 50}},
                "by_source": {"terms": {"field": "source", "size": 50}},
                "latest": {"top_hits": {"size": 1, "sort": [{"timestamp": {"order": "desc"}}]}},
                "earliest": {"top_hits": {"size": 1, "sort": [{"timestamp": {"order": "asc"}}]}},
            }
        }
        response = opensearch.client.search(index=opensearch.log_index, body=query)
        aggs = response.get("aggregations", {})
        total = response["hits"]["total"]["value"] if "total" in response["hits"] else 0

        severity_counts = {
            b["key"]: b["doc_count"]
            for b in aggs.get("by_severity", {}).get("buckets", [])
        }

        latest_hits = aggs.get("latest", {}).get("hits", {}).get("hits", [])
        earliest_hits = aggs.get("earliest", {}).get("hits", {}).get("hits", [])

        ingestion_rate = 0
        if latest_hits and earliest_hits:
            latest_ts = latest_hits[0].get("_source", {}).get("timestamp", "")
            earliest_ts = earliest_hits[0].get("_source", {}).get("timestamp", "")
            if latest_ts and earliest_ts:
                try:
                    if isinstance(latest_ts, str):
                        latest_ts = datetime.fromisoformat(latest_ts.replace('Z', '+00:00'))
                    if isinstance(earliest_ts, str):
                        earliest_ts = datetime.fromisoformat(earliest_ts.replace('Z', '+00:00'))
                    time_diff_hours = (latest_ts - earliest_ts).total_seconds() / 3600
                    ingestion_rate = total / max(time_diff_hours, 1) if time_diff_hours > 0 else 0
                except (ValueError, TypeError):
                    pass

        return {
            "total_logs": total,
            "ingestion_rate_per_hour": round(ingestion_rate, 2),
            "severity_distribution": severity_counts
        }
    except Exception as e:
        logger.warning("Stats query failed, returning empty stats: %s", e)
        return {"total_logs": 0, "ingestion_rate_per_hour": 0, "severity_distribution": {}}


@router.get("/verify", response_model=Dict[str, Any])
async def verify_logs_integrity(limit: int = Query(200, ge=1, le=1000)):
    """Spot-check stored logs: recompute log_hash and count mismatches.
    Any mismatch means telemetry was altered outside the ingest path."""
    logs = opensearch.get_logs_filtered(limit=limit, offset=0, sort_by="timestamp", sort_order="desc")
    checked, mismatched = 0, []
    for entry in logs:
        meta = entry.get("metadata") or {}
        sealed = meta.get("log_hash")
        if not sealed:
            continue  # ingested before sealing was enabled
        checked += 1
        if canonical_log_hash(entry) != sealed:
            mismatched.append({"timestamp": entry.get("timestamp"), "host": entry.get("host"),
                               "message": str(entry.get("message", ""))[:120]})
    return {"ok": len(mismatched) == 0, "checked": checked,
            "mismatched": len(mismatched), "samples": mismatched[:10]}


@router.delete("/purge")
async def purge_all_data(
    user: dict = Depends(require_roles(["ADMIN"])),
    confirm: bool = Query(False, description="Must be true — safety switch"),
    include_incidents: bool = Query(False, description="Also purge incident docs (refused when legal holds exist)"),
):
    """Delete telemetry. Safety rules (evidence protection):
    - requires ?confirm=true
    - incident docs only with ?include_incidents=true, and NEVER when any
      incident is under legal hold (check GET /api/incidents/holds/active first)
    - tamper-evident audit index (chaelsiem-audit-logs) is never purged here."""
    if not confirm:
        raise HTTPException(status_code=400, detail="Purge requires ?confirm=true")
    indices = [
        opensearch.log_index,
        opensearch.yara_index,
        "chaelsiem-source-heartbeats",
    ]
    if include_incidents:
        incidents = []
        try:
            resp = opensearch.client.search(
                index=opensearch.incident_index,
                body={"size": 1000, "query": {"term": {"legal_hold": True}}, "_source": ["incident_id"]},
                ignore_unavailable=True,
            )
            incidents = resp.get("hits", {}).get("hits", [])
        except Exception:
            pass
        if incidents:
            raise HTTPException(
                status_code=409,
                detail=f"Refused: {len(incidents)} incident(s) under legal hold. Release holds first.",
            )
        indices.append(opensearch.incident_index)
    deleted = []
    for idx in indices:
        try:
            if opensearch.client.indices.exists(index=idx):
                opensearch.client.delete_by_query(index=idx, body={"query": {"match_all": {}}})
                deleted.append(idx)
                logger.info("Purged index: %s", idx)
        except Exception as e:
            logger.warning("Failed to purge %s: %s", idx, e)
    return {"status": "purged", "indices": deleted}


