import logging
from fastapi import APIRouter, HTTPException, Query, Request
from models.schema import FlowRecord, FlowStats
from storage.opensearch_client import OpenSearchClient
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

router = APIRouter()
opensearch = OpenSearchClient()

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "flow-collector"}

@router.post("/ingest", status_code=202)
async def ingest_flow(flow: FlowRecord, request: Request):
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        flow.tenant_id = tenant_id
    try:
        opensearch.index_flow(flow)
        return {"status": "queued", "flow": f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store flow: {str(e)}")

@router.post("/ingest/batch", status_code=202)
async def ingest_flows_batch(flows: List[FlowRecord], request: Request):
    tenant_id = getattr(request.state, "tenant_id", None)
    ingested = 0
    for flow in flows:
        if tenant_id:
            flow.tenant_id = tenant_id
        try:
            opensearch.index_flow(flow)
            ingested += 1
        except Exception as e:
            logger.warning(f"Failed to store flow: {e}")
    return {"status": "queued", "ingested": ingested, "total": len(flows)}

@router.get("/", response_model=List[Dict[str, Any]])
async def list_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    min_bytes: Optional[int] = None,
    sort_by: str = Query("timestamp", pattern="^(timestamp|bytes|packets|duration_seconds|src_ip|dst_ip)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$")
):
    return opensearch.get_flows(
        limit=limit, offset=offset,
        src_ip=src_ip, dst_ip=dst_ip,
        protocol=protocol, min_bytes=min_bytes,
        sort_by=sort_by, sort_order=sort_order
    )

@router.get("/stats", response_model=Dict[str, Any])
async def get_flow_stats():
    return opensearch.get_flow_stats()

@router.get("/top-ports", response_model=List[Dict[str, Any]])
async def get_top_ports(limit: int = Query(20, ge=1, le=100)):
    stats = opensearch.get_flow_stats()
    return stats.get("top_ports", [])[:limit]

@router.get("/top-talkers", response_model=List[Dict[str, Any]])
async def get_top_talkers(limit: int = Query(20, ge=1, le=100)):
    stats = opensearch.get_flow_stats()
    return stats.get("top_src_ips", [])[:limit]
