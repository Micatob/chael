import logging
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from storage.opensearch_client import OpenSearchFeedStorage

logger = logging.getLogger(__name__)

router = APIRouter()
store = OpenSearchFeedStorage()


@router.get("/health")
async def health():
    healthy = store.health()
    return {"status": "healthy" if healthy else "degraded", "service": "threat-feed"}


@router.get("/enrich/ip/{ip}")
async def enrich_ip(ip: str):
    results = store.search("value", ip)
    if not results:
        return {"ip": ip, "matches": [], "total": 0}
    return {"ip": ip, "matches": results, "total": len(results)}


@router.get("/enrich/domain/{domain}")
async def enrich_domain(domain: str):
    results = store.search("value", domain)
    if not results:
        return {"domain": domain, "matches": [], "total": 0}
    return {"domain": domain, "matches": results, "total": len(results)}


@router.get("/enrich/hash/{file_hash}")
async def enrich_hash(file_hash: str):
    results = store.search("value", file_hash)
    if not results:
        return {"hash": file_hash, "matches": [], "total": 0}
    return {"hash": file_hash, "matches": results, "total": len(results)}
