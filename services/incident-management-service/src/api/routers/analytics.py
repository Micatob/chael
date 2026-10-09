from fastapi import APIRouter
from typing import Dict, Any
from storage.factory import get_storage_client

router = APIRouter()

@router.get("/health")
async def analytics_health():
    return {"status": "healthy", "service": "incident-management-service"}

@router.get("/overview")
async def get_analytics_overview():
    stats = get_storage_client().get_analytics()
    stats["ingestion_trend"] = get_storage_client().get_log_trend()
    return stats
