from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from storage.factory import get_storage_client

router = APIRouter()

class HuntIncidentParams(BaseModel):
    search: Optional[str] = None
    status: Optional[str] = None
    risk_score_min: Optional[int] = None
    risk_score_max: Optional[int] = None
    host: Optional[str] = None
    attack_type: Optional[str] = None
    limit: int = 50
    offset: int = 0
    sort_by: str = "timestamp"
    sort_order: str = "desc"

@router.post("/hunt")
async def hunt_incidents(params: HuntIncidentParams):
    """Hunt for incidents matching specified criteria."""
    try:
        storage = get_storage_client()
        results = storage.search_incidents(
            limit=params.limit,
            offset=params.offset,
            search=params.search,
            status=params.status,
            risk_score_min=params.risk_score_min,
            risk_score_max=params.risk_score_max,
            host=params.host,
            attack_type=params.attack_type,
            sort_by=params.sort_by,
            sort_order=params.sort_order
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Incident hunt failed: {str(e)}")
