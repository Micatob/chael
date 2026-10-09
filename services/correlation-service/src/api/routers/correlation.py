import json
import logging
import os
from fastapi import APIRouter, BackgroundTasks, Body, Depends
from models.schema import NormalizedLog
from detection.correlation import CorrelationEngine
from storage.factory import get_storage_client
from auth.middleware import require_roles
import requests

logger = logging.getLogger(__name__)

router = APIRouter()
correlation = CorrelationEngine()
opensearch = get_storage_client()

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "correlation-service"}

def process_incident_background(incident):
    try:
        # Index incident
        opensearch.index_incident(incident)

        # Serialize incident to JSON-safe dict (handles datetime objects)
        incident_data = json.loads(incident.json())
        
        soar_url = os.getenv("SOAR_SERVICE_URL", "http://soar-service:8083") + "/api/soar/trigger"
        response = requests.post(soar_url, json=incident_data)
        if response.status_code != 200:
            logger.warning("Failed to trigger SOAR: %d", response.status_code)

        im_url = os.getenv("INCIDENT_MGMT_URL", "http://incident-management-service:8082") + "/api/incidents/create"
        response = requests.post(im_url, json=incident_data)
        if response.status_code != 201:
            logger.warning("Failed to create incident in management: %d", response.status_code)
    except Exception as e:
        logger.error("Error processing incident: %s", e)

@router.post("/process", status_code=200, dependencies=[Depends(require_roles(["ADMIN"]))])
async def process_log(log_data: dict, background_tasks: BackgroundTasks):
    """Process log for correlation."""
    try:
        log = NormalizedLog(**log_data)
        incident = correlation.process_log(log)
        if incident:
            logger.info("Incident triggered: %s", incident.description)
            background_tasks.add_task(process_incident_background, incident)
        return {"status": "processed"}
    except Exception as e:
        logger.error("Process error: %s", e)
        return {"error": str(e)}