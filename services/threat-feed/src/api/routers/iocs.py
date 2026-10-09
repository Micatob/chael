import logging
import csv
import io
import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, UploadFile, File, Body
from typing import Dict, Any, List
from pydantic import BaseModel
from storage.opensearch_client import OpenSearchFeedStorage

logger = logging.getLogger(__name__)

router = APIRouter()
store = OpenSearchFeedStorage()


class BulkIOCRequest(BaseModel):
    iocs: List[Dict[str, Any]]


@router.post("/iocs/bulk", status_code=201)
async def bulk_upload_iocs(payload: BulkIOCRequest):
    count = 0
    errors = []
    for ioc in payload.iocs:
        try:
            ioc_type = ioc.get("type", "").upper()
            value = ioc.get("value", "").strip()
            if not value:
                continue
            if ioc_type not in ("IP_ADDRESS", "DOMAIN", "URL", "HASH_MD5", "HASH_SHA1", "HASH_SHA256"):
                continue
            doc = {
                "ioc_id": str(uuid.uuid4()),
                "type": ioc_type,
                "value": value,
                "description": ioc.get("description", ""),
                "source": ioc.get("source", "manual_upload"),
                "confidence": ioc.get("confidence", "medium"),
                "tags": ioc.get("tags", []),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": ioc.get("expires_at"),
            }
            store.client.index(index="chaelsiem-threat-feed", body=doc, refresh=False)
            count += 1
        except Exception as e:
            errors.append({"value": ioc.get("value"), "error": str(e)})
    logger.info("Bulk uploaded %d IOCs with %d errors", count, len(errors))
    return {"status": "completed", "uploaded": count, "errors": errors}


@router.post("/iocs/bulk/csv", status_code=201)
async def bulk_upload_csv(file: UploadFile = File(...)):
    count = 0
    errors = []
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            try:
                ioc_type = row.get("type", "").strip().upper()
                value = row.get("value", "").strip()
                if not value or not ioc_type:
                    continue
                if ioc_type not in ("IP_ADDRESS", "DOMAIN", "URL", "HASH_MD5", "HASH_SHA1", "HASH_SHA256"):
                    continue
                doc = {
                    "ioc_id": str(uuid.uuid4()),
                    "type": ioc_type,
                    "value": value,
                    "description": row.get("description", ""),
                    "source": "csv_upload",
                    "confidence": row.get("confidence", "medium"),
                    "tags": [t.strip() for t in row.get("tags", "").split(",") if t.strip()],
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                store.client.index(index="chaelsiem-threat-feed", body=doc, refresh=False)
                count += 1
            except Exception as e:
                errors.append({"row": row.get("value"), "error": str(e)})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV parse error: {str(e)}")
    logger.info("CSV uploaded %d IOCs with %d errors", count, len(errors))
    return {"status": "completed", "uploaded": count, "errors": errors}
