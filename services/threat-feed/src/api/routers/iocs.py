import logging
import csv
import io
import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, UploadFile, File, Body, Query
from typing import Dict, Any, List
from pydantic import BaseModel
from storage.opensearch_client import OpenSearchFeedStorage

logger = logging.getLogger(__name__)

router = APIRouter()
store = OpenSearchFeedStorage()

# Fixed TAXII collection id so clients can pin it (stable across restarts).
_TAXII_COLLECTION_ID = "5f3f2c1a-7b4e-4d9a-8c1e-000000000001"

_CONF_MAP = {"low": 30, "medium": 60, "high": 85}


def _list_iocs(limit: int = 100) -> List[Dict[str, Any]]:
    """Newest-first IOC list, capped. Empty (never 500) when OS is down."""
    limit = max(1, min(int(limit), 500))
    try:
        client = getattr(store, "client", None)
        if client is None:
            return []
        resp = client.search(
            index="chaelsiem-threat-feed",
            body={"query": {"match_all": {}}, "sort": [{"created_at": {"order": "desc", "unmapped_type": "date"}}], "size": limit},
            ignore_unavailable=True,
        )
        return [h.get("_source", {}) for h in (resp.get("hits", {}).get("hits", []) or [])]
    except Exception as e:
        logger.warning("STIX list failed: %s", e)
        return []


def _ioc_to_pattern(ioc: Dict[str, Any]) -> str | None:
    t = str(ioc.get("type", "")).upper()
    v = str(ioc.get("value", "")).strip().replace("'", "")
    if not v:
        return None
    if t == "IP_ADDRESS":
        return f"[ipv4-addr:value='{v}']" if ":" not in v else f"[ipv6-addr:value='{v}']"
    if t == "DOMAIN":
        return f"[domain-name:value='{v}']"
    if t == "URL":
        return f"[url:value='{v}']"
    if t in ("HASH_MD5", "HASH_SHA1", "HASH_SHA256"):
        algo = {"HASH_MD5": "MD5", "HASH_SHA1": "SHA-1", "HASH_SHA256": "SHA-256"}[t]
        return f"[file:hashes.'{algo}'='{v}']"
    return None


def _ioc_to_indicator(ioc: Dict[str, Any]) -> Dict[str, Any] | None:
    pattern = _ioc_to_pattern(ioc)
    if not pattern:
        return None
    created = str(ioc.get("created_at") or datetime.now(timezone.utc).isoformat())
    conf = _CONF_MAP.get(str(ioc.get("confidence", "medium")).lower(), 60)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "labels": ["malicious-activity"],
        "confidence": conf,
        "description": str(ioc.get("description", ""))[:512],
    }


def _stix_bundle(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--c9d5f4f1-7b3a-4a1e-9f2e-chaelsiem0001",
        "created": now,
        "modified": now,
        "name": "Chael SIEM",
        "identity_class": "system",
    }
    objects: List[Dict[str, Any]] = [identity]
    for ioc in iocs:
        ind = _ioc_to_indicator(ioc)
        if ind:
            objects.append(ind)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


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


@router.get("/stix")
async def export_stix(limit: int = Query(100, ge=1, le=500)):
    """STIX 2.1 bundle of stored IOCs (no new deps, stdlib only). Empty objects (never 500) when feed is down."""
    iocs = _list_iocs(limit)
    return _stix_bundle(iocs)


@router.get("/taxii/collections")
async def taxii_collections():
    """Minimal TAXII 2.1 collection discovery (single read-only IOC collection)."""
    return {"collections": [{"id": _TAXII_COLLECTION_ID, "title": "Chael SIEM IOCs",
                             "description": "Manual + feed IOCs as STIX 2.1 indicators",
                             "can_read": True, "can_write": False}]}


@router.get("/taxii/collections/{collection_id}/objects")
async def taxii_objects(collection_id: str, limit: int = Query(100, ge=1, le=500)):
    """Minimal TAXII 2.1 objects envelope for the IOC collection."""
    if collection_id != _TAXII_COLLECTION_ID:
        raise HTTPException(status_code=404, detail="Unknown collection")
    iocs = _list_iocs(limit)
    return _stix_bundle(iocs)
