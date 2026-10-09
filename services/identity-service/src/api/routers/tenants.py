import logging
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Optional
from opensearchpy import OpenSearch
from config import settings
from auth.middleware import require_roles

logger = logging.getLogger(__name__)

router = APIRouter()

TENANTS_INDEX = "chaelsiem-tenants"

class TenantCreate(BaseModel):
    tenant_id: str
    name: str
    admin_username: str
    admin_password: str

class TenantUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None

def _get_opensearch():
    return OpenSearch(
        hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
        http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD) if settings.OPENSEARCH_USER else None,
        use_ssl=settings.OPENSEARCH_USE_SSL,
        verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )

def _ensure_tenants_index(client):
    try:
        if not client.indices.exists(index=TENANTS_INDEX):
            client.indices.create(
                index=TENANTS_INDEX,
                body={
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                    "mappings": {
                        "properties": {
                            "tenant_id": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "admin_username": {"type": "keyword"},
                            "is_active": {"type": "boolean"},
                            "created_at": {"type": "date"},
                        }
                    },
                },
            )
            logger.info("Created index %s", TENANTS_INDEX)
    except Exception as e:
        logger.warning("Could not create index %s: %s", TENANTS_INDEX, e)

@router.get("/tenants")
async def list_tenants(request: Request, user: dict = Depends(require_roles(["ADMIN"]))):
    if settings.TENANT_MODE == "single":
        return {"tenants": [{"tenant_id": settings.DEFAULT_TENANT_ID, "name": "Default Tenant", "is_active": True}]}
    client = _get_opensearch()
    _ensure_tenants_index(client)
    try:
        res = client.search(index=TENANTS_INDEX, body={"query": {"match_all": {}}}, size=1000)
        tenants = [{"tenant_id": h["_source"]["tenant_id"], "name": h["_source"]["name"], "is_active": h["_source"].get("is_active", True)} for h in res["hits"]["hits"]]
        return {"tenants": tenants}
    except Exception as e:
        logger.error("Failed to list tenants: %s", e)
        return {"tenants": []}

@router.post("/tenants")
async def create_tenant(tenant: TenantCreate, user: dict = Depends(require_roles(["ADMIN"]))):
    if settings.TENANT_MODE == "single":
        raise HTTPException(status_code=400, detail="Single-tenant mode: cannot create tenants. Set TENANT_MODE=multi")
    client = _get_opensearch()
    _ensure_tenants_index(client)
    doc = {"tenant_id": tenant.tenant_id, "name": tenant.name, "admin_username": tenant.admin_username, "admin_password": tenant.admin_password, "is_active": True, "created_at": "now"}
    try:
        client.index(index=TENANTS_INDEX, id=tenant.tenant_id, body=doc, refresh=True)
        logger.info("Created tenant: %s (%s)", tenant.tenant_id, tenant.name)
        return {"status": "created", "tenant_id": tenant.tenant_id}
    except Exception as e:
        logger.error("Failed to create tenant: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create tenant")

@router.get("/tenants/{tenant_id}")
async def get_tenant(tenant_id: str, user: dict = Depends(require_roles(["ADMIN"]))):
    if settings.TENANT_MODE == "single":
        if tenant_id != settings.DEFAULT_TENANT_ID:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return {"tenant_id": tenant_id, "name": "Default Tenant", "is_active": True}
    client = _get_opensearch()
    try:
        res = client.get(index=TENANTS_INDEX, id=tenant_id)
        src = res["_source"]
        return {"tenant_id": src["tenant_id"], "name": src["name"], "is_active": src.get("is_active", True)}
    except Exception:
        raise HTTPException(status_code=404, detail="Tenant not found")

@router.put("/tenants/{tenant_id}")
async def update_tenant(tenant_id: str, update: TenantUpdate, user: dict = Depends(require_roles(["ADMIN"]))):
    if settings.TENANT_MODE == "single":
        raise HTTPException(status_code=400, detail="Single-tenant mode: cannot update tenants")
    client = _get_opensearch()
    body = {}
    if update.name is not None:
        body["name"] = update.name
    if update.is_active is not None:
        body["is_active"] = update.is_active
    if not body:
        return {"status": "noop"}
    try:
        client.update(index=TENANTS_INDEX, id=tenant_id, body={"doc": body}, refresh=True)
        return {"status": "updated", "tenant_id": tenant_id}
    except Exception as e:
        logger.error("Failed to update tenant %s: %s", tenant_id, e)
        raise HTTPException(status_code=500, detail="Failed to update tenant")

@router.delete("/tenants/{tenant_id}")
async def delete_tenant(tenant_id: str, user: dict = Depends(require_roles(["ADMIN"]))):
    if settings.TENANT_MODE == "single":
        raise HTTPException(status_code=400, detail="Single-tenant mode: cannot delete tenants")
    client = _get_opensearch()
    try:
        client.delete(index=TENANTS_INDEX, id=tenant_id, refresh=True)
        return {"status": "deleted", "tenant_id": tenant_id}
    except Exception:
        raise HTTPException(status_code=404, detail="Tenant not found")
