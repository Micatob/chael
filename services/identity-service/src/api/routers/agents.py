import logging
import secrets
import uuid
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import hashlib
from config import settings
from core.identity.jwt import create_access_token
from storage.agent_store import AgentStore
from auth.middleware import require_roles
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter()
store = AgentStore()


class AgentRegisterRequest(BaseModel):
    hostname: str
    metadata: dict = {}


class AgentRegisterResponse(BaseModel):
    agent_id: str
    agent_key: str
    hostname: str


class AgentListResponse(BaseModel):
    agent_id: str
    hostname: str
    last_seen: str = ""
    current_version: str = ""
    online: bool = False


class AgentVerifyRequest(BaseModel):
    agent_id: str
    agent_key: str


class AgentVerifyResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_hours: int = 24


class AgentAutoRegisterRequest(BaseModel):
    agent_name: str
    hostname: str = ""
    metadata: dict = {}


@router.post("/agent/register", response_model=AgentRegisterResponse)
async def register_agent(request: AgentRegisterRequest, user: dict = Depends(require_roles(["ADMIN"]))):
    agent_id = str(uuid.uuid4())
    agent_key = secrets.token_hex(32)
    agent_key_hash = hashlib.sha256(agent_key.encode()).hexdigest()
    hostname = request.hostname or "unknown"

    success = store.register_agent(
        agent_id=agent_id,
        machine_id=agent_id,
        hostname=hostname,
        api_key_hash=agent_key_hash,
        agent_key_raw=agent_key,
        agent_version="1.0.0",
        metadata={"auto_registered": True, "agent_name": request.agent_name, **request.metadata},
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to register agent")

    logger.info("Registered agent id=%s hostname=%s by %s", agent_id, hostname, user.get("username", "unknown"))
    return AgentRegisterResponse(agent_id=agent_id, agent_key=agent_key, hostname=hostname)


@router.post("/agent/auto-register", response_model=AgentRegisterResponse)
async def auto_register_agent(request: AgentAutoRegisterRequest):
    hostname = request.hostname or request.agent_name
    existing = store.get_agent_by_hostname(hostname)
    if existing and existing.get("status") != "revoked":
        agent_key = existing.get("agent_key_raw") or secrets.token_hex(32)
        agent_key_hash = hashlib.sha256(agent_key.encode()).hexdigest()
        store.update_agent_key(existing["agent_id"], agent_key_hash, agent_key)
        logger.info("Re-registered existing agent id=%s hostname=%s with preserved key", existing["agent_id"], hostname)
        return AgentRegisterResponse(agent_id=existing["agent_id"], agent_key=agent_key, hostname=hostname)

    agent_id = str(uuid.uuid4())
    agent_key = secrets.token_hex(32)
    agent_key_hash = hashlib.sha256(agent_key.encode()).hexdigest()

    success = store.register_agent(
        agent_id=agent_id,
        machine_id=agent_id,
        hostname=hostname,
        api_key_hash=agent_key_hash,
        agent_key_raw=agent_key,
        agent_version="1.0.0",
        metadata={"auto_registered": True, "agent_name": request.agent_name, **request.metadata},
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to register agent")

    logger.info("Auto-registered agent id=%s name=%s hostname=%s", agent_id, request.agent_name, hostname)
    return AgentRegisterResponse(agent_id=agent_id, agent_key=agent_key, hostname=hostname)


@router.post("/agent/verify", response_model=AgentVerifyResponse)
async def verify_agent(request: AgentVerifyRequest):
    agent = store.get_agent(request.agent_id)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent_id or agent_key")

    if agent.get("status") == "revoked":
        raise HTTPException(status_code=401, detail="Agent has been revoked")

    if hashlib.sha256(request.agent_key.encode()).hexdigest() != agent.get("api_key_hash", ""):
        raise HTTPException(status_code=401, detail="Invalid agent_id or agent_key")

    store.mark_online(request.agent_id)

    user_data = {
        "id": request.agent_id,
        "username": f"agent:{agent.get('hostname', 'unknown')}",
        "role": "AGENT",
        "permissions": ["logs:ingest", "logs:read"],
    }
    token = create_access_token(user_data)

    logger.info("Agent verified id=%s hostname=%s", request.agent_id, agent.get("hostname"))
    return AgentVerifyResponse(access_token=token, token_type="bearer", expires_in_hours=settings.AGENT_TOKEN_EXPIRE_HOURS)


@router.post("/agent/{agent_id}/mark-online")
async def mark_agent_online(agent_id: str):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    store.mark_online(agent_id)
    return {"status": "online", "agent_id": agent_id}


@router.get("/agent/{agent_id}/config")
async def get_agent_config(agent_id: str, user: dict = Depends(require_roles(["ADMIN", "AGENT"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    config = agent.get("metadata", {})
    default_config = {
        "windows_event_ids": [4624, 4625, 4634, 4648, 4672, 4740, 4720, 4722, 4723, 4724, 4725, 4726, 4732, 4738,
                              4673, 4674, 4688, 4719, 4739, 4656, 4663, 4657, 4608, 4697, 7045, 1102, 4103, 4104,
                              4768, 4769, 4771, 4772, 4778, 4779, 5156, 4698],
        "windows_log": "Security",
        "powershell_log": True,
        "sysmon_log": True,
        "defender_log": True,
        "poll_interval": 2,
        "batch_size": 50,
    }
    merged = {**default_config, **config}
    return {"agent_id": agent_id, "config": merged}


@router.put("/agent/{agent_id}/config")
async def update_agent_config(agent_id: str, config: dict, user: dict = Depends(require_roles(["ADMIN"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    store.update_heartbeat(agent_id=agent_id, metadata=config)
    logger.info("Updated config for agent id=%s by %s", agent_id, user.get("username", "unknown"))
    return {"message": f"Agent {agent_id} config updated", "config": config}


@router.delete("/agent/{agent_id}")
async def revoke_agent(agent_id: str, user: dict = Depends(require_roles(["ADMIN"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    success = store.revoke_agent(agent_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to revoke agent")

    logger.info("Revoked agent id=%s", agent_id)
    return {"message": f"Agent {agent_id} revoked"}


@router.post("/agent/{agent_id}/rotate")
async def rotate_agent_key(agent_id: str, user: dict = Depends(require_roles(["ADMIN"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    new_key = secrets.token_hex(32)
    new_hash = hashlib.sha256(new_key.encode()).hexdigest()

    success = store.rotate_api_key(agent_id, new_hash)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to rotate key")

    logger.info("Rotated key for agent id=%s", agent_id)
    return {"agent_id": agent_id, "agent_key": new_key}


@router.get("/agent/version")
async def get_agent_version():
    return {
        "latest_version": settings.LATEST_AGENT_VERSION,
        "download_url": settings.AGENT_DOWNLOAD_URL,
        "release_date": "",
        "changelog": "",
        "minimum_version": "1.0.0",
    }


@router.post("/agent/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, payload: dict = {}):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    current_version = payload.get("version", "")
    metadata = payload.get("metadata", {})
    store.update_heartbeat(
        agent_id=agent_id,
        status="online",
        version=current_version,
        metadata=metadata,
    )

    update_available = False
    if current_version and settings.LATEST_AGENT_VERSION:
        update_available = current_version != settings.LATEST_AGENT_VERSION

    return {
        "status": "acknowledged",
        "update_available": update_available,
        "latest_version": settings.LATEST_AGENT_VERSION,
    }


@router.get("/agents", response_model=list[AgentListResponse])
async def list_agents(include_revoked: bool = False, user: dict = Depends(require_roles(["ADMIN"]))):
    agents = store.list_agents(include_revoked=include_revoked)
    now = datetime.now(timezone.utc)
    results = []
    for a in agents:
        online = False
        last_seen = a.get("last_seen", "")
        if last_seen:
            try:
                last_seen_dt = datetime.fromisoformat(last_seen)
                online = (now - last_seen_dt).total_seconds() < 120
            except Exception:
                online = False
        results.append(AgentListResponse(
            agent_id=a["agent_id"],
            hostname=a.get("hostname", ""),
            last_seen=last_seen if isinstance(last_seen, str) else "",
            current_version=a.get("agent_version", ""),
            online=online,
        ))
    return results


@router.delete("/agent/{agent_id}/hard")
async def delete_agent(agent_id: str, user: dict = Depends(require_roles(["ADMIN"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    success = store.delete_agent(agent_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete agent")

    logger.info("Deleted agent id=%s permanently by %s", agent_id, user.get("username", "unknown"))
    return {"message": f"Agent {agent_id} permanently deleted"}


@router.delete("/agents/purge")
async def purge_all_agents(user: dict = Depends(require_roles(["ADMIN"]))):
    agents = store.list_agents(include_revoked=True)
    count = len(agents)
    for a in agents:
        store.delete_agent(a["agent_id"])
    logger.info("Purged %d agents by %s", count, user.get("username", "unknown"))
    return {"message": f"Purged {count} agents", "count": count}
