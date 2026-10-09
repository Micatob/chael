import json
import logging
import secrets
import uuid
import hashlib
import hmac
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from config import settings
from storage.agent_store import AgentStore
from core.ca import CertificateAuthority
from core.identity.jwt import create_access_token
from auth.middleware import require_roles

log = logging.getLogger("identity-service.agent-registration")

router = APIRouter()
store = AgentStore()
ca = CertificateAuthority()


class RegisterRequest(BaseModel):
    machine_id: str
    hostname: str
    platform: str = ""
    platform_version: str = ""
    os_info: str = ""
    public_key: str = ""
    signature: str = ""
    agent_version: str = ""


class RegisterResponse(BaseModel):
    agent_id: str
    certificate: str = ""
    ca_certificate: str = ""
    api_key: str = ""
    auth_method: str = "mtls"
    server_ca_fingerprint: str = ""


class VerifyRequest(BaseModel):
    agent_id: str
    api_key: str = ""
    signature: str = ""
    timestamp: str = ""


class HeartbeatRequest(BaseModel):
    version: str = ""
    status: str = "online"
    metadata: Dict[str, Any] = {}


@router.post("/agents/register", response_model=RegisterResponse)
async def register_agent(req: RegisterRequest):
    existing = store.get_agent_by_machine_id(req.machine_id)
    if existing:
        if existing["status"] == "revoked":
            raise HTTPException(status_code=403, detail="Agent has been revoked")
        agent_id = existing["agent_id"]
        log.info("Re-registering agent %s (machine: %s)", agent_id, req.machine_id)

        if req.public_key and existing.get("public_key_pem"):
            cert_pem, ca_pem = ca.sign_agent_cert(
                req.machine_id, req.hostname, req.public_key
            )
            store.register_agent(
                agent_id=agent_id, machine_id=req.machine_id,
                hostname=req.hostname, platform=req.platform,
                platform_version=req.platform_version, os_info=req.os_info,
                public_key_pem=req.public_key,
                client_cert_pem=cert_pem, ca_cert_pem=ca_pem,
                agent_version=req.agent_version, metadata={"last_renewal": datetime.now(timezone.utc).isoformat()},
            )
            return RegisterResponse(
                agent_id=agent_id, certificate=cert_pem,
                ca_certificate=ca_pem, auth_method="mtls",
            )

        api_key = existing.get("agent_key_raw") or secrets.token_hex(32)
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        store.update_agent_key(agent_id, api_key_hash, api_key)
        return RegisterResponse(
            agent_id=agent_id, api_key=api_key,
            auth_method="api_key",
        )

    agent_id = str(uuid.uuid4())
    auth_method = "api_key"

    if req.public_key:
        try:
            cert_pem, ca_pem = ca.sign_agent_cert(
                req.machine_id, req.hostname, req.public_key
            )
            api_key_hash = ""
            store.register_agent(
                agent_id=agent_id, machine_id=req.machine_id,
                hostname=req.hostname, platform=req.platform,
                platform_version=req.platform_version, os_info=req.os_info,
                public_key_pem=req.public_key,
                client_cert_pem=cert_pem, ca_cert_pem=ca_pem,
                agent_version=req.agent_version,
            )
            auth_method = "mtls"
            log.info("New mTLS agent %s (machine: %s, hostname: %s)", agent_id, req.machine_id, req.hostname)
            return RegisterResponse(
                agent_id=agent_id, certificate=cert_pem,
                ca_certificate=ca_pem, auth_method="mtls",
            )
        except Exception as e:
            log.warning("mTLS registration failed for %s, falling back to API key: %s", req.machine_id, e)

    api_key = secrets.token_hex(32)
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    store.register_agent(
        agent_id=agent_id, machine_id=req.machine_id,
        hostname=req.hostname, platform=req.platform,
        platform_version=req.platform_version, os_info=req.os_info,
        api_key_hash=api_key_hash, agent_key_raw=api_key,
        agent_version=req.agent_version,
    )
    log.info("New API-key agent %s (machine: %s, hostname: %s)", agent_id, req.machine_id, req.hostname)
    return RegisterResponse(agent_id=agent_id, api_key=api_key, auth_method="api_key")


@router.post("/agents/verify")
async def verify_agent(req: VerifyRequest):
    agent = store.get_agent(req.agent_id)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent_id")

    if agent["status"] == "revoked":
        raise HTTPException(status_code=403, detail="Agent has been revoked")

    api_key_hash = hashlib.sha256(req.api_key.encode()).hexdigest()
    if api_key_hash != agent.get("api_key_hash", ""):
        raise HTTPException(status_code=401, detail="Invalid API key")

    user_data = {
        "id": req.agent_id,
        "username": f"agent:{agent.get('hostname', 'unknown')}",
        "role": "AGENT",
        "permissions": ["logs:ingest", "logs:read"],
        "machine_id": agent.get("machine_id", ""),
    }
    token = create_access_token(user_data)
    return {"access_token": token, "token_type": "bearer", "expires_in_hours": 24}


@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, req: HeartbeatRequest):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    store.update_heartbeat(
        agent_id=agent_id, status=req.status,
        version=req.version, metadata=req.metadata,
    )

    update_available = False
    if req.version and settings.LATEST_AGENT_VERSION:
        update_available = req.version != settings.LATEST_AGENT_VERSION

    return {
        "status": "acknowledged",
        "update_available": update_available,
        "latest_version": settings.LATEST_AGENT_VERSION,
    }


@router.get("/agents/summary")
async def agents_summary(user: dict = Depends(require_roles(["ADMIN"]))):
    return store.get_agent_status_summary()


@router.get("/agents/status/dashboard")
async def agent_dashboard(user: dict = Depends(require_roles(["ADMIN"]))):
    agents = store.list_agents(include_revoked=False)
    now = datetime.now(timezone.utc)
    online_agents = []
    offline_count = 0
    for a in agents:
        last_seen = a.get("last_seen", "")
        is_online = False
        if last_seen:
            try:
                is_online = (now - datetime.fromisoformat(last_seen)).total_seconds() < 120
            except Exception:
                pass
        if is_online:
            online_agents.append({
                "agent_id": a.get("agent_id"),
                "hostname": a.get("hostname"),
                "platform": a.get("platform"),
                "version": a.get("agent_version"),
                "last_seen": last_seen,
            })
        else:
            offline_count += 1

    summary = store.get_agent_status_summary()
    return {
        "summary": summary,
        "online_agents": online_agents,
        "offline_count": offline_count,
        "total_agents": len(agents),
    }


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, user: dict = Depends(require_roles(["ADMIN"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.pop("api_key_hash", None)
    agent.pop("public_key_pem", None)
    agent.pop("client_cert_pem", None)
    agent.pop("ca_cert_pem", None)
    return agent


@router.get("/agents", response_model=list[Dict[str, Any]])
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
        results.append({
            "agent_id": a.get("agent_id", ""),
            "hostname": a.get("hostname", ""),
            "machine_id": a.get("machine_id", ""),
            "platform": a.get("platform", ""),
            "agent_version": a.get("agent_version", ""),
            "status": "online" if online else ("offline" if a.get("status") in ("online", "offline") else a.get("status", "")),
            "last_seen": last_seen,
            "registered_at": a.get("registered_at", ""),
        })
    return results


@router.post("/agents/{agent_id}/revoke")
async def revoke_agent(agent_id: str, reason: str = "", user: dict = Depends(require_roles(["ADMIN"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    store.revoke_agent(agent_id, reason=reason)
    return {"status": "revoked", "agent_id": agent_id}


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str, user: dict = Depends(require_roles(["ADMIN"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    store.delete_agent(agent_id)
    return {"status": "deleted", "agent_id": agent_id}


@router.post("/agents/{agent_id}/rotate-key")
async def rotate_api_key(agent_id: str, user: dict = Depends(require_roles(["ADMIN"]))):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    new_key = secrets.token_hex(32)
    new_hash = hashlib.sha256(new_key.encode()).hexdigest()
    store.rotate_api_key(agent_id, new_hash)
    return {"agent_id": agent_id, "api_key": new_key}


@router.get("/agents/{agent_id}/heartbeats")
async def agent_heartbeat_history(agent_id: str, limit: int = 50, user: dict = Depends(require_roles(["ADMIN"]))):
    return store.get_recent_heartbeats(agent_id, limit=limit)
