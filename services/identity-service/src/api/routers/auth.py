import hmac
import logging
from fastapi import APIRouter, HTTPException, Response, Request
from pydantic import BaseModel
from jose import jwt, JWTError
from config import settings
from core.identity.jwt import create_access_token

logger = logging.getLogger(__name__)

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
async def login(request: LoginRequest, response: Response):
    role = ""
    username = ""
    if hmac.compare_digest(request.username, settings.ADMIN_USERNAME) and \
            hmac.compare_digest(request.password, settings.ADMIN_PASSWORD):
        role, username = "ADMIN", settings.ADMIN_USERNAME
    elif settings.APPROVER_USERNAME and hmac.compare_digest(request.username, settings.APPROVER_USERNAME) and \
            hmac.compare_digest(request.password, settings.APPROVER_PASSWORD):
        role, username = "APPROVER", settings.APPROVER_USERNAME
    elif settings.ANALYST_USERNAME and hmac.compare_digest(request.username, settings.ANALYST_USERNAME) and \
            hmac.compare_digest(request.password, settings.ANALYST_PASSWORD):
        role, username = "ANALYST", settings.ANALYST_USERNAME
    logger.info("Login attempt: username=%s success=%s role=%s", request.username, bool(role), role or "-")
    if role:
        tenant_id = settings.DEFAULT_TENANT_ID if settings.TENANT_MODE == "single" else username
        user_data = {
            "id": f"usr-{role.lower()}",
            "username": username,
            "role": role,
            "permissions": ["all"] if role == "ADMIN" else (
                ["soar:approve", "incidents:review"] if role == "APPROVER"
                else ["soar:trigger", "incidents:work"]),
            "tenant_id": tenant_id,
        }
        token = create_access_token(user_data)

        response.set_cookie(
            key="s2_token",
            value=token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

        return {"user": {"username": username, "role": role, "tenant_id": tenant_id}, "access_token": token, "token_type": "bearer"}

    raise HTTPException(status_code=401, detail="Invalid credentials")

@router.get("/validate")
async def validate_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        token = auth_header.split(" ", 1)[1]
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.JWT_ALGORITHM])
        return {"sub": payload.get("sub"), "role": payload.get("role"), "tenant_id": payload.get("tenant_id", settings.DEFAULT_TENANT_ID), "valid": True}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "identity-service"}

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("s2_token")
    return {"message": "Logged out"}
