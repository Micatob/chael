from datetime import datetime, timedelta, timezone
from jose import jwt
from config import settings
import uuid

# In-memory revoked JTIs: jti -> exp epoch. Single-node safe; restart clears
# (sessions invalidate on restart when JWT_SECRET is auto-generated anyway).
_REVOKED_JTIS: dict = {}


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "jti": str(uuid.uuid4())})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def revoke_jti(jti: str, exp_epoch: float = 0):
    if jti:
        _REVOKED_JTIS[jti] = exp_epoch or 9999999999.0


def is_jti_revoked(jti: str) -> bool:
    if not jti:
        return False
    exp = _REVOKED_JTIS.get(jti)
    if exp is None:
        return False
    import time as _time
    if exp < _time.time():
        _REVOKED_JTIS.pop(jti, None)
        return False
    return True
