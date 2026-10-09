import os
from typing import ClassVar

def safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

class Settings:
    OPENSEARCH_HOST: ClassVar[str] = os.getenv("OPENSEARCH_HOST", "opensearch")
    OPENSEARCH_PORT: ClassVar[int] = safe_int(os.getenv("OPENSEARCH_PORT", "9200"), 9200)
    OPENSEARCH_USER: ClassVar[str] = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD: ClassVar[str] = os.getenv("OPENSEARCH_PASSWORD", "ChaelSIEMStrongPass1!")
    OPENSEARCH_USE_SSL: ClassVar[bool] = os.getenv("OPENSEARCH_USE_SSL", "True").lower() == "true"
    OPENSEARCH_VERIFY_CERTS: ClassVar[bool] = os.getenv("OPENSEARCH_VERIFY_CERTS", "False").lower() == "true"
    
    DEFAULT_TENANT_ID: ClassVar[str] = os.getenv("DEFAULT_TENANT_ID", "default")
    JWT_SECRET: ClassVar[str] = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: ClassVar[str] = "HS256"

    @property
    def jwt_secret(self) -> str:
        if not self.JWT_SECRET:
            import logging as _log
            _log.warning("JWT_SECRET not set! Using auto-generated fallback (sessions invalidate on restart)")
            return os.urandom(32).hex()
        return self.JWT_SECRET

    INCIDENT_SERVICE_URL: ClassVar[str] = os.getenv("INCIDENT_SERVICE_URL", "http://incident-management-service:8082")
    API_PORT: ClassVar[int] = safe_int(os.getenv("API_PORT", "8084"), 8084)
    POLL_INTERVAL_MINUTES: ClassVar[int] = safe_int(os.getenv("POLL_INTERVAL_MINUTES", "15"), 15)
    LOG_LEVEL: ClassVar[str] = os.getenv("LOG_LEVEL", "INFO")

settings = Settings()
