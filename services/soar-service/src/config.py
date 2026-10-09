import os
import sys
from typing import ClassVar

sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def safe_int(value: str, default: int) -> int:
    """Safely convert string to integer with fallback"""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def strtobool(value: str) -> bool:
    """Convert string representation of truth to boolean"""
    return value.strip().lower() in ("true", "1", "t", "yes", "y")


class Settings:
    OPENSEARCH_HOST: ClassVar[str] = os.getenv("OPENSEARCH_HOST", "opensearch")
    OPENSEARCH_PORT: ClassVar[int] = safe_int(os.getenv("OPENSEARCH_PORT", "9200"), 9200)
    OPENSEARCH_USER: ClassVar[str] = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD: ClassVar[str] = os.getenv("OPENSEARCH_PASSWORD", "ChaelSIEMStrongPass1!")
    OPENSEARCH_USE_SSL: ClassVar[bool] = strtobool(os.getenv("OPENSEARCH_USE_SSL", "True"))
    OPENSEARCH_VERIFY_CERTS: ClassVar[bool] = strtobool(os.getenv("OPENSEARCH_VERIFY_CERTS", "False"))
    
    STORAGE_TYPE: ClassVar[str] = os.getenv("STORAGE_TYPE", "opensearch")  # Options: 'opensearch', 'local'
    
    API_HOST: ClassVar[str] = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: ClassVar[int] = safe_int(os.getenv("API_PORT", "8083"), 8083)

    LOG_LEVEL: ClassVar[str] = os.getenv("LOG_LEVEL", "INFO")

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

    # SOAR integration backends
    FIREWALL_BACKEND: ClassVar[str] = os.getenv("FIREWALL_BACKEND", "auto")
    HOST_ISOLATION_BACKEND: ClassVar[str] = os.getenv("HOST_ISOLATION_BACKEND", "auto")
    EDR_PROVIDER: ClassVar[str] = os.getenv("EDR_PROVIDER", "")

    # State persistence (approval queue + agent tasks survive restarts)
    SOAR_REDIS_ENABLED: ClassVar[str] = os.getenv("SOAR_REDIS_ENABLED", "true")
    REDIS_HOST: ClassVar[str] = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT: ClassVar[int] = safe_int(os.getenv("REDIS_PORT", "6379"), 6379)
    REDIS_PASSWORD: ClassVar[str] = os.getenv("REDIS_PASSWORD", "")


settings = Settings()
