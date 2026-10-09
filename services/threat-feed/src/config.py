import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


class Settings:
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "8090"))

    OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
    OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
    OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "ChaelSIEMStrongPass1!")
    OPENSEARCH_USE_SSL = os.getenv("OPENSEARCH_USE_SSL", "True").lower() == "true"
    OPENSEARCH_VERIFY_CERTS = os.getenv("OPENSEARCH_VERIFY_CERTS", "False").lower() == "true"

    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    POLL_INTERVAL_MINUTES = int(os.getenv("POLL_INTERVAL_MINUTES", "60"))

    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    DEFAULT_TENANT_ID: str = os.getenv("DEFAULT_TENANT_ID", "default")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"

    @property
    def jwt_secret(self) -> str:
        if not self.JWT_SECRET:
            import logging as _log
            _log.warning("JWT_SECRET not set! Using auto-generated fallback (sessions invalidate on restart)")
            return os.urandom(32).hex()
        return self.JWT_SECRET


settings = Settings()
