import os

class Settings:
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8085"))

    OPENSEARCH_HOST: str = os.getenv("OPENSEARCH_HOST", "opensearch")
    OPENSEARCH_PORT: int = int(os.getenv("OPENSEARCH_PORT", "9200"))
    OPENSEARCH_USER: str = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD: str = os.getenv("OPENSEARCH_PASSWORD", "ChaelSIEMStrongPass1!")
    OPENSEARCH_USE_SSL: str = os.getenv("OPENSEARCH_USE_SSL", "True").lower() == "true"
    OPENSEARCH_VERIFY_CERTS: str = os.getenv("OPENSEARCH_VERIFY_CERTS", "False").lower() == "true"

    NETFLOW_PORT: int = int(os.getenv("NETFLOW_PORT", "2055"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"
    DEFAULT_TENANT_ID: str = os.getenv("DEFAULT_TENANT_ID", "default")

    @property
    def jwt_secret(self) -> str:
        if not self.JWT_SECRET:
            import logging as _log
            _log.warning("JWT_SECRET not set! Using auto-generated fallback (sessions invalidate on restart)")
            return os.urandom(32).hex()
        return self.JWT_SECRET

settings = Settings()
