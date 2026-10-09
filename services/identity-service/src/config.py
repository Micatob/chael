import os

class Settings:
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8004"))
    
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    @property
    def jwt_secret(self) -> str:
        if not self.JWT_SECRET:
            import logging as _log
            _log.warning("JWT_SECRET not set! Using auto-generated fallback (sessions invalidate on restart)")
            return os.urandom(32).hex()
        return self.JWT_SECRET

    TENANT_MODE: str = os.getenv("TENANT_MODE", "single")
    DEFAULT_TENANT_ID: str = os.getenv("DEFAULT_TENANT_ID", "default")

    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "ChaelSIEMStrongPass1!")

    # SOC role split (env-provisioned accounts; empty = disabled).
    # APPROVER: may approve/reject high-impact SOAR actions, may not trigger them.
    # ANALYST: may trigger playbooks + work incidents, may not approve.
    # ADMIN keeps both powers but can never approve its own triggers.
    APPROVER_USERNAME: str = os.getenv("APPROVER_USERNAME", "")
    APPROVER_PASSWORD: str = os.getenv("APPROVER_PASSWORD", "")
    ANALYST_USERNAME: str = os.getenv("ANALYST_USERNAME", "")
    ANALYST_PASSWORD: str = os.getenv("ANALYST_PASSWORD", "")

    OPENSEARCH_HOST: str = os.getenv("OPENSEARCH_HOST", "opensearch")
    OPENSEARCH_PORT: int = int(os.getenv("OPENSEARCH_PORT", "9200"))
    OPENSEARCH_USER: str = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD: str = os.getenv("OPENSEARCH_PASSWORD", "ChaelSIEMStrongPass1!")
    OPENSEARCH_USE_SSL: str = os.getenv("OPENSEARCH_USE_SSL", "True").lower() == "true"
    OPENSEARCH_VERIFY_CERTS: str = os.getenv("OPENSEARCH_VERIFY_CERTS", "False").lower() == "true"

    AGENT_TOKEN_EXPIRE_HOURS: int = 24
    LATEST_AGENT_VERSION: str = os.getenv("LATEST_AGENT_VERSION", "1.0.0")
    AGENT_DOWNLOAD_URL: str = os.getenv("AGENT_DOWNLOAD_URL", "")
    AGENT_UPDATE_CHECK_INTERVAL_MINUTES: int = int(os.getenv("AGENT_UPDATE_CHECK_INTERVAL_MINUTES", "60"))

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

settings = Settings()
