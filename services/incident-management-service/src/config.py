import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class Settings:
    OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
    OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
    OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "ChaelSIEMStrongPass1!")
    OPENSEARCH_USE_SSL = os.getenv("OPENSEARCH_USE_SSL", "True").lower() == "true"
    OPENSEARCH_VERIFY_CERTS = os.getenv("OPENSEARCH_VERIFY_CERTS", "False").lower() == "true"
    
    STORAGE_TYPE = os.getenv("STORAGE_TYPE", "opensearch")  # Options: 'opensearch', 'local'
    
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "8082"))

    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    DEFAULT_TENANT_ID: str = os.getenv("DEFAULT_TENANT_ID", "default")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"

    # Outbound dispatch: mitigation actions are queued as real agent tasks
    # in SOAR (never simulated). Service JWT via identity admin creds.
    SOAR_SERVICE_URL: str = os.getenv("SOAR_SERVICE_URL", "http://soar-service:8083")
    IDENTITY_SERVICE_URL: str = os.getenv("IDENTITY_SERVICE_URL", "http://identity-service:8004")
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")

    @property
    def jwt_secret(self) -> str:
        if not self.JWT_SECRET:
            import logging as _log
            _log.warning("JWT_SECRET not set! Using auto-generated fallback (sessions invalidate on restart)")
            return os.urandom(32).hex()
        return self.JWT_SECRET

settings = Settings()
