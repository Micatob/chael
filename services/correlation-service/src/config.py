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
    API_PORT = int(os.getenv("API_PORT", "8081"))

    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    DEFAULT_TENANT_ID: str = os.getenv("DEFAULT_TENANT_ID", "default")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"

    @property
    def jwt_secret(self) -> str:
        if not self.JWT_SECRET:
            import logging as _log
            _log.warning("JWT_SECRET not set! Using auto-generated fallback (sessions will invalidate on restart)")
            return os.urandom(32).hex()
        return self.JWT_SECRET

    REDIS_HOST = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
    REDIS_SOCKET_TIMEOUT = int(os.getenv("REDIS_SOCKET_TIMEOUT", "5"))
    REDIS_SOCKET_CONNECT_TIMEOUT = int(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT", "3"))

    BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "10"))
    BRUTE_FORCE_WINDOW_SECONDS = int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", "300"))
    REPEATED_ERROR_THRESHOLD = int(os.getenv("REPEATED_ERROR_THRESHOLD", "20"))
    REPEATED_ERROR_WINDOW_SECONDS = int(os.getenv("REPEATED_ERROR_WINDOW_SECONDS", "600"))

settings = Settings()
