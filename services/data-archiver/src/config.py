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
    OPENSEARCH_PASSWORD: ClassVar[str] = os.getenv("OPENSEARCH_PASSWORD", "")
    OPENSEARCH_USE_SSL: ClassVar[bool] = os.getenv("OPENSEARCH_USE_SSL", "True").lower() == "true"
    OPENSEARCH_VERIFY_CERTS: ClassVar[bool] = os.getenv("OPENSEARCH_VERIFY_CERTS", "False").lower() == "true"
    
    ARCHIVE_RETENTION_DAYS: ClassVar[int] = safe_int(os.getenv("ARCHIVE_RETENTION_DAYS", "30"), 30)
    ARCHIVE_DIR: ClassVar[str] = os.getenv("ARCHIVE_DIR", "/archive")
    ARCHIVE_SCHEDULE_CRON: ClassVar[str] = os.getenv("ARCHIVE_SCHEDULE_CRON", "0 2 * * *") # Default: 2 AM daily

    # SOC digest reports (built from OpenSearch, sent over SMTP)
    DIGEST_ENABLED: ClassVar[bool] = os.getenv("DIGEST_ENABLED", "true").lower() == "true"
    DIGEST_DAILY_CRON: ClassVar[str] = os.getenv("DIGEST_DAILY_CRON", "0 8 * * *")
    DIGEST_WEEKLY_CRON: ClassVar[str] = os.getenv("DIGEST_WEEKLY_CRON", "0 9 * * 1")
    SMTP_HOST: ClassVar[str] = os.getenv("SMTP_HOST", "")
    SMTP_PORT: ClassVar[int] = safe_int(os.getenv("SMTP_PORT", "587"), 587)
    SMTP_USER: ClassVar[str] = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: ClassVar[str] = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM: ClassVar[str] = os.getenv("SMTP_FROM", "siem@chael.local")
    SMTP_TO: ClassVar[str] = os.getenv("SMTP_TO", "")
    SMTP_TLS: ClassVar[bool] = os.getenv("SMTP_TLS", "true").lower() == "true"

    # Service auth (shares identity-service JWT; gateway already enforces
    # auth_request on /api/backup/, this is defense-in-depth for direct callers)
    JWT_SECRET: ClassVar[str] = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: ClassVar[str] = "HS256"
    DEFAULT_TENANT_ID: ClassVar[str] = os.getenv("DEFAULT_TENANT_ID", "default")

settings = Settings()
