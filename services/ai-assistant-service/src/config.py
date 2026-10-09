import os


def safe_int(v: str, default: int) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


class Settings:
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = safe_int(os.getenv("API_PORT", "8093"), 8093)
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Multi-provider AI (opt-in, BYOK, privacy-first). Service works WITHOUT a key
    # via the deterministic local fallback. Providers activate when their key is set
    # and AI_ENABLED=true. On rate-limit/5xx/timeout, provider-model lines cool down
    # and calls rotate to the next line (OpenRouter models -> Groq backup).
    AI_ENABLED: bool = os.getenv("AI_ENABLED", "false").lower() == "true"
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")
    GROQ_BASE_URL: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    # Comma-separated Groq model failover list — 429/5xx/timeout rotates to next.
    # Verified live 2026-09-22: qwen/qwen3.8-27b (primary, clean instruction
    # following), openai/gpt-oss-20b (backup), groq/compound-mini (tool-using).
    # NOTE: llama-3.3-70b-versatile is RETIRED by Groq (404) — do not use.
    GROQ_MODELS: str = os.getenv(
        "GROQ_MODELS",
        "qwen/qwen3.8-27b,openai/gpt-oss-20b,groq/compound-mini",
    )
    GROQ_TIMEOUT_S: int = safe_int(os.getenv("GROQ_TIMEOUT_S", "8"), 8)
    GROQ_MAX_TOKENS: int = safe_int(os.getenv("GROQ_MAX_TOKENS", "800"), 800)

    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_BASE_URL: str = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    # Comma-separated model list — 429/5xx advances to the next model.
    OPENROUTER_MODELS: str = os.getenv(
        "OPENROUTER_MODELS",
        "meta-llama/llama-3.3-70b-instruct,deepseek/deepseek-chat,qwen/qwen-2.5-72b-instruct",
    )
    AI_PROVIDER_ORDER: str = os.getenv("AI_PROVIDER_ORDER", "groq,gemini,openrouter")
    AI_TIMEOUT_S: int = safe_int(os.getenv("AI_TIMEOUT_S", "30"), 30)
    AI_KEY_COOLDOWN_S: int = safe_int(os.getenv("AI_KEY_COOLDOWN_S", "300"), 300)

    # Third provider: Google Gemini via OpenAI-compatible endpoint
    # (https://generativelanguage.googleapis.com/v1beta/openai/).
    # Free tier is generous, good reasoning, joins the same
    # per-model circuit-breaker / auto-failover rotation as Groq + OpenRouter.
    # Get a key at https://aistudio.google.com/apikey.
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_BASE_URL: str = os.getenv(
        "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"
    )
    # Comma-separated Gemini model failover list.
    GEMINI_MODELS: str = os.getenv(
        "GEMINI_MODELS",
        "gemini-2.5-flash,gemini-2.0-flash",
    )
    GEMINI_TIMEOUT_S: int = safe_int(os.getenv("GEMINI_TIMEOUT_S", "30"), 30)
    GEMINI_MAX_TOKENS: int = safe_int(os.getenv("GEMINI_MAX_TOKENS", "1500"), 1500)

    REDIS_HOST: str = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT: int = safe_int(os.getenv("REDIS_PORT", "6379"), 6379)
    REDIS_DB: int = safe_int(os.getenv("REDIS_DB", "0"), 0)

    INCIDENT_SERVICE_URL: str = os.getenv("INCIDENT_SERVICE_URL", "http://incident-management-service:8082")
    OPENSEARCH_HOST: str = os.getenv("OPENSEARCH_HOST", "opensearch")

    # Machine-to-machine auth so the assistant can read live SIEM state
    # (log stats, incident list/detail) for grounded chat. Uses the same admin
    # login as analysts; token cached ~12h (server expiry 24h), refreshed on 401.
    IDENTITY_SERVICE_URL: str = os.getenv("IDENTITY_SERVICE_URL", "http://identity-service:8004")
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")

    # Safety rails (what makes this better than push-button AI in big SIEMs)
    AI_MAX_INCIDENTS_PER_HOUR: int = safe_int(os.getenv("AI_MAX_INCIDENTS_PER_HOUR", "60"), 60)
    AI_CACHE_TTL_S: int = safe_int(os.getenv("AI_CACHE_TTL_S", "3600"), 3600)

    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"

    @property
    def jwt_secret(self) -> str:
        return self.JWT_SECRET
    DEFAULT_TENANT_ID: str = os.getenv("DEFAULT_TENANT_ID", "default")


settings = Settings()
