import os

class Settings:
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8091"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    OPENSEARCH_HOST: str = os.getenv("OPENSEARCH_HOST", "opensearch")
    OPENSEARCH_PORT: int = int(os.getenv("OPENSEARCH_PORT", "9200"))
    OPENSEARCH_USER: str = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD: str = os.getenv("OPENSEARCH_PASSWORD", "ChaelSIEMStrongPass1!")
    SIGMA_REPO_URL: str = os.getenv("SIGMA_REPO_URL", "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules")
    RULES_INDEX: str = "sigma-rules"
    CONVERTED_RULES_INDEX: str = "chael-correlation-rules"

settings = Settings()