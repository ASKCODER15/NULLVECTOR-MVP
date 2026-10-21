from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "NullVector"
    PROJECT_VERSION: str = "0.2.0"

    DEBUG: bool = False

    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # LM Studio exposes an OpenAI-compatible API; the base URL must include
    # the API prefix because services append /chat/completions to it.
    LM_STUDIO_URL: str = "http://127.0.0.1:1234/v1"
    LM_STUDIO_MODEL: str = "qwen/qwen3-8b"

    # Upper bound for a single target call. A scan runs several of these.
    SCAN_TIMEOUT_SECONDS: int = 15

    QDRANT_URL: str = ""

    LOG_LEVEL: str = "INFO"

    # Comma-separated. Never use "*" with credentials enabled.
    CORS_ORIGINS: str = (
        "http://localhost:8501,http://127.0.0.1:8501,"
        "http://localhost:3000,http://127.0.0.1:3000,"
        "http://localhost:5173,http://127.0.0.1:5173"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @property
    def cors_origins(self) -> list:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


settings = Settings()