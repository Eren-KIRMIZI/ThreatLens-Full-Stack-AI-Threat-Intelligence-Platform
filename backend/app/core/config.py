"""Application configuration loaded from environment / .env file."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed access to all runtime configuration.

    Values are read from environment variables or the `.env` file.
    Secrets (API keys) are never exposed to the API layer directly;
    they are consumed only inside backend services.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "ThreatLens"
    app_version: str = "0.1.0"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"

    # Secrets
    virustotal_api_key: str | None = None
    openrouter_api_key: str | None = None
    openrouter_model: str = "openrouter/auto"

    # Optional enrichment providers
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    threatfox_api_key: str | None = None
    malwarebazaar_api_key: str | None = None

    # Enrichment
    enrichment_timeout_seconds: float = 45.0

    # AI
    ai_assist_default: bool = False

    # Database
    # SQLite for development. Supabase/PostgreSQL: set to a postgresql+asyncpg:// URL.
    database_url: str = "sqlite+aiosqlite:///./threatlens.db"

    # Cache
    cache_ttl_seconds: int = 3600

    # Scheduler (0 disables the background watchlist rescan loop)
    watchlist_rescan_interval_seconds: int = 0

    # RBAC (opt-in; clients then send X-ThreatLens-Role: viewer|analyst|admin)
    rbac_enabled: bool = False

    # Uploads
    max_upload_size_mb: int = 32

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    """Return a cached, immutable settings instance."""
    return Settings()