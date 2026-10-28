"""
Agni Core Configuration & Environment Settings
"""
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application runtime settings with environment overrides."""

    # Project Identity
    PROJECT_NAME: str = "Agni (अग्नि) Threat Detection Engine"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Network Security Binding
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    ALLOW_EXTERNAL_BIND: bool = False

    # Base Directories
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = Path(__file__).resolve().parent.parent.parent / "data"
    DATABASE_URL: str | None = None
    RULES_DIR: Path = Path(__file__).resolve().parent.parent.parent / "rules"
    EXPORTS_DIR: Path = Path(__file__).resolve().parent.parent.parent / "exports"

    # CORS Allowed Origins
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # Telemetry & Monitoring Intervals
    TELEMETRY_INTERVAL_SECONDS: int = 5
    FIM_POLL_INTERVAL_SECONDS: int = 60
    NETWORK_POLL_INTERVAL_SECONDS: int = 15
    CORRELATION_WINDOW_SECONDS: int = 300
    EVENT_RETENTION_DAYS: int = 30

    # Operational Limits & Safety
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    MAX_FIM_FILE_SIZE_BYTES: int = 100 * 1024 * 1024  # 100 MB
    MAX_SOCKETS_PER_CYCLE: int = 2000

    # Demo & Sample Mode
    DEMO_MODE_DEFAULT: bool = False

    model_config = SettingsConfigDict(
        env_prefix="AGNI_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("HOST")
    @classmethod
    def validate_loopback_host(cls, v: str, info) -> str:
        """Enforces that Agni strictly binds to local loopback addresses."""
        loopback_hosts = {"127.0.0.1", "localhost", "::1"}
        allow_external = info.data.get("ALLOW_EXTERNAL_BIND", False)
        if not allow_external and v not in loopback_hosts:
            raise ValueError(
                f"Security violation: Agni is configured to bind to external host '{v}'. "
                f"Loopback binding ('127.0.0.1') is required for defense in depth. "
                f"Set AGNI_ALLOW_EXTERNAL_BIND=true only if explicitly authorized."
            )
        return v

    def get_database_url(self) -> str:
        """Returns SQLite database URL with formatted POSIX path."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        db_path = (self.DATA_DIR / "agni.db").resolve()
        return f"sqlite:///{db_path.as_posix()}"

    def ensure_directories(self) -> None:
        """Create required local runtime directories safely."""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.RULES_DIR.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    settings = Settings()
    settings.ensure_directories()
    return settings
