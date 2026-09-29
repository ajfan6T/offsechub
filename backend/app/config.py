from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime configuration. Every field can be overridden with an OFFSECHUB_* env var."""

    model_config = SettingsConfigDict(env_prefix="OFFSECHUB_", env_file=".env", extra="ignore")

    database_url: str = f"sqlite:///{BASE_DIR / 'data' / 'runtime' / 'offsechub.db'}"
    storage_dir: Path = BASE_DIR / "data" / "runtime" / "evidence"
    frontend_dist: Path = BASE_DIR.parent / "frontend" / "dist"

    # Session cookie settings. Set cookie_secure=true whenever served over HTTPS.
    session_cookie_name: str = "offsechub_session"
    session_ttl_hours: int = 12
    cookie_secure: bool = False

    max_upload_mb: int = 50

    # Bootstrap admin, created on first start when the user table is empty.
    admin_email: str = "admin@offsechub.local"
    admin_password: str | None = None

    # Login brute-force protection.
    login_max_attempts: int = 10
    login_window_seconds: int = 300

    # Allowed origins for cross-origin API access (e.g. the Vite dev server).
    cors_origins: list[str] = []

    # Interactive API docs at /api/docs. Disable in production if not needed.
    api_docs: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
