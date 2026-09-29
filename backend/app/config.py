import sys
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


def _default_dist() -> Path:
    # Inside a PyInstaller bundle, data files live under sys._MEIPASS.
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        return Path(bundle) / "frontend" / "dist"
    return BASE_DIR.parent / "frontend" / "dist"


class Settings(BaseSettings):
    """Process-level settings (OFFSECHUB_* env vars). Vault settings live in the vault."""

    model_config = SettingsConfigDict(env_prefix="OFFSECHUB_", extra="ignore")

    frontend_dist: Path = _default_dist()
    max_upload_mb: int = 512


@lru_cache
def get_settings() -> Settings:
    return Settings()
