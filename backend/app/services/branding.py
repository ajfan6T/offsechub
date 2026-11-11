"""Report branding and report assets (DOCX templates, the logo).

Branding lives in the vault's settings (``report.branding``); the logo and any
uploaded DOCX templates are ``ReportAsset`` rows, i.e. inside the encrypted
database. Every report format (HTML, DOCX, PDF) reads the same ``branding``
dict from the report context.
"""

import base64
import hashlib
import re
from typing import Any

from sqlalchemy.orm import Session

from ..bootstrap import get_setting, set_setting
from ..models import ReportAsset

SETTING = "report.branding"
DEFAULT_ACCENT = "#0f766e"
DEFAULT_CLASSIFICATION = "CONFIDENTIAL"
MAX_LOGO_BYTES = 1024 * 1024
MAX_TEMPLATE_BYTES = 5 * 1024 * 1024
LOGO_TYPES = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff"}
HEX_COLOUR = re.compile(r"^#[0-9a-fA-F]{6}$")

DEFAULTS: dict[str, Any] = {
    "organization": "",
    "accent": DEFAULT_ACCENT,
    "classification": DEFAULT_CLASSIFICATION,
    "footer": "",
    "logo_id": None,
    "default_template_id": None,
}


class AssetError(ValueError):
    pass


def load_settings(db: Session) -> dict[str, Any]:
    stored = get_setting(db, SETTING) or {}
    return {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS}}


def save_settings(db: Session, values: dict[str, Any]) -> dict[str, Any]:
    current = load_settings(db)
    current.update({k: v for k, v in values.items() if k in DEFAULTS})
    if not HEX_COLOUR.match(current["accent"] or ""):
        raise AssetError("accent must be a colour like #0f766e")
    for key, kind in (("logo_id", "logo"), ("default_template_id", "template")):
        if current[key] is not None and get_asset(db, current[key], kind) is None:
            raise AssetError(f"no {kind} with id {current[key]}")
    set_setting(db, SETTING, current)
    return current


def get_asset(db: Session, asset_id: int, kind: str) -> ReportAsset | None:
    asset = db.get(ReportAsset, asset_id)
    return asset if asset is not None and asset.kind == kind else None


def report_branding(db: Session, profile: dict) -> dict[str, Any]:
    """The ``branding`` dict of the report context (logo bytes included)."""
    s = load_settings(db)
    logo = get_asset(db, s["logo_id"], "logo") if s["logo_id"] is not None else None
    return {
        "organization": (s["organization"] or profile.get("organization") or "").strip(),
        "accent": s["accent"] if HEX_COLOUR.match(s["accent"] or "") else DEFAULT_ACCENT,
        "classification": (s["classification"] or "").strip(),
        "footer": (s["footer"] or "").strip(),
        "logo": logo.data if logo else None,
        "logo_content_type": logo.content_type if logo else None,
        "logo_data_uri": (f"data:{logo.content_type};base64,{base64.b64encode(logo.data).decode()}"
                          if logo else None),
    }


def check_logo(data: bytes) -> str:
    """Return the logo's content type, judged by its bytes, not its name."""
    if len(data) > MAX_LOGO_BYTES:
        raise AssetError("the logo must be at most 1 MB")
    for ctype, magic in LOGO_TYPES.items():
        if data.startswith(magic):
            return ctype
    raise AssetError("the logo must be a PNG or JPEG image")


def add_asset(db: Session, *, kind: str, name: str, filename: str, content_type: str,
              data: bytes) -> ReportAsset:
    asset = ReportAsset(kind=kind, name=name[:255], filename=filename[:255],
                        content_type=content_type, size=len(data),
                        sha256=hashlib.sha256(data).hexdigest(), data=data)
    db.add(asset)
    db.flush()
    return asset
