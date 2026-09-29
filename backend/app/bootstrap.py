"""First-run setup: schema, bootstrap admin and the default finding library."""

import json
import logging
import secrets
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import db as db_module
from .config import get_settings
from .models import FindingTemplate, User
from .security import hash_password
from .services import cvss

log = logging.getLogger("offsechub")
TEMPLATES_FILE = Path(__file__).resolve().parent / "data" / "finding_templates.json"


def init_db() -> None:
    settings = get_settings()
    if settings.database_url.startswith("sqlite:///"):
        Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    db_module.Base.metadata.create_all(db_module.engine)


def ensure_admin(db: Session) -> None:
    if db.scalar(select(func.count(User.id))):
        return
    settings = get_settings()
    password = settings.admin_password or secrets.token_urlsafe(18)
    db.add(User(email=settings.admin_email.lower(), full_name="Administrator", role="admin",
                password_hash=hash_password(password)))
    db.commit()
    if settings.admin_password:
        log.warning("Created admin user %s", settings.admin_email)
    else:
        # Printed once so the operator can sign in; change it immediately.
        log.warning("Created admin user %s with generated password: %s", settings.admin_email, password)


def seed_finding_templates(db: Session) -> int:
    if db.scalar(select(func.count(FindingTemplate.id))):
        return 0
    entries = json.loads(TEMPLATES_FILE.read_text())
    for e in entries:
        if e.get("cvss_vector"):
            e["cvss_vector"] = cvss.calculate(e["cvss_vector"]).vector
        db.add(FindingTemplate(**e))
    db.commit()
    return len(entries)


def bootstrap() -> None:
    init_db()
    with db_module.SessionLocal() as db:
        ensure_admin(db)
        seed_finding_templates(db)
