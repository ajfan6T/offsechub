"""Per-vault setup that runs every time a vault is created or unlocked."""

import json
import logging
from collections.abc import Callable
from pathlib import Path

from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

from .db import Base
from .models import FindingTemplate, Setting
from .services import cvss
from .vault.manager import DEFAULT_AUTO_LOCK_MIN, OpenVault, VaultError, VaultManager

log = logging.getLogger("offsechub")
TEMPLATES_FILE = Path(__file__).resolve().parent / "data" / "finding_templates.json"
# Bump when an older OffsecHub must refuse to open the vault (it would ignore new
# tables or columns and could leave them inconsistent), and add a migration.
SCHEMA_VERSION = 2


def get_setting(db: Session, key: str, default=None):
    row = db.get(Setting, key)
    return default if row is None else row.value


def set_setting(db: Session, key: str, value) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def seed_finding_templates(db: Session) -> int:
    if db.scalar(select(func.count(FindingTemplate.id))):
        return 0
    entries = json.loads(TEMPLATES_FILE.read_text())
    for e in entries:
        if e.get("cvss_vector"):
            e["cvss_vector"] = cvss.calculate(e["cvss_vector"]).vector
        db.add(FindingTemplate(**e))
    return len(entries)


def _migrate_v2(db: Session) -> None:
    """0.3.0: retests, report templates and the branding logo.

    Their tables are new, so ``create_all`` has already made them; this step
    only records that the vault now needs OffsecHub 0.3.0 or later.
    """


MIGRATIONS: dict[int, Callable[[Session], None]] = {2: _migrate_v2}


def make_unlock_hook(manager: VaultManager):
    def on_unlock(vault: OpenVault) -> None:
        with vault.session() as db:
            existing = set(inspect(db.connection()).get_table_names())
            Base.metadata.create_all(bind=db.connection())
            created_tables = existing != set(Base.metadata.tables)
            version = get_setting(db, "schema.version")
            if version is None:
                set_setting(db, "schema.version", SCHEMA_VERSION)
                seed_finding_templates(db)
            elif version > SCHEMA_VERSION:
                raise VaultError("this vault was created by a newer version of OffsecHub; "
                                 "please upgrade to open it")
            elif version < SCHEMA_VERSION:
                for step in range(version + 1, SCHEMA_VERSION + 1):
                    MIGRATIONS[step](db)
                    log.info("vault schema migrated to version %d", step)
                set_setting(db, "schema.version", SCHEMA_VERSION)
            manager.auto_lock_minutes = int(
                get_setting(db, "vault.auto_lock_minutes", DEFAULT_AUTO_LOCK_MIN)
            )
            # Only commit real changes: every commit schedules an encrypted save.
            if created_tables or db.new or db.dirty:
                db.commit()
            else:
                db.rollback()

    return on_unlock
