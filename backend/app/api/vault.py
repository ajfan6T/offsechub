"""Vault lifecycle, settings, operator profile and app-level endpoints."""

import platform
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import __version__
from ..bootstrap import get_setting, set_setting
from ..db import get_db, get_manager, get_vault
from ..services import audit
from ..vault.appconfig import default_vault_dir
from ..vault.manager import OpenVault, VaultError, VaultInUse, VaultManager, WrongSecret

router = APIRouter(tags=["vault"])


class CreateIn(BaseModel):
    path: str = Field(min_length=1)
    password: str


class UnlockIn(BaseModel):
    path: str = Field(min_length=1)
    password: str | None = None
    recovery_key: str | None = None
    recovery_kit: dict | None = None  # only needed if every vault.json copy is lost


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class PasswordIn(BaseModel):
    password: str


class VaultSettings(BaseModel):
    auto_lock_minutes: int = Field(ge=0, le=480)


class Profile(BaseModel):
    name: str = Field(default="", max_length=255)
    email: str = Field(default="", max_length=255)
    organization: str = Field(default="", max_length=255)


class ForgetIn(BaseModel):
    path: str | None = None


class Preferences(BaseModel):
    remember_recent: bool


def _log(vault: OpenVault, summary: str, action: str = "update") -> None:
    with vault.session() as db:
        audit.record(db, action=action, entity_type="vault", summary=summary)
        db.commit()


# ------------------------------------------------------------------ lifecycle


@router.get("/api/vault/status")
def vault_status(manager: VaultManager = Depends(get_manager)):
    return manager.status()


@router.post("/api/vault/create", status_code=201)
def create_vault(body: CreateIn, manager: VaultManager = Depends(get_manager)):
    try:
        info = manager.create(Path(body.path), body.password)
    except VaultInUse as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    except (VaultError, OSError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    _log(manager.require(), "Created vault", action="create")
    return {"recovery_key": info.key, "recovery_kit": info.kit, "status": manager.status()}


@router.post("/api/vault/unlock")
def unlock_vault(body: UnlockIn, manager: VaultManager = Depends(get_manager)):
    if not body.password and not body.recovery_key:
        raise HTTPException(422, "password or recovery_key is required")
    try:
        manager.unlock(Path(body.path), password=body.password, recovery_key=body.recovery_key,
                       recovery_kit=body.recovery_kit)
    except WrongSecret as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    except VaultInUse as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    except VaultError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    vault = manager.require()
    how = "recovery key" if body.recovery_key else "password"
    notes = [*vault.warnings, *vault.notices]
    _log(vault, f"Unlocked with {how}" + (f" ({'; '.join(notes)})" if notes else ""), action="unlock")
    return manager.status()


@router.post("/api/vault/lock")
def lock_vault(manager: VaultManager = Depends(get_manager)):
    try:
        manager.lock(reason="manual")
    except VaultError as exc:  # could not even seal the database: stays unlocked
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None
    return manager.status()


@router.post("/api/vault/close")
def close_vault(manager: VaultManager = Depends(get_manager)):
    """Lock and return to the vault picker."""
    try:
        manager.forget()
    except VaultError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None
    return manager.status()


@router.post("/api/vault/change-password", status_code=204)
def change_password(body: ChangePasswordIn, vault: OpenVault = Depends(get_vault)):
    try:
        vault.change_password(body.current_password, body.new_password)
    except WrongSecret as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    except VaultError as exc:
        raise HTTPException(422, str(exc)) from None
    _log(vault, "Changed vault password")


class ResetIn(BaseModel):
    recovery_key: str
    new_password: str


@router.post("/api/vault/reset-password")
def reset_password(body: ResetIn, vault: OpenVault = Depends(get_vault)):
    """After unlocking with the recovery key: choose a new password.

    The recovery key has now been typed outside its safe place, so it is
    rotated at the same time and the new one is returned (shown once).
    """
    if not vault.must_set_password:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only needed after unlocking with the recovery key")
    try:
        info = vault.reset_password(body.recovery_key, body.new_password)
    except WrongSecret as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    except VaultError as exc:
        raise HTTPException(422, str(exc)) from None
    _log(vault, "Set a new password after recovery and rotated the recovery key")
    return {"recovery_key": info.key, "recovery_kit": info.kit}


@router.post("/api/vault/rekey")
def rekey(body: PasswordIn, vault: OpenVault = Depends(get_vault)):
    """Replace the master key after a suspected compromise of a password or backup."""
    try:
        info = vault.rekey(body.password)
    except WrongSecret as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    _log(vault, "Rekeyed the vault: old headers and credentials can no longer decrypt new data")
    return {"recovery_key": info.key, "recovery_kit": info.kit}


@router.post("/api/vault/recovery-key")
def rotate_recovery_key(body: PasswordIn, vault: OpenVault = Depends(get_vault)):
    try:
        info = vault.rotate_recovery_key(body.password)
    except WrongSecret as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    _log(vault, "Generated a new recovery key (the previous one no longer opens this vault)")
    return {"recovery_key": info.key, "recovery_kit": info.kit}


@router.get("/api/vault/recovery-kit")
def recovery_kit(vault: OpenVault = Depends(get_vault)):
    """The current recovery slot (no secret): with the recovery key it restores a lost header."""
    return vault.recovery_kit()


class BackupIn(BaseModel):
    path: str = Field(min_length=1)


@router.post("/api/vault/backup")
def backup_vault(body: BackupIn, vault: OpenVault = Depends(get_vault)):
    """Write a consistent, verified copy of the vault (still encrypted) to a new folder."""
    try:
        result = vault.export_backup(Path(body.path))
    except (VaultError, OSError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    _log(vault, f"Exported an encrypted backup to {result['path']}", action="export")
    return result


@router.post("/api/vault/verify")
def verify_vault(vault: OpenVault = Depends(get_vault)):
    """Authenticate every evidence file against its recorded fingerprint."""
    return vault.verify()


@router.get("/api/vault/settings", response_model=VaultSettings)
def get_vault_settings(manager: VaultManager = Depends(get_manager), _db: Session = Depends(get_db)):
    return VaultSettings(auto_lock_minutes=manager.auto_lock_minutes)


@router.put("/api/vault/settings", response_model=VaultSettings)
def put_vault_settings(body: VaultSettings, manager: VaultManager = Depends(get_manager),
                       db: Session = Depends(get_db)):
    set_setting(db, "vault.auto_lock_minutes", body.auto_lock_minutes)
    audit.record(db, action="update", entity_type="vault",
                 summary=f"Auto-lock set to {body.auto_lock_minutes or 'never'} minutes")
    db.commit()
    manager.auto_lock_minutes = body.auto_lock_minutes
    manager.touch()
    return body


# -------------------------------------------------------------------- profile


@router.get("/api/profile", response_model=Profile)
def get_profile(db: Session = Depends(get_db)):
    return Profile(**(get_setting(db, "operator.profile") or {}))


@router.put("/api/profile", response_model=Profile)
def put_profile(body: Profile, db: Session = Depends(get_db)):
    set_setting(db, "operator.profile", body.model_dump())
    db.commit()
    return body


# ------------------------------------------------------------------------ app


@router.get("/api/app/info")
def app_info(request: Request):
    return {
        "version": __version__,
        "desktop": bool(getattr(request.app.state, "desktop", False)),
        "platform": platform.system(),
        "default_vault_dir": str(default_vault_dir()),
    }


@router.get("/api/app/recent")
def recent_vaults(manager: VaultManager = Depends(get_manager)):
    return {
        "remember_recent": manager.config.remember_recent,
        "vaults": [
            {"path": p, "name": Path(p).name.removesuffix(".ohvault"),
             "exists": (Path(p) / "vault.json").exists()}
            for p in manager.config.recent()
        ],
    }


@router.post("/api/app/recent/forget", status_code=204)
def forget_recent(body: ForgetIn, manager: VaultManager = Depends(get_manager)):
    manager.config.forget_recent(body.path)


@router.put("/api/app/preferences", status_code=204)
def set_preferences(body: Preferences, manager: VaultManager = Depends(get_manager)):
    manager.config.set_remember_recent(body.remember_recent)


@router.post("/api/app/activity", status_code=204)
def user_activity():
    """Heartbeat from the UI on real user input; resets the auto-lock timer (in middleware)."""


@router.post("/api/app/launch-link")
def launch_link(request: Request):
    """New one-time browser link. CLI only (bearer token), never the UI."""
    if getattr(request.state, "auth_kind", None) != "bearer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only available to the CLI")
    auth = request.app.state.auth
    return {"url": auth.launch_url(request.app.state.port)}
