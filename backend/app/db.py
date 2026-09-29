"""SQLAlchemy base and the request → vault session dependency.

There is no global engine: the only database is the in-memory SQLite of the
currently unlocked vault (see app/vault/manager.py).
"""

from collections.abc import Iterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import DeclarativeBase, Session

from .vault.manager import OpenVault, VaultLocked, VaultManager


class Base(DeclarativeBase):
    pass


LOCKED_DETAIL = "The vault is locked"


def get_manager(request: Request) -> VaultManager:
    return request.app.state.vaults


def get_vault(manager: VaultManager = Depends(get_manager)) -> OpenVault:
    try:
        return manager.require()
    except VaultLocked:
        raise HTTPException(423, LOCKED_DETAIL) from None


def _vault_session(vault: OpenVault = Depends(get_vault)) -> Iterator[Session]:
    try:
        with vault.session() as session:
            yield session
    except VaultLocked:
        raise HTTPException(423, LOCKED_DETAIL) from None


def get_db(session: Session = Depends(_vault_session, scope="function")) -> Session:
    """A session with exclusive access to the vault DB for the endpoint's duration.

    ``scope="function"`` closes it (releasing the vault's DB lock) right after
    the response is serialized but *before* it is sent, so the group-commit
    middleware can wait for the save without deadlocking against it.
    Never lock the vault (or call vault.save()) while holding this session.
    """
    return session
