"""Engagement hand-off files: export one engagement encrypted, import it into another vault."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..db import get_vault
from ..deps import get_engagement
from ..models import Engagement
from ..schemas import ClientOut, ImportOut, OplogOut, ScopeItemOut, TestCaseOut
from ..services import audit, handoff, storage
from ..vault import header as vault_header
from ..vault.manager import OpenVault, VaultLocked
from . import activity, engagements, evidence, findings, recon, scope, targets, testing
from .evidence import vault_session

router = APIRouter(tags=["handoff"])
PASSPHRASE_HEADER = "X-Handoff-Passphrase"
MAX_HANDOFF_BYTES = 8 * 1024 * 1024 * 1024


class HandoffExportIn(BaseModel):
    directory: str = Field(min_length=1)
    passphrase: str = Field(min_length=1, max_length=1024)
    filename: str | None = Field(default=None, max_length=200)


@router.post("/api/engagements/{engagement_id}/handoff")
def export_handoff(engagement_id: int, body: HandoffExportIn, vault: OpenVault = Depends(get_vault)):
    """Write the engagement, with its evidence, to a passphrase-encrypted file in ``directory``."""
    with vault_session(vault) as db:
        eng = get_engagement(engagement_id, db)
        manifest, blobs = handoff.build_manifest(eng)
        code = eng.code
        db.rollback()
    name = storage.sanitize_filename(body.filename or f"{code}{handoff.SUFFIX}")
    if not name.endswith(handoff.SUFFIX):
        name += handoff.SUFFIX
    dest = Path(body.directory).expanduser() / name
    try:
        size = handoff.write_handoff(vault, manifest, blobs, body.passphrase, dest, vault_header.DEFAULT_ARGON2)
    except handoff.HandoffError as exc:
        raise HTTPException(400, str(exc)) from None
    except OSError as exc:
        raise HTTPException(400, f"could not write {dest}: {exc.strerror or exc}") from None
    with vault_session(vault) as db:
        audit.record(db, action="export", entity_type="engagement", engagement_id=engagement_id,
                     summary=f"Exported {code} to a hand-off file ({len(manifest['findings'])} findings, "
                             f"{len(blobs)} evidence files)")
        db.commit()
    return {"path": str(dest), "bytes": size, "findings": len(manifest["findings"]), "evidence_files": len(blobs)}


@router.post("/api/handoff/import", status_code=201)
async def import_handoff(request: Request, vault: OpenVault = Depends(get_vault)):
    """Import a hand-off file sent as the raw request body; the passphrase travels in a header.

    The upload is spooled to an anonymous temp file first. It is ciphertext,
    so nothing readable touches disk, and decryption never holds the DB lock.
    """
    passphrase = request.headers.get(PASSPHRASE_HEADER, "")
    if not passphrase:
        raise HTTPException(422, "The passphrase is required")
    spooled = handoff.spool()
    try:
        size = 0
        async for chunk in request.stream():
            if vault.closed:
                raise VaultLocked()
            size += len(chunk)
            if size > MAX_HANDOFF_BYTES:
                raise HTTPException(413, "The hand-off file is too large")
            spooled.write(chunk)
        if not size:
            raise HTTPException(422, "Empty file")
        spooled.seek(0)
        return await run_in_threadpool(_import, vault, spooled, passphrase)
    except VaultLocked:
        raise HTTPException(423, "The vault is locked") from None
    finally:
        spooled.close()


# What a file's data can still cause after validation: a database constraint
# (or an integer SQLite cannot hold), or a record that the pages' code or
# response models cannot handle. Anything else is a server error.
_DATA_ERRORS = (StatementError, ValueError, TypeError, LookupError)


def _check_displayable(db: Session, eng: Engagement) -> None:
    """Defence in depth: build what the engagement's pages load, as their endpoints do.

    Validation should already ensure this. Anything that slips past it fails
    the import (ValueError and friends) instead of a page later (a 500).
    """
    db.flush()
    db.expire_all()  # read back what was stored, as a later request will
    engagements.read_engagement(eng=eng, db=db)
    engagements.engagement_summary(eng=eng, db=db)
    ClientOut.model_validate(eng.client)
    targets.list_targets(q=None, scope_status=None, kind=None, eng=eng, db=db)
    findings.list_findings(severity=None, status_filter=None, eng=eng, db=db)
    evidence.list_evidence(finding_id=None, target_id=None, eng=eng, db=db)
    for rows, model in ((scope.list_scope(eng=eng), ScopeItemOut),
                        (testing.list_tests(eng=eng, db=db), TestCaseOut),
                        (activity.list_oplog(eng=eng, db=db), OplogOut),
                        (recon.list_imports(eng=eng, db=db), ImportOut)):
        for row in rows:
            model.model_validate(row)


def _import(vault: OpenVault, src, passphrase: str) -> dict:
    try:
        manifest, blobs = handoff.read_handoff(vault, src, passphrase)
    except handoff.HandoffError as exc:
        raise HTTPException(400, str(exc)) from None
    try:
        with vault_session(vault) as db:
            try:
                eng = handoff.apply_manifest(db, manifest, blobs)
                _check_displayable(db, eng)
                out = {"engagement_id": eng.id, "code": eng.code, "renamed": eng.code != manifest.engagement.code,
                       "findings": len(manifest.findings), "evidence_files": len(manifest.evidence)}
                db.commit()
                return out
            except BaseException:
                db.rollback()  # no partial engagement
                raise
    except BaseException as exc:
        # Nothing was committed, so no row refers to the new blobs: delete every one.
        storage.delete_blobs(vault, [b.blob_id for b in blobs])
        if isinstance(exc, handoff.HandoffError):
            raise HTTPException(400, str(exc)) from None
        if isinstance(exc, _DATA_ERRORS):
            raise HTTPException(400, "the file's contents could not be imported") from None
        raise
