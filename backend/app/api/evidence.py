"""Evidence: encrypted files attached to findings, targets and test cases.

Uploads are the raw request body, not multipart: Starlette spools multipart
parts over 1 MiB to plaintext temp files, which would defeat the vault. The
body is streamed straight into the blob encryptor instead.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..db import LOCKED_DETAIL, get_db, get_vault
from ..deps import get_engagement, get_or_404
from ..models import Engagement, Evidence, Finding, Target, TestCase
from ..schemas import EvidenceOut, EvidenceTextIn, EvidenceUpdate
from ..services import audit, storage
from ..vault.manager import OpenVault, VaultLocked

router = APIRouter(prefix="/api/engagements/{engagement_id}/evidence", tags=["evidence"])

EVIDENCE_CSP = "default-src 'none'; sandbox"


@contextmanager
def vault_session(vault: OpenVault) -> Iterator[Session]:
    """``vault.session()`` for code that must not hold ``get_db`` for the whole request."""
    try:
        with vault.session() as db:
            yield db
    except VaultLocked:
        raise HTTPException(423, LOCKED_DETAIL) from None


def declared_length(request: Request) -> int:
    """The Content-Length, so an oversized upload is refused before it is read."""
    value = request.headers.get("content-length", "")
    return int(value) if value.isdigit() else 0


def evidence_out(ev: Evidence) -> EvidenceOut:
    out = EvidenceOut.model_validate(ev)
    out.is_image = ev.content_type in storage.INLINE_IMAGE_TYPES
    return out


def _validate_links(db: Session, eid: int, finding_id: int | None = None,
                    target_id: int | None = None, test_case_id: int | None = None) -> None:
    if finding_id is not None:
        get_or_404(db, Finding, finding_id, eid)
    if target_id is not None:
        get_or_404(db, Target, target_id, eid)
    if test_case_id is not None:
        get_or_404(db, TestCase, test_case_id, eid)


def _record_upload(db: Session, ev: Evidence) -> None:
    audit.record(db, action="create", entity_type="evidence", entity_id=ev.id,
                 engagement_id=ev.engagement_id,
                 summary=f"Added {ev.filename} ({ev.size} bytes, sha256 {ev.sha256[:16]}...)")


@router.get("", response_model=list[EvidenceOut])
def list_evidence(finding_id: int | None = None, target_id: int | None = None,
                  eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    q = select(Evidence).where(Evidence.engagement_id == eng.id)
    if finding_id is not None:
        q = q.where(Evidence.finding_id == finding_id)
    if target_id is not None:
        q = q.where(Evidence.target_id == target_id)
    q = q.order_by(Evidence.created_at.desc(), Evidence.id.desc())
    return [evidence_out(e) for e in db.scalars(q)]


@router.post("/upload", response_model=EvidenceOut, status_code=201)
async def upload_evidence(
    engagement_id: int,
    request: Request,
    filename: str = Query(min_length=1, max_length=255),
    description: str = "",
    finding_id: int | None = None,
    target_id: int | None = None,
    test_case_id: int | None = None,
    vault: OpenVault = Depends(get_vault),
):
    """Stream the raw request body (``Content-Type`` = the file's type) into the vault.

    Deliberately no ``get_db``: the DB session is exclusive, and holding it for
    a long upload would stall every other request.
    """
    content_type = request.headers.get("content-type", "")
    if content_type.lower().startswith("multipart/"):
        raise HTTPException(415, "Send the file as the raw request body, not multipart")
    links = {"finding_id": finding_id, "target_id": target_id, "test_case_id": test_case_id}

    def validate(db: Session) -> None:
        get_engagement(engagement_id, db)
        _validate_links(db, engagement_id, **links)

    def precheck() -> None:
        with vault_session(vault) as db:
            validate(db)

    def insert(blob: storage.StoredBlob) -> EvidenceOut:
        with storage.discard_on_error(vault, blob), vault_session(vault) as db:
            validate(db)  # again: rows may have been deleted during a long upload
            ev = storage.add_evidence(db, blob, engagement_id=engagement_id, filename=filename,
                                      content_type=content_type, description=description, **links)
            _record_upload(db, ev)
            db.commit()
            return evidence_out(ev)

    await run_in_threadpool(precheck)  # fail before accepting the body
    try:
        storage.check_size(declared_length(request))
        blob = await storage.receive_blob(vault, request.stream())
    except storage.UploadTooLarge as exc:
        raise HTTPException(413, str(exc)) from None
    except storage.EmptyUpload as exc:
        raise HTTPException(422, str(exc)) from None
    except VaultLocked:
        raise HTTPException(423, LOCKED_DETAIL) from None
    return await run_in_threadpool(insert, blob)


@router.post("/text", response_model=EvidenceOut, status_code=201)
def create_text_evidence(body: EvidenceTextIn, eng: Engagement = Depends(get_engagement),
                         db: Session = Depends(get_db), vault: OpenVault = Depends(get_vault)):
    """Store pasted text (HTTP request/response, tool output, shell transcript) as evidence."""
    _validate_links(db, eng.id, body.finding_id, body.target_id, body.test_case_id)
    name = body.filename if "." in body.filename else body.filename + ".txt"
    try:
        blob = storage.write_bytes(vault, body.content.encode())
    except storage.UploadTooLarge as exc:
        raise HTTPException(413, str(exc)) from None
    with storage.discard_on_error(vault, blob):
        ev = storage.add_evidence(
            db, blob, engagement_id=eng.id, filename=name, content_type="text/plain",
            description=body.description, finding_id=body.finding_id,
            target_id=body.target_id, test_case_id=body.test_case_id,
        )
        _record_upload(db, ev)
        db.commit()
    return evidence_out(ev)


@router.get("/{evidence_id}/download")
def download_evidence(engagement_id: int, evidence_id: int, inline: bool = False,
                      vault: OpenVault = Depends(get_vault)):
    """Decrypt and stream an evidence file.

    The DB session is released before streaming starts, so a large download
    doesn't block other requests. Size and SHA-256 are verified as the file
    streams; on a mismatch the iterator raises and the connection is aborted,
    so a client never receives a complete-looking but altered file.
    """
    with vault_session(vault) as db:
        ev = get_or_404(db, Evidence, evidence_id, engagement_id)
    # The detached row keeps its loaded columns.
    try:
        chunks = storage.stream_evidence(vault, ev)
    except FileNotFoundError:
        raise HTTPException(410, "Evidence file is missing from the vault") from None

    safe_inline = inline and ev.content_type in storage.INLINE_IMAGE_TYPES
    disposition = "inline" if safe_inline else "attachment"
    return StreamingResponse(
        chunks,
        media_type=ev.content_type if safe_inline else "application/octet-stream",
        headers={
            "Content-Length": str(ev.size),
            "Content-Disposition": f"{disposition}; filename*=UTF-8''{quote(ev.filename)}",
            "X-Content-SHA256": ev.sha256,
            "Content-Security-Policy": EVIDENCE_CSP,
            "Cache-Control": "private, no-store",
        },
    )


@router.patch("/{evidence_id}", response_model=EvidenceOut)
def update_evidence(evidence_id: int, body: EvidenceUpdate,
                    eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    ev = get_or_404(db, Evidence, evidence_id, eng.id)
    data = body.model_dump(exclude_unset=True)
    _validate_links(db, eng.id, data.get("finding_id"), data.get("target_id"),
                    data.get("test_case_id"))
    for k, v in data.items():
        if k == "description" and v is None:
            continue
        setattr(ev, k, v)
    audit.record(db, action="update", entity_type="evidence", entity_id=ev.id,
                 engagement_id=eng.id, summary=f"Updated evidence {ev.filename}")
    db.commit()
    return evidence_out(ev)


@router.delete("/{evidence_id}", status_code=204)
def delete_evidence(evidence_id: int, eng: Engagement = Depends(get_engagement),
                    db: Session = Depends(get_db), vault: OpenVault = Depends(get_vault)):
    ev = get_or_404(db, Evidence, evidence_id, eng.id)
    blob_id = ev.storage_key
    db.delete(ev)
    audit.record(db, action="delete", entity_type="evidence", entity_id=evidence_id,
                 engagement_id=eng.id,
                 summary=f"Deleted evidence {ev.filename} (sha256 {ev.sha256})")
    db.commit()
    storage.delete_blobs(vault, [blob_id])
