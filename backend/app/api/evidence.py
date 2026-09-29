from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import EngagementAccess, engagement_reader, engagement_writer, get_or_404
from ..models import Evidence, Finding, Target, TestCase
from ..schemas import EvidenceOut, EvidenceTextIn, EvidenceUpdate
from ..services import audit, storage
from .recon import read_upload

router = APIRouter(prefix="/api/engagements/{engagement_id}/evidence", tags=["evidence"])


def evidence_out(ev: Evidence) -> EvidenceOut:
    out = EvidenceOut.model_validate(ev)
    out.is_image = ev.content_type in storage.INLINE_IMAGE_TYPES
    return out


def _validate_links(db: Session, eid: int, finding_id, target_id, test_case_id) -> None:
    if finding_id is not None:
        get_or_404(db, Finding, finding_id, eid)
    if target_id is not None:
        get_or_404(db, Target, target_id, eid)
    if test_case_id is not None:
        get_or_404(db, TestCase, test_case_id, eid)


@router.get("", response_model=list[EvidenceOut])
def list_evidence(finding_id: int | None = None, target_id: int | None = None,
                  access: EngagementAccess = Depends(engagement_reader),
                  db: Session = Depends(get_db)):
    q = select(Evidence).where(Evidence.engagement_id == access.engagement.id)
    if finding_id is not None:
        q = q.where(Evidence.finding_id == finding_id)
    if target_id is not None:
        q = q.where(Evidence.target_id == target_id)
    return [evidence_out(e) for e in db.scalars(q.order_by(Evidence.created_at.desc()))]


def _store(db: Session, access: EngagementAccess, request: Request, **kwargs) -> EvidenceOut:
    try:
        ev = storage.store_evidence(db, engagement_id=access.engagement.id,
                                    uploaded_by_id=access.user.id, **kwargs)
    except storage.UploadTooLarge as exc:
        raise HTTPException(413, str(exc)) from None
    audit.record(db, user=access.user, action="create", entity_type="evidence", entity_id=ev.id,
                 engagement_id=access.engagement.id,
                 summary=f"Uploaded {ev.filename} ({ev.size} bytes, sha256 {ev.sha256[:16]}...)",
                 request=request)
    db.commit()
    return evidence_out(ev)


@router.post("", response_model=EvidenceOut, status_code=201)
async def upload_evidence(
    request: Request,
    file: UploadFile = File(...),
    description: str = Form(""),
    finding_id: int | None = Form(None),
    target_id: int | None = Form(None),
    test_case_id: int | None = Form(None),
    access: EngagementAccess = Depends(engagement_writer),
    db: Session = Depends(get_db),
):
    _validate_links(db, access.engagement.id, finding_id, target_id, test_case_id)
    data = await read_upload(file)
    if not data:
        raise HTTPException(422, "Empty file")
    return _store(db, access, request, filename=file.filename or "evidence.bin", data=data,
                  content_type=file.content_type, description=description,
                  finding_id=finding_id, target_id=target_id, test_case_id=test_case_id)


@router.post("/text", response_model=EvidenceOut, status_code=201)
def create_text_evidence(body: EvidenceTextIn, request: Request,
                         access: EngagementAccess = Depends(engagement_writer),
                         db: Session = Depends(get_db)):
    """Store pasted text (HTTP request/response, tool output, shell transcript) as evidence."""
    _validate_links(db, access.engagement.id, body.finding_id, body.target_id, body.test_case_id)
    name = body.filename if "." in body.filename else body.filename + ".txt"
    return _store(db, access, request, filename=name, data=body.content.encode(),
                  content_type="text/plain", description=body.description,
                  finding_id=body.finding_id, target_id=body.target_id,
                  test_case_id=body.test_case_id)


@router.get("/{evidence_id}/download")
def download_evidence(evidence_id: int, inline: bool = False,
                      access: EngagementAccess = Depends(engagement_reader),
                      db: Session = Depends(get_db)):
    ev = get_or_404(db, Evidence, evidence_id, access.engagement.id)
    try:
        data = storage.read_evidence(ev)
    except FileNotFoundError:
        raise HTTPException(410, "Evidence file is missing from storage") from None

    safe_inline = inline and ev.content_type in storage.INLINE_IMAGE_TYPES
    disposition = "inline" if safe_inline else "attachment"
    media_type = ev.content_type if safe_inline else "application/octet-stream"
    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f"{disposition}; filename*=UTF-8''{quote(ev.filename)}",
            "X-Content-SHA256": ev.sha256,
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "private, no-store",
        },
    )


@router.patch("/{evidence_id}", response_model=EvidenceOut)
def update_evidence(evidence_id: int, body: EvidenceUpdate, request: Request,
                    access: EngagementAccess = Depends(engagement_writer),
                    db: Session = Depends(get_db)):
    ev = get_or_404(db, Evidence, evidence_id, access.engagement.id)
    data = body.model_dump(exclude_unset=True)
    _validate_links(db, access.engagement.id, data.get("finding_id"), data.get("target_id"),
                    data.get("test_case_id"))
    for k, v in data.items():
        if k == "description" and v is None:
            continue
        setattr(ev, k, v)
    audit.record(db, user=access.user, action="update", entity_type="evidence", entity_id=ev.id,
                 engagement_id=access.engagement.id, summary=f"Updated evidence {ev.filename}",
                 request=request)
    db.commit()
    return evidence_out(ev)


@router.delete("/{evidence_id}", status_code=204)
def delete_evidence(evidence_id: int, request: Request,
                    access: EngagementAccess = Depends(engagement_writer),
                    db: Session = Depends(get_db)):
    ev = get_or_404(db, Evidence, evidence_id, access.engagement.id)
    db.delete(ev)
    audit.record(db, user=access.user, action="delete", entity_type="evidence", entity_id=evidence_id,
                 engagement_id=access.engagement.id,
                 summary=f"Deleted evidence {ev.filename} (sha256 {ev.sha256})", request=request)
    db.commit()
    storage.delete_evidence_file(ev)
