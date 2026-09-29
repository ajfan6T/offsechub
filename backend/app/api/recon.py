from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import EngagementAccess, engagement_reader, engagement_writer
from ..models import ReconImport
from ..schemas import ImportOut, ImportTool
from ..services import audit, storage
from ..services.importers.apply import ImportContext, apply_result
from ..services.importers.parsers import PARSERS, ParseError

router = APIRouter(prefix="/api/engagements/{engagement_id}/imports", tags=["recon"])


async def read_upload(file: UploadFile) -> bytes:
    limit = get_settings().max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"File exceeds {get_settings().max_upload_mb} MB limit")
    return data


@router.get("", response_model=list[ImportOut])
def list_imports(access: EngagementAccess = Depends(engagement_reader), db: Session = Depends(get_db)):
    return db.scalars(
        select(ReconImport)
        .where(ReconImport.engagement_id == access.engagement.id)
        .order_by(ReconImport.created_at.desc())
    ).all()


@router.post("", response_model=ImportOut, status_code=201)
async def import_tool_output(
    request: Request,
    tool: ImportTool = Form(...),
    file: UploadFile = File(...),
    skip_out_of_scope: bool = Form(True),
    access: EngagementAccess = Depends(engagement_writer),
    db: Session = Depends(get_db),
):
    """Import Nmap XML, nuclei JSON/JSONL or a plain host list.

    Hosts matching an exclusion are never imported. Hosts outside the include
    rules are skipped unless ``skip_out_of_scope`` is false, in which case they
    are imported and flagged out of scope.
    """
    data = await read_upload(file)
    try:
        parsed = PARSERS[tool](data)
    except ParseError as exc:
        raise HTTPException(422, str(exc)) from None

    eng = access.engagement
    # Keep the raw tool output as evidence so every imported record is traceable.
    raw = storage.store_evidence(
        db,
        engagement_id=eng.id,
        filename=file.filename or f"{tool}-output",
        data=data,
        content_type=file.content_type,
        uploaded_by_id=access.user.id,
        description=f"Raw {tool} output (import)",
    )
    ctx = ImportContext(db, eng, tool, access.user.id, skip_out_of_scope)
    stats = apply_result(ctx, parsed)
    record = ReconImport(
        engagement_id=eng.id,
        tool=tool,
        filename=raw.filename,
        evidence_id=raw.id,
        stats=stats,
        created_by_id=access.user.id,
    )
    db.add(record)
    db.flush()
    audit.record(
        db, user=access.user, action="import", entity_type="import", entity_id=record.id,
        engagement_id=eng.id,
        summary=(
            f"Imported {tool} {raw.filename}: {stats['targets_created']} new targets, "
            f"{stats['services_created']} services, {stats['findings_created']} findings, "
            f"{stats['skipped_out_of_scope'] + stats['skipped_excluded']} skipped (scope)"
        ),
        request=request,
    )
    db.commit()
    return record
