"""Recon imports: Nmap XML, nuclei JSON/JSONL and plain host lists."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..db import get_db, get_vault
from ..deps import get_engagement
from ..models import Engagement, ReconImport
from ..schemas import ImportOut, ImportTool
from ..services import audit, storage
from ..services.importers.apply import ImportContext, apply_result
from ..services.importers.parsers import PARSERS, ParseError
from ..vault.manager import OpenVault
from .evidence import declared_length, vault_session

router = APIRouter(prefix="/api/engagements/{engagement_id}/imports", tags=["recon"])


@router.get("", response_model=list[ImportOut])
def list_imports(eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    return db.scalars(
        select(ReconImport)
        .where(ReconImport.engagement_id == eng.id)
        .order_by(ReconImport.created_at.desc(), ReconImport.id.desc())
    ).all()


@router.post("/upload", response_model=ImportOut, status_code=201)
async def import_tool_output(
    engagement_id: int,
    request: Request,
    tool: ImportTool,
    filename: str = Query("", max_length=255),
    skip_out_of_scope: bool = True,
    vault: OpenVault = Depends(get_vault),
):
    """Import tool output sent as the raw request body.

    Hosts matching an exclusion are never imported. Hosts outside the include
    rules are skipped unless ``skip_out_of_scope`` is false, in which case they
    are imported and flagged out of scope. Like evidence uploads, this does not
    hold the DB session while the body arrives.
    """
    def precheck() -> None:
        with vault_session(vault) as db:
            get_engagement(engagement_id, db)

    await run_in_threadpool(precheck)
    try:
        storage.check_size(declared_length(request))
        data = await storage.receive_bytes(request.stream())
    except storage.UploadTooLarge as exc:
        raise HTTPException(413, str(exc)) from None
    if not data:
        raise HTTPException(422, "Empty file")
    return await run_in_threadpool(
        _import, vault, engagement_id, tool, filename or f"{tool}-output",
        request.headers.get("content-type"), data, skip_out_of_scope,
    )


def _import(vault: OpenVault, engagement_id: int, tool: str, filename: str,
            content_type: str | None, data: bytes, skip_out_of_scope: bool) -> ImportOut:
    # Parse and encrypt before taking the (exclusive) DB session: both can be slow.
    try:
        parsed = PARSERS[tool](data)
    except ParseError as exc:
        raise HTTPException(422, str(exc)) from None
    # Keep the raw tool output as evidence so every imported record is traceable.
    blob = storage.write_bytes(vault, data)
    with storage.discard_on_error(vault, blob), vault_session(vault) as db:
        eng = get_engagement(engagement_id, db)
        raw = storage.add_evidence(db, blob, engagement_id=eng.id, filename=filename,
                                   content_type=content_type,
                                   description=f"Raw {tool} output (import)")
        stats = apply_result(ImportContext(db, eng, tool, skip_out_of_scope), parsed)
        record = ReconImport(engagement_id=eng.id, tool=tool, filename=raw.filename,
                             evidence_id=raw.id, stats=stats)
        db.add(record)
        db.flush()
        audit.record(
            db, action="import", entity_type="import", entity_id=record.id, engagement_id=eng.id,
            summary=(
                f"Imported {tool} {raw.filename}: {stats['targets_created']} new targets, "
                f"{stats['services_created']} services, {stats['findings_created']} findings, "
                f"{stats['skipped_out_of_scope'] + stats['skipped_excluded']} skipped (scope)"
            ),
        )
        db.commit()
        return ImportOut.model_validate(record)
