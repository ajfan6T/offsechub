from typing import Literal

from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..bootstrap import get_setting
from ..db import get_db, get_vault
from ..deps import get_engagement
from ..models import Engagement
from ..services import audit, reporting, storage
from ..vault.manager import OpenVault

router = APIRouter(prefix="/api/engagements/{engagement_id}/report", tags=["reports"])

# The HTML report may be framed by the app for preview, but it must not load
# anything: images are embedded as data: URIs and no script is allowed.
REPORT_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'self'"


@router.get("")
def generate_report(
    format: Literal["html", "md", "json"] = "html",
    include_drafts: bool = False,
    download: bool = False,
    eng: Engagement = Depends(get_engagement),
    db: Session = Depends(get_db),
    vault: OpenVault = Depends(get_vault),
):
    ctx = reporting.build_context(
        eng,
        profile=get_setting(db, "operator.profile") or {},
        include_drafts=include_drafts,
        read_image=(lambda ev: storage.read_evidence(vault, ev)) if format == "html" else None,
    )
    audit.record(db, action="export", entity_type="report", engagement_id=eng.id,
                 summary=f"Generated {format} report ({ctx['total_findings']} findings"
                         f"{', drafts included' if include_drafts else ''})")
    db.commit()

    headers = {"Cache-Control": "private, no-store"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{eng.code}-report.{format}"'

    if format == "json":
        return JSONResponse(ctx, headers=headers)
    if format == "md":
        return Response(reporting.render_markdown(ctx), media_type="text/markdown; charset=utf-8",
                        headers=headers)
    headers["Content-Security-Policy"] = REPORT_CSP
    headers["X-Frame-Options"] = "SAMEORIGIN"
    return Response(reporting.render_html(ctx), media_type="text/html; charset=utf-8",
                    headers=headers)
