from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import EngagementAccess, engagement_reader
from ..services import audit, reporting

router = APIRouter(prefix="/api/engagements/{engagement_id}/report", tags=["reports"])

# The HTML report may be framed by the app for preview, but it must not load
# anything: images are embedded as data: URIs and no script is allowed.
REPORT_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'self'"


@router.get("")
def generate_report(
    request: Request,
    format: Literal["html", "md", "json"] = "html",
    include_drafts: bool = False,
    download: bool = False,
    access: EngagementAccess = Depends(engagement_reader),
    db: Session = Depends(get_db),
):
    eng = access.engagement
    # Drafts are internal working material; read-only members only get the client view.
    include_drafts = include_drafts and access.can_write
    ctx = reporting.build_context(eng, access.user, include_drafts, embed_images=format == "html")
    audit.record(db, user=access.user, action="export", entity_type="report", engagement_id=eng.id,
                 summary=f"Generated {format} report ({ctx['total_findings']} findings"
                         f"{', drafts included' if include_drafts else ''})",
                 request=request)
    db.commit()

    filename = f"{eng.code}-report.{format}"
    headers = {"Cache-Control": "private, no-store"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'

    if format == "json":
        return JSONResponse(ctx, headers=headers)
    if format == "md":
        return Response(reporting.render_markdown(ctx), media_type="text/markdown; charset=utf-8",
                        headers=headers)
    headers["Content-Security-Policy"] = REPORT_CSP
    headers["X-Frame-Options"] = "SAMEORIGIN"
    return Response(reporting.render_html(ctx), media_type="text/html; charset=utf-8",
                    headers=headers)
