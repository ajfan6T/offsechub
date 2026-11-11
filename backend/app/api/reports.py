from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse

from ..bootstrap import get_setting
from ..db import get_vault
from ..deps import get_engagement
from ..services import audit, branding, reporting, storage
from ..services.report_docx import TemplateProblem, render_docx
from ..vault.manager import OpenVault
from .evidence import vault_session

router = APIRouter(prefix="/api/engagements/{engagement_id}/report", tags=["reports"])

# The HTML report may be framed by the app for preview, but it must not load
# anything: images are embedded as data: URIs and no script is allowed.
REPORT_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'self'"
DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
BINARY_FORMATS = ("html", "docx", "pdf")


@router.get("")
def generate_report(
    engagement_id: int,
    format: Literal["html", "md", "json", "docx", "pdf"] = "html",
    include_drafts: bool = False,
    download: bool = False,
    template_id: int | None = None,
    vault: OpenVault = Depends(get_vault),
):
    """Render the engagement report.

    DOCX uses ``template_id``, else the default template from the branding
    settings, else the built-in one. Rendering happens after the vault's
    database session is released, so a long export never blocks the app.
    """
    template: bytes | None = None
    with vault_session(vault) as db:
        eng = get_engagement(engagement_id, db)
        profile = get_setting(db, "operator.profile") or {}
        ctx = reporting.build_context(
            eng,
            profile=profile,
            include_drafts=include_drafts,
            read_image=(lambda ev: storage.read_evidence(vault, ev)) if format in BINARY_FORMATS else None,
            branding=branding.report_branding(db, profile),
        )
        if format == "docx":
            tid = template_id if template_id is not None else branding.load_settings(db)["default_template_id"]
            if tid is not None:
                asset = branding.get_asset(db, tid, "template")
                if asset is None:
                    raise HTTPException(404, "Report template not found")
                template = asset.data
        code = eng.code
        audit.record(db, action="export", entity_type="report", engagement_id=eng.id,
                     summary=f"Generated {format} report ({ctx['total_findings']} findings"
                             f"{', drafts included' if include_drafts else ''})")
        db.commit()

    headers = {"Cache-Control": "private, no-store"}
    if download or format in ("docx", "pdf"):
        disposition = "attachment" if download or format == "docx" else "inline"
        headers["Content-Disposition"] = f'{disposition}; filename="{code}-report.{format}"'

    if format == "json":
        return JSONResponse(reporting.json_safe(ctx), headers=headers)
    if format == "md":
        return Response(reporting.render_markdown(ctx), media_type="text/markdown; charset=utf-8",
                        headers=headers)
    if format == "docx":
        try:
            body = render_docx(ctx, template)
        except TemplateProblem as exc:
            raise HTTPException(422, f"Report template: {exc}") from None
        return Response(body, media_type=DOCX_TYPE, headers=headers)
    if format == "pdf":
        from ..services.report_pdf import render_pdf  # ReportLab is slow to import

        return Response(render_pdf(ctx), media_type="application/pdf", headers=headers)
    headers["Content-Security-Policy"] = REPORT_CSP
    headers["X-Frame-Options"] = "SAMEORIGIN"
    return Response(reporting.render_html(ctx), media_type="text/html; charset=utf-8",
                    headers=headers)
