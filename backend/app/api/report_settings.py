"""Report branding (organisation, colours, logo) and DOCX report templates."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from ..db import get_vault
from ..models import ReportAsset
from ..services import audit, branding
from ..services.report_docx import BUILTIN, TemplateProblem, check_template
from ..services.storage import sanitize_filename
from ..vault.manager import OpenVault
from .evidence import declared_length, vault_session

router = APIRouter(tags=["reports"])
DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


class BrandingIn(BaseModel):
    organization: str | None = Field(default=None, max_length=255)
    accent: str | None = Field(default=None, max_length=7)
    classification: str | None = Field(default=None, max_length=120)
    footer: str | None = Field(default=None, max_length=255)
    default_template_id: int | None = None


class BrandingOut(BaseModel):
    organization: str
    accent: str
    classification: str
    footer: str
    logo_id: int | None
    default_template_id: int | None


class ReportTemplateOut(BaseModel):
    id: int
    name: str
    filename: str
    size: int
    sha256: str
    created_at: str


async def _read_body(request: Request, limit: int, what: str) -> bytes:
    if declared_length(request) > limit:
        raise HTTPException(413, f"The {what} must be at most {limit // (1024 * 1024)} MB")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > limit:
            raise HTTPException(413, f"The {what} must be at most {limit // (1024 * 1024)} MB")
    if not buf:
        raise HTTPException(422, "Empty file")
    return bytes(buf)


def _template_out(a: ReportAsset) -> ReportTemplateOut:
    return ReportTemplateOut(id=a.id, name=a.name, filename=a.filename, size=a.size, sha256=a.sha256,
                             created_at=a.created_at.isoformat())


# ------------------------------------------------------------------ branding


@router.get("/api/report-branding", response_model=BrandingOut)
def get_branding(vault: OpenVault = Depends(get_vault)):
    with vault_session(vault) as db:
        return BrandingOut(**branding.load_settings(db))


@router.put("/api/report-branding", response_model=BrandingOut)
def put_branding(body: BrandingIn, vault: OpenVault = Depends(get_vault)):
    with vault_session(vault) as db:
        try:
            saved = branding.save_settings(db, body.model_dump(exclude_unset=True))
        except branding.AssetError as exc:
            raise HTTPException(422, str(exc)) from None
        audit.record(db, action="update", entity_type="settings", summary="Updated report branding")
        db.commit()
        return BrandingOut(**saved)


@router.post("/api/report-branding/logo", response_model=BrandingOut, status_code=201)
async def upload_logo(request: Request, vault: OpenVault = Depends(get_vault)):
    data = await _read_body(request, branding.MAX_LOGO_BYTES, "logo")
    try:
        ctype = branding.check_logo(data)
    except branding.AssetError as exc:
        raise HTTPException(422, str(exc)) from None

    def store() -> BrandingOut:
        with vault_session(vault) as db:
            settings = branding.load_settings(db)
            old = settings["logo_id"]
            asset = branding.add_asset(db, kind="logo", name="Logo", filename="logo." + ctype.split("/")[1],
                                       content_type=ctype, data=data)
            saved = branding.save_settings(db, {"logo_id": asset.id})
            if old is not None and (prev := branding.get_asset(db, old, "logo")) is not None:
                db.delete(prev)
            audit.record(db, action="update", entity_type="settings", summary="Uploaded a report logo")
            db.commit()
            return BrandingOut(**saved)

    return await run_in_threadpool(store)


@router.get("/api/report-branding/logo")
def get_logo(vault: OpenVault = Depends(get_vault)):
    with vault_session(vault) as db:
        logo_id = branding.load_settings(db)["logo_id"]
        asset = branding.get_asset(db, logo_id, "logo") if logo_id is not None else None
        if asset is None:
            raise HTTPException(404, "No logo")
        return Response(asset.data, media_type=asset.content_type,
                        headers={"Cache-Control": "private, no-store"})


@router.delete("/api/report-branding/logo", status_code=204)
def delete_logo(vault: OpenVault = Depends(get_vault)):
    with vault_session(vault) as db:
        logo_id = branding.load_settings(db)["logo_id"]
        branding.save_settings(db, {"logo_id": None})
        if logo_id is not None and (asset := branding.get_asset(db, logo_id, "logo")) is not None:
            db.delete(asset)
        audit.record(db, action="update", entity_type="settings", summary="Removed the report logo")
        db.commit()


# ------------------------------------------------------------------ templates


@router.get("/api/report-templates", response_model=list[ReportTemplateOut])
def list_templates(vault: OpenVault = Depends(get_vault)):
    with vault_session(vault) as db:
        rows = db.scalars(select(ReportAsset).where(ReportAsset.kind == "template")
                          .order_by(ReportAsset.name, ReportAsset.id))
        return [_template_out(a) for a in rows]


@router.get("/api/report-templates/builtin/download", dependencies=[Depends(get_vault)])
def download_builtin_template():
    """The built-in template, as a starting point for a house style."""
    return Response(BUILTIN.read_bytes(), media_type=DOCX_TYPE,
                    headers={"Content-Disposition": 'attachment; filename="offsechub-report-template.docx"'})


@router.post("/api/report-templates/upload", response_model=ReportTemplateOut, status_code=201)
async def upload_template(request: Request, filename: str = Query("template.docx", max_length=255),
                          name: str = Query("", max_length=255), vault: OpenVault = Depends(get_vault)):
    data = await _read_body(request, branding.MAX_TEMPLATE_BYTES, "template")
    try:
        await run_in_threadpool(check_template, data)
    except TemplateProblem as exc:
        raise HTTPException(422, f"Report template: {exc}") from None
    safe = sanitize_filename(filename)

    def store() -> ReportTemplateOut:
        with vault_session(vault) as db:
            asset = branding.add_asset(db, kind="template", name=name.strip() or safe.rsplit(".", 1)[0],
                                       filename=safe, content_type=DOCX_TYPE, data=data)
            audit.record(db, action="create", entity_type="report_template", entity_id=asset.id,
                         summary=f"Added report template '{asset.name}'")
            db.commit()
            return _template_out(asset)

    return await run_in_threadpool(store)


@router.get("/api/report-templates/{template_id}/download")
def download_template(template_id: int, vault: OpenVault = Depends(get_vault)):
    with vault_session(vault) as db:
        asset = branding.get_asset(db, template_id, "template")
        if asset is None:
            raise HTTPException(404, "Report template not found")
        return Response(asset.data, media_type=DOCX_TYPE,
                        headers={"Content-Disposition": f'attachment; filename="{asset.filename}"'})


@router.delete("/api/report-templates/{template_id}", status_code=204)
def delete_template(template_id: int, vault: OpenVault = Depends(get_vault)):
    with vault_session(vault) as db:
        asset = branding.get_asset(db, template_id, "template")
        if asset is None:
            raise HTTPException(404, "Report template not found")
        if branding.load_settings(db)["default_template_id"] == template_id:
            branding.save_settings(db, {"default_template_id": None})
        db.delete(asset)
        audit.record(db, action="delete", entity_type="report_template", entity_id=template_id,
                     summary=f"Deleted report template '{asset.name}'")
        db.commit()
