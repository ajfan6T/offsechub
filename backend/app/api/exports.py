"""Findings exports for ticketing and vulnerability-management tools (CSV, SARIF, DefectDojo)."""

from typing import Literal

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_engagement
from ..models import Engagement
from ..services import audit, exports

router = APIRouter(prefix="/api/engagements/{engagement_id}/export", tags=["reports"])


@router.get("/findings")
def export_findings(format: Literal["csv", "sarif", "defectdojo"] = "csv", include_drafts: bool = False,
                    eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    render, media_type, suffix = exports.FORMATS[format]
    findings = exports.select_findings(eng, include_drafts)
    body = render(eng, findings)
    audit.record(db, action="export", entity_type="findings", engagement_id=eng.id,
                 summary=f"Exported {len(findings)} findings as {format}")
    db.commit()
    return Response(body, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{eng.code}-{suffix}"',
        "Cache-Control": "private, no-store",
    })
