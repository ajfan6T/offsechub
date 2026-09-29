from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..db import get_db
from ..deps import (
    EngagementAccess,
    current_user,
    engagement_reader,
    engagement_writer,
    get_or_404,
    require_lead,
)
from ..models import Evidence, Finding, FindingTemplate, Target, User
from ..schemas import (
    SEVERITY_ORDER,
    CvssIn,
    CvssOut,
    FindingIn,
    FindingOut,
    FindingTemplateIn,
    FindingTemplateOut,
    FindingTemplateUpdate,
    FindingUpdate,
)
from ..services import audit, cvss
from ..services.findings import apply_cvss, finding_ref, next_finding_number

router = APIRouter(tags=["findings"])
prefix = "/api/engagements/{engagement_id}/findings"


def finding_out(f: Finding, evidence_count: int) -> FindingOut:
    out = FindingOut.model_validate(f)
    out.ref = finding_ref(f.engagement, f)
    out.evidence_count = evidence_count
    return out


def _evidence_counts(db: Session, finding_ids: list[int]) -> dict[int, int]:
    if not finding_ids:
        return {}
    return dict(
        db.execute(
            select(Evidence.finding_id, func.count())
            .where(Evidence.finding_id.in_(finding_ids))
            .group_by(Evidence.finding_id)
        ).all()
    )


def _resolve_targets(db: Session, eid: int, ids: list[int]) -> list[Target]:
    return [get_or_404(db, Target, tid, eid) for tid in dict.fromkeys(ids)]


def _apply_cvss_or_422(finding: Finding, vector: str | None, severity: str | None) -> None:
    try:
        apply_cvss(finding, vector, severity)
    except cvss.CvssError as exc:
        raise HTTPException(422, f"Invalid CVSS vector: {exc}") from None


@router.get(prefix, response_model=list[FindingOut])
def list_findings(severity: str | None = None,
                  status_filter: str | None = Query(None, alias="status"),
                  access: EngagementAccess = Depends(engagement_reader),
                  db: Session = Depends(get_db)):
    q = (
        select(Finding)
        .where(Finding.engagement_id == access.engagement.id)
        .options(selectinload(Finding.targets))
    )
    if severity:
        q = q.where(Finding.severity == severity)
    if status_filter:
        q = q.where(Finding.status == status_filter)
    findings = sorted(db.scalars(q), key=lambda f: (SEVERITY_ORDER[f.severity], f.number))
    counts = _evidence_counts(db, [f.id for f in findings])
    return [finding_out(f, counts.get(f.id, 0)) for f in findings]


@router.post(prefix, response_model=FindingOut, status_code=201)
def create_finding(body: FindingIn, request: Request,
                   access: EngagementAccess = Depends(engagement_writer),
                   db: Session = Depends(get_db)):
    eid = access.engagement.id
    base: dict = {}
    if body.template_id is not None:
        tpl = db.get(FindingTemplate, body.template_id)
        if tpl is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
        base = {k: getattr(tpl, k) for k in
                ("title", "severity", "cvss_vector", "cwe", "description", "impact",
                 "remediation", "references")}
    # Explicit fields override the template.
    fields = {k: v for k, v in body.model_dump(exclude={"target_ids", "template_id"}).items()
              if v is not None}
    merged = {**base, **fields}
    if not merged.get("title"):
        raise HTTPException(422, "title is required (or choose a template)")

    vector = merged.pop("cvss_vector", None)
    fallback_severity = merged.pop("severity", None) or "medium"
    finding = Finding(
        engagement_id=eid,
        number=next_finding_number(db, eid),
        source="template" if body.template_id else "manual",
        created_by_id=access.user.id,
        severity=fallback_severity,
        **merged,
    )
    # An explicit severity wins; otherwise a CVSS vector decides; otherwise the template's.
    _apply_cvss_or_422(finding, vector, body.severity)
    finding.targets = _resolve_targets(db, eid, body.target_ids)
    db.add(finding)
    db.flush()
    audit.record(db, user=access.user, action="create", entity_type="finding", entity_id=finding.id,
                 engagement_id=eid,
                 summary=f"{finding_ref(access.engagement, finding)} {finding.title} ({finding.severity})",
                 request=request)
    db.commit()
    return finding_out(finding, 0)


@router.get(prefix + "/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, access: EngagementAccess = Depends(engagement_reader),
                db: Session = Depends(get_db)):
    f = get_or_404(db, Finding, finding_id, access.engagement.id)
    return finding_out(f, _evidence_counts(db, [f.id]).get(f.id, 0))


@router.patch(prefix + "/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, body: FindingUpdate, request: Request,
                   access: EngagementAccess = Depends(engagement_writer),
                   db: Session = Depends(get_db)):
    eid = access.engagement.id
    f = get_or_404(db, Finding, finding_id, eid)
    data = body.model_dump(exclude_unset=True)
    old_status = f.status

    if "target_ids" in data:
        f.targets = _resolve_targets(db, eid, data.pop("target_ids") or [])
    vector = data.pop("cvss_vector", None)
    severity = data.pop("severity", None)
    _apply_cvss_or_422(f, vector, severity)
    for k, v in data.items():
        if v is not None:
            setattr(f, k, v)

    summary = f"Updated {finding_ref(access.engagement, f)} {f.title}"
    if f.status != old_status:
        summary += f": status {old_status} -> {f.status}"
    audit.record(db, user=access.user, action="update", entity_type="finding", entity_id=f.id,
                 engagement_id=eid, summary=summary, request=request)
    db.commit()
    db.refresh(f)
    return finding_out(f, _evidence_counts(db, [f.id]).get(f.id, 0))


@router.delete(prefix + "/{finding_id}", status_code=204)
def delete_finding(finding_id: int, request: Request,
                   access: EngagementAccess = Depends(engagement_writer),
                   db: Session = Depends(get_db)):
    f = get_or_404(db, Finding, finding_id, access.engagement.id)
    ref = finding_ref(access.engagement, f)
    db.delete(f)
    audit.record(db, user=access.user, action="delete", entity_type="finding", entity_id=finding_id,
                 engagement_id=access.engagement.id, summary=f"Deleted {ref} {f.title}",
                 request=request)
    db.commit()


@router.post(prefix + "/{finding_id}/save-as-template", response_model=FindingTemplateOut,
             status_code=201)
def save_as_template(finding_id: int, request: Request,
                     access: EngagementAccess = Depends(engagement_reader),
                     db: Session = Depends(get_db)):
    """Promote a polished write-up into the shared library (leads/admins)."""
    if access.user.role not in ("admin", "lead"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only leads can curate the finding library")
    f = get_or_404(db, Finding, finding_id, access.engagement.id)
    if db.scalar(select(FindingTemplate).where(FindingTemplate.title == f.title)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A template with this title already exists")
    tpl = FindingTemplate(
        title=f.title, severity=f.severity, cvss_vector=f.cvss_vector, cwe=f.cwe,
        description=f.description, impact=f.impact, remediation=f.remediation,
        references=f.references,
    )
    db.add(tpl)
    db.flush()
    audit.record(db, user=access.user, action="create", entity_type="finding_template",
                 entity_id=tpl.id, summary=f"Saved '{tpl.title}' to the finding library",
                 request=request)
    db.commit()
    return template_out(tpl)


# ------------------------------------------------------------------ templates


def template_out(t: FindingTemplate) -> FindingTemplateOut:
    out = FindingTemplateOut.model_validate(t)
    if t.cvss_vector:
        try:
            out.cvss_score = cvss.calculate(t.cvss_vector).score
        except cvss.CvssError:
            pass
    return out


@router.get("/api/finding-templates", response_model=list[FindingTemplateOut])
def list_templates(q: str | None = None, _: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    stmt = select(FindingTemplate).order_by(FindingTemplate.category, FindingTemplate.title)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(func.lower(FindingTemplate.title).like(like)
                          | func.lower(FindingTemplate.category).like(like)
                          | func.lower(FindingTemplate.cwe).like(like))
    return [template_out(t) for t in db.scalars(stmt)]


def _validate_template_vector(vector: str | None) -> str | None:
    if vector:
        try:
            return cvss.calculate(vector).vector
        except cvss.CvssError as exc:
            raise HTTPException(422, f"Invalid CVSS vector: {exc}") from None
    return vector


@router.post("/api/finding-templates", response_model=FindingTemplateOut, status_code=201)
def create_template(body: FindingTemplateIn, request: Request, user: User = Depends(require_lead),
                    db: Session = Depends(get_db)):
    if db.scalar(select(FindingTemplate).where(FindingTemplate.title == body.title)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A template with this title already exists")
    data = body.model_dump()
    data["cvss_vector"] = _validate_template_vector(data["cvss_vector"]) or ""
    tpl = FindingTemplate(**data)
    db.add(tpl)
    db.flush()
    audit.record(db, user=user, action="create", entity_type="finding_template", entity_id=tpl.id,
                 summary=f"Created template '{tpl.title}'", request=request)
    db.commit()
    return template_out(tpl)


@router.patch("/api/finding-templates/{template_id}", response_model=FindingTemplateOut)
def update_template(template_id: int, body: FindingTemplateUpdate, request: Request,
                    user: User = Depends(require_lead), db: Session = Depends(get_db)):
    tpl = db.get(FindingTemplate, template_id)
    if tpl is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    data = body.model_dump(exclude_unset=True, exclude_none=True)
    if "cvss_vector" in data:
        data["cvss_vector"] = _validate_template_vector(data["cvss_vector"]) or ""
    if "title" in data and data["title"] != tpl.title and db.scalar(
        select(FindingTemplate).where(FindingTemplate.title == data["title"])
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "A template with this title already exists")
    for k, v in data.items():
        setattr(tpl, k, v)
    audit.record(db, user=user, action="update", entity_type="finding_template", entity_id=tpl.id,
                 summary=f"Updated template '{tpl.title}'", request=request)
    db.commit()
    return template_out(tpl)


@router.delete("/api/finding-templates/{template_id}", status_code=204)
def delete_template(template_id: int, request: Request, user: User = Depends(require_lead),
                    db: Session = Depends(get_db)):
    tpl = db.get(FindingTemplate, template_id)
    if tpl is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    db.delete(tpl)
    audit.record(db, user=user, action="delete", entity_type="finding_template",
                 entity_id=template_id, summary=f"Deleted template '{tpl.title}'", request=request)
    db.commit()


@router.post("/api/cvss", response_model=CvssOut)
def score_cvss(body: CvssIn, _: User = Depends(current_user)):
    try:
        r = cvss.calculate(body.vector)
    except cvss.CvssError as exc:
        raise HTTPException(422, str(exc)) from None
    return CvssOut(vector=r.vector, score=r.score, severity=r.severity, metrics=r.metrics)
