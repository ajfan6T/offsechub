from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db, get_vault
from ..deps import get_engagement
from ..models import (
    Client,
    Engagement,
    Evidence,
    Finding,
    OperatorLogEntry,
    Service,
    Target,
    TestCase,
)
from ..schemas import EngagementCreate, EngagementOut, EngagementSummary, EngagementUpdate
from ..services import audit, storage
from ..services.scope import ScopeMatcher
from ..vault.manager import OpenVault

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


def finding_counts(db: Session, engagement_ids: list[int]) -> dict[int, dict[str, int]]:
    """Severity counts per engagement, ignoring false positives."""
    rows = db.execute(
        select(Finding.engagement_id, Finding.severity, func.count())
        .where(Finding.engagement_id.in_(engagement_ids), Finding.status != "false_positive")
        .group_by(Finding.engagement_id, Finding.severity)
    ).all()
    out: dict[int, dict[str, int]] = {}
    for eid, sev, n in rows:
        out.setdefault(eid, {})[sev] = n
    return out


def engagement_out(eng: Engagement, counts: dict[str, int]) -> EngagementOut:
    out = EngagementOut.model_validate(eng)
    out.finding_counts = counts
    return out


def _with_counts(db: Session, eng: Engagement) -> EngagementOut:
    return engagement_out(eng, finding_counts(db, [eng.id]).get(eng.id, {}))


def _check_dates(start, end) -> None:
    if start and end and end < start:
        raise HTTPException(422, "end_date is before start_date")


@router.get("", response_model=list[EngagementOut])
def list_engagements(status_filter: str | None = Query(None, alias="status"),
                     db: Session = Depends(get_db)):
    q = select(Engagement).order_by(Engagement.updated_at.desc())
    if status_filter:
        q = q.where(Engagement.status == status_filter)
    engagements = db.scalars(q).all()
    counts = finding_counts(db, [e.id for e in engagements])
    return [engagement_out(e, counts.get(e.id, {})) for e in engagements]


@router.post("", response_model=EngagementOut, status_code=201)
def create_engagement(body: EngagementCreate, db: Session = Depends(get_db)):
    if db.get(Client, body.client_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    if db.scalar(select(Engagement).where(Engagement.code == body.code)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Engagement code {body.code} is already used")
    _check_dates(body.start_date, body.end_date)
    eng = Engagement(**body.model_dump())
    db.add(eng)
    db.flush()
    audit.record(db, action="create", entity_type="engagement", entity_id=eng.id,
                 engagement_id=eng.id, summary=f"Created engagement {eng.code} {eng.name}")
    db.commit()
    return engagement_out(eng, {})


@router.get("/{engagement_id}", response_model=EngagementOut)
def read_engagement(eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    return _with_counts(db, eng)


@router.patch("/{engagement_id}", response_model=EngagementOut)
def update_engagement(body: EngagementUpdate, eng: Engagement = Depends(get_engagement),
                      db: Session = Depends(get_db)):
    data = body.model_dump(exclude_unset=True)
    if data.get("client_id") is not None and db.get(Client, data["client_id"]) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    _check_dates(data.get("start_date", eng.start_date), data.get("end_date", eng.end_date))
    changed = []
    for key, value in data.items():
        # Dates may be cleared with null; other fields ignore it.
        if (key in ("start_date", "end_date") or value is not None) and getattr(eng, key) != value:
            setattr(eng, key, value)
            changed.append(key)
    audit.record(db, action="update", entity_type="engagement", entity_id=eng.id,
                 engagement_id=eng.id, summary=f"Updated {', '.join(changed) or 'nothing'}")
    db.commit()
    db.refresh(eng)
    return _with_counts(db, eng)


@router.delete("/{engagement_id}", status_code=204)
def delete_engagement(eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db),
                      vault: OpenVault = Depends(get_vault)):
    blob_ids = [ev.storage_key for ev in eng.evidence]
    audit.record(db, action="delete", entity_type="engagement", entity_id=eng.id,
                 summary=f"Deleted engagement {eng.code} {eng.name} "
                         f"and {len(blob_ids)} evidence files")
    db.delete(eng)
    db.commit()
    storage.delete_blobs(vault, blob_ids)


@router.get("/{engagement_id}/summary", response_model=EngagementSummary)
def engagement_summary(eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    matcher = ScopeMatcher(eng.scope_items)
    targets = db.scalars(select(Target).where(Target.engagement_id == eng.id)).all()
    scope_counts = Counter(matcher.check_target(t.value, t.ip, t.hostname) for t in targets)

    def grouped(column, model):
        return dict(
            db.execute(
                select(column, func.count()).where(model.engagement_id == eng.id).group_by(column)
            ).all()
        )

    return EngagementSummary(
        targets=len(targets),
        targets_in_scope=scope_counts["in_scope"],
        targets_out_of_scope=scope_counts["out_of_scope"] + scope_counts["excluded"],
        targets_compromised=sum(1 for t in targets if t.status == "compromised"),
        services=db.scalar(
            select(func.count(Service.id)).join(Target).where(Target.engagement_id == eng.id)
        ) or 0,
        scope_items=len(eng.scope_items),
        findings_by_severity=finding_counts(db, [eng.id]).get(eng.id, {}),
        findings_by_status=grouped(Finding.status, Finding),
        tests_by_status=grouped(TestCase.status, TestCase),
        evidence=db.scalar(select(func.count(Evidence.id)).where(Evidence.engagement_id == eng.id)) or 0,
        oplog_entries=db.scalar(
            select(func.count(OperatorLogEntry.id)).where(OperatorLogEntry.engagement_id == eng.id)
        ) or 0,
    )
