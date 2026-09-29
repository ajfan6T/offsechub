"""Operator log, activity feed and dashboard."""

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..bootstrap import get_setting
from ..db import get_db
from ..deps import get_engagement, get_or_404
from ..models import AuditEvent, Engagement, Finding, OperatorLogEntry, TestCase
from ..schemas import ActivityOut, DashboardOut, OplogIn, OplogOut
from ..services import audit
from ..services.findings import finding_ref
from .engagements import engagement_out, finding_counts

router = APIRouter(tags=["activity"])
oplog_prefix = "/api/engagements/{engagement_id}/oplog"

ACTIVE_ENGAGEMENT_STATUSES = ("planning", "active", "reporting", "review")
OPEN_FINDING_STATUSES = ("draft", "confirmed", "reported")
OPEN_TEST_STATUSES = ("not_started", "in_progress", "blocked")


def profile_name(db: Session) -> str:
    return (get_setting(db, "operator.profile") or {}).get("name", "")


# ----------------------------------------------------------------- operator log


def _oplog(db: Session, eng: Engagement) -> list[OperatorLogEntry]:
    return db.scalars(
        select(OperatorLogEntry)
        .where(OperatorLogEntry.engagement_id == eng.id)
        .order_by(OperatorLogEntry.occurred_at.desc())
    ).all()


@router.get(oplog_prefix, response_model=list[OplogOut])
def list_oplog(eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    return _oplog(db, eng)


@router.post(oplog_prefix, response_model=OplogOut, status_code=201)
def add_oplog(body: OplogIn, eng: Engagement = Depends(get_engagement),
              db: Session = Depends(get_db)):
    data = body.model_dump()
    if data["occurred_at"] is None:
        data.pop("occurred_at")
    if not any(data.get(k) for k in ("command", "description", "target")):
        raise HTTPException(422, "Provide at least a command, description or target")
    data["operator"] = (data["operator"] or "").strip() or profile_name(db)
    entry = OperatorLogEntry(engagement_id=eng.id, **data)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.delete(oplog_prefix + "/{entry_id}", status_code=204)
def delete_oplog(entry_id: int, eng: Engagement = Depends(get_engagement),
                 db: Session = Depends(get_db)):
    entry = get_or_404(db, OperatorLogEntry, entry_id, eng.id)
    db.delete(entry)
    # Log removal is itself recorded: the op log is a deconfliction record.
    audit.record(db, action="delete", entity_type="oplog", entity_id=entry_id,
                 engagement_id=eng.id,
                 summary=f"Deleted op-log entry from {entry.occurred_at:%Y-%m-%d %H:%M} "
                         f"({entry.tool} {entry.target})".strip())
    db.commit()


@router.get(oplog_prefix + "/export.csv")
def export_oplog(eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    """CSV for blue-team deconfliction: who did what, from where, against what, when."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["occurred_at_utc", "operator", "source_host", "target", "tool", "command",
                "description", "outcome"])
    for e in reversed(_oplog(db, eng)):
        w.writerow([e.occurred_at.isoformat(), e.operator, e.source_host, e.target, e.tool,
                    e.command, e.description, e.outcome])
    audit.record(db, action="export", entity_type="oplog", engagement_id=eng.id,
                 summary="Exported operator log (CSV)")
    db.commit()
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{eng.code}-oplog.csv"'},
    )


# --------------------------------------------------------------------- activity


def _activity(db: Session, limit: int, engagement_id: int | None = None) -> list[AuditEvent]:
    q = select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit)
    if engagement_id is not None:
        q = q.where(AuditEvent.engagement_id == engagement_id)
    return db.scalars(q).all()


@router.get("/api/engagements/{engagement_id}/activity", response_model=list[ActivityOut])
def engagement_activity(limit: int = Query(200, ge=1, le=1000),
                        eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    return _activity(db, limit, eng.id)


@router.get("/api/activity", response_model=list[ActivityOut])
def vault_activity(limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)):
    """Everything recorded in this vault, including vault events and deleted engagements."""
    return _activity(db, limit)


# ------------------------------------------------------------------ dashboard


@router.get("/api/dashboard", response_model=DashboardOut)
def dashboard(db: Session = Depends(get_db)):
    engagements = db.scalars(select(Engagement)).all()
    by_status: dict[str, int] = {}
    for e in engagements:
        by_status[e.status] = by_status.get(e.status, 0) + 1

    open_by_sev = dict(
        db.execute(
            select(Finding.severity, func.count())
            .where(Finding.status.in_(OPEN_FINDING_STATUSES))
            .group_by(Finding.severity)
        ).all()
    )

    active = [e for e in engagements if e.status in ACTIVE_ENGAGEMENT_STATUSES]
    active.sort(key=lambda e: (e.end_date is None, e.end_date or e.created_at.date()))
    active_ids = [e.id for e in active]
    open_tests = db.scalar(
        select(func.count(TestCase.id)).where(
            TestCase.status.in_(OPEN_TEST_STATUSES), TestCase.engagement_id.in_(active_ids)
        )
    )
    counts = finding_counts(db, active_ids)

    recent = db.scalars(
        select(Finding)
        .where(Finding.status != "false_positive")
        .order_by(Finding.created_at.desc())
        .limit(8)
    ).all()
    eng_by_id = {e.id: e for e in engagements}

    return DashboardOut(
        engagements_by_status=by_status,
        open_findings_by_severity=open_by_sev,
        open_tests=open_tests or 0,
        active_engagements=[engagement_out(e, counts.get(e.id, {})) for e in active[:10]],
        recent_findings=[
            {
                "id": f.id,
                "engagement_id": f.engagement_id,
                "engagement_code": eng_by_id[f.engagement_id].code,
                "ref": finding_ref(eng_by_id[f.engagement_id], f),
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "created_at": f.created_at.isoformat(),
            }
            for f in recent
        ],
    )
