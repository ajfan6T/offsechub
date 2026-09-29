import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import EngagementAccess, current_user, engagement_reader, engagement_writer, get_or_404, require_admin
from ..models import AuditEvent, Engagement, EngagementMember, Finding, OperatorLogEntry, TestCase, User
from ..schemas import AuditOut, DashboardOut, OplogIn, OplogOut
from ..services import audit
from ..services.findings import finding_ref
from .engagements import engagement_out, finding_counts, visible_engagements_query

router = APIRouter(tags=["activity"])
oplog_prefix = "/api/engagements/{engagement_id}/oplog"


# ----------------------------------------------------------------- operator log


@router.get(oplog_prefix, response_model=list[OplogOut])
def list_oplog(access: EngagementAccess = Depends(engagement_reader), db: Session = Depends(get_db)):
    return db.scalars(
        select(OperatorLogEntry)
        .where(OperatorLogEntry.engagement_id == access.engagement.id)
        .order_by(OperatorLogEntry.occurred_at.desc())
    ).all()


@router.post(oplog_prefix, response_model=OplogOut, status_code=201)
def add_oplog(body: OplogIn, request: Request,
              access: EngagementAccess = Depends(engagement_writer),
              db: Session = Depends(get_db)):
    data = body.model_dump()
    if data["occurred_at"] is None:
        data.pop("occurred_at")
    if not any(data.get(k) for k in ("command", "description", "target")):
        raise HTTPException(422, "Provide at least a command, description or target")
    entry = OperatorLogEntry(engagement_id=access.engagement.id, user_id=access.user.id, **data)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.delete(oplog_prefix + "/{entry_id}", status_code=204)
def delete_oplog(entry_id: int, request: Request,
                 access: EngagementAccess = Depends(engagement_writer),
                 db: Session = Depends(get_db)):
    entry = get_or_404(db, OperatorLogEntry, entry_id, access.engagement.id)
    if entry.user_id != access.user.id and not access.can_manage:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only delete your own entries")
    db.delete(entry)
    # Log removal is itself audited: the op log is a deconfliction record.
    audit.record(db, user=access.user, action="delete", entity_type="oplog", entity_id=entry_id,
                 engagement_id=access.engagement.id,
                 summary=f"Deleted op-log entry from {entry.occurred_at:%Y-%m-%d %H:%M} "
                         f"({entry.tool} {entry.target})".strip(),
                 request=request)
    db.commit()


@router.get(oplog_prefix + "/export.csv")
def export_oplog(request: Request, access: EngagementAccess = Depends(engagement_reader),
                 db: Session = Depends(get_db)):
    """CSV for blue-team deconfliction: who did what, from where, against what, when."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["occurred_at_utc", "operator", "source_host", "target", "tool", "command",
                "description", "outcome"])
    for e in list_oplog(access, db)[::-1]:
        w.writerow([e.occurred_at.isoformat(), e.user.email if e.user else "", e.source_host,
                    e.target, e.tool, e.command, e.description, e.outcome])
    audit.record(db, user=access.user, action="export", entity_type="oplog",
                 engagement_id=access.engagement.id, summary="Exported operator log (CSV)",
                 request=request)
    db.commit()
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="{access.engagement.code}-oplog.csv"'},
    )


# ---------------------------------------------------------------- audit trail


@router.get("/api/engagements/{engagement_id}/activity", response_model=list[AuditOut])
def engagement_activity(limit: int = Query(200, ge=1, le=1000),
                        access: EngagementAccess = Depends(engagement_reader),
                        db: Session = Depends(get_db)):
    return db.scalars(
        select(AuditEvent)
        .where(AuditEvent.engagement_id == access.engagement.id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
    ).all()


@router.get("/api/audit", response_model=list[AuditOut])
def global_audit(limit: int = Query(200, ge=1, le=1000), _: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    return db.scalars(
        select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit)
    ).all()


# ------------------------------------------------------------------ dashboard

OPEN_FINDING_STATUSES = ("draft", "confirmed", "reported")


@router.get("/api/dashboard", response_model=DashboardOut)
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    engagements = db.scalars(visible_engagements_query(user)).all()
    ids = [e.id for e in engagements]
    by_status: dict[str, int] = {}
    for e in engagements:
        by_status[e.status] = by_status.get(e.status, 0) + 1

    open_by_sev = dict(
        db.execute(
            select(Finding.severity, func.count())
            .where(Finding.engagement_id.in_(ids), Finding.status.in_(OPEN_FINDING_STATUSES))
            .group_by(Finding.severity)
        ).all()
    ) if ids else {}

    my_open_tests = db.scalar(
        select(func.count(TestCase.id)).where(
            TestCase.assignee_id == user.id,
            TestCase.status.in_(("not_started", "in_progress", "blocked")),
            TestCase.engagement_id.in_(ids),
        )
    ) if ids else 0

    roles = dict(
        db.execute(
            select(EngagementMember.engagement_id, EngagementMember.role).where(
                EngagementMember.user_id == user.id
            )
        ).all()
    )
    active = [e for e in engagements if e.status in ("planning", "active", "reporting", "review")]
    active.sort(key=lambda e: (e.end_date is None, e.end_date or e.created_at.date()))
    counts = finding_counts(db, [e.id for e in active])

    recent = db.scalars(
        select(Finding)
        .where(Finding.engagement_id.in_(ids), Finding.status != "false_positive")
        .order_by(Finding.created_at.desc())
        .limit(8)
    ).all() if ids else []
    eng_by_id: dict[int, Engagement] = {e.id: e for e in engagements}

    return DashboardOut(
        engagements_by_status=by_status,
        open_findings_by_severity=open_by_sev,
        my_open_tests=my_open_tests or 0,
        active_engagements=[engagement_out(e, roles.get(e.id), counts.get(e.id, {})) for e in active[:10]],
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
