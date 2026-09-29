from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import (
    EngagementAccess,
    current_user,
    engagement_manager,
    engagement_reader,
    require_lead,
)
from ..models import (
    Client,
    Engagement,
    EngagementMember,
    Evidence,
    Finding,
    OperatorLogEntry,
    Service,
    Target,
    TestCase,
    User,
)
from ..schemas import (
    EngagementCreate,
    EngagementOut,
    EngagementSummary,
    EngagementUpdate,
    MemberIn,
    MemberOut,
)
from ..services import audit, storage
from ..services.scope import ScopeMatcher

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


def engagement_out(eng: Engagement, my_role: str | None, counts: dict[str, int]) -> EngagementOut:
    out = EngagementOut.model_validate(eng)
    out.my_role = my_role
    out.finding_counts = counts
    return out


def visible_engagements_query(user: User):
    q = select(Engagement)
    if user.role != "admin":
        q = q.join(EngagementMember).where(EngagementMember.user_id == user.id)
    return q


def _check_dates(start, end) -> None:
    if start and end and end < start:
        raise HTTPException(422, "end_date is before start_date")


@router.get("", response_model=list[EngagementOut])
def list_engagements(status_filter: str | None = Query(None, alias="status"),
                     user: User = Depends(current_user),
                     db: Session = Depends(get_db)):
    q = visible_engagements_query(user).order_by(Engagement.updated_at.desc())
    if status_filter:
        q = q.where(Engagement.status == status_filter)
    engagements = db.scalars(q).all()
    roles = dict(
        db.execute(
            select(EngagementMember.engagement_id, EngagementMember.role).where(
                EngagementMember.user_id == user.id
            )
        ).all()
    )
    counts = finding_counts(db, [e.id for e in engagements])
    return [engagement_out(e, roles.get(e.id), counts.get(e.id, {})) for e in engagements]


@router.post("", response_model=EngagementOut, status_code=201)
def create_engagement(body: EngagementCreate, request: Request, user: User = Depends(require_lead),
                      db: Session = Depends(get_db)):
    if db.get(Client, body.client_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    if db.scalar(select(Engagement).where(Engagement.code == body.code)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Engagement code {body.code} is already used")
    _check_dates(body.start_date, body.end_date)
    eng = Engagement(**body.model_dump(), created_by_id=user.id)
    eng.members.append(EngagementMember(user_id=user.id, role="lead"))
    db.add(eng)
    db.flush()
    audit.record(db, user=user, action="create", entity_type="engagement", entity_id=eng.id,
                 engagement_id=eng.id, summary=f"Created engagement {eng.code} {eng.name}",
                 request=request)
    db.commit()
    return engagement_out(eng, "lead", {})


@router.get("/{engagement_id}", response_model=EngagementOut)
def get_engagement(access: EngagementAccess = Depends(engagement_reader),
                   db: Session = Depends(get_db)):
    eng = access.engagement
    return engagement_out(eng, access.member_role, finding_counts(db, [eng.id]).get(eng.id, {}))


@router.patch("/{engagement_id}", response_model=EngagementOut)
def update_engagement(body: EngagementUpdate, request: Request,
                      access: EngagementAccess = Depends(engagement_manager),
                      db: Session = Depends(get_db)):
    eng = access.engagement
    data = body.model_dump(exclude_unset=True)
    if "client_id" in data and data["client_id"] is not None and db.get(Client, data["client_id"]) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    _check_dates(data.get("start_date", eng.start_date), data.get("end_date", eng.end_date))
    changed = []
    for key, value in data.items():
        if key in ("start_date", "end_date") or value is not None:
            if getattr(eng, key) != value:
                setattr(eng, key, value)
                changed.append(key)
    audit.record(db, user=access.user, action="update", entity_type="engagement", entity_id=eng.id,
                 engagement_id=eng.id,
                 summary=f"Updated {', '.join(changed) or 'nothing'}", request=request)
    db.commit()
    db.refresh(eng)
    return engagement_out(eng, access.member_role, finding_counts(db, [eng.id]).get(eng.id, {}))


@router.delete("/{engagement_id}", status_code=204)
def delete_engagement(request: Request, access: EngagementAccess = Depends(engagement_reader),
                      db: Session = Depends(get_db)):
    if access.user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admins can delete engagements")
    eng = access.engagement
    files = list(eng.evidence)
    audit.record(db, user=access.user, action="delete", entity_type="engagement", entity_id=eng.id,
                 summary=f"Deleted engagement {eng.code} {eng.name} and {len(files)} evidence files",
                 request=request)
    db.delete(eng)
    db.commit()
    for ev in files:
        storage.delete_evidence_file(ev)


@router.get("/{engagement_id}/summary", response_model=EngagementSummary)
def engagement_summary(access: EngagementAccess = Depends(engagement_reader),
                       db: Session = Depends(get_db)):
    eng = access.engagement
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
        findings_by_severity=dict(
            db.execute(
                select(Finding.severity, func.count())
                .where(Finding.engagement_id == eng.id, Finding.status != "false_positive")
                .group_by(Finding.severity)
            ).all()
        ),
        findings_by_status=grouped(Finding.status, Finding),
        tests_by_status=grouped(TestCase.status, TestCase),
        evidence=db.scalar(select(func.count(Evidence.id)).where(Evidence.engagement_id == eng.id)) or 0,
        oplog_entries=db.scalar(
            select(func.count(OperatorLogEntry.id)).where(OperatorLogEntry.engagement_id == eng.id)
        ) or 0,
    )


# -------------------------------------------------------------------- members


@router.get("/{engagement_id}/members", response_model=list[MemberOut])
def list_members(access: EngagementAccess = Depends(engagement_reader)):
    return sorted(access.engagement.members, key=lambda m: m.user.full_name.lower())


@router.put("/{engagement_id}/members", response_model=MemberOut)
def upsert_member(body: MemberIn, request: Request,
                  access: EngagementAccess = Depends(engagement_manager),
                  db: Session = Depends(get_db)):
    """Add a member or change their role."""
    eng = access.engagement
    target_user = db.get(User, body.user_id)
    if target_user is None or not target_user.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    member = db.get(EngagementMember, (eng.id, body.user_id))
    if member is None:
        member = EngagementMember(engagement_id=eng.id, user_id=body.user_id, role=body.role)
        db.add(member)
        summary = f"Added {target_user.email} as {body.role}"
    else:
        if member.role == "lead" and body.role != "lead" and _lead_count(eng) == 1:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "An engagement needs at least one lead")
        member.role = body.role
        summary = f"Changed {target_user.email} to {body.role}"
    audit.record(db, user=access.user, action="update", entity_type="member",
                 entity_id=body.user_id, engagement_id=eng.id, summary=summary, request=request)
    db.commit()
    db.refresh(member)
    return member


def _lead_count(eng: Engagement) -> int:
    return sum(1 for m in eng.members if m.role == "lead")


@router.delete("/{engagement_id}/members/{user_id}", status_code=204)
def remove_member(user_id: int, request: Request,
                  access: EngagementAccess = Depends(engagement_manager),
                  db: Session = Depends(get_db)):
    eng = access.engagement
    member = db.get(EngagementMember, (eng.id, user_id))
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
    if member.role == "lead" and _lead_count(eng) == 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "An engagement needs at least one lead")
    email = member.user.email
    db.delete(member)
    audit.record(db, user=access.user, action="delete", entity_type="member", entity_id=user_id,
                 engagement_id=eng.id, summary=f"Removed {email}", request=request)
    db.commit()
