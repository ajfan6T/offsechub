import ipaddress

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..db import get_db
from ..deps import get_engagement, get_or_404
from ..models import Engagement, Service, Target, finding_targets
from ..schemas import ServiceIn, ServiceOut, TargetIn, TargetOut, TargetUpdate
from ..services import audit
from ..services.scope import ScopeMatcher

router = APIRouter(prefix="/api/engagements/{engagement_id}/targets", tags=["targets"])


def _finding_counts(db: Session, target_ids: list[int]) -> dict[int, int]:
    if not target_ids:
        return {}
    return dict(
        db.execute(
            select(finding_targets.c.target_id, func.count())
            .where(finding_targets.c.target_id.in_(target_ids))
            .group_by(finding_targets.c.target_id)
        ).all()
    )


def target_out(t: Target, matcher: ScopeMatcher, finding_count: int = 0) -> TargetOut:
    out = TargetOut.model_validate(t)
    out.scope_status = matcher.check_target(t.value, t.ip, t.hostname)
    out.finding_count = finding_count
    return out


def _clean_tags(tags: list[str]) -> list[str]:
    return sorted({t.strip().lower()[:50] for t in tags if t.strip()})


@router.get("", response_model=list[TargetOut])
def list_targets(q: str | None = None, scope_status: str | None = None, kind: str | None = None,
                 eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    stmt = (
        select(Target)
        .where(Target.engagement_id == eng.id)
        .options(selectinload(Target.services))
        .order_by(Target.value)
    )
    if kind:
        stmt = stmt.where(Target.kind == kind)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            func.lower(Target.value).like(like)
            | func.lower(Target.hostname).like(like)
            | Target.ip.like(like)
            | func.lower(Target.os).like(like)
        )
    targets = db.scalars(stmt).all()
    matcher = ScopeMatcher(eng.scope_items)
    counts = _finding_counts(db, [t.id for t in targets])
    out = [target_out(t, matcher, counts.get(t.id, 0)) for t in targets]
    if scope_status:
        out = [t for t in out if t.scope_status == scope_status]
    return out


@router.post("", response_model=TargetOut, status_code=201)
def create_target(body: TargetIn, eng: Engagement = Depends(get_engagement),
                  db: Session = Depends(get_db)):
    value = body.value.strip()
    if db.scalar(select(Target).where(Target.engagement_id == eng.id, Target.value == value)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Target already exists in this engagement")
    data = body.model_dump()
    data.update(value=value, tags=_clean_tags(body.tags))
    if not data["ip"]:
        try:
            data["ip"] = str(ipaddress.ip_address(value))
        except ValueError:
            pass
    target = Target(engagement_id=eng.id, source="manual", **data)
    db.add(target)
    db.flush()
    out = target_out(target, ScopeMatcher(eng.scope_items))
    audit.record(db, action="create", entity_type="target", entity_id=target.id,
                 engagement_id=eng.id, summary=f"Added target {value} ({out.scope_status})")
    db.commit()
    return out


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, eng: Engagement = Depends(get_engagement),
               db: Session = Depends(get_db)):
    t = get_or_404(db, Target, target_id, eng.id)
    return target_out(t, ScopeMatcher(eng.scope_items), _finding_counts(db, [t.id]).get(t.id, 0))


@router.patch("/{target_id}", response_model=TargetOut)
def update_target(target_id: int, body: TargetUpdate, eng: Engagement = Depends(get_engagement),
                  db: Session = Depends(get_db)):
    t = get_or_404(db, Target, target_id, eng.id)
    data = body.model_dump(exclude_unset=True, exclude_none=True)
    if "tags" in data:
        data["tags"] = _clean_tags(data["tags"])
    for k, v in data.items():
        setattr(t, k, v)
    audit.record(db, action="update", entity_type="target", entity_id=t.id,
                 engagement_id=eng.id,
                 summary=f"Updated target {t.value}: {', '.join(data) or 'nothing'}")
    db.commit()
    return target_out(t, ScopeMatcher(eng.scope_items), _finding_counts(db, [t.id]).get(t.id, 0))


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, eng: Engagement = Depends(get_engagement),
                  db: Session = Depends(get_db)):
    t = get_or_404(db, Target, target_id, eng.id)
    db.delete(t)
    audit.record(db, action="delete", entity_type="target", entity_id=target_id,
                 engagement_id=eng.id, summary=f"Deleted target {t.value}")
    db.commit()


# ------------------------------------------------------------------- services


@router.post("/{target_id}/services", response_model=ServiceOut, status_code=201)
def add_service(target_id: int, body: ServiceIn, eng: Engagement = Depends(get_engagement),
                db: Session = Depends(get_db)):
    t = get_or_404(db, Target, target_id, eng.id)
    if any(s.port == body.port and s.protocol == body.protocol for s in t.services):
        raise HTTPException(status.HTTP_409_CONFLICT, "Service already recorded on this target")
    svc = Service(target_id=t.id, **body.model_dump())
    db.add(svc)
    db.flush()
    audit.record(db, action="create", entity_type="service", entity_id=svc.id,
                 engagement_id=eng.id, summary=f"Added {body.port}/{body.protocol} to {t.value}")
    db.commit()
    return svc


def _service_or_404(db: Session, eng: Engagement, target_id: int, service_id: int) -> Service:
    t = get_or_404(db, Target, target_id, eng.id)
    svc = db.get(Service, service_id)
    if svc is None or svc.target_id != t.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service not found")
    return svc


@router.put("/{target_id}/services/{service_id}", response_model=ServiceOut)
def update_service(target_id: int, service_id: int, body: ServiceIn,
                   eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    svc = _service_or_404(db, eng, target_id, service_id)
    for k, v in body.model_dump().items():
        setattr(svc, k, v)
    audit.record(db, action="update", entity_type="service", entity_id=svc.id,
                 engagement_id=eng.id,
                 summary=f"Updated {svc.port}/{svc.protocol} on {svc.target.value}")
    db.commit()
    return svc


@router.delete("/{target_id}/services/{service_id}", status_code=204)
def delete_service(target_id: int, service_id: int, eng: Engagement = Depends(get_engagement),
                   db: Session = Depends(get_db)):
    svc = _service_or_404(db, eng, target_id, service_id)
    db.delete(svc)
    audit.record(db, action="delete", entity_type="service", entity_id=service_id,
                 engagement_id=eng.id,
                 summary=f"Removed {svc.port}/{svc.protocol} from {svc.target.value}")
    db.commit()
