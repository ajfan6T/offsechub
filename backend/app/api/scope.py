from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import EngagementAccess, engagement_manager, engagement_reader, get_or_404
from ..models import ScopeItem
from ..schemas import ScopeCheckIn, ScopeCheckResult, ScopeItemIn, ScopeItemOut, ScopeItemUpdate
from ..services import audit
from ..services.scope import ScopeMatcher, normalize_scope_value

router = APIRouter(prefix="/api/engagements/{engagement_id}/scope", tags=["scope"])


@router.get("", response_model=list[ScopeItemOut])
def list_scope(access: EngagementAccess = Depends(engagement_reader)):
    return sorted(access.engagement.scope_items, key=lambda s: (s.rule != "include", s.kind, s.value))


@router.post("", response_model=ScopeItemOut, status_code=201)
def add_scope_item(body: ScopeItemIn, request: Request,
                   access: EngagementAccess = Depends(engagement_manager),
                   db: Session = Depends(get_db)):
    """Scope changes are restricted to leads: scope is a contractual boundary."""
    try:
        value = normalize_scope_value(body.kind, body.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    eng = access.engagement
    if any(s.kind == body.kind and s.value == value and s.rule == body.rule for s in eng.scope_items):
        raise HTTPException(status.HTTP_409_CONFLICT, "That scope rule already exists")
    item = ScopeItem(engagement_id=eng.id, kind=body.kind, value=value, rule=body.rule,
                     notes=body.notes)
    db.add(item)
    db.flush()
    audit.record(db, user=access.user, action="create", entity_type="scope", entity_id=item.id,
                 engagement_id=eng.id, summary=f"Scope {body.rule}: {body.kind} {value}",
                 request=request)
    db.commit()
    return item


@router.patch("/{item_id}", response_model=ScopeItemOut)
def update_scope_item(item_id: int, body: ScopeItemUpdate, request: Request,
                      access: EngagementAccess = Depends(engagement_manager),
                      db: Session = Depends(get_db)):
    item = get_or_404(db, ScopeItem, item_id, access.engagement.id)
    for k, v in body.model_dump(exclude_unset=True, exclude_none=True).items():
        setattr(item, k, v)
    audit.record(db, user=access.user, action="update", entity_type="scope", entity_id=item.id,
                 engagement_id=access.engagement.id,
                 summary=f"Scope {item.rule}: {item.kind} {item.value}", request=request)
    db.commit()
    return item


@router.delete("/{item_id}", status_code=204)
def delete_scope_item(item_id: int, request: Request,
                      access: EngagementAccess = Depends(engagement_manager),
                      db: Session = Depends(get_db)):
    item = get_or_404(db, ScopeItem, item_id, access.engagement.id)
    db.delete(item)
    audit.record(db, user=access.user, action="delete", entity_type="scope", entity_id=item_id,
                 engagement_id=access.engagement.id,
                 summary=f"Removed scope {item.rule}: {item.kind} {item.value}", request=request)
    db.commit()


@router.post("/check", response_model=list[ScopeCheckResult])
def check_scope(body: ScopeCheckIn, access: EngagementAccess = Depends(engagement_reader)):
    """Check arbitrary hosts/IPs/URLs against this engagement's scope before touching them."""
    matcher = ScopeMatcher(access.engagement.scope_items)
    results = []
    for raw in body.values:
        if not raw.strip():
            continue
        d = matcher.check(raw)
        results.append(ScopeCheckResult(value=d.value, status=d.status, rule_id=d.rule_id,
                                         reason=d.reason))
    return results
