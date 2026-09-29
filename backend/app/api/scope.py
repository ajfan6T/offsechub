from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_engagement, get_or_404
from ..models import Engagement, ScopeItem
from ..schemas import ScopeCheckIn, ScopeCheckResult, ScopeItemIn, ScopeItemOut, ScopeItemUpdate
from ..services import audit
from ..services.scope import ScopeMatcher, normalize_scope_value

router = APIRouter(prefix="/api/engagements/{engagement_id}/scope", tags=["scope"])


@router.get("", response_model=list[ScopeItemOut])
def list_scope(eng: Engagement = Depends(get_engagement)):
    return sorted(eng.scope_items, key=lambda s: (s.rule != "include", s.kind, s.value))


@router.post("", response_model=ScopeItemOut, status_code=201)
def add_scope_item(body: ScopeItemIn, eng: Engagement = Depends(get_engagement),
                   db: Session = Depends(get_db)):
    """Scope is a contractual boundary, so every change is recorded in the activity log."""
    try:
        value = normalize_scope_value(body.kind, body.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if any(s.kind == body.kind and s.value == value and s.rule == body.rule for s in eng.scope_items):
        raise HTTPException(status.HTTP_409_CONFLICT, "That scope rule already exists")
    item = ScopeItem(engagement_id=eng.id, kind=body.kind, value=value, rule=body.rule,
                     notes=body.notes)
    db.add(item)
    db.flush()
    audit.record(db, action="create", entity_type="scope", entity_id=item.id,
                 engagement_id=eng.id, summary=f"Scope {body.rule}: {body.kind} {value}")
    db.commit()
    return item


@router.patch("/{item_id}", response_model=ScopeItemOut)
def update_scope_item(item_id: int, body: ScopeItemUpdate,
                      eng: Engagement = Depends(get_engagement), db: Session = Depends(get_db)):
    item = get_or_404(db, ScopeItem, item_id, eng.id)
    for k, v in body.model_dump(exclude_unset=True, exclude_none=True).items():
        setattr(item, k, v)
    audit.record(db, action="update", entity_type="scope", entity_id=item.id,
                 engagement_id=eng.id, summary=f"Scope {item.rule}: {item.kind} {item.value}")
    db.commit()
    return item


@router.delete("/{item_id}", status_code=204)
def delete_scope_item(item_id: int, eng: Engagement = Depends(get_engagement),
                      db: Session = Depends(get_db)):
    item = get_or_404(db, ScopeItem, item_id, eng.id)
    db.delete(item)
    audit.record(db, action="delete", entity_type="scope", entity_id=item_id,
                 engagement_id=eng.id,
                 summary=f"Removed scope {item.rule}: {item.kind} {item.value}")
    db.commit()


@router.post("/check", response_model=list[ScopeCheckResult])
def check_scope(body: ScopeCheckIn, eng: Engagement = Depends(get_engagement)):
    """Check arbitrary hosts/IPs/URLs against this engagement's scope before touching them."""
    matcher = ScopeMatcher(eng.scope_items)
    results = []
    for raw in body.values:
        if not raw.strip():
            continue
        d = matcher.check(raw)
        results.append(ScopeCheckResult(value=d.value, status=d.status, rule_id=d.rule_id,
                                         reason=d.reason))
    return results
