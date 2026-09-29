"""Request dependencies for engagement-scoped routes.

Single operator: there are no roles or memberships. What remains is making
sure every object belongs to the engagement in the URL.
"""

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from .db import get_db
from .models import Engagement


def get_engagement(engagement_id: int, db: Session = Depends(get_db)) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found")
    return eng


def get_or_404(db: Session, model, obj_id: int, engagement_id: int):
    """Fetch an engagement-scoped row, refusing rows from other engagements."""
    obj = db.get(model, obj_id)
    if obj is None or obj.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{model.__name__} not found")
    return obj
