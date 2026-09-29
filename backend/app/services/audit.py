from sqlalchemy.orm import Session

from ..models import AuditEvent


def record(
    db: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: int | None = None,
    engagement_id: int | None = None,
    summary: str = "",
) -> None:
    """Append an activity event. Committed together with the caller's transaction."""
    db.add(
        AuditEvent(
            engagement_id=engagement_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            summary=summary[:1000],
        )
    )
