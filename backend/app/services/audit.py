from fastapi import Request
from sqlalchemy.orm import Session

from ..models import AuditEvent, User


def client_ip(request: Request | None) -> str:
    if request is None or request.client is None:
        return ""
    return request.client.host


def record(
    db: Session,
    *,
    user: User | None,
    action: str,
    entity_type: str,
    entity_id: int | None = None,
    engagement_id: int | None = None,
    summary: str = "",
    request: Request | None = None,
) -> None:
    """Append an audit event. Committed together with the caller's transaction."""
    db.add(
        AuditEvent(
            user_id=user.id if user else None,
            engagement_id=engagement_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            summary=summary[:1000],
            ip_address=client_ip(request),
        )
    )
