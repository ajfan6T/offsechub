"""Request dependencies: authentication, CSRF protection and access control.

Access model
  * Global roles: admin > lead > tester > viewer.
  * Admins can see and change everything.
  * Everyone else only sees engagements they are a member of; non-members get
    404 so engagement existence is not disclosed.
  * Writing inside an engagement needs member role lead/tester (and a global
    role other than viewer). Managing the engagement itself (settings,
    members, deletion) needs admin or member role lead.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import AuthToken, Engagement, EngagementMember, User
from .security import hash_token

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "x-requested-with"


def _as_aware(dt: datetime) -> datetime:
    # SQLite drops tzinfo; everything we store is UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail)


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    settings = get_settings()
    token: str | None = None
    via_cookie = False

    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    else:
        token = request.cookies.get(settings.session_cookie_name)
        via_cookie = token is not None

    if not token:
        raise _unauthorized()

    # Cookie-authenticated state changes must carry a custom header. Browsers
    # will not attach one cross-site without a CORS preflight we never grant,
    # which blocks CSRF even where SameSite is unavailable.
    if via_cookie and request.method not in SAFE_METHODS and not request.headers.get(CSRF_HEADER):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing X-Requested-With header")

    row = db.scalar(select(AuthToken).where(AuthToken.token_hash == hash_token(token)))
    now = datetime.now(timezone.utc)
    if row is None or (row.expires_at and _as_aware(row.expires_at) < now):
        raise _unauthorized("Session expired or invalid")
    user = row.user
    if not user.is_active:
        raise _unauthorized("Account disabled")

    # Avoid a write on every request.
    if row.last_used_at is None or now - _as_aware(row.last_used_at) > timedelta(minutes=1):
        row.last_used_at = now
        db.commit()

    request.state.auth_token_id = row.id
    return user


def require_roles(*roles: str):
    def checker(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user

    return checker


require_admin = require_roles("admin")
require_lead = require_roles("admin", "lead")
require_writer = require_roles("admin", "lead", "tester")


@dataclass
class EngagementAccess:
    engagement: Engagement
    user: User
    member_role: str | None  # None for admins who aren't members

    @property
    def can_write(self) -> bool:
        if self.user.role == "admin":
            return True
        return self.user.role != "viewer" and self.member_role in ("lead", "tester")

    @property
    def can_manage(self) -> bool:
        return self.user.role == "admin" or (
            self.member_role == "lead" and self.user.role != "viewer"
        )


def load_access(db: Session, user: User, engagement_id: int) -> EngagementAccess:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found")
    member = db.get(EngagementMember, (engagement_id, user.id))
    if member is None and user.role != "admin":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found")
    return EngagementAccess(eng, user, member.role if member else None)


def engagement_reader(
    engagement_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> EngagementAccess:
    return load_access(db, user, engagement_id)


def engagement_writer(access: EngagementAccess = Depends(engagement_reader)) -> EngagementAccess:
    if not access.can_write:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Read-only access to this engagement")
    return access


def engagement_manager(access: EngagementAccess = Depends(engagement_reader)) -> EngagementAccess:
    if not access.can_manage:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the engagement lead can do this")
    return access


def get_or_404(db: Session, model, obj_id: int, engagement_id: int):
    """Fetch an engagement-scoped row, refusing rows from other engagements."""
    obj = db.get(model, obj_id)
    if obj is None or obj.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{model.__name__} not found")
    return obj
