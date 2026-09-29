from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin, require_writer
from ..models import AuthToken, User
from ..schemas import UserBrief, UserCreate, UserOut, UserUpdate
from ..security import hash_password
from ..services import audit

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.full_name)).all()


@router.get("/directory", response_model=list[UserBrief])
def directory(_: User = Depends(require_writer), db: Session = Depends(get_db)):
    """Active users, for picking team members and assignees (no account details)."""
    return db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.full_name)).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with that email already exists")
    user = User(
        email=body.email,
        full_name=body.full_name,
        role=body.role,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    db.flush()
    audit.record(db, user=admin, action="create", entity_type="user", entity_id=user.id,
                 summary=f"Created user {user.email} ({user.role})", request=request)
    db.commit()
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, request: Request,
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    data = body.model_dump(exclude_unset=True)
    if user.id == admin.id and (data.get("role", "admin") != "admin" or data.get("is_active") is False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot demote or disable yourself")

    changes = []
    if "password" in data and data["password"]:
        user.password_hash = hash_password(data.pop("password"))
        changes.append("password reset")
    data.pop("password", None)
    for key, value in data.items():
        if value is not None and getattr(user, key) != value:
            setattr(user, key, value)
            changes.append(f"{key}={value}")
    if data.get("is_active") is False or "password reset" in changes:
        # Disabling or resetting a password kills every live session and token.
        db.execute(delete(AuthToken).where(AuthToken.user_id == user.id))
    audit.record(db, user=admin, action="update", entity_type="user", entity_id=user.id,
                 summary=f"Updated {user.email}: {', '.join(changes) or 'no changes'}",
                 request=request)
    db.commit()
    return user
