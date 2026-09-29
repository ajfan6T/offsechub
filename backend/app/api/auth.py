from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import CSRF_HEADER, current_user
from ..models import AuthToken, User
from ..schemas import LoginIn, PasswordChange, TokenCreate, TokenCreated, TokenOut, UserOut
from ..security import (
    DUMMY_PASSWORD_HASH,
    LoginThrottle,
    hash_password,
    hash_token,
    new_token,
    verify_password,
)
from ..services import audit

router = APIRouter(prefix="/api/auth", tags=["auth"])

_settings = get_settings()
throttle = LoginThrottle(_settings.login_max_attempts, _settings.login_window_seconds)


def _issue_session(db: Session, user: User) -> str:
    token = new_token()
    db.add(
        AuthToken(
            user_id=user.id,
            token_hash=hash_token(token),
            kind="session",
            name="browser",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=_settings.session_ttl_hours),
        )
    )
    return token


@router.post("/login", response_model=UserOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    # Login CSRF: require the same custom header as other state changes.
    if not request.headers.get(CSRF_HEADER):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing X-Requested-With header")

    email = body.email.strip().lower()
    keys = (f"ip:{audit.client_ip(request)}", f"email:{email}")
    if throttle.is_blocked(*keys):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed logins, try later")

    user = db.scalar(select(User).where(User.email == email))
    # Always run a hash comparison so response timing doesn't reveal valid emails.
    ok = verify_password(body.password, user.password_hash if user else DUMMY_PASSWORD_HASH)
    if not user or not ok or not user.is_active:
        throttle.record_failure(*keys)
        audit.record(db, user=user, action="login_failed", entity_type="user",
                     entity_id=user.id if user else None, summary=f"Failed login for {email}",
                     request=request)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    throttle.reset(*keys)
    token = _issue_session(db, user)
    user.last_login_at = datetime.now(timezone.utc)
    audit.record(db, user=user, action="login", entity_type="user", entity_id=user.id,
                 summary="Signed in", request=request)
    db.commit()

    response.set_cookie(
        _settings.session_cookie_name,
        token,
        max_age=_settings.session_ttl_hours * 3600,
        httponly=True,
        secure=_settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return user


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, user: User = Depends(current_user),
           db: Session = Depends(get_db)):
    token_id = getattr(request.state, "auth_token_id", None)
    if token_id:
        db.execute(delete(AuthToken).where(AuthToken.id == token_id, AuthToken.kind == "session"))
        db.commit()
    response.delete_cookie(_settings.session_cookie_name, path="/")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/change-password", status_code=204)
def change_password(body: PasswordChange, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    # Revoke every other session; API tokens are left alone.
    current = getattr(request.state, "auth_token_id", None)
    db.execute(
        delete(AuthToken).where(
            AuthToken.user_id == user.id, AuthToken.kind == "session", AuthToken.id != current
        )
    )
    audit.record(db, user=user, action="update", entity_type="user", entity_id=user.id,
                 summary="Changed password", request=request)
    db.commit()


@router.get("/tokens", response_model=list[TokenOut])
def list_tokens(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return db.scalars(
        select(AuthToken)
        .where(AuthToken.user_id == user.id, AuthToken.kind == "api")
        .order_by(AuthToken.created_at.desc())
    ).all()


@router.post("/tokens", response_model=TokenCreated, status_code=201)
def create_token(body: TokenCreate, request: Request, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    token = "ohub_" + new_token()
    row = AuthToken(
        user_id=user.id,
        token_hash=hash_token(token),
        kind="api",
        name=body.name,
        expires_at=(
            datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)
            if body.expires_in_days
            else None
        ),
    )
    db.add(row)
    db.flush()
    audit.record(db, user=user, action="create", entity_type="api_token", entity_id=row.id,
                 summary=f"Created API token '{body.name}'", request=request)
    db.commit()
    return TokenCreated.model_validate({**TokenOut.model_validate(row).model_dump(), "token": token})


@router.delete("/tokens/{token_id}", status_code=204)
def revoke_token(token_id: int, request: Request, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    row = db.get(AuthToken, token_id)
    if row is None or row.user_id != user.id or row.kind != "api":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    db.delete(row)
    audit.record(db, user=user, action="delete", entity_type="api_token", entity_id=token_id,
                 summary=f"Revoked API token '{row.name}'", request=request)
    db.commit()
