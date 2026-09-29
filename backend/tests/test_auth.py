from fastapi.testclient import TestClient

from app.main import app

from .conftest import ADMIN, PASSWORD, Api, user_id


def test_login_me_logout(admin):
    me = admin.ok("GET", "/api/auth/me")
    assert me["email"] == ADMIN[0] and me["role"] == "admin"
    admin.ok("POST", "/api/auth/logout", status=204)
    assert admin.get("/api/auth/me").status_code == 401


def test_session_cookie_flags(admin):
    r = Api().post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_bad_credentials_are_indistinguishable(admin):
    c = Api()
    wrong = c.post("/api/auth/login", json={"email": ADMIN[0], "password": "nope-nope-nope"})
    unknown = c.post("/api/auth/login", json={"email": "ghost@test.local", "password": "nope-nope-nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_login_requires_csrf_header(admin):
    with TestClient(app) as raw:
        r = raw.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert r.status_code == 403


def test_cookie_auth_state_change_requires_csrf_header(admin):
    token_cookie = admin.cookies.get("offsechub_session")
    raw = TestClient(app, cookies={"offsechub_session": token_cookie})
    assert raw.get("/api/auth/me").status_code == 200  # safe method is fine
    r = raw.post("/api/clients", json={"name": "Evil Corp"})
    assert r.status_code == 403


def test_login_throttle(admin):
    c = Api()
    for _ in range(10):
        c.post("/api/auth/login", json={"email": ADMIN[0], "password": "wrong-password"})
    r = c.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert r.status_code == 429


def test_api_token_lifecycle(admin):
    created = admin.ok("POST", "/api/auth/tokens", json={"name": "ci", "expires_in_days": 30})
    assert created["token"].startswith("ohub_")
    bearer = TestClient(app, headers={"Authorization": f"Bearer {created['token']}"})
    # Bearer auth is not cookie-based, so no CSRF header is needed.
    assert bearer.post("/api/clients", json={"name": "Via Token"}).status_code == 201
    listed = admin.ok("GET", "/api/auth/tokens")
    assert [t["name"] for t in listed] == ["ci"] and "token" not in listed[0]
    admin.ok("DELETE", f"/api/auth/tokens/{created['id']}")
    assert bearer.get("/api/auth/me").status_code == 401


def test_change_password_revokes_other_sessions(admin, make_user):
    user = make_user("t@test.local")
    other = Api().login("t@test.local", PASSWORD)
    user.ok("POST", "/api/auth/change-password", status=204,
            json={"current_password": PASSWORD, "new_password": "a-brand-new-password"})
    assert user.get("/api/auth/me").status_code == 200
    assert other.get("/api/auth/me").status_code == 401
    Api().login("t@test.local", "a-brand-new-password")


def test_short_password_rejected(admin):
    r = admin.post("/api/users", json={"email": "x@test.local", "full_name": "X", "password": "short"})
    assert r.status_code == 422


def test_disabling_user_kills_sessions(admin, make_user):
    user = make_user("gone@test.local")
    admin.ok("PATCH", f"/api/users/{user_id(admin, 'gone@test.local')}", json={"is_active": False})
    assert user.get("/api/auth/me").status_code == 401
    r = Api().post("/api/auth/login", json={"email": "gone@test.local", "password": PASSWORD})
    assert r.status_code == 401


def test_admin_cannot_demote_self(admin):
    r = admin.patch(f"/api/users/{user_id(admin, ADMIN[0])}", json={"role": "tester"})
    assert r.status_code == 400


def test_login_is_audited(admin):
    events = admin.ok("GET", "/api/audit")
    assert any(e["action"] == "login" for e in events)
