import os
import tempfile
from pathlib import Path

# Configure an isolated database and evidence store before the app is imported.
_TMP = Path(tempfile.mkdtemp(prefix="offsechub-tests-"))
# Set OFFSECHUB_TEST_DATABASE_URL (e.g. postgresql+psycopg://...) to run against PostgreSQL.
os.environ["OFFSECHUB_DATABASE_URL"] = os.environ.get(
    "OFFSECHUB_TEST_DATABASE_URL", f"sqlite:///{_TMP / 'test.db'}"
)
os.environ["OFFSECHUB_STORAGE_DIR"] = str(_TMP / "evidence")
os.environ["OFFSECHUB_ADMIN_EMAIL"] = "admin@test.local"
os.environ["OFFSECHUB_ADMIN_PASSWORD"] = "admin-password-123"
os.environ["OFFSECHUB_FRONTEND_DIST"] = str(_TMP / "no-frontend")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db as db_module  # noqa: E402
from app import security  # noqa: E402
from app.api import auth as auth_api  # noqa: E402
from app.main import app  # noqa: E402

# Cheap hashing keeps the suite fast; parameters are stored per hash so this is safe.
security._SCRYPT_N = 2**10

ADMIN = ("admin@test.local", "admin-password-123")
PASSWORD = "correct-horse-battery"
SAMPLES = Path(__file__).resolve().parents[2] / "samples"


class Api(TestClient):
    """A TestClient that always sends the CSRF header and raises on unexpected status."""

    def __init__(self):
        super().__init__(app, headers={"X-Requested-With": "OffsecHub"})

    def login(self, email: str, password: str) -> "Api":
        r = self.post("/api/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return self

    def ok(self, method: str, url: str, status: int | None = None, **kw):
        r = self.request(method, url, **kw)
        expected = status or (201 if method.upper() == "POST" else 204 if method.upper() == "DELETE" else 200)
        assert r.status_code == expected, f"{method} {url} -> {r.status_code}: {r.text}"
        return r.json() if r.content and r.headers.get("content-type", "").startswith("application/json") else r


@pytest.fixture(autouse=True)
def fresh_db():
    db_module.Base.metadata.drop_all(db_module.engine)
    auth_api.throttle._failures.clear()
    yield


@pytest.fixture
def admin() -> Api:
    with Api() as c:  # entering runs the lifespan -> bootstrap (tables + admin)
        yield c.login(*ADMIN)


@pytest.fixture
def make_user(admin):
    def _make(email: str, role: str = "tester", name: str | None = None) -> Api:
        admin.ok("POST", "/api/users", json={"email": email, "full_name": name or email.split("@")[0],
                                             "password": PASSWORD, "role": role})
        return Api().login(email, PASSWORD)

    return _make


@pytest.fixture
def engagement(admin):
    """A client + engagement with a realistic scope, owned by the admin."""
    client = admin.ok("POST", "/api/clients", json={"name": "ACME"})
    eng = admin.ok("POST", "/api/engagements", json={
        "client_id": client["id"], "name": "External test", "code": "ACME-EXT",
        "type": "external_network", "start_date": "2026-09-01", "end_date": "2026-09-30",
    })
    base = f"/api/engagements/{eng['id']}"
    for kind, value, rule in [
        ("cidr", "203.0.113.0/28", "include"),
        ("wildcard", "*.acme-corp.example", "include"),
        ("domain", "vpn.acme-corp.example", "exclude"),
        ("ip", "203.0.113.11", "exclude"),
    ]:
        admin.ok("POST", f"{base}/scope", json={"kind": kind, "value": value, "rule": rule})
    return eng


def user_id(admin: Api, email: str) -> int:
    return next(u["id"] for u in admin.ok("GET", "/api/users") if u["email"] == email)
