"""Shared fixtures: an isolated app + unlocked vault per test."""

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.localauth import LocalAuth
from app.vault import header as vault_header
from app.vault.appconfig import AppConfig
from app.vault.crypto import Argon2Params
from app.vault.manager import VaultManager

PASSWORD = "correct horse battery staple"
SAMPLES = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Minimum allowed Argon2 cost keeps the suite fast (real vaults use 64 MiB/t=3)."""
    monkeypatch.setattr(vault_header, "DEFAULT_ARGON2", Argon2Params(m_kib=19456, t=2, p=1))


class Api(TestClient):
    """TestClient that sends the CSRF header and asserts expected status codes."""

    def __init__(self, app):
        super().__init__(app, headers={"X-Requested-With": "OffsecHub"})

    def ok(self, method: str, url: str, status: int | None = None, **kw):
        r = self.request(method, url, **kw)
        m = method.upper()
        expected = status or (201 if m == "POST" else 204 if m == "DELETE" else 200)
        assert r.status_code == expected, f"{method} {url} -> {r.status_code}: {r.text}"
        ctype = r.headers.get("content-type", "")
        return r.json() if r.content and ctype.startswith("application/json") else r


@pytest.fixture
def app_ctx(tmp_path):
    from app.main import create_app  # imported lazily so unit suites don't need the routers

    manager = VaultManager(AppConfig(tmp_path / "config"))
    auth = LocalAuth()
    auth.allowed_hosts = {"testserver"}
    auth.allowed_origins = {"http://testserver"}
    app = create_app(manager, auth, frontend_dist=tmp_path / "no-frontend")
    yield app, manager, auth
    manager.shutdown()


@pytest.fixture
def anon(app_ctx):
    """A client that has exchanged the launch token but has no vault open."""
    app, _manager, auth = app_ctx
    client = Api(app)
    r = client.get(f"/_launch?token={auth.new_launch_token()}", follow_redirects=False)
    assert r.status_code == 303
    return client


@pytest.fixture
def api(anon, tmp_path):
    """Authenticated client with a freshly created, unlocked vault."""
    body = anon.ok("POST", "/api/vault/create", json={"path": str(tmp_path / "test"), "password": PASSWORD})
    anon.recovery_key = body["recovery_key"]
    anon.vault_path = body["status"]["path"]
    return anon


@pytest.fixture
def engagement(api):
    """A client + engagement with a realistic scope."""
    client = api.ok("POST", "/api/clients", json={"name": "ACME"})
    eng = api.ok("POST", "/api/engagements", json={
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
        api.ok("POST", f"{base}/scope", json={"kind": kind, "value": value, "rule": rule})
    return eng


@pytest.fixture
def vault(api, app_ctx):
    """The unlocked vault behind ``api``, for inspecting rows and blob files directly."""
    return app_ctx[1].require()


def wait_until(predicate, timeout: float = 5.0) -> bool:
    """Poll for work the vault does in the background (saves, blob sweeps)."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.02)
    return True
