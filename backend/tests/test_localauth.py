"""The localhost API must reject everything but its own window (and the CLI)."""

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient

from app.localauth import COOKIE_NAME, LocalAuth, LocalAuthMiddleware

HOST = "127.0.0.1:43210"


async def ok(request):
    return PlainTextResponse(f"ok {request.state.auth_kind}")


async def ws(websocket):  # pragma: no cover - must never be reached
    await websocket.accept()


@pytest.fixture
def auth():
    a = LocalAuth()
    a.bind(43210)
    return a


@pytest.fixture
def client(auth):
    app = Starlette(routes=[Route("/api/x", ok, methods=["GET", "POST"]), Route("/", ok),
                            WebSocketRoute("/ws", ws)])
    app.add_middleware(LocalAuthMiddleware, auth=auth)
    return TestClient(app, base_url=f"http://{HOST}")


def launch(client, auth):
    token = auth.new_launch_token()
    r = client.get(f"/_launch?token={token}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    return r


def test_dns_rebinding_host_is_refused(client, auth):
    launch(client, auth)
    r = client.get("/api/x", headers={"host": "evil.example:43210"})
    assert r.status_code == 421
    assert client.get("/api/x", headers={"host": "127.0.0.1:9999"}).status_code == 421


def test_unauthenticated_requests_are_refused(client):
    assert client.get("/api/x").status_code == 401
    assert client.get("/").status_code == 401


def test_launch_token_is_single_use_and_sets_strict_cookie(client, auth):
    token = auth.new_launch_token()
    r = client.get(f"/_launch?token={token}", follow_redirects=False)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/api/x").text == "ok cookie"
    fresh = TestClient(client.app, base_url=f"http://{HOST}")
    assert fresh.get(f"/_launch?token={token}", follow_redirects=False).status_code == 403


def test_new_launch_token_invalidates_the_previous_one(client, auth):
    first = auth.new_launch_token()
    auth.new_launch_token()
    assert client.get(f"/_launch?token={first}", follow_redirects=False).status_code == 403


def test_wrong_or_missing_token(client, auth):
    auth.new_launch_token()
    assert client.get("/_launch?token=nope", follow_redirects=False).status_code == 403
    assert client.get("/_launch", follow_redirects=False).status_code == 403


def test_forged_cookie_is_refused(client):
    client.cookies.set(COOKIE_NAME, "guess")
    assert client.get("/api/x").status_code == 401


def test_cookie_post_requires_csrf_header_and_same_origin(client, auth):
    launch(client, auth)
    assert client.post("/api/x").status_code == 403
    assert client.post("/api/x", headers={"X-Requested-With": "OffsecHub"}).status_code == 200
    evil = {"X-Requested-With": "OffsecHub", "Origin": "http://evil.example"}
    assert client.post("/api/x", headers=evil).status_code == 403
    same = {"X-Requested-With": "OffsecHub", "Origin": f"http://{HOST}"}
    assert client.post("/api/x", headers=same).status_code == 200


def test_bearer_token_for_cli(client, auth):
    r = client.post("/api/x", headers={"Authorization": f"Bearer {auth.api_token}"})
    assert r.status_code == 200 and r.text == "ok bearer"
    assert client.get("/api/x", headers={"Authorization": "Bearer ohub_wrong"}).status_code == 401


def test_websockets_are_refused(client, auth):
    launch(client, auth)
    with pytest.raises(Exception):
        with client.websocket_connect("/ws"):
            pass


@pytest.mark.parametrize("host", [None, "[::1]:43210", "127.0.0.1.:43210", "0.0.0.0:43210",
                                  "localhost.:43210", "127.0.0.1", "LOCALHOST:43210x"])
def test_host_check_fails_closed(auth, host):
    """Missing Host and alternate loopback spellings are all refused."""
    import asyncio

    sent = {}

    async def downstream(scope, receive, send):  # pragma: no cover - must not be reached
        raise AssertionError("request reached the app")

    mw = LocalAuthMiddleware(downstream, auth=auth)
    headers = [] if host is None else [(b"host", host.encode())]
    scope = {"type": "http", "path": "/api/x", "method": "GET", "headers": headers, "query_string": b""}

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        if message["type"] == "http.response.start":
            sent["status"] = message["status"]

    asyncio.run(mw(scope, receive, send))
    assert sent["status"] == 421


def test_null_origin_is_refused(client, auth):
    launch(client, auth)
    r = client.post("/api/x", headers={"X-Requested-With": "OffsecHub", "Origin": "null"})
    assert r.status_code == 403


def test_auth_precedes_everything_else(client):
    """An unauthenticated caller learns nothing (no 423/404 leaks), only 401."""
    assert client.get("/api/anything/at/all").status_code == 401


def test_only_ui_changes_and_the_heartbeat_count_as_activity(auth):
    hits = []
    app = Starlette(routes=[Route("/api/x", ok, methods=["GET", "POST"]),
                            Route("/api/app/activity", ok, methods=["POST"])])
    app.add_middleware(LocalAuthMiddleware, auth=auth, on_activity=lambda: hits.append(1),
                       activity_paths={"/api/app/activity"})
    ui = TestClient(app, base_url=f"http://{HOST}", headers={"X-Requested-With": "OffsecHub"})
    launch(ui, auth)
    ui.get("/api/x")
    assert hits == []  # background reads never keep the vault open
    ui.post("/api/x")
    ui.post("/api/app/activity")
    assert len(hits) == 2
    cli = TestClient(app, base_url=f"http://{HOST}", headers={"Authorization": f"Bearer {auth.api_token}"})
    cli.post("/api/x")
    assert len(hits) == 2  # automation (e.g. a cron job pushing scans) does not either
