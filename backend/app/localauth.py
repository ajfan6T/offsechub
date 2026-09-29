"""Authentication for the localhost API.

The API listens on 127.0.0.1 only, but that is not a security boundary on its
own: other local users, other processes and web pages in the user's browser
(via DNS rebinding or CSRF) can all reach a localhost port. So every request
must pass, in order:

1. Host allow-list    exact ``127.0.0.1:<port>`` / ``localhost:<port>``  → else 421
2. Authentication     session cookie (from a one-time launch token) or the
                      per-process bearer token (CLI)                      → else 401
3. CSRF               cookie-authenticated unsafe methods need the
                      ``X-Requested-With`` header, and a present ``Origin``
                      must be our own origin                              → else 403
"""

from __future__ import annotations

import hmac
import secrets
from urllib.parse import parse_qs

from starlette.datastructures import Headers
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

COOKIE_NAME = "ohub_session"
CSRF_HEADER = "x-requested-with"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
LAUNCH_PATH = "/_launch"

UNAUTHENTICATED_PAGE = """<!doctype html><meta charset="utf-8"><title>OffsecHub</title>
<body style="font:15px system-ui;background:#0a0f1a;color:#e6ebf5;display:grid;place-items:center;height:100vh;margin:0">
<div style="max-width:440px;text-align:center"><h2>OffsecHub is locked to its own window</h2>
<p style="color:#8a97b0">This local server only accepts the OffsecHub app. If you started it with
<code>--browser</code>, use the one-time link printed in the terminal, or run
<code>offsechub open</code> to get a fresh link.</p></div></body>"""


def _eq(a: str | None, b: str) -> bool:
    return a is not None and hmac.compare_digest(a.encode(), b.encode())


class LocalAuth:
    """Per-process secrets. Nothing here is persisted except via runtime.json."""

    def __init__(self) -> None:
        self.session_secret = secrets.token_urlsafe(32)
        self.api_token = "ohub_" + secrets.token_urlsafe(32)
        self._launch_token: str | None = None
        self.allowed_hosts: set[str] = set()
        self.allowed_origins: set[str] = set()
        self.cookie_secure = False

    def bind(self, port: int) -> None:
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.allowed_hosts = hosts
        self.allowed_origins = {f"http://{h}" for h in hosts}

    def new_launch_token(self) -> str:
        """Issue a fresh single-use launch token (invalidates any unused one)."""
        self._launch_token = secrets.token_urlsafe(32)
        return self._launch_token

    def consume_launch_token(self, token: str | None) -> bool:
        current = self._launch_token
        if current is None or not _eq(token, current):
            return False
        self._launch_token = None  # single use
        return True

    def launch_url(self, port: int) -> str:
        return f"http://127.0.0.1:{port}{LAUNCH_PATH}?token={self.new_launch_token()}"

    def classify(self, headers: Headers) -> str | None:
        """Return 'cookie', 'bearer' or None."""
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer ") and _eq(auth[7:].strip(), self.api_token):
            return "bearer"
        cookie = headers.get("cookie", "")
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME and _eq(value, self.session_secret):
                return "cookie"
        return None


class LocalAuthMiddleware:
    """Pure ASGI middleware so it also covers streaming responses and static files."""

    def __init__(self, app: ASGIApp, auth: LocalAuth, on_activity=None, activity_paths=()):
        self.app = app
        self.auth = auth
        self.on_activity = on_activity
        self.activity_paths = set(activity_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        path: str = scope["path"]
        method: str = scope["method"]

        # 1. DNS rebinding: the Host header must be exactly ours.
        if headers.get("host") not in self.auth.allowed_hosts:
            await PlainTextResponse("Misdirected request", status_code=421)(scope, receive, send)
            return

        # One-time launch: exchange the token for a session cookie.
        if path == LAUNCH_PATH:
            token = parse_qs(scope.get("query_string", b"").decode()).get("token", [None])[0]
            if method == "GET" and self.auth.consume_launch_token(token):
                resp: Response = RedirectResponse("/", status_code=303)
                resp.set_cookie(COOKIE_NAME, self.auth.session_secret, httponly=True,
                                samesite="strict", secure=self.auth.cookie_secure, path="/")
                resp.headers["Referrer-Policy"] = "no-referrer"
                resp.headers["Cache-Control"] = "no-store"
            else:
                resp = HTMLResponse(UNAUTHENTICATED_PAGE, status_code=403)
            await resp(scope, receive, send)
            return

        # 2. Authentication.
        kind = self.auth.classify(headers)
        if kind is None:
            if path.startswith("/api/"):
                resp = PlainTextResponse("Not authenticated", status_code=401)
            else:
                resp = HTMLResponse(UNAUTHENTICATED_PAGE, status_code=401)
            await resp(scope, receive, send)
            return

        # 3. CSRF for browser-style (cookie) requests.
        if kind == "cookie" and method not in SAFE_METHODS:
            origin = headers.get("origin")
            if not headers.get(CSRF_HEADER) or (origin and origin not in self.auth.allowed_origins):
                await PlainTextResponse("Cross-site request refused", status_code=403)(scope, receive, send)
                return

        scope.setdefault("state", {})["auth_kind"] = kind
        # Auto-lock follows the *user*, not HTTP traffic: background GETs,
        # refetches and CLI/bearer automation never keep the vault open.
        # Changes made in the UI (and its explicit input heartbeat) do.
        if self.on_activity and kind == "cookie" and path.startswith("/api/") and (
            method not in SAFE_METHODS or path in self.activity_paths
        ):
            self.on_activity()
        await self.app(scope, receive, send)
