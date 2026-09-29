"""Application factory for the local API.

Middleware order (outermost first): security headers → local auth → routes.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from . import __version__
from .api import (
    activity,
    clients,
    engagements,
    evidence,
    findings,
    recon,
    reports,
    scope,
    targets,
    testing,
    vault,
)
from .bootstrap import make_unlock_hook
from .config import get_settings
from .localauth import LocalAuth, LocalAuthMiddleware
from .vault.manager import VaultManager

log = logging.getLogger("offsechub")

SPA_CSP = (
    "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"
# Only unsafe methods and this explicit heartbeat (sent by the UI on real keyboard or
# mouse input) reset the idle timer. Polling and background refetches do not.
ACTIVITY_PATHS = ("/api/app/activity",)
GROUP_COMMIT_TIMEOUT_S = 10.0


def create_app(
    manager: VaultManager | None = None,
    auth: LocalAuth | None = None,
    *,
    desktop: bool = False,
    frontend_dist: Path | None = None,
) -> FastAPI:
    manager = manager or VaultManager()
    auth = auth or LocalAuth()
    manager.on_unlock(make_unlock_hook(manager))
    dist = frontend_dist or get_settings().frontend_dist

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        manager.shutdown()  # flush + lock on exit

    app = FastAPI(
        title="OffsecHub",
        version=__version__,
        description="Local API of the OffsecHub desktop app.",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.vaults = manager
    app.state.auth = auth
    app.state.desktop = desktop
    app.state.port = None

    @app.middleware("http")
    async def group_commit(request: Request, call_next):
        """A 2xx for a change means the change is on disk.

        Commits only reach memory; the saver persists them (coalescing
        concurrent commits into one save). Mutating requests wait for that save.
        If it cannot complete (disk full, drive removed) the response still goes
        out, flagged ``X-OffsecHub-Saved: 0``, and the UI shows the save error.
        """
        vault = manager.current
        before = vault.commit_seq if vault is not None else None
        response = await call_next(request)
        if vault is not None and request.method not in ("GET", "HEAD", "OPTIONS") \
                and vault.commit_seq != before and not vault.closed:
            saved = await run_in_threadpool(vault.wait_saved, vault.commit_seq, GROUP_COMMIT_TIMEOUT_S)
            response.headers["X-OffsecHub-Saved"] = "1" if saved else "0"
        return response

    app.add_middleware(LocalAuthMiddleware, auth=auth, on_activity=manager.touch,
                       activity_paths=ACTIVITY_PATHS)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        h.setdefault("Cache-Control", "no-store")
        if request.url.path.startswith("/api/"):
            h.setdefault("Content-Security-Policy", API_CSP)
        else:
            h.setdefault("Content-Security-Policy", SPA_CSP)
        return response

    for module in (vault, clients, engagements, scope, targets, recon, testing, evidence,
                   findings, reports, activity):
        app.include_router(module.router)

    @app.get("/api/health", tags=["meta"])
    def health():
        return {"status": "ok", "version": __version__}

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                   include_in_schema=False)
    def api_not_found(path: str):
        raise HTTPException(404, "Not found")

    _mount_spa(app, dist)
    return app


def _mount_spa(app: FastAPI, dist: Path) -> None:
    """Serve the built React app, falling back to index.html for client-side routes."""
    index = dist / "index.html"

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if not index.exists():
            return JSONResponse(
                {"detail": "Frontend not built. Run `npm run build` in frontend/."}, status_code=404
            )
        candidate = (dist / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
            return FileResponse(candidate)
        return FileResponse(index)
