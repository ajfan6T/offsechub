import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import __version__
from .api import (
    activity,
    auth,
    clients,
    engagements,
    evidence,
    findings,
    recon,
    reports,
    scope,
    targets,
    testing,
    users,
)
from .bootstrap import bootstrap
from .config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# Swagger UI loads from a CDN and boots with an inline script; allow that on the docs page only.
DOCS_CSP = (
    "default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'unsafe-inline' https://cdn.jsdelivr.net; img-src data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; frame-ancestors 'none'"
)
SPA_CSP = (
    "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="OffsecHub",
        version=__version__,
        description="Offensive security engagement management API.",
        lifespan=lifespan,
        docs_url="/api/docs" if settings.api_docs else None,
        openapi_url="/api/openapi.json" if settings.api_docs else None,
        redoc_url=None,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.url.path == "/api/docs":
            h.setdefault("Content-Security-Policy", DOCS_CSP)
        elif request.url.path.startswith("/api/"):
            h.setdefault("Cache-Control", "no-store")
            h.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        else:
            h.setdefault("Content-Security-Policy", SPA_CSP)
        if settings.cookie_secure:
            h.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response

    for module in (auth, users, clients, engagements, scope, targets, recon, testing, evidence,
                   findings, reports, activity):
        app.include_router(module.router)

    @app.get("/api/health", tags=["meta"])
    def health():
        return {"status": "ok", "version": __version__}

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                   include_in_schema=False)
    def api_not_found(path: str):
        raise HTTPException(404, "Not found")

    _mount_spa(app, settings.frontend_dist)
    return app


def _mount_spa(app: FastAPI, dist: Path) -> None:
    """Serve the built React app, falling back to index.html for client-side routes."""
    index = dist / "index.html"

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if not index.exists():
            return JSONResponse(
                {"detail": "Frontend not built. Run `npm run build` in frontend/ or use the Vite dev server."},
                status_code=404,
            )
        candidate = (dist / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
            return FileResponse(candidate)
        return FileResponse(index)


app = create_app()
