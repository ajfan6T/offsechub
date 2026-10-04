"""Client for the running app's local API, authenticated with the bearer token.

Used by the CLI (``offsechub open``, ``offsechub import``) and by the desktop
shell's ``save_download`` bridge function. The app publishes its port and token
in ``runtime.json`` (0600, per-user directory) while it runs.
"""

from __future__ import annotations

import http.client
import json
import os
import tempfile
from pathlib import Path
from typing import IO, Any

from .vault import durable
from .vault.appconfig import read_runtime


class NotRunning(Exception):
    """No OffsecHub instance is reachable."""


class LocalApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _detail(status: int, body: bytes) -> str:
    try:
        detail = json.loads(body).get("detail")
    except (ValueError, AttributeError):
        detail = body.decode(errors="replace").strip()
    if isinstance(detail, list):  # pydantic validation errors
        detail = "; ".join(str(d.get("msg", d)) for d in detail)
    return str(detail or f"HTTP {status}")


class LocalClient:
    def __init__(self, port: int, token: str, timeout: float = 120):
        self.port = int(port)
        self.token = token
        self.timeout = timeout

    @classmethod
    def from_runtime(cls) -> LocalClient:
        info = read_runtime()
        if not info:
            raise NotRunning("OffsecHub is not running. Start it first.")
        try:
            client = cls(int(info["port"]), str(info["token"]))
        except (KeyError, TypeError, ValueError):
            raise NotRunning("OffsecHub's runtime file is damaged. Restart the app.") from None
        if not client.alive():
            raise NotRunning("OffsecHub is not running (stale runtime file). Start it first.")
        return client

    def alive(self) -> bool:
        try:
            status, _headers, _body = self.request("GET", "/api/health", timeout=2)
        except OSError:
            return False
        return status == 200

    def _connect(self, timeout: float | None = None) -> http.client.HTTPConnection:
        # http.client sends "Host: 127.0.0.1:<port>", exactly what the API allow-lists.
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout or self.timeout)

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", **(extra or {})}

    def request(self, method: str, path: str, body: bytes | IO[bytes] | None = None,
                headers: dict[str, str] | None = None, timeout: float | None = None):
        conn = self._connect(timeout)
        try:
            conn.request(method, path, body=body, headers=self._headers(headers))
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def json(self, method: str, path: str, payload: Any = None, *, body: bytes | IO[bytes] | None = None,
             content_type: str | None = None, length: int | None = None) -> Any:
        headers: dict[str, str] = {}
        if payload is not None:
            body = json.dumps(payload).encode()
            content_type = "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        if length is not None:
            headers["Content-Length"] = str(length)
        status, _headers, data = self.request(method, path, body, headers)
        if status >= 400:
            raise LocalApiError(status, _detail(status, data))
        return json.loads(data) if data else None

    def download(self, path: str, dest: Path) -> int:
        """Stream ``GET path`` into ``dest`` atomically; returns the byte count.

        The response goes to a private temp file next to ``dest`` and is renamed
        over it only once complete, so a failed download never leaves a partial
        file under the chosen name.
        """
        dest = Path(dest)
        conn = self._connect()
        try:
            conn.request("GET", path, headers=self._headers())
            resp = conn.getresponse()
            if resp.status != 200:
                raise LocalApiError(resp.status, _detail(resp.status, resp.read()))
            fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".offsechub-", suffix=".part")
            size = 0
            try:
                with os.fdopen(fd, "wb") as out:
                    while chunk := resp.read(1 << 16):
                        out.write(chunk)
                        size += len(chunk)
                    out.flush()
                    durable.fsync_file(out)
                durable.replace(Path(tmp), dest)
                durable.fsync_dir(dest.parent)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
            return size
        finally:
            conn.close()
