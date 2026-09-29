"""Plaintext application config: recent vault paths and the runtime file.

Nothing sensitive lives here. Only vault *paths* are remembered (and the user
can turn that off or clear it), never names, keys or content.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

MAX_RECENT = 10


def config_dir() -> Path:
    override = os.environ.get("OFFSECHUB_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        # Local, not Roaming: roaming profiles would copy recent paths and the
        # rollback marks to other machines in the domain.
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "OffsecHub"


def default_vault_dir() -> Path:
    return Path.home() / "OffsecHub"


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class AppConfig:
    def __init__(self, directory: Path | None = None):
        self.dir = directory or config_dir()
        self.file = self.dir / "config.json"

    def _load(self) -> dict:
        try:
            data = json.loads(self.file.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        _atomic_write(self.file, json.dumps(data, indent=2).encode())

    @property
    def remember_recent(self) -> bool:
        return bool(self._load().get("remember_recent", True))

    def set_remember_recent(self, value: bool) -> None:
        data = self._load()
        data["remember_recent"] = bool(value)
        if not value:
            data["recent"] = []
        self._save(data)

    def recent(self) -> list[str]:
        items = self._load().get("recent", [])
        return [p for p in items if isinstance(p, str)][:MAX_RECENT]

    def add_recent(self, path: Path) -> None:
        data = self._load()
        if not data.get("remember_recent", True):
            return
        p = str(Path(path).resolve())
        items = [x for x in data.get("recent", []) if x != p]
        data["recent"] = [p, *items][:MAX_RECENT]
        self._save(data)

    # Rollback detection: the newest snapshot generation seen per vault, MACed
    # with a key derived from that vault's master key (so it cannot be forged,
    # only deleted, which just disables the warning).
    def high_water(self, vault_id: str) -> dict | None:
        record = self._load().get("high_water", {}).get(vault_id)
        return record if isinstance(record, dict) else None

    def set_high_water(self, vault_id: str, generation: int, mac: str) -> None:
        data = self._load()
        marks = data.setdefault("high_water", {})
        current = marks.get(vault_id)
        if isinstance(current, dict) and int(current.get("generation", -1)) > generation:
            return
        marks[vault_id] = {"generation": generation, "mac": mac}
        self._save(data)

    def forget_recent(self, path: str | None = None) -> None:
        data = self._load()
        data["recent"] = [] if path is None else [x for x in data.get("recent", []) if x != path]
        self._save(data)


def runtime_file() -> Path:
    """Where the running app publishes its port + bearer token for the CLI.

    Always a per-user directory: $XDG_RUNTIME_DIR (0700, tmpfs) on Linux, else
    the user's config dir. Never a shared temp directory.
    """
    base = os.environ.get("XDG_RUNTIME_DIR")
    directory = Path(base) / "offsechub" if base and sys.platform.startswith("linux") else config_dir()
    return directory / "runtime.json"


def _check_private_dir(directory: Path) -> None:
    """The bearer token equals a full session: refuse a directory others can tamper with."""
    if os.name == "nt":
        return  # per-user %APPDATA%; ACLs are inherited from the profile
    st = directory.lstat()
    import stat as _stat

    if _stat.S_ISLNK(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise PermissionError(f"refusing to write the runtime token into insecure directory {directory}")


def write_runtime(port: int, token: str) -> Path:
    path = runtime_file()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _check_private_dir(path.parent)
    # mkstemp (O_EXCL, 0600) + rename: never follows a planted symlink.
    _atomic_write(path, json.dumps({"pid": os.getpid(), "port": port, "token": token}).encode())
    return path


def read_runtime() -> dict | None:
    try:
        return json.loads(runtime_file().read_text())
    except (OSError, ValueError):
        return None


def clear_runtime(token: str) -> None:
    data = read_runtime()
    if data and data.get("token") == token:
        runtime_file().unlink(missing_ok=True)
