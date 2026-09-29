"""Crash-durable file primitives, per platform.

* Linux: fsync(file), rename, fsync(directory).
* macOS: fsync() does not flush the drive's write cache; use F_FULLFSYNC
  (what SQLite's ``fullfsync`` does) for files and directories.
* Windows: directories cannot be fsynced; renames use MoveFileExW with
  MOVEFILE_WRITE_THROUGH. Antivirus, the search indexer and sync clients
  routinely hold new files open for a moment, so sharing violations are
  retried with backoff instead of being reported as save failures.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

_WIN_TRANSIENT = {5, 32, 33}  # ACCESS_DENIED, SHARING_VIOLATION, LOCK_VIOLATION
_RETRY_DELAYS = (0.02, 0.05, 0.1, 0.2, 0.4, 0.8, 1.0)


def fsync_fd(fd: int) -> None:
    if sys.platform == "darwin":
        import fcntl

        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass  # not supported by this file system: fall back to fsync
    os.fsync(fd)


def fsync_file(fh) -> None:
    fh.flush()
    fsync_fd(fh.fileno())


def fsync_dir(directory: Path) -> None:
    """Persist renames in ``directory``. (Windows: rename is write-through instead.)"""
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        fsync_fd(fd)
    finally:
        os.close(fd)


def _retrying(fn, *args) -> None:
    for delay in (*_RETRY_DELAYS, None):
        try:
            fn(*args)
            return
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) not in _WIN_TRANSIENT or delay is None:
                raise
            time.sleep(delay)


def _win_move(src: str, dst: str) -> None:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH = 0x1, 0x8
    move = ctypes.windll.kernel32.MoveFileExW
    move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move.restype = wintypes.BOOL
    if not move(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH):
        err = ctypes.get_last_error() or ctypes.GetLastError()
        raise OSError(None, ctypes.FormatError(err), src, err, dst)


def replace(src: Path, dst: Path) -> None:
    """Atomically replace ``dst`` with ``src`` (durable once the dir is fsynced)."""
    if os.name == "nt":  # pragma: no cover - Windows only
        _retrying(_win_move, str(src), str(dst))
    else:
        os.replace(src, dst)


def link_or_copy(src: Path, dst: Path) -> None:
    """Make ``dst`` a copy of ``src`` without ever removing ``src``.

    A hard link is instant and atomic; file systems without hard links
    (FAT, some network shares) get a durable copy instead.
    """
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)
        with open(dst, "rb+") as fh:
            fsync_file(fh)


def unlink(path: Path) -> None:
    _retrying(lambda p: Path(p).unlink(missing_ok=True), path)
