"""Exclusive, crash-safe advisory lock on a vault directory.

The OS releases the lock when the process dies, so a crash never leaves a
stale lock behind. (Advisory locks are unreliable on some network file
systems; vaults should live on a local disk.)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


class VaultInUse(Exception):
    pass


class DirLock:
    def __init__(self, directory: Path):
        self.path = directory / ".lock"
        self._fh = None

    def acquire(self) -> None:
        fh = open(self.path, "a+b")
        try:
            if sys.platform == "win32":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            raise VaultInUse("this vault is already open in another OffsecHub window") from None
        # Diagnostic only; the lock itself is what matters. (No hostname: the
        # vault may be synced or shared, and that would be needless metadata.)
        fh.seek(0)
        fh.truncate()
        fh.write(f"{os.getpid()}\n".encode())
        fh.flush()
        self._fh = fh

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt

                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None

    @property
    def held(self) -> bool:
        return self._fh is not None
