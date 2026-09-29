"""Best-effort process hardening for the process that holds decrypted data.

* No core dumps (a crash must not write the plaintext heap to disk).
* Linux: PR_SET_DUMPABLE=0 also stops other processes of the *same user* from
  ptrace-attaching or reading /proc/<pid>/mem (unless they are root).
* Windows: no Windows Error Reporting dump dialog.

None of this defeats malware already running as the user with debugging
rights; see docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import logging
import sys

log = logging.getLogger("offsechub")

PR_SET_DUMPABLE = 4


def harden_process() -> list[str]:
    """Apply what the platform supports; returns the measures that took effect."""
    applied: list[str] = []
    if sys.platform != "win32":
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            applied.append("core dumps disabled")
        except (ImportError, ValueError, OSError):
            log.debug("could not disable core dumps", exc_info=True)
    if sys.platform.startswith("linux"):
        try:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
                applied.append("ptrace and /proc/<pid>/mem blocked for same-user processes")
        except (OSError, AttributeError):
            log.debug("prctl(PR_SET_DUMPABLE) failed", exc_info=True)
    if sys.platform == "win32":  # pragma: no cover - Windows only
        try:
            import ctypes

            SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX = 0x0001, 0x0002
            ctypes.windll.kernel32.SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)
            applied.append("crash dump dialog disabled")
        except (OSError, AttributeError):
            pass
    return applied
