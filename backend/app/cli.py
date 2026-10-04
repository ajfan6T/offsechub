"""Command line entry point.

    offsechub                                   open the desktop app
    offsechub --browser                         run without a window, in your browser
    offsechub open                              one-time browser link to the running app
    offsechub import ACME-EXT-26 scan.xml --tool nmap
                                                send tool output to the running app
    offsechub demo ~/OffsecHub/Demo             create a vault filled with sample data
    offsechub version
"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path
from urllib.parse import urlencode

from . import __version__

IMPORT_TOOLS = ("nmap", "nuclei", "list")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="offsechub",
        description="OffsecHub: a local-first, encrypted workspace for penetration testing engagements.",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--browser", action="store_true",
                      help="no window: serve the app to your browser (weaker isolation, see the docs)")
    mode.add_argument("--dev", action="store_true",
                      help="API on 127.0.0.1:8000 for the Vite dev server on localhost:5173")
    p.add_argument("--no-open", action="store_true", help="with --browser: print the link, don't open it")
    p.add_argument("--debug", action="store_true", help="enable the webview's developer tools")
    p.add_argument("-v", "--verbose", action="store_true", help="log more")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    o = sub.add_parser("open", help="print and open a one-time browser link to the running app")
    o.add_argument("--no-open", action="store_true", help="only print the link")

    i = sub.add_parser("import", help="import Nmap, nuclei or host-list output into the running app")
    i.add_argument("engagement", help="engagement code (e.g. ACME-EXT-26) or numeric id")
    i.add_argument("file", type=Path, help="tool output file")
    i.add_argument("--tool", required=True, choices=IMPORT_TOOLS)
    i.add_argument("--include-out-of-scope", action="store_true",
                   help="import hosts outside the scope too, flagged out of scope (exclusions still apply)")

    d = sub.add_parser("demo", help="create a new vault with a sample engagement")
    d.add_argument("path", type=Path, help="folder for the new vault (.ohvault is appended)")
    d.add_argument("--password-stdin", action="store_true", help="read the password from standard input")

    sub.add_parser("version", help="print the version")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    if args.command == "version":
        print(f"OffsecHub {__version__}")
        return 0
    if args.command == "open":
        return cmd_open(no_open=args.no_open)
    if args.command == "import":
        return cmd_import(args.engagement, args.file, args.tool, args.include_out_of_scope)
    if args.command == "demo":
        return cmd_demo(args.path, password_stdin=args.password_stdin)

    from .desktop import run

    mode = "dev" if args.dev else "browser" if args.browser else "window"
    return run(mode, open_browser=not args.no_open, debug=args.debug)


def _fail(message: str) -> int:
    print(f"offsechub: {message}", file=sys.stderr)
    return 1


def cmd_open(*, no_open: bool = False) -> int:
    from .desktop import open_in_browser
    from .localclient import LocalApiError, LocalClient, NotRunning

    try:
        url = LocalClient.from_runtime().json("POST", "/api/app/launch-link")["url"]
    except (NotRunning, LocalApiError) as exc:
        return _fail(str(exc))
    if no_open:
        print(url)
    else:
        open_in_browser(url)
    return 0


def find_engagement(engagements: list[dict], ref: str) -> dict | None:
    """Match by code (case-insensitive) first, then by numeric id."""
    for e in engagements:
        if e["code"].casefold() == ref.casefold():
            return e
    if ref.isdigit():
        return next((e for e in engagements if e["id"] == int(ref)), None)
    return None


def cmd_import(engagement: str, file: Path, tool: str, include_out_of_scope: bool = False) -> int:
    from .localclient import LocalApiError, LocalClient, NotRunning

    try:
        size = file.stat().st_size
    except OSError as exc:
        return _fail(f"cannot read {file}: {exc.strerror}")
    try:
        client = LocalClient.from_runtime()
        status = client.json("GET", "/api/vault/status")
        if status["state"] != "unlocked":
            return _fail("unlock a vault in OffsecHub first")
        eng = find_engagement(client.json("GET", "/api/engagements"), engagement)
        if eng is None:
            return _fail(f"no engagement {engagement!r} in vault {status['name']}")
        query = urlencode({"tool": tool, "filename": file.name,
                           "skip_out_of_scope": str(not include_out_of_scope).lower()})
        with file.open("rb") as fh:
            result = client.json("POST", f"/api/engagements/{eng['id']}/imports/upload?{query}",
                                 body=fh, content_type="application/octet-stream", length=size)
    except (NotRunning, LocalApiError) as exc:
        return _fail(str(exc))
    stats = ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in result["stats"].items())
    print(f"Imported {file.name} into {status['name']} / {eng['code']}. {stats}")
    return 0


def _read_new_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Vault password (12+ characters): ")
    if getpass.getpass("Repeat password: ") != first:
        raise ValueError("the passwords do not match")
    return first


def cmd_demo(path: Path, *, password_stdin: bool = False) -> int:
    from .bootstrap import make_unlock_hook
    from .demo import seed_demo
    from .vault.appconfig import AppConfig
    from .vault.manager import VaultError, VaultManager

    try:
        password = _read_new_password(password_stdin)
    except ValueError as exc:
        return _fail(str(exc))
    manager = VaultManager(AppConfig())
    manager.on_unlock(make_unlock_hook(manager))
    try:
        info = manager.create(path, password)
        vault = manager.require()
        seed_demo(vault)
        vault_path = vault.path
    except (VaultError, OSError) as exc:
        return _fail(str(exc))
    finally:
        manager.shutdown()
    print(f"Created {vault_path} with a sample engagement.\n")
    print("Recovery key (shown once; it opens the vault if you forget the password):\n")
    print(f"  {info.key}\n")
    print("Store it somewhere safe, then clear your terminal's scrollback. Open the vault with `offsechub`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
