"""Desktop shell: the local API on a private port, shown in a native window.

    offsechub              native window (pywebview: WebKit, WebView2 or WebKitGTK)
    offsechub --browser    no window: opens the app in your browser (reduced security)
    offsechub --dev        API on 127.0.0.1:8000 for the Vite dev server (localhost:5173)

The API binds 127.0.0.1 on a port the OS picks and admits only the client that
presents the one-time launch token (``localauth.py``). The window's JavaScript
can reach Python through exactly three functions, all of which open a native
dialog the user has to confirm.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import signal
import socket
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .localauth import LocalAuth
from .localclient import LocalClient, NotRunning
from .main import create_app
from .vault.appconfig import (
    AppConfig,
    _check_private_dir,
    clear_runtime,
    default_vault_dir,
    runtime_file,
    write_runtime,
)
from .vault.hardening import harden_process
from .vault.manager import VaultManager

log = logging.getLogger("offsechub")

DEV_PORT = 8000
DEV_HOSTS = ("localhost:5173", "127.0.0.1:5173")
BRIDGE_FUNCTIONS = ("pick_folder", "pick_vault", "save_download")
WINDOW_BACKGROUND = "#0a0f1a"

BROWSER_WARNING = """\
Browser mode has weaker isolation than the desktop window:
  * the session cookie is shared with every other web server on 127.0.0.1;
  * browser extensions can read the app's pages;
  * downloads and the browser's cache and history live in your browser profile.
Use it when the desktop window is unavailable. Press Ctrl+C here to lock the vault and quit."""


# ------------------------------------------------------------------ server


def bind_loopback(port: int = 0) -> socket.socket:
    """Bind 127.0.0.1 ourselves, so the port is known before the server starts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == "nt":
        # Otherwise another process could bind the same port with SO_REUSEADDR
        # and receive some of our connections.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    elif port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # --dev restarts quickly
    sock.bind(("127.0.0.1", port))
    sock.set_inheritable(False)
    return sock


class LocalServer:
    """uvicorn on a pre-bound socket; no access log (URLs carry engagement ids)."""

    def __init__(self, app, sock: socket.socket):
        import uvicorn

        self.sock = sock
        self.port: int = sock.getsockname()[1]
        config = uvicorn.Config(
            app, log_config=None, access_log=False, log_level="warning", ws="none",
            lifespan="on", server_header=False, timeout_graceful_shutdown=5,
        )
        self.server = uvicorn.Server(config)
        self.thread: threading.Thread | None = None

    def start(self, timeout: float = 20) -> None:
        """Serve from a background thread; the main thread keeps the GUI and signals."""
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]},
                                       name="offsechub-api", daemon=True)
        self.thread.start()
        deadline = time.monotonic() + timeout
        while not self.server.started:
            if not self.thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("the local API did not start")
            time.sleep(0.02)

    def stop(self, timeout: float = 30) -> None:
        self.server.should_exit = True
        if self.thread is not None:
            self.thread.join(timeout)


def running_instance() -> LocalClient | None:
    try:
        return LocalClient.from_runtime()
    except NotRunning:
        return None


# ------------------------------------------------------------------ bridge


class _BridgeState:
    window: Any = None
    client: LocalClient | None = None
    allowed_hosts: frozenset[str] = frozenset()


_bridge = _BridgeState()


# pywebview builds window.pywebview.api with `new Function(...)`, which the app's
# CSP (script-src 'self', no 'unsafe-eval') forbids. This replacement builds the
# same promise-returning functions from closures. Flat names only.
CSP_SAFE_CREATE_API = r"""
window.pywebview._createApi = function (funcList) {
  funcList.forEach(function (element) {
    var funcName = element.func;
    if (typeof funcName !== 'string' || funcName.indexOf('.') !== -1) return;
    window.pywebview._returnValuesCallbacks[funcName] = {};
    window.pywebview.api[funcName] = function () {
      var id = (Math.random() + '').substring(2);
      var args = Array.prototype.slice.call(arguments);
      var promise = new Promise(function (resolve, reject) {
        window.pywebview._checkValue(funcName, resolve, reject, id);
      });
      window.pywebview._jsApiCallback(funcName, args, id);
      return promise;
    };
  });
};
true;
"""


def install_bridge(allowed: tuple[str, ...] = BRIDGE_FUNCTIONS) -> None:
    """A JS bridge that admits exact, allow-listed names and works under the CSP.

    Two changes to pywebview (6.x):

    * Dispatch. pywebview resolves a call by walking a *dotted attribute path*
      from its JS API object (``a.b.__class__...``), which turns script in the
      page into attribute traversal in Python. OffsecHub passes no JS API
      object, and this dispatcher only calls functions registered with
      ``window.expose`` under one of the ``allowed`` names. pywebview's own
      internal messages (window dragging, shared state, DOM events) are refused
      too: OffsecHub doesn't use them.
    * No eval. pywebview creates the page-side functions with ``new Function``
      and returns results through ``eval``; the CSP blocks both. Results go back
      through ``run_js`` as a JSON literal instead, and the API object is built
      by ``CSP_SAFE_CREATE_API``.
    """
    from webview import util

    original_load = getattr(util.load_js_files, "__wrapped__", util.load_js_files)

    def load_js_files(window, platform):
        js_code, finish_script = original_load(window, platform)
        return js_code + CSP_SAFE_CREATE_API, finish_script

    def js_bridge_call(window, func_name, param, value_id):
        func = getattr(window, "_functions", {}).get(func_name) if func_name in allowed else None
        if func is None:
            log.warning("refused a bridge call to %r", str(func_name)[:80])
            return None
        args = param if isinstance(param, list) else []
        threading.Thread(target=_answer_bridge_call, args=(window, func_name, func, args, value_id),
                         name="offsechub-bridge", daemon=True).start()
        return None

    load_js_files.__wrapped__ = original_load  # type: ignore[attr-defined]
    js_bridge_call.__wrapped__ = getattr(util.js_bridge_call, "__wrapped__", util.js_bridge_call)  # type: ignore[attr-defined]
    util.load_js_files = load_js_files
    util.js_bridge_call = js_bridge_call
    # GUI backends import the dispatcher by name; patch any already loaded.
    for name, module in list(sys.modules.items()):
        if name.startswith("webview.platforms") and hasattr(module, "js_bridge_call"):
            module.js_bridge_call = js_bridge_call


def _answer_bridge_call(window, func_name: str, func, args: list, value_id) -> None:
    try:
        reply: dict[str, Any] = {"value": json.dumps(func(*args))}
    except Exception as exc:  # reaches the page as a rejected promise; no traceback
        log.warning("bridge call %s failed: %s", func_name, exc)
        reply = {"isError": True,
                 "value": json.dumps({"message": str(exc), "name": type(exc).__name__, "stack": ""})}
    callbacks = f"window.pywebview._returnValuesCallbacks[{json.dumps(func_name)}]"
    window.run_js(f"(function (cbs) {{ var cb = cbs && cbs[{json.dumps(str(value_id))}]; "
                  f"if (cb) cb({json.dumps(reply)}); return true; }})({callbacks});")


def _in_app(url: str | None) -> bool:
    parts = urlsplit(url or "")
    return parts.scheme == "http" and parts.netloc in _bridge.allowed_hosts


def _require_app_page() -> Any:
    window = _bridge.window
    if window is None or not _in_app(window.get_current_url()):
        raise PermissionError("Only OffsecHub's own pages can open native dialogs")
    return window


def _first(result: Any) -> str | None:
    """create_file_dialog returns a str (save), a sequence (open/folder) or None."""
    if not result:
        return None
    return result if isinstance(result, str) else str(result[0])


def _start_dir(preferred: Path) -> str:
    return str(preferred if preferred.is_dir() else Path.home())


def looks_like_vault(path: Path) -> bool:
    return any((path / name).exists() for name in ("vault.json", "vault.json.mirror", "db.enc"))


def validate_api_path(api_path: Any) -> str:
    """A same-origin API path, nothing else: no scheme, host, traversal or control bytes."""
    if not isinstance(api_path, str) or len(api_path) > 2048:
        raise ValueError("Not an OffsecHub download")
    parts = urlsplit(api_path)
    segments = unquote(parts.path).split("/")
    if (parts.scheme or parts.netloc or parts.fragment or not parts.path.startswith("/api/")
            or "\\" in api_path or any(ord(c) < 0x20 or ord(c) == 0x7F for c in api_path)
            or ".." in segments or "" in segments[1:-1]):
        raise ValueError("Not an OffsecHub download")
    return api_path


def safe_download_name(name: Any, fallback: str = "download") -> str:
    """A bare file name for the save dialog (the user can still change it)."""
    base = str(name or "").replace("\\", "/").rsplit("/", 1)[-1]
    base = re.sub(r'[<>:"|?*\x00-\x1f\x7f]', "-", base).strip(" .")
    return base[:200] or fallback


# The functions below are what the page can call (window.pywebview.api.*).
# Module-level, flat, and holding no reference to the vault.


def pick_folder() -> str | None:
    """Native "choose folder" dialog; resolves to a path or null."""
    import webview

    window = _require_app_page()
    return _first(window.create_file_dialog(webview.FileDialog.FOLDER,
                                            directory=_start_dir(default_vault_dir())))


def pick_vault() -> str | None:
    """Native "open vault" dialog; resolves to a vault folder or null."""
    import webview

    window = _require_app_page()
    chosen = _first(window.create_file_dialog(webview.FileDialog.FOLDER,
                                              directory=_start_dir(default_vault_dir())))
    if chosen and not looks_like_vault(Path(chosen)):
        raise ValueError(f"{chosen} is not an OffsecHub vault (it has no vault.json)")
    return chosen


def save_download(api_path: str, suggested_name: str = "") -> str | None:
    """Save an export or evidence file through a native "save as" dialog.

    The webview's own download handling is off: WebKit on macOS re-fetches
    downloads without the session cookie, and other engines save silently to
    the Downloads folder. Instead the user picks a destination and the shell
    fetches the file from the local API itself. Resolves to the saved path,
    or null if the user cancelled.
    """
    import webview

    window = _require_app_page()
    path = validate_api_path(api_path)
    if _bridge.client is None:
        raise RuntimeError("OffsecHub is shutting down")
    downloads = Path.home() / "Downloads"
    dest = _first(window.create_file_dialog(webview.FileDialog.SAVE, directory=_start_dir(downloads),
                                            save_filename=safe_download_name(suggested_name)))
    if not dest:
        return None
    _bridge.client.download(path, Path(dest))
    return dest


def _keep_in_app(window) -> None:
    """Navigation guard: the window only ever shows OffsecHub itself."""
    url = window.get_current_url()
    if url and not _in_app(url):
        log.warning("blocked navigation away from OffsecHub")
        window.load_url(f"http://127.0.0.1:{_bridge.client.port}/" if _bridge.client else "about:blank")


# ------------------------------------------------------------------ modes


def _ensure_std_streams() -> None:
    """Windowed builds have no console: give logging somewhere harmless to write."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w"))  # noqa: SIM115 - process lifetime


WINDOW_HELP = (
    "On Windows, install the Microsoft Edge WebView2 Runtime. On Linux, install WebKitGTK "
    "(gir1.2-webkit2-4.1). Or run OffsecHub in your browser instead: offsechub --browser "
    "(offsechub-cli --browser on Windows)."
)


def show_message(text: str, *, error: bool = True, dialog: bool = False) -> None:
    """Print, and for the windowed app also show a native dialog (there may be no console)."""
    print(text, file=sys.stderr, flush=True)
    if not dialog:
        return
    try:
        if sys.platform == "win32":
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, text, "OffsecHub", 0x10 if error else 0x40)
        elif sys.platform == "darwin":
            import subprocess

            subprocess.run(["osascript", "-e", "on run argv", "-e",
                            "display alert \"OffsecHub\" message (item 1 of argv)", "-e", "end run", text],
                           check=False, timeout=600, capture_output=True)
    except Exception:  # best effort: the message is in the log too
        log.debug("could not show a dialog", exc_info=True)


def write_redirect_file(url: str) -> Path:
    """A private page that forwards to ``url``.

    Opening the one-time link directly would put it on the browser's command
    line, where other local users can read it (ps) and race to redeem it.
    """
    directory = runtime_file().parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _check_private_dir(directory)
    fd, name = tempfile.mkstemp(prefix="open-", suffix=".html", dir=directory)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write('<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer">'
                 f'<meta http-equiv="refresh" content="0;url={html.escape(url)}"><title>OffsecHub</title>')
    timer = threading.Timer(60, lambda: Path(name).unlink(missing_ok=True))
    timer.daemon = True
    timer.start()
    return Path(name)


def open_in_browser(url: str) -> None:
    print(f"\nIf your browser does not open, paste this one-time link into it:\n  {url}\n", flush=True)
    try:
        webbrowser.open(write_redirect_file(url).as_uri())
    except (OSError, webbrowser.Error) as exc:
        log.warning("could not open a browser: %s", exc)


def run(mode: str = "window", *, open_browser: bool = True, debug: bool = False) -> int:
    """Start OffsecHub. ``mode`` is "window", "browser" or "dev"."""
    _ensure_std_streams()
    for measure in harden_process():
        log.info("hardening: %s", measure)

    if mode != "dev" and (other := running_instance()) is not None:
        message = "OffsecHub is already running. Switch to its window."
        if mode != "window":
            message = f"OffsecHub is already running (port {other.port}). Run `offsechub open` for a browser link to it."
        show_message(message, error=False, dialog=mode == "window")
        return 1

    manager = VaultManager(AppConfig())
    auth = LocalAuth()
    try:
        sock = bind_loopback(DEV_PORT if mode == "dev" else 0)
    except OSError as exc:
        print(f"Could not listen on 127.0.0.1: {exc}", file=sys.stderr)
        return 1
    port = sock.getsockname()[1]
    auth.bind(port, DEV_HOSTS if mode == "dev" else ())
    app = create_app(manager, auth, desktop=mode == "window")
    app.state.port = port
    server = LocalServer(app, sock)
    try:
        server.start()
        try:  # only once the API answers, so the CLI never finds a dead port
            write_runtime(port, auth.api_token)
        except OSError as exc:  # the app still works, only the CLI can't find it
            log.warning("the CLI will not be able to reach this instance: %s", exc)
        if mode == "window":
            try:
                _run_window(server, manager, auth, debug=debug)
            except Exception as exc:  # no GUI toolkit, no WebView2...
                log.exception("the desktop window failed")
                show_message(f"OffsecHub could not open its window:\n\n{exc}\n\n{WINDOW_HELP}", dialog=True)
                return 1
        else:
            _run_foreground(server, auth, mode, open_browser=open_browser)
    finally:
        _bridge.client = None
        server.stop()  # lifespan shutdown: flush, lock, release the vault
        try:
            manager.shutdown()  # idempotent; the server's lifespan normally did it already
        except Exception:
            log.exception("could not lock the vault cleanly")
        clear_runtime(auth.api_token)
    return 0


def _run_foreground(server: LocalServer, auth: LocalAuth, mode: str, *, open_browser: bool) -> None:
    # Ctrl+C, kill and closing the terminal (SIGHUP) all lock and save first.
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: setattr(server.server, "should_exit", True))
    if mode == "dev":
        url = auth.launch_url(server.port).replace(f"127.0.0.1:{server.port}", DEV_HOSTS[0])
        print(f"OffsecHub API (dev) on 127.0.0.1:{server.port}. Start `npm run dev` in frontend/, "
              f"then open:\n  {url}", flush=True)
    else:
        print(BROWSER_WARNING, flush=True)
        url = auth.launch_url(server.port)
        if open_browser:
            open_in_browser(url)
        else:
            print(f"\nOne-time link:\n  {url}\n", flush=True)
    while server.thread is not None and server.thread.is_alive():
        server.thread.join(0.5)  # wakes up for signal handlers


def _run_window(server: LocalServer, manager: VaultManager, auth: LocalAuth, *, debug: bool) -> None:
    import webview

    install_bridge()
    webview.settings["ALLOW_DOWNLOADS"] = False  # save_download replaces them
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
    _bridge.client = LocalClient(server.port, auth.api_token)
    _bridge.allowed_hosts = frozenset(auth.allowed_hosts)
    window = webview.create_window(
        "OffsecHub", url=auth.launch_url(server.port), width=1360, height=880, min_size=(960, 640),
        text_select=True, background_color=WINDOW_BACKGROUND,
    )
    _bridge.window = window
    window.expose(pick_folder, pick_vault, save_download)
    window.events.loaded += _keep_in_app

    def quit_app(*_args) -> None:
        def close() -> None:
            try:
                manager.shutdown()
            finally:
                for w in list(webview.windows):
                    w.destroy()

        threading.Thread(target=close, name="offsechub-quit").start()

    for name in ("SIGTERM", "SIGHUP", "SIGINT"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), quit_app)
    try:
        webview.start(private_mode=True, debug=debug)
    finally:
        _bridge.window = None
