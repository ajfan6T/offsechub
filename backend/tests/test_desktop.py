"""The desktop shell: JS bridge containment, downloads, runtime file, CLI."""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import cli, desktop
from app.localauth import LocalAuth
from app.localclient import LocalApiError, LocalClient
from app.main import create_app
from app.vault.appconfig import AppConfig, read_runtime
from app.vault.manager import VaultManager

from .conftest import PASSWORD, SAMPLES

webview = pytest.importorskip("webview")


class FakeEvent(list):
    def __iadd__(self, handler):
        self.append(handler)
        return self


class FakeEvents:
    def __init__(self):
        self.loaded = FakeEvent()


class FakeWindow:
    """Just enough of pywebview's Window for the shell's code paths."""

    def __init__(self, url="http://127.0.0.1:5000/", dialog_result=None):
        self.url = url
        self.dialog_result = dialog_result
        self.dialogs = []
        self.loaded_urls = []
        self.evaluated = []
        self.exposed = {}
        self._functions = self.exposed
        self.events = FakeEvents()
        self.done = threading.Event()

    def get_current_url(self):
        return self.url

    def create_file_dialog(self, dialog_type, directory="", allow_multiple=False, save_filename="", file_types=()):
        self.dialogs.append((dialog_type, save_filename))
        return self.dialog_result

    def load_url(self, url):
        self.loaded_urls.append(url)

    def run_js(self, script):
        self.evaluated.append(script)
        self.done.set()

    def expose(self, *functions):
        for f in functions:
            self.exposed[f.__name__] = f


@pytest.fixture
def bridge(monkeypatch):
    """Reset the module-level bridge state after each test."""
    state = desktop._bridge
    monkeypatch.setattr(state, "window", None)
    monkeypatch.setattr(state, "client", None)
    monkeypatch.setattr(state, "allowed_hosts", frozenset({"127.0.0.1:5000", "localhost:5000"}))
    return state


@pytest.fixture
def isolated_dirs(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))
    monkeypatch.setenv("OFFSECHUB_CONFIG_DIR", str(tmp_path / "config"))
    return tmp_path


# ------------------------------------------------------------- bridge


@pytest.fixture
def patched_bridge(monkeypatch):
    """install_bridge() patches pywebview's module globals; undo that afterwards."""
    from webview import util

    monkeypatch.setattr(util, "js_bridge_call", util.js_bridge_call)
    monkeypatch.setattr(util, "load_js_files", util.load_js_files)
    desktop.install_bridge()
    return util


def test_bridge_dispatch_refuses_everything_but_exposed_names(patched_bridge):
    """pywebview walks dotted attribute paths; only exact exposed names may get through."""
    util = patched_bridge
    window = FakeWindow()
    window._js_api = None
    called = []

    def pick_folder():
        called.append("pick_folder")
        return "/chosen"

    def helper():  # exposed by mistake, but not on the allow-list
        called.append("helper")

    window.expose(pick_folder, helper)
    for name in ("pick_folder.__globals__", "__class__.__init__.__globals__", "helper", "pick_vault",
                 "save_download", "pywebviewStateUpdate", "pywebviewMoveWindow", "pywebviewAsyncCallback"):
        assert util.js_bridge_call(window, name, [], "1") is None
    assert called == [] and window.evaluated == []

    util.js_bridge_call(window, "pick_folder", [], '1"]);alert(1);//')
    assert window.done.wait(5)
    assert called == ["pick_folder"]
    reply = window.evaluated[0]
    # Returned with run_js as JSON literals (pywebview's evaluate_js needs eval, which the CSP blocks),
    # and the page-supplied id cannot break out of its string.
    assert "eval(" not in reply and '{"value": "\\"/chosen\\""}' in reply
    assert '"1\\"]);alert(1);//"' in reply


def test_bridge_errors_reject_without_a_traceback(patched_bridge):
    window = FakeWindow()

    def pick_vault():
        raise ValueError("/x is not an OffsecHub vault")

    window.expose(pick_vault)
    patched_bridge.js_bridge_call(window, "pick_vault", [], "7")
    assert window.done.wait(5)
    assert '\\"isError\\"' not in window.evaluated[0]  # a real JSON object, not a string
    assert '"isError": true' in window.evaluated[0] and "not an OffsecHub vault" in window.evaluated[0]
    assert "Traceback" not in window.evaluated[0]


def test_bridge_patch_reaches_loaded_gui_backends(monkeypatch, patched_bridge):
    util = patched_bridge
    module = type(sys)("webview.platforms.fake")
    module.js_bridge_call = None
    monkeypatch.setitem(sys.modules, "webview.platforms.fake", module)
    desktop.install_bridge()  # idempotent: wraps the originals, not the wrappers
    assert module.js_bridge_call is util.js_bridge_call
    assert not hasattr(util.js_bridge_call.__wrapped__, "__wrapped__")
    assert not hasattr(util.load_js_files.__wrapped__, "__wrapped__")


NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="needs node")
def test_page_side_api_works_without_eval(patched_bridge, tmp_path):
    """Run pywebview's real api.js with string code generation disabled, as under the app's CSP.

    pywebview's own _createApi (new Function) fails there; OffsecHub's replacement
    yields promise-returning functions that post to the native bridge.
    """
    api_js = (Path(webview.util.get_js_dir()) / "api.js").read_text() % {
        "token": "t", "platform": "gtkwebkit2", "uid": "w", "js_api_endpoint": "None"}
    funcs = json.dumps([{"func": f, "params": []} for f in desktop.BRIDGE_FUNCTIONS] +
                       [{"func": "a.b", "params": []}])
    script = tmp_path / "bridge.js"
    script.write_text(f"""
globalThis.window = globalThis;
globalThis.Window = function () {{}};  // DOM classes pywebview's stringify checks against
globalThis.Node = function () {{}};
var posted = [];
window.webkit = {{messageHandlers: {{jsBridge: {{postMessage: function (m) {{ posted.push(JSON.parse(m)); }}}}}}}};
{api_js}
var stock;
try {{ window.pywebview._createApi({funcs}); stock = 'worked'; }} catch (e) {{ stock = e.name; }}
{desktop.CSP_SAFE_CREATE_API}
window.pywebview._createApi({funcs});
var p = window.pywebview.api.save_download('/api/x', 'x.txt');
var call = posted[0];
window.pywebview._returnValuesCallbacks[call.funcName][call.id]({{value: '"/home/me/x.txt"'}});
p.then(function (v) {{
  console.log(JSON.stringify({{stock: stock, call: call, value: v,
    names: Object.keys(window.pywebview.api).sort()}}));
}});
""")
    out = subprocess.run([NODE, "--disallow-code-generation-from-strings", str(script)],
                         capture_output=True, text=True, timeout=30, check=True).stdout
    result = json.loads(out)
    assert result["stock"] == "EvalError"  # why the replacement exists
    assert result["call"]["funcName"] == "save_download" and result["call"]["params"] == ["/api/x", "x.txt"]
    assert result["value"] == "/home/me/x.txt"
    assert result["names"] == sorted(desktop.BRIDGE_FUNCTIONS)  # dotted names are never created


def test_injected_scripts_include_the_csp_safe_api(patched_bridge):
    window = type("W", (), {"uid": "w", "js_api_endpoint": None, "text_select": True, "zoomable": False,
                            "draggable": False, "easy_drag": False, "frameless": False, "state": {}})()
    js_code, finish = patched_bridge.load_js_files(window, "gtkwebkit2")
    assert js_code.endswith(desktop.CSP_SAFE_CREATE_API) and "_createApi" in finish


def test_window_gets_no_js_api_object_and_only_three_functions(monkeypatch, bridge):
    created, started, handlers = {}, {}, {}
    window = FakeWindow()

    def create_window(title, **kwargs):
        created.update(kwargs, title=title)
        return window

    monkeypatch.setattr(webview, "create_window", create_window)
    monkeypatch.setattr(webview, "start", lambda **kw: started.update(kw))
    monkeypatch.setattr(desktop, "install_bridge", lambda: None)
    monkeypatch.setattr(desktop.signal, "signal", lambda sig, fn: handlers.setdefault(sig, fn))
    for key in ("ALLOW_DOWNLOADS", "OPEN_EXTERNAL_LINKS_IN_BROWSER"):
        monkeypatch.setitem(webview.settings, key, webview.settings[key])

    auth = LocalAuth()
    auth.bind(5000)

    class FakeServer:
        port = 5000

    desktop._run_window(FakeServer(), manager=None, auth=auth, debug=False)
    assert "js_api" not in created and created["text_select"] is True
    assert created["url"].startswith("http://127.0.0.1:5000/_launch?token=")
    assert sorted(window.exposed) == sorted(desktop.BRIDGE_FUNCTIONS)
    assert all(f.__module__ == "app.desktop" for f in window.exposed.values())
    assert started == {"private_mode": True, "debug": False}
    assert webview.settings["ALLOW_DOWNLOADS"] is False
    assert webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] is True
    assert desktop._keep_in_app in window.events.loaded
    assert bridge.window is None  # cleared when the GUI loop ends


def test_bridge_functions_only_serve_the_app_page(bridge, tmp_path):
    (tmp_path / "Real.ohvault").mkdir()
    (tmp_path / "Real.ohvault" / "vault.json").write_text("{}")
    bridge.window = FakeWindow(url="https://evil.example/", dialog_result=[str(tmp_path)])
    for fn in (desktop.pick_folder, desktop.pick_vault):
        with pytest.raises(PermissionError):
            fn()
    with pytest.raises(PermissionError):
        desktop.save_download("/api/vault/recovery-kit", "kit.json")
    assert bridge.window.dialogs == []  # refused before any dialog opened

    bridge.window.url = "http://127.0.0.1:5000/settings"
    assert desktop.pick_folder() == str(tmp_path)
    with pytest.raises(ValueError, match="not an OffsecHub vault"):
        desktop.pick_vault()
    bridge.window.dialog_result = (str(tmp_path / "Real.ohvault"),)
    assert desktop.pick_vault() == str(tmp_path / "Real.ohvault")
    bridge.window.dialog_result = None
    assert desktop.pick_folder() is None


def test_navigation_guard_returns_to_the_app(bridge):
    bridge.client = LocalClient(5000, "t")
    away = FakeWindow(url="https://evil.example/phish")
    desktop._keep_in_app(away)
    assert away.loaded_urls == ["http://127.0.0.1:5000/"]
    home = FakeWindow(url="http://127.0.0.1:5000/engagements/1")
    desktop._keep_in_app(home)
    assert home.loaded_urls == []


@pytest.mark.parametrize("path", [
    "/api/engagements/1/evidence/2/download",
    "/api/engagements/1/report?format=md&download=true",
    "/api/vault/recovery-kit",
])
def test_download_paths_accepted(path):
    assert desktop.validate_api_path(path) == path


@pytest.mark.parametrize("path", [
    "http://evil.example/api/x", "//evil.example/api/x", "/api/../app/info", "/api/%2e%2e/x",
    "/assets/index.js", "/api/x#y", "/api/x\\y", "/api/x\ny", "/api//x", "api/x", "", None, 5,
    "/api/" + "a" * 3000,
])
def test_download_paths_refused(path):
    with pytest.raises(ValueError):
        desktop.validate_api_path(path)


@pytest.mark.parametrize("name,expected", [
    ("report.md", "report.md"), ("../../etc/passwd", "passwd"), ("C:\\Users\\x\\a.txt", "a.txt"),
    ('a:b?"c".txt', "a-b--c-.txt"), ("", "download"), ("...", "download"), ("x\x00y", "x-y"),
])
def test_download_names_are_bare_file_names(name, expected):
    assert desktop.safe_download_name(name) == expected


# ------------------------------------------------- live server (real HTTP)


@pytest.fixture
def live(tmp_path):
    """The real app on a real loopback socket, as the shell runs it."""
    manager = VaultManager(AppConfig(tmp_path / "config"))
    auth = LocalAuth()
    sock = desktop.bind_loopback(0)
    port = sock.getsockname()[1]
    auth.bind(port)
    app = create_app(manager, auth, desktop=True, frontend_dist=tmp_path / "no-frontend")
    app.state.port = port
    server = desktop.LocalServer(app, sock)
    server.start()
    client = LocalClient(port, auth.api_token)
    yield client, manager, auth
    server.stop()
    manager.shutdown()


def test_server_listens_on_loopback_and_requires_the_token(live):
    client, _manager, _auth = live
    assert client.alive()
    with pytest.raises(LocalApiError) as exc:
        LocalClient(client.port, "ohub_wrong").json("GET", "/api/vault/status")
    assert exc.value.status == 401


def _vault_with_evidence(client: LocalClient, tmp_path: Path) -> tuple[int, int]:
    client.json("POST", "/api/vault/create", {"path": str(tmp_path / "v"), "password": PASSWORD})
    owner = client.json("POST", "/api/clients", {"name": "ACME"})
    eng = client.json("POST", "/api/engagements", {"client_id": owner["id"], "name": "Ext", "code": "ACME-1",
                                                   "type": "external_network"})
    ev = client.json("POST", f"/api/engagements/{eng['id']}/evidence/text",
                     {"filename": "notes.txt", "content": "id=0(root)\n"})
    return eng["id"], ev["id"]


def test_save_download_fetches_through_the_api_and_writes_atomically(live, bridge, tmp_path):
    client, manager, auth = live
    eng_id, ev_id = _vault_with_evidence(client, tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    dest = out / "saved.txt"
    bridge.client = client
    bridge.allowed_hosts = frozenset(auth.allowed_hosts)
    bridge.window = FakeWindow(url=f"http://127.0.0.1:{client.port}/", dialog_result=str(dest))
    path = f"/api/engagements/{eng_id}/evidence/{ev_id}/download"

    assert desktop.save_download(path, "../notes.txt") == str(dest)
    assert dest.read_text() == "id=0(root)\n"
    assert bridge.window.dialogs[-1] == (webview.FileDialog.SAVE, "notes.txt")

    bridge.window.dialog_result = None  # cancelled: nothing fetched, nothing written
    assert desktop.save_download(path, "notes.txt") is None

    manager.lock(reason="manual")
    bridge.window.dialog_result = str(out / "locked.txt")
    with pytest.raises(LocalApiError) as exc:
        desktop.save_download(path, "notes.txt")
    assert exc.value.status == 423
    assert sorted(p.name for p in out.iterdir()) == ["saved.txt"]  # no partial file left behind


def test_report_export_is_recorded_in_activity(live, tmp_path):
    client, _manager, _auth = live
    eng_id, _ev = _vault_with_evidence(client, tmp_path)
    size = client.download(f"/api/engagements/{eng_id}/report?format=md&download=true", tmp_path / "r.md")
    assert size > 0 and (tmp_path / "r.md").read_text().startswith("# ")
    events = client.json("GET", f"/api/engagements/{eng_id}/activity")
    assert any(e["action"] == "export" for e in events)


# ---------------------------------------------------- process lifecycle


def test_runtime_file_exists_only_while_serving(isolated_dirs, monkeypatch):
    monkeypatch.setattr(desktop, "harden_process", lambda: [])
    seen = {}

    def foreground(server, auth, mode, *, open_browser):
        info = read_runtime()
        seen["mode"] = (mode, open_browser)
        seen["runtime"] = info
        seen["mode_bits"] = stat.S_IMODE(os.stat(desktop.runtime_file()).st_mode)
        seen["alive"] = LocalClient(info["port"], info["token"]).alive()
        seen["second"] = desktop.run("browser")  # a second instance refuses to start

    monkeypatch.setattr(desktop, "_run_foreground", foreground)
    assert desktop.run("browser", open_browser=False) == 0
    assert seen["mode"] == ("browser", False)
    assert seen["alive"] and seen["mode_bits"] == 0o600
    assert seen["runtime"]["token"].startswith("ohub_")
    assert seen["second"] == 1
    assert read_runtime() is None


def test_redirect_file_keeps_the_token_off_the_command_line(isolated_dirs):
    url = "http://127.0.0.1:5000/_launch?token=abc&x=<y>"
    page = desktop.write_redirect_file(url)
    assert page.parent == desktop.runtime_file().parent
    assert stat.S_IMODE(page.stat().st_mode) == 0o600
    assert 'content="0;url=http://127.0.0.1:5000/_launch?token=abc&amp;x=&lt;y&gt;"' in page.read_text()


def test_dev_mode_admits_the_vite_origin(tmp_path):
    manager = VaultManager(AppConfig(tmp_path / "config"))
    auth = LocalAuth()
    auth.bind(desktop.DEV_PORT, desktop.DEV_HOSTS)
    app = create_app(manager, auth, frontend_dist=tmp_path / "no-frontend")
    try:
        vite = TestClient(app, base_url="http://localhost:5173")
        assert vite.get(f"/_launch?token={auth.new_launch_token()}", follow_redirects=False).status_code == 303
        headers = {"X-Requested-With": "OffsecHub", "Origin": "http://localhost:5173"}
        assert vite.put("/api/app/preferences", json={"remember_recent": False}, headers=headers).status_code == 204
        other = TestClient(app, base_url="http://localhost:5174")
        assert other.get("/api/vault/status").status_code == 421
    finally:
        manager.shutdown()


# ------------------------------------------------------------------ CLI


def test_cli_parses_the_documented_commands():
    p = cli._parser()
    a = p.parse_args(["import", "ACME-EXT-26", "scan.xml", "--tool", "nmap"])
    assert (a.command, a.engagement, a.file, a.tool, a.include_out_of_scope) == \
        ("import", "ACME-EXT-26", Path("scan.xml"), "nmap", False)
    assert p.parse_args(["--browser", "--no-open"]).browser
    assert p.parse_args(["demo", "x"]).path == Path("x")
    with pytest.raises(SystemExit):
        p.parse_args(["--browser", "--dev"])
    with pytest.raises(SystemExit):
        p.parse_args(["import", "A", "f", "--tool", "masscan"])


def test_cli_version(capsys):
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.startswith("OffsecHub ")


def test_find_engagement_by_code_or_id():
    engagements = [{"id": 3, "code": "ACME-EXT-26"}, {"id": 7, "code": "7"}]
    assert cli.find_engagement(engagements, "acme-ext-26")["id"] == 3
    assert cli.find_engagement(engagements, "7")["id"] == 7  # a code wins over an id
    assert cli.find_engagement(engagements, "3")["id"] == 3
    assert cli.find_engagement(engagements, "nope") is None


def test_cli_import_needs_a_running_app(isolated_dirs, capsys):
    assert cli.main(["import", "ACME", str(SAMPLES / "nmap-acme.xml"), "--tool", "nmap"]) == 1
    assert "not running" in capsys.readouterr().err


def test_cli_import_into_running_app(live, tmp_path, isolated_dirs, capsys, monkeypatch):
    client, _manager, _auth = live
    _vault_with_evidence(client, tmp_path)
    monkeypatch.setattr("app.localclient.read_runtime", lambda: {"port": client.port, "token": client.token})
    assert cli.main(["import", "acme-1", str(SAMPLES / "subdomains-acme.txt"), "--tool", "list",
                     "--include-out-of-scope"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Imported subdomains-acme.txt into v / ACME-1.")


def test_cli_demo_creates_a_vault_and_prints_the_recovery_key_once(isolated_dirs, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(["demo", str(isolated_dirs / "Demo"), "--password-stdin"]) == 0
    out = capsys.readouterr().out
    key = next(line.strip() for line in out.splitlines() if line.strip().startswith("OHRK-"))
    manager = VaultManager(AppConfig())
    try:
        manager.unlock(isolated_dirs / "Demo.ohvault", recovery_key=key)
        assert manager.require().must_set_password
    finally:
        manager.shutdown()
    assert cli.main(["demo", str(isolated_dirs / "Demo"), "--password-stdin"]) == 1  # never overwrites


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
@pytest.mark.parametrize("signame", ["SIGTERM", "SIGHUP", "SIGINT"])
def test_signals_save_lock_and_clean_up(isolated_dirs, signame):
    """Ctrl+C, kill and closing the terminal all save and lock before exiting.

    uvicorn re-raises the signals it handled after shutting down; with default
    handlers that killed the process before runtime.json was removed.
    """
    import signal as signals
    import time

    proc = subprocess.Popen([sys.executable, "-m", "app", "--browser", "--no-open"],
                            cwd=Path(__file__).resolve().parents[1],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 20
        while read_runtime() is None:
            assert proc.poll() is None and time.monotonic() < deadline, proc.stderr.read()
            time.sleep(0.05)
        client = LocalClient.from_runtime()
        client.json("POST", "/api/vault/create", {"path": str(isolated_dirs / "v"), "password": PASSWORD})
        client.json("PUT", "/api/profile", {"name": signame, "email": "", "organization": ""})
        proc.send_signal(getattr(signals, signame))
        assert proc.wait(30) == 0, proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()
    assert read_runtime() is None
    manager = VaultManager(AppConfig())
    try:
        manager.unlock(isolated_dirs / "v.ohvault", password=PASSWORD)  # the vault lock was released
        with manager.require().session() as db:
            from app.bootstrap import get_setting

            assert get_setting(db, "operator.profile")["name"] == signame
    finally:
        manager.shutdown()
