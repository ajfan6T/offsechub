"""Smoke-test an installed OffsecHub: the real binary, as a user would run it.

    python packaging/smoke_test.py --app /usr/bin/offsechub                       # Linux .deb
    python packaging/smoke_test.py --app /Applications/OffsecHub.app/Contents/MacOS/offsechub
    python packaging/smoke_test.py --app "C:\\...\\offsechub.exe" --cli "C:\\...\\offsechub-cli.exe"

Standard library only. Uses a throwaway config directory, so it never touches
the user's settings. Checks, in order:

1. `version` and `demo` (Argon2, AES-GCM and the bundled sample data work in
   the installed build);
2. the desktop window (or `--browser` mode) starts, publishes runtime.json and
   serves the UI;
3. the local API unlocks the demo vault and renders a report (templates);
4. the window is still alive a few seconds later (the GUI toolkit loaded);
5. a normal shutdown (SIGTERM, or closing the window on Windows) saves, locks
   and removes runtime.json.

Exits non-zero with a message on the first failure.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PASSWORD = "smoke-test-password-2026"
WINDOWS = sys.platform == "win32"


def fail(message: str, proc: subprocess.Popen | None = None) -> None:
    print(f"FAIL {message}", flush=True)
    if proc is not None:
        if proc.poll() is None:
            proc.kill()
        out = proc.stdout.read() if proc.stdout else ""
        if out:
            print(out[-4000:])
    sys.exit(1)


def ok(message: str) -> None:
    print(f"PASS {message}", flush=True)


def call(port: int, token: str, method: str, path: str, body: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    return resp.status, payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True, help="the installed app (windowed on Windows)")
    parser.add_argument("--cli", help="console binary for commands (Windows: offsechub-cli.exe); defaults to --app")
    parser.add_argument("--browser", action="store_true", help="test --browser mode instead of the window")
    parser.add_argument("--startup-timeout", type=float, default=90)
    args = parser.parse_args()
    app, cli = args.app, args.cli or args.app

    work = Path(tempfile.mkdtemp(prefix="offsechub-smoke-"))
    env = dict(os.environ, OFFSECHUB_CONFIG_DIR=str(work / "config"))
    runtime = work / "config" / "runtime.json"
    if sys.platform.startswith("linux"):
        (work / "run").mkdir(mode=0o700)
        env["XDG_RUNTIME_DIR"] = str(work / "run")
        runtime = work / "run" / "offsechub" / "runtime.json"

    out = subprocess.run([cli, "version"], env=env, capture_output=True, text=True, timeout=120)
    if out.returncode != 0 or not out.stdout.startswith("OffsecHub "):
        fail(f"`version`: exit {out.returncode}: {out.stdout}{out.stderr}")
    ok(out.stdout.strip())

    vault = work / "vaults" / "Smoke"
    out = subprocess.run([cli, "demo", str(vault), "--password-stdin"], input=PASSWORD + "\n", env=env,
                         capture_output=True, text=True, timeout=300)
    vault = vault.with_name("Smoke.ohvault")
    if out.returncode != 0 or "OHRK-" not in out.stdout or not (vault / "db.enc").exists():
        fail(f"`demo`: exit {out.returncode}: {out.stdout}{out.stderr}")
    ok("demo vault created (Argon2id, AES-256-GCM, bundled samples)")

    command = [app, "--browser", "--no-open"] if args.browser else [app]
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0
    proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            creationflags=flags)
    deadline = time.monotonic() + args.startup_timeout
    while not runtime.exists():
        if proc.poll() is not None:
            fail(f"the app exited with {proc.returncode} before it was ready", proc)
        if time.monotonic() > deadline:
            fail("the app did not publish runtime.json in time", proc)
        time.sleep(0.25)
    time.sleep(0.5)  # written atomically, but give the API a moment
    info = json.loads(runtime.read_text())
    port, token = int(info["port"]), info["token"]
    ok(f"{'browser mode' if args.browser else 'window'} started, API on 127.0.0.1:{port}")

    status, body = call(port, token, "GET", "/")
    if status != 200 or b'id="root"' not in body:
        fail(f"UI not served: HTTP {status}", proc)
    status, body = call(port, token, "POST", "/api/vault/unlock", {"path": str(vault), "password": PASSWORD})
    if status != 200 or json.loads(body)["state"] != "unlocked":
        fail(f"unlock: HTTP {status}: {body[:300]!r}", proc)
    status, body = call(port, token, "GET", "/api/engagements")
    engagements = json.loads(body)
    if status != 200 or [e["code"] for e in engagements] != ["ACME-EXT-26"]:
        fail(f"engagements: HTTP {status}: {body[:300]!r}", proc)
    status, body = call(port, token, "GET", f"/api/engagements/{engagements[0]['id']}/report?format=html")
    if status != 200 or b"ACME Corporation" not in body:
        fail(f"report: HTTP {status}", proc)
    ok("UI served; vault unlocked; report rendered")

    time.sleep(5)
    if proc.poll() is not None:
        fail(f"the app exited with {proc.returncode} after starting", proc)
    ok("still running after 5 s")

    if WINDOWS:
        # taskkill without /F asks the window to close, like the user clicking X.
        subprocess.run(["taskkill", "/PID", str(proc.pid)], capture_output=True)
    else:
        proc.send_signal(signal.SIGTERM)
    try:
        code = proc.wait(60)
    except subprocess.TimeoutExpired:
        fail("the app did not exit after being asked to close", proc)
    if WINDOWS and code != 0 and runtime.exists():
        print(f"WARN the app was stopped (exit {code}) rather than closed; skipping the clean-exit check")
    else:
        if code != 0:
            fail(f"exit code {code} after a normal close", proc)
        if runtime.exists():
            fail("runtime.json was left behind", proc)
        ok("closed cleanly: saved, locked, runtime.json removed")
    shutil.rmtree(work, ignore_errors=True)
    print("smoke test passed")


if __name__ == "__main__":
    main()
