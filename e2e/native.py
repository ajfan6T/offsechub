"""Drive the real OffsecHub window (WebKitGTK, under Xvfb in CI) through a scenario.

Unlocks the demo vault, opens evidence, saves a file through the native bridge,
tries a dotted-path bridge call and an off-site navigation, then locks.
Run through e2e/run.sh; results go to $E2E_DIR/native-results.json.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

WORK = Path(os.environ["E2E_DIR"])
SHOTS = Path(os.environ.get("SHOTS", WORK / "shots"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import webview  # noqa: E402

from app import desktop  # noqa: E402

PASSWORD = "demo-password-1234"
results: dict = {}

HELPERS = r"""
window.__t = {
  text: () => document.body.innerText,
  click(label) {
    const el = [...document.querySelectorAll('button, a')].find(b => b.textContent.trim() === label && !b.disabled);
    if (!el) return false; el.click(); return true;
  },
  set(sel, v) {
    const el = document.querySelector(sel); if (!el) return false;
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
    el.dispatchEvent(new Event('input', {bubbles: true})); return true;
  },
};
true
"""


def shot(name):
    if shutil.which("import"):  # ImageMagick
        subprocess.run(["import", "-window", "root", str(SHOTS / f"native-{name}.png")], check=False)


def js(w, expr):
    """Evaluate an expression natively (the app's CSP rightly forbids pywebview's eval)."""
    out = w.run_js(f"JSON.stringify((function () {{ return ({expr}); }})())")
    return json.loads(out) if out not in (None, "", "undefined") else None


def wait_for(w, expr, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if js(w, expr):
                return True
        except Exception:
            pass
        time.sleep(0.25)
    raise TimeoutError(js)


def scenario():
    w = webview.windows[0]
    try:
        wait_for(w, "document.body && document.body.innerText.includes('Open vault')")
        w.run_js(HELPERS)
        results["url_after_launch"] = w.get_current_url()
        wait_for(w, "!!(window.pywebview && window.pywebview.api && window.pywebview.api.save_download)")
        results["bridge_api"] = js(w, "Object.keys(window.pywebview.api).sort()")
        time.sleep(0.5)
        shot("01-welcome")

        # Open the recent "Demo" vault and unlock it with the password.
        js(w, "__t.click('Open')")
        wait_for(w, "!!document.querySelector('input[type=password]')")
        js(w, f"__t.set('input[type=password]', {json.dumps(PASSWORD)})")
        time.sleep(0.3)
        shot("02-unlock")
        w.run_js("document.querySelector('form.gate-form').requestSubmit();")
        wait_for(w, "document.body.innerText.includes('Dashboard')", 40)
        w.run_js(HELPERS)
        time.sleep(1)
        shot("03-dashboard")

        # Navigate to the engagement's evidence and save a file through the bridge.
        w.run_js("fetch('/api/engagements').then(r => r.json()).then(j => { window.__eng = j[0].id; })")
        wait_for(w, "window.__eng")
        eng = js(w, "window.__eng")
        results["engagement"] = eng
        w.run_js(f"history.pushState(null, '', '/engagements/{eng}/evidence'); "
                 "dispatchEvent(new PopStateEvent('popstate'));")
        wait_for(w, "document.body.innerText.includes('git-config-response.txt')")
        time.sleep(1)
        shot("04-evidence")

        dest = WORK / "native-saved.txt"
        dest.unlink(missing_ok=True)
        # The native "save as" dialog needs a human; answer it for the test.
        w.create_file_dialog = lambda *a, **k: str(dest)
        w.run_js("[...document.querySelectorAll('a[download]')].find(a => a.textContent.trim() === "
                 "'git-config-response.txt').click();")
        saved = True
        wait_for(w, "document.body.innerText.includes('Saved to')", 15)
        results["save_download_clicked"] = saved
        results["saved_file_bytes"] = dest.stat().st_size if dest.exists() else None
        shot("05-saved-toast")

        # Script in the page tries to walk attributes through the bridge.
        w.run_js("window.pywebview._jsApiCallback('pick_folder.__globals__', [], 'x1'); "
                 "window.pywebview._jsApiCallback('__class__.__init__', [], 'x2');")
        # Navigation away from the app is reverted.
        w.run_js("location.href = 'about:blank#away';")
        time.sleep(2)
        results["url_after_navigation_attempt"] = w.get_current_url()

        # Lock from the UI.
        wait_for(w, "document.body && document.body.innerText.includes('Lock')", 20)
        w.run_js(HELPERS)
        js(w, "__t.click('Lock')")
        wait_for(w, "document.body.innerText.includes('Unlock')", 20)
        time.sleep(0.5)
        shot("06-locked")
        results["ok"] = True
    except Exception:
        results["error"] = traceback.format_exc()
        shot("99-error")
    finally:
        (WORK / "native-results.json").write_text(json.dumps(results, indent=2, default=str))
        for win in list(webview.windows):
            win.destroy()


original_start = webview.start
webview.start = lambda **kw: original_start(scenario, **kw)
sys.exit(desktop.run("window"))
