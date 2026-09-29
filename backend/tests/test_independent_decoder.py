"""The spec-only decoder in tools/ can read a vault written by the application."""

import importlib.util
import sqlite3
from pathlib import Path

from app.bootstrap import make_unlock_hook
from app.models import Client, Engagement, Evidence
from app.vault.appconfig import AppConfig
from app.vault.manager import VaultManager

TOOL = Path(__file__).resolve().parents[2] / "tools" / "ohvault_decrypt.py"
PW = "correct horse battery staple"


def load_tool():
    spec = importlib.util.spec_from_file_location("ohvault_decrypt", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_decoder_reads_app_written_vault(tmp_path):
    m = VaultManager(AppConfig(tmp_path / "cfg"))
    m.on_unlock(make_unlock_hook(m))
    try:
        m.create(tmp_path / "acme", PW)
        v = m.require()
        bid, key, sha, size = v.write_blob(b"PNG-ish screenshot bytes" * 5000)
        with v.session() as s:
            c = Client(name="ACME Corp")
            s.add(c)
            s.flush()
            e = Engagement(client_id=c.id, name="Ext", code="ACME-EXT", type="api")
            s.add(e)
            s.flush()
            s.add(Evidence(engagement_id=e.id, filename="shot.png", content_type="image/png", size=size,
                           sha256=sha, storage_key=bid, blob_key=key))
            s.commit()
        path = v.path
        m.lock()
    finally:
        m.shutdown()

    tool = load_tool()
    out = tmp_path / "out"
    assert tool.main([str(path), str(out), "--evidence", "--password", PW]) == 0
    conn = sqlite3.connect(out / "offsechub.sqlite")
    assert conn.execute("SELECT name FROM clients").fetchall() == [("ACME Corp",)]
    files = list((out / "evidence").iterdir())
    assert len(files) == 1 and files[0].read_bytes() == b"PNG-ish screenshot bytes" * 5000
    assert tool.main([str(path), str(tmp_path / "x"), "--password", "wrong password!"]) == 1
