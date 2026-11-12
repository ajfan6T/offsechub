"""Engagement hand-off files: export, import, and what a hostile file cannot do."""

import io
import struct
from pathlib import Path

import pytest
from PIL import Image

from app.services import handoff
from app.vault import header as vault_header
from app.vault.crypto import Argon2Params

from .conftest import PASSWORD, SAMPLES

PASSPHRASE = "share this out of band"


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (64, 32), (200, 30, 30)).save(buf, "PNG")
    return buf.getvalue()


@pytest.fixture
def full_engagement(api, engagement):
    base = f"/api/engagements/{engagement['id']}"
    api.ok("POST", f"{base}/imports/upload?tool=nmap&filename=nmap-acme.xml",
           content=(SAMPLES / "nmap-acme.xml").read_bytes(), headers={"Content-Type": "application/xml"})
    targets = api.ok("GET", f"{base}/targets")
    t = next(x for x in targets if x["services"])
    f = api.ok("POST", f"{base}/findings", json={
        "title": "Weak TLS", "status": "reported", "target_ids": [t["id"]], "description": "**TLS 1.0**",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"})
    api.ok("POST", f"{base}/findings/{f['id']}/retests", json={"tested_on": "2026-10-01", "result": "not_resolved"})
    api.ok("POST", f"{base}/evidence/upload?filename=shot.png&finding_id={f['id']}",
           content=_png(), headers={"Content-Type": "image/png"})
    tc = api.ok("POST", f"{base}/tests", json={"title": "Check TLS", "finding_id": f["id"], "target_id": t["id"]})
    api.ok("POST", f"{base}/evidence/text", json={"filename": "notes.txt", "content": "testssl output",
                                                  "test_case_id": tc["id"]})
    api.ok("POST", f"{base}/oplog", json={"tool": "nmap", "command": "nmap -sV 203.0.113.0/28", "outcome": "success"})
    return base


def _export(api, base, tmp_path, passphrase=PASSPHRASE, **kw):
    return api.ok("POST", f"{base}/handoff", 200, json={"directory": str(tmp_path), "passphrase": passphrase, **kw})


def _import(api, data: bytes, passphrase=PASSPHRASE):
    return api.post("/api/handoff/import", content=data,
                    headers={"Content-Type": "application/octet-stream", "X-Handoff-Passphrase": passphrase})


def _snapshot(api, base):
    """Everything an engagement holds, without ids that change on import."""
    findings = api.ok("GET", f"{base}/findings")
    evidence = api.ok("GET", f"{base}/evidence")
    return {
        "scope": sorted((s["value"], s["rule"]) for s in api.ok("GET", f"{base}/scope")),
        "targets": sorted((t["value"], len(t["services"])) for t in api.ok("GET", f"{base}/targets")),
        "findings": [(f["ref"].split("-")[-1], f["title"], f["cvss_vector"], f["cvss_score"], f["status"],
                      [t["value"] for t in f["targets"]], [r["result"] for r in f["retests"]]) for f in findings],
        "evidence": sorted((e["filename"], e["sha256"], e["size"], e["finding_id"] is not None,
                            e["test_case_id"] is not None) for e in evidence),
        "bytes": sorted(api.get(f"{base}/evidence/{e['id']}/download").content for e in evidence),
        "tests": sorted((t["title"], t["finding_id"] is not None) for t in api.ok("GET", f"{base}/tests")),
        "oplog": [o["command"] for o in api.ok("GET", f"{base}/oplog")],
        "imports": [(i["tool"], i["evidence_id"] is not None) for i in api.ok("GET", f"{base}/imports")],
    }


def test_round_trip_into_another_vault(api, full_engagement, tmp_path):
    before = _snapshot(api, full_engagement)
    out = _export(api, full_engagement, tmp_path)
    path = Path(out["path"])
    assert path.name == "ACME-EXT.ohengagement" and out["evidence_files"] == 3 and out["findings"] == 1
    data = path.read_bytes()
    assert data[:4] == b"OHEX" and b"Weak TLS" not in data and b"testssl" not in data  # encrypted

    api.ok("POST", "/api/vault/create", json={"path": str(tmp_path / "other"), "password": PASSWORD})
    r = _import(api, data)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["code"] == "ACME-EXT" and body["renamed"] is False
    assert _snapshot(api, f"/api/engagements/{body['engagement_id']}") == before
    clients = api.ok("GET", "/api/clients")
    assert [c["name"] for c in clients] == ["ACME"]


def test_import_into_the_same_vault_renames_the_code(api, full_engagement, tmp_path):
    data = Path(_export(api, full_engagement, tmp_path)["path"]).read_bytes()
    body = _import(api, data).json()
    assert body["code"] == "ACME-EXT-2" and body["renamed"] is True
    assert len(api.ok("GET", "/api/clients")) == 1  # reuses the existing client
    acts = api.ok("GET", f"/api/engagements/{body['engagement_id']}/activity")
    assert any("hand-off" in a["summary"] for a in acts)


def test_wrong_passphrase_tampering_and_truncation(api, full_engagement, tmp_path):
    data = Path(_export(api, full_engagement, tmp_path)["path"]).read_bytes()
    count = len(api.ok("GET", "/api/engagements"))
    r = _import(api, data, "not the passphrase at all")
    assert r.status_code == 400 and "passphrase is wrong" in r.json()["detail"]
    for broken in (data[:-1], data[:200], data[:handoff.HEADER_LEN + 10],
                   data[:300] + bytes([data[300] ^ 1]) + data[301:]):
        r = _import(api, broken)
        assert r.status_code == 400, r.text
    assert _import(api, b"PK\x03\x04 not ours").status_code == 400
    assert len(api.ok("GET", "/api/engagements")) == count  # nothing was imported


def test_hostile_kdf_settings_are_refused_before_argon2(api):
    header = struct.pack(">4sBIBB32sI", b"OHEX", 1, 4 * 1024 * 1024 + 1, 3, 4, b"\0" * 32, 65536)
    r = _import(api, header + b"\0" * 100)
    assert r.status_code == 400 and "unsupported key settings" in r.json()["detail"]
    future = struct.pack(">4sBIBB32sI", b"OHEX", 2, 19456, 2, 1, b"\0" * 32, 65536)
    assert "newer version" in _import(api, future + b"\0" * 100).json()["detail"]


def _forged(app_ctx, tmp_path, manifest: dict, blobs=()) -> bytes:
    _app, manager, _auth = app_ctx
    dest = tmp_path / "forged.ohengagement"
    handoff.write_handoff(manager.require(), manifest, list(blobs), PASSPHRASE, dest,
                          vault_header.DEFAULT_ARGON2)
    return dest.read_bytes()


def test_invalid_contents_are_refused(api, app_ctx, full_engagement, tmp_path):
    _app, manager, _auth = app_ctx
    with manager.require().session() as db:
        from app.models import Engagement
        manifest, blobs = handoff.build_manifest(db.get(Engagement, int(full_engagement.rsplit("/", 1)[1])))
        db.rollback()
    bad = {**manifest, "findings": [{**manifest["findings"][0], "status": "pwned"}]}
    r = _import(api, _forged(app_ctx, tmp_path, bad, blobs))
    assert r.status_code == 400 and "not valid" in r.json()["detail"]

    (tmp_path / "forged.ohengagement").unlink()
    wrong_hash = {**manifest, "evidence": [{**manifest["evidence"][0], "sha256": "0" * 64}, *manifest["evidence"][1:]]}
    r = _import(api, _forged(app_ctx, tmp_path, wrong_hash, blobs))
    assert r.status_code == 400 and "does not match its fingerprint" in r.json()["detail"]

    (tmp_path / "forged.ohengagement").unlink()
    dangling = {**manifest, "findings": [{**manifest["findings"][0], "targets": [999999]}]}
    r = _import(api, _forged(app_ctx, tmp_path, dangling, blobs))
    assert r.status_code == 400 and "does not contain" in r.json()["detail"]


def test_export_checks(api, full_engagement, tmp_path):
    r = api.post(f"{full_engagement}/handoff", json={"directory": str(tmp_path), "passphrase": "short"})
    assert r.status_code == 400 and "at least 12" in r.json()["detail"]
    _export(api, full_engagement, tmp_path)
    r = api.post(f"{full_engagement}/handoff", json={"directory": str(tmp_path), "passphrase": PASSPHRASE})
    assert r.status_code == 400 and "already exists" in r.json()["detail"]
    r = api.post(f"{full_engagement}/handoff", json={"directory": str(tmp_path / "missing"), "passphrase": PASSPHRASE})
    assert r.status_code == 400 and "does not exist" in r.json()["detail"]
    out = _export(api, full_engagement, tmp_path, filename="../../escape")
    assert Path(out["path"]).parent == tmp_path and Path(out["path"]).name == "escape.ohengagement"
    assert not list(tmp_path.glob(".*.tmp"))


def test_params_validation_matches_the_vault():
    with pytest.raises(Exception):
        Argon2Params(m_kib=1, t=1, p=1).validate()
