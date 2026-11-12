"""Engagement hand-off files: export, import, and what a hostile file cannot do."""

import hashlib
import io
import json
import math
import struct
import types
from itertools import zip_longest
from pathlib import Path
from typing import Literal, Union, get_args, get_origin

import pytest
from PIL import Image
from sqlalchemy.exc import IntegrityError

from app import schemas
from app.models import Engagement
from app.services import handoff
from app.vault import header as vault_header
from app.vault.crypto import Argon2Params

from .conftest import PASSWORD, SAMPLES, wait_until

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
    dest.unlink(missing_ok=True)
    handoff.write_handoff(manager.require(), manifest, list(blobs), PASSPHRASE, dest,
                          vault_header.DEFAULT_ARGON2)
    return dest.read_bytes()


def _manifest(app_ctx, base: str) -> tuple[dict, list]:
    """The manifest dict and blob references an export of ``base`` would write."""
    with app_ctx[1].require().session() as db:
        manifest, blobs = handoff.build_manifest(db.get(Engagement, int(base.rsplit("/", 1)[1])))
        db.rollback()
    return json.loads(json.dumps(manifest)), blobs  # a deep copy, as the file would carry it


def _nothing_added(api, vault, engagements: int, blobs: set[str]) -> None:
    """No engagement was added, and every blob the import wrote is gone again."""
    assert len(api.ok("GET", "/api/engagements")) == engagements
    assert api.ok("POST", "/api/vault/verify", 200)["orphaned_files"] == 0
    assert wait_until(lambda: vault.blob_ids_on_disk() == blobs)


def test_invalid_contents_are_refused(api, app_ctx, full_engagement, tmp_path):
    manifest, blobs = _manifest(app_ctx, full_engagement)
    bad = {**manifest, "findings": [{**manifest["findings"][0], "status": "pwned"}]}
    r = _import(api, _forged(app_ctx, tmp_path, bad, blobs))
    assert r.status_code == 400 and "not valid" in r.json()["detail"]

    wrong_hash = {**manifest, "evidence": [{**manifest["evidence"][0], "sha256": "0" * 64}, *manifest["evidence"][1:]]}
    r = _import(api, _forged(app_ctx, tmp_path, wrong_hash, blobs))
    assert r.status_code == 400 and "does not match its fingerprint" in r.json()["detail"]

    dangling = {**manifest, "findings": [{**manifest["findings"][0], "targets": [999999]}]}
    r = _import(api, _forged(app_ctx, tmp_path, dangling, blobs))
    assert r.status_code == 400 and "does not contain" in r.json()["detail"]


def _duplicate(manifest: dict, blobs: list, key: str) -> list:
    """Repeat the first record of ``manifest[key]`` under the same id; returns the matching blobs."""
    first = manifest[key][0]
    other = {"targets": {"value": "198.51.100.77", "services": []}, "findings": {"number": 99, "targets": []},
             "test_cases": {"title": "Another check"}, "evidence": {}}[key]
    manifest[key].insert(1, {**first, **other})
    return [blobs[0], *blobs] if key == "evidence" else blobs  # the repeated file's bytes follow it too


def test_duplicate_ids_are_refused(api, app_ctx, vault, full_engagement, tmp_path):
    engagements, on_disk = len(api.ok("GET", "/api/engagements")), vault.blob_ids_on_disk()
    for key, what in [("evidence", "evidence id"), ("targets", "target id"), ("findings", "finding id"),
                      ("test_cases", "test case id")]:
        manifest, blobs = _manifest(app_ctx, full_engagement)
        data = _forged(app_ctx, tmp_path, manifest, _duplicate(manifest, blobs, key))
        r = _import(api, data)
        assert r.status_code == 400, (key, r.text)
        assert f"{what} {manifest[key][0]['id']} appears more than once" in r.json()["detail"], key
        _nothing_added(api, vault, engagements, on_disk)


def test_dangling_references_are_refused(api, app_ctx, full_engagement, tmp_path):
    engagements = len(api.ok("GET", "/api/engagements"))
    for record, link in [("findings", "targets"), ("test_cases", "target"), ("test_cases", "finding"),
                         ("evidence", "finding"), ("evidence", "target"), ("evidence", "test_case"),
                         ("imports", "evidence")]:
        manifest, blobs = _manifest(app_ctx, full_engagement)
        manifest[record][0][link] = [424242] if link == "targets" else 424242
        r = _import(api, _forged(app_ctx, tmp_path, manifest, blobs))
        assert r.status_code == 400, (record, link, r.text)
        what = link.replace("_", " ").removesuffix("s")
        assert f"refers to {what} 424242, which the file does not contain" in r.json()["detail"], (record, link)
    assert len(api.ok("GET", "/api/engagements")) == engagements


def _with_service(m: dict) -> dict:
    return next(t for t in m["targets"] if t["services"])


# Values the API refuses, or that a page could not show; each must fail validation with a 400.
INVALID = {
    "targets.0.kind": lambda m: m["targets"][0].update(kind="evil"),
    "engagement.code": lambda m: m["engagement"].update(code="ACME—Ω"),
    "engagement: end_date is before": lambda m: m["engagement"].update(start_date="2026-09-30",
                                                                       end_date="2026-09-01"),
    "invalid ip scope value": lambda m: m["scope"][0].update(kind="ip", value="not-an-ip"),
    "invalid CVSS vector": lambda m: m["findings"][0].update(cvss_vector="CVSS:3.1/AV:N"),
    "findings.0.retests.0.result": lambda m: m["findings"][0]["retests"][0].update(result="fixed"),
    "findings.0.title": lambda m: m["findings"][0].update(title="T" * 256),
    "test_cases.0.status": lambda m: m["test_cases"][0].update(status="done"),
    "oplog.0.outcome": lambda m: m["oplog"][0].update(outcome="pwned"),
    "imports.0.tool": lambda m: m["imports"][0].update(tool="metasploit"),
    "imports.0.stats.errors": lambda m: m["imports"][0]["stats"].update(errors="not a list"),
    "imports.0.stats.hosts_seen": lambda m: m["imports"][0]["stats"].update(hosts_seen=-1),
    "target value": lambda m: m["targets"].append({**m["targets"][0], "id": 424242, "services": []}),
    "finding number": lambda m: m["findings"].append({**m["findings"][0], "id": 424242, "targets": []}),
    "service": lambda m: _with_service(m)["services"].append(_with_service(m)["services"][0]),
}


def test_values_the_app_refuses_are_refused(api, app_ctx, full_engagement, tmp_path):
    engagements = len(api.ok("GET", "/api/engagements"))
    for expected, spoil in INVALID.items():
        manifest, blobs = _manifest(app_ctx, full_engagement)
        spoil(manifest)
        r = _import(api, _forged(app_ctx, tmp_path, manifest, blobs))
        assert r.status_code == 400, (expected, r.text)
        assert "not valid" in r.json()["detail"] and expected in r.json()["detail"], (expected, r.text)
    assert len(api.ok("GET", "/api/engagements")) == engagements


def test_import_stats_get_the_shape_the_recon_page_reads(api, app_ctx, full_engagement, tmp_path):
    recorded = api.ok("GET", f"{full_engagement}/imports")[0]["stats"]
    manifest, blobs = _manifest(app_ctx, full_engagement)
    manifest["imports"][0]["stats"] = {"hosts_seen": 3, "surprise": {"nested": True}}
    manifest["engagement"]["code"] = " acme-ho "  # normalised as the API does
    body = _import(api, _forged(app_ctx, tmp_path, manifest, blobs)).json()
    assert body["code"] == "ACME-HO"
    stats = api.ok("GET", f"/api/engagements/{body['engagement_id']}/imports")[0]["stats"]
    assert set(stats) == set(recorded)  # every count a real import records, and nothing else
    assert stats["hosts_seen"] == 3 and stats["errors"] == [] and stats["targets_created"] == 0


def test_a_failure_while_adding_records_leaves_nothing_behind(api, app_ctx, full_engagement, tmp_path,
                                                              monkeypatch):
    data = Path(_export(api, full_engagement, tmp_path)["path"]).read_bytes()
    api.ok("POST", "/api/vault/create", json={"path": str(tmp_path / "other"), "password": PASSWORD})
    vault = app_ctx[1].require()
    for error, status in [(ValueError("unexpected"), 400),
                          (IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed")), 400),
                          (RuntimeError("a bug, not the file"), None)]:
        def fail(*_args, _error=error, **_kw):
            raise _error

        # Recording the import is apply_manifest's last step, after every record and blob row is flushed.
        monkeypatch.setattr(handoff.audit, "record", fail)
        if status:  # a data problem: a 400 that names no internals
            r = _import(api, data)
            assert r.status_code == 400 and r.json()["detail"] == "the file's contents could not be imported"
        else:  # anything else is still a server error, but cleans up the same way
            with pytest.raises(RuntimeError):
                _import(api, data)
        monkeypatch.undo()
        _nothing_added(api, vault, 0, set())
        assert api.ok("GET", "/api/clients") == []


# ---------------------------------------------------------------- edge values

LONG = "L" * 5000
V31_LONG = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:" + "Z" * 600  # optional values aren't checked
V40_FULL = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/"
            "MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Amber")
NMAP_IP_PROTOCOL = (b'<nmaprun><host><status state="up"/><address addr="203.0.113.5" addrtype="ipv4"/>'
                    b'<ports><port protocol="ip" portid="6"><state state="open"/><service name="tcp"/>'
                    b'</port></ports></host></nmaprun>')
SAMPLE_FOR = {"nmap": "nmap-acme.xml", "nuclei": "nuclei-acme.jsonl", "list": "subdomains-acme.txt",
              "burp": "burp-acme.xml", "nessus": "nessus-acme.nessus"}


def _fill(n: int, prefix: str) -> str:
    return (prefix + "x" * n)[:n]


@pytest.fixture
def edge_engagement(api):
    """An engagement holding the largest and oddest values the API and the importers accept."""
    client = api.ok("POST", "/api/clients", json={"name": _fill(255, "Client "), "industry": LONG,
                                                  "contact_name": LONG, "contact_email": LONG, "notes": LONG})
    eng = api.ok("POST", "/api/engagements", json={
        "client_id": client["id"], "name": _fill(255, "Edge "), "code": "E" * 32, "type": "web_application",
        "start_date": "2026-09-01", "end_date": "2026-09-01", "description": LONG, "rules_of_engagement": LONG})
    base = f"/api/engagements/{eng['id']}"
    api.ok("PATCH", base, json={"status": "review", "executive_summary": LONG})
    for kind, value, rule in [
        ("ip", "203.0.113.5", "include"), ("cidr", "198.51.100.0/24", "include"),
        ("range", "192.0.2.1-192.0.2.9", "exclude"), ("domain", "example.com", "include"),
        ("wildcard", "*.example.com", "include"), ("other", _fill(512, "acct-"), "include"),
        ("url", "https://" + "a" * 496 + ".example", "exclude"),  # 512 characters; stored with a "/" more
    ]:
        api.ok("POST", f"{base}/scope", json={"kind": kind, "value": value, "rule": rule, "notes": LONG})

    targets = []
    for kind, status in zip_longest(get_args(schemas.TargetKind), get_args(schemas.TargetStatus), fillvalue="new"):
        targets.append(api.ok("POST", f"{base}/targets", json={
            "kind": kind, "status": status, "value": _fill(512, f"{kind}.example.com/"), "hostname": LONG,
            "ip": LONG, "os": LONG, "notes": LONG, "tags": [_fill(50, f"tag{i}-") for i in range(300)]}))
    targets.append(api.ok("POST", f"{base}/targets", json={"value": " "}))  # stored as ""
    targets.append(api.ok("POST", f"{base}/targets", json={"value": "203.0.113.5"}))
    for port, protocol in [(0, "tcp"), (65535, "udp"), (132, "sctp")]:
        api.ok("POST", f"{base}/targets/{targets[0]['id']}/services", json={
            "port": port, "protocol": protocol, "state": LONG, "name": LONG, "product": LONG, "version": LONG,
            "extra_info": LONG})

    findings = []
    severities = get_args(schemas.Severity)
    for i, status in enumerate(get_args(schemas.FindingStatus)):
        findings.append(api.ok("POST", f"{base}/findings", json={
            "title": _fill(255, f"Finding {i} "), "severity": severities[i % len(severities)], "status": status,
            "cvss_vector": [V31_LONG, V40_FULL, ""][i % 3],
            "cwe": "CWE-79: Cross-site Scripting" if i else "CWE-" + "9" * 2000,
            "description": LONG, "impact": LONG, "steps_to_reproduce": LONG, "remediation": LONG,
            "references": LONG, "target_ids": [t["id"] for t in targets] if i == 0 else []}))
    for result in get_args(schemas.RetestResult):  # on the draft finding, so its status stays
        api.ok("POST", f"{base}/findings/{findings[0]['id']}/retests", json={
            "tested_on": "2026-09-02", "result": result, "tester": _fill(255, "Tester "), "notes": LONG})

    tests = []
    for i, status in enumerate(get_args(schemas.TestStatus)):
        tests.append(api.ok("POST", f"{base}/tests", json={
            "methodology": _fill(2000, "m"), "ref": _fill(2000, f"r{i}"), "category": _fill(2000, "c"),
            "title": _fill(255, f"Test {i} "), "description": LONG, "status": status, "notes": LONG,
            "target_id": targets[i]["id"] if i % 2 else None, "finding_id": findings[i]["id"] if i % 3 else None}))
    for i, outcome in enumerate(get_args(schemas.OplogOutcome)):
        api.ok("POST", f"{base}/oplog", json={
            "occurred_at": f"2026-09-0{i + 1}T10:00:00Z", "operator": _fill(255, "Operator "), "outcome": outcome,
            "source_host": LONG, "target": LONG, "tool": LONG, "command": LONG, "description": LONG})

    api.ok("POST", f"{base}/evidence/upload?filename=shot.png&finding_id={findings[1]['id']}",
           content=_png(), headers={"Content-Type": "image/png"})
    api.ok("POST", f"{base}/evidence/text", json={
        "filename": _fill(251, "n") + ".txt", "content": "transcript", "description": LONG,
        "target_id": targets[1]["id"], "test_case_id": tests[0]["id"]})

    imports = [(tool, (SAMPLES / name).read_bytes()) for tool, name in SAMPLE_FOR.items()]
    imports += [("nmap", NMAP_IP_PROTOCOL),  # a protocol the API's ServiceIn would not take
                ("list", b"https://www.example.com/" + b"p" * 600 + b"\n!!not a host!!\n")]  # a long value, an error
    assert {tool for tool, _ in imports} == set(get_args(schemas.ImportTool))
    for tool, data in imports:
        api.ok("POST", f"{base}/imports/upload?tool={tool}&skip_out_of_scope=false", content=data,
               headers={"Content-Type": "application/octet-stream"})
    return base


def _everything(api, base: str) -> dict:
    """All the engagement's pages show, with ids and creation times left out and links named."""
    targets = api.ok("GET", f"{base}/targets")
    findings = api.ok("GET", f"{base}/findings")
    tests = api.ok("GET", f"{base}/tests")
    evidence = api.ok("GET", f"{base}/evidence")
    names = {"target_id": {t["id"]: t["value"] for t in targets},
             "finding_id": {f["id"]: f["number"] for f in findings},
             "test_case_id": {t["id"]: t["ref"] for t in tests},
             "evidence_id": {e["id"]: e["sha256"] for e in evidence}}

    def plain(x):
        if isinstance(x, dict):
            return {k: names[k].get(v) if k in names else plain(v) for k, v in x.items()
                    if k not in ("id", "created_at", "updated_at")}
        if isinstance(x, list):
            return sorted((plain(v) for v in x), key=lambda v: json.dumps(v, sort_keys=True))
        return x

    eng = api.ok("GET", base)
    return plain({
        "engagement": eng, "summary": api.ok("GET", f"{base}/summary"),
        "client": next(c for c in api.ok("GET", "/api/clients") if c["id"] == eng["client"]["id"]),
        "scope": api.ok("GET", f"{base}/scope"), "targets": targets, "findings": findings, "tests": tests,
        "oplog": api.ok("GET", f"{base}/oplog"), "evidence": evidence, "imports": api.ok("GET", f"{base}/imports"),
        "bytes": [hashlib.sha256(api.get(f"{base}/evidence/{e['id']}/download").content).hexdigest()
                  for e in evidence],
    })


def test_edge_values_round_trip(api, app_ctx, edge_engagement, tmp_path):
    before = _everything(api, edge_engagement)
    assert any(len(f["cwe"]) > 20 for f in before["findings"])
    values = [t["value"] for t in before["targets"]]
    assert "" in values and max(map(len, values)) > 512
    assert any(s["protocol"] == "ip" for t in before["targets"] for s in t["services"])
    assert any(i["stats"]["errors"] for i in before["imports"])
    assert max(len(s["value"]) for s in before["scope"]) == 513

    # One engagement has one type and status: the others are checked against the manifest model.
    engagement = _manifest(app_ctx, edge_engagement)[0]["engagement"]
    for field, choices in (("type", schemas.EngagementType), ("status", schemas.EngagementStatus)):
        for value in get_args(choices):
            handoff._Engagement.model_validate({**engagement, field: value})

    data = Path(_export(api, edge_engagement, tmp_path)["path"]).read_bytes()
    api.ok("POST", "/api/vault/create", json={"path": str(tmp_path / "other"), "password": PASSWORD})
    r = _import(api, data)
    assert r.status_code == 201, r.text
    assert r.json()["renamed"] is False
    assert _everything(api, f"/api/engagements/{r.json()['engagement_id']}") == before


# The API's input models and the manifest's models for the same records (API field -> manifest field).
COUNTERPARTS = [
    (schemas.ClientIn, handoff._Client, {}), (schemas.EngagementCreate, handoff._Engagement, {}),
    (schemas.EngagementUpdate, handoff._Engagement, {}), (schemas.ScopeItemIn, handoff._Scope, {}),
    (schemas.TargetIn, handoff._Target, {}), (schemas.TargetUpdate, handoff._Target, {}),
    (schemas.ServiceIn, handoff._Service, {}), (schemas.FindingIn, handoff._Finding, {"target_ids": "targets"}),
    (schemas.FindingUpdate, handoff._Finding, {"target_ids": "targets"}), (schemas.RetestIn, handoff._Retest, {}),
    (schemas.TestCaseIn, handoff._TestCase, {"target_id": "target", "finding_id": "finding"}),
    (schemas.OplogIn, handoff._Oplog, {}),
    (schemas.EvidenceTextIn, handoff._Evidence, {"finding_id": "finding", "target_id": "target",
                                                 "test_case_id": "test_case"}),
]


def _lengths(model, name: str) -> tuple[float, float]:
    meta = model.model_fields[name].metadata
    low = next((m.min_length for m in meta if hasattr(m, "min_length")), 0)
    high = next((m.max_length for m in meta if hasattr(m, "max_length")), None)
    return low, high or model.model_config.get("str_max_length") or math.inf


def _required_type(annotation):
    if get_origin(annotation) in (Union, types.UnionType):
        rest = [a for a in get_args(annotation) if a is not type(None)]
        return rest[0] if len(rest) == 1 else annotation
    return annotation


@pytest.mark.parametrize("api_model, ours, renamed", COUNTERPARTS, ids=[c[0].__name__ for c in COUNTERPARTS])
def test_the_manifest_is_never_stricter_than_the_api(api_model, ours, renamed):
    for name, field in api_model.model_fields.items():
        mine = renamed.get(name, name)
        if mine not in ours.model_fields:
            continue  # not carried in a hand-off file (client_id, template_id, content)
        theirs, own = _required_type(field.annotation), _required_type(ours.model_fields[mine].annotation)
        assert own == theirs or (own is str and get_origin(theirs) is Literal), name
        (api_low, api_high), (low, high) = _lengths(api_model, name), _lengths(ours, mine)
        assert low <= api_low and high >= min(api_high, handoff.MAX_TEXT), name


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
