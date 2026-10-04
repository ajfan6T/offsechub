import pytest

from app.config import get_settings
from app.services.importers.parsers import ParseError, parse_list, parse_nmap_xml, parse_nuclei

from .conftest import SAMPLES


def _upload(api, eng, tool, filename, data, skip=True):
    return api.post(f"/api/engagements/{eng['id']}/imports/upload", content=data,
                    params={"tool": tool, "filename": filename, "skip_out_of_scope": str(skip).lower()})


def _import(api, eng, tool, filename, skip=True):
    r = _upload(api, eng, tool, filename, (SAMPLES / filename).read_bytes(), skip)
    assert r.status_code == 201, r.text
    return r.json()


def _targets(api, eng):
    return {t["value"]: t for t in api.ok("GET", f"/api/engagements/{eng['id']}/targets")}


def test_parse_nmap_sample():
    result = parse_nmap_xml((SAMPLES / "nmap-acme.xml").read_bytes())
    hosts = {h.value: h for h in result.hosts}
    assert "203.0.113.13" not in hosts  # host down
    www = hosts["203.0.113.10"]
    assert www.hostname == "www.acme-corp.example" and www.os == "Linux 5.4"
    assert [(s.port, s.product) for s in www.services] == [(22, "OpenSSH"), (80, "nginx"), (443, "nginx")]
    assert [s.state for s in hosts["203.0.113.11"].services] == ["open", "open|filtered"]


def test_nmap_import_enforces_scope(api, engagement):
    rec = _import(api, engagement, "nmap", "nmap-acme.xml")
    s = rec["stats"]
    assert s["targets_created"] == 2  # .10 and .12
    assert s["skipped_excluded"] == 1  # .11 VPN is explicitly excluded
    assert s["skipped_out_of_scope"] == 1  # 198.51.100.7
    assert s["services_created"] == 5
    targets = _targets(api, engagement)
    assert set(targets) == {"203.0.113.10", "203.0.113.12"}
    assert all(t["scope_status"] == "in_scope" and t["source"] == "nmap" for t in targets.values())
    # Raw output is preserved as evidence for traceability.
    ev = api.ok("GET", f"/api/engagements/{engagement['id']}/evidence")
    assert [e["id"] for e in ev] == [rec["evidence_id"]]


def test_reimport_is_idempotent(api, engagement):
    _import(api, engagement, "nmap", "nmap-acme.xml")
    second = _import(api, engagement, "nmap", "nmap-acme.xml")
    assert second["stats"]["targets_created"] == 0 and second["stats"]["services_created"] == 0


def test_out_of_scope_can_be_imported_but_is_flagged(api, engagement):
    _import(api, engagement, "nmap", "nmap-acme.xml", skip=False)
    targets = _targets(api, engagement)
    assert targets["198.51.100.7"]["scope_status"] == "out_of_scope"
    assert "203.0.113.11" not in targets  # exclusions are never imported


def test_nuclei_import_aggregates_findings(api, engagement):
    rec = _import(api, engagement, "nuclei", "nuclei-acme.jsonl")
    assert rec["stats"]["findings_created"] == 2
    assert rec["stats"]["skipped_out_of_scope"] == 1  # third-party host
    findings = {f["title"]: f for f in api.ok("GET", f"/api/engagements/{engagement['id']}/findings")}
    headers = findings["HTTP Missing Security Headers"]
    assert headers["status"] == "draft" and headers["source"] == "nuclei"
    assert sorted(t["value"] for t in headers["targets"]) == [
        "https://portal.acme-corp.example", "https://www.acme-corp.example"]
    assert "portal.acme-corp.example/login" in headers["steps_to_reproduce"]
    git = findings["Git Configuration - Detect"]
    assert git["cvss_score"] == 5.3 and git["severity"] == "medium" and git["cwe"] == "CWE-200"
    assert "Apache 2.4.49 - Path Traversal" not in findings

    again = _import(api, engagement, "nuclei", "nuclei-acme.jsonl")
    assert again["stats"]["findings_created"] == 0


def test_list_import(api, engagement):
    rec = _import(api, engagement, "list", "subdomains-acme.txt")
    assert rec["stats"]["errors"] == ["line 8: not a host, IP or URL: !!invalid-entry"]
    targets = _targets(api, engagement)
    assert "vpn.acme-corp.example" not in targets
    assert targets["https://portal.acme-corp.example"]["kind"] == "web"
    assert targets["api.acme-corp.example"]["kind"] == "domain"


def test_parse_list_handles_ips_and_urls():
    r = parse_list(b"10.0.0.1\nhttps://a.example.com/login\n# comment\n\nb.example.com 1.2.3.4\n")
    assert [(h.value, h.kind) for h in r.hosts] == [
        ("10.0.0.1", "host"), ("https://a.example.com/login", "web"), ("b.example.com", "domain")]


def test_xml_entity_expansion_is_rejected(api, engagement):
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>
<nmaprun><host><address addr="&lol2;" addrtype="ipv4"/></host></nmaprun>"""
    with pytest.raises(ParseError):
        parse_nmap_xml(bomb)
    assert _upload(api, engagement, "nmap", "bomb.xml", bomb).status_code == 422


def test_external_entities_are_rejected():
    xxe = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>"""
    with pytest.raises(ParseError):
        parse_nmap_xml(xxe)


def test_nuclei_json_array_and_bad_input():
    r = parse_nuclei(b'[{"template-id":"x","info":{"name":"X","severity":"weird"},"host":"10.0.0.1"}]')
    assert r.issues[0].severity == "info" and r.hosts[0].value == "10.0.0.1"
    with pytest.raises(ParseError):
        parse_nuclei(b"")


def test_wrong_tool_for_file(api, engagement):
    assert _upload(api, engagement, "nmap", "x.json", b'{"a": 1}').status_code == 422


def test_raw_output_is_kept_as_encrypted_evidence(api, engagement, vault):
    data = (SAMPLES / "nmap-acme.xml").read_bytes()
    rec = _import(api, engagement, "nmap", "nmap-acme.xml")
    base = f"/api/engagements/{engagement['id']}"
    assert api.get(f"{base}/evidence/{rec['evidence_id']}/download").content == data
    assert [i["id"] for i in api.ok("GET", f"{base}/imports")] == [rec["id"]]
    assert all(data not in p.read_bytes() for p in vault.path.rglob("*") if p.is_file())
    activity = api.ok("GET", f"{base}/activity")
    assert activity[0]["action"] == "import" and "2 new targets" in activity[0]["summary"]


def test_rejected_imports_leave_nothing_behind(api, engagement, vault):
    base = f"/api/engagements/{engagement['id']}"
    assert _upload(api, engagement, "nmap", "empty.xml", b"").status_code == 422
    assert _upload(api, engagement, "nmap", "bad.xml", b"<nmaprun>").status_code == 422
    assert _upload(api, engagement, "masscan", "x.txt", b"10.0.0.1").status_code == 422
    missing = {"id": 999}
    assert _upload(api, missing, "list", "x.txt", b"10.0.0.1").status_code == 404
    assert api.ok("GET", f"{base}/evidence") == [] and api.ok("GET", f"{base}/imports") == []
    assert vault.blob_ids_on_disk() == set()


def test_import_size_limit(api, engagement, vault):
    settings = get_settings()
    old, settings.max_upload_mb = settings.max_upload_mb, 1
    try:
        big = b"10.0.0.1\n" * (2**20 // 9 + 1)
        assert _upload(api, engagement, "list", "hosts.txt", big).status_code == 413
        chunked = iter([big[:2**19], big[2**19:]])  # no Content-Length: enforced while reading
        assert _upload(api, engagement, "list", "hosts.txt", chunked).status_code == 413
    finally:
        settings.max_upload_mb = old
    assert vault.blob_ids_on_disk() == set()


def test_import_filename_defaults_to_tool(api, engagement):
    r = api.post(f"/api/engagements/{engagement['id']}/imports/upload", params={"tool": "list"},
                 content=b"203.0.113.4\n")
    assert r.status_code == 201 and r.json()["filename"] == "list-output"


def test_parsers_tolerate_malformed_fields():
    """Tool output is attacker-influenced: odd field types become errors, never crashes."""
    r = parse_nuclei(b'{"template-id": null, "info": [null]}\n'
                     b'{"template-id": "x", "info": ["n"], "host": "http://[::1"}\n'
                     b'{"template-id": "y", "info": {"classification": 5}, "host": "10.0.0.2"}')
    assert r.errors == ["skipped record without template-id"]
    assert [i.key for i in r.issues] == ["nuclei:x", "nuclei:y"]

    r = parse_nmap_xml(b'<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                       b'<os><osmatch name="Linux" accuracy="9x"/></os><ports>'
                       b'<port portid="99999"><state state="open"/></port>'
                       b'<port portid="22"><state state="open"/></port></ports></host></nmaprun>')
    assert r.hosts[0].os == "Linux" and [s.port for s in r.hosts[0].services] == [22]
    assert r.errors == ["bad port id on host 10.0.0.1"]
