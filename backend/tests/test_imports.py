import pytest

from app.services.importers.parsers import ParseError, parse_list, parse_nmap_xml, parse_nuclei

from .conftest import SAMPLES


def _import(api, eng, tool, filename, content=None, skip=True, status=201):
    data = content if content is not None else (SAMPLES / filename).read_bytes()
    return api.ok("POST", f"/api/engagements/{eng['id']}/imports", status=status,
                  data={"tool": tool, "skip_out_of_scope": str(skip).lower()},
                  files={"file": (filename, data)})


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


def test_nmap_import_enforces_scope(admin, engagement):
    rec = _import(admin, engagement, "nmap", "nmap-acme.xml")
    s = rec["stats"]
    assert s["targets_created"] == 2  # .10 and .12
    assert s["skipped_excluded"] == 1  # .11 VPN is explicitly excluded
    assert s["skipped_out_of_scope"] == 1  # 198.51.100.7
    assert s["services_created"] == 5
    targets = _targets(admin, engagement)
    assert set(targets) == {"203.0.113.10", "203.0.113.12"}
    assert all(t["scope_status"] == "in_scope" and t["source"] == "nmap" for t in targets.values())
    # Raw output is preserved as evidence for traceability.
    ev = admin.ok("GET", f"/api/engagements/{engagement['id']}/evidence")
    assert [e["id"] for e in ev] == [rec["evidence_id"]]


def test_reimport_is_idempotent(admin, engagement):
    _import(admin, engagement, "nmap", "nmap-acme.xml")
    second = _import(admin, engagement, "nmap", "nmap-acme.xml")
    assert second["stats"]["targets_created"] == 0 and second["stats"]["services_created"] == 0


def test_out_of_scope_can_be_imported_but_is_flagged(admin, engagement):
    _import(admin, engagement, "nmap", "nmap-acme.xml", skip=False)
    targets = _targets(admin, engagement)
    assert targets["198.51.100.7"]["scope_status"] == "out_of_scope"
    assert "203.0.113.11" not in targets  # exclusions are never imported


def test_nuclei_import_aggregates_findings(admin, engagement):
    rec = _import(admin, engagement, "nuclei", "nuclei-acme.jsonl")
    assert rec["stats"]["findings_created"] == 2
    assert rec["stats"]["skipped_out_of_scope"] == 1  # third-party host
    findings = {f["title"]: f for f in admin.ok("GET", f"/api/engagements/{engagement['id']}/findings")}
    headers = findings["HTTP Missing Security Headers"]
    assert headers["status"] == "draft" and headers["source"] == "nuclei"
    assert sorted(t["value"] for t in headers["targets"]) == [
        "https://portal.acme-corp.example", "https://www.acme-corp.example"]
    assert "portal.acme-corp.example/login" in headers["steps_to_reproduce"]
    git = findings["Git Configuration - Detect"]
    assert git["cvss_score"] == 5.3 and git["severity"] == "medium" and git["cwe"] == "CWE-200"
    assert "Apache 2.4.49 - Path Traversal" not in findings

    again = _import(admin, engagement, "nuclei", "nuclei-acme.jsonl")
    assert again["stats"]["findings_created"] == 0


def test_list_import(admin, engagement):
    rec = _import(admin, engagement, "list", "subdomains-acme.txt")
    assert rec["stats"]["errors"] == ["line 8: not a host, IP or URL: !!invalid-entry"]
    targets = _targets(admin, engagement)
    assert "vpn.acme-corp.example" not in targets
    assert targets["https://portal.acme-corp.example"]["kind"] == "web"
    assert targets["api.acme-corp.example"]["kind"] == "domain"


def test_parse_list_handles_ips_and_urls():
    r = parse_list(b"10.0.0.1\nhttps://a.example.com/login\n# comment\n\nb.example.com 1.2.3.4\n")
    assert [(h.value, h.kind) for h in r.hosts] == [
        ("10.0.0.1", "host"), ("https://a.example.com/login", "web"), ("b.example.com", "domain")]


def test_xml_entity_expansion_is_rejected(admin, engagement):
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>
<nmaprun><host><address addr="&lol2;" addrtype="ipv4"/></host></nmaprun>"""
    with pytest.raises(ParseError):
        parse_nmap_xml(bomb)
    r = admin.post(f"/api/engagements/{engagement['id']}/imports",
                   data={"tool": "nmap"}, files={"file": ("bomb.xml", bomb)})
    assert r.status_code == 422


def test_external_entities_are_rejected():
    xxe = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>"""
    with pytest.raises(ParseError):
        parse_nmap_xml(xxe)


def test_nuclei_json_array_and_bad_input():
    r = parse_nuclei(b'[{"template-id":"x","info":{"name":"X","severity":"weird"},"host":"10.0.0.1"}]')
    assert r.issues[0].severity == "info" and r.hosts[0].value == "10.0.0.1"
    with pytest.raises(ParseError):
        parse_nuclei(b"")


def test_wrong_tool_for_file(admin, engagement):
    r = admin.post(f"/api/engagements/{engagement['id']}/imports",
                   data={"tool": "nmap"}, files={"file": ("x.json", b'{"a": 1}')})
    assert r.status_code == 422
