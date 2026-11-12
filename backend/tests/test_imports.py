import base64
import re
from html.parser import HTMLParser

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.config import get_settings
from app.services import richtext
from app.services.importers.burp import parse_burp_xml
from app.services.importers.htmltext import (
    code_block,
    html_links,
    html_to_markdown,
    inline_code,
    safe_url,
    text_to_markdown,
)
from app.services.importers.nessus import parse_nessus
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


# ------------------------------------------------------------- Burp Suite


def _burp(*issues: str) -> bytes:
    return ('<?xml version="1.0"?><issues burpVersion="2026.8.2">' + "".join(issues) + "</issues>").encode()


def _burp_issue(*, type_="2097920", name="Cross-site scripting (reflected)", severity="High",
                host="https://www.acme-corp.example", ip="203.0.113.10", path="/", extra="") -> str:
    return (f"<issue><serialNumber>1</serialNumber><type>{type_}</type><name>{name}</name>"
            f'<host ip="{ip}">{host}</host><path>{path}</path><location>{path}</location>'
            f"<severity>{severity}</severity><confidence>Firm</confidence>{extra}</issue>")


def _b64_request(raw: bytes) -> str:
    return (f'<requestresponse><request method="GET" base64="true">{base64.b64encode(raw).decode()}'
            f"</request></requestresponse>")


def _code_blocks(text: str) -> list[str]:
    return [b.text for b in richtext.parse(text) if b.kind == "code"]


def test_parse_burp_sample():
    result = parse_burp_xml((SAMPLES / "burp-acme.xml").read_bytes())
    assert result.errors == []
    issues = {(i.key, i.matched_at): i for i in result.issues}
    assert len(issues) == 7

    xss = issues[("burp:2097920", "https://portal.acme-corp.example/search")]
    assert (xss.title, xss.severity, xss.cwe, xss.cvss_vector) == (
        "Cross-site scripting (reflected)", "high", "CWE-79", "")
    host = xss.host
    assert (host.kind, host.value, host.hostname, host.ip) == (
        "web", "https://portal.acme-corp.example", "portal.acme-corp.example", "203.0.113.14")
    # Background, then detail; HTML entities become text, inside bold.
    assert xss.description.startswith("Reflected cross-site scripting arises when")
    assert "The payload **abc<script>alert(1)</script>xyz** was submitted" in xss.description
    assert xss.description.endswith("Burp Suite confidence: Certain.")
    assert "\n- HTML-encode user input wherever" in xss.remediation
    assert "*search term*" in xss.remediation
    assert xss.references[0] == "https://portswigger.net/web-security/cross-site-scripting"
    assert "https://cwe.mitre.org/data/definitions/79.html" in xss.references
    assert "https://capec.mitre.org/data/definitions/591.html" in xss.references
    # The base64 request is decoded into a fenced block, CRLF normalised.
    assert xss.reproduction.startswith(
        "Matched at: `https://portal.acme-corp.example/search`\nLocation: `/search [q parameter]`\n\n```http\n")
    [request] = _code_blocks(xss.reproduction)
    assert request.startswith("GET /search?q=abc%3cscript%3ealert(1)%3c%2fscript%3exyz&lang=en HTTP/2\n"
                              "Host: portal.acme-corp.example\n")
    assert "\r" not in request

    hsts = issues[("burp:16777984", "https://www.acme-corp.example/")]
    assert hsts.severity == "low" and hsts.cwe == "CWE-523"
    assert "`Strict-Transport-Security: max-age=31536000; includeSubDomains`" in hsts.remediation
    assert _code_blocks(hsts.reproduction)[0].startswith("GET / HTTP/1.1\nHost: www.acme-corp.example")

    js = issues[("burp:5245360", "https://www.acme-corp.example/assets/js/jquery-1.12.4.min.js")]
    assert js.description.endswith("Burp Suite confidence: Tentative.")
    assert "We detected **jquery** version **1.12.4**" in js.description
    assert "\n- CVE-2019-11358: Object.prototype pollution through `jQuery.extend(true, {}, ...)`." in js.description
    assert js.cwe == "CWE-1104"
    assert issues[("burp:5245344", "https://www.acme-corp.example/contact")].severity == "info"


def test_burp_import_groups_issue_types_and_enforces_scope(api, engagement):
    rec = _import(api, engagement, "burp", "burp-acme.xml")
    s = rec["stats"]
    assert (s["hosts_seen"], s["targets_created"], s["findings_created"], s["findings_updated"]) == (4, 2, 4, 1)
    assert s["skipped_excluded"] == 1  # vpn.acme-corp.example
    assert s["skipped_out_of_scope"] == 1  # careers.talentportal.example
    targets = _targets(api, engagement)
    assert set(targets) == {"https://www.acme-corp.example", "https://portal.acme-corp.example"}
    assert all(t["kind"] == "web" and t["source"] == "burp" for t in targets.values())

    findings = {f["title"]: f for f in api.ok("GET", f"/api/engagements/{engagement['id']}/findings")}
    assert set(findings) == {"Cross-site scripting (reflected)", "Strict transport security not enforced",
                             "Vulnerable JavaScript dependency", "Frameable response (potential Clickjacking)"}
    hsts = findings["Strict transport security not enforced"]
    assert hsts["status"] == "draft" and hsts["source"] == "burp" and hsts["cvss_score"] is None
    # One finding per issue type, listing every in-scope host; the VPN is excluded.
    assert sorted(t["value"] for t in hsts["targets"]) == [
        "https://portal.acme-corp.example", "https://www.acme-corp.example"]
    assert "https://portal.acme-corp.example/login" in hsts["steps_to_reproduce"]
    assert "vpn.acme-corp.example" not in hsts["steps_to_reproduce"]
    frame = findings["Frameable response (potential Clickjacking)"]
    assert [t["value"] for t in frame["targets"]] == ["https://www.acme-corp.example"]
    assert "talentportal" not in frame["steps_to_reproduce"]
    xss = findings["Cross-site scripting (reflected)"]
    assert xss["severity"] == "high" and xss["cwe"] == "CWE-79"
    assert xss["references"].splitlines()[0] == "https://portswigger.net/web-security/cross-site-scripting"

    again = _import(api, engagement, "burp", "burp-acme.xml")
    assert again["stats"]["findings_created"] == 0 and again["stats"]["findings_updated"] == 0


def test_burp_out_of_scope_import_keeps_exclusions_out(api, engagement):
    _import(api, engagement, "burp", "burp-acme.xml", skip=False)
    targets = _targets(api, engagement)
    assert targets["https://careers.talentportal.example"]["scope_status"] == "out_of_scope"
    assert "https://vpn.acme-corp.example" not in targets


def test_burp_request_decoding_truncation_and_fence():
    raw = (b"POST /api/upload HTTP/1.1\r\nHost: www.acme-corp.example\r\n\r\n"
           b"note ```` and \xff\xfe bytes\n" + b"A" * 5000)
    result = parse_burp_xml(_burp(_burp_issue(extra=_b64_request(raw))))
    repro = result.issues[0].reproduction
    total = len(raw.decode("utf-8", errors="replace").replace("\r\n", "\n"))
    assert "\n`````http\n" in repro  # longer than the 4-backtick run inside
    assert repro.endswith(f"Request truncated to the first 4000 of {total} characters.")
    [block] = _code_blocks(repro)  # the fence holds: one block, not closed early
    assert len(block) == 4000 and block.startswith("POST /api/upload HTTP/1.1\nHost:")
    assert "note ```` and \ufffd\ufffd bytes" in block


def test_burp_bad_input():
    bad_b64 = '<requestresponse><request base64="true">not base64!</request></requestresponse>'
    r = parse_burp_xml(_burp(
        _burp_issue(severity="False positive"),
        _burp_issue(host="ftp://files.acme-corp.example"),
        _burp_issue(type_=""),
        _burp_issue(extra=bad_b64, severity="Weird"),
        _burp_issue(type_="134217728", name="Extension: debug endpoint"),
        _burp_issue(type_="134217728", name="Extension: verbose errors", host="http://[::1"),
    ))
    assert r.errors == ["issue 2: skipped, host is not an http(s) URL",
                        "issue 3: skipped, no issue type",
                        "issue 4 (Cross-site scripting (reflected)): request is not valid base64",
                        "issue 6: skipped, host is not an http(s) URL"]
    assert [(i.key, i.severity) for i in r.issues] == [
        ("burp:2097920", "info"), ("burp:134217728:Extension: debug endpoint", "high")]
    assert r.issues[0].reproduction == "Matched at: `https://www.acme-corp.example/`"
    assert parse_burp_xml(_burp()).issues == []


def test_burp_text_is_converted_safely():
    extra = ("<issueBackground><![CDATA[<script>alert(document.cookie)</script><p>See "
             "<a href=\"javascript:alert(1)\">this</a> &amp; <a href=\"https://example.com/a (b)\">that</a>"
             "</p><style>p { color: red }</style>]]></issueBackground>"
             "<references><![CDATA[<a href=\"data:text/html,x\">x</a><a href=\" https://ok.example/ \">ok</a>"
             "]]></references>")
    issue = parse_burp_xml(_burp(_burp_issue(extra=extra))).issues[0]
    assert issue.description == ("See this & [that](https://example.com/a%20%28b%29)\n\n"
                                 "Burp Suite confidence: Firm.")
    assert issue.references == ["https://ok.example/"]


# ----------------------------------------------------------------- Nessus


def _nessus(*hosts: str) -> bytes:
    return ('<?xml version="1.0" ?><NessusClientData_v2><Report name="t">' + "".join(hosts)
            + "</Report></NessusClientData_v2>").encode()


def _report_host(name: str, *items: str, props: str = "") -> str:
    return f'<ReportHost name="{name}"><HostProperties>{props}</HostProperties>{"".join(items)}</ReportHost>'


def _item(plugin="10001", severity="2", port="443", svc="www", proto="tcp", body="") -> str:
    return (f'<ReportItem port="{port}" svc_name="{svc}" protocol="{proto}" severity="{severity}" '
            f'pluginID="{plugin}" pluginName="Plugin {plugin}" pluginFamily="General">{body}</ReportItem>')


def test_parse_nessus_sample():
    result = parse_nessus((SAMPLES / "nessus-acme.nessus").read_bytes())
    assert result.errors == []
    hosts = {h.value: h for h in result.hosts}
    assert list(hosts) == ["203.0.113.10", "203.0.113.12", "203.0.113.11", "198.51.100.7"]
    www = hosts["203.0.113.10"]
    assert (www.kind, www.ip, www.hostname, www.os) == (
        "host", "203.0.113.10", "www.acme-corp.example", "Linux Kernel 5.4 on Ubuntu 20.04")
    # One service per port, however many plugins reported on it; port 0 is not a service.
    assert [(s.port, s.protocol, s.state, s.name) for s in www.services] == [
        (22, "tcp", "open", "ssh"), (80, "tcp", "open", "www"), (443, "tcp", "open", "www")]
    assert hosts["203.0.113.12"].hostname == "mail.acme-corp.example"  # host-fqdn wins over hostname

    issues = {(i.key, i.matched_at): i for i in result.issues}
    # Severity 0 plugins (scan info, SYN scanner, service detection) are not findings.
    assert not {"nessus:19506", "nessus:11219", "nessus:22964", "nessus:10267"} & {k for k, _ in issues}
    assert {i.severity for i in result.issues} == {"low", "medium", "high", "critical"}

    terrapin = issues[("nessus:187315", "203.0.113.10:22/tcp")]
    assert terrapin.title == "SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)"
    assert terrapin.severity == "medium"
    assert terrapin.cvss_vector == "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"  # v3 over v4
    assert terrapin.description.startswith(
        "The remote SSH server is vulnerable to a man-in-the-middle prefix truncation attack.\n\n"
        "The remote SSH server is vulnerable to a man-in-the-middle prefix truncation weakness")
    assert terrapin.references == ["https://terrapin-attack.com/", "https://nvd.nist.gov/vuln/detail/CVE-2023-48795",
                                   "https://www.cve.org/CVERecord?id=CVE-2023-48795"]
    assert terrapin.remediation.startswith("Upgrade the SSH server to a release")
    assert terrapin.reproduction.startswith("Matched at: `203.0.113.10:22/tcp`\n\n```\nSupports following")

    sweet32 = issues[("nessus:42873", "203.0.113.12:3389/tcp")]
    assert (sweet32.severity, sweet32.cwe) == ("high", "CWE-326")
    assert "Medium Strength Ciphers (> 64-bit and < 112-bit key, or 3DES)" in _code_blocks(sweet32.reproduction)[0]
    smtp = issues[("nessus:54582", "203.0.113.12:25/tcp")]
    assert (smtp.severity, smtp.cvss_vector, smtp.cwe) == ("low", "", "CWE-319")  # CVSS v2 is ignored
    assert issues[("nessus:190710", "203.0.113.11:443/tcp")].severity == "critical"


def test_nessus_import_groups_plugins_and_enforces_scope(api, engagement):
    rec = _import(api, engagement, "nessus", "nessus-acme.nessus")
    s = rec["stats"]
    assert (s["hosts_seen"], s["targets_created"], s["services_created"]) == (4, 2, 5)
    assert (s["findings_created"], s["findings_updated"]) == (6, 1)
    assert s["skipped_excluded"] == 1 and s["skipped_out_of_scope"] == 1
    targets = _targets(api, engagement)
    assert set(targets) == {"203.0.113.10", "203.0.113.12"}
    mail = targets["203.0.113.12"]
    assert mail["os"] == "Microsoft Windows Server 2019 Standard" and mail["source"] == "nessus"
    assert [(sv["port"], sv["name"]) for sv in mail["services"]] == [(25, "smtp"), (3389, "msrdp")]

    findings = {f["title"]: f for f in api.ok("GET", f"/api/engagements/{engagement['id']}/findings")}
    assert not any("FortiOS" in t for t in findings)  # the excluded VPN's critical never lands
    tls = findings["TLS Version 1.0 Protocol Detection"]
    assert sorted(t["value"] for t in tls["targets"]) == ["203.0.113.10", "203.0.113.12"]
    assert "203.0.113.12:3389/tcp" in tls["steps_to_reproduce"] and tls["cwe"] == "CWE-327"
    hsts = findings["HSTS Missing From HTTPS Server (RFC 6797)"]
    assert [t["value"] for t in hsts["targets"]] == ["203.0.113.10"]  # 198.51.100.7 is out of scope
    terrapin = findings["SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)"]
    assert (terrapin["cvss_score"], terrapin["source"], terrapin["status"]) == (5.9, "nessus", "draft")
    assert "https://www.cve.org/CVERecord?id=CVE-2023-48795" in terrapin["references"].splitlines()
    assert findings["SMTP Service Cleartext Login Permitted"]["cvss_score"] is None

    again = _import(api, engagement, "nessus", "nessus-acme.nessus")
    assert again["stats"]["findings_created"] == 0 and again["stats"]["findings_updated"] == 0
    assert again["stats"]["services_created"] == 0


def test_nessus_fields_and_bad_input():
    cvss4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    long_output = "x" * 4100
    data = _nessus(
        _report_host(
            "scanner-named.acme-corp.example",
            _item("1", body=f"<cvss4_vector>{cvss4}</cvss4_vector><cvss_vector>CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
                            f"</cvss_vector><solution>n/a</solution><plugin_output>{long_output}</plugin_output>"
                            "<cve>CVE-2024-0001</cve><cve>not-a-cve</cve><see_also>javascript:x https://ok.example"
                            "</see_also>"),
            _item("2", severity="0", port="0", svc="general"),
            _item("3", severity="x"),
            _item("4", port="70000"),
            _item("5", severity="1", port="443", svc="https"),
            props='<tag name="hostname">SCAN01</tag>'),
        '<ReportHost name=""><HostProperties/></ReportHost>',
        _report_host("10.0.0.5", _item("6", severity="4", port="0", svc="general")),
    )
    r = parse_nessus(data)
    assert r.errors == ["bad severity on host scanner-named.acme-corp.example (plugin 3)",
                        "bad port on host scanner-named.acme-corp.example (plugin 4)",
                        "skipped a ReportHost without a name or host-ip"]
    named, by_ip = r.hosts
    assert (named.value, named.ip, named.hostname) == ("scanner-named.acme-corp.example", "", "SCAN01")
    assert [(s.port, s.name) for s in named.services] == [(443, "www")]  # first name wins
    assert (by_ip.value, by_ip.ip, by_ip.services) == ("10.0.0.5", "10.0.0.5", [])
    first = r.issues[0]
    assert first.cvss_vector == cvss4  # no v3 vector: v4 is used, v2 never
    assert first.remediation == ""  # "n/a"
    assert first.references == ["https://ok.example", "https://www.cve.org/CVERecord?id=CVE-2024-0001"]
    assert first.reproduction.endswith("Plugin output truncated to the first 4000 of 4100 characters.")
    assert len(_code_blocks(first.reproduction)[0]) == 4000
    assert [(i.key, i.severity, i.matched_at) for i in r.issues] == [
        ("nessus:1", "medium", "scanner-named.acme-corp.example:443/tcp"),
        ("nessus:5", "low", "scanner-named.acme-corp.example:443/tcp"),
        ("nessus:6", "critical", "10.0.0.5:0/tcp")]


def test_nessus_plain_text_becomes_markdown():
    assert text_to_markdown("Synopsis.\r\n\r\n\r\nIssues:\n\n  - CVE-2024-1 \n  - CVE-2024-2\n# not a heading\n"
                            "C:\\Windows\\_temp and `ticks`") == (
        "Synopsis.\n\nIssues:\n\n  - CVE-2024-1\n  - CVE-2024-2\n\\# not a heading\n"
        "C:\\Windows\\\\_temp and \\`ticks\\`")
    blocks = richtext.parse(text_to_markdown("Issues:\n\n  - one\n  - two"))
    assert blocks[1].kind == "bullets" and len(blocks[1].items) == 2


# ---------------------------------------------------------- shared checks


@pytest.mark.parametrize("parser", [parse_burp_xml, parse_nessus])
def test_new_xml_parsers_reject_malformed_and_foreign_input(parser):
    for data in [b"", b"<issues>", b"<NessusClientData_v2><Report>", b"\xff\xfe<x/>", b"not xml at all",
                 (SAMPLES / "nmap-acme.xml").read_bytes()]:
        with pytest.raises(ParseError):
            parser(data)
    # Each format is rejected by the other's parser.
    other = "nessus-acme.nessus" if parser is parse_burp_xml else "burp-acme.xml"
    with pytest.raises(ParseError):
        parser((SAMPLES / other).read_bytes())


@pytest.mark.parametrize("tool, parser, root", [
    ("burp", parse_burp_xml, "issues"), ("nessus", parse_nessus, "NessusClientData_v2")])
def test_new_xml_parsers_reject_entities(api, engagement, tool, parser, root):
    bomb = (f'<?xml version="1.0"?><!DOCTYPE {root} [<!ENTITY lol "lol">'
            f'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><{root}>&lol2;</{root}>').encode()
    xxe = (f'<?xml version="1.0"?><!DOCTYPE {root} [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
           f"<{root}>&e;</{root}>").encode()
    for payload in (bomb, xxe):
        with pytest.raises(ParseError):
            parser(payload)
        assert _upload(api, engagement, tool, "evil.xml", payload).status_code == 422
    assert api.ok("GET", f"/api/engagements/{engagement['id']}/evidence") == []


def test_html_to_markdown_structure():
    html = ("<h4>Server certificate</h4><table><tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>www.example.com</td>"
            "</tr><tr><td><b>Issued by:</b></td><td>R3</td></tr></table>"
            "<p>First<br>second</p><div>Steps:</div><ol><li>Open <i>Settings</i></li><li>Then <code>x`y</code></li>"
            "</ol><ul><li>a<p>b</p></li></ul><pre>\nline 1\n```\n  indented</pre>")
    assert html_to_markdown(html) == (
        "**Server certificate**\n\n**Issued to:** www.example.com\n**Issued by:** R3\n\n"
        "First\nsecond\n\nSteps:\n\n1. Open *Settings*\n2. Then ``x`y``\n\n- a\n  b\n\n"
        "````\nline 1\n```\n  indented\n````")


def test_html_to_markdown_keeps_text_literal():
    # Markup-like text stays text: only what richtext would misread is escaped.
    md = html_to_markdown("<p>*.example.com, snake_case, a *b c* d, `cmd`, C:\\_x, 2*3</p>"
                          "<p>- dash</p><p>1. one</p><p># hash</p><p>```</p>")
    assert md == ("*.example.com, snake_case, a \\*b c* d, \\`cmd\\`, C:\\\\_x, 2*3\n\n"
                  "\\- dash\n\n1\\. one\n\n\\# hash\n\n\\`\\`\\`")
    assert richtext.is_plain(richtext.parse(md))
    # Emphasis is emitted only where richtext will render it.
    assert html_to_markdown("<b>a</b>b <b>(x)</b> <b> c </b>.") == "ab (x) **c** ."
    assert html_to_markdown("<b><i>both</i></b> <code><b>c</b></code>") == "**both** `c`"


def test_html_to_markdown_is_safe():
    md = html_to_markdown('<script>alert("x")</script><style>*{}</style><template><b>t</b></template>'
                          '<p onclick="alert(1)">Hi &lt;img src=x onerror=alert(1)&gt; &amp; &#x27;bye&#39;</p>'
                          '<a href="javascript:alert(1)">js</a> <a href="JaVa&#10;Script:alert(1)">js2</a> '
                          '<a href="//evil.example">rel</a> <a href="https://ok.example/a b">ok</a>'
                          "<script>never closed")
    assert md == ("Hi <img src=x onerror=alert(1)> & 'bye'\n\n"
                  "js js2 rel [ok](https://ok.example/a%20b)")
    assert "<img" not in richtext.to_html(md)
    assert html_links('<a href="https://a.example">a</a><a href="https://a.example">again</a>'
                      '<a href="mailto:x@y">m</a>') == ["https://a.example"]
    assert safe_url("ftp://x.example") == "" and safe_url("https://") == ""
    assert html_to_markdown("") == "" and html_to_markdown(None) == ""


def test_inline_code_and_fences_hold_any_content():
    for text in ["plain", "a`b", "``x``", "`", "ends with `", "```"]:
        [span] = richtext.parse_inline(inline_code(text))
        assert span.code and span.text == text
    for text in ["x", "```\ny", "a\n````\n`````\nb", "~~~\nz"]:
        [block] = richtext.parse(code_block(text, "http"))
        assert block.kind == "code" and block.text == text
    assert code_block("  \n ") == "" and inline_code("  ") == ""


_STYLE_TAGS = {"b": "b", "strong": "b", "h4": "b", "i": "i", "em": "i", "code": "c", "kbd": "c", "pre": "p"}


class _Visible(HTMLParser):
    """The text a browser would show for an HTML fragment, with its bold/italic/code styling."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = {"b": 0, "i": 0, "c": 0, "p": 0}
        self.skip = 0
        self.chars: list[tuple[str, set]] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "template"):
            self.skip += 1
        elif tag in _STYLE_TAGS and not self.skip:
            self.depth[_STYLE_TAGS[tag]] += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "template"):
            self.skip = max(0, self.skip - 1)
        elif tag in _STYLE_TAGS and not self.skip and self.depth[_STYLE_TAGS[tag]]:
            self.depth[_STYLE_TAGS[tag]] -= 1

    def handle_data(self, data):
        if not self.skip:
            style = {"c" if k == "p" else k for k, v in self.depth.items() if v}
            self.chars.extend((ch, style) for ch in data if not ch.isspace())


def _rendered(md: str) -> list[tuple[str, set]]:
    out = []

    def add(spans):
        for sp in spans:
            style = {k for k, on in (("b", sp.bold), ("i", sp.italic), ("c", sp.code)) if on}
            out.extend((ch, style) for ch in sp.text if not ch.isspace())

    for block in richtext.parse(md):
        if block.kind == "code":
            out.extend((ch, {"c"}) for ch in block.text if not ch.isspace())
        elif block.kind in ("bullets", "numbers"):
            for item in block.items:
                add(item)
        else:
            add(block.spans)
    return out


_HTML_PIECES = st.sampled_from([
    "a", "b c", " ", "\n", "*", "**", "_", "__", "`", "``", "\\", "\\*", "- ", "1. ", "2) ", "# ", "~~~", "```",
    "&lt;", "&amp;", "&#96;", "x_y", "*.example.com", "(", ")", "'", ".", ":", "/", "-", "!", "+",
    "<b>", "</b>", "<strong>", "</strong>", "<i>", "</i>", "<em>", "</em>", "<code>", "</code>", "<kbd>", "</kbd>",
    "<p>", "</p>", "<div>", "</div>", "<br>", "<br/>", "<ul>", "</ul>", "<ol>", "</ol>", "<li>", "</li>",
    "<pre>", "</pre>", '<a href="javascript:x">', "</a>", "<script>", "</script>", "<h4>", "</h4>",
    "<table>", "<tr>", "<td>", "</td>", "</tr>", "</table>",
])


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_HTML_PIECES, max_size=40))
def test_html_to_markdown_renders_the_same_text(pieces):
    """Whatever the HTML, richtext shows its visible text and never adds formatting to it."""
    html = "".join(pieces)
    visible = _Visible()
    visible.feed(html)
    visible.close()
    rendered = _rendered(html_to_markdown(html))
    assert "".join(c for c, _ in rendered) == "".join(c for c, _ in visible.chars)
    for (_, got), (_, source) in zip(rendered, visible.chars):
        assert got <= source  # bold+italic may lose one; nothing gains any


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=300))
def test_scanner_text_conversion_never_crashes(text):
    for value in (text, f"<b>{text}</b>", f"<pre>{text}</pre>", f'<a href="{text}">x</a>'):
        html_to_markdown(value)
    text_to_markdown(text)
    [block] = richtext.parse(code_block(text + "x"))
    assert block.text == re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "\ufffd",
                                (text + "x").replace("\r\n", "\n").replace("\r", "\n")).strip("\n")
