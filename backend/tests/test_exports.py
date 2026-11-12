"""Findings exports: Jira-ready CSV, SARIF 2.1.0 and DefectDojo generic JSON."""

import csv
import io
import json


def _setup(api, engagement):
    base = f"/api/engagements/{engagement['id']}"
    t1 = api.ok("POST", f"{base}/targets", json={"value": "https://www.acme-corp.example"})
    t2 = api.ok("POST", f"{base}/targets", json={"value": "203.0.113.4"})
    f = api.ok("POST", f"{base}/findings", json={
        "title": "=HYPERLINK(\"http://evil\",\"click\")", "status": "confirmed", "target_ids": [t1["id"], t2["id"]],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-89",
        "description": "-2+3 in a banner\n@SUM(A1)", "remediation": "Use parameterised queries.",
        "references": "https://owasp.org/www-community/attacks/SQL_Injection\nnot a url",
    })
    api.ok("POST", f"{base}/findings/{f['id']}/retests", json={"result": "not_resolved"})
    api.ok("POST", f"{base}/findings", json={"title": "Draft only", "status": "draft"})
    return base


def test_csv_is_jira_ready_and_defused(api, engagement):
    base = _setup(api, engagement)
    r = api.get(f"{base}/export/findings?format=csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'filename="ACME-EXT-findings.csv"' in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:5] == ["Summary", "Description", "Priority", "Labels", "Labels"]
    assert len(rows) == 2  # the draft is left out
    row = dict(zip(rows[0][5:], rows[1][5:]))
    assert rows[1][0] == 'ACME-EXT-001 =HYPERLINK("http://evil","click")'  # not at cell start: harmless
    assert rows[1][2] == "Highest" and rows[1][3:5] == ["pentest", "ACME-EXT"]
    assert row["CVSS score"] == "9.8" and row["Retest"] == "not_resolved"
    assert "-2+3 in a banner" in rows[1][1]
    for cell in rows[1]:
        assert not cell.startswith(("=", "+", "-", "@")), cell
    drafts = list(csv.reader(io.StringIO(api.get(f"{base}/export/findings?format=csv&include_drafts=true").text)))
    assert len(drafts) == 3


def test_formula_cells_are_prefixed():
    from app.services.exports import defuse
    assert defuse("=1+1") == "'=1+1" and defuse("@cmd") == "'@cmd" and defuse("-x") == "'-x"
    assert defuse("plain") == "plain" and defuse(None) == "" and defuse(9.8) == "9.8"


def test_sarif(api, engagement):
    base = _setup(api, engagement)
    r = api.get(f"{base}/export/findings?format=sarif")
    doc = json.loads(r.text)
    assert doc["version"] == "2.1.0" and r.headers["content-type"].startswith("application/sarif+json")
    run = doc["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "ACME-EXT-001" and rule["properties"]["security-severity"] == "9.8"
    assert "CWE-89" in rule["properties"]["tags"]
    assert rule["helpUri"] == "https://owasp.org/www-community/attacks/SQL_Injection"
    result = run["results"][0]
    assert result["level"] == "error" and result["ruleId"] == "ACME-EXT-001"
    assert [loc["logicalLocations"][0]["name"] for loc in result["locations"]] == [
        "203.0.113.4", "https://www.acme-corp.example"]


def test_defectdojo(api, engagement):
    base = _setup(api, engagement)
    data = json.loads(api.get(f"{base}/export/findings?format=defectdojo").text)
    f = data["findings"][0]
    assert f["severity"] == "Critical" and f["cwe"] == 89 and f["cvssv3_score"] == 9.8
    assert f["unique_id_from_tool"] == "ACME-EXT-001" and f["active"] is True and f["verified"] is True
    assert {"host": "203.0.113.4"} in f["endpoints"] and "https://www.acme-corp.example" in f["endpoints"]


def test_cvss_version_helper():
    from app.services.cvss import version_of
    assert version_of("CVSS:4.0/AV:N") == "4.0"


def test_unknown_format_is_rejected(api, engagement):
    assert api.get(f"/api/engagements/{engagement['id']}/export/findings?format=xlsx").status_code == 422
