def _base(eng):
    return f"/api/engagements/{eng['id']}"


def _template(api, title):
    return next(t for t in api.ok("GET", "/api/finding-templates") if t["title"] == title)


def test_library_is_seeded(api):
    templates = api.ok("GET", "/api/finding-templates")
    assert len(templates) >= 10
    sqli = _template(api, "SQL Injection")
    assert sqli["cvss_score"] == 9.8 and sqli["cwe"] == "CWE-89"
    assert api.ok("GET", "/api/finding-templates?q=kerberoast")[0]["category"] == "Active Directory"


def test_create_finding_from_template(api, engagement):
    t = api.ok("POST", f"{_base(engagement)}/targets", json={"value": "203.0.113.4"})
    tpl = _template(api, "Reflected Cross-Site Scripting (XSS)")
    f = api.ok("POST", f"{_base(engagement)}/findings",
               json={"template_id": tpl["id"], "target_ids": [t["id"]],
                     "steps_to_reproduce": "GET /?q=<script>"})
    assert f["title"] == tpl["title"] and f["cvss_score"] == 6.1 and f["severity"] == "medium"
    assert f["ref"] == "ACME-EXT-001" and f["source"] == "template"
    assert [x["value"] for x in f["targets"]] == ["203.0.113.4"]
    assert "created_by" not in f
    f2 = api.ok("POST", f"{_base(engagement)}/findings", json={"title": "Second"})
    assert f2["ref"] == "ACME-EXT-002" and f2["severity"] == "medium"


def test_finding_targets_must_be_in_the_engagement(api, engagement):
    other_client = api.ok("POST", "/api/clients", json={"name": "Other"})
    other = api.ok("POST", "/api/engagements", json={
        "client_id": other_client["id"], "name": "Other", "code": "OTHER", "type": "api"})
    t = api.ok("POST", f"{_base(other)}/targets", json={"value": "10.0.0.1"})
    r = api.post(f"{_base(engagement)}/findings", json={"title": "x", "target_ids": [t["id"]]})
    assert r.status_code == 404


def test_severity_derivation_and_override(api, engagement):
    base = f"{_base(engagement)}/findings"
    f = api.ok("POST", base, json={"title": "RCE",
                                   "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert f["severity"] == "critical"
    f = api.ok("PATCH", f"{base}/{f['id']}", json={"severity": "high"})
    assert f["severity"] == "high" and f["cvss_score"] == 9.8
    f = api.ok("PATCH", f"{base}/{f['id']}", json={"cvss_vector": ""})
    assert f["cvss_score"] is None and f["cvss_vector"] == ""
    assert api.patch(f"{base}/{f['id']}", json={"cvss_vector": "bogus"}).status_code == 422


def test_findings_sorted_by_severity(api, engagement):
    base = f"{_base(engagement)}/findings"
    for title, sev in [("low one", "low"), ("crit one", "critical"), ("med one", "medium")]:
        api.ok("POST", base, json={"title": title, "severity": sev})
    assert [f["severity"] for f in api.ok("GET", base)] == ["critical", "medium", "low"]
    assert [f["title"] for f in api.ok("GET", f"{base}?severity=low")] == ["low one"]


def test_status_change_is_recorded(api, engagement):
    base = f"{_base(engagement)}/findings"
    f = api.ok("POST", base, json={"title": "Audit me"})
    api.ok("PATCH", f"{base}/{f['id']}", json={"status": "confirmed"})
    events = api.ok("GET", f"{_base(engagement)}/activity")
    assert any("status draft -> confirmed" in e["summary"] for e in events)
    assert all("user" not in e and "ip_address" not in e for e in events)
    api.ok("DELETE", f"{base}/{f['id']}")
    assert api.get(f"{base}/{f['id']}").status_code == 404


def test_save_as_template_and_library_management(api, engagement):
    f = api.ok("POST", f"{_base(engagement)}/findings",
               json={"title": "Custom writeup", "description": "desc", "severity": "low"})
    tpl = api.ok("POST", f"{_base(engagement)}/findings/{f['id']}/save-as-template")
    assert tpl["title"] == "Custom writeup" and tpl["severity"] == "low"
    assert api.post(f"{_base(engagement)}/findings/{f['id']}/save-as-template").status_code == 409

    tpl = api.ok("PATCH", f"/api/finding-templates/{tpl['id']}",
                 json={"cvss_vector": "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"})
    assert tpl["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert tpl["cvss_score"] == 9.8
    bad_vector = {"title": "x", "cvss_vector": "junk"}
    assert api.post("/api/finding-templates", json=bad_vector).status_code == 422
    assert api.post("/api/finding-templates", json={"title": "SQL Injection"}).status_code == 409
    api.ok("DELETE", f"/api/finding-templates/{tpl['id']}")
    assert all(t["id"] != tpl["id"] for t in api.ok("GET", "/api/finding-templates"))


def test_methodology_apply_and_progress(api, engagement):
    methods = {m["id"]: m for m in api.ok("GET", "/api/methodologies")}
    assert {"owasp-wstg", "owasp-api-2023", "external-network", "internal-ad", "aws-cloud"} <= set(methods)
    base = f"{_base(engagement)}/tests"
    created = api.ok("POST", f"{base}/apply", json={"methodology_id": "owasp-api-2023"})
    assert len(created) == methods["owasp-api-2023"]["case_count"]
    assert "assignee" not in created[0]
    assert api.ok("POST", f"{base}/apply", json={"methodology_id": "owasp-api-2023"}) == []
    assert api.post(f"{base}/apply", json={"methodology_id": "nope"}).status_code == 404

    target = api.ok("POST", f"{_base(engagement)}/targets", json={"value": "203.0.113.5"})
    tc = api.ok("PATCH", f"{base}/{created[0]['id']}",
                json={"status": "failed", "target_id": target["id"]})
    assert tc["status"] == "failed" and tc["target_id"] == target["id"]
    tc = api.ok("PATCH", f"{base}/{created[0]['id']}", json={"target_id": None})
    assert tc["target_id"] is None and tc["status"] == "failed"  # links clear, status stays
    assert api.patch(f"{base}/{created[0]['id']}", json={"finding_id": 999}).status_code == 404

    custom = api.ok("POST", base, json={"title": "Check the VPN banner", "status": "blocked"})
    assert custom["methodology"] == "custom"
    summary = api.ok("GET", f"{_base(engagement)}/summary")
    assert summary["tests_by_status"] == {"failed": 1, "blocked": 1, "not_started": len(created) - 1}
    # Every open check (not started, in progress, blocked) in active engagements.
    assert api.ok("GET", "/api/dashboard")["open_tests"] == len(created)
    api.ok("DELETE", f"{base}/{custom['id']}")
    assert api.ok("GET", "/api/dashboard")["open_tests"] == len(created) - 1


def test_oplog_operator_and_csv_export(api, engagement):
    base = f"{_base(engagement)}/oplog"
    api.ok("PUT", "/api/profile", json={"name": "Riley Chen", "email": "", "organization": ""})
    e = api.ok("POST", base, json={"tool": "nmap", "target": "203.0.113.0/28",
                                   "command": "nmap -sV 203.0.113.0/28", "source_host": "192.0.2.200"})
    assert e["operator"] == "Riley Chen" and "user" not in e
    other = api.ok("POST", base, json={"operator": "  Sam Okafor ", "target": "203.0.113.12",
                                       "tool": "netexec", "outcome": "detected"})
    assert other["operator"] == "Sam Okafor"
    assert api.post(base, json={"tool": "x"}).status_code == 422

    csv = api.ok("GET", f"{base}/export.csv")
    assert csv.headers["content-type"].startswith("text/csv")
    assert 'filename="ACME-EXT-oplog.csv"' in csv.headers["content-disposition"]
    lines = csv.text.splitlines()
    assert lines[0].startswith("occurred_at_utc,operator,source_host")
    assert ",Riley Chen,192.0.2.200,203.0.113.0/28,nmap,nmap -sV 203.0.113.0/28," in lines[1]
    assert ",Sam Okafor,," in lines[2]

    # Deleting an entry is itself recorded: the log is a deconfliction record.
    api.ok("DELETE", f"{base}/{e['id']}")
    assert [x["id"] for x in api.ok("GET", base)] == [other["id"]]
    events = api.ok("GET", f"{_base(engagement)}/activity")
    assert events[0]["entity_type"] == "oplog" and events[0]["action"] == "delete"
    assert events[1]["action"] == "export"
