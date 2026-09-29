from .conftest import user_id


def _base(eng):
    return f"/api/engagements/{eng['id']}"


def _template(admin, title):
    return next(t for t in admin.ok("GET", "/api/finding-templates") if t["title"] == title)


def test_library_is_seeded(admin):
    templates = admin.ok("GET", "/api/finding-templates")
    assert len(templates) >= 10
    sqli = _template(admin, "SQL Injection")
    assert sqli["cvss_score"] == 9.8 and sqli["cwe"] == "CWE-89"
    assert admin.ok("GET", "/api/finding-templates?q=kerberoast")[0]["category"] == "Active Directory"


def test_create_finding_from_template(admin, engagement):
    t = admin.ok("POST", f"{_base(engagement)}/targets", json={"value": "203.0.113.4"})
    tpl = _template(admin, "Reflected Cross-Site Scripting (XSS)")
    f = admin.ok("POST", f"{_base(engagement)}/findings",
                 json={"template_id": tpl["id"], "target_ids": [t["id"]],
                       "steps_to_reproduce": "GET /?q=<script>"})
    assert f["title"] == tpl["title"] and f["cvss_score"] == 6.1 and f["severity"] == "medium"
    assert f["ref"] == "ACME-EXT-001" and f["source"] == "template"
    assert [x["value"] for x in f["targets"]] == ["203.0.113.4"]
    f2 = admin.ok("POST", f"{_base(engagement)}/findings", json={"title": "Second"})
    assert f2["ref"] == "ACME-EXT-002" and f2["severity"] == "medium"


def test_severity_derivation_and_override(admin, engagement):
    base = f"{_base(engagement)}/findings"
    f = admin.ok("POST", base, json={"title": "RCE",
                                     "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert f["severity"] == "critical"
    f = admin.ok("PATCH", f"{base}/{f['id']}", json={"severity": "high"})
    assert f["severity"] == "high" and f["cvss_score"] == 9.8
    f = admin.ok("PATCH", f"{base}/{f['id']}", json={"cvss_vector": ""})
    assert f["cvss_score"] is None and f["cvss_vector"] == ""
    assert admin.patch(f"{base}/{f['id']}", json={"cvss_vector": "bogus"}).status_code == 422


def test_findings_sorted_by_severity(admin, engagement):
    base = f"{_base(engagement)}/findings"
    for title, sev in [("low one", "low"), ("crit one", "critical"), ("med one", "medium")]:
        admin.ok("POST", base, json={"title": title, "severity": sev})
    assert [f["severity"] for f in admin.ok("GET", base)] == ["critical", "medium", "low"]
    assert [f["title"] for f in admin.ok("GET", f"{base}?severity=low")] == ["low one"]


def test_status_change_is_audited(admin, engagement):
    base = f"{_base(engagement)}/findings"
    f = admin.ok("POST", base, json={"title": "Audit me"})
    admin.ok("PATCH", f"{base}/{f['id']}", json={"status": "confirmed"})
    events = admin.ok("GET", f"{_base(engagement)}/activity")
    assert any("status draft -> confirmed" in e["summary"] for e in events)


def test_save_as_template(admin, engagement, make_user):
    f = admin.ok("POST", f"{_base(engagement)}/findings",
                 json={"title": "Custom writeup", "description": "desc", "severity": "low"})
    tpl = admin.ok("POST", f"{_base(engagement)}/findings/{f['id']}/save-as-template")
    assert tpl["title"] == "Custom writeup"
    tester = make_user("t@test.local")
    assert tester.post("/api/finding-templates", json={"title": "x"}).status_code == 403


def test_methodology_apply_and_progress(admin, engagement, make_user):
    methods = {m["id"]: m for m in admin.ok("GET", "/api/methodologies")}
    assert {"owasp-wstg", "owasp-api-2023", "external-network", "internal-ad", "aws-cloud"} <= set(methods)
    base = f"{_base(engagement)}/tests"
    created = admin.ok("POST", f"{base}/apply", json={"methodology_id": "owasp-api-2023"})
    assert len(created) == methods["owasp-api-2023"]["case_count"]
    assert admin.ok("POST", f"{base}/apply", json={"methodology_id": "owasp-api-2023"}) == []

    tester = make_user("t@test.local")
    tid = user_id(admin, "t@test.local")
    # Assignees must be engagement members.
    assert admin.patch(f"{base}/{created[0]['id']}", json={"assignee_id": tid}).status_code == 400
    admin.ok("PUT", f"{_base(engagement)}/members", json={"user_id": tid, "role": "tester"})
    tc = tester.ok("PATCH", f"{base}/{created[0]['id']}", json={"assignee_id": tid, "status": "failed"})
    assert tc["status"] == "failed" and tc["assignee"]["id"] == tid
    tc = tester.ok("PATCH", f"{base}/{created[0]['id']}", json={"assignee_id": None})
    assert tc["assignee"] is None and tc["status"] == "failed"

    summary = admin.ok("GET", f"{_base(engagement)}/summary")
    assert summary["tests_by_status"]["failed"] == 1
    assert admin.ok("GET", "/api/dashboard")["my_open_tests"] == 0


def test_oplog_and_csv_export(admin, engagement, make_user):
    base = f"{_base(engagement)}/oplog"
    e = admin.ok("POST", base, json={"tool": "nmap", "target": "203.0.113.0/28",
                                     "command": "nmap -sV 203.0.113.0/28", "source_host": "192.0.2.200"})
    assert e["user"]["email"] == "admin@test.local"
    assert admin.post(base, json={"tool": "x"}).status_code == 422
    csv = admin.ok("GET", f"{base}/export.csv")
    assert "nmap -sV 203.0.113.0/28" in csv.text and csv.headers["content-type"].startswith("text/csv")

    tester = make_user("t@test.local")
    admin.ok("PUT", f"{_base(engagement)}/members",
             json={"user_id": user_id(admin, "t@test.local"), "role": "tester"})
    assert tester.delete(f"{base}/{e['id']}").status_code == 403
    admin.ok("DELETE", f"{base}/{e['id']}")
