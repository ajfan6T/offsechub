"""Finding retests and the schema migration that introduced them."""

from sqlalchemy import text

from app.bootstrap import SCHEMA_VERSION, get_setting

from .conftest import PASSWORD


def _findings(eng):
    return f"/api/engagements/{eng['id']}/findings"


def test_retests_track_the_fix(api, engagement):
    api.ok("PUT", "/api/profile", json={"name": "Riley Chen", "organization": "", "email": ""})
    f = api.ok("POST", _findings(engagement), json={"title": "Weak TLS", "status": "reported"})
    assert f["retests"] == [] and f["retest_status"] is None
    url = f"{_findings(engagement)}/{f['id']}/retests"

    first = api.ok("POST", url, json={"tested_on": "2026-10-20", "result": "not_resolved",
                                      "notes": "TLS 1.0 still offered"})
    assert first["tester"] == "Riley Chen" and first["tested_on"] == "2026-10-20"
    got = api.ok("GET", f"{_findings(engagement)}/{f['id']}")
    assert got["status"] == "reported" and got["retest_status"] == "not_resolved"

    api.ok("POST", url, json={"tested_on": "2026-11-03", "result": "resolved", "tester": "Sam"})
    got = api.ok("GET", f"{_findings(engagement)}/{f['id']}")
    assert got["status"] == "remediated"  # a resolved retest closes a reported finding
    assert [r["result"] for r in got["retests"]] == ["not_resolved", "resolved"]
    assert got["retest_status"] == "resolved" and got["retests"][1]["tester"] == "Sam"
    listed = api.ok("GET", _findings(engagement))
    assert listed[0]["retest_status"] == "resolved"

    api.ok("DELETE", f"{url}/{first['id']}")
    got = api.ok("GET", f"{_findings(engagement)}/{f['id']}")
    assert [r["result"] for r in got["retests"]] == ["resolved"]
    activity = api.ok("GET", f"/api/engagements/{engagement['id']}/activity")
    assert any("Retested" in a["summary"] and "remediated" in a["summary"] for a in activity)


def test_retest_leaves_other_statuses_alone(api, engagement):
    f = api.ok("POST", _findings(engagement), json={"title": "Accepted risk", "status": "risk_accepted"})
    url = f"{_findings(engagement)}/{f['id']}/retests"
    api.ok("POST", url, json={"result": "resolved"})
    api.ok("POST", url, json={"result": "not_resolved"})
    assert api.ok("GET", f"{_findings(engagement)}/{f['id']}")["status"] == "risk_accepted"


def test_status_follows_the_latest_retest_by_date(api, engagement):
    f = api.ok("POST", _findings(engagement), json={"title": "Weak TLS", "status": "reported"})
    url = f"{_findings(engagement)}/{f['id']}/retests"
    get = lambda: api.ok("GET", f"{_findings(engagement)}/{f['id']}")  # noqa: E731

    failed = api.ok("POST", url, json={"tested_on": "2026-10-10", "result": "not_resolved"})
    # A resolved retest dated earlier is history, not the current state.
    early = api.ok("POST", url, json={"tested_on": "2026-10-01", "result": "resolved"})
    assert (get()["status"], get()["retest_status"]) == ("reported", "not_resolved")

    # Removing the later failure makes the resolved retest the latest one.
    api.ok("DELETE", f"{url}/{failed['id']}")
    assert (get()["status"], get()["retest_status"]) == ("remediated", "resolved")

    # A later failed retest reopens a remediated finding.
    api.ok("POST", url, json={"tested_on": "2026-10-20", "result": "partially_resolved"})
    assert (get()["status"], get()["retest_status"]) == ("reported", "partially_resolved")
    activity = api.ok("GET", f"/api/engagements/{engagement['id']}/activity")
    assert any("remediated -> reported" in a["summary"] for a in activity)

    # Same date: the one recorded last counts.
    api.ok("POST", url, json={"tested_on": "2026-10-20", "result": "resolved"})
    assert get()["status"] == "remediated"
    # Removing every retest leaves the status as it is.
    for r in get()["retests"]:
        api.ok("DELETE", f"{url}/{r['id']}")
    assert get()["status"] == "remediated" and get()["retest_status"] is None
    assert early["result"] == "resolved"


def test_retest_validation_and_scoping(api, engagement):
    f = api.ok("POST", _findings(engagement), json={"title": "x"})
    g = api.ok("POST", _findings(engagement), json={"title": "y"})
    url = f"{_findings(engagement)}/{f['id']}/retests"
    assert api.post(url, json={"result": "fixed"}).status_code == 422
    r = api.ok("POST", url, json={"result": "partially_resolved"})
    # A retest id from another finding is not reachable through this one.
    assert api.delete(f"{_findings(engagement)}/{g['id']}/retests/{r['id']}").status_code == 404
    assert api.post(f"{_findings(engagement)}/99999/retests", json={"result": "resolved"}).status_code == 404
    # Deleting the finding deletes its retests.
    api.ok("DELETE", f"{_findings(engagement)}/{f['id']}")


def test_v1_vault_is_migrated_on_unlock(api, app_ctx):
    _app, manager, _auth = app_ctx
    vault = manager.require()
    # Make it look like a vault written by 0.2.0: schema 1, no new tables.
    with vault.session() as db:
        db.execute(text("DROP TABLE finding_retests"))
        db.execute(text("DROP TABLE report_assets"))
        db.execute(text("UPDATE settings SET value = '1' WHERE key = 'schema.version'"))
        db.commit()
    api.ok("POST", "/api/vault/lock", 200)
    api.ok("POST", "/api/vault/unlock", 200, json={"path": api.vault_path, "password": PASSWORD})
    with manager.require().session() as db:
        assert get_setting(db, "schema.version") == SCHEMA_VERSION == 2
        tables = {r[0] for r in db.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        assert {"finding_retests", "report_assets"} <= tables
        db.rollback()


def test_newer_vault_is_refused_with_a_message(api, app_ctx):
    _app, manager, _auth = app_ctx
    with manager.require().session() as db:
        db.execute(text("UPDATE settings SET value = '99' WHERE key = 'schema.version'"))
        db.commit()
    api.ok("POST", "/api/vault/lock", 200)
    r = api.post("/api/vault/unlock", json={"path": api.vault_path, "password": PASSWORD})
    assert r.status_code == 400 and "newer version of OffsecHub" in r.json()["detail"]
    assert manager.current is None


def test_reports_render_rich_text_and_retests(api, engagement):
    base = f"/api/engagements/{engagement['id']}"
    f = api.ok("POST", f"{base}/findings", json={
        "title": "Stored XSS", "status": "confirmed",
        "description": "Payload **persists** in `comment`:\n\n- one\n- two <script>alert(1)</script>",
        "steps_to_reproduce": "POST /comment HTTP/1.1\nHost: x\n\nbody=<img src=x onerror=alert(1)>",
        "remediation": "Encode output. See [OWASP](https://owasp.org/x) and [bad](javascript:alert(1)).",
    })
    api.ok("POST", f"{base}/findings/{f['id']}/retests",
           json={"tested_on": "2026-11-01", "result": "not_resolved", "notes": "Still **fires**"})

    html = api.ok("GET", f"{base}/report?format=html").text
    assert "<strong>persists</strong>" in html and "<code>comment</code>" in html
    assert "<ul><li>one</li><li>two &lt;script&gt;alert(1)&lt;/script&gt;</li></ul>" in html
    assert "<script>alert(1)</script>" not in html and "onerror=alert(1)>" not in html
    # Unformatted steps (a raw request) stay a code block.
    assert '<pre class="steps">POST /comment HTTP/1.1\nHost: x' in html
    assert 'href="https://owasp.org/x"' in html and "javascript:" not in html.split("<body>")[1].split("bad")[0][-80:]
    assert "Retest history" in html and "Not resolved" in html and "<strong>fires</strong>" in html
    assert "<th>Retest</th>" in html
    assert "CONFIDENTIAL. This report contains" in html

    md = api.ok("GET", f"{base}/report?format=md").text
    assert "```\nPOST /comment HTTP/1.1" in md and "#### Retest history" in md
    assert "| 2026-11-01 | Not resolved |" in md

    data = api.ok("GET", f"{base}/report?format=json")
    row = data["findings"][0]
    assert row["retest_status"] == "not_resolved" and row["retests"][0]["notes"] == "Still **fires**"
    assert "logo" not in data["branding"] and data["branding"]["classification"] == "CONFIDENTIAL"
