import hashlib
import json

from app.config import get_settings


def _base(eng):
    return f"/api/engagements/{eng['id']}"


PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15"
       b"\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff\x89\x99=\x1d\x00\x00"
       b"\x00\x00IEND\xaeB`\x82")


def test_upload_and_download_evidence(admin, engagement):
    f = admin.ok("POST", f"{_base(engagement)}/findings", json={"title": "Has evidence"})
    ev = admin.ok("POST", f"{_base(engagement)}/evidence",
                  data={"description": "screenshot", "finding_id": str(f["id"])},
                  files={"file": ("../../etc/shot.png", PNG, "image/png")})
    assert ev["filename"] == "shot.png"  # path components stripped
    assert ev["sha256"] == hashlib.sha256(PNG).hexdigest() and ev["is_image"]

    r = admin.get(f"{_base(engagement)}/evidence/{ev['id']}/download")
    assert r.content == PNG and r.headers["content-disposition"].startswith("attachment")
    assert r.headers["content-type"] == "application/octet-stream"
    r = admin.get(f"{_base(engagement)}/evidence/{ev['id']}/download?inline=true")
    assert r.headers["content-type"] == "image/png" and r.headers["content-disposition"].startswith("inline")
    assert admin.ok("GET", f"{_base(engagement)}/findings/{f['id']}")["evidence_count"] == 1


def test_active_content_is_never_served_inline(admin, engagement):
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
    ev = admin.ok("POST", f"{_base(engagement)}/evidence", files={"file": ("x.svg", svg, "image/svg+xml")})
    assert not ev["is_image"]
    r = admin.get(f"{_base(engagement)}/evidence/{ev['id']}/download?inline=true")
    assert r.headers["content-disposition"].startswith("attachment")
    assert r.headers["content-type"] == "application/octet-stream"
    assert "sandbox" in r.headers["content-security-policy"]


def test_text_evidence_and_limits(admin, engagement):
    ev = admin.ok("POST", f"{_base(engagement)}/evidence/text",
                  json={"filename": "request", "content": "GET / HTTP/1.1\r\nHost: x\r\n\r\n"})
    assert ev["filename"] == "request.txt" and ev["content_type"] == "text/plain"

    settings = get_settings()
    old = settings.max_upload_mb
    settings.max_upload_mb = 1
    try:
        r = admin.post(f"{_base(engagement)}/evidence", files={"file": ("big.bin", b"0" * (1024 * 1024 + 1))})
        assert r.status_code == 413
    finally:
        settings.max_upload_mb = old


def test_evidence_link_must_be_same_engagement(admin, engagement):
    other_client = admin.ok("POST", "/api/clients", json={"name": "Other"})
    other = admin.ok("POST", "/api/engagements", json={
        "client_id": other_client["id"], "name": "Other", "code": "OTHER", "type": "api"})
    f = admin.ok("POST", f"{_base(other)}/findings", json={"title": "elsewhere"})
    r = admin.post(f"{_base(engagement)}/evidence", data={"finding_id": str(f["id"])},
                   files={"file": ("a.txt", b"hi")})
    assert r.status_code == 404


def _report_fixture(admin, engagement):
    base = _base(engagement)
    admin.ok("PATCH", base, json={"executive_summary": "Overall posture is weak."})
    t = admin.ok("POST", f"{base}/targets", json={"value": "203.0.113.10", "hostname": "www.acme-corp.example"})
    f = admin.ok("POST", f"{base}/findings", json={
        "title": "<script>alert('xss')</script> Stored XSS", "status": "confirmed",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", "target_ids": [t["id"]],
        "description": "Payload <img src=x onerror=alert(1)>"})
    admin.ok("POST", f"{base}/findings", json={"title": "Unconfirmed lead", "status": "draft"})
    admin.ok("POST", f"{base}/findings", json={"title": "Not real", "status": "false_positive"})
    admin.ok("POST", f"{base}/evidence", data={"finding_id": str(f["id"])},
             files={"file": ("shot.png", PNG, "image/png")})
    return base


def test_html_report(admin, engagement):
    base = _report_fixture(admin, engagement)
    r = admin.get(f"{base}/report")
    assert r.status_code == 200
    html = r.text
    assert "Overall posture is weak." in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt; Stored XSS" in html
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "Unconfirmed lead" not in html and "Not real" not in html
    assert "data:image/png;base64," in html  # screenshot embedded
    assert "ACME-EXT-001" in html and "203.0.113.10" in html
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp

    with_drafts = admin.get(f"{base}/report?include_drafts=true").text
    assert "Unconfirmed lead" in with_drafts and "Not real" not in with_drafts


def test_viewers_cannot_pull_draft_findings(admin, engagement, make_user):
    base = _report_fixture(admin, engagement)
    viewer = make_user("client@test.local", role="viewer")
    uid = next(u["id"] for u in admin.ok("GET", "/api/users") if u["email"] == "client@test.local")
    admin.ok("PUT", f"{base}/members", json={"user_id": uid, "role": "viewer"})
    html = viewer.get(f"{base}/report?include_drafts=true").text
    assert "Stored XSS" in html and "Unconfirmed lead" not in html


def test_markdown_and_json_report(admin, engagement):
    base = _report_fixture(admin, engagement)
    md = admin.get(f"{base}/report?format=md&download=true")
    assert md.headers["content-disposition"] == 'attachment; filename="ACME-EXT-report.md"'
    assert "## 5. Detailed findings" in md.text and "Stored XSS" in md.text

    data = json.loads(admin.get(f"{base}/report?format=json").text)
    assert data["total_findings"] == 1 and data["severity_counts"]["high"] == 1
    assert data["findings"][0]["targets"] == ["203.0.113.10"]
    assert "data_uri" not in json.dumps(data)  # images only embedded in HTML
    events = admin.ok("GET", f"{base}/activity")
    assert any(e["action"] == "export" and e["entity_type"] == "report" for e in events)


def test_delete_engagement_removes_evidence_files(admin, engagement):
    def stored_files():
        return {p for p in get_settings().storage_dir.rglob("*") if p.is_file()}

    before = stored_files()
    admin.ok("POST", f"{_base(engagement)}/evidence", files={"file": ("a.txt", b"secret")})
    added = stored_files() - before
    assert len(added) == 1
    admin.ok("DELETE", _base(engagement))
    assert admin.get(_base(engagement)).status_code == 404
    assert not (added & stored_files())
    events = admin.ok("GET", "/api/audit")
    assert events[0]["action"] == "delete" and events[0]["entity_type"] == "engagement"


def test_health_headers_and_dashboard(admin, engagement):
    r = admin.get("/api/health")
    assert r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert admin.get("/api/nope").status_code == 404
    d = admin.ok("GET", "/api/dashboard")
    assert d["engagements_by_status"] == {"planning": 1}
    assert d["active_engagements"][0]["code"] == "ACME-EXT"


def test_api_docs_have_their_own_csp(admin):
    assert admin.get("/api/openapi.json").json()["info"]["title"] == "OffsecHub"
    r = admin.get("/api/docs")
    assert r.status_code == 200 and "cdn.jsdelivr.net" in r.headers["content-security-policy"]
    # The strict SPA policy still applies everywhere else.
    assert "cdn.jsdelivr.net" not in admin.get("/").headers["content-security-policy"]
