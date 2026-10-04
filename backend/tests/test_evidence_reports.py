import asyncio
import hashlib
import json
import tempfile

import pytest

from app.config import get_settings
from app.models import Evidence
from app.services import storage
from app.vault.crypto import CryptoError
from app.vault.manager import BlobIntegrityError, VaultLocked

from .conftest import wait_until

PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15"
       b"\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff\x89\x99=\x1d\x00\x00"
       b"\x00\x00IEND\xaeB`\x82")


def _base(eng):
    return f"/api/engagements/{eng['id']}"


def _upload(api, eng, filename, data, content_type="application/octet-stream", **params):
    """Raw-body upload, like the UI's fetch(url, {body: file})."""
    return api.post(f"{_base(eng)}/evidence/upload", params={"filename": filename, **params},
                    content=data, headers={"Content-Type": content_type})


def _row(vault, evidence_id) -> Evidence:
    with vault.session() as db:
        return db.get(Evidence, evidence_id)


def _blob_file(vault, evidence_id):
    key = _row(vault, evidence_id).storage_key
    return vault.path / "blobs" / key[:2] / key


# ---------------------------------------------------------------- evidence


def test_upload_and_download_evidence(api, engagement):
    f = api.ok("POST", f"{_base(engagement)}/findings", json={"title": "Has evidence"})
    r = _upload(api, engagement, "../../etc/shot.png", PNG, "image/png",
                description="screenshot", finding_id=f["id"])
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["filename"] == "shot.png"  # path components stripped
    assert ev["sha256"] == hashlib.sha256(PNG).hexdigest() and ev["size"] == len(PNG)
    assert ev["is_image"] and ev["description"] == "screenshot" and ev["finding_id"] == f["id"]
    assert not {"blob_key", "storage_key", "uploaded_by"} & set(ev)

    r = api.get(f"{_base(engagement)}/evidence/{ev['id']}/download")
    assert r.content == PNG and r.headers["content-disposition"].startswith("attachment")
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-length"] == str(len(PNG))
    assert r.headers["x-content-sha256"] == ev["sha256"]
    assert r.headers["content-security-policy"] == "default-src 'none'; sandbox"
    r = api.get(f"{_base(engagement)}/evidence/{ev['id']}/download?inline=true")
    assert r.headers["content-type"] == "image/png"
    assert r.headers["content-disposition"].startswith("inline")
    assert api.ok("GET", f"{_base(engagement)}/findings/{f['id']}")["evidence_count"] == 1
    linked = api.ok("GET", f"{_base(engagement)}/evidence?finding_id={f['id']}")
    assert [e["id"] for e in linked] == [ev["id"]]


@pytest.mark.parametrize("filename,ctype,body", [
    ("x.svg", "image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'),
    ("page.html", "text/html", b"<script>alert(1)</script>"),
    ("shot.png", "application/octet-stream", b"not really a png"),  # type guessed from the name
])
def test_only_raster_images_are_served_inline(api, engagement, filename, ctype, body):
    ev = _upload(api, engagement, filename, body, ctype).json()
    r = api.get(f"{_base(engagement)}/evidence/{ev['id']}/download?inline=true")
    if ev["is_image"]:
        assert ev["content_type"] == "image/png"
        assert r.headers["content-disposition"].startswith("inline")
    else:
        assert r.headers["content-disposition"].startswith("attachment")
        assert r.headers["content-type"] == "application/octet-stream"
    assert "sandbox" in r.headers["content-security-policy"]


def test_large_upload_is_streamed_into_the_vault(api, engagement, vault, monkeypatch):
    """> 1 MiB is where multipart would spool plaintext to a temp file."""
    def no_spooling(*_args, **_kwargs):  # pragma: no cover - must never run
        raise AssertionError("the request body was spooled to a temporary file")

    monkeypatch.setattr(tempfile.SpooledTemporaryFile, "rollover", no_spooling)
    marker = b"PLAINTEXT-EVIDENCE-MARKER|"
    data = marker * (3 * 2**20 // len(marker))
    chunks = (data[i:i + 100_000] for i in range(0, len(data), 100_000))  # chunked, no Content-Length
    r = _upload(api, engagement, "capture.pcap", chunks, "application/vnd.tcpdump.pcap")
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["size"] == len(data) and ev["sha256"] == hashlib.sha256(data).hexdigest()

    download = api.get(f"{_base(engagement)}/evidence/{ev['id']}/download")
    assert download.content == data
    blob = _blob_file(vault, ev["id"]).read_bytes()
    assert len(blob) > len(data) and marker not in blob
    assert not any(marker in p.read_bytes() for p in vault.path.rglob("*") if p.is_file())


def test_multipart_is_refused(api, engagement, vault):
    r = api.post(f"{_base(engagement)}/evidence/upload", params={"filename": "a.txt"},
                 files={"file": ("a.txt", b"hello")})
    assert r.status_code == 415
    assert vault.blob_ids_on_disk() == set()


def test_download_verifies_size_and_fingerprint(api, engagement, vault):
    ev = _upload(api, engagement, "notes.txt", b"original evidence" * 1000, "text/plain").json()
    url = f"{_base(engagement)}/evidence/{ev['id']}/download"
    with vault.session() as db:
        db.get(Evidence, ev["id"]).sha256 = "0" * 64
        db.commit()
    # The transfer is aborted rather than completed with a file that doesn't match.
    with pytest.raises(BlobIntegrityError):
        api.get(url)

    path = _blob_file(vault, ev["id"])
    raw = bytearray(path.read_bytes())
    raw[-20] ^= 1
    path.write_bytes(bytes(raw))
    with pytest.raises(CryptoError):
        api.get(url)

    path.unlink()
    assert api.get(url).status_code == 410


def test_locking_stops_transfers_in_flight(api, engagement, vault, app_ctx):
    manager = app_ctx[1]
    ev = _upload(api, engagement, "big.bin", b"x" * 200_000).json()
    row = _row(vault, ev["id"])
    downloading = storage.stream_evidence(vault, row)
    assert len(next(downloading)) == 64 * 1024

    async def body():
        yield b"a" * 100_000
        manager.lock()
        yield b"b" * 100_000

    with pytest.raises(VaultLocked):
        asyncio.run(storage.receive_blob(vault, body()))
    with pytest.raises(VaultLocked):
        next(downloading)
    # The partial upload is gone; only the committed blob remains.
    assert [p.name for p in (vault.path / "blobs").rglob("*") if p.is_file()] == [row.storage_key]


def test_text_evidence(api, engagement):
    content = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    ev = api.ok("POST", f"{_base(engagement)}/evidence/text",
                json={"filename": "request", "content": content, "description": "raw request"})
    assert ev["filename"] == "request.txt" and ev["content_type"] == "text/plain"
    assert ev["sha256"] == hashlib.sha256(content.encode()).hexdigest()
    r = api.get(f"{_base(engagement)}/evidence/{ev['id']}/download")
    assert r.text == content


def test_upload_limits_and_empty_files(api, engagement, vault):
    settings = get_settings()
    old, settings.max_upload_mb = settings.max_upload_mb, 1
    big = b"0" * (2**20 + 1)
    try:
        assert _upload(api, engagement, "big.bin", big).status_code == 413  # Content-Length
        assert _upload(api, engagement, "big.bin", iter([big[:2**19], big[2**19:]])).status_code == 413
        r = api.post(f"{_base(engagement)}/evidence/text",
                     json={"filename": "t", "content": "x" * len(big)})
        assert r.status_code == 413
    finally:
        settings.max_upload_mb = old
    assert _upload(api, engagement, "empty.txt", b"").status_code == 422
    assert api.post(f"{_base(engagement)}/evidence/upload", content=b"no name").status_code == 422
    assert vault.blob_ids_on_disk() == set()


def test_evidence_links_must_be_in_the_same_engagement(api, engagement, vault):
    other_client = api.ok("POST", "/api/clients", json={"name": "Other"})
    other = api.ok("POST", "/api/engagements", json={
        "client_id": other_client["id"], "name": "Other", "code": "OTHER", "type": "api"})
    f = api.ok("POST", f"{_base(other)}/findings", json={"title": "elsewhere"})
    assert _upload(api, engagement, "a.txt", b"hi", finding_id=f["id"]).status_code == 404
    assert _upload(api, {"id": 999}, "a.txt", b"hi").status_code == 404
    assert vault.blob_ids_on_disk() == set()

    ev = _upload(api, engagement, "a.txt", b"hi").json()
    r = api.patch(f"{_base(engagement)}/evidence/{ev['id']}", json={"finding_id": f["id"]})
    assert r.status_code == 404
    assert api.get(f"{_base(other)}/evidence/{ev['id']}/download").status_code == 404


def test_update_and_delete_evidence_removes_the_blob(api, engagement, vault):
    t = api.ok("POST", f"{_base(engagement)}/targets", json={"value": "203.0.113.10"})
    ev = _upload(api, engagement, "a.txt", b"secret").json()
    ev = api.ok("PATCH", f"{_base(engagement)}/evidence/{ev['id']}",
                json={"target_id": t["id"], "description": "banner"})
    assert ev["target_id"] == t["id"] and ev["description"] == "banner"
    path = _blob_file(vault, ev["id"])
    assert path.exists()

    api.ok("DELETE", f"{_base(engagement)}/evidence/{ev['id']}")
    assert api.ok("GET", f"{_base(engagement)}/evidence") == []
    # Removed once no retained snapshot references it (the saver does that promptly).
    assert wait_until(lambda: not path.exists())
    events = api.ok("GET", f"{_base(engagement)}/activity")
    assert events[0]["action"] == "delete" and events[0]["entity_type"] == "evidence"


def test_delete_engagement_removes_evidence_blobs(api, engagement, vault):
    for name in ("a.txt", "b.txt"):
        _upload(api, engagement, name, name.encode() * 100)
    assert len(vault.blob_ids_on_disk()) == 2

    api.ok("DELETE", _base(engagement))
    assert api.get(_base(engagement)).status_code == 404
    assert wait_until(lambda: not vault.blob_ids_on_disk())
    events = api.ok("GET", "/api/activity")
    assert events[0]["action"] == "delete" and events[0]["entity_type"] == "engagement"
    assert "2 evidence files" in events[0]["summary"]


# ----------------------------------------------------------------- reports


PROFILE = {"name": "Riley Chen", "organization": "Example Security Ltd",
           "email": "riley@example-security.test"}


def _report_fixture(api, engagement):
    base = _base(engagement)
    api.ok("PUT", "/api/profile", json=PROFILE)
    api.ok("PATCH", base, json={"executive_summary": "Overall posture is weak."})
    t = api.ok("POST", f"{base}/targets",
               json={"value": "203.0.113.10", "hostname": "www.acme-corp.example"})
    f = api.ok("POST", f"{base}/findings", json={
        "title": "<script>alert('xss')</script> Stored XSS", "status": "confirmed",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", "target_ids": [t["id"]],
        "description": "Payload <img src=x onerror=alert(1)>"})
    draft = api.ok("POST", f"{base}/findings", json={"title": "Unconfirmed lead", "status": "draft"})
    api.ok("POST", f"{base}/findings", json={"title": "Not real", "status": "false_positive"})
    _upload(api, engagement, "shot.png", PNG, "image/png", finding_id=f["id"])
    api.ok("POST", f"{base}/evidence/text",
           json={"filename": "request.txt", "content": "GET /comments", "finding_id": f["id"]})
    api.ok("POST", f"{base}/evidence/text",
           json={"filename": "draft-notes.txt", "content": "maybe", "finding_id": draft["id"]})
    return base


def test_html_report(api, engagement):
    base = _report_fixture(api, engagement)
    r = api.get(f"{base}/report")
    assert r.status_code == 200
    html = r.text
    assert "Overall posture is weak." in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt; Stored XSS" in html
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "Unconfirmed lead" not in html and "Not real" not in html
    assert "ACME-EXT-001" in html and "203.0.113.10" in html
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp

    with_drafts = api.get(f"{base}/report?include_drafts=true").text
    assert "Unconfirmed lead" in with_drafts and "Not real" not in with_drafts
    assert "draft-notes.txt" in with_drafts and "draft-notes.txt" not in html


def test_report_embeds_images_lists_fingerprints_and_preparer(api, engagement):
    base = _report_fixture(api, engagement)
    html = api.get(f"{base}/report").text
    assert "data:image/png;base64," in html  # decrypted and verified from the vault
    assert "Appendix B: evidence fingerprints" in html
    assert hashlib.sha256(PNG).hexdigest() in html
    assert hashlib.sha256(b"GET /comments").hexdigest() in html and "13 bytes" in html
    assert "chain of custody" not in html.lower()
    assert "Prepared by" in html and "Riley Chen, Example Security Ltd" in html
    assert PROFILE["email"] in html

    md = api.get(f"{base}/report?format=md").text
    assert "## Appendix B: evidence fingerprints" in md
    assert f"| ACME-EXT-001 | shot.png | {len(PNG)} bytes | `{hashlib.sha256(PNG).hexdigest()}` |" in md
    assert "### Prepared by" in md and "- Organization: Example Security Ltd" in md

    data = json.loads(api.get(f"{base}/report?format=json").text)
    assert data["prepared_by"] == PROFILE
    assert [e["filename"] for e in data["evidence_fingerprints"]] == ["shot.png", "request.txt"]


def test_report_never_embeds_an_unverified_image(api, engagement, vault):
    base = _report_fixture(api, engagement)
    shot = next(e for e in api.ok("GET", f"{base}/evidence") if e["filename"] == "shot.png")
    with vault.session() as db:
        db.get(Evidence, shot["id"]).sha256 = "0" * 64
        db.commit()
    html = api.get(f"{base}/report").text
    assert "data:image/png" not in html and "could not be verified" in html


def test_report_without_profile_or_evidence(api, engagement):
    html = api.get(f"{_base(engagement)}/report").text
    assert "No evidence is attached to the reported findings." in html
    assert "Prepared by" not in html


def test_markdown_and_json_report(api, engagement):
    base = _report_fixture(api, engagement)
    md = api.get(f"{base}/report?format=md&download=true")
    assert md.headers["content-disposition"] == 'attachment; filename="ACME-EXT-report.md"'
    assert "## 5. Detailed findings" in md.text and "Stored XSS" in md.text

    raw = api.get(f"{base}/report?format=json").text
    data = json.loads(raw)
    assert data["total_findings"] == 1 and data["severity_counts"]["high"] == 1
    assert data["findings"][0]["targets"] == ["203.0.113.10"]
    assert "data_uri" not in raw  # images are only embedded in HTML
    assert "blob_key" not in raw and "storage_key" not in raw
    events = api.ok("GET", f"{base}/activity")
    assert any(e["action"] == "export" and e["entity_type"] == "report" for e in events)


# ---------------------------------------------------------------- general


def test_health_headers_and_dashboard(api, engagement):
    r = api.get("/api/health")
    assert r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert api.get("/api/nope").status_code == 404
    d = api.ok("GET", "/api/dashboard")
    assert d["engagements_by_status"] == {"planning": 1} and d["open_tests"] == 0
    assert d["active_engagements"][0]["code"] == "ACME-EXT"
    assert "my_role" not in d["active_engagements"][0]


def test_clients_and_engagements(api, engagement):
    clients = api.ok("GET", "/api/clients")
    assert [(c["name"], c["engagement_count"]) for c in clients] == [("ACME", 1)]
    acme = clients[0]
    assert api.post("/api/clients", json={"name": "ACME"}).status_code == 409
    assert api.delete(f"/api/clients/{acme['id']}").status_code == 409  # still has engagements
    api.ok("PATCH", f"/api/clients/{acme['id']}", json={"industry": "Manufacturing"})

    base = _base(engagement)
    assert api.patch(base, json={"end_date": "2026-08-01"}).status_code == 422  # before start
    eng = api.ok("PATCH", base, json={"status": "active", "end_date": None})
    assert eng["status"] == "active" and eng["end_date"] is None
    assert [e["code"] for e in api.ok("GET", "/api/engagements?status=active")] == ["ACME-EXT"]
    dup = {"client_id": acme["id"], "name": "Dup", "code": "acme-ext", "type": "api"}
    assert api.post("/api/engagements", json=dup).status_code == 409

    api.ok("DELETE", base)
    api.ok("DELETE", f"/api/clients/{acme['id']}")
    assert api.ok("GET", "/api/clients") == []


def test_openapi_is_served_but_interactive_docs_are_not(api):
    assert api.get("/api/openapi.json").json()["info"]["title"] == "OffsecHub"
    assert api.get("/api/docs").status_code == 404
