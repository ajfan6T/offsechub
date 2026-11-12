"""Word reports: the built-in template, user templates and their safety checks."""

import io
import zipfile

import pytest
from docx import Document
from PIL import Image

from app.services.report_docx import BUILTIN, TemplateProblem, check_template


def _png(color=(200, 30, 30), size=(320, 180), fmt="PNG") -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, fmt)
    return buf.getvalue()


@pytest.fixture
def report_setup(api, engagement):
    base = f"/api/engagements/{engagement['id']}"
    t = api.ok("POST", f"{base}/targets", json={"value": "203.0.113.4"})
    f = api.ok("POST", f"{base}/findings", json={
        "title": "Exposed Git repository <b>", "status": "confirmed", "target_ids": [t["id"]],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "The **.git** folder is served:\n\n- `config` leaks the remote\n- objects can be fetched\n\n"
                       "See [docs](https://git-scm.com/docs) & <script>alert(1)</script>\x07",
        "steps_to_reproduce": "GET /.git/config HTTP/1.1\nHost: www.acme-corp.example",
        "remediation": "1. Block `/.git/`\n2. Rotate credentials",
    })
    api.ok("POST", f"{base}/findings/{f['id']}/retests",
           json={"tested_on": "2026-10-20", "result": "not_resolved", "notes": "Still **served**"})
    api.ok("POST", f"{base}/evidence/upload?filename=shot.png&finding_id={f['id']}",
           content=_png(), headers={"Content-Type": "image/png"})
    api.ok("POST", f"{base}/evidence/upload?filename=shot.webp&finding_id={f['id']}",
           content=_png((20, 120, 200), fmt="WEBP"), headers={"Content-Type": "image/webp"})
    api.ok("PATCH", base, json={"executive_summary": "Overall risk is **moderate**.",
                                "rules_of_engagement": "No DoS."})
    return base


def _docx(api, url) -> Document:
    r = api.get(url)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/vnd.openxmlformats-officedocument")
    assert "attachment" in r.headers["content-disposition"]
    return Document(io.BytesIO(r.content))


def _text(doc: Document) -> str:
    parts = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        for row in t.rows:
            parts.extend(c.text for c in row.cells)
    return "\n".join(parts)


def test_builtin_docx_report(api, report_setup):
    doc = _docx(api, f"{report_setup}/report?format=docx")
    text = _text(doc)
    assert "ACME-EXT-001  Exposed Git repository <b>" in text
    assert "<script>alert(1)</script>" in text  # literal text, never markup
    assert "\x07" not in text
    assert "Overall risk is moderate." in text and "Not resolved" in text and "Still served" in text
    assert "5.3 (CVSS v3.1) CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" in text
    styles = {p.style.name for p in doc.paragraphs}
    assert {"List Bullet", "OH Numbered", "OH Code", "Heading 1", "Heading 2"} <= styles
    code = [p.text for p in doc.paragraphs if p.style.name == "OH Code"]
    assert "GET /.git/config HTTP/1.1\nHost: www.acme-corp.example" in code
    numbered = [p.text for p in doc.paragraphs if p.style.name == "OH Numbered" and "Block" in p.text]
    assert numbered == ["1.\tBlock /.git/"]
    bold = [r.text for p in doc.paragraphs for r in p.runs if r.bold]
    assert ".git" in bold and "moderate" in bold
    # Both screenshots are embedded (the WebP one converted to PNG).
    assert len(doc.inline_shapes) == 2
    with zipfile.ZipFile(io.BytesIO(api.get(f"{report_setup}/report?format=docx").content)) as zf:
        rels = zf.read("word/_rels/document.xml.rels").decode()
    assert "https://git-scm.com/docs" in rels and "javascript" not in rels
    # No unrendered template tags are left behind.
    assert "{{" not in text and "{%" not in text


def test_branding_reaches_the_docx(api, report_setup):
    api.ok("PUT", "/api/report-branding", json={"organization": "Example Security Ltd", "accent": "#1d4ed8",
                                                "classification": "TLP:AMBER", "footer": "Example footer"})
    api.ok("POST", "/api/report-branding/logo", content=_png((10, 10, 10), (400, 120)),
           headers={"Content-Type": "image/png"})
    doc = _docx(api, f"{report_setup}/report?format=docx")
    text = _text(doc)
    assert "Example Security Ltd" in text and "TLP:AMBER. This report contains" in text
    header = doc.sections[0].header.paragraphs[0].text
    assert "TLP:AMBER" in header and "ACME-EXT" in header
    assert "Example footer" in doc.sections[0].footer.paragraphs[0].text
    assert doc.styles["Heading 1"].font.color.rgb == (0x1D, 0x4E, 0xD8)
    assert len(doc.inline_shapes) == 3  # logo + two screenshots


def _template_bytes(body: str) -> bytes:
    doc = Document(str(BUILTIN))
    doc.add_paragraph(body)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def test_user_templates(api, report_setup):
    builtin = api.get("/api/report-templates/builtin/download")
    assert builtin.status_code == 200 and builtin.content == BUILTIN.read_bytes()

    data = _template_bytes("CUSTOM {{ client.name }} {{ findings|length }} findings")
    tpl = api.ok("POST", "/api/report-templates/upload?filename=house.docx&name=House style", content=data,
                 headers={"Content-Type": "application/octet-stream"})
    assert tpl["name"] == "House style" and tpl["size"] == len(data)
    listed = api.ok("GET", "/api/report-templates")
    assert [t["name"] for t in listed] == ["House style"]
    assert api.get(f"/api/report-templates/{tpl['id']}/download").content == data

    text = _text(_docx(api, f"{report_setup}/report?format=docx&template_id={tpl['id']}"))
    assert "CUSTOM ACME 1 findings" in text
    # As the default template it applies without template_id; the built-in one still uses no id.
    api.ok("PUT", "/api/report-branding", json={"default_template_id": tpl["id"]})
    assert "CUSTOM ACME" in _text(_docx(api, f"{report_setup}/report?format=docx"))
    assert api.get(f"{report_setup}/report?format=docx&template_id=999").status_code == 404

    api.ok("DELETE", f"/api/report-templates/{tpl['id']}")
    assert api.ok("GET", "/api/report-branding")["default_template_id"] is None
    assert "CUSTOM" not in _text(_docx(api, f"{report_setup}/report?format=docx"))


@pytest.mark.parametrize("body, message", [
    ("{{ ''.__class__.__mro__[1].__subclasses__() }}", "could not be rendered"),
    ("{{ 'x' * 100000000 }}", "could not be rendered"),
    ("{% for x in %}", "syntax error"),
])
def test_hostile_templates_are_refused(api, report_setup, body, message):
    r = api.post("/api/report-templates/upload?filename=t.docx&name=t", content=_template_bytes(body),
                 headers={"Content-Type": "application/octet-stream"})
    if r.status_code == 201:  # syntax is fine; the sandbox stops it at render time
        out = api.get(f"{report_setup}/report?format=docx&template_id={r.json()['id']}")
        assert out.status_code == 422 and message in out.json()["detail"], out.text
    else:
        assert r.status_code == 422 and message in r.json()["detail"], r.text


def test_template_file_checks():
    with pytest.raises(TemplateProblem, match="not a Word document"):
        check_template(b"not a zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
    with pytest.raises(TemplateProblem, match="not allowed"):
        check_template(buf.getvalue())
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", "<x/>")
        zf.writestr("big.bin", b"\0" * (70 * 1024 * 1024))
    with pytest.raises(TemplateProblem, match="too large once unpacked"):
        check_template(bomb.getvalue())
    check_template(BUILTIN.read_bytes())


def test_logo_must_be_an_image(api):
    r = api.post("/api/report-branding/logo", content=b"<svg></svg>", headers={"Content-Type": "image/svg+xml"})
    assert r.status_code == 422
    assert api.put("/api/report-branding", json={"accent": "red"}).status_code == 422


def test_pdf_report_through_the_api(api, report_setup):
    from pypdf import PdfReader

    r = api.get(f"{report_setup}/report?format=pdf&download=1")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"].startswith("attachment;")
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(r.content)).pages)
    assert "Exposed Git repository <b>" in text
    assert "<script>alert(1)</script>" in text
    assert "Not resolved" in text and "CVSS v3.1" in text


def _render_with(api, report_setup, body):
    r = api.post("/api/report-templates/upload?filename=t.docx&name=t", content=_template_bytes(body),
                 headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 201, r.text
    return api.get(f"{report_setup}/report?format=docx&template_id={r.json()['id']}")


def test_templates_cannot_reach_the_document_objects(api, report_setup, tmp_path):
    # InlineImage.tpl is the live DocxTemplate: save() would write anywhere on disk.
    api.ok("POST", "/api/report-branding/logo", content=_png(), headers={"Content-Type": "image/png"})
    target = tmp_path / "written.docx"
    for body in (
        "{% for f in findings %}{% for i in f.images %}{{ i.inline.tpl.save('" + str(target) + "') }}{% endfor %}{% endfor %}",
        "{{ logo.tpl.save('" + str(target) + "') }}",
        "{{ logo['tpl'].docx }}",
        "{{ logo|attr('tpl')|attr('docx') }}",
        "{{ ((findings|first).rt.description|attr('xml')).strip() }}",
        "{{ rt.executive_summary.__class__.__mro__ }}",
    ):
        out = _render_with(api, report_setup, body)
        assert out.status_code == 422 and "unsafe" in out.json()["detail"], (body, out.text)
    assert not target.exists()


@pytest.mark.parametrize("body", [
    "{{ 'A'.center(1500000000) }}",
    "{{ 'x'.ljust(500000000) }}",
    "{{ 'A'|center(10**9) }}",
    "{{ '%0500000000d' % 1 }}",
    "{{ '%0500000000d'|format(1) }}",
    "{{ ((10**100)**100)**100 }}",
    "{{ ''|indent(1000000000) }}",
])
def test_template_blow_ups_are_refused(api, report_setup, body):
    out = _render_with(api, report_setup, body)
    assert out.status_code == 422 and "could not be rendered" in out.json()["detail"], out.text


def test_a_template_that_runs_too_long_is_stopped(api, report_setup, monkeypatch):
    import app.services.report_docx as report_docx

    monkeypatch.setattr(report_docx, "RENDER_TIMEOUT_S", 3)
    body = "{% for i in range(100000) %}{% for j in range(100000) %}{% endfor %}{% endfor %}"
    out = _render_with(api, report_setup, body)
    assert out.status_code == 422 and "longer than 3 seconds" in out.json()["detail"], out.text
    # The app is unaffected and keeps rendering.
    assert api.get(f"{report_setup}/report?format=docx").status_code == 200


def test_declarations_are_found_in_any_part_and_encoding():
    def docx_with(name, data):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("word/document.xml", "<x/>")
            zf.writestr(name, data)
        return buf.getvalue()

    declaration = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "e">]><x>&e;</x>'
    for name, data in (("word/header1.XML", declaration.encode()),
                       ("customXml/item1", declaration.encode()),
                       ("word/footer1.xml", "﻿".encode("utf-16-le") + declaration.encode("utf-16-le"))):
        with pytest.raises(TemplateProblem, match="not allowed"):
            check_template(docx_with(name, data))
    # Pictures are never parsed as XML, so an SVG's DOCTYPE there is fine (the file is then
    # refused for other reasons, being no real template, but not for the declaration).
    with pytest.raises(TemplateProblem) as exc:
        check_template(docx_with("word/media/image1.svg", declaration.encode()))
    assert "not allowed" not in str(exc.value)


def test_control_characters_in_branding_never_reach_word(api, report_setup):
    api.ok("PUT", "/api/report-branding", json={"organization": "Example\x07 Security\x0b Ltd"})
    text = _text(_docx(api, f"{report_setup}/report?format=docx"))
    assert "Example Security Ltd" in text and "\x07" not in text
