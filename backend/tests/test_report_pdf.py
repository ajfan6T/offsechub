"""PDF report rendering (services/report_pdf.py)."""

import base64
import copy
import hashlib
import re
import struct
import time
import zlib
from io import BytesIO

import pytest
from PIL import Image
from pypdf import PdfReader

from app.models import Engagement, Evidence
from app.services import reporting, storage
from app.services.report_pdf import render_pdf

from .test_evidence_reports import PNG, PROFILE, _base, _report_fixture, _upload

STANDARD_FONTS = ("Helvetica", "Times", "Courier", "Symbol", "ZapfDingbats")


# ------------------------------------------------------------------ helpers


def _reader(pdf: bytes) -> PdfReader:
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    return PdfReader(BytesIO(pdf))


def _pages(pdf: bytes) -> list[str]:
    return [p.extract_text() for p in _reader(pdf).pages]


def _text(pdf: bytes) -> str:
    return "\n".join(_pages(pdf))


def _flat(text: str) -> str:
    """Extracted text without any whitespace, for strings that may wrap anywhere."""
    return re.sub(r"\s+", "", text)


def _norm(text: str) -> str:
    """Extracted text with runs of whitespace as one space, for strings that wrap at spaces."""
    return re.sub(r"\s+", " ", text)


def _images(pdf: bytes) -> list:
    """Image XObjects drawn on the pages (soft masks are not counted)."""
    found = {}
    for page in _reader(pdf).pages:
        xobjects = (page.get("/Resources") or {}).get("/XObject") or {}
        for ref in xobjects.values():
            obj = ref.get_object()
            if obj.get("/Subtype") == "/Image":
                found[ref.idnum] = obj
    return list(found.values())


def _fonts(pdf: bytes) -> set[str]:
    names = set()
    for page in _reader(pdf).pages:
        for ref in ((page.get("/Resources") or {}).get("/Font") or {}).values():
            names.add(str(ref.get_object()["/BaseFont"]))
    return names


def _link_uris(pdf: bytes) -> list[str]:
    uris = []
    for page in _reader(pdf).pages:
        for annot in page.get("/Annots") or []:
            action = annot.get_object().get("/A") or {}
            if "/URI" in action:
                uris.append(str(action["/URI"]))
    return uris


def _png(size=(640, 360), mode="RGB", colour="teal") -> bytes:
    im = Image.new(mode, size, colour)
    buf = BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def _jpeg(size=(800, 600)) -> bytes:
    buf = BytesIO()
    Image.new("RGB", size, (200, 30, 30)).save(buf, "JPEG", quality=80)
    return buf.getvalue()


def _png_claiming(width: int, height: int) -> bytes:
    """A tiny PNG whose header claims huge dimensions (a decompression bomb's shape)."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\0" * 64))
            + chunk(b"IEND", b""))


def _finding(i: int = 1, **kw) -> dict:
    row = {
        "id": i, "ref": f"GLX-{i:03d}", "title": f"Finding number {i}", "severity": "medium",
        "status": "confirmed", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_version": "3.1", "cvss_score": 5.3, "cwe": "CWE-200",
        "description": "Description text.", "impact": "Impact text.",
        "steps_to_reproduce": "", "remediation": "Remediation text.", "references": [],
        "targets": ["203.0.113.10"], "images": [], "attachments": [], "retests": [],
        "retest_status": None,
    }
    row.update(kw)
    return row


def _ctx(findings=None, **kw) -> dict:
    """A synthetic report context shaped like reporting.build_context's."""
    findings = [_finding(1)] if findings is None else findings
    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ("critical", "high", "medium", "low", "info")}
    ctx = {
        "engagement": {"name": "Perimeter review", "code": "GLX-WEB", "status": "active",
                       "type": "Web Application Penetration Test", "start_date": "2026-10-01",
                       "end_date": "2026-10-14", "description": "Background.",
                       "rules_of_engagement": "No DoS.", "executive_summary": "Summary."},
        "client": {"name": "Globex Corporation", "contact_name": ""},
        "prepared_by": {"name": "Sam Okafor", "organization": "Okafor Security",
                        "email": "sam@example.test"},
        "scope": {"include": [{"kind": "domain", "value": "globex.example", "notes": "Main site"}],
                  "exclude": []},
        "severity_counts": counts,
        "total_findings": len(findings),
        "findings": findings,
        "evidence_fingerprints": [],
        "coverage": [{"methodology": "OWASP WSTG", "total": 10, "passed": 6, "failed": 2,
                      "not_applicable": 1, "blocked": 0, "incomplete": 1}],
        "targets": [{"value": "203.0.113.10", "hostname": "www.globex.example",
                     "ip": "203.0.113.10", "os": "Linux", "status": "tested",
                     "services": ["443/tcp https nginx 1.25"]}],
        "generated_at": "2026-11-11 10:00 UTC",
        "draft": False,
    }
    ctx.update(kw)
    return ctx


def _vault_context(vault, engagement, **kw) -> dict:
    with vault.session() as db:
        eng = db.get(Engagement, engagement["id"])
        return reporting.build_context(
            eng, profile=PROFILE, read_image=lambda ev: storage.read_evidence(vault, ev), **kw)


# ------------------------------------------------------------------ from a vault


def test_pdf_report_from_a_vault_engagement(api, engagement, vault):
    _report_fixture(api, engagement)
    pdf = render_pdf(_vault_context(vault, engagement))
    pages = _pages(pdf)
    text = "\n".join(pages)

    assert len(pages) > 1
    assert "ACME" in pages[0] and "External test" in pages[0]
    assert "External Network Penetration Test" in pages[0]
    assert "Reference ACME-EXT" in pages[0]
    assert "Testing window 2026-09-01 to 2026-09-30" in pages[0]
    assert "Prepared by Riley Chen, Example Security Ltd" in pages[0]
    assert "DRAFT - not for distribution" in pages[0]  # still planning, so a draft
    assert "Overall posture is weak." in text
    # The title is shown as typed: never markup, in the details, the summary and the contents.
    assert text.count("<script>alert('xss')</script> Stored XSS") >= 3
    assert "Payload <img src=x onerror=alert(1)>" in text
    assert "ACME-EXT-001" in text and "203.0.113.10" in text
    assert "1 finding reported." in text
    assert "CVSS v3.1" in text and "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N" in text
    assert "Unconfirmed lead" not in text and "Not real" not in text

    # Evidence: the image is embedded and captioned with its short fingerprint; every
    # file is listed with its full SHA-256 in the appendix.
    png_sha = hashlib.sha256(PNG).hexdigest()
    request_sha = hashlib.sha256(b"GET /comments").hexdigest()
    assert len(_images(pdf)) == 1
    assert f"shot.png (fingerprint {png_sha[:16]})" in text
    assert "Appendix B: evidence fingerprints" in text
    assert png_sha in text and request_sha in text  # each on one line, not wrapped
    assert "13 bytes" in text and "draft-notes.txt" not in text
    assert "Prepared by" in pages[-1] and PROFILE["email"] in pages[-1]

    with_drafts = _text(render_pdf(_vault_context(vault, engagement, include_drafts=True)))
    assert "Unconfirmed lead" in with_drafts and "draft-notes.txt" in with_drafts
    assert "Not real" not in with_drafts


def test_pdf_running_header_footer_and_page_numbers(api, engagement, vault):
    _report_fixture(api, engagement)
    pages = _pages(render_pdf(_vault_context(vault, engagement)))
    total = len(pages)
    assert "Page 1 of" not in pages[0]  # the cover carries no running header or footer
    for number, page in enumerate(pages[1:], start=2):
        assert f"Page {number} of {total}" in page
        assert "CONFIDENTIAL" in page and "ACME-EXT" in page and "DRAFT" in page
        assert "Generated by OffsecHub on" in page


def test_delivered_report_is_not_marked_draft(api, engagement, vault):
    _report_fixture(api, engagement)
    api.ok("PATCH", _base(engagement), json={"status": "delivered"})
    text = _text(render_pdf(_vault_context(vault, engagement)))
    assert "DRAFT" not in text


def test_pdf_never_embeds_an_unverified_image(api, engagement, vault):
    base = _report_fixture(api, engagement)
    shot = next(e for e in api.ok("GET", f"{base}/evidence") if e["filename"] == "shot.png")
    with vault.session() as db:
        db.get(Evidence, shot["id"]).sha256 = "0" * 64
        db.commit()
    pdf = render_pdf(_vault_context(vault, engagement))
    assert _images(pdf) == []
    assert _flat("could not be verified; not embedded") in _flat(_text(pdf))


def test_pdf_embeds_real_images_from_the_vault(api, engagement, vault):
    f = api.ok("POST", f"{_base(engagement)}/findings",
               json={"title": "Screens", "status": "confirmed"})
    for name, data, ctype in [("wide.png", _png((1600, 900)), "image/png"),
                              ("photo.jpg", _jpeg(), "image/jpeg")]:
        assert _upload(api, engagement, name, data, ctype, finding_id=f["id"]).status_code == 201
    pdf = render_pdf(_vault_context(vault, engagement))
    images = _images(pdf)
    assert len(images) == 2
    assert any("/DCTDecode" in str(img.get("/Filter")) for img in images)  # JPEG passed through


# ------------------------------------------------------------------ escaping


INJECTIONS = ['<font name="x">', "<para>", "&amp;", "AT&T", "<br/>", "</b>", "<b>not bold</b>",
              '<a name="f0"/>', "&lt;tag&gt;", "&#60;", '<onDraw name="x" label="y"/>',
              '<img src="x"/>', "<![CDATA[x]]>", '<unichar name="SNOWMAN"/>']


def test_user_text_is_never_reportlab_markup():
    payload = " ".join(INJECTIONS)
    link = '<link href="https://evil.example/">click</link>'
    finding = _finding(
        1, ref="X-1&<b>", title=f"Title {INJECTIONS[0]} {INJECTIONS[1]}", cwe="CWE-79 <i>",
        status="confirmed<br/>", cvss_vector="CVSS:3.1/<b>&amp;", targets=["<para>host"],
        description=f"{payload}\n\n{link}\n\n`{INJECTIONS[0]}` and **{INJECTIONS[6]}**\n\n"
                    "- item <br/> &amp;\n\n```\n<para>&amp;</para> <font color=\"red\">\n```",
        impact=payload, steps_to_reproduce=f"GET /?q={INJECTIONS[0]}&x=<br/> HTTP/1.1",
        remediation=f"# {INJECTIONS[1]}\n\n{payload}",
        references=["<link href='x'>ref</link>", "https://example.com/a?b=1&c=2"],
        attachments=[{"filename": "<para>.txt", "description": "&amp;", "sha256": "ab" * 32,
                      "size": 3, "problem": "<b>x</b>"}],
        retests=[{"tested_on": "2026-11-01", "result": "resolved", "tester": "<i>t</i>",
                  "notes": f"{INJECTIONS[0]} &amp;"}],
        retest_status="resolved",
    )
    ctx = _ctx(
        [finding],
        engagement={"name": "<b>Eng</b> &amp;", "code": "C<br/>", "type": "<para>",
                    "start_date": "2026-01-01", "end_date": None, "description": payload,
                    "rules_of_engagement": payload, "executive_summary": payload},
        client={"name": "<font name=\"x\">Client&amp;</font>"},
        prepared_by={"name": "<b>P</b>", "organization": "&amp;Org", "email": "<e@x>"},
        scope={"include": [{"kind": "<i>", "value": "<para>", "notes": "&amp;"}],
               "exclude": [{"kind": "ip", "value": "1.2.3.4", "notes": "<br/>"}]},
        coverage=[{"methodology": "<seq/>", "total": 1, "passed": 1, "failed": 0,
                   "not_applicable": 0, "blocked": 0, "incomplete": 0}],
        targets=[{"value": "<b>t</b>", "hostname": "&amp;", "ip": "<br/>", "os": "<i>",
                  "status": "new", "services": ["80/tcp <para>"]}],
        evidence_fingerprints=[{"finding": "X-1&<b>", "filename": "<br/>.png", "size": 1,
                                "sha256": "cd" * 32}],
        branding={"organization": "<b>Org</b>", "accent": "#123456", "logo": None,
                  "footer": "<br/>&amp; footer", "classification": "<i>SECRET</i>"},
        retested=True,
    )
    pdf = render_pdf(ctx)
    text = _norm(_text(pdf))
    for s in INJECTIONS + ["<font color=\"red\">", "<para>&amp;</para>", "X-1&<b>",
                           "<link href='x'>ref</link>", '<font name="x">Client&amp;</font>',
                           "<b>Eng</b> &amp;", "C<br/>", "<i>SECRET</i>", "<b>Org</b>",
                           "<br/>&amp; footer", "CWE-79 <i>", "confirmed<br/>", "<para>host",
                           "CVSS:3.1/<b>&amp;", "<para>.txt", "(<b>x</b>)", "<i>t</i>",
                           "80/tcp <para>", "<br/>.png", "<seq/>", "<e@x>", "&amp;Org"]:
        assert s in text, s
    assert f"GET /?q={INJECTIONS[0]}&x=<br/> HTTP/1.1" in text  # plain steps: a code block
    assert '<link href="https://evil.example/">click</link>' in text
    assert all("evil.example" not in uri for uri in _link_uris(pdf))
    assert _link_uris(pdf) == ["https://example.com/a?b=1&c=2"]
    assert "\u2603" not in text  # <unichar name="SNOWMAN"/> stayed text


def test_control_characters_and_unicode():
    title = "Bell\x07 escape \x1b[31mred\x1b[0m null\x00 Привет Ελληνικά Ünïcödé “quoted” ✓ 🔥"
    ctx = _ctx([_finding(1, title=title, description="tab\there\x0bvt \udcff lone surrogate")],
               client={"name": "Société Générale"})
    text = _text(render_pdf(ctx))
    assert "Société Générale" in text
    assert "Привет Ελληνικά Ünïcödé “quoted” ✓" in text
    assert "\ufffd[31mred" in text and "Bell\ufffd" in text
    assert "lone surrogate" in text


# ------------------------------------------------------------------ rich text


def test_rich_text_becomes_formatted_flowables():
    description = (
        "Intro with **bold**, *italic*, `inline <code>` and "
        "[the advisory](https://example.com/adv).\n"
        "Second line of the same paragraph.\n\n"
        "## Details heading\n\n"
        "- first bullet\n- second bullet\n\n"
        "7. seventh step\n8. eighth step\n\n"
        "```\n" + "A" * 300 + "\n    indented line\n```"
    )
    pdf = render_pdf(_ctx([_finding(1, description=description)]))
    text = _text(pdf)
    assert "Intro with bold, italic, inline <code> and the advisory." in text
    assert "Second line of the same paragraph." in text
    assert "Details heading" in text and "**" not in text and "```" not in text
    assert re.search(r"\u2022\s*first bullet", text) and re.search(r"\u2022\s*second bullet", text)
    assert re.search(r"7\.\s*seventh step", text) and re.search(r"8\.\s*eighth step", text)
    assert "https://example.com/adv" in _link_uris(pdf)
    fonts = {f.split("+")[-1] for f in _fonts(pdf)}
    assert {"DejaVuSans", "DejaVuSans-Bold", "DejaVuSans-Oblique", "DejaVuSansMono"} <= fonts
    # The 300-character code line is wrapped inside the frame, not cut off or overflowing.
    runs = re.findall(r"A{2,}", text)
    assert sum(map(len, runs)) == 300 and max(map(len, runs)) <= 100
    assert "    indented line" in text


def test_steps_to_reproduce_plain_text_stays_a_code_block():
    request = "POST /login HTTP/1.1\nHost: globex.example\n\nuser=admin&pass=*secret*_x_"
    pdf = render_pdf(_ctx([_finding(1, steps_to_reproduce=request)]))
    text = _text(pdf)
    assert "POST /login HTTP/1.1\nHost: globex.example" in text
    assert "user=admin&pass=*secret*_x_" in text
    steps = "1. Log in as **admin**\n2. Open `/x`"
    formatted = render_pdf(_ctx([_finding(1, steps_to_reproduce=steps)]))
    assert re.search(r"1\.\s*Log in as admin", _text(formatted))


def test_only_bundled_fonts_are_used():
    pdf = render_pdf(_ctx([_finding(1, description="**b** *i* ***bi*** `c` **`bc`**")]))
    fonts = _fonts(pdf)
    assert fonts and not any(std in f for f in fonts for std in STANDARD_FONTS)
    assert {f.split("+")[-1] for f in fonts} <= {
        "DejaVuSans", "DejaVuSans-Bold", "DejaVuSans-Oblique", "DejaVuSans-BoldOblique",
        "DejaVuSansMono", "DejaVuSansMono-Bold"}


# ------------------------------------------------------------------ report content


def test_branding_retests_and_cvss_versions():
    logo = _png((300, 90), colour="navy")
    findings = [
        _finding(1, severity="critical", cvss_score=9.3, cvss_version="4.0",
                 cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                 retests=[{"tested_on": "2026-10-20", "result": "not_resolved", "tester": "Sam",
                           "notes": "Still **exploitable**."},
                          {"tested_on": "2026-11-02", "result": "partially_resolved",
                           "tester": "Ana", "notes": "Main host fixed."}],
                 retest_status="partially_resolved"),
        _finding(2, severity="high", cvss_score=7.5, cvss_version="",
                 cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                 retests=[{"tested_on": "2026-11-03", "result": "resolved", "tester": "Ana",
                           "notes": ""}], retest_status="resolved"),
        _finding(3, severity="low", cvss_score=None, cvss_vector="", cvss_version=""),
    ]
    ctx = _ctx(findings, retested=True, branding={
        "organization": "Northwind Offensive Security", "accent": "#7c3aed",
        "logo": logo, "logo_content_type": "image/png", "logo_data_uri": None,
        "footer": "Northwind Offensive Security Ltd - Company No. 0123456",
        "classification": "TLP:AMBER+STRICT"})
    pdf = render_pdf(ctx)
    pages = _pages(pdf)
    text = "\n".join(pages)
    assert "Northwind Offensive Security" in pages[0] and "TLP:AMBER+STRICT" in pages[0]
    assert "Prepared by Sam Okafor, Northwind Offensive Security" in pages[0]
    for page in pages[1:]:
        assert "TLP:AMBER+STRICT" in page and "Company No. 0123456" in page
    assert "CONFIDENTIAL" not in text
    assert len(_images(pdf)) == 1  # the logo
    assert "CVSS v4.0" in text and "CVSS v3.0" in text
    assert "Retest history" in text and "Tester" in text
    assert re.search(r"2026-10-20\s*Not\s+resolved\s*Sam\s*Still exploitable\.", text)
    assert re.search(r"2026-11-02\s*Partially\s+resolved\s*Ana\s*Main host fixed\.", text)
    assert re.search(r"2026-11-03\s*Resolved\s*Ana", text)
    assert "Retest" in pages[2]  # the summary table's column


def test_empty_classification_is_omitted():
    ctx = _ctx(branding={"organization": "", "accent": "#0f766e", "logo": None, "footer": "",
                         "classification": ""})
    pages = _pages(render_pdf(ctx))
    assert "CONFIDENTIAL" not in "\n".join(pages)
    assert "This report contains sensitive security information" not in pages[0]
    assert "Generated by OffsecHub on 2026-11-11 10:00 UTC" in pages[1]


def test_severity_counts_summary_and_contents():
    findings = [_finding(i, severity=s, title=f"{s.title()} issue {i}")
                for i, s in enumerate(["critical", "high", "high", "medium", "info"], start=1)]
    pdf = render_pdf(_ctx(findings, draft=True))
    reader = _reader(pdf)
    pages = _pages(pdf)
    text = "\n".join(pages)
    assert "DRAFT - not for distribution" in pages[0]
    assert "5 findings reported." in text
    assert re.search(r"CRITICAL\s*1\s*HIGH\s*2\s*MEDIUM\s*1\s*LOW\s*0\s*INFO\s*1", text)

    # The contents and the bookmarks list every section and finding, with the right pages.
    outline = reader.outline
    titles = [o.title for o in outline if not isinstance(o, list)]
    assert titles == ["1. Executive summary", "2. Findings overview",
                      "3. Scope and rules of engagement", "4. Methodology and coverage",
                      "5. Detailed findings", "Appendix A: assets in scope",
                      "Appendix B: evidence fingerprints"]
    children = next(o for o in outline if isinstance(o, list))
    assert [c.title for c in children] == [f"GLX-{i:03d} {f['title']}"
                                           for i, f in enumerate(findings, start=1)]
    contents = pages[1]
    for child in children:
        page = reader.get_destination_page_number(child) + 1
        assert re.search(re.escape(child.title) + rf"\s*{page}\b", contents)
        assert child.title in pages[page - 1]


def test_no_findings_and_empty_fields():
    ctx = _ctx([], scope={"include": [], "exclude": []}, coverage=[], targets=[],
               engagement={"name": "Empty", "code": "E-1", "type": "Security Assessment",
                           "executive_summary": "", "description": None})
    text = _text(render_pdf(ctx))
    for s in ["0 findings reported.", "No findings were reported.",
              "No executive summary has been written yet.", "No scope recorded.",
              "No methodology checklist was tracked for this engagement.",
              "No in-scope assets recorded.", "No evidence is attached to the reported findings."]:
        assert s in text


@pytest.mark.parametrize("ctx", [
    {},
    {"findings": [{"title": "Only a title"}]},
    {"findings": [None, "junk", {}], "scope": None, "coverage": None, "targets": [{}],
     "evidence_fingerprints": [{}], "severity_counts": {"high": "x"}, "branding": {},
     "engagement": {"start_date": "2026-01-01"}, "client": {}, "prepared_by": None},
    {"findings": [{"title": "x", "references": "https://a.example\nnot a url", "cvss_score": 10,
                   "images": [{}], "attachments": [{}], "retests": [{}], "targets": None}],
     "branding": {"accent": "red", "logo": b"not an image", "classification": None}},
    {"findings": {"not": "a list"}, "engagement": "x", "client": None, "branding": "x",
     "scope": {"include": "x", "exclude": [None]}, "targets": "x", "coverage": [1, 2]},
    {"findings": [{"title": 42, "ref": None, "severity": None, "status": None, "targets": "one",
                   "references": None, "images": "x", "attachments": None, "retests": "x",
                   "description": 7, "steps_to_reproduce": ["not", "text"], "cvss_score": "n/a",
                   "cvss_vector": None, "cwe": None}],
     "evidence_fingerprints": [{"size": "big", "sha256": None}], "total_findings": "1"},
])
def test_missing_and_odd_keys_never_crash(ctx):
    text = _text(render_pdf(ctx))
    assert "1. Executive summary" in text and "Appendix B: evidence fingerprints" in text


def test_long_unbroken_tokens_wrap_everywhere():
    token = "deadbeef" * 60  # 480 characters with nowhere to break
    url = "https://example.com/" + "a" * 400
    finding = _finding(
        1, title=token[:200], description=f"{token}\n\n`{token}`\n\n**{url}**",
        impact=f"[{token}]({url})", cvss_vector=token, cwe=token, targets=[token],
        references=[url, token],
        attachments=[{"filename": token, "description": token, "sha256": token, "size": 1}],
        retests=[{"tested_on": "2026-11-01", "result": "resolved", "tester": token,
                  "notes": token}],
        retest_status="resolved")
    ctx = _ctx([finding], retested=True, client={"name": token},
               scope={"include": [{"kind": token, "value": token, "notes": token}], "exclude": []},
               targets=[{"value": token, "hostname": token, "ip": token, "os": token,
                         "status": token, "services": [token]}],
               evidence_fingerprints=[{"finding": token, "filename": token, "size": 1,
                                       "sha256": token}],
               branding={"organization": token, "accent": "#0f766e", "logo": None,
                         "footer": token, "classification": token[:40]})
    pdf = render_pdf(ctx)
    text = _text(pdf)
    longest = max(len(word) for word in text.split())
    assert longest <= 110, longest  # wrapped to the frame or the cell, never one overflowing run
    assert _flat(text).count(token) >= 10


# ------------------------------------------------------------------ images


def test_images_are_embedded_and_bad_ones_are_skipped():
    good = [
        ("wide.png", _png((1200, 500))),
        ("photo.jpg", _jpeg()),
        ("alpha.png", _png((200, 200), "RGBA", (255, 0, 0, 128))),
        ("palette.gif", _png((64, 64), "P", 3)),
        ("huge.png", _png((4000, 3000))),
        ("tall.png", _png((300, 6000))),
    ]
    bad = [
        ("corrupt.png", b"\x89PNG\r\n\x1a\n not really"),
        ("truncated.png", _png((400, 400), colour="red")[:-40]),
        ("bomb.png", _png_claiming(50_000, 50_000)),
        ("text.png", b"hello"),
    ]
    images = [{"filename": n, "description": f"{n} desc", "sha256": hashlib.sha256(d).hexdigest(),
               "size": len(d), "content_type": "image/png", "data": d} for n, d in good + bad]
    images.append({"filename": "uri.png", "description": "", "sha256": "e" * 64, "size": 1,
                   "content_type": "image/png", "data_uri": "data:image/png;base64,!!!notbase64"})
    images.append({"filename": "nodata.png", "description": "", "sha256": "f" * 64, "size": 1,
                   "content_type": "image/png"})
    images.append({"filename": "fromuri.png", "description": "", "sha256": "1" * 64, "size": 1,
                   "content_type": "image/png",
                   "data_uri": "data:image/png;base64," + base64.b64encode(PNG).decode()})
    pdf = render_pdf(_ctx([_finding(1, images=images)]))
    text = _text(pdf)
    embedded = _images(pdf)
    assert len(embedded) == len(good) + 1
    assert max(int(img["/Width"]) for img in embedded) <= 2400  # downscaled
    assert any("/DCTDecode" in str(img.get("/Filter")) for img in embedded)
    assert any("/SMask" in img for img in embedded)  # transparency kept
    for name, data in good:
        assert f"{name} - {name} desc (fingerprint {hashlib.sha256(data).hexdigest()[:16]})" in text
    for name in [n for n, _ in bad] + ["uri.png", "nodata.png"]:
        assert re.search(re.escape(name) + r".*\(image could not be decoded; not embedded\)",
                         _norm(text))


def test_photos_are_turned_upright():
    """A phone photo stored sideways with an EXIF orientation shows as a browser shows it."""
    exif = Image.Exif()
    exif[0x0112] = 6  # rotate 90 degrees clockwise to display
    buf = BytesIO()
    Image.new("RGB", (400, 200), "green").save(buf, "JPEG", exif=exif)
    data = buf.getvalue()
    pdf = render_pdf(_ctx([_finding(1, images=[{
        "filename": "door.jpg", "description": "", "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data), "content_type": "image/jpeg", "data": data}])]))
    (image,) = _images(pdf)
    assert (int(image["/Width"]), int(image["/Height"])) == (200, 400)


# ------------------------------------------------------------------ scale


def _long_finding(i: int) -> dict:
    para = ("The application reflects the parameter into the page without encoding it, so an "
            "attacker can run script in a victim's session and act on their behalf. ") * 6
    return _finding(
        i, severity=["critical", "high", "medium", "low", "info"][i % 5],
        title=f"Reflected cross-site scripting in search parameter variant {i}",
        description=f"{para}\n\n{para}\n\n- **Endpoint:** `/search?q=`\n- Payload: "
                    "`<svg onload=alert(1)>`\n\n```\nGET /search?q=%3Csvg%20onload%3Dalert(1)%3E "
                    "HTTP/1.1\nHost: www.globex.example\n```",
        impact=para, steps_to_reproduce="1. Open the search page\n2. Submit the payload\n"
                                        "3. Observe the alert", remediation=para,
        references=["https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
        targets=[f"203.0.113.{i % 250}", f"host{i}.globex.example"],
        attachments=[{"filename": f"request-{i}.txt", "description": "Raw request",
                      "sha256": hashlib.sha256(str(i).encode()).hexdigest(), "size": 1234}])


def test_two_hundred_long_findings_render_quickly():
    findings = [_long_finding(i) for i in range(1, 201)]
    prints = [{"finding": f["ref"], "filename": a["filename"], "size": a["size"],
               "sha256": a["sha256"]} for f in findings for a in f["attachments"]]
    ctx = _ctx(findings, evidence_fingerprints=prints)
    started = time.perf_counter()
    pdf = render_pdf(copy.deepcopy(ctx))
    elapsed = time.perf_counter() - started
    reader = _reader(pdf)
    assert len(reader.pages) > 200
    text = _text(pdf)
    assert "200 findings reported." in text
    assert "GLX-200 Reflected cross-site scripting in search parameter variant 200" in text
    assert prints[-1]["sha256"] in text
    last = len(reader.pages)
    assert f"Page {last} of {last}" in reader.pages[-1].extract_text()
    assert elapsed < 30, f"rendering 200 findings took {elapsed:.1f}s"
