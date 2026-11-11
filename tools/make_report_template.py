"""Generate backend/app/templates/report.docx, the built-in Word report template.

    python tools/make_report_template.py

The output is a docxtpl template: ordinary Word content with Jinja tags
({{ ... }}, {%p ... %} for whole paragraphs, {%tr ... %} for table rows).
Users download it from the app, restyle it in Word and upload it as their own
template; docs/REPORT_TEMPLATES.md lists the variables. Rerun this script
after changing it and commit the regenerated .docx.
"""

from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_BREAK, WD_PARAGRAPH_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

OUT = Path(__file__).resolve().parents[1] / "backend" / "app" / "templates" / "report.docx"
INK = RGBColor(0x11, 0x18, 0x27)
MUTED = RGBColor(0x6B, 0x72, 0x80)
ACCENT = RGBColor(0x0F, 0x76, 0x6E)  # replaced by the branding accent at render time
FONT = "Calibri"
MONO = "Consolas"


def set_font(style, name=FONT, size=None, bold=None, color=None):
    style.font.name = name
    rpr = style.element.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.append(fonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        fonts.set(qn(attr), name)
    if size:
        style.font.size = Pt(size)
    if bold is not None:
        style.font.bold = bold
    if color is not None:
        style.font.color.rgb = color


def shade(element, fill):
    """Background shading for a paragraph (pPr) or table cell (tcPr)."""
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    element.append(shd)


def styles(doc):
    s = doc.styles
    set_font(s["Normal"], size=10.5, color=INK)
    s["Normal"].paragraph_format.space_after = Pt(6)
    s["Normal"].paragraph_format.line_spacing = 1.15
    set_font(s["Title"], size=28, bold=True, color=INK)
    s["Title"].paragraph_format.space_after = Pt(4)
    # python-docx's default Title has a bottom border; keep the cover clean.
    for el in s["Title"].element.findall(".//" + qn("w:pBdr")):
        el.getparent().remove(el)
    set_font(s["Subtitle"], size=15, color=INK)
    for name, size in (("Heading 1", 16), ("Heading 2", 13), ("Heading 3", 11), ("Heading 4", 10.5)):
        set_font(s[name], size=size, bold=True, color=ACCENT if name in ("Heading 1", "Heading 2") else INK)
        s[name].paragraph_format.space_before = Pt(14 if name == "Heading 1" else 10)
        s[name].paragraph_format.space_after = Pt(4)
        s[name].paragraph_format.keep_with_next = True
    set_font(s["List Bullet"], size=10.5, color=INK)

    code = s.add_style("OH Code", WD_STYLE_TYPE.PARAGRAPH)
    code.base_style = s["Normal"]
    set_font(code, MONO, size=8.5, color=INK)
    code.paragraph_format.space_after = Pt(0)
    code.paragraph_format.line_spacing = 1.0
    code.paragraph_format.left_indent = Cm(0.2)
    shade(code.element.get_or_add_pPr(), "F3F4F6")

    numbered = s.add_style("OH Numbered", WD_STYLE_TYPE.PARAGRAPH)
    numbered.base_style = s["Normal"]
    numbered.paragraph_format.left_indent = Cm(0.9)
    numbered.paragraph_format.first_line_indent = Cm(-0.6)
    numbered.paragraph_format.space_after = Pt(2)

    small = s.add_style("OH Small", WD_STYLE_TYPE.PARAGRAPH)
    small.base_style = s["Normal"]
    set_font(small, size=8.5, color=MUTED)

    kicker = s.add_style("OH Kicker", WD_STYLE_TYPE.PARAGRAPH)
    kicker.base_style = s["Normal"]
    set_font(kicker, size=10, bold=True, color=ACCENT)
    kicker.font.all_caps = True

    draft = s.add_style("OH Draft", WD_STYLE_TYPE.PARAGRAPH)
    draft.base_style = s["Normal"]
    set_font(draft, size=11, bold=True, color=RGBColor(0x92, 0x40, 0x0E))
    shade(draft.element.get_or_add_pPr(), "FEF3C7")

    mono = s.add_style("OH Mono", WD_STYLE_TYPE.CHARACTER)
    set_font(mono, MONO, size=9)


def para(doc_or_cell, text="", style=None, bold=False):
    p = doc_or_cell.add_paragraph(style=style)
    if text:
        run = p.add_run(text)
        run.bold = bold
    return p


def field(paragraph, instruction):
    """A Word field such as PAGE or NUMPAGES (updated by Word when printing/opening)."""
    run = paragraph.add_run()
    for kind, text in (("begin", None), (None, instruction), ("separate", None), (None, "1"), ("end", None)):
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        elif text == instruction:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = f" {instruction} "
        else:
            el = OxmlElement("w:t")
            el.text = text
        run._r.append(el)


def table(doc, headers, loop, cells, widths=None, when=None, empty=None):
    """A table whose body repeats one row per item: {%tr for ... %} rows wrap it.

    ``when`` leaves the whole table out unless the condition holds (paragraph
    tags around a table make it conditional); ``empty`` is the text shown instead.
    """
    if when:
        para(doc, "{%p if " + when + " %}")
    t = doc.add_table(rows=4, cols=len(headers))
    t.style = doc.styles["Table Grid"]
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = ""
        r = c.paragraphs[0].add_run(h)
        r.bold = True
        shade(c._tc.get_or_add_tcPr(), "F3F4F6")
    t.rows[1].cells[0].text = "{%tr " + loop + " %}"
    for i, value in enumerate(cells):
        t.rows[2].cells[i].text = value
        if value.startswith("{% cellbg"):
            white_bold(t.rows[2].cells[i])
    t.rows[3].cells[0].text = "{%tr endfor %}"
    if widths:
        widths_of(t, widths)
    keep_rows_whole(t)
    # Mark the header row so Word repeats it on every page.
    tr_pr = t.rows[0]._tr.get_or_add_trPr()
    header = OxmlElement("w:tblHeader")
    tr_pr.append(header)
    if when:
        if empty:
            para(doc, "{%p else %}")
            para(doc, empty, style="OH Small")
        para(doc, "{%p endif %}")
    return t


def widths_of(t, widths):
    """Column widths that Word and LibreOffice both honour (grid and cells)."""
    t.autofit = False
    for i, w in enumerate(widths):
        t.columns[i].width = Cm(w)
        for row in t.rows:
            row.cells[i].width = Cm(w)


def keep_rows_whole(t):
    for row in t.rows:
        tr_pr = row._tr.get_or_add_trPr()
        tr_pr.append(OxmlElement("w:cantSplit"))


def white_bold(cell):
    """Severity cells: white bold text on the severity colour set by {% cellbg %}."""
    for run in cell.paragraphs[0].runs:
        run.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)


def rich(doc, var):
    para(doc, "{{p " + var + " }}")


def build() -> Document:
    doc = Document()
    styles(doc)
    sec = doc.sections[0]
    sec.page_height, sec.page_width = Cm(29.7), Cm(21.0)
    for side in ("left_margin", "right_margin"):
        setattr(sec, side, Cm(2.2))
    sec.top_margin, sec.bottom_margin = Cm(2.2), Cm(2.0)
    sec.different_first_page_header_footer = True

    # Word's Header/Footer styles carry centre and right tab stops.
    for style in ("Header", "Footer"):
        set_font(doc.styles[style], size=8.5, color=MUTED)
    header = sec.header.paragraphs[0]
    header.style = doc.styles["Header"]
    header.add_run("{{ branding.classification }}\t\t{{ engagement.code }}")
    footer = sec.footer.paragraphs[0]
    footer.style = doc.styles["Footer"]
    footer.add_run("{{ branding.footer }}\t\tPage ")
    field(footer, "PAGE")
    footer.add_run(" of ")
    field(footer, "NUMPAGES")

    # ----------------------------------------------------------------- cover
    para(doc, "{{ logo }}")
    para(doc, "{%p if draft %}")
    para(doc, "DRAFT - not for distribution", style="OH Draft")
    para(doc, "{%p endif %}")
    for _ in range(4):
        para(doc)
    para(doc, "{{ engagement.type }}", style="OH Kicker")
    para(doc, "{{ client.name }}", style="Title")
    para(doc, "{{ engagement.name }}", style="Subtitle")
    para(doc)
    para(doc, "Reference {{ engagement.code }}")
    para(doc, "{%p if engagement.start_date %}")
    para(doc, "Testing window {{ engagement.start_date }}{% if engagement.end_date %} to {{ engagement.end_date }}{% endif %}")
    para(doc, "{%p endif %}")
    para(doc, "{%p if prepared_by_line %}")
    para(doc, "Prepared by {{ prepared_by_line }}")
    para(doc, "{%p endif %}")
    para(doc, "Generated {{ generated_at }}")
    para(doc)
    para(doc, "{%p if branding.classification %}")
    para(doc, "{{ branding.classification }}. This report contains sensitive security information about "
              "{{ client.name }}. Distribution is restricted to authorised recipients.", style="OH Small")
    para(doc, "{%p endif %}")
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # -------------------------------------------------------------- contents
    para(doc, "Contents", style="Heading 1")
    for line in ("1. Executive summary", "2. Findings overview", "3. Scope and rules of engagement",
                 "4. Methodology and coverage", "5. Detailed findings"):
        para(doc, line)
    para(doc, "{%p for f in findings %}")
    para(doc, "{{ f.ref }}  {{ f.title }}", style="OH Numbered")
    para(doc, "{%p endfor %}")
    para(doc, "Appendix A: assets in scope")
    para(doc, "Appendix B: evidence fingerprints")

    # ------------------------------------------------------------- 1 summary
    p = para(doc, "1. Executive summary", style="Heading 1")
    p.paragraph_format.page_break_before = True
    para(doc, "{%p if engagement.executive_summary %}")
    rich(doc, "rt.executive_summary")
    para(doc, "{%p else %}")
    para(doc, "No executive summary has been written yet.", style="OH Small")
    para(doc, "{%p endif %}")
    para(doc, "{%p if engagement.description %}")
    para(doc, "Engagement background", style="Heading 3")
    rich(doc, "rt.description")
    para(doc, "{%p endif %}")

    # ------------------------------------------------------------ 2 overview
    para(doc, "2. Findings overview", style="Heading 1")
    para(doc, "{{ total_findings }} finding{{ '' if total_findings == 1 else 's' }} reported.")
    counts = doc.add_table(rows=2, cols=5)
    counts.style = doc.styles["Table Grid"]
    for i, (sev, fill) in enumerate((("Critical", "7F1D1D"), ("High", "DC2626"), ("Medium", "EA580C"),
                                     ("Low", "CA8A04"), ("Info", "2563EB"))):
        head = counts.rows[0].cells[i]
        head.text = ""
        run = head.paragraphs[0].add_run(sev)
        run.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        head.paragraphs[0].alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
        shade(head._tc.get_or_add_tcPr(), fill)
        cell = counts.rows[1].cells[i]
        cell.text = "{{ severity_counts." + sev.lower() + " }}"
        cell.paragraphs[0].alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
    widths_of(counts, [3.32] * 5)
    para(doc)
    table(doc, ["Ref", "Title", "Severity", "CVSS", "Status", "Retest", "Affected"], "for f in findings",
          ["{{ f.ref }}", "{{ f.title }}", "{% cellbg f.severity_fill %}{{ f.severity_short }}",
           "{{ f.cvss_score_text }}", "{{ f.status_label }}", "{{ f.retest_label }}", "{{ f.targets|length }}"],
          widths=[3.0, 4.9, 2.0, 1.3, 2.0, 2.0, 1.4], when="findings")

    # --------------------------------------------------------------- 3 scope
    para(doc, "3. Scope and rules of engagement", style="Heading 1")
    para(doc, "In scope", style="Heading 3")
    table(doc, ["Type", "Value", "Notes"], "for s in scope.include", ["{{ s.kind }}", "{{ s.value }}", "{{ s.notes }}"],
          widths=[2.5, 6.5, 7.6], when="scope.include", empty="No scope recorded.")
    para(doc, "{%p if scope.exclude %}")
    para(doc, "Explicitly excluded", style="Heading 3")
    para(doc, "{%p endif %}")
    table(doc, ["Type", "Value", "Notes"], "for s in scope.exclude", ["{{ s.kind }}", "{{ s.value }}", "{{ s.notes }}"],
          widths=[2.5, 6.5, 7.6], when="scope.exclude")
    para(doc, "{%p if engagement.rules_of_engagement %}")
    para(doc, "Rules of engagement", style="Heading 3")
    rich(doc, "rt.rules_of_engagement")
    para(doc, "{%p endif %}")

    # --------------------------------------------------------- 4 methodology
    para(doc, "4. Methodology and coverage", style="Heading 1")
    table(doc, ["Methodology", "Checks", "Passed", "Vulnerable", "N/A", "Blocked", "Not completed"],
          "for c in coverage",
          ["{{ c.methodology }}", "{{ c.total }}", "{{ c.passed }}", "{{ c.failed }}", "{{ c.not_applicable }}",
           "{{ c.blocked }}", "{{ c.incomplete }}"],
          widths=[5.0, 1.7, 1.7, 2.1, 1.5, 1.8, 2.8],
          when="coverage", empty="No methodology checklist was tracked for this engagement.")
    para(doc, "Severity ratings use the CVSS base score (v3.1 or v4.0) where a vector is provided: Critical "
              "9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, Informational 0.0.")

    # ------------------------------------------------------------ 5 findings
    p = para(doc, "5. Detailed findings", style="Heading 1")
    p.paragraph_format.page_break_before = True
    para(doc, "{%p if not findings %}")
    para(doc, "No findings were reported.", style="OH Small")
    para(doc, "{%p endif %}")
    para(doc, "{%p for f in findings %}")
    para(doc, "{{ f.ref }}  {{ f.title }}", style="Heading 2")
    meta = doc.add_table(rows=5, cols=2)
    meta.style = doc.styles["Table Grid"]
    for i, (label, value) in enumerate((
        ("Severity", "{% cellbg f.severity_fill %}{{ f.severity_label }}"),
        ("Status", "{{ f.status_label }}{% if f.retest_status %} (retest: {{ f.retest_label }}){% endif %}"),
        ("CVSS", "{{ f.cvss_text }}"),
        ("Weakness", "{{ f.cwe or '-' }}"),
        ("Affected assets", "{{ f.targets|join(', ') if f.targets else 'See description' }}"),
    )):
        meta.rows[i].cells[0].text = label
        meta.rows[i].cells[0].paragraphs[0].runs[0].bold = True
        shade(meta.rows[i].cells[0]._tc.get_or_add_tcPr(), "F9FAFB")
        meta.rows[i].cells[1].text = value
        if value.startswith("{% cellbg"):
            white_bold(meta.rows[i].cells[1])
    widths_of(meta, [3.6, 13.0])
    keep_rows_whole(meta)
    for title, key in (("Description", "description"), ("Impact", "impact"),
                       ("Steps to reproduce", "steps_to_reproduce")):
        para(doc, "{%p if f." + key + " %}")
        para(doc, title, style="Heading 3")
        rich(doc, "f.rt." + key)
        para(doc, "{%p endif %}")
    para(doc, "{%p if f.images or f.attachments %}")
    para(doc, "Evidence", style="Heading 3")
    para(doc, "{%p endif %}")
    para(doc, "{%p for img in f.images %}")
    para(doc, "{{ img.inline }}")
    para(doc, "{{ img.filename }}{% if img.description %} - {{ img.description }}{% endif %} "
              "(fingerprint {{ img.sha256[:16] }})", style="OH Small")
    para(doc, "{%p endfor %}")
    table(doc, ["File", "Description", "SHA-256"], "for a in f.attachments",
          ["{{ a.filename }}{% if a.problem %} ({{ a.problem }}){% endif %}", "{{ a.description }}",
           "{{ a.sha256 }}"], widths=[4.5, 5.0, 7.1], when="f.attachments")
    para(doc, "{%p if f.remediation %}")
    para(doc, "Remediation", style="Heading 3")
    rich(doc, "f.rt.remediation")
    para(doc, "{%p endif %}")
    para(doc, "{%p if f.retests %}")
    para(doc, "Retest history", style="Heading 3")
    para(doc, "{%p endif %}")
    table(doc, ["Date", "Result", "Tester", "Notes"], "for r in f.retests",
          ["{{ r.tested_on }}", "{{ r.label }}", "{{ r.tester }}", "{{r r.notes_rt }}"], widths=[2.4, 3.2, 3.4, 7.6],
          when="f.retests")
    para(doc, "{%p if f.references %}")
    para(doc, "References", style="Heading 3")
    para(doc, "{%p endif %}")
    para(doc, "{%p for r in f.references %}")
    para(doc, "{{ r }}", style="List Bullet")
    para(doc, "{%p endfor %}")
    para(doc, "{%p endfor %}")

    # ------------------------------------------------------------- appendices
    p = para(doc, "Appendix A: assets in scope", style="Heading 1")
    p.paragraph_format.page_break_before = True
    table(doc, ["Asset", "Hostname / IP", "OS", "Services", "Status"], "for t in targets",
          ["{{ t.value }}", "{{ t.hostname }}{% if t.ip and t.ip != t.value %} {{ t.ip }}{% endif %}", "{{ t.os }}",
           "{{ t.services|join(', ') }}", "{{ t.status_label }}"], widths=[3.8, 3.8, 2.6, 4.4, 2.0],
          when="targets", empty="No in-scope assets recorded.")
    para(doc, "Appendix B: evidence fingerprints", style="Heading 1")
    para(doc, "SHA-256 fingerprints of the evidence attached to the findings in this report, recorded when each file "
              "was added. Recomputing a file's SHA-256 confirms it is the one referenced here.")
    table(doc, ["Finding", "File", "Size", "SHA-256"], "for e in evidence_fingerprints",
          ["{{ e.finding }}", "{{ e.filename }}", "{{ e.size }} bytes", "{{ e.sha256 }}"],
          widths=[2.8, 4.2, 2.2, 7.4], when="evidence_fingerprints",
          empty="No evidence is attached to the reported findings.")
    para(doc, "{%p if prepared_by_line %}")
    para(doc, "Prepared by", style="Heading 3")
    para(doc, "{{ prepared_by_line }}{% if prepared_by.email %} ({{ prepared_by.email }}){% endif %}")
    para(doc, "{%p endif %}")
    return doc


if __name__ == "__main__":
    build().save(OUT)
    print(f"wrote {OUT}")
