"""Word (DOCX) reports: the built-in template or the tester's own.

Templates are docxtpl documents: Word content with Jinja tags. A template may
come from anywhere (a colleague, a download), so it is handled as untrusted:

* it is checked on upload and again before rendering (size, a bounded zip, no
  DTDs or entity declarations in its XML, valid template syntax);
* it renders in a Jinja sandbox with autoescaping, so it can read the report
  context but not reach Python internals, and context text cannot inject XML;
* oversized repetition (``"x" * 10**9``) and huge powers are refused.

Rich text (finding fields) becomes real Word paragraphs: body text, "List
Bullet" items, "OH Numbered" items, "OH Code" blocks and "Heading 4"
headings. Those style names exist in the built-in template; a custom template
that lacks one falls back to Word's default paragraph style.
"""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from typing import Any

from docx.shared import Mm, RGBColor
from docxtpl import DocxTemplate, InlineImage, RichText, RichTextParagraph
from jinja2 import TemplateError as JinjaTemplateError
from jinja2.sandbox import SandboxedEnvironment, SecurityError
from PIL import Image, UnidentifiedImageError

from . import richtext
from .branding import MAX_TEMPLATE_BYTES

BUILTIN = Path(__file__).resolve().parent.parent / "templates" / "report.docx"
MAX_ZIP_ENTRIES = 1000
MAX_UNZIPPED_BYTES = 64 * 1024 * 1024
MAX_REPEAT = 10_000
IMAGE_WIDTH_MM = 160
IMAGE_MAX_HEIGHT_MM = 200
SEVERITY_FILL = {"critical": "7F1D1D", "high": "DC2626", "medium": "EA580C", "low": "CA8A04", "info": "2563EB"}
RETEST_LABELS = {"resolved": "Resolved", "partially_resolved": "Partially resolved",
                 "not_resolved": "Not resolved"}
# XML 1.0 forbids these; scanner output and pasted text sometimes contain them.
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


class TemplateProblem(ValueError):
    """The file is not a usable report template (message is shown to the user)."""


class _Sandbox(SandboxedEnvironment):
    intercepted_binops = frozenset({"*", "**"})

    def call_binop(self, context, operator, left, right):
        if operator == "**" and isinstance(right, (int, float)) and abs(right) > 100:
            raise SecurityError("exponent too large")
        if operator == "*":
            sizes = [len(v) for v in (left, right) if isinstance(v, (str, bytes, list, tuple))]
            counts = [v for v in (left, right) if isinstance(v, int)]
            if sizes and counts and sizes[0] * abs(counts[0]) > MAX_REPEAT * 100:
                raise SecurityError("repetition too large")
        return super().call_binop(context, operator, left, right)


def _environment() -> SandboxedEnvironment:
    return _Sandbox(autoescape=True)


def check_template(data: bytes) -> None:
    """Raise TemplateProblem unless ``data`` is a safe, well-formed docxtpl template."""
    if len(data) > MAX_TEMPLATE_BYTES:
        raise TemplateProblem("the template must be at most 5 MB")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_UNZIPPED_BYTES:
                raise TemplateProblem("the template is too large once unpacked")
            names = {i.filename for i in infos}
            if "word/document.xml" not in names:
                raise TemplateProblem("this is not a Word document (.docx)")
            for info in infos:
                if info.filename.endswith((".xml", ".rels")):
                    head = zf.read(info)
                    if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
                        raise TemplateProblem("the template contains XML declarations that are not allowed")
    except zipfile.BadZipFile:
        raise TemplateProblem("this is not a Word document (.docx)") from None
    try:
        DocxTemplate(io.BytesIO(data)).get_undeclared_template_variables(_environment())
    except JinjaTemplateError as exc:
        raise TemplateProblem(f"template syntax error: {exc}") from None
    except Exception as exc:  # python-docx/lxml reject malformed parts in many ways
        raise TemplateProblem(f"the template could not be read: {exc}") from None


# ------------------------------------------------------------------ rich text


def _clean(text: str) -> str:
    return _XML_INVALID.sub("", text)


def _runs(tpl: DocxTemplate, spans: list[richtext.Span], prefix: str = "") -> RichText:
    rt = RichText()
    if prefix:
        rt.add(prefix)
    for s in spans:
        if s.is_break:
            rt.add("\n")
            continue
        text = _clean(s.text)
        if s.href:
            rt.add(text, bold=s.bold, italic=s.italic, color="0F766E", underline=True,
                   url_id=tpl.build_url_id(s.href))
        else:
            rt.add(text, bold=s.bold, italic=s.italic, font="Consolas" if s.code else None)
    return rt


def _style(tpl: DocxTemplate, name: str) -> str | None:
    """The style id for a style name in this template (ids are localised, names are not)."""
    cache = tpl.__dict__.setdefault("_oh_styles", {})
    if name not in cache:
        tpl.init_docx()
        try:
            cache[name] = tpl.docx.styles[name].style_id
        except KeyError:
            cache[name] = None  # missing from a custom template: Word's default paragraph style
    return cache[name]


def rich(tpl: DocxTemplate, text: str | None, *, steps: bool = False) -> RichTextParagraph | str:
    """Word paragraphs for a rich-text field (use ``{{p var }}`` in a template)."""
    blocks = richtext.parse(text)
    if not blocks:
        return ""
    if steps and richtext.is_plain(blocks):
        # Unformatted steps are usually a raw request: keep them as code.
        blocks = [richtext.Block("code", text=text or "")]
    out = RichTextParagraph()
    for b in blocks:
        if b.kind == "paragraph":
            out.add(_runs(tpl, b.spans))
        elif b.kind == "heading":
            out.add(_runs(tpl, b.spans), parastyle=_style(tpl, "Heading 4"))
        elif b.kind == "bullets":
            for item in b.items:
                out.add(_runs(tpl, item), parastyle=_style(tpl, "List Bullet"))
        elif b.kind == "numbers":
            for n, item in enumerate(b.items, start=b.start):
                out.add(_runs(tpl, item, prefix=f"{n}.\t"), parastyle=_style(tpl, "OH Numbered"))
        else:  # code
            out.add(RichText(_clean(b.text) or " ", font="Consolas"), parastyle=_style(tpl, "OH Code"))
    return out


def _inline(tpl: DocxTemplate, text: str | None) -> RichText:
    """Rich text flattened into one paragraph (for table cells: ``{{r var }}``)."""
    spans: list[richtext.Span] = []
    for b in richtext.parse(text):
        if spans:
            spans.append(richtext.Span("\n"))
        if b.kind == "code":
            spans.append(richtext.Span(b.text, code=True))
        elif b.kind in ("bullets", "numbers"):
            for i, item in enumerate(b.items):
                if i:
                    spans.append(richtext.Span("\n"))
                spans.extend([richtext.Span("• " if b.kind == "bullets" else f"{b.start + i}. "), *item])
        else:
            spans.extend(b.spans)
    return _runs(tpl, spans)


# ------------------------------------------------------------------ images


def _image(tpl: DocxTemplate, data: bytes, *, width_mm: float, max_height_mm: float) -> InlineImage | None:
    """An inline picture sized to fit, or None if the bytes are not a usable image."""
    try:
        with Image.open(io.BytesIO(data)) as img:
            w, h = img.size
            if img.format not in ("PNG", "JPEG", "GIF", "BMP"):
                buf = io.BytesIO()
                img.convert("RGBA").save(buf, "PNG")  # e.g. WebP, which Word cannot show
                data = buf.getvalue()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        return None
    if not w or not h:
        return None
    if width_mm * h / w > max_height_mm:
        return InlineImage(tpl, io.BytesIO(data), height=Mm(max_height_mm))
    return InlineImage(tpl, io.BytesIO(data), width=Mm(width_mm))


# ------------------------------------------------------------------ context


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return _clean(value)
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def build_docx_context(ctx: dict, tpl: DocxTemplate) -> dict:
    """The report context plus Word objects: rich paragraphs, pictures, labels."""
    c = _sanitize({k: v for k, v in ctx.items() if k != "branding"})
    branding = ctx["branding"]
    c["branding"] = _sanitize({k: v for k, v in branding.items() if k not in ("logo", "logo_data_uri")})
    eng = c["engagement"]
    c["rt"] = {key: rich(tpl, eng.get(key)) for key in ("executive_summary", "description", "rules_of_engagement")}
    c["prepared_by_line"] = ", ".join(x for x in (c["prepared_by"]["name"], branding["organization"]) if x)
    logo = branding.get("logo")
    c["logo"] = (_image(tpl, logo, width_mm=55, max_height_mm=22) or "") if logo else ""

    for f, raw in zip(c["findings"], ctx["findings"]):
        f["severity_label"] = f["severity"].capitalize() if f["severity"] != "info" else "Informational"
        f["severity_short"] = f["severity"].capitalize()
        f["severity_fill"] = SEVERITY_FILL.get(f["severity"], "6B7280")
        f["status_label"] = f["status"].replace("_", " ").capitalize()
        f["cvss_score_text"] = "-" if f["cvss_score"] is None else f"{f['cvss_score']:.1f}"
        f["cvss_text"] = (f"{f['cvss_score']:.1f} (CVSS v{f['cvss_version']}) {f['cvss_vector']}"
                          if f["cvss_vector"] and f["cvss_score"] is not None else "-")
        f["retest_label"] = RETEST_LABELS.get(f["retest_status"] or "", "-")
        f["rt"] = {key: rich(tpl, raw.get(key), steps=key == "steps_to_reproduce")
                   for key in ("description", "impact", "steps_to_reproduce", "remediation")}
        for r in f["retests"]:
            r["label"] = RETEST_LABELS.get(r["result"], r["result"])
            r["notes_rt"] = _inline(tpl, r["notes"])
        images = []
        for img, raw_img in zip(f["images"], raw["images"]):
            img.pop("data", None)
            img.pop("data_uri", None)
            pic = _image(tpl, raw_img.get("data") or b"", width_mm=IMAGE_WIDTH_MM,
                         max_height_mm=IMAGE_MAX_HEIGHT_MM)
            if pic is None:
                f["attachments"].append({**img, "problem": "image could not be decoded; not embedded"})
            else:
                images.append({**img, "inline": pic})
        f["images"] = images
    for t in c["targets"]:
        t["status_label"] = t["status"].replace("_", " ").capitalize()
    return c


def render_docx(ctx: dict, template: bytes | None = None) -> bytes:
    """Render the report context into a .docx (``template`` = a user's template bytes)."""
    if template is not None:
        check_template(template)
    tpl = DocxTemplate(io.BytesIO(template) if template is not None else BUILTIN)
    if template is None:
        # The built-in template takes its accent colour from the branding settings.
        tpl.init_docx()
        accent = RGBColor.from_string(ctx["branding"]["accent"].lstrip("#").upper())
        for name in ("Heading 1", "Heading 2", "OH Kicker"):
            tpl.docx.styles[name].font.color.rgb = accent
    try:
        tpl.render(build_docx_context(ctx, tpl), jinja_env=_environment(), autoescape=True)
    except (JinjaTemplateError, SecurityError) as exc:
        raise TemplateProblem(f"the template could not be rendered: {exc}") from None
    out = io.BytesIO()
    tpl.save(out)
    return out.getvalue()
