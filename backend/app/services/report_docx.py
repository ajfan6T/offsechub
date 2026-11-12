"""Word (DOCX) reports: the built-in template or the tester's own.

Templates are docxtpl documents: Word content with Jinja tags. A template may
come from anywhere (a colleague, a download), so it is handled as untrusted:

* it is checked on upload and again before rendering (size, a bounded zip, no
  DTDs or entity declarations in its XML, valid template syntax);
* it renders in a Jinja sandbox with autoescaping. Attributes can be read only
  on plain values (strings, numbers, lists, dicts) and Jinja's own helpers, so
  the Word objects in the context (pictures, formatted text, which hold the
  live document) stay opaque. Context text cannot inject XML;
* it renders in a separate process, stopped after RENDER_TIMEOUT_S (and, on
  Linux, limited in memory), so a template that loops or allocates without end
  cannot hang or crash the app. Obvious blow-ups (``"x" * 10**9``, huge powers,
  widths such as ``"x".center(10**9)``) are refused outright.

Rich text (finding fields) becomes real Word paragraphs: body text, "List
Bullet" items, "OH Numbered" items, "OH Code" blocks and "Heading 4"
headings. Those style names exist in the built-in template; a custom template
that lacks one falls back to Word's default paragraph style.
"""

from __future__ import annotations

import io
import multiprocessing
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

from docx.shared import Mm, RGBColor
from docxtpl import DocxTemplate, InlineImage, RichText, RichTextParagraph
from jinja2 import TemplateError as JinjaTemplateError
from jinja2.filters import do_center, do_format, do_indent
from jinja2.sandbox import SandboxedEnvironment, SecurityError
from PIL import Image, UnidentifiedImageError

from . import richtext
from .branding import MAX_TEMPLATE_BYTES

BUILTIN = Path(__file__).resolve().parent.parent / "templates" / "report.docx"
MAX_ZIP_ENTRIES = 1000
MAX_UNZIPPED_BYTES = 64 * 1024 * 1024
MAX_REPEAT = 10_000
MAX_WIDTH = 10_000  # str.center/ljust/rjust/zfill/expandtabs and %-format widths
RENDER_TIMEOUT_S = 120
MAX_OUTPUT_BYTES = 512 * 1024 * 1024
CHILD_MEMORY_BYTES = 4 * 1024 * 1024 * 1024  # Linux only (RLIMIT_AS)
IMAGE_WIDTH_MM = 160
IMAGE_MAX_HEIGHT_MM = 200
SEVERITY_FILL = {"critical": "7F1D1D", "high": "DC2626", "medium": "EA580C", "low": "CA8A04", "info": "2563EB"}
RETEST_LABELS = {"resolved": "Resolved", "partially_resolved": "Partially resolved",
                 "not_resolved": "Not resolved"}
_XML_DECLARATIONS = tuple(m.encode(enc) for m in ("<!DOCTYPE", "<!ENTITY")
                          for enc in ("utf-8", "utf-16-le", "utf-16-be"))
# XML 1.0 forbids these; scanner output and pasted text sometimes contain them.
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


class TemplateProblem(ValueError):
    """The file is not a usable report template (message is shown to the user)."""


_PLAIN = (str, int, float, bool, type(None), list, tuple, dict)
_WIDTH_METHODS = {"center", "ljust", "rjust", "zfill", "expandtabs"}
_PRINTF_SIZES = re.compile(r"%[-+ #0]*(\*|\d+)?(?:\.(\*|\d+))?")


def _check_printf(fmt: str) -> None:
    for width, precision in _PRINTF_SIZES.findall(fmt):
        for n in (width, precision):
            if n == "*" or (n and int(n) > MAX_WIDTH):
                raise SecurityError("format width too large")


class _Sandbox(SandboxedEnvironment):
    intercepted_binops = frozenset({"*", "**", "%"})

    def is_safe_attribute(self, obj, attr, value):
        # Plain data and Jinja's own helpers (loop, cycler, namespace) only. Word objects
        # (InlineImage.tpl is the live DocxTemplate, with save() and friends) stay opaque.
        if not (isinstance(obj, _PLAIN) or type(obj).__module__.startswith("jinja2.")):
            return False
        return super().is_safe_attribute(obj, attr, value)

    def call_binop(self, context, operator, left, right):
        if operator == "**" and (not isinstance(left, (int, float)) or abs(left) > 10**6
                                 or not isinstance(right, (int, float)) or abs(right) > 100):
            raise SecurityError("power too large")
        if operator == "*":
            sizes = [len(v) for v in (left, right) if isinstance(v, (str, bytes, list, tuple))]
            counts = [v for v in (left, right) if isinstance(v, int)]
            if sizes and counts and sizes[0] * abs(counts[0]) > MAX_REPEAT * 100:
                raise SecurityError("repetition too large")
        if operator == "%" and isinstance(left, str):
            _check_printf(left)
        return super().call_binop(context, operator, left, right)

    def call(__self, __context, __obj, *args, **kwargs):  # noqa: N805 (Jinja's signature: "self" may be a kwarg)
        if (getattr(__obj, "__name__", "") in _WIDTH_METHODS and isinstance(getattr(__obj, "__self__", None), str)
                and any(isinstance(a, int) and a > MAX_WIDTH for a in (*args, *kwargs.values()))):
            raise SecurityError("width too large")
        return super().call(__context, __obj, *args, **kwargs)


def _safe_center(value, width=80):
    if isinstance(width, int) and width > MAX_WIDTH:
        raise SecurityError("width too large")
    return do_center(value, width)


def _safe_indent(s, width=4, *args, **kwargs):
    if isinstance(width, int) and width > MAX_WIDTH or isinstance(width, str) and len(width) > MAX_WIDTH:
        raise SecurityError("indent too large")
    return do_indent(s, width, *args, **kwargs)


def _safe_format(value, *args, **kwargs):
    _check_printf(str(value))
    return do_format(value, *args, **kwargs)


def _environment() -> SandboxedEnvironment:
    env = _Sandbox(autoescape=True)
    env.filters.update(center=_safe_center, indent=_safe_indent, format=_safe_format)
    return env


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
                # Every part but pictures, whatever its name, in UTF-8 or UTF-16.
                if info.filename.lower().startswith("word/media/"):
                    continue
                part = zf.read(info)
                if any(marker in part for marker in _XML_DECLARATIONS):
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
    c["prepared_by_line"] = ", ".join(x for x in (c["prepared_by"]["name"], c["branding"]["organization"]) if x)
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
    """Render the report context into a .docx (``template`` = a user's template bytes).

    The built-in template renders here. A user's template renders in a child
    process with a time limit: see the module docstring.
    """
    if template is None:
        return _render(ctx, None)
    check_template(template)
    mp = multiprocessing.get_context("spawn")
    receiver, sender = mp.Pipe(duplex=False)
    proc = mp.Process(target=_render_child, args=(sender, ctx, template), daemon=True,
                      name="offsechub-docx-template")
    proc.start()
    sender.close()
    try:
        if not receiver.poll(RENDER_TIMEOUT_S):
            raise TemplateProblem(f"rendering took longer than {RENDER_TIMEOUT_S} seconds, so it was stopped")
        try:
            # Raw bytes, never pickle: the child ran an untrusted template.
            message = receiver.recv_bytes(MAX_OUTPUT_BYTES)
        except EOFError:
            raise TemplateProblem("the renderer stopped (the template may use too much memory)") from None
        except OSError:
            raise TemplateProblem("the rendered report is too large") from None
    finally:
        receiver.close()
        if proc.is_alive():
            proc.kill()
        proc.join(10)
    kind, body = message[:1], message[1:]
    if kind == b"K":
        return body
    if kind == b"P":
        raise TemplateProblem(body.decode("utf-8", "replace"))
    raise RuntimeError(f"the Word renderer failed: {body.decode('utf-8', 'replace')}")


def _render_child(conn, ctx: dict, template: bytes) -> None:
    """Child process entry point: render, then send one status byte and the payload."""
    try:
        if sys.platform.startswith("linux"):
            import resource

            resource.setrlimit(resource.RLIMIT_AS, (CHILD_MEMORY_BYTES, CHILD_MEMORY_BYTES))
        body = _render(ctx, template)
    except TemplateProblem as exc:
        conn.send_bytes(b"P" + str(exc).encode("utf-8"))
    except MemoryError:
        conn.send_bytes(b"P" + b"the template used too much memory, so it was stopped")
    except BaseException as exc:  # reported to the parent, which raises
        conn.send_bytes(b"E" + f"{type(exc).__name__}: {exc}"[:2000].encode("utf-8"))
    else:
        conn.send_bytes(b"K" + body)
    finally:
        conn.close()


def _render(ctx: dict, template: bytes | None) -> bytes:
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
