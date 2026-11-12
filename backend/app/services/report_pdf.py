"""PDF engagement report, rendered with ReportLab platypus from ``reporting.build_context``.

The layout follows the HTML report (``templates/report.html.j2``): the same
sections in the same order, the same wording and the same severity colours,
plus what paper needs: a cover page, a running header and footer with
"Page X of Y", a table of contents and PDF bookmarks.

ReportLab's ``Paragraph`` takes an XML-like mini-markup, so user text must
never reach it raw: a finding that quotes ``<font name="x">`` or ``&amp;`` has
to print exactly that. Every piece of text from the context goes through
``_esc`` (``xml.sax.saxutils.escape`` after replacing control characters), and
the only tags in a paragraph are the ones this module writes around escaped
text: ``<b>``, ``<i>``, ``<font>``, ``<link>``, ``<a>`` and ``<br/>``. Header,
footer and code blocks are drawn with plain canvas strings, which have no
markup at all.

Text is set in the bundled DejaVu fonts (``data/fonts``), never in the 14
standard PDF fonts, which only cover Latin-1.
"""

from __future__ import annotations

import base64
import binascii
import re
import threading
import warnings
from collections import Counter
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image as PILImage
from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.doctemplate import IndexingFlowable
from reportlab.platypus.tableofcontents import TableOfContents

from . import richtext

__all__ = ["render_pdf"]

FONT_DIR = Path(__file__).resolve().parent.parent / "data" / "fonts"
SANS = "OffsecHubSans"
SANS_BOLD = "OffsecHubSans-Bold"
SANS_ITALIC = "OffsecHubSans-Oblique"
SANS_BOLD_ITALIC = "OffsecHubSans-BoldOblique"
MONO = "OffsecHubMono"
MONO_BOLD = "OffsecHubMono-Bold"
_FONT_FILES = {
    SANS: "DejaVuSans.ttf",
    SANS_BOLD: "DejaVuSans-Bold.ttf",
    SANS_ITALIC: "DejaVuSans-Oblique.ttf",
    SANS_BOLD_ITALIC: "DejaVuSans-BoldOblique.ttf",
    MONO: "DejaVuSansMono.ttf",
    MONO_BOLD: "DejaVuSansMono-Bold.ttf",
}

# The HTML report's palette.
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLOURS = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#ea580c",
                    "low": "#ca8a04", "info": "#2563eb"}
SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
                   "info": "Informational"}
RETEST_LABELS = {"resolved": "Resolved", "partially_resolved": "Partially resolved",
                 "not_resolved": "Not resolved"}
RETEST_COLOURS = {"resolved": "#047857", "partially_resolved": "#b45309",
                  "not_resolved": "#b91c1c"}
INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
LINE = colors.HexColor("#e5e7eb")
SOFT = colors.HexColor("#f9fafb")
CODE_BG = colors.HexColor("#f3f4f6")
DRAFT_BG, DRAFT_INK, DRAFT_BORDER = (colors.HexColor(c) for c in ("#fef3c7", "#92400e", "#fcd34d"))
DEFAULT_ACCENT = "#0f766e"
DEFAULT_CLASSIFICATION = "CONFIDENTIAL"

PAGE_W, PAGE_H = A4
MARGIN_X = 56
MARGIN_TOP = 66
MARGIN_BOTTOM = 70
FRAME_W = PAGE_W - 2 * MARGIN_X
FRAME_H = PAGE_H - MARGIN_TOP - MARGIN_BOTTOM

# Evidence images: decoded (and so verified to be an image) before they are
# embedded; anything larger is downscaled, anything absurd is left out.
MAX_IMAGE_PIXELS = 40_000_000
MAX_IMAGE_SIDE = 2400
MAX_TITLE_CHARS = 2000
CELL_PAD = 4.5
# Wide enough for a whole SHA-256 on one line (7 pt mono), so it reads and copies as one.
HASH_COL_W = 64 * 7 * 0.6021 + 2 * CELL_PAD + 1.5

_HEX_COLOUR = re.compile(r"^#[0-9a-fA-F]{6}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff]")
_URL = re.compile(r"^(?:https?://|mailto:)[^\s<>\"]+$", re.IGNORECASE)

_fonts_lock = threading.Lock()
_fonts_ready = False
_render_lock = threading.Lock()


def register_fonts() -> None:
    """Register the bundled DejaVu faces with ReportLab (once per process)."""
    global _fonts_ready
    with _fonts_lock:
        if _fonts_ready:
            return
        # Binary streams: ASCII85 (ReportLab's default) makes every image and page
        # a quarter larger for nothing. OffsecHub is the only ReportLab user here.
        rl_config.useA85 = 0
        for name, filename in _FONT_FILES.items():
            pdfmetrics.registerFont(TTFont(name, str(FONT_DIR / filename)))
        pdfmetrics.registerFontFamily(SANS, normal=SANS, bold=SANS_BOLD, italic=SANS_ITALIC,
                                      boldItalic=SANS_BOLD_ITALIC)
        # No oblique mono face is bundled: italic code stays upright.
        pdfmetrics.registerFontFamily(MONO, normal=MONO, bold=MONO_BOLD, italic=MONO,
                                      boldItalic=MONO_BOLD)
        _fonts_ready = True


# ------------------------------------------------------------------ text helpers


def _clean(value) -> str:
    """Text as a str with control characters (and lone surrogates) made visible as U+FFFD."""
    if value is None:
        return ""
    return _CONTROL.sub("\ufffd", value if isinstance(value, str) else str(value))


def _esc(value) -> str:
    """Text for ReportLab paragraph markup: nothing in it can be read as a tag or entity."""
    return escape(_clean(value))


def _attr(value) -> str:
    """Text for a double-quoted attribute in paragraph markup."""
    return escape(_clean(value), {'"': "&quot;"})


def _hex(colour: colors.Color) -> str:
    return "#" + colour.hexval()[2:]


def _tint(colour: colors.Color, amount: float) -> colors.Color:
    """``colour`` mixed with white (amount 0 = white, 1 = the colour)."""
    return colors.Color(*(1 - amount + amount * c for c in (colour.red, colour.green, colour.blue)))


def _fit(text: str, font: str, size: float, width: float) -> str:
    """``text`` cut with an ellipsis so it fits ``width`` on one line."""
    if pdfmetrics.stringWidth(text, font, size) <= width:
        return text
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if pdfmetrics.stringWidth(text[:mid] + "\u2026", font, size) <= width:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo].rstrip() + "\u2026"


def _table_style(commands: list) -> TableStyle:
    """A table style that also sets the cell font: a Table selects one for every cell it
    draws, even when the cell holds a flowable, and the default would pull in Helvetica."""
    return TableStyle([("FONT", (0, 0), (-1, -1), SANS, 8.5), *commands])


@lru_cache(maxsize=4096)
def _char_width(ch: str, font: str, size: float) -> float:
    return pdfmetrics.stringWidth(ch, font, size)


def _wrap_chars(line: str, font: str, size: float, width: float) -> list[str]:
    """Hard-wrap one line of preformatted text at the character that would overflow."""
    if not line:
        return [""]
    if line.isascii() and font in (MONO, MONO_BOLD):  # every ASCII glyph has the same advance
        per = max(1, int(width // _char_width("0", font, size)))
        return [line[i:i + per] for i in range(0, len(line), per)]
    out, cur, used = [], [], 0.0
    for ch in line:
        w = _char_width(ch, font, size)
        if cur and used + w > width:
            out.append("".join(cur))
            cur, used = [], 0.0
        cur.append(ch)
        used += w
    out.append("".join(cur))
    return out


def _score(value) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, float):
        return f"{value:.1f}"
    return _clean(value)


def _byte_count(size) -> str:
    if isinstance(size, int):
        return f"{size:,} byte{'' if size == 1 else 's'}"
    return _clean(size)


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _dicts(value) -> list[dict]:
    """The dicts in a list from the context (anything else in it is ignored)."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, (list, tuple)) else []


def _strings(value) -> list:
    """A list of values from the context; a lone string counts as one."""
    if isinstance(value, str):
        return [value] if value else []
    return [v for v in value if v is not None] if isinstance(value, (list, tuple)) else []


def _words(value) -> str:
    return _clean(value).replace("_", " ")


def _cvss_label(f: dict) -> str:
    version = _clean(f.get("cvss_version"))
    if not version:
        prefix = _clean(f.get("cvss_vector")).strip().split("/", 1)[0]
        version = prefix[5:] if prefix.upper().startswith("CVSS:") else ""
    return f"CVSS v{version}" if version else "CVSS"


def _image_bytes(item: dict) -> bytes | None:
    data = item.get("data")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    uri = item.get("data_uri")
    if isinstance(uri, str) and uri.startswith("data:") and "," in uri:
        head, _, payload = uri.partition(",")
        if head.endswith(";base64"):
            try:
                return base64.b64decode(payload)
            except (binascii.Error, ValueError):
                return None
    return None


def _load_image(data: bytes) -> tuple[ImageReader, int, int]:
    """Decode an image fully and return something ReportLab can embed, plus its pixel size.

    Raises on anything that is not a decodable raster image of sane dimensions.
    JPEGs that need no change are passed through as they are; everything else
    is converted to RGB(A) or greyscale, turned upright (EXIF orientation, as a
    browser shows it) and downscaled to ``MAX_IMAGE_SIDE``.
    """

    with warnings.catch_warnings():
        warnings.simplefilter("error", PILImage.DecompressionBombWarning)
        im = PILImage.open(BytesIO(data))
        width, height = im.size
        if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
            raise ValueError("image dimensions out of range")
        orientation = im.getexif().get(0x0112, 1)
        if orientation in (5, 6, 7, 8):  # stored rotated by 90 degrees
            width, height = height, width
        if (im.format == "JPEG" and im.mode in ("RGB", "L") and orientation in (1, None)
                and max(width, height) <= MAX_IMAGE_SIDE):
            im.load()  # a truncated or corrupt file fails here, not in the PDF viewer
            return ImageReader(BytesIO(data)), width, height
        if im.format == "JPEG":
            im.draft("RGB", (MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
        im.load()
        if im.mode in ("RGBA", "LA", "PA") or (im.mode == "P" and "transparency" in im.info):
            im = im.convert("RGBA")
            if im.getextrema()[3][0] == 255:  # fully opaque: no soft mask needed
                im = im.convert("RGB")
        elif im.mode not in ("RGB", "L"):
            im = im.convert("RGB")
        T = PILImage.Transpose
        turn = {2: T.FLIP_LEFT_RIGHT, 3: T.ROTATE_180, 4: T.FLIP_TOP_BOTTOM, 5: T.TRANSPOSE,
                6: T.ROTATE_270, 7: T.TRANSVERSE, 8: T.ROTATE_90}.get(orientation)
        if turn is not None:
            im = im.transpose(turn)
        if max(im.size) > MAX_IMAGE_SIDE:
            im.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
        return ImageReader(im), width, height


# ------------------------------------------------------------------ flowables

class _Para(Paragraph):
    """A Paragraph that remembers its line breaks for the last width it was wrapped to.

    Breaking lines is most of the work, and the same paragraph is wrapped
    several times at the same width: by tables sizing their rows, by the frame,
    and again in multiBuild's second pass.
    """

    _oh_wrapped_at = None

    def wrap(self, availWidth, availHeight):
        if self._oh_wrapped_at == availWidth and getattr(self, "blPara", None) is not None:
            return self.width, self.height
        size = super().wrap(availWidth, availHeight)
        self._oh_wrapped_at = availWidth if size[1] != 0x7FFFFFFF else None  # not "no room"
        return size


class _Badge(Flowable):
    """A severity pill: white upper-case text on the severity colour."""

    def __init__(self, label: str, colour: colors.Color, size: float = 7):
        super().__init__()
        self.label = _fit(_clean(label).upper() or "-", SANS_BOLD, size, 120)
        self.colour, self.size = colour, size
        self.pad_x, self.pad_y = 5, 2.4
        self.width = pdfmetrics.stringWidth(self.label, SANS_BOLD, size) + 2 * self.pad_x
        self.height = size + 2 * self.pad_y

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(self.colour)
        c.roundRect(0, 0, self.width, self.height, self.height / 2, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont(SANS_BOLD, self.size)
        c.drawCentredString(self.width / 2, self.height / 2 - self.size * 0.36, self.label)


class _Bar(Flowable):
    """One bar of the severity chart, as wide as its share of the largest count."""

    def __init__(self, fraction: float, colour: colors.Color, height: float = 9):
        super().__init__()
        self.fraction, self.colour, self.height = max(0.0, min(1.0, fraction)), colour, height

    def wrap(self, availWidth, availHeight):
        self.width = availWidth
        return availWidth, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(SOFT)
        c.rect(0, 0, self.width, self.height, stroke=0, fill=1)
        if self.fraction > 0:
            c.setFillColor(self.colour)
            c.roundRect(0, 0, max(2.0, self.width * self.fraction), self.height, 1.5, stroke=0,
                        fill=1)


class _Rule(Flowable):
    """The accent line under a section heading."""

    def __init__(self, colour: colors.Color, thickness: float = 2, space_after: float = 8):
        super().__init__()
        self.colour, self.thickness = colour, thickness
        self.spaceBefore, self.spaceAfter = 2, space_after
        self.keepWithNext = 1

    def wrap(self, availWidth, availHeight):
        self.width = availWidth
        return availWidth, self.thickness

    def draw(self):
        self.canv.setFillColor(self.colour)
        self.canv.rect(0, 0, self.width, self.thickness, stroke=0, fill=1)


class _CodeBlock(Flowable):
    """Preformatted text in the mono font on a light panel.

    Long lines are hard-wrapped at the available width (ReportLab's
    ``Preformatted`` would run off the page), and the block splits across
    pages line by line. It is drawn with canvas text, so no markup applies.
    """

    font, size, leading, pad = MONO, 8, 10.6, 6

    def __init__(self, text: str | None = None, *, lines: list[str] | None = None,
                 top: bool = True, bottom: bool = True):
        super().__init__()
        self.source = lines if lines is not None else _clean(text).expandtabs(4).split("\n")
        self.top, self.bottom = top, bottom
        self.spaceBefore = 3 if top else 0
        self.spaceAfter = 6 if bottom else 0
        self._wrapped_at: float | None = None
        self._lines: list[str] = []

    def _layout(self, availWidth: float) -> list[str]:
        inner = max(availWidth - 2 * self.pad, 4 * self.size)
        if self._wrapped_at != inner:
            self._lines = [part for line in self.source
                           for part in _wrap_chars(line, self.font, self.size, inner)]
            self._wrapped_at = inner
        return self._lines

    def _pads(self) -> float:
        return (self.pad if self.top else 0) + (self.pad if self.bottom else 0)

    def wrap(self, availWidth, availHeight):
        lines = self._layout(availWidth)
        self.width = availWidth
        self.height = len(lines) * self.leading + self._pads()
        return self.width, self.height

    def split(self, availWidth, availHeight):
        lines = self._layout(availWidth)
        room = availHeight - (self.pad if self.top else 0) - 1
        n = min(int(room // self.leading), len(lines) - 1)
        if n < 1:
            return []
        return [_CodeBlock(lines=lines[:n], top=self.top, bottom=False),
                _CodeBlock(lines=lines[n:], top=False, bottom=self.bottom)]

    def draw(self):
        c = self.canv
        w, h = self.width, self.height
        c.setFillColor(CODE_BG)
        c.rect(0, 0, w, h, stroke=0, fill=1)
        c.setStrokeColor(LINE)
        c.setLineWidth(0.6)
        c.line(0, 0, 0, h)
        c.line(w, 0, w, h)
        if self.top:
            c.line(0, h, w, h)
        if self.bottom:
            c.line(0, 0, w, 0)
        text = c.beginText(self.pad, h - (self.pad if self.top else 0) - self.size)
        text.setFont(self.font, self.size, self.leading)
        text.setFillColor(INK)
        for line in self._lines:
            text.textLine(line)
        c.drawText(text)


class _Picture(Flowable):
    """An image at its natural size (96 dpi), scaled down to fit the frame width and a height."""

    def __init__(self, reader: ImageReader, px_w: int, px_h: int, *, max_w: float | None = None,
                 max_h: float = FRAME_H * 0.8, border: bool = True, hAlign: str = "LEFT"):
        super().__init__()
        self.reader, self.px_w, self.px_h = reader, px_w, px_h
        self.max_w, self.max_h, self.border, self.hAlign = max_w, max_h, border, hAlign

    def wrap(self, availWidth, availHeight):
        natural_w, natural_h = self.px_w * 0.75, self.px_h * 0.75
        scale = min(1.0, availWidth / natural_w, (self.max_w or availWidth) / natural_w,
                    self.max_h / natural_h)
        self.width, self.height = natural_w * scale, natural_h * scale
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.drawImage(self.reader, 0, 0, self.width, self.height, mask="auto")
        if self.border:
            c.setStrokeColor(LINE)
            c.setLineWidth(0.75)
            c.rect(0, 0, self.width, self.height, stroke=1, fill=0)


class _Contents(TableOfContents):
    """Table of contents as a two-column table: wrapped titles, page numbers aligned right.

    Both columns link to the heading. The entries' text is markup this
    module built from escaped strings.
    """

    def __init__(self, level_styles: list[ParagraphStyle], number_style: ParagraphStyle):
        super().__init__(levelStyles=level_styles, dotsMinLevel=-1)
        self.number_style = number_style
        self.tableStyle = _table_style([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 1.6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6),
        ])

    def wrap(self, availWidth, availHeight):
        rows = []
        for level, text, page, key in self._lastEntries or [(0, "", 0, None)]:
            style = self.getLevelStyle(level)
            if key:
                rows.append([_Para(f'<a href="#{key}">{text}</a>', style),
                             _Para(f'<a href="#{key}">{page}</a>', self.number_style)])
            else:
                rows.append([_Para(text, style), _Para(str(page), self.number_style)])
        number_w = 40
        self._table = Table(rows, colWidths=(availWidth - number_w, number_w),
                            style=self.tableStyle, splitInRow=1)
        self.width, self.height = self._table.wrapOn(self.canv, availWidth, availHeight)
        return self.width, self.height


class _PageTotal(IndexingFlowable):
    """The document's page count, for "Page X of Y".

    The footer of each pass shows the total the previous pass ended with, and
    ``multiBuild`` keeps building until the two agree (alongside the table of
    contents, which needs the same second pass). Unlike buffering every page
    until the end, this leaves bookmarks and links pointing at the right pages.
    """

    def __init__(self):
        super().__init__()
        self.doc: BaseDocTemplate | None = None
        self.total = 0  # where the last pass ended
        self.shown = 0  # what this pass prints

    def beforeBuild(self):
        self.shown = self.total

    def afterBuild(self):
        self.total = self.doc.page if self.doc else 0

    def isSatisfied(self):
        return self.shown == self.total

    def wrap(self, availWidth, availHeight):
        return 0, 0

    def draw(self):
        pass


class _ReportDoc(BaseDocTemplate):
    def afterFlowable(self, flowable):
        entry = getattr(flowable, "_oh_toc", None)
        if entry:
            level, markup, plain, key = entry
            self.canv.addOutlineEntry(plain, key, level=level, closed=False)
            self.notify("TOCEntry", (level, markup, self.page, key))


# ------------------------------------------------------------------ renderer


class _Renderer:
    def __init__(self, ctx: dict):
        self.ctx = ctx
        self.eng = _dict(ctx.get("engagement"))
        self.client = _dict(ctx.get("client"))
        self.prepared = _dict(ctx.get("prepared_by"))
        branding = _dict(ctx.get("branding"))
        self.branding = branding
        accent = branding.get("accent") or DEFAULT_ACCENT
        self.accent = colors.HexColor(accent if _HEX_COLOUR.match(str(accent)) else DEFAULT_ACCENT)
        self.classification = _clean(branding.get("classification", DEFAULT_CLASSIFICATION)).strip()
        # Branding names the organisation on the cover (it defaults to the profile's).
        self.organization = _clean(branding["organization"] if "organization" in branding
                                   else self.prepared.get("organization")).strip()
        self.footer_text = _clean(branding.get("footer")).strip()
        self.code = _clean(self.eng.get("code")).strip()
        self.client_name = _clean(self.client.get("name")).strip()
        self.generated_at = _clean(ctx.get("generated_at"))
        self.draft = bool(ctx.get("draft"))
        self.findings = _dicts(ctx.get("findings"))
        self.toc_entries: list[tuple] = []
        self._footer_markup: str | None = None
        self._styles()

    # ---------------------------------------------------------------- styles

    def _styles(self) -> None:
        def style(name, **kw):
            base = {"fontName": SANS, "fontSize": 9.5, "leading": 13.6, "textColor": INK,
                    "splitLongWords": 1, "spaceAfter": 5}
            return ParagraphStyle(name, **{**base, **kw})

        accent = self.accent
        self.st = {
            "body": style("body"),
            "muted": style("muted", textColor=MUTED),
            "small": style("small", fontSize=8.5, leading=11.5, textColor=MUTED),
            "h2": style("h2", fontName=SANS_BOLD, fontSize=16, leading=20, spaceBefore=16,
                        spaceAfter=3, keepWithNext=1),
            "h3": style("h3", fontName=SANS_BOLD, fontSize=12, leading=15, spaceBefore=12,
                        spaceAfter=5, keepWithNext=1),
            "h4": style("h4", fontName=SANS_BOLD, fontSize=10.5, leading=13.5, spaceBefore=9,
                        spaceAfter=3, keepWithNext=1),
            "finding": style("finding", fontName=SANS_BOLD, fontSize=12, leading=15.5,
                             spaceAfter=0),
            "rich_h1": style("rich_h1", fontName=SANS_BOLD, fontSize=10.5, leading=13.5,
                             spaceBefore=6, spaceAfter=3, keepWithNext=1),
            "rich_h2": style("rich_h2", fontName=SANS_BOLD, fontSize=10, leading=13,
                             spaceBefore=5, spaceAfter=2, keepWithNext=1),
            "rich_h3": style("rich_h3", fontName=SANS_BOLD, fontSize=9.5, leading=12.5,
                             spaceBefore=4, spaceAfter=2, keepWithNext=1),
            "td": style("td", fontSize=8.5, leading=11.2, spaceAfter=0),
            "td_rich": style("td_rich", fontSize=8.5, leading=11.2, spaceAfter=3),
            "th": style("th", fontName=SANS_BOLD, fontSize=8.5, leading=11.2, spaceAfter=0),
            "th_right": style("th_right", fontName=SANS_BOLD, fontSize=8.5, leading=11.2,
                              spaceAfter=0, alignment=TA_RIGHT),
            "td_mono": style("td_mono", fontName=MONO, fontSize=7.5, leading=10.4, spaceAfter=0),
            "td_hash": style("td_hash", fontName=MONO, fontSize=7, leading=9.4, spaceAfter=0),
            "td_right": style("td_right", fontSize=8.5, leading=11.2, spaceAfter=0,
                              alignment=TA_RIGHT),
            "meta_label": style("meta_label", fontSize=9, leading=12.5, textColor=MUTED,
                                spaceAfter=0),
            "meta": style("meta", fontSize=9, leading=12.5, spaceAfter=0),
            "meta_mono": style("meta_mono", fontName=MONO, fontSize=8.5, leading=12,
                               spaceAfter=0),
            "ref": style("ref", fontName=MONO, fontSize=8.5, leading=11.5, spaceAfter=1.5,
                         leftIndent=14, bulletIndent=3, bulletFontName=SANS, bulletFontSize=8.5),
            "caption": style("caption", fontSize=8.5, leading=11.5, textColor=MUTED,
                             spaceBefore=3, spaceAfter=10),
            "toc0": style("toc0", fontName=SANS_BOLD, fontSize=10, leading=14, spaceAfter=0),
            "toc1": style("toc1", fontSize=9, leading=12, leftIndent=14, spaceAfter=0),
            "toc_page": style("toc_page", fontSize=9, leading=12, alignment=TA_RIGHT,
                              spaceAfter=0),
            "cover_org": style("cover_org", fontName=SANS_BOLD, fontSize=11, leading=14,
                               textColor=INK),
            "cover_kicker": style("cover_kicker", fontName=SANS_BOLD, fontSize=13, leading=17,
                                  textColor=accent, spaceAfter=10),
            "cover_title": style("cover_title", fontName=SANS_BOLD, fontSize=26, leading=31,
                                 spaceAfter=8),
            "cover_sub": style("cover_sub", fontSize=15, leading=19, spaceAfter=18),
            "cover_meta": style("cover_meta", fontSize=10, leading=15, textColor=MUTED,
                                spaceAfter=0),
            "cover_note": style("cover_note", fontSize=8.5, leading=12, textColor=MUTED),
            "draft": style("draft", fontName=SANS_BOLD, fontSize=10, leading=13,
                           textColor=DRAFT_INK, spaceAfter=0),
            "footer": style("footer", fontSize=7.5, leading=9.5, textColor=MUTED, spaceAfter=0),
        }
        self._list_styles: dict[tuple[float, bool], ParagraphStyle] = {}
        self.table_style = _table_style([
            ("BACKGROUND", (0, 0), (-1, 0), _tint(self.accent, 0.12)),
            ("LINEBELOW", (0, 0), (-1, 0), 1, _tint(self.accent, 0.6)),
            ("LINEBELOW", (0, 1), (-1, -1), 0.6, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), CELL_PAD),
            ("RIGHTPADDING", (0, 0), (-1, -1), CELL_PAD),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])

    def _list_style(self, bullet_w: float, compact: bool) -> ParagraphStyle:
        base = self.st["td_rich" if compact else "body"]
        indent = max(14.0 if compact else 16.0, round(bullet_w + 8))
        key = (indent, compact)
        if key not in self._list_styles:
            self._list_styles[key] = ParagraphStyle(
                f"{base.name}-li{indent}", parent=base, leftIndent=indent, bulletIndent=2,
                bulletFontName=SANS, bulletFontSize=base.fontSize, spaceAfter=2)
        return self._list_styles[key]

    # ---------------------------------------------------------------- helpers

    def p(self, text, style: str = "body") -> Paragraph:
        return _Para(_esc(text), self.st[style])

    def muted(self, text: str) -> Paragraph:
        return _Para(f"<i>{_esc(text)}</i>", self.st["muted"])

    def cols(self, *widths: float | None) -> list[float]:
        """Column widths filling the frame; ``None`` columns share what is left."""
        fixed = sum(w for w in widths if w)
        flex = [w for w in widths if not w]
        rest = max(40.0, (FRAME_W - fixed) / max(1, len(flex)))
        return [w if w else rest for w in widths]

    def table(self, header: list[str], rows: list[list], widths: list[float],
              right: tuple[int, ...] = ()) -> Table:
        """A data table: tinted header row repeated on each page, rows split across pages."""
        data = [[_Para(_esc(h), self.st["th_right" if i in right else "th"])
                 for i, h in enumerate(header)]] + rows
        t = Table(data, colWidths=widths, repeatRows=1, splitByRow=1, splitInRow=1,
                  hAlign="LEFT", spaceBefore=4, spaceAfter=10)
        t.setStyle(self.table_style)
        return t

    def mono_width(self, values, size: float, lo: float, hi: float) -> float:
        widest = max((pdfmetrics.stringWidth(_clean(v), MONO, size) for v in values), default=0)
        return max(lo, min(hi, widest + 10))

    def severity_colour(self, severity) -> colors.Color:
        return colors.HexColor(SEVERITY_COLOURS.get(_clean(severity).lower(), _hex(MUTED)))

    def badge(self, severity, size: float = 7) -> _Badge:
        return _Badge(_clean(severity) or "-", self.severity_colour(severity), size)

    def retest_markup(self, result) -> str:
        result = _clean(result)
        label = RETEST_LABELS.get(result, _words(result) or "-")
        colour = RETEST_COLOURS.get(result)
        return f'<font color="{colour}"><b>{_esc(label)}</b></font>' if colour else _esc(label)

    def section(self, title: str, key: str, *, toc: bool = True) -> list[Flowable]:
        heading = _Para(f'<a name="{key}"/>{_esc(title)}', self.st["h2"])
        if toc:
            heading._oh_toc = (0, _esc(title), title, key)
            self.toc_entries.append((0, _esc(title), 0, key))
        return [heading, _Rule(self.accent)]

    # ---------------------------------------------------------------- rich text

    def spans(self, spans: list[richtext.Span]) -> str:
        out = []
        for s in spans:
            if s.is_break:
                out.append("<br/>")
                continue
            piece = _esc(s.text)
            if s.code:
                piece = f'<font face="{MONO}" backColor="{_hex(CODE_BG)}">{piece}</font>'
            if s.italic:
                piece = f"<i>{piece}</i>"
            if s.bold:
                piece = f"<b>{piece}</b>"
            if s.href:
                piece = f'<link href="{_attr(s.href)}" color="{_hex(self.accent)}">{piece}</link>'
            out.append(piece)
        return "".join(out)

    def blocks(self, blocks: list[richtext.Block], *, compact: bool = False) -> list[Flowable]:
        """Flowables for parsed rich text; ``compact`` sets it at table-cell size."""
        out: list[Flowable] = []
        body = self.st["td_rich" if compact else "body"]
        for b in blocks:
            if b.kind == "paragraph":
                out.append(_Para(self.spans(b.spans), body))
            elif b.kind == "heading":
                style = "th" if compact else f"rich_h{min(3, max(1, b.level))}"
                out.append(_Para(self.spans(b.spans), self.st[style]))
            elif b.kind == "code":
                out.append(_CodeBlock(b.text))
            elif b.kind in ("bullets", "numbers") and b.items:
                if b.kind == "bullets":
                    labels = ["\u2022"] * len(b.items)
                else:
                    labels = [f"{b.start + i}." for i in range(len(b.items))]
                width = max(pdfmetrics.stringWidth(lbl, SANS, body.fontSize) for lbl in labels)
                style = self._list_style(width, compact)
                for label, item in zip(labels, b.items):
                    out.append(_Para(self.spans(item), style, bulletText=label))
                out.append(Spacer(1, 3))
        return out

    def rich(self, text, *, compact: bool = False) -> list[Flowable]:
        return self.blocks(richtext.parse(_clean(text)), compact=compact)

    def steps(self, text) -> list[Flowable]:
        """Unformatted steps (often a raw HTTP request) stay a code block, as in the HTML report."""
        text = _clean(text).replace("\r\n", "\n").replace("\r", "\n")
        blocks = richtext.parse(text)
        if richtext.is_plain(blocks):
            return [_CodeBlock(text.strip("\n"))]
        return self.blocks(blocks)

    # ---------------------------------------------------------------- pages

    def draw_cover_page(self, canv: Canvas, doc) -> None:
        canv.saveState()
        canv.setFillColor(self.accent)
        canv.rect(MARGIN_X - 2, MARGIN_BOTTOM, 6, PAGE_H - MARGIN_TOP - MARGIN_BOTTOM,
                  stroke=0, fill=1)
        canv.restoreState()

    def draw_body_page(self, canv: Canvas, doc) -> None:
        canv.saveState()
        left, right = MARGIN_X, PAGE_W - MARGIN_X
        y = PAGE_H - 40
        x = left
        if self.classification:
            canv.setFont(SANS_BOLD, 8)
            canv.setFillColor(self.accent)
            label = _fit(self.classification, SANS_BOLD, 8, FRAME_W * 0.45)
            canv.drawString(x, y, label)
            x += pdfmetrics.stringWidth(label, SANS_BOLD, 8) + 10
        if self.draft:
            canv.setFont(SANS_BOLD, 8)
            canv.setFillColor(DRAFT_INK)
            canv.drawString(x, y, "DRAFT")
            x += pdfmetrics.stringWidth("DRAFT", SANS_BOLD, 8) + 10
        canv.setFont(SANS, 8)
        canv.setFillColor(MUTED)
        code = _fit(self.code, SANS, 8, FRAME_W * 0.3)
        room = right - x - 12 - pdfmetrics.stringWidth(code + " \u00b7 ", SANS, 8)
        heading = code
        if self.client_name and room > 40:
            client = _fit(self.client_name, SANS, 8, room)
            heading = f"{client} \u00b7 {code}" if code else client
        canv.drawRightString(right, y, heading)
        canv.setStrokeColor(LINE)
        canv.setLineWidth(0.6)
        canv.line(left, y - 7, right, y - 7)

        top = MARGIN_BOTTOM - 22
        canv.line(left, top + 9, right, top + 9)
        footer = _Para(self.footer_markup(), self.st["footer"])
        _, h = footer.wrapOn(canv, FRAME_W - 90, 40)
        footer.drawOn(canv, left, top - h + 7)
        canv.setFont(SANS, 7.5)
        canv.setFillColor(MUTED)
        canv.drawRightString(right, top, f"Page {doc.page} of {self.page_total.shown or '?'}")
        canv.restoreState()

    def footer_markup(self) -> str:
        """The branding footer (or the generator line), cut to at most three lines."""
        if self._footer_markup is None:
            text = self.footer_text or f"Generated by OffsecHub on {self.generated_at}"
            while True:
                markup = _esc(text)
                _, h = _Para(markup, self.st["footer"]).wrap(FRAME_W - 90, 100)
                if h <= 3 * self.st["footer"].leading + 0.1 or len(text) < 24:
                    break
                text = text[:int(len(text) * 0.85)].rstrip() + "\u2026"
            self._footer_markup = markup
        return self._footer_markup

    # ---------------------------------------------------------------- sections

    def cover(self) -> list[Flowable]:
        out: list[Flowable] = []
        logo = _image_bytes({"data": self.branding.get("logo"),
                             "data_uri": self.branding.get("logo_data_uri")})
        if logo:
            try:
                reader, w, h = _load_image(logo)
            except Exception:  # a broken logo never stops the report
                pass
            else:
                out += [_Picture(reader, w, h, max_w=200, max_h=72, border=False), Spacer(1, 8)]
        if self.organization:
            out.append(self.p(self.organization, "cover_org"))
        out.append(Spacer(1, 120 if out else 150))
        if self.draft:
            banner = Table([[_Para("DRAFT - not for distribution", self.st["draft"])]],
                           colWidths=[220], hAlign="LEFT", spaceAfter=22)
            banner.setStyle(_table_style([
                ("BACKGROUND", (0, 0), (-1, -1), DRAFT_BG),
                ("BOX", (0, 0), (-1, -1), 0.8, DRAFT_BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            out.append(banner)
        out.append(self.p(self.eng.get("type") or "Security Assessment", "cover_kicker"))
        out.append(self.p(self.client_name, "cover_title"))
        out.append(self.p(self.eng.get("name"), "cover_sub"))
        lines = [f"Reference {_clean(self.eng.get('code'))}"]
        start, end = _clean(self.eng.get("start_date")), _clean(self.eng.get("end_date"))
        if start:
            lines.append(f"Testing window {start}" + (f" to {end}" if end else ""))
        by = [s for s in (_clean(self.prepared.get("name")).strip(), self.organization) if s]
        if by:
            lines.append("Prepared by " + ", ".join(by))
        lines.append(f"Generated {self.generated_at}")
        out.append(_Para("<br/>".join(_esc(line) for line in lines), self.st["cover_meta"]))
        if self.classification:
            out += [Spacer(1, 40), _Para(
                f"<b>{_esc(self.classification)}</b>. This report contains sensitive security "
                f"information about {_esc(self.client_name)}. Distribution is restricted to "
                f"authorised recipients.", self.st["cover_note"])]
        return out

    def contents(self) -> list[Flowable]:
        self.toc = _Contents([self.st["toc0"], self.st["toc1"]], self.st["toc_page"])
        return [_Para("Contents", self.st["h2"]), _Rule(self.accent), self.toc]

    def summary(self) -> list[Flowable]:
        out = self.section("1. Executive summary", "s-summary")
        out += self.rich(self.eng.get("executive_summary")) or [
            self.muted("No executive summary has been written yet.")]
        if _clean(self.eng.get("description")).strip():
            out.append(self.p("Engagement background", "h3"))
            out += self.rich(self.eng.get("description"))
        return out

    def overview(self) -> list[Flowable]:
        out = self.section("2. Findings overview", "s-overview")
        total = self.ctx.get("total_findings")
        if not isinstance(total, int):
            total = len(self.findings)
        out.append(self.p(f"{total} finding{'' if total == 1 else 's'} reported."))
        counts = self.ctx.get("severity_counts")
        if not isinstance(counts, dict):
            seen = Counter(_clean(f.get("severity")).lower() for f in self.findings)
            counts = {s: seen.get(s, 0) for s in SEVERITIES}
        top = max([n for n in counts.values() if isinstance(n, int)] + [1])
        rows = []
        for sev, n in counts.items():
            n = n if isinstance(n, int) else 0
            rows.append([self.badge(sev), _Bar(n / top, self.severity_colour(sev)),
                         _Para(f"<b>{n}</b>", self.st["td"])])
        bars = Table(rows, colWidths=[78, 260, 36], hAlign="LEFT", spaceBefore=2, spaceAfter=12)
        bars.setStyle(_table_style([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        out.append(bars)
        if not self.findings:
            return out
        retested = bool(self.ctx.get("retested")) or any(f.get("retest_status")
                                                          for f in self.findings)
        ref_w = self.mono_width((f.get("ref") for f in self.findings), 7.5, 42, 104)
        header = ["Ref", "Title", "Severity", "CVSS", "Status"]
        widths = [ref_w, None, 56, 38, 60]
        if retested:
            header.append("Retest")
            widths.append(70)
        header.append("Affected")
        widths.append(52)
        rows = []
        for i, f in enumerate(self.findings):
            row = [
                _Para(f'<a href="#f{i}">{_esc(f.get("ref"))}</a>', self.st["td_mono"]),
                self.p(_clean(f.get("title"))[:MAX_TITLE_CHARS], "td"),
                self.badge(f.get("severity")),
                self.p(_score(f.get("cvss_score")), "td"),
                self.p(_words(f.get("status")), "td"),
            ]
            if retested:
                status = f.get("retest_status")
                row.append(_Para(self.retest_markup(status) if status else "-", self.st["td"]))
            row.append(self.p(str(len(_strings(f.get("targets")))), "td"))
            rows.append(row)
        out.append(self.table(header, rows, self.cols(*widths)))
        return out

    def scope(self) -> list[Flowable]:
        out = self.section("3. Scope and rules of engagement", "s-scope")
        scope = _dict(self.ctx.get("scope"))

        def scope_table(items):
            widths = self.cols(70, 180, None)
            rows = [[self.p(s.get("kind"), "td"), self.p(s.get("value"), "td_mono"),
                     self.p(s.get("notes"), "td")] for s in items]
            return self.table(["Type", "Value", "Notes"], rows, widths)

        out.append(self.p("In scope", "h3"))
        include = _dicts(scope.get("include"))
        out.append(scope_table(include) if include else self.p("No scope recorded.", "muted"))
        exclude = _dicts(scope.get("exclude"))
        if exclude:
            out += [self.p("Explicitly excluded", "h3"), scope_table(exclude)]
        if _clean(self.eng.get("rules_of_engagement")).strip():
            out.append(self.p("Rules of engagement", "h3"))
            out += self.rich(self.eng.get("rules_of_engagement"))
        return out

    def methodology(self) -> list[Flowable]:
        out = self.section("4. Methodology and coverage", "s-methodology")
        coverage = _dicts(self.ctx.get("coverage"))
        if coverage:
            keys = ["total", "passed", "failed", "not_applicable", "blocked", "incomplete"]
            rows = [[self.p(c.get("methodology"), "td")]
                    + [self.p(c.get(k, 0), "td_right") for k in keys] for c in coverage]
            widths = self.cols(None, 44, 46, 62, 34, 48, 64)
            out.append(self.table(["Methodology", "Checks", "Passed", "Vulnerable", "N/A",
                                   "Blocked", "Not completed"], rows, widths,
                                  right=(1, 2, 3, 4, 5, 6)))
        else:
            out.append(self.p("No methodology checklist was tracked for this engagement.", "muted"))
        out.append(self.p("Severity ratings use the CVSS base score (v3.1 or v4.0) where a vector "
                          "is provided: Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, "
                          "Low 0.1-3.9, Informational 0.0."))
        return out

    def finding_details(self) -> list[Flowable]:
        out = self.section("5. Detailed findings", "s-findings")
        if not self.findings:
            out.append(self.p("No findings were reported.", "muted"))
        for i, f in enumerate(self.findings):
            out += self.finding(i, f)
        return out

    def finding(self, i: int, f: dict) -> list[Flowable]:
        key = f"f{i}"
        ref = _clean(f.get("ref"))
        title = _clean(f.get("title"))[:MAX_TITLE_CHARS]
        badge = self.badge(f.get("severity"), 7.5)
        heading = _Para(
            f'<a name="{key}"/><font face="{MONO}" color="{_hex(MUTED)}">{_esc(ref)}</font> '
            f"{_esc(title)}", self.st["finding"])
        head = Table([[badge, heading]], colWidths=[badge.width + 12, FRAME_W - badge.width - 12],
                     hAlign="LEFT", spaceBefore=6, spaceAfter=6)
        head.setStyle(_table_style([
            ("BACKGROUND", (0, 0), (-1, -1), SOFT),
            ("BOX", (0, 0), (-1, -1), 0.6, LINE),
            ("LINEBEFORE", (0, 0), (0, -1), 3, self.severity_colour(f.get("severity"))),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        markup = f"{_esc(ref)} {_esc(title)}".strip()
        head._oh_toc = (1, markup, f"{ref} {title}".strip(), key)
        self.toc_entries.append((1, markup, 0, key))

        sev = _clean(f.get("severity"))
        meta = [("Severity", _Para(
            f'<font color="{_hex(self.severity_colour(sev))}"><b>'
            f"{_esc(SEVERITY_LABELS.get(sev.lower(), sev) or '-')}</b></font>", self.st["meta"])),
            ("Status", self.p(_words(f.get("status")) or "-", "meta"))]
        vector = _clean(f.get("cvss_vector")).strip()
        if vector:
            meta.append((_cvss_label(f), _Para(
                f"<b>{_esc(_score(f.get('cvss_score')))}</b> "
                f'<font face="{MONO}" size="8.5">{_esc(vector)}</font>', self.st["meta"])))
        elif f.get("cvss_score") not in (None, ""):
            meta.append(("CVSS", _Para(f"<b>{_esc(_score(f.get('cvss_score')))}</b>",
                                           self.st["meta"])))
        if _clean(f.get("cwe")).strip():
            meta.append(("Weakness", self.p(f.get("cwe"), "meta")))
        targets = [_clean(t) for t in _strings(f.get("targets"))]
        meta.append(("Affected assets", self.p(", ".join(targets) if targets else "See description",
                                               "meta_mono")))
        meta_table = Table([[self.p(label, "meta_label"), value] for label, value in meta],
                           colWidths=[100, FRAME_W - 100], hAlign="LEFT", splitInRow=1,
                           spaceAfter=4)
        meta_table.setStyle(_table_style([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 1.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ]))
        out: list[Flowable] = [CondPageBreak(160), head, meta_table]

        for label, field in (("Description", "description"), ("Impact", "impact")):
            body = self.rich(f.get(field))
            if body:
                out += [self.p(label, "h4"), *body]
        if _clean(f.get("steps_to_reproduce")).strip():
            out += [self.p("Steps to reproduce", "h4"), *self.steps(f.get("steps_to_reproduce"))]
        out += self.evidence(f)
        body = self.rich(f.get("remediation"))
        if body:
            out += [self.p("Remediation", "h4"), *body]
        out += self.retests(f)
        refs = f.get("references")
        lines = refs.splitlines() if isinstance(refs, str) else _strings(refs)
        refs = [_clean(r).strip() for r in lines if _clean(r).strip()]
        if refs:
            out.append(self.p("References", "h4"))
            for r in refs:
                text = (f'<link href="{_attr(r)}" color="{_hex(self.accent)}">{_esc(r)}</link>'
                        if _URL.match(r) else _esc(r))
                out.append(_Para(text, self.st["ref"], bulletText="\u2022"))
        out.append(Spacer(1, 14))
        return out

    def evidence(self, f: dict) -> list[Flowable]:
        images = _dicts(f.get("images"))
        attachments = _dicts(f.get("attachments"))
        if not images and not attachments:
            return []
        out: list[Flowable] = [self.p("Evidence", "h4")]
        for img in images:
            caption = _esc(img.get("filename"))
            if _clean(img.get("description")).strip():
                caption += f" - {_esc(img.get('description'))}"
            caption += (f' (fingerprint <font face="{MONO}">{_esc(_clean(img.get("sha256"))[:16])}'
                        f"</font>)")
            data = _image_bytes(img)
            try:
                if not data:
                    raise ValueError("no image data")
                reader, w, h = _load_image(data)
            except Exception:  # undecodable evidence is reported, never fatal
                out.append(_Para(f"{caption} <i>(image could not be decoded; not embedded)</i>",
                                     self.st["caption"]))
                continue
            out.append(KeepTogether([_Picture(reader, w, h),
                                     _Para(caption, self.st["caption"])]))
        if attachments:
            rows = []
            for a in attachments:
                name = _esc(a.get("filename"))
                if _clean(a.get("problem")).strip():
                    name += f' <font color="{_hex(MUTED)}"><i>({_esc(a.get("problem"))})</i></font>'
                rows.append([_Para(name, self.st["td"]), self.p(a.get("description"), "td"),
                             self.p(a.get("sha256"), "td_hash")])
            out.append(self.table(["File", "Description", "SHA-256"], rows,
                                  self.cols(None, 96, HASH_COL_W)))
        return out

    def retests(self, f: dict) -> list[Flowable]:
        retests = _dicts(f.get("retests"))
        if not retests:
            return []
        rows = [[self.p(r.get("tested_on"), "td"),
                 _Para(self.retest_markup(r.get("result")), self.st["td"]),
                 self.p(r.get("tester"), "td"),
                 self.rich(r.get("notes"), compact=True) or ""] for r in retests]
        return [self.p("Retest history", "h4"),
                self.table(["Date", "Result", "Tester", "Notes"], rows,
                           self.cols(62, 98, 96, None))]

    def assets(self) -> list[Flowable]:
        out = self.section("Appendix A: assets in scope", "s-assets")
        targets = _dicts(self.ctx.get("targets"))
        if not targets:
            out.append(self.p("No in-scope assets recorded.", "muted"))
            return out
        rows = []
        for t in targets:
            value, hostname, ip = (_clean(t.get(k)) for k in ("value", "hostname", "ip"))
            names = [_esc(hostname)] if hostname else []
            if ip and ip != value:
                names.append(_esc(ip))
            services = "<br/>".join(_esc(s) for s in _strings(t.get("services")))
            rows.append([self.p(value, "td_mono"), _Para("<br/>".join(names), self.st["td_mono"]),
                         self.p(t.get("os"), "td"), _Para(services, self.st["td_mono"]),
                         self.p(_words(t.get("status")), "td")])
        out.append(self.table(["Asset", "Hostname / IP", "OS", "Services", "Status"], rows,
                              self.cols(118, 112, 56, None, 50)))
        return out

    def fingerprints(self) -> list[Flowable]:
        out = self.section("Appendix B: evidence fingerprints", "s-fingerprints")
        out.append(self.p("SHA-256 fingerprints of the evidence attached to the findings in this "
                          "report, recorded when each file was added. Recomputing a file's SHA-256 "
                          "confirms it is the one referenced here."))
        prints = _dicts(self.ctx.get("evidence_fingerprints"))
        if not prints:
            out.append(self.p("No evidence is attached to the reported findings.", "muted"))
            return out
        ref_w = self.mono_width((e.get("finding") for e in prints), 7.5, 42, 96)
        rows = [[self.p(e.get("finding"), "td_mono"), self.p(e.get("filename"), "td"),
                 self.p(_byte_count(e.get("size")), "td"), self.p(e.get("sha256"), "td_hash")]
                for e in prints]
        out.append(self.table(["Finding", "File", "Size", "SHA-256"], rows,
                              self.cols(ref_w, None, 54, HASH_COL_W)))
        return out

    def preparer(self) -> list[Flowable]:
        fields = [(label, _clean(self.prepared.get(k)).strip()) for label, k in
                  (("Name", "name"), ("Organization", "organization"), ("Email", "email"))]
        fields = [(label, v) for label, v in fields if v]
        if not fields:
            return []
        t = Table([[self.p(label, "meta_label"), self.p(v, "meta")] for label, v in fields],
                  colWidths=[100, FRAME_W - 100], hAlign="LEFT")
        t.setStyle(_table_style([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 1.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ]))
        return [Spacer(1, 16), self.p("Prepared by", "h3"), t]

    def closing(self) -> list[Flowable]:
        parts = [self.code, f"Generated by OffsecHub on {self.generated_at}", self.classification,
                 self.footer_text]
        text = " \u00b7 ".join(p for p in parts if p)
        return [Spacer(1, 24), _Para(_esc(text), self.st["small"])]

    # ---------------------------------------------------------------- build

    def story(self) -> list[Flowable]:
        self.page_total = _PageTotal()
        story: list[Flowable] = [self.page_total, NextPageTemplate("body"), *self.cover(),
                                 PageBreak()]
        story += self.contents()
        story += [PageBreak(), *self.summary(), *self.overview(), *self.scope(),
                  *self.methodology()]
        story += [PageBreak(), *self.finding_details()]
        story += [PageBreak(), *self.assets(), *self.fingerprints(), *self.preparer(),
                  *self.closing()]
        return story

    def render(self) -> bytes:
        story = self.story()
        # Pass 1 lays the contents out with the right entries (page numbers to
        # come), so pass 2 has the same pagination and multiBuild stops there.
        self.toc._entries = list(self.toc_entries)
        buf = BytesIO()
        name, kind = _clean(self.eng.get("name")), _clean(self.eng.get("type"))
        doc = _ReportDoc(
            buf, pagesize=A4, leftMargin=MARGIN_X, rightMargin=MARGIN_X, topMargin=MARGIN_TOP,
            bottomMargin=MARGIN_BOTTOM,
            title=" - ".join(p for p in (self.code, name, "Security Assessment Report") if p),
            author=_clean(self.prepared.get("name") or self.organization),
            subject=(f"{kind} for {self.client_name}" if kind and self.client_name
                     else kind or self.client_name),
            creator="OffsecHub", producer="OffsecHub", lang="en",
            initialFontName=SANS, initialFontSize=9.5, initialLeading=13.6,
        )
        frame = Frame(MARGIN_X, MARGIN_BOTTOM, FRAME_W, FRAME_H, id="body", leftPadding=0,
                      rightPadding=0, topPadding=0, bottomPadding=0)
        cover = Frame(MARGIN_X + 26, MARGIN_BOTTOM, FRAME_W - 26, FRAME_H, id="cover",
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        doc.addPageTemplates([
            PageTemplate("cover", [cover], onPage=self.draw_cover_page),
            PageTemplate("body", [frame], onPage=self.draw_body_page),
        ])
        self.page_total.doc = doc
        doc.multiBuild(story)
        return buf.getvalue()


def render_pdf(ctx: dict) -> bytes:
    """The engagement report as PDF bytes, from ``reporting.build_context``'s dict.

    Every key is optional: missing or malformed parts are left out, never fatal.
    """
    register_fonts()
    with _render_lock:  # ReportLab keeps some module-level state: one report at a time
        return _Renderer(ctx).render()
