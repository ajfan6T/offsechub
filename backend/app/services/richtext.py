"""A small, safe Markdown subset for finding and engagement text.

Finding text is written by the tester but routinely quotes what a target sent
back: payloads, banners, HTML, wildcards. So nothing here passes markup
through. The parser produces a format-neutral structure (``Block`` and
``Span``), and each renderer (HTML here, DOCX in ``report_docx``, PDF in
``report_pdf``) escapes text for its own format.

Supported, deliberately less than CommonMark:

blocks
    paragraphs, separated by blank lines; single newlines stay line breaks
    ``- `` / ``* `` / ``+ `` bullet items and ``1. `` / ``1) `` numbered items;
    lines indented under an item continue it
    fenced code blocks (````` or ``~~~``; a language name after the fence is ignored)
    ``#`` to ``######`` headings
inline
    ``**bold**`` / ``__bold__``, ``*italic*`` / ``_italic_``, ```code```,
    ``[text](https://...)`` links (http, https and mailto only), ``\\`` escapes

Emphasis is stricter than CommonMark so pentest text stays literal: a marker
opens only after whitespace, an opening bracket or quote, or the start of the
text, and only before a letter or digit; it closes only after a non-space and
before whitespace, punctuation or the end, but not inside a file name, host or
path. ``*.example.com``, ``file_names``, ``__init__.py``, ``2*3*4`` and ``a * b``
are therefore plain text. The frontend preview
(``frontend/src/lib/richtext.ts``) implements the same rules.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

__all__ = ["Block", "Span", "parse", "parse_inline", "to_html", "is_plain"]

_ESCAPABLE = set("\\`*_{}[]()#+-.!>~|")
_OPEN_BEFORE = set("([{\"'")
_LINK_URL = re.compile(r"(?:https?://|mailto:)[^\s()<>\"]+", re.IGNORECASE)
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*([\w+#.-]*)[ \t]*$")
_HEADING = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$")
_BULLET = re.compile(r"^ {0,3}[-*+][ \t]+(.*)$")
_NUMBER = re.compile(r"^ {0,3}(\d{1,9})[.)][ \t]+(.*)$")
_CONTINUATION = re.compile(r"^(?: {2,}|\t)(\S.*)$")


@dataclass(frozen=True)
class Span:
    """A run of text with one style. ``text == "\\n"`` is a line break."""

    text: str
    bold: bool = False
    italic: bool = False
    code: bool = False
    href: str | None = None

    @property
    def is_break(self) -> bool:
        return self.text == "\n" and not self.code


@dataclass
class Block:
    kind: str  # paragraph | heading | bullets | numbers | code
    spans: list[Span] = field(default_factory=list)  # paragraph, heading
    items: list[list[Span]] = field(default_factory=list)  # bullets, numbers
    text: str = ""  # code
    level: int = 0  # heading: 1-6
    start: int = 1  # numbers


# ------------------------------------------------------------------ inline


def _is_space(ch: str) -> bool:
    return ch == "" or ch.isspace()


def _can_open(text: str, i: int, size: int) -> bool:
    prev = text[i - 1] if i > 0 else ""
    nxt = text[i + size] if i + size < len(text) else ""
    return (prev == "" or prev.isspace() or prev in _OPEN_BEFORE) and nxt.isalnum()


def _can_close(text: str, i: int, size: int) -> bool:
    prev = text[i - 1] if i > 0 else ""
    nxt = text[i + size] if i + size < len(text) else ""
    if prev == "" or prev.isspace() or prev in "*_":
        return False
    if nxt in ".-/:" and nxt and text[i + size + 1:i + size + 2].isalnum():
        return False  # inside a file name, host or path: __init__.py, _x_.txt
    return nxt == "" or (nxt not in "*_" and not nxt.isalnum())


def _code_span_end(text: str, i: int) -> tuple[int, str] | None:
    """If a code span starts at ``i``, return (index after it, its content)."""
    run = len(text[i:]) - len(text[i:].lstrip("`"))
    j = i + run
    while True:
        k = text.find("`" * run, j)
        if k < 0:
            return None
        after = k + run
        if after < len(text) and text[after] == "`":  # longer run: not our closer
            j = after + len(text[after:]) - len(text[after:].lstrip("`"))
            continue
        content = text[i + run:k].replace("\n", " ")
        if len(content) > 2 and content[0] == " " and content[-1] == " " and content.strip():
            content = content[1:-1]
        return after, content


def _link_end(text: str, i: int) -> tuple[int, str, str] | None:
    """If ``[text](url)`` starts at ``i``, return (index after it, text, url)."""
    close = text.find("](", i + 1)
    if close < 0 or "\n" in text[i + 1:close] or close == i + 1:
        return None
    m = _LINK_URL.match(text, close + 2)
    if not m or m.end() >= len(text) or text[m.end()] != ")":
        return None
    label = text[i + 1:close]
    if "[" in label:
        return None
    return m.end() + 1, label, m.group(0)


def _find_closer(text: str, start: int, delim: str) -> int:
    """Index of the closing ``delim`` for an opener ending at ``start``, or -1."""
    i, size = start, len(delim)
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in _ESCAPABLE:
            i += 2
            continue
        if ch == "`":
            span = _code_span_end(text, i)
            if span:
                i = span[0]
                continue
        if text.startswith(delim, i):
            run_end = i
            while run_end < len(text) and text[run_end] == delim[0]:
                run_end += 1
            if run_end - i == size and _can_close(text, i, size):
                return i
            i = run_end
            continue
        i += 1
    return -1


def parse_inline(text: str, *, bold: bool = False, italic: bool = False) -> list[Span]:
    spans: list[Span] = []
    buf: list[str] = []

    def flush() -> None:
        if buf:
            spans.append(Span("".join(buf), bold=bold, italic=italic))
            buf.clear()

    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in _ESCAPABLE:
            buf.append(text[i + 1])
            i += 2
            continue
        if ch == "\n":
            flush()
            spans.append(Span("\n", bold=bold, italic=italic))
            i += 1
            continue
        if ch == "`":
            span = _code_span_end(text, i)
            if span:
                flush()
                spans.append(Span(span[1], bold=bold, italic=italic, code=True))
                i = span[0]
                continue
            run = len(text[i:]) - len(text[i:].lstrip("`"))
            buf.append("`" * run)
            i += run
            continue
        if ch == "[":
            link = _link_end(text, i)
            if link:
                flush()
                end, label, url = link
                spans.append(Span(label, bold=bold, italic=italic, href=url))
                i = end
                continue
        if ch in "*_":
            run = len(text[i:]) - len(text[i:].lstrip(ch))
            if run in (1, 2) and _can_open(text, i, run):
                delim = ch * run
                close = _find_closer(text, i + run, delim)
                if close > i + run:
                    flush()
                    inner = text[i + run:close]
                    if run == 2:
                        spans.extend(parse_inline(inner, bold=True, italic=italic))
                    else:
                        spans.extend(parse_inline(inner, bold=bold, italic=True))
                    i = close + run
                    continue
            buf.append(ch * run)
            i += run
            continue
        buf.append(ch)
        i += 1
    flush()
    return _merge(spans)


def _merge(spans: list[Span]) -> list[Span]:
    out: list[Span] = []
    for s in spans:
        if (out and not s.is_break and not out[-1].is_break and s.href is None
                and out[-1].href is None and (s.bold, s.italic, s.code)
                == (out[-1].bold, out[-1].italic, out[-1].code)):
            out[-1] = Span(out[-1].text + s.text, s.bold, s.italic, s.code)
        elif s.text:
            out.append(s)
    return out


# ------------------------------------------------------------------ blocks


def parse(text: str | None) -> list[Block]:
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    blocks: list[Block] = []
    para: list[str] = []
    lst: Block | None = None
    item: list[str] | None = None

    def end_para() -> None:
        if para:
            blocks.append(Block("paragraph", spans=parse_inline("\n".join(para))))
            para.clear()

    def end_item() -> None:
        nonlocal item
        if lst is not None and item is not None:
            lst.items.append(parse_inline("\n".join(item)))
        item = None

    def end_list() -> None:
        nonlocal lst
        end_item()
        if lst is not None and lst.items:
            blocks.append(lst)
        lst = None

    i, blank_run = 0, False
    while i < len(lines):
        line = lines[i]
        fence = _FENCE.match(line)
        if fence:
            end_para()
            end_list()
            marker = fence.group(1)
            body: list[str] = []
            i += 1
            while i < len(lines):
                closing = lines[i].strip()
                if closing and set(closing) == {marker[0]} and len(closing) >= len(marker):
                    i += 1
                    break
                body.append(lines[i])
                i += 1
            blocks.append(Block("code", text="\n".join(body)))
            blank_run = False
            continue
        if not line.strip():
            end_para()
            end_item()
            blank_run = True
            i += 1
            continue
        heading = _HEADING.match(line)
        bullet = _BULLET.match(line)
        number = _NUMBER.match(line)
        if heading and heading.group(2):
            end_para()
            end_list()
            blocks.append(Block("heading", spans=parse_inline(heading.group(2)),
                                level=len(heading.group(1))))
        elif bullet or number:
            end_para()
            kind = "bullets" if bullet else "numbers"
            if lst is None or lst.kind != kind:
                end_list()
                lst = Block(kind, start=int(number.group(1)) if number else 1)
            else:
                end_item()
            item = [(bullet or number).group(1 if bullet else 2)]
        elif lst is not None and item is not None and _CONTINUATION.match(line):
            item.append(_CONTINUATION.match(line).group(1))
        elif lst is not None and item is None and blank_run and _CONTINUATION.match(line):
            # An indented paragraph after a blank line still belongs to the last item.
            lst.items[-1] = lst.items[-1] + [Span("\n"), Span("\n")] + parse_inline(
                _CONTINUATION.match(line).group(1))
        else:
            end_list()
            para.append(line)
        blank_run = False
        i += 1
    end_para()
    end_list()
    return blocks


def is_plain(blocks: list[Block]) -> bool:
    """True when the text used no formatting at all (one or more plain paragraphs)."""
    return all(
        b.kind == "paragraph" and all(not (s.bold or s.italic or s.code or s.href) for s in b.spans)
        for b in blocks
    )


# ------------------------------------------------------------------ HTML


def _spans_html(spans: list[Span]) -> str:
    out = []
    for s in spans:
        if s.is_break:
            out.append("<br>")
            continue
        piece = html.escape(s.text, quote=True)
        if s.code:
            piece = f"<code>{piece}</code>"
        if s.italic:
            piece = f"<em>{piece}</em>"
        if s.bold:
            piece = f"<strong>{piece}</strong>"
        if s.href:
            piece = (f'<a href="{html.escape(s.href, quote=True)}" '
                     f'rel="noopener noreferrer">{piece}</a>')
        out.append(piece)
    return "".join(out)


def to_html(text: str | None, *, heading_base: int = 4) -> str:
    """Escaped HTML for ``text``. Headings start at ``<h{heading_base}>`` (capped at h6)."""
    parts = []
    for b in parse(text):
        if b.kind == "paragraph":
            parts.append(f"<p>{_spans_html(b.spans)}</p>")
        elif b.kind == "heading":
            level = min(6, heading_base + b.level - 1)
            parts.append(f"<h{level}>{_spans_html(b.spans)}</h{level}>")
        elif b.kind == "code":
            parts.append(f"<pre><code>{html.escape(b.text, quote=True)}</code></pre>")
        else:
            tag = "ul" if b.kind == "bullets" else "ol"
            start = f' start="{b.start}"' if b.kind == "numbers" and b.start != 1 else ""
            items = "".join(f"<li>{_spans_html(it)}</li>" for it in b.items)
            parts.append(f"<{tag}{start}>{items}</{tag}>")
    return "\n".join(parts)
