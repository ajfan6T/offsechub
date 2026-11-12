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
text, and a single marker only before a letter or digit (a double one before
any non-space, so ``**.git**`` is bold); it closes only after a non-space and
before whitespace, punctuation or the end, but not inside a file name, host or
path. ``*.example.com``, ``file_names``, ``__init__.py``, ``2*3*4`` and ``a * b``
are therefore plain text. The frontend preview
(``frontend/src/lib/richtext.ts``) implements the same rules.

Parsing takes time linear in the text (up to a log factor), whatever the text:
it often comes from a scan target, so it must not be able to stall a report.
"""

from __future__ import annotations

import html
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field

__all__ = ["Block", "Span", "parse", "parse_inline", "to_html", "is_plain"]

_ESCAPABLE = set("\\`*_{}[]()#+-.!>~|")
_OPEN_BEFORE = set("([{\"'")
_LINK_URL = re.compile(r"(?:https?://|mailto:)[^\s()<>\"]+", re.IGNORECASE)
_RUN = {ch: re.compile(re.escape(ch) + "+") for ch in "`*_"}
# Group 2, the language, is None when there is none. (Written so that a run of spaces
# before something else cannot make the pattern backtrack quadratically.)
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*(?:([\w+#.-]+)[ \t]*)?$")
_HEADING = re.compile(r" {0,3}(#{1,6})[ \t]+")  # the rest is read by _heading
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


# Emphasis content is parsed in place, as the window text[lo:hi] of the text being parsed,
# so the positions found once in _Text serve every level of nesting. Everything below reads
# a window exactly as the old code read the slice text[lo:hi]: nothing outside it is seen.


class _Text:
    """A text being parsed inline, with the positions that the scans look up by bisection."""

    def __init__(self, text: str) -> None:
        self.text = text
        runs = [m.span() for m in _RUN["`"].finditer(text)]
        self.tick_starts = [a for a, _ in runs]  # maximal runs of backticks
        self.tick_ends = [b for _, b in runs]
        self.ticks_by_length: dict[int, list[int]] = {}
        for a, b in runs:
            self.ticks_by_length.setdefault(b - a, []).append(a)
        self.link_middles = [m.start() for m in re.finditer(r"\]\(", text)]
        self.label_stops = [m.start() for m in re.finditer(r"[\[\n]", text)]


def _first(positions: list[int], i: int) -> int:
    """The first of the sorted ``positions`` at or after ``i``, or a number past them all."""
    k = bisect_left(positions, i)
    return positions[k] if k < len(positions) else 1 << 62


def _run_end(text: str, i: int, hi: int) -> int:
    """End of the run of ``text[i]`` characters starting at ``i`` (at most ``hi``)."""
    return _RUN[text[i]].match(text, i, hi).end()


def _can_open(text: str, lo: int, hi: int, i: int, size: int) -> bool:
    prev = text[i - 1] if i > lo else ""
    nxt = text[i + size] if i + size < hi else ""
    if not (prev == "" or prev.isspace() or prev in _OPEN_BEFORE):
        return False
    # A single marker needs a letter or digit next (so *.example.com stays literal);
    # a double one only a non-space (so **.git** is bold).
    return nxt.isalnum() if size == 1 else (nxt != "" and not nxt.isspace() and nxt not in "*_")


def _can_close(text: str, lo: int, hi: int, i: int, size: int) -> bool:
    prev = text[i - 1] if i > lo else ""
    nxt = text[i + size] if i + size < hi else ""
    if prev == "" or prev.isspace() or prev in "*_":
        return False
    after = text[i + size + 1] if i + size + 1 < hi else ""
    if nxt in ".-/:" and nxt and after.isalnum():
        return False  # inside a file name, host or path: __init__.py, _x_.txt
    return nxt == "" or (nxt not in "*_" and not nxt.isalnum())


def _code_span(t: _Text, i: int, hi: int) -> tuple[int, int] | None:
    """If a code span starts at ``i``, return (start of its closing run, index after it).

    It opens with the backticks from ``i`` on (``i`` may be inside a run, after an escaped
    backtick) and closes at the next run of exactly as many. A window never splits a run of
    backticks (an emphasis marker is on either side of it), so the text's runs are its runs.
    """
    run = t.tick_ends[bisect_right(t.tick_starts, i) - 1] - i
    starts = t.ticks_by_length.get(run, [])
    k = bisect_left(starts, i + run)
    if k == len(starts) or starts[k] >= hi:
        return None
    return starts[k], starts[k] + run


def _code_content(text: str, start: int, end: int) -> str:
    content = text[start:end].replace("\n", " ")
    if len(content) > 2 and content[0] == " " and content[-1] == " " and content.strip():
        content = content[1:-1]
    return content


def _link_end(t: _Text, i: int, hi: int) -> tuple[int, str, str] | None:
    """If ``[text](url)`` starts at ``i``, return (index after it, text, url)."""
    text = t.text
    close = _first(t.link_middles, i + 1)  # the first "](" after the "["
    if close + 2 > hi or close == i + 1 or _first(t.label_stops, i + 1) < close:
        return None  # no "](", an empty label, or a "[" or line break in it
    m = _LINK_URL.match(text, close + 2, hi)
    if not m or m.end() >= hi or text[m.end()] != ")":
        return None
    return m.end() + 1, text[i + 1:close], m.group(0)


def _find_closer(t: _Text, lo: int, hi: int, start: int, delim: str, memo: dict[int, int]) -> int:
    """Index of the closing ``delim`` for an opener ending at ``start``, or -1.

    Where the scan goes next depends only on where it is, so ``memo`` (one per window and
    delimiter) records the answer for every position a scan passes through, and a later scan
    stops as soon as it reaches one of them. Together the scans visit each position once.
    """
    text, size = t.text, len(delim)
    i, passed, found = start, [], -1
    while i < hi:
        if i in memo:
            found = memo[i]
            break
        passed.append(i)
        ch = text[i]
        if ch == "\\" and i + 1 < hi and text[i + 1] in _ESCAPABLE:
            i += 2
            continue
        if ch == "`":
            span = _code_span(t, i, hi)
            if span:
                i = span[1]
                continue
        if text.startswith(delim, i, hi):
            run_end = _run_end(text, i, hi)
            if run_end - i == size and _can_close(text, lo, hi, i, size):
                found = i
                break
            i = run_end
            continue
        i += 1
    for p in passed:
        memo[p] = found
    return found


def parse_inline(text: str, *, bold: bool = False, italic: bool = False) -> list[Span]:
    return _parse_window(_Text(text), 0, len(text), bold, italic)


def _parse_window(t: _Text, lo: int, hi: int, bold: bool, italic: bool) -> list[Span]:
    text = t.text
    spans: list[Span] = []
    buf: list[str] = []
    memos: dict[str, dict[int, int]] = {}  # for _find_closer, per delimiter

    def flush() -> None:
        if buf:
            spans.append(Span("".join(buf), bold=bold, italic=italic))
            buf.clear()

    i = lo
    while i < hi:
        ch = text[i]
        if ch == "\\" and i + 1 < hi and text[i + 1] in _ESCAPABLE:
            buf.append(text[i + 1])
            i += 2
            continue
        if ch == "\n":
            flush()
            spans.append(Span("\n", bold=bold, italic=italic))
            i += 1
            continue
        if ch == "`":
            run = _run_end(text, i, hi) - i
            span = _code_span(t, i, hi)
            if span:
                flush()
                spans.append(Span(_code_content(text, i + run, span[0]), bold=bold, italic=italic,
                                  code=True))
                i = span[1]
                continue
            buf.append("`" * run)
            i += run
            continue
        if ch == "[":
            link = _link_end(t, i, hi)
            if link:
                flush()
                end, label, url = link
                spans.append(Span(label, bold=bold, italic=italic, href=url))
                i = end
                continue
        if ch in "*_":
            run = _run_end(text, i, hi) - i
            if run in (1, 2) and _can_open(text, lo, hi, i, run):
                delim = ch * run
                close = _find_closer(t, lo, hi, i + run, delim, memos.setdefault(delim, {}))
                if close > i + run:
                    flush()
                    if run == 2:
                        spans.extend(_parse_window(t, i + run, close, True, italic))
                    else:
                        spans.extend(_parse_window(t, i + run, close, bold, True))
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
    """Join neighbouring spans of one style (but not links or breaks); drop empty ones."""
    groups: list[list[Span]] = []
    for s in spans:
        last = groups[-1][0] if groups else None
        if (last is not None and not s.is_break and not last.is_break and s.href is None
                and last.href is None and (s.bold, s.italic, s.code)
                == (last.bold, last.italic, last.code)):
            groups[-1].append(s)
        elif s.text:
            groups.append([s])
    # Joined once per group: adding the texts up one at a time would be quadratic.
    return [g[0] if len(g) == 1 else Span("".join(s.text for s in g), g[0].bold, g[0].italic,
                                          g[0].code) for g in groups]


# ------------------------------------------------------------------ blocks


def _heading(line: str) -> tuple[int, str] | None:
    """(level, title) if ``line`` is a heading with a title.

    Reads the line as ``^ {0,3}(#{1,6})[ \\t]+(.*?)[ \\t]*#*[ \\t]*$`` would, without that
    pattern's backtracking, which takes cubic time on a long run of spaces.
    """
    m = _HEADING.match(line)
    if not m:
        return None
    title = line[m.end():].rstrip(" \t").rstrip("#").rstrip(" \t")
    return (len(m.group(1)), title) if title else None


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
        heading = _heading(line)
        bullet = _BULLET.match(line)
        number = _NUMBER.match(line)
        if heading:
            end_para()
            end_list()
            blocks.append(Block("heading", spans=parse_inline(heading[1]), level=heading[0]))
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
            # (Extended in place: copying the item for each paragraph would be quadratic.)
            lst.items[-1] += [Span("\n"), Span("\n"),
                              *parse_inline(_CONTINUATION.match(line).group(1))]
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
