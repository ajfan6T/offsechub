"""Scanner text to the Markdown subset that finding fields use (see ``richtext``).

Burp Suite writes issue text as HTML fragments, and that HTML quotes what a
target sent back (payloads, response snippets). So no markup is passed
through: tags are read only to recover structure, and everything else comes
out as text that ``richtext`` renders literally. Standard library only.

    <p> <div> <h1>-<h6> <table> ...   paragraphs (headings in bold)
    <br> <tr>                         line breaks
    <ul> / <ol> with <li>             "- " / "1. " items (nested lists are flattened)
    <b> <strong> / <i> <em>           **bold** / *italic*
    <code> <kbd> <samp> / <pre>       `code` / a fenced block
    <a href="http(s)://...">          [text](url); any other link keeps only its text
    <script> <style> <template>       dropped, content and all
    anything else                     dropped, its text kept

Literal Markdown characters in the text are escaped only where ``richtext``
would otherwise read them as markup: a backslash before a punctuation mark,
backticks, a ``*`` or ``_`` that could open emphasis, and list, heading or
fence markers at the start of a line. ``*.example.com`` and ``snake_case``
stay as they are.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import quote, urlsplit

__all__ = ["clean_text", "code_block", "html_links", "html_to_markdown", "inline_code",
           "safe_url", "text_to_markdown", "truncated_block"]

_ESCAPABLE = "\\`*_{}[]()#+-.!>~|"
_OPEN_BEFORE = "([{\"'"
# C0 controls other than tab and newline: XML-based report formats reject them.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BACKSLASH = re.compile(r"\\(?=[" + re.escape(_ESCAPABLE) + r"]|$)")
_EMPHASIS_RUN = re.compile(r"\*+|_+")
_BACKTICKS = re.compile(r"`+")
_SPACE = re.compile(r"\s+")
_URL_UNSAFE = re.compile(r'[\s"()<>]')
# Lines that richtext reads as block markup: group 1 is what precedes the
# character to escape. A fence counts only as a whole line, so a line that
# starts with a code span is left alone.
_FENCE_LINE = re.compile(r"^( {0,3})(?:`{3,}|~{3,})[ \t]*[\w+#.-]*[ \t]*$")
_HEADING_LINE = re.compile(r"^( {0,3})#{1,6}[ \t]")
_LIST_LINE = re.compile(r"^( {0,3})[-*+][ \t]|^( {0,3}\d{1,9})[.)][ \t]")

_SKIP = {"script", "style", "template"}
_BLOCKS = {"p", "div", "blockquote", "table", "section", "article", "header", "footer", "main",
           "nav", "aside", "address", "figure", "figcaption", "details", "summary", "form",
           "fieldset", "dl", "dt", "dd", "hr", "center"}
_HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_CODE = {"code", "kbd", "samp", "tt", "var"}


# ------------------------------------------------------------------ helpers


def clean_text(text: str) -> str:
    """Unix newlines and no control characters (U+FFFD marks where one was)."""
    return _CONTROL.sub("\ufffd", text.replace("\r\n", "\n").replace("\r", "\n"))


def _longest_backtick_run(text: str) -> int:
    return max((len(m) for m in _BACKTICKS.findall(text)), default=0)


def inline_code(text: str) -> str:
    """A code span that holds ``text`` literally, whatever backticks it contains."""
    text = " ".join(clean_text(text).split())
    if not text:
        return ""
    fence = "`" * (_longest_backtick_run(text) + 1)
    if text[0] == "`" or text[-1] == "`":
        text = f" {text} "  # richtext strips one space from each side
    return f"{fence}{text}{fence}"


def code_block(text: str, lang: str = "") -> str:
    """A fenced block whose fence is longer than any backtick run inside it."""
    text = clean_text(text).strip("\n")
    if not text.strip():
        return ""
    fence = "`" * max(3, _longest_backtick_run(text) + 1)
    return f"{fence}{lang}\n{text}\n{fence}"


def truncated_block(text: str, limit: int, *, lang: str = "", what: str = "Output") -> str:
    """``code_block`` of at most ``limit`` characters, with a note when cut."""
    text = clean_text(text).strip("\n")
    if len(text) <= limit:
        return code_block(text, lang)
    block = code_block(text[:limit], lang)
    return f"{block}\n\n{what} truncated to the first {limit} of {len(text)} characters."


def safe_url(href: str | None) -> str:
    """``href`` if it is an absolute http(s) URL, made safe for a richtext link; else ""."""
    # Browsers drop tabs and newlines inside URLs, so "java\nscript:" is javascript:.
    url = re.sub(r"[\t\n\r]", "", (href or "").strip())
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return ""
    # Percent-encode what would end a richtext link early.
    return _URL_UNSAFE.sub(lambda m: quote(m.group(), safe=""), _CONTROL.sub("", url))


def _escape(text: str, prev: str, more: bool) -> str:
    """Escape plain text so richtext shows it literally.

    ``prev`` is the character rendered before ``text``; ``more`` says whether
    anything follows it on the same line (then a trailing marker is escaped
    too, as it could open emphasis with what comes next).
    """
    text = _BACKSLASH.sub(r"\\\\", text).replace("`", "\\`")
    out: list[str] = []
    pos = 0
    for m in _EMPHASIS_RUN.finditer(text):
        before = text[m.start() - 1] if m.start() else prev
        after = text[m.end()] if m.end() < len(text) else ""
        could_open = before == "" or before.isspace() or before in _OPEN_BEFORE
        if len(m.group()) <= 2 and could_open and (after.isalnum() or (not after and more)):
            out.append(text[pos:m.start()] + "\\")
            pos = m.start()
    out.append(text[pos:])
    return "".join(out)


def _opens(prev: str, nxt: str) -> bool:
    return (prev == "" or prev.isspace() or prev in _OPEN_BEFORE) and nxt.isalnum()


def _closes(prev: str, nxt: str, after: str) -> bool:
    if prev == "" or prev.isspace() or prev in "*_":
        return False
    if nxt and nxt in ".-/:" and after.isalnum():
        return False
    return nxt == "" or (nxt not in "*_" and not nxt.isalnum())


def _escape_line_start(line: str, *, lists: bool) -> str:
    """Escape block markup at the start of a line (list markers only if ``lists``)."""
    m = _FENCE_LINE.match(line) or _HEADING_LINE.match(line) or (lists and _LIST_LINE.match(line))
    if not m:
        return line
    end = m.end(1) if m.group(1) is not None else m.end(2)
    return f"{line[:end]}\\{line[end:]}"


# ------------------------------------------------------------- plain text


def text_to_markdown(text: str | None) -> str:
    """Plain scanner text (e.g. Nessus) as Markdown, keeping its lines and "- " lists."""
    lines = [line.rstrip() for line in clean_text(text or "").split("\n")]
    out: list[str] = []
    for line in lines:
        if not line and (not out or not out[-1]):
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = _escape(line[indent:], "", False)
        out.append(_escape_line_start(line[:indent] + body, lists=False))
    return "\n".join(out).strip("\n")


# -------------------------------------------------------------------- HTML

_BR = ("br",)


class _Converter(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        # (list number or None, markdown): items of one list are not separated by blank lines.
        self.blocks: list[tuple[int | None, str]] = []
        self.tokens: list[tuple] = []
        self.item: str | None = None  # marker of the list item being written
        self.item_list = 0  # number of the list it belongs to
        self.lists: list[list] = []  # [tag, items so far, list number]
        self.list_count = 0
        self.bold = self.italic = self.code = self.skip = self.pre = 0
        self.pre_text: list[str] = []
        self.link: dict | None = None
        self.links: list[str] = []

    # -- structure

    def _break(self) -> None:
        if self.tokens and self.tokens[-1] is not _BR:
            self.tokens.append(_BR)

    def _boundary(self) -> None:
        """A block starts or ends: a new paragraph, or a new line inside a list item."""
        if self.item is not None:
            self._break()
        else:
            self._flush()

    def _flush(self) -> None:
        self._end_link()
        lines = _render(self.tokens)
        self.tokens = []
        item, self.item = self.item, None
        if item is None:
            text = "\n".join(_escape_line_start(line, lists=True) for line in lines)
            if text:
                self.blocks.append((None, text))
            return
        lines = [_escape_line_start(line, lists=True) for line in lines if line]
        if lines:
            self.blocks.append((self.item_list, item + "\n  ".join(lines)))

    def _start_item(self) -> None:
        self._flush()
        if self.lists:
            self.lists[-1][1] += 1
            tag, count, self.item_list = self.lists[-1]
            self.item = f"{count}. " if tag == "ol" else "- "
        else:
            self.item, self.item_list = "- ", 0

    def _end_link(self) -> None:
        if self.link is None:
            return
        link, self.link = self.link, None
        self.tokens.append(("link", " ".join("".join(link["text"]).split()), link["href"]))

    # -- parser callbacks

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP or self.skip:
            self.skip += tag in _SKIP
            return
        if self.pre:
            if tag == "br":
                self.pre_text.append("\n")
            self.pre += tag == "pre"
            return
        if tag == "br":
            self.tokens.append(_BR)
        elif tag == "tr":
            self._break()
        elif tag in ("td", "th"):
            self.tokens.append(("text", " ", False, False, False))
        elif tag in _BLOCKS:
            self._boundary()
        elif tag in _HEADINGS:
            self._boundary()
            self.bold += 1
        elif tag in ("ul", "ol"):
            self._flush()
            self.list_count += 1
            self.lists.append([tag, 0, self.list_count])
        elif tag == "li":
            self._start_item()
        elif tag in ("b", "strong"):
            self.bold += 1
        elif tag in ("i", "em"):
            self.italic += 1
        elif tag in _CODE:
            self.code += 1
        elif tag == "pre":
            self._flush()
            self.pre, self.pre_text = 1, []
        elif tag == "a" and self.link is None:
            # Other links are dropped: their text flows on as ordinary text.
            href = safe_url(dict(attrs).get("href"))
            if href:
                self.link = {"href": href, "text": []}
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if self.skip:
            self.skip -= tag in _SKIP
            return
        if self.pre:
            if tag == "pre":
                self.pre -= 1
                if not self.pre:
                    self._end_pre()
            return
        if tag in _BLOCKS:
            self._boundary()
        elif tag in _HEADINGS:
            self.bold = max(0, self.bold - 1)
            self._boundary()
        elif tag in ("ul", "ol", "li"):
            self._flush()
            if tag != "li" and self.lists:
                self.lists.pop()
        elif tag in ("b", "strong"):
            self.bold = max(0, self.bold - 1)
        elif tag in ("i", "em"):
            self.italic = max(0, self.italic - 1)
        elif tag in _CODE:
            self.code = max(0, self.code - 1)
        elif tag == "a":
            self._end_link()
        elif tag == "tr":
            self._break()

    def handle_data(self, data: str) -> None:
        if self.skip:
            return
        if self.pre:
            self.pre_text.append(data)
        elif self.link is not None:
            self.link["text"].append(data)
        else:
            self.tokens.append(("text", data, self.bold > 0, self.italic > 0, self.code > 0))

    def _end_pre(self) -> None:
        # HTML ignores a newline right after <pre>.
        text = "".join(self.pre_text).removeprefix("\n")
        self.pre_text = []
        block = code_block(text.rstrip())
        if block:
            self.blocks.append((None, block))

    def finish(self) -> str:
        self.close()
        if self.pre:
            self._end_pre()
        self._flush()
        out: list[str] = []
        prev: int | None = None
        for group, text in self.blocks:
            if out:
                out.append("\n" if group is not None and group == prev else "\n\n")
            out.append(text)
            prev = group
        return "".join(out)


def _pieces(tokens: list[tuple]) -> list[tuple[str, str, str]]:
    """One line's tokens as (style, text, url) with HTML whitespace rules applied."""
    raw: list[tuple[str, str, str]] = []
    for tok in tokens:
        if tok[0] == "link":
            raw.append(("link", tok[1], tok[2]))
            continue
        _, text, bold, italic, code = tok
        style = "code" if code else "bold" if bold else "italic" if italic else "plain"
        text = _SPACE.sub(" ", clean_text(text))
        if raw and raw[-1][0] == style:
            raw[-1] = (style, _SPACE.sub(" ", raw[-1][1] + text), "")
        elif text:
            raw.append((style, text, ""))

    out: list[tuple[str, str, str]] = []
    at_space = True

    def plain(text: str) -> None:
        nonlocal at_space
        if at_space:
            text = text.lstrip(" ")
        if not text:
            return
        if out and out[-1][0] == "plain":
            out[-1] = ("plain", out[-1][1] + text, "")
        else:
            out.append(("plain", text, ""))
        at_space = text.endswith(" ")

    for style, text, url in raw:
        if style == "plain":
            plain(text)
            continue
        core = text.strip(" ")
        if text.startswith(" "):
            plain(" ")
        if core or style == "link":
            out.append((style, core, url))
            at_space = False
        if text.endswith(" ") and core:
            plain(" ")
    while out and out[-1][0] == "plain" and out[-1][1].endswith(" "):
        text = out[-1][1].rstrip(" ")
        out[-1:] = [("plain", text, "")] if text else []
    return out


def _link(label: str, url: str) -> str:
    # richtext takes the label verbatim, up to the first "](" and without "[".
    label = (label or url).replace("[", "(").replace("]", ")")
    return f"[{label}]({url})"


def _preview(piece: tuple[str, str, str] | None) -> str:
    """How a piece renders when it gets no emphasis of its own."""
    if piece is None:
        return ""
    style, text, url = piece
    if style == "code":
        return inline_code(text)
    if style == "link":
        return _link(text, url)
    return _escape(text, "*", True)


def _render_line(pieces: list[tuple[str, str, str]]) -> str:
    out = ""
    for i, (style, text, url) in enumerate(pieces):
        more = i + 1 < len(pieces)
        if style == "code":
            out += inline_code(text)
        elif style == "link":
            out += _link(text, url)
        elif style == "plain":
            out += _escape(text, out[-1:], more)
        else:
            body = _escape(text, "*", more)
            follow = _preview(pieces[i + 1] if more else None)
            if len(follow) < 2 and i + 2 < len(pieces):
                follow += _preview(pieces[i + 2])
            if ("*" not in text and _opens(out[-1:], body[:1])
                    and _closes(body[-1:], follow[:1], follow[1:2])):
                marker = "**" if style == "bold" else "*"
                out += marker + body + marker
            else:
                out += _escape(text, out[-1:], more)
    return out


def _render(tokens: list[tuple]) -> list[str]:
    """Rendered lines of a block, without leading, trailing or repeated blank lines."""
    lines: list[list[tuple]] = [[]]
    for tok in tokens:
        if tok is _BR:
            lines.append([])
        else:
            lines[-1].append(tok)
    out: list[str] = []
    for line in lines:
        text = _render_line(_pieces(line))
        if text or (out and out[-1]):
            out.append(text)
    while out and not out[-1]:
        out.pop()
    return out


def html_to_markdown(html: str | None) -> str:
    """Convert a scanner's HTML fragment to the richtext Markdown subset."""
    if not html:
        return ""
    conv = _Converter()
    conv.feed(html)
    return conv.finish()


def html_links(html: str | None) -> list[str]:
    """The http(s) link targets in an HTML fragment, in order, without duplicates."""
    if not html:
        return []
    conv = _Converter()
    conv.feed(html)
    conv.finish()
    return list(dict.fromkeys(conv.links))
