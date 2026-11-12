"""The Markdown subset used in finding text (app/services/richtext.py)."""

import html
import re
import time

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from app.services.richtext import _FENCE, Span, is_plain, parse, parse_inline, to_html


def styles(text):
    return [(s.text, s.bold, s.italic, s.code, s.href) for s in parse_inline(text)]


def test_basic_inline_styles():
    assert styles("**bold** and *it* and _it2_ and __b2__ and `x = 1`") == [
        ("bold", True, False, False, None),
        (" and ", False, False, False, None),
        ("it", False, True, False, None),
        (" and ", False, False, False, None),
        ("it2", False, True, False, None),
        (" and ", False, False, False, None),
        ("b2", True, False, False, None),
        (" and ", False, False, False, None),
        ("x = 1", False, False, True, None),
    ]


def test_pentest_text_stays_literal():
    for text in [
        "*.acme-corp.example and *.acme.com",
        "file_names_with_underscores and __init__.py",
        "2*3*4 = 24",
        "a * b * c",
        "SELECT * FROM users WHERE name = '*'",
        "rm -rf /tmp/*_old",
        "**",
        "*",
        "_",
        "snake_case_*_mixed*",
        "_x_.txt and *y*.example",
    ]:
        spans = parse_inline(text)
        assert len(spans) == 1 and spans[0].text == text, (text, spans)
        assert not (spans[0].bold or spans[0].italic or spans[0].code)


def test_emphasis_after_brackets_and_before_punctuation():
    assert styles("(*see below*).") == [
        ("(", False, False, False, None),
        ("see below", False, True, False, None),
        (").", False, False, False, None),
    ]
    assert styles("**Critical!**") == [("Critical!", True, False, False, None)]


def test_double_markers_open_before_punctuation():
    assert styles("the **.git** folder and __.env__ file") == [
        ("the ", False, False, False, None),
        (".git", True, False, False, None),
        (" folder and ", False, False, False, None),
        (".env", True, False, False, None),
        (" file", False, False, False, None),
    ]
    for text in ["src/**/*.js", "**/*.py and **", "a ** b ** c"]:
        assert styles(text) == [(text, False, False, False, None)], text


def test_nested_emphasis():
    assert styles("**bold *both* bold**") == [
        ("bold ", True, False, False, None),
        ("both", True, True, False, None),
        (" bold", True, False, False, None),
    ]


def test_code_spans_protect_markers():
    assert styles("`*not italic*` *italic*") == [
        ("*not italic*", False, False, True, None),
        (" ", False, False, False, None),
        ("italic", False, True, False, None),
    ]
    assert styles("``a ` b``") == [("a ` b", False, False, True, None)]
    assert styles("unclosed ` tick") == [("unclosed ` tick", False, False, False, None)]


def test_escapes():
    assert styles(r"\*not italic\* and \_x\_") == [("*not italic* and _x_", False, False, False, None)]
    assert styles(r"C:\Users\admin") == [(r"C:\Users\admin", False, False, False, None)]


def test_links_only_safe_schemes():
    assert styles("[OWASP](https://owasp.org/x)") == [("OWASP", False, False, False, "https://owasp.org/x")]
    assert styles("[mail](mailto:a@b.example)")[0][4] == "mailto:a@b.example"
    for bad in ["[x](javascript:alert(1))", "[x](data:text/html,hi)", "[x](//evil)", "[x](file:///etc/passwd)"]:
        assert all(s[4] is None for s in styles(bad)), bad


def test_line_breaks_are_kept():
    spans = parse_inline("line one\nline two")
    assert [s.text for s in spans] == ["line one", "\n", "line two"]
    assert spans[1].is_break


def test_blocks():
    text = (
        "# Summary\n"
        "First line\nsecond line\n\n"
        "- one\n- **two**\n  continued\n\n"
        "3. three\n4. four\n\n"
        "```http\nGET /.git/config HTTP/1.1\nHost: x\n```\n"
        "after"
    )
    blocks = parse(text)
    assert [b.kind for b in blocks] == ["heading", "paragraph", "bullets", "numbers", "code", "paragraph"]
    assert blocks[0].level == 1 and blocks[0].spans[0].text == "Summary"
    assert [s.text for s in blocks[2].items[1]] == ["two", "\n", "continued"]
    assert blocks[3].start == 3 and len(blocks[3].items) == 2
    assert blocks[4].text == "GET /.git/config HTTP/1.1\nHost: x"


def test_list_survives_blank_lines_between_items():
    blocks = parse("1. a\n\n2. b\n\n3. c")
    assert [b.kind for b in blocks] == ["numbers"]
    assert len(blocks[0].items) == 3


def test_unclosed_fence_runs_to_the_end():
    blocks = parse("```\nraw <b>\nstill code")
    assert blocks == [blocks[0]] and blocks[0].kind == "code"
    assert blocks[0].text == "raw <b>\nstill code"


def test_fence_language_is_not_shown():
    # As in Markdown, the word after an opening fence names the language; it is not content.
    blocks = parse("```python\nprint(1)\n```")
    assert [(b.kind, b.text) for b in blocks] == [("code", "print(1)")]
    assert "python" not in to_html("```python\nprint(1)\n```")


def test_wildcard_bullet_is_not_a_list():
    blocks = parse("*.acme.example is in scope")
    assert [b.kind for b in blocks] == ["paragraph"]


def test_is_plain():
    assert is_plain(parse("Just text\nwith a break"))
    assert not is_plain(parse("**bold**"))
    assert not is_plain(parse("- item"))


def test_html_escapes_everything():
    out = to_html('<script>alert(1)</script> **bold <b>x</b>** [a"b](https://x.example/?q=1&r=2)')
    assert "<script>" not in out and "<b>x</b>" not in out
    assert "&lt;script&gt;" in out and "<strong>bold &lt;b&gt;x&lt;/b&gt;</strong>" in out
    assert '<a href="https://x.example/?q=1&amp;r=2" rel="noopener noreferrer">a&quot;b</a>' in out
    # A URL with markup in it is not a link at all.
    assert "href" not in to_html("[x](https://x.example/?q=<y>)")


def test_html_structure():
    out = to_html("Intro\n\n- a\n- b\n\n2. x\n\n```\n<raw>\n```", heading_base=4)
    assert out == (
        "<p>Intro</p>\n<ul><li>a</li><li>b</li></ul>\n"
        '<ol start="2"><li>x</li></ol>\n<pre><code>&lt;raw&gt;</code></pre>'
    )
    assert to_html("### deep", heading_base=5) == "<h6>deep</h6>"


TAG = re.compile(r"<[^>]*>")


@settings(max_examples=400, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("ab *_`[]()\\#-+1.\n<>&\"'h:/s")), max_size=80))
def test_html_never_emits_unescaped_markup(text):
    out = to_html(text)
    allowed = {"p", "/p", "br", "strong", "/strong", "em", "/em", "code", "/code", "pre", "/pre",
               "ul", "/ul", "ol", "/ol", "li", "/li", "a", "/a"} | {f"h{i}" for i in range(1, 7)} | {
               f"/h{i}" for i in range(1, 7)}
    for tag in TAG.findall(out):
        name = tag[1:-1].split()[0] if tag[1:-1].strip() else ""
        assert name in allowed, (text, tag)
        if name == "a":
            assert re.fullmatch(r'<a href="(?:https?://|mailto:)[^"<>]*" rel="noopener noreferrer">', tag), tag


@settings(max_examples=400, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("ab *_`\n<&x")), max_size=60))
def test_no_text_is_lost_outside_markers(text):
    # Every letter that isn't a formatting marker survives into the HTML. (A fence's
    # language word is the one exception, tested above.)
    assume(not any((m := _FENCE.match(line)) and m.group(2) for line in text.split("\n")))
    visible = html.unescape(TAG.sub("", to_html(text)))
    for ch in "abx<&":
        assert visible.count(ch) == text.count(ch), (text, visible)


def test_span_defaults():
    assert Span("x").href is None and not Span("x").is_break


# Parse time. Finding text can quote whatever a target sent back (nuclei extracted-results
# lands in finding fields unescaped), so no input may make parsing slower than linear and
# stall a report. Each input below once took from 25 seconds to hours; now well under two.


def parses_quickly(text, limit=5.0):
    # Generous for slow CI machines: every input takes well under 2 s now, and the old
    # quadratic code took 25 s to hours on them.
    start = time.perf_counter()
    blocks = parse(text)
    elapsed = time.perf_counter() - start
    assert elapsed < limit, f"{elapsed:.1f} s to parse {len(text):,} characters"
    return blocks


def test_openers_without_closers_parse_in_linear_time():
    # Each opener used to scan the rest of the text for a closer.
    for text in ["*a " * 70_000, "**a __b *c _d " * 15_000]:
        assert is_plain(parses_quickly(text))


def test_unmatched_backtick_runs_parse_in_linear_time():
    # Each run (and each position in it, for a closer scan) used to search the rest of the
    # text for a run of its length.
    assert is_plain(parses_quickly("*a " + "".join("`" * k + " x " for k in range(1, 600))))


def test_link_search_is_linear():
    # Each "[" used to search for "](" and then read the label and the URL.
    assert is_plain(parses_quickly("[" * 100_000 + "](http://" + "a" * 100_000))
    [block] = parses_quickly("[a" * 50_000 + "](http://" + "a" * 100_000 + ")")
    assert block.spans[-1] == Span("a", href="http://" + "a" * 100_000)


def test_deeply_nested_emphasis_parses_in_linear_time():
    # Nesting is not limited to the four kinds of marker: each closer scan here steps into a
    # backtick run and skips the inner closers as code, so this nests 500 deep.
    text = "x"
    for k in range(500, 0, -1):
        text = f"*a {'`' * (2 * k + 1)} {text} {'`' * (2 * k)} b*"
    [block] = parses_quickly(text)
    assert all(s.italic and not s.code for s in block.spans)


def test_long_heading_and_fence_lines_parse_in_linear_time():
    # The heading pattern backtracked in cubic time over a run of spaces, the fence one in quadratic.
    assert [b.kind for b in parses_quickly("# a" + " " * 200_000 + "b")] == ["heading"]
    assert [b.kind for b in parses_quickly("```" + " " * 200_000 + "!")] == ["paragraph"]


def test_many_list_paragraphs_parse_in_linear_time():
    # Each indented paragraph used to copy the whole item so far.
    [block] = parses_quickly("- a" + "\n\n  b" * 40_000)
    assert block.kind == "bullets" and len(block.items[0]) == 1 + 3 * 40_000


def test_many_spans_of_one_style_join_in_linear_time():
    # Joining neighbouring spans of one style used to copy the joined text again for each span.
    [block] = parses_quickly("*a " + "(_b_)" * 200_000 + " c*")
    assert block.spans == [Span("a " + "(b)" * 200_000 + " c", italic=True)]
