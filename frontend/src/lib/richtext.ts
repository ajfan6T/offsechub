// The Markdown subset used in finding text. A port of backend/app/services/richtext.py:
// same blocks, same inline rules, so the preview matches every report format. Keep the
// two in step. The output is a structure rendered as React elements, never HTML strings.

export interface Span {
  text: string; // "\n" is a line break
  bold?: boolean;
  italic?: boolean;
  code?: boolean;
  href?: string;
}

export type Block =
  | { kind: "paragraph" | "heading"; spans: Span[]; level?: number }
  | { kind: "bullets" | "numbers"; items: Span[][]; start: number }
  | { kind: "code"; text: string };

// Parsing takes time linear in the text (up to a log factor), whatever the text: it often
// comes from a scan target, so a hostile one must not be able to hang the page.

const ESCAPABLE = new Set("\\`*_{}[]()#+-.!>~|");
const OPEN_BEFORE = new Set("([{\"'");
const LINK_URL = /(?:https?:\/\/|mailto:)[^\s()<>"]+/iy; // sticky: set lastIndex first
// Group 2, the language, is undefined when there is none. (Written so that a run of spaces
// before something else cannot make the pattern backtrack quadratically.)
const FENCE = /^ {0,3}(`{3,}|~{3,})[ \t]*(?:([\w+#.-]+)[ \t]*)?$/;
const HEADING = /^ {0,3}(#{1,6})[ \t]+/; // the rest is read by readHeading
// "." stops at U+2028/U+2029; (?![ \t]) makes the pattern then fail at once instead of
// retrying every split of the spaces before it.
const BULLET = /^ {0,3}[-*+][ \t]+(?![ \t])(.*)$/;
const NUMBER = /^ {0,3}(\d{1,9})[.)][ \t]+(?![ \t])(.*)$/;
const CONTINUATION = /^(?: {2,}|\t)(\S.*)$/;

const isSpace = (ch: string) => ch === "" || /\s/.test(ch);
const isAlnum = (ch: string) => ch !== "" && /[\p{L}\p{N}]/u.test(ch);

// Emphasis content is parsed in place, as the window [lo, hi) of the text being parsed, so the
// positions found once by scanText serve every level of nesting. Everything below reads a window
// exactly as the old code read the slice text.slice(lo, hi): nothing outside it is seen.

interface ScannedText {
  text: string;
  tickStarts: number[]; // maximal runs of backticks
  tickEnds: number[];
  ticksByLength: Map<number, number[]>;
  linkMiddles: number[]; // each "]("
  labelStops: number[]; // each "[" or line break
}

function scanText(text: string): ScannedText {
  const t: ScannedText = {
    text,
    tickStarts: [],
    tickEnds: [],
    ticksByLength: new Map(),
    linkMiddles: [],
    labelStops: [],
  };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "`") {
      const end = runEnd(text, i, text.length);
      t.tickStarts.push(i);
      t.tickEnds.push(end);
      const starts = t.ticksByLength.get(end - i);
      if (starts) starts.push(i);
      else t.ticksByLength.set(end - i, [i]);
      i = end - 1;
    } else if (ch === "]" && text[i + 1] === "(") t.linkMiddles.push(i);
    else if (ch === "[" || ch === "\n") t.labelStops.push(i);
  }
  return t;
}

// How many of the sorted positions are below x.
function bisect(positions: number[], x: number): number {
  let lo = 0;
  let hi = positions.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (positions[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

// The first of the sorted positions at or after i, or Infinity.
const first = (positions: number[], i: number) => positions[bisect(positions, i)] ?? Infinity;

// End of the run of text[i] characters starting at i (at most hi).
function runEnd(text: string, i: number, hi: number): number {
  let j = i;
  while (j < hi && text[j] === text[i]) j++;
  return j;
}

function canOpen(text: string, lo: number, hi: number, i: number, size: number): boolean {
  const prev = i > lo ? text[i - 1] : "";
  if (!(prev === "" || isSpace(prev) || OPEN_BEFORE.has(prev))) return false;
  // A single marker needs a letter or digit next (so *.example.com stays literal);
  // a double one only a non-space (so **.git** is bold).
  const next = i + size < hi ? text[i + size] : "";
  return size === 1 ? isAlnum(next) : next !== "" && !isSpace(next) && next !== "*" && next !== "_";
}

function canClose(text: string, lo: number, hi: number, i: number, size: number): boolean {
  const prev = i > lo ? text[i - 1] : "";
  const next = i + size < hi ? text[i + size] : "";
  if (prev === "" || isSpace(prev) || prev === "*" || prev === "_") return false;
  const after = i + size + 1 < hi ? text[i + size + 1] : "";
  if (next !== "" && ".-/:".includes(next) && isAlnum(after)) return false;
  return next === "" || (next !== "*" && next !== "_" && !isAlnum(next));
}

// If a code span starts at i, return [start of its closing run, index after it]. It opens with
// the backticks from i on (i may be inside a run, after an escaped backtick) and closes at the
// next run of exactly as many. A window never splits a run of backticks (an emphasis marker is
// on either side of it), so the text's runs are its runs.
function codeSpan(t: ScannedText, i: number, hi: number): [number, number] | null {
  const run = t.tickEnds[bisect(t.tickStarts, i + 1) - 1] - i;
  const starts = t.ticksByLength.get(run) ?? [];
  const k = bisect(starts, i + run);
  if (k === starts.length || starts[k] >= hi) return null;
  return [starts[k], starts[k] + run];
}

function codeContent(text: string, start: number, end: number): string {
  let content = text.slice(start, end).replace(/\n/g, " ");
  if (content.length > 2 && content[0] === " " && content.endsWith(" ") && content.trim()) content = content.slice(1, -1);
  return content;
}

function linkEnd(t: ScannedText, i: number, hi: number): [number, string, string] | null {
  const text = t.text;
  const close = first(t.linkMiddles, i + 1); // the first "](" after the "["
  // No "](", an empty label, or a "[" or line break in it.
  if (close + 2 > hi || close === i + 1 || first(t.labelStops, i + 1) < close) return null;
  // Matched in the whole text: a URL that reaches hi is no link in the window either.
  LINK_URL.lastIndex = close + 2;
  const m = LINK_URL.exec(text);
  if (!m) return null;
  const end = close + 2 + m[0].length;
  if (end >= hi || text[end] !== ")") return null;
  return [end + 1, text.slice(i + 1, close), m[0]];
}

// Index of the closing delim for an opener ending at start, or -1. Where the scan goes next
// depends only on where it is, so memo (one per window and delimiter) records the answer for
// every position a scan passes through, and a later scan stops as soon as it reaches one of
// them. Together the scans visit each position once.
function findCloser(
  t: ScannedText,
  lo: number,
  hi: number,
  start: number,
  delim: string,
  memo: Map<number, number>,
): number {
  const text = t.text;
  const passed: number[] = [];
  let i = start;
  let found = -1;
  while (i < hi) {
    const known = memo.get(i);
    if (known !== undefined) {
      found = known;
      break;
    }
    passed.push(i);
    const ch = text[i];
    if (ch === "\\" && i + 1 < hi && ESCAPABLE.has(text[i + 1])) {
      i += 2;
      continue;
    }
    if (ch === "`") {
      const span = codeSpan(t, i, hi);
      if (span) {
        i = span[1];
        continue;
      }
    }
    if (i + delim.length <= hi && text.startsWith(delim, i)) {
      const end = runEnd(text, i, hi);
      if (end - i === delim.length && canClose(text, lo, hi, i, delim.length)) {
        found = i;
        break;
      }
      i = end;
      continue;
    }
    i++;
  }
  for (const p of passed) memo.set(p, found);
  return found;
}

export function parseInline(text: string, bold = false, italic = false): Span[] {
  return parseWindow(scanText(text), 0, text.length, bold, italic);
}

function parseWindow(t: ScannedText, lo: number, hi: number, bold: boolean, italic: boolean): Span[] {
  const text = t.text;
  const spans: Span[] = [];
  const memos = new Map<string, Map<number, number>>(); // for findCloser, per delimiter
  let buf = "";
  const flush = () => {
    if (buf) spans.push({ text: buf, bold, italic });
    buf = "";
  };
  let i = lo;
  while (i < hi) {
    const ch = text[i];
    if (ch === "\\" && i + 1 < hi && ESCAPABLE.has(text[i + 1])) {
      buf += text[i + 1];
      i += 2;
      continue;
    }
    if (ch === "\n") {
      flush();
      spans.push({ text: "\n", bold, italic });
      i++;
      continue;
    }
    if (ch === "`") {
      const run = runEnd(text, i, hi) - i;
      const span = codeSpan(t, i, hi);
      if (span) {
        flush();
        spans.push({ text: codeContent(text, i + run, span[0]), bold, italic, code: true });
        i = span[1];
        continue;
      }
      buf += "`".repeat(run);
      i += run;
      continue;
    }
    if (ch === "[") {
      const link = linkEnd(t, i, hi);
      if (link) {
        flush();
        spans.push({ text: link[1], bold, italic, href: link[2] });
        i = link[0];
        continue;
      }
    }
    if (ch === "*" || ch === "_") {
      const run = runEnd(text, i, hi) - i;
      if ((run === 1 || run === 2) && canOpen(text, lo, hi, i, run)) {
        const delim = ch.repeat(run);
        let memo = memos.get(delim);
        if (!memo) memos.set(delim, (memo = new Map()));
        const close = findCloser(t, lo, hi, i + run, delim, memo);
        if (close > i + run) {
          flush();
          const inner =
            run === 2 ? parseWindow(t, i + run, close, true, italic) : parseWindow(t, i + run, close, bold, true);
          for (const s of inner) spans.push(s); // not push(...inner): a long list overflows the stack
          i = close + run;
          continue;
        }
      }
      buf += ch.repeat(run);
      i += run;
      continue;
    }
    buf += ch;
    i++;
  }
  flush();
  return spans.filter((s) => s.text);
}

function stripEnd(s: string, chars: string): string {
  let end = s.length;
  while (end > 0 && chars.includes(s[end - 1])) end--;
  return s.slice(0, end);
}

// [level, title] if the line is a heading with a title. Reads it as
// /^ {0,3}(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$/ would, without that pattern's backtracking,
// which takes cubic time on a long run of spaces.
function readHeading(line: string): [number, string] | null {
  const m = HEADING.exec(line);
  if (!m) return null;
  const rest = line.slice(m[0].length);
  if (/[\n\r\u2028\u2029]/.test(rest)) return null; // "." does not match these
  const title = stripEnd(stripEnd(stripEnd(rest, " \t"), "#"), " \t");
  return title ? [m[1].length, title] : null;
}

export function parse(text: string): Block[] {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let para: string[] = [];
  let list: Extract<Block, { kind: "bullets" | "numbers" }> | null = null;
  let item: string[] | null = null;

  const endPara = () => {
    if (para.length) blocks.push({ kind: "paragraph", spans: parseInline(para.join("\n")) });
    para = [];
  };
  const endItem = () => {
    if (list && item) list.items.push(parseInline(item.join("\n")));
    item = null;
  };
  const endList = () => {
    endItem();
    if (list && list.items.length) blocks.push(list);
    list = null;
  };

  let blankRun = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fence = FENCE.exec(line);
    if (fence) {
      endPara();
      endList();
      const marker = fence[1];
      const body: string[] = [];
      for (i++; i < lines.length; i++) {
        const closing = lines[i].trim();
        if (closing && [...closing].every((c) => c === marker[0]) && closing.length >= marker.length) break;
        body.push(lines[i]);
      }
      blocks.push({ kind: "code", text: body.join("\n") });
      blankRun = false;
      continue;
    }
    if (!line.trim()) {
      endPara();
      endItem();
      blankRun = true;
      continue;
    }
    const heading = readHeading(line);
    const bullet = BULLET.exec(line);
    const number = NUMBER.exec(line);
    const cont = CONTINUATION.exec(line);
    if (heading) {
      endPara();
      endList();
      blocks.push({ kind: "heading", spans: parseInline(heading[1]), level: heading[0] });
    } else if (bullet || number) {
      endPara();
      const kind = bullet ? "bullets" : "numbers";
      if (!list || list.kind !== kind) {
        endList();
        list = { kind, items: [], start: number ? Number(number[1]) : 1 };
      } else {
        endItem();
      }
      item = [bullet ? bullet[1] : number![2]];
    } else if (list && item && cont) {
      item.push(cont[1]);
    } else if (list && !item && blankRun && cont && list.items.length) {
      // Extended in place: copying the item for each paragraph would be quadratic.
      const last = list.items[list.items.length - 1];
      last.push({ text: "\n" }, { text: "\n" });
      for (const s of parseInline(cont[1])) last.push(s);
    } else {
      endList();
      para.push(line);
    }
    blankRun = false;
  }
  endPara();
  endList();
  return blocks;
}
