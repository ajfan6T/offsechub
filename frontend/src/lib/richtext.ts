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

const ESCAPABLE = new Set("\\`*_{}[]()#+-.!>~|");
const OPEN_BEFORE = new Set("([{\"'");
const LINK_URL = /^(?:https?:\/\/|mailto:)[^\s()<>"]+/i;
const FENCE = /^ {0,3}(`{3,}|~{3,})[ \t]*([\w+#.-]*)[ \t]*$/;
const HEADING = /^ {0,3}(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$/;
const BULLET = /^ {0,3}[-*+][ \t]+(.*)$/;
const NUMBER = /^ {0,3}(\d{1,9})[.)][ \t]+(.*)$/;
const CONTINUATION = /^(?: {2,}|\t)(\S.*)$/;

const isSpace = (ch: string) => ch === "" || /\s/.test(ch);
const isAlnum = (ch: string) => ch !== "" && /[\p{L}\p{N}]/u.test(ch);
const at = (text: string, i: number) => (i >= 0 && i < text.length ? text[i] : "");

function runLength(text: string, i: number, ch: string): number {
  let j = i;
  while (j < text.length && text[j] === ch) j++;
  return j - i;
}

function canOpen(text: string, i: number, size: number): boolean {
  const prev = at(text, i - 1);
  if (!(prev === "" || isSpace(prev) || OPEN_BEFORE.has(prev))) return false;
  // A single marker needs a letter or digit next (so *.example.com stays literal);
  // a double one only a non-space (so **.git** is bold).
  const next = at(text, i + size);
  return size === 1 ? isAlnum(next) : next !== "" && !isSpace(next) && next !== "*" && next !== "_";
}

function canClose(text: string, i: number, size: number): boolean {
  const prev = at(text, i - 1);
  const next = at(text, i + size);
  if (prev === "" || isSpace(prev) || prev === "*" || prev === "_") return false;
  if (next !== "" && ".-/:".includes(next) && isAlnum(at(text, i + size + 1))) return false;
  return next === "" || (next !== "*" && next !== "_" && !isAlnum(next));
}

function codeSpanEnd(text: string, i: number): [number, string] | null {
  const run = runLength(text, i, "`");
  let j = i + run;
  for (;;) {
    const k = text.indexOf("`".repeat(run), j);
    if (k < 0) return null;
    const after = k + run;
    if (at(text, after) === "`") {
      j = after + runLength(text, after, "`");
      continue;
    }
    let content = text.slice(i + run, k).replace(/\n/g, " ");
    if (content.length > 2 && content[0] === " " && content.endsWith(" ") && content.trim()) content = content.slice(1, -1);
    return [after, content];
  }
}

function linkEnd(text: string, i: number): [number, string, string] | null {
  const close = text.indexOf("](", i + 1);
  if (close < 0 || close === i + 1 || text.slice(i + 1, close).includes("\n")) return null;
  const m = LINK_URL.exec(text.slice(close + 2));
  if (!m) return null;
  const end = close + 2 + m[0].length;
  if (at(text, end) !== ")") return null;
  const label = text.slice(i + 1, close);
  if (label.includes("[")) return null;
  return [end + 1, label, m[0]];
}

function findCloser(text: string, start: number, delim: string): number {
  let i = start;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "\\" && ESCAPABLE.has(at(text, i + 1))) {
      i += 2;
      continue;
    }
    if (ch === "`") {
      const span = codeSpanEnd(text, i);
      if (span) {
        i = span[0];
        continue;
      }
    }
    if (text.startsWith(delim, i)) {
      const run = runLength(text, i, delim[0]);
      if (run === delim.length && canClose(text, i, delim.length)) return i;
      i += run;
      continue;
    }
    i++;
  }
  return -1;
}

export function parseInline(text: string, bold = false, italic = false): Span[] {
  const spans: Span[] = [];
  let buf = "";
  const flush = () => {
    if (buf) spans.push({ text: buf, bold, italic });
    buf = "";
  };
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "\\" && ESCAPABLE.has(at(text, i + 1))) {
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
      const span = codeSpanEnd(text, i);
      if (span) {
        flush();
        spans.push({ text: span[1], bold, italic, code: true });
        i = span[0];
        continue;
      }
      const run = runLength(text, i, "`");
      buf += "`".repeat(run);
      i += run;
      continue;
    }
    if (ch === "[") {
      const link = linkEnd(text, i);
      if (link) {
        flush();
        spans.push({ text: link[1], bold, italic, href: link[2] });
        i = link[0];
        continue;
      }
    }
    if (ch === "*" || ch === "_") {
      const run = runLength(text, i, ch);
      if ((run === 1 || run === 2) && canOpen(text, i, run)) {
        const delim = ch.repeat(run);
        const close = findCloser(text, i + run, delim);
        if (close > i + run) {
          flush();
          const inner = text.slice(i + run, close);
          spans.push(...(run === 2 ? parseInline(inner, true, italic) : parseInline(inner, bold, true)));
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
    const heading = HEADING.exec(line);
    const bullet = BULLET.exec(line);
    const number = NUMBER.exec(line);
    const cont = CONTINUATION.exec(line);
    if (heading && heading[2]) {
      endPara();
      endList();
      blocks.push({ kind: "heading", spans: parseInline(heading[2]), level: heading[1].length });
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
      const last = list.items[list.items.length - 1];
      list.items[list.items.length - 1] = [...last, { text: "\n" }, { text: "\n" }, ...parseInline(cont[1])];
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
