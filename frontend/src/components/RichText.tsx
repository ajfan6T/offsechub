import { type ReactNode, useId, useState } from "react";
import { type Block, parse, type Span } from "../lib/richtext";

function spans(list: Span[]): ReactNode[] {
  return list.map((s, i) => {
    if (s.text === "\n" && !s.code) return <br key={i} />;
    let node: ReactNode = s.code ? <code>{s.text}</code> : s.text;
    if (s.italic) node = <em>{node}</em>;
    if (s.bold) node = <strong>{node}</strong>;
    // Shown, not followed: navigating would take the window away from the unsaved form.
    if (s.href) node = <span className="rt-link" title={s.href}>{node}</span>;
    return <span key={i}>{node}</span>;
  });
}

function block(b: Block, i: number): ReactNode {
  switch (b.kind) {
    case "paragraph":
      return <p key={i}>{spans(b.spans)}</p>;
    case "heading":
      return <h5 key={i}>{spans(b.spans)}</h5>;
    case "code":
      return <pre key={i}><code>{b.text}</code></pre>;
    case "bullets":
      return <ul key={i}>{b.items.map((it, j) => <li key={j}>{spans(it)}</li>)}</ul>;
    case "numbers":
      return <ol key={i} start={b.start}>{b.items.map((it, j) => <li key={j}>{spans(it)}</li>)}</ol>;
  }
}

/** Finding text rendered with the same Markdown subset as the reports. */
export function RichText({ text, empty }: { text: string; empty?: ReactNode }) {
  const blocks = parse(text);
  if (!blocks.length) return <div className="rich muted small">{empty ?? "Nothing written yet."}</div>;
  return <div className="rich">{blocks.map(block)}</div>;
}

export const RICH_HINT = "**bold**, *italic*, `code`, - lists, 1. steps, ``` blocks";

/**
 * A rich-text field: label, Write / Preview switch, textarea and hint. It lays out its own
 * label (rather than using Field) so the switch stays out of the textarea's accessible name.
 */
export function RichField({
  label,
  hint,
  value,
  onChange,
  rows = 5,
  mono,
  placeholder,
}: {
  label: string;
  hint?: ReactNode;
  value: string;
  onChange: (value: string) => void;
  rows?: number;
  mono?: boolean;
  placeholder?: string;
}) {
  const id = useId();
  const [preview, setPreview] = useState(false);
  return (
    <div className="field field-wide rich-field">
      <div className="rich-head">
        <label className="field-label" htmlFor={id}>{label}</label>
        <div className="seg" role="group" aria-label={`${label}: write or preview`}>
          <button type="button" className={preview ? "" : "on"} aria-pressed={!preview} onClick={() => setPreview(false)}>Write</button>
          <button type="button" className={preview ? "on" : ""} aria-pressed={preview} onClick={() => setPreview(true)}>Preview</button>
        </div>
      </div>
      {preview ? (
        <div className="rich-preview" id={id} tabIndex={0} aria-label={`${label} preview`} style={{ minHeight: `${rows * 1.55}em` }}>
          <RichText text={value} />
        </div>
      ) : (
        <textarea id={id} rows={rows} className={mono ? "mono" : undefined} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
      )}
      <span className="field-hint">{hint ? <>{hint} · </> : null}Formatting: {RICH_HINT}</span>
    </div>
  );
}
