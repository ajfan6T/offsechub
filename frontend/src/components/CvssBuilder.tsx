import { useQuery } from "@tanstack/react-query";
import { type MouseEvent, useEffect, useState } from "react";
import { api } from "../api";
import type { CvssResult } from "../types";
import { SeverityBadge } from "./ui";

type Version = "3.1" | "4.0";
type Metric = { key: string; label: string; options: [string, string][] };
type MetricGroup = { title?: string; metrics: Metric[] };

const IMPACT: [string, string][] = [["N", "None"], ["L", "Low"], ["H", "High"]];

const V3_METRICS: Metric[] = [
  { key: "AV", label: "Attack vector", options: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
  { key: "AC", label: "Attack complexity", options: [["L", "Low"], ["H", "High"]] },
  { key: "PR", label: "Privileges required", options: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  { key: "UI", label: "User interaction", options: [["N", "None"], ["R", "Required"]] },
  { key: "S", label: "Scope", options: [["U", "Unchanged"], ["C", "Changed"]] },
  { key: "C", label: "Confidentiality", options: IMPACT },
  { key: "I", label: "Integrity", options: IMPACT },
  { key: "A", label: "Availability", options: IMPACT },
];

const V4_EXPLOITABILITY: Metric[] = [
  { key: "AV", label: "Attack vector", options: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
  { key: "AC", label: "Attack complexity", options: [["L", "Low"], ["H", "High"]] },
  { key: "AT", label: "Attack requirements", options: [["N", "None"], ["P", "Present"]] },
  { key: "PR", label: "Privileges required", options: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  { key: "UI", label: "User interaction", options: [["N", "None"], ["P", "Passive"], ["A", "Active"]] },
];

const impacts = (prefix: string): Metric[] => [
  { key: `${prefix}C`, label: "Confidentiality", options: IMPACT },
  { key: `${prefix}I`, label: "Integrity", options: IMPACT },
  { key: `${prefix}A`, label: "Availability", options: IMPACT },
];

const SPECS: Record<Version, { prefix: string; groups: MetricGroup[]; placeholder: string; hint: string }> = {
  "3.1": {
    prefix: "CVSS:3.1",
    groups: [{ metrics: V3_METRICS }],
    placeholder: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    hint: "Pick all eight metrics or paste a vector",
  },
  "4.0": {
    prefix: "CVSS:4.0",
    groups: [
      { metrics: V4_EXPLOITABILITY },
      { title: "Vulnerable system", metrics: impacts("V") },
      { title: "Subsequent system", metrics: impacts("S") },
    ],
    placeholder: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    hint: "Pick all eleven metrics or paste a vector",
  },
};

const pickerMetrics = (version: Version) => SPECS[version].groups.flatMap((g) => g.metrics);

function versionOf(vector: string): Version | null {
  if (vector.startsWith("CVSS:4.0")) return "4.0";
  if (vector.startsWith("CVSS:3")) return "3.1";
  return null;
}

function parse(vector: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) out[k] = v;
  }
  return out;
}

// The picked metrics as a vector, keeping any extra (threat, environmental...) metrics that were pasted.
function build(version: Version, metrics: Record<string, string>): string {
  const picker = pickerMetrics(version);
  if (!picker.every((m) => metrics[m.key])) return "";
  const keys = new Set(picker.map((m) => m.key));
  const picked = picker.map((m) => `${m.key}:${metrics[m.key]}`);
  const extras = Object.entries(metrics)
    .filter(([k]) => !keys.has(k))
    .map(([k, v]) => `${k}:${v}`);
  return [SPECS[version].prefix, ...picked, ...extras].join("/");
}

// Picks that mean the same in the other version (AV, AC, PR and sometimes UI) survive a switch.
function carryOver(metrics: Record<string, string>, version: Version): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of pickerMetrics(version)) {
    const v = metrics[m.key];
    if (v && m.options.some(([code]) => code === v)) out[m.key] = v;
  }
  return out;
}

export function useCvssScore(vector: string) {
  return useQuery({
    queryKey: ["cvss", vector],
    queryFn: () => api.post<CvssResult>("/api/cvss", { vector }),
    enabled: versionOf(vector) !== null,
    staleTime: Infinity,
    retry: false,
  });
}

export function CvssBuilder({ value, onChange }: { value: string; onChange: (vector: string) => void }) {
  const [version, setVersion] = useState<Version>(() => versionOf(value) ?? "3.1");
  const [metrics, setMetrics] = useState<Record<string, string>>(() => parse(value));
  const [raw, setRaw] = useState(value);
  const score = useCvssScore(value);
  const spec = SPECS[version];

  useEffect(() => {
    setMetrics(parse(value));
    setRaw(value);
    const v = versionOf(value);
    if (v) setVersion(v);
  }, [value]);

  const switchVersion = (next: Version) => {
    if (next === version) return;
    setVersion(next);
    // The current vector stays until all of the new version's metrics are picked.
    setMetrics(versionOf(value) === next ? parse(value) : carryOver(metrics, next));
  };

  const pick = (key: string, v: string) => {
    const next = { ...metrics, [key]: v };
    setMetrics(next);
    const vector = build(version, next);
    if (vector) onChange(vector);
  };

  // The builder sits inside a form field's <label>, which turns a click on any plain text in
  // here into a click on the first button (the version switch). Keep such clicks inert.
  const ignoreLabelClicks = (e: MouseEvent) => {
    if (!(e.target as Element).closest("button, input")) e.preventDefault();
  };

  return (
    <div className="cvss" onClick={ignoreLabelClicks}>
      <div className="cvss-metric" style={{ marginBottom: 12 }}>
        <span className="cvss-label">Version</span>
        <div className="seg">
          {(["3.1", "4.0"] as Version[]).map((v) => (
            <button type="button" key={v} className={version === v ? "on" : ""} onClick={() => switchVersion(v)}>
              CVSS {v}
            </button>
          ))}
        </div>
      </div>
      {spec.groups.map((group, i) => (
        <div key={group.title ?? i} style={i ? { marginTop: 14 } : undefined}>
          {group.title && (
            <div className="cvss-label" style={{ color: "var(--text)", marginBottom: 8 }}>
              {group.title}
            </div>
          )}
          <div className="cvss-grid">
            {group.metrics.map((m) => (
              <div key={m.key} className="cvss-metric">
                <span className="cvss-label">{m.label}</span>
                <div className="seg">
                  {m.options.map(([code, label]) => (
                    <button
                      type="button"
                      key={code}
                      className={metrics[m.key] === code ? "on" : ""}
                      onClick={() => pick(m.key, code)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
      <div className="cvss-footer">
        <input
          className="mono"
          value={raw}
          placeholder={spec.placeholder}
          onChange={(e) => setRaw(e.target.value)}
          onBlur={() => raw !== value && onChange(raw.trim())}
        />
        {value && score.data && <SeverityBadge severity={score.data.severity} score={score.data.score} />}
        {value && score.error && <span className="error-text">{(score.error as Error).message}</span>}
        {!value && <span className="muted small">{spec.hint}</span>}
        {value && (
          <button type="button" className="link" onClick={() => onChange("")}>
            Clear
          </button>
        )}
      </div>
    </div>
  );
}
