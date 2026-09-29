import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { CvssResult } from "../types";
import { SeverityBadge } from "./ui";

const METRICS: { key: string; label: string; options: [string, string][] }[] = [
  { key: "AV", label: "Attack vector", options: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
  { key: "AC", label: "Attack complexity", options: [["L", "Low"], ["H", "High"]] },
  { key: "PR", label: "Privileges required", options: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  { key: "UI", label: "User interaction", options: [["N", "None"], ["R", "Required"]] },
  { key: "S", label: "Scope", options: [["U", "Unchanged"], ["C", "Changed"]] },
  { key: "C", label: "Confidentiality", options: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  { key: "I", label: "Integrity", options: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  { key: "A", label: "Availability", options: [["N", "None"], ["L", "Low"], ["H", "High"]] },
];

function parse(vector: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) out[k] = v;
  }
  return out;
}

function build(metrics: Record<string, string>): string {
  if (!METRICS.every((m) => metrics[m.key])) return "";
  return "CVSS:3.1/" + METRICS.map((m) => `${m.key}:${metrics[m.key]}`).join("/");
}

export function useCvssScore(vector: string) {
  return useQuery({
    queryKey: ["cvss", vector],
    queryFn: () => api.post<CvssResult>("/api/cvss", { vector }),
    enabled: vector.startsWith("CVSS:3"),
    staleTime: Infinity,
    retry: false,
  });
}

export function CvssBuilder({ value, onChange }: { value: string; onChange: (vector: string) => void }) {
  const [metrics, setMetrics] = useState<Record<string, string>>(() => parse(value));
  const [raw, setRaw] = useState(value);
  const score = useCvssScore(value);

  useEffect(() => {
    setMetrics(parse(value));
    setRaw(value);
  }, [value]);

  const pick = (key: string, v: string) => {
    const next = { ...metrics, [key]: v };
    setMetrics(next);
    const vector = build(next);
    if (vector) onChange(vector);
  };

  return (
    <div className="cvss">
      <div className="cvss-grid">
        {METRICS.map((m) => (
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
      <div className="cvss-footer">
        <input
          className="mono"
          value={raw}
          placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          onChange={(e) => setRaw(e.target.value)}
          onBlur={() => raw !== value && onChange(raw.trim())}
        />
        {value && score.data && <SeverityBadge severity={score.data.severity} score={score.data.score} />}
        {value && score.error && <span className="error-text">{(score.error as Error).message}</span>}
        {!value && <span className="muted small">Pick all eight metrics or paste a vector</span>}
        {value && (
          <button type="button" className="link" onClick={() => onChange("")}>
            Clear
          </button>
        )}
      </div>
    </div>
  );
}
