import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { api } from "../../api";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorBox,
  Loading,
  Modal,
  SeverityBadge,
  useApiMutation,
} from "../../components/ui";
import { FINDING_STATUSES, SEVERITIES, titleCase } from "../../lib/format";
import type { Finding, FindingStatus, FindingTemplate, Severity } from "../../types";
import { useEngagement, useFindings } from "./context";

export function Findings() {
  const { base } = useEngagement();
  const q = useFindings(base);
  const navigate = useNavigate();
  const [severity, setSeverity] = useState<Severity | "">("");
  const [status, setStatus] = useState<FindingStatus | "">("");
  const [search, setSearch] = useState("");
  const [picking, setPicking] = useState(false);
  const patch = useApiMutation(
    (v: { id: number; status: FindingStatus }) => api.patch(`${base}/findings/${v.id}`, { status: v.status }),
    { invalidate: [[base, "findings"], [base, "summary"], [base], ["dashboard"]] },
  );

  const all = q.data ?? [];
  const rows = all.filter(
    (f) =>
      (!severity || f.severity === severity) &&
      (!status || f.status === status) &&
      `${f.ref} ${f.title} ${f.cwe} ${f.targets.map((t) => t.value).join(" ")}`.toLowerCase().includes(search.toLowerCase()),
  );
  const drafts = all.filter((f) => f.status === "draft").length;

  return (
    <>
      <div className="sev-filter">
        {SEVERITIES.map((s) => {
          const n = all.filter((f) => f.severity === s && f.status !== "false_positive").length;
          return (
            <button key={s} className={`sev-tile sev-tile-${s} ${severity === s ? "on" : ""}`} onClick={() => setSeverity(severity === s ? "" : s)}>
              <strong>{n}</strong>
              <span>{titleCase(s)}</span>
            </button>
          );
        })}
      </div>
      <div className="toolbar">
        <input placeholder="Search ref, title, CWE, affected asset" value={search} onChange={(e) => setSearch(e.target.value)} />
        <select value={status} onChange={(e) => setStatus(e.target.value as FindingStatus | "")}>
          <option value="">All statuses</option>
          {Object.entries(FINDING_STATUSES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        {drafts > 0 && (
          <Button size="sm" variant="ghost" onClick={() => setStatus("draft")}>
            {drafts} to triage
          </Button>
        )}
        <Button onClick={() => setPicking(true)}>From library</Button>
        <Button variant="primary" onClick={() => navigate("new")}>New finding</Button>
      </div>
      <Card>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <ErrorBox error={q.error} />
        ) : rows.length === 0 ? (
          <Empty title="No findings">Write one, pick one from the library, or import nuclei results.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Ref</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>Affected</th>
                <th>Evidence</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className={f.status === "false_positive" ? "dim" : ""}>
                  <td className="mono small nowrap">{f.ref}</td>
                  <td>
                    <Link to={String(f.id)} className="strong">{f.title}</Link>
                    <div className="muted small">
                      {f.cwe && <span className="mono">{f.cwe} · </span>}
                      {f.source !== "manual" && <Badge>{f.source}</Badge>}
                    </div>
                  </td>
                  <td><SeverityBadge severity={f.severity} score={f.cvss_score} /></td>
                  <td className="small">
                    {f.targets.length === 0 ? <span className="warn-text">none</span> : f.targets.length === 1 ? <span className="mono">{f.targets[0]!.value}</span> : `${f.targets.length} assets`}
                  </td>
                  <td className="small">{f.evidence_count || <span className="warn-text">none</span>}</td>
                  <td>
                    <select value={f.status} onChange={(e) => patch.mutate({ id: f.id, status: e.target.value as FindingStatus })}>
                      {Object.entries(FINDING_STATUSES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {picking && <TemplatePicker onClose={() => setPicking(false)} />}
    </>
  );
}

function TemplatePicker({ onClose }: { onClose: () => void }) {
  const { base } = useEngagement();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const templates = useQuery({ queryKey: ["finding-templates"], queryFn: () => api.get<FindingTemplate[]>("/api/finding-templates") });
  const create = useApiMutation((template_id: number) => api.post<Finding>(`${base}/findings`, { template_id }), {
    invalidate: [[base, "findings"], [base, "summary"]],
    success: (f) => `Created ${f.ref}`,
    onSuccess: (f) => navigate(String(f.id)),
  });
  const rows = (templates.data ?? []).filter((t) => `${t.title} ${t.category} ${t.cwe}`.toLowerCase().includes(search.toLowerCase()));
  return (
    <Modal title="New finding from library" onClose={onClose} wide>
      <input placeholder="Search templates" value={search} onChange={(e) => setSearch(e.target.value)} autoFocus />
      {templates.isLoading ? (
        <Loading />
      ) : (
        <table className="table">
          <tbody>
            {rows.map((t) => (
              <tr key={t.id} className="clickable" onClick={() => create.mutate(t.id)}>
                <td className="strong">{t.title}</td>
                <td className="muted small">{t.category}</td>
                <td><SeverityBadge severity={t.severity} score={t.cvss_score} /></td>
                <td className="mono small">{t.cwe}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}
