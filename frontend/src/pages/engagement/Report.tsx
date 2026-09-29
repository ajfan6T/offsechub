import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api, qs } from "../../api";
import { Button, Card, Field, useApiMutation } from "../../components/ui";
import type { Engagement, TestCase } from "../../types";
import { useEngagement, useFindings } from "./context";

interface Check {
  ok: boolean;
  label: string;
  link?: string;
}

export function Report() {
  const { engagement: e, base } = useEngagement();
  const findings = useFindings(base);
  const tests = useQuery({ queryKey: [base, "tests"], queryFn: () => api.get<TestCase[]>(`${base}/tests`) });
  const [drafts, setDrafts] = useState(false);
  const [nonce, setNonce] = useState(0);
  const [summary, setSummary] = useState(e.executive_summary);
  const saveSummary = useApiMutation(() => api.patch<Engagement>(base, { executive_summary: summary }), {
    invalidate: [[base]],
    success: "Executive summary saved",
    onSuccess: () => setNonce((n) => n + 1),
  });

  const reportable = (findings.data ?? []).filter((f) => !["draft", "false_positive"].includes(f.status));
  const draftCount = (findings.data ?? []).filter((f) => f.status === "draft").length;
  const incomplete = (tests.data ?? []).filter((t) => t.status === "not_started" || t.status === "in_progress").length;
  const checks: Check[] = [
    { ok: !!e.executive_summary.trim(), label: "Executive summary written" },
    { ok: draftCount === 0, label: draftCount ? `${draftCount} draft finding(s) not triaged` : "All findings triaged", link: "../findings" },
    ...[
      ["description", "a description"],
      ["remediation", "remediation advice"],
    ].map(([field, text]) => {
      const missing = reportable.filter((f) => !String(f[field as "description"]).trim()).length;
      return { ok: missing === 0, label: missing ? `${missing} finding(s) missing ${text}` : `Every finding has ${text}`, link: "../findings" };
    }),
    {
      ok: reportable.every((f) => f.targets.length > 0),
      label: reportable.every((f) => f.targets.length > 0) ? "Affected assets recorded" : "Some findings have no affected assets",
      link: "../findings",
    },
    {
      ok: reportable.every((f) => f.evidence_count > 0),
      label: reportable.every((f) => f.evidence_count > 0) ? "Evidence attached to every finding" : "Some findings have no evidence",
      link: "../evidence",
    },
    { ok: !!tests.data?.length && incomplete === 0, label: !tests.data?.length ? "No methodology tracked" : incomplete ? `${incomplete} test case(s) not completed` : "Methodology complete", link: "../testing" },
    { ok: !!e.rules_of_engagement.trim(), label: "Rules of engagement recorded", link: ".." },
  ];
  const ready = checks.filter((c) => c.ok).length;
  const url = (format: string, download = false) => `${base}/report${qs({ format, include_drafts: drafts || undefined, download: download || undefined })}`;

  return (
    <div className="grid-1-2 align-start">
      <div className="stack">
        <Card title={`Report readiness ${ready}/${checks.length}`}>
          <ul className="checks">
            {checks.map((c) => (
              <li key={c.label} className={c.ok ? "ok" : "todo"}>
                <span className="check-icon">{c.ok ? "✓" : "!"}</span>
                {c.link && !c.ok ? <Link to={c.link}>{c.label}</Link> : c.label}
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Executive summary">
          <Field label="Written for a non-technical reader: overall risk, key themes, top priorities">
            <textarea rows={10} value={summary} onChange={(ev) => setSummary(ev.target.value)} />
          </Field>
          <Button variant="primary" disabled={summary === e.executive_summary} loading={saveSummary.isPending} onClick={() => saveSummary.mutate(undefined)}>
            Save summary
          </Button>
        </Card>
        <Card title="Export">
          <label className="check">
            <input type="checkbox" checked={drafts} onChange={(ev) => setDrafts(ev.target.checked)} /> Include draft findings (internal QA copy)
          </label>
          <div className="actions wrap">
            <a className="btn btn-primary" href={url("html", true)} download>Save printable HTML</a>
            <a className="btn btn-secondary" href={url("md", true)} download>Markdown</a>
            <a className="btn btn-secondary" href={url("json", true)} download>JSON</a>
          </div>
          <p className="muted small">
            For a PDF, open the saved HTML file in your browser, then Print → Save as PDF. The file is self-contained (images
            embedded, no scripts). {reportable.length} finding(s) will be included. Every export is recorded in the activity
            log.
          </p>
        </Card>
      </div>
      <Card title="Preview" actions={<Button size="sm" variant="ghost" onClick={() => setNonce((n) => n + 1)}>Refresh</Button>}>
        {/* Empty sandbox: the report runs with no scripts and an opaque origin, so it can never reach the API. */}
        <iframe key={`${nonce}-${drafts}`} className="report-frame" title="Report preview" src={url("html")} sandbox="" />
      </Card>
    </div>
  );
}
