import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../../api";
import {
  Button,
  Card,
  ConfirmButton,
  Field,
  Loading,
  SeverityBadge,
  Stat,
  useApiMutation,
} from "../../components/ui";
import { ENGAGEMENT_STATUSES, ENGAGEMENT_TYPES, SEVERITIES, TEST_STATUSES, titleCase } from "../../lib/format";
import { useNavigate } from "react-router";
import type { Engagement, EngagementSummary, TestStatus } from "../../types";
import { useEngagement } from "./context";

export function Overview() {
  const { engagement: e, base } = useEngagement();
  const summary = useQuery({ queryKey: [base, "summary"], queryFn: () => api.get<EngagementSummary>(`${base}/summary`) });
  const s = summary.data;

  return (
    <>
      {s && (
        <div className="stats">
          <Stat label="Scope rules" value={s.scope_items} tone={s.scope_items ? undefined : "amber"} hint={s.scope_items ? undefined : "Define scope before testing"} />
          <Stat label="Targets" value={s.targets} hint={`${s.targets_in_scope} in scope · ${s.targets_out_of_scope} out`} tone={s.targets_out_of_scope ? "amber" : undefined} />
          <Stat label="Open services" value={s.services} />
          <Stat label="Compromised" value={s.targets_compromised} tone={s.targets_compromised ? "red" : undefined} />
          <Stat label="Evidence items" value={s.evidence} />
          <Stat label="Op-log entries" value={s.oplog_entries} />
        </div>
      )}
      <div className="grid-2">
        <div className="stack">
          {s ? <FindingsCard s={s} /> : <Loading />}
          {s && <TestingCard s={s} />}
        </div>
        <div className="stack">
          <DetailsCard key={e.updated_at} />
          <DangerCard />
        </div>
      </div>
    </>
  );
}

function FindingsCard({ s }: { s: EngagementSummary }) {
  const max = Math.max(1, ...SEVERITIES.map((x) => s.findings_by_severity[x] ?? 0));
  const drafts = s.findings_by_status.draft ?? 0;
  return (
    <Card title="Findings">
      {SEVERITIES.map((sev) => (
        <div key={sev} className="hbar">
          <SeverityBadge severity={sev} />
          <div className="hbar-track">
            <div className={`hbar-fill sev-bg-${sev}`} style={{ width: `${((s.findings_by_severity[sev] ?? 0) / max) * 100}%` }} />
          </div>
          <strong>{s.findings_by_severity[sev] ?? 0}</strong>
        </div>
      ))}
      {drafts > 0 && <p className="warn-text small">{drafts} draft finding(s) awaiting triage</p>}
    </Card>
  );
}

function TestingCard({ s }: { s: EngagementSummary }) {
  const order: TestStatus[] = ["passed", "failed", "not_applicable", "blocked", "in_progress", "not_started"];
  const total = order.reduce((n, k) => n + (s.tests_by_status[k] ?? 0), 0);
  const done = total - (s.tests_by_status.not_started ?? 0) - (s.tests_by_status.in_progress ?? 0);
  return (
    <Card title="Test coverage">
      {total === 0 ? (
        <p className="muted">No methodology applied yet. Add one from the Testing tab.</p>
      ) : (
        <>
          <div className="progress">
            {order.map((k) =>
              s.tests_by_status[k] ? (
                <span key={k} className={`progress-seg t-${k}`} style={{ flexGrow: s.tests_by_status[k] }} title={`${TEST_STATUSES[k]}: ${s.tests_by_status[k]}`} />
              ) : null,
            )}
          </div>
          <p className="small">
            <strong>{Math.round((done / total) * 100)}%</strong> complete · {done}/{total} checks ·{" "}
            <span className="error-text">{s.tests_by_status.failed ?? 0} vulnerable</span>
          </p>
        </>
      )}
    </Card>
  );
}

function DetailsCard() {
  const { engagement: e, base } = useEngagement();
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({
    name: e.name,
    type: e.type,
    status: e.status,
    start_date: e.start_date ?? "",
    end_date: e.end_date ?? "",
    description: e.description,
    rules_of_engagement: e.rules_of_engagement,
  });
  const save = useApiMutation(
    () => api.patch<Engagement>(base, { ...form, start_date: form.start_date || null, end_date: form.end_date || null }),
    { invalidate: [[base], ["engagements"], ["dashboard"]], success: "Engagement updated", onSuccess: () => setEditing(false) },
  );
  const setStatus = useApiMutation((status: string) => api.patch(base, { status }), {
    invalidate: [[base], ["engagements"], ["dashboard"]],
    success: "Status updated",
  });
  const set = (k: keyof typeof form) => (ev: { target: { value: string } }) => setForm({ ...form, [k]: ev.target.value });

  if (editing)
    return (
      <Card title="Engagement details">
        <div className="form-grid">
          <Field label="Name" wide>
            <input value={form.name} onChange={set("name")} />
          </Field>
          <Field label="Type">
            <select value={form.type} onChange={set("type")}>
              {Object.entries(ENGAGEMENT_TYPES).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Status">
            <select value={form.status} onChange={set("status")}>
              {ENGAGEMENT_STATUSES.map((st) => (
                <option key={st} value={st}>
                  {titleCase(st)}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Start">
            <input type="date" value={form.start_date} onChange={set("start_date")} />
          </Field>
          <Field label="End">
            <input type="date" value={form.end_date} onChange={set("end_date")} />
          </Field>
          <Field label="Description" wide>
            <textarea rows={4} value={form.description} onChange={set("description")} />
          </Field>
          <Field label="Rules of engagement" wide>
            <textarea rows={6} value={form.rules_of_engagement} onChange={set("rules_of_engagement")} />
          </Field>
        </div>
        <div className="actions">
          <Button onClick={() => setEditing(false)}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} onClick={() => save.mutate(undefined)}>
            Save
          </Button>
        </div>
      </Card>
    );

  return (
    <Card
      title="Engagement details"
      actions={
        <Button size="sm" variant="ghost" onClick={() => setEditing(true)}>
          Edit
        </Button>
      }
    >
      <dl className="dl">
        <dt>Client</dt>
        <dd>{e.client.name}</dd>
        <dt>Status</dt>
        <dd>
          <select value={e.status} onChange={(ev) => setStatus.mutate(ev.target.value)}>
            {ENGAGEMENT_STATUSES.map((st) => (
              <option key={st} value={st}>
                {titleCase(st)}
              </option>
            ))}
          </select>
        </dd>
        <dt>Reference</dt>
        <dd className="mono">{e.code}</dd>
      </dl>
      <h3>Description</h3>
      <p className="pre">{e.description || <span className="muted">None</span>}</p>
      <h3>Rules of engagement</h3>
      <p className="pre">{e.rules_of_engagement || <span className="warn-text">Not recorded. Capture testing windows, restrictions and emergency contacts.</span>}</p>
    </Card>
  );
}

function DangerCard() {
  const { engagement: e, base } = useEngagement();
  const navigate = useNavigate();
  const del = useApiMutation(() => api.del(base), {
    invalidate: [["engagements"], ["dashboard"]],
    success: `Deleted ${e.code}`,
    onSuccess: () => navigate("/engagements"),
  });
  return (
    <Card title="Data retention">
      <p className="muted small">
        Deleting an engagement permanently removes its targets, findings, op log and evidence files. The activity log keeps
        a record of the deletion.
      </p>
      <ConfirmButton
        variant="danger"
        message={`Permanently delete ${e.code} and all of its evidence? This cannot be undone.`}
        onConfirm={() => del.mutate(undefined)}
      >
        Delete engagement
      </ConfirmButton>
    </Card>
  );
}
