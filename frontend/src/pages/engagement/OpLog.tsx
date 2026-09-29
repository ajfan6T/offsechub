import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api } from "../../api";
import { Badge, Button, Card, ConfirmButton, Empty, Field, Loading, useApiMutation } from "../../components/ui";
import { fmtDateTime } from "../../lib/format";
import type { OplogEntry, OplogOutcome } from "../../types";
import { useProfile } from "../../vault/context";
import { useEngagement } from "./context";

const OUTCOME_TONE: Record<OplogOutcome, string> = { info: "neutral", success: "green", failure: "muted", detected: "amber" };
const SOURCE_KEY = "offsechub.oplog.source";

function localNow(): string {
  const d = new Date();
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 16);
}

export function OpLog() {
  const { base, engagement } = useEngagement();
  const profile = useProfile();
  const q = useQuery({ queryKey: [base, "oplog"], queryFn: () => api.get<OplogEntry[]>(`${base}/oplog`) });
  const blank = () => ({
    occurred_at: localNow(),
    source_host: localStorage.getItem(SOURCE_KEY) ?? "",
    target: "",
    tool: "",
    command: "",
    description: "",
    outcome: "info" as OplogOutcome,
  });
  const [form, setForm] = useState(blank);
  const set = (k: keyof ReturnType<typeof blank>) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  const add = useApiMutation(
    () => {
      localStorage.setItem(SOURCE_KEY, form.source_host);
      return api.post(`${base}/oplog`, { ...form, occurred_at: new Date(form.occurred_at).toISOString() });
    },
    { invalidate: [[base, "oplog"], [base, "summary"]], success: "Logged", onSuccess: () => setForm(blank()) },
  );
  const remove = useApiMutation((id: number) => api.del(`${base}/oplog/${id}`), { invalidate: [[base, "oplog"]] });

  return (
    <>
      <p className="muted">
        The operator log is your deconfliction record: when the SOC asks "was that you?", this answers it. Log noisy or risky
        actions, credential use and anything that touched production.
      </p>
      <Card title="Log an action">
        <div className="form-grid oplog-form">
          <Field label="When (local time)"><input type="datetime-local" value={form.occurred_at} onChange={set("occurred_at")} /></Field>
          <Field label="Source host / IP"><input className="mono" value={form.source_host} onChange={set("source_host")} placeholder="192.0.2.200" /></Field>
          <Field label="Target"><input className="mono" value={form.target} onChange={set("target")} placeholder="10.0.0.5 / https://..." /></Field>
          <Field label="Tool"><input value={form.tool} onChange={set("tool")} placeholder="nmap, sqlmap, netexec" /></Field>
          <Field label="Command" wide><input className="mono" value={form.command} onChange={set("command")} placeholder="Exact command or request" /></Field>
          <Field label="What / why" wide><input value={form.description} onChange={set("description")} /></Field>
          <Field label="Outcome">
            <select value={form.outcome} onChange={set("outcome")}>
              <option value="info">Info</option>
              <option value="success">Success</option>
              <option value="failure">Failed</option>
              <option value="detected">Detected / blocked</option>
            </select>
          </Field>
        </div>
        <div className="actions">
          <Button variant="primary" loading={add.isPending} disabled={!form.command && !form.description && !form.target} onClick={() => add.mutate(undefined)}>
            Add entry
          </Button>
          {profile.data && (
            <span className="muted small">
              {profile.data.name ? (
                <>Logged as <strong>{profile.data.name}</strong></>
              ) : (
                <>Entries carry your profile name. <Link to="/settings">Set it in Settings</Link> so exported logs are attributable.</>
              )}
            </span>
          )}
        </div>
      </Card>
      <Card
        title={`Timeline (${q.data?.length ?? 0})`}
        actions={<a className="btn btn-secondary btn-sm" href={`${base}/oplog/export.csv`} download={`${engagement.code}-oplog.csv`}>Export CSV</a>}
      >
        {q.isLoading ? (
          <Loading />
        ) : !q.data?.length ? (
          <Empty title="No entries yet" />
        ) : (
          <table className="table">
            <thead>
              <tr><th>When</th><th>Operator</th><th>Source → target</th><th>Tool / command</th><th>Outcome</th><th /></tr>
            </thead>
            <tbody>
              {q.data.map((e) => (
                <tr key={e.id}>
                  <td className="small nowrap">{fmtDateTime(e.occurred_at)}</td>
                  <td className="small">{e.operator || "-"}</td>
                  <td className="mono small">{e.source_host || "?"} → {e.target || "?"}</td>
                  <td>
                    {e.tool && <strong className="small">{e.tool}</strong>}
                    {e.command && <div className="mono small cmd">{e.command}</div>}
                    {e.description && <div className="small muted">{e.description}</div>}
                  </td>
                  <td><Badge tone={OUTCOME_TONE[e.outcome]}>{e.outcome}</Badge></td>
                  <td className="right">
                    <ConfirmButton size="sm" variant="ghost" message="Delete this entry? The deletion is recorded in the activity log." onConfirm={() => remove.mutate(e.id)}>
                      Delete
                    </ConfirmButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
