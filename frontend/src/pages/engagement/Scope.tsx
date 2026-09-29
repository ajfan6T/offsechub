import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../../api";
import {
  Badge,
  Button,
  Card,
  ConfirmButton,
  Empty,
  Field,
  Loading,
  ScopeBadge,
  useApiMutation,
  useToast,
} from "../../components/ui";
import { guessScopeKind, SCOPE_KINDS } from "../../lib/format";
import type { ScopeCheckResult, ScopeItem, ScopeKind } from "../../types";
import { useEngagement } from "./context";

export function Scope() {
  const { base } = useEngagement();
  const q = useQuery({ queryKey: [base, "scope"], queryFn: () => api.get<ScopeItem[]>(`${base}/scope`) });
  const remove = useApiMutation((id: number) => api.del(`${base}/scope/${id}`), {
    invalidate: [[base, "scope"], [base, "targets"], [base, "summary"]],
    success: "Scope rule removed",
  });
  const includes = q.data?.filter((s) => s.rule === "include") ?? [];
  const excludes = q.data?.filter((s) => s.rule === "exclude") ?? [];

  const table = (items: ScopeItem[]) => (
    <table className="table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Value</th>
          <th>Notes</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {items.map((s) => (
          <tr key={s.id}>
            <td className="small">{SCOPE_KINDS[s.kind].label}</td>
            <td className="mono">{s.value}</td>
            <td className="muted">{s.notes}</td>
            <td className="right">
              <ConfirmButton size="sm" variant="ghost" message={`Remove ${s.value} from scope?`} onConfirm={() => remove.mutate(s.id)}>
                Remove
              </ConfirmButton>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <div className="grid-2-1">
      <div className="stack">
        <Card title={<>In scope <Badge tone="green">{includes.length}</Badge></>}>
          {q.isLoading ? <Loading /> : includes.length ? table(includes) : <Empty title="Nothing is in scope yet">Every target will be flagged out of scope until you add include rules.</Empty>}
        </Card>
        <Card title={<>Excluded <Badge tone="red">{excludes.length}</Badge></>}>
          {excludes.length ? table(excludes) : <Empty title="No exclusions">Exclusions always win over inclusions (e.g. a third-party host inside an in-scope range).</Empty>}
        </Card>
      </div>
      <div className="stack">
        <AddScope />
        <ScopeChecker />
        <Card title="How matching works">
          <ul className="small muted tight">
            <li><strong>CIDR / range / IP</strong> match addresses, including IPs inside URLs.</li>
            <li><strong>Wildcard</strong> *.example.com matches subdomains only, not example.com itself.</li>
            <li><strong>URL prefix</strong> matches on a path boundary: /api covers /api/v1 but not /apix.</li>
            <li>Imports skip excluded hosts always, and out-of-scope hosts by default.</li>
          </ul>
        </Card>
      </div>
    </div>
  );
}

function AddScope() {
  const { base } = useEngagement();
  const toast = useToast();
  const [kind, setKind] = useState<ScopeKind>("cidr");
  const [value, setValue] = useState("");
  const [rule, setRule] = useState<"include" | "exclude">("include");
  const [notes, setNotes] = useState("");
  const [bulk, setBulk] = useState("");
  const invalidate = [[base, "scope"], [base, "targets"], [base, "summary"]];

  const add = useApiMutation(() => api.post(`${base}/scope`, { kind, value, rule, notes }), {
    invalidate,
    success: "Scope rule added",
    onSuccess: () => {
      setValue("");
      setNotes("");
    },
  });
  const addBulk = useApiMutation(
    async () => {
      const lines = bulk.split("\n").map((l) => l.trim()).filter(Boolean);
      const failures: { line: string; error: string }[] = [];
      for (const line of lines) {
        try {
          await api.post(`${base}/scope`, { kind: guessScopeKind(line), value: line, rule });
        } catch (e) {
          failures.push({ line, error: (e as Error).message });
        }
      }
      return { added: lines.length - failures.length, failures };
    },
    {
      invalidate,
      onSuccess: (r) => {
        toast("success", `Added ${r.added} scope rule(s)`);
        if (r.failures.length) toast("error", r.failures.map((f) => `${f.line}: ${f.error}`).join("\n"));
        // Leave only the failed lines in the box so they can be fixed and retried.
        setBulk(r.failures.map((f) => f.line).join("\n"));
      },
    },
  );

  return (
    <Card title="Add scope">
      <div className="seg seg-block">
        <button className={rule === "include" ? "on" : ""} onClick={() => setRule("include")}>Include</button>
        <button className={rule === "exclude" ? "on danger" : ""} onClick={() => setRule("exclude")}>Exclude</button>
      </div>
      <div className="form-grid single">
        <Field label="Type">
          <select value={kind} onChange={(e) => setKind(e.target.value as ScopeKind)}>
            {Object.entries(SCOPE_KINDS).map(([k, v]) => (
              <option key={k} value={k}>{v.label}</option>
            ))}
          </select>
        </Field>
        <Field label="Value">
          <input className="mono" placeholder={SCOPE_KINDS[kind].example} value={value} onChange={(e) => setValue(e.target.value)} />
        </Field>
        <Field label="Notes">
          <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="e.g. production, client-owned" />
        </Field>
      </div>
      <Button variant="primary" disabled={!value} loading={add.isPending} onClick={() => add.mutate(undefined)}>
        Add {rule}
      </Button>
      <hr />
      <Field label={`Bulk ${rule} (one per line, type auto-detected)`}>
        <textarea rows={4} className="mono" value={bulk} onChange={(e) => setBulk(e.target.value)} placeholder={"203.0.113.0/24\n*.example.com\nhttps://app.example.com/"} />
      </Field>
      <Button disabled={!bulk.trim()} loading={addBulk.isPending} onClick={() => addBulk.mutate(undefined)}>
        Add all
      </Button>
    </Card>
  );
}

function ScopeChecker() {
  const { base } = useEngagement();
  const [values, setValues] = useState("");
  const [results, setResults] = useState<ScopeCheckResult[] | null>(null);
  const check = useApiMutation(
    () => api.post<ScopeCheckResult[]>(`${base}/scope/check`, { values: values.split("\n").map((v) => v.trim()).filter(Boolean) }),
    { onSuccess: setResults },
  );
  return (
    <Card title="Scope check">
      <p className="muted small">Before you touch it, check it. Paste hosts, IPs or URLs.</p>
      <textarea rows={3} className="mono" value={values} onChange={(e) => setValues(e.target.value)} placeholder={"10.0.0.5\nportal.example.com"} />
      <Button disabled={!values.trim()} loading={check.isPending} onClick={() => check.mutate(undefined)}>
        Check
      </Button>
      {results && (
        <table className="table scope-results">
          <tbody>
            {results.map((r) => (
              <tr key={r.value}>
                <td>
                  <span className="mono">{r.value}</span>
                  <span className="muted small reason">{r.reason}</span>
                </td>
                <td className="right"><ScopeBadge status={r.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
