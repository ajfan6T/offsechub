import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../../api";
import { useUser } from "../../auth";
import { Button, Card, Empty, Field, Loading, Modal, useApiMutation } from "../../components/ui";
import { TEST_STATUSES } from "../../lib/format";
import type { Methodology, TestCase, TestStatus } from "../../types";
import { useEngagement, useMembers, useTargets } from "./context";

export function Testing() {
  const { base, canWrite } = useEngagement();
  const user = useUser();
  const navigate = useNavigate();
  const tests = useQuery({ queryKey: [base, "tests"], queryFn: () => api.get<TestCase[]>(`${base}/tests`) });
  const methods = useQuery({ queryKey: ["methodologies"], queryFn: () => api.get<Methodology[]>("/api/methodologies") });
  const members = useMembers(base);
  const targets = useTargets(base);
  const [methodology, setMethodology] = useState("");
  const [applyTarget, setApplyTarget] = useState("");
  const [filter, setFilter] = useState({ status: "", mine: false, methodology: "" });
  const [expanded, setExpanded] = useState<number | null>(null);
  const [adding, setAdding] = useState(false);
  const invalidate = [[base, "tests"], [base, "summary"], ["dashboard"]];

  const apply = useApiMutation(
    () => api.post<TestCase[]>(`${base}/tests/apply`, { methodology_id: methodology, target_id: applyTarget ? Number(applyTarget) : null }),
    { invalidate, success: (r) => `Added ${r.length} test cases` },
  );
  const update = useApiMutation(
    (v: { id: number; patch: Partial<Record<string, unknown>> }) => api.patch<TestCase>(`${base}/tests/${v.id}`, v.patch),
    { invalidate },
  );

  const methodName = (id: string) => methods.data?.find((m) => m.id === id)?.name ?? (id === "custom" ? "Custom checks" : id);
  const targetName = (id: number | null) => (id ? targets.data?.find((t) => t.id === id)?.value : null);
  const rows = (tests.data ?? []).filter(
    (t) =>
      (!filter.status || t.status === filter.status) &&
      (!filter.mine || t.assignee?.id === user.id) &&
      (!filter.methodology || t.methodology === filter.methodology),
  );
  const groups = new Map<string, Map<string, TestCase[]>>();
  for (const t of rows) {
    const key = `${t.methodology}|${t.target_id ?? ""}`;
    if (!groups.has(key)) groups.set(key, new Map());
    const cats = groups.get(key)!;
    if (!cats.has(t.category)) cats.set(t.category, []);
    cats.get(t.category)!.push(t);
  }
  const counts = (tests.data ?? []).reduce<Record<string, number>>((acc, t) => ({ ...acc, [t.status]: (acc[t.status] ?? 0) + 1 }), {});
  const total = tests.data?.length ?? 0;
  const done = total - (counts.not_started ?? 0) - (counts.in_progress ?? 0);

  return (
    <>
      <div className="grid-2-1 align-start">
        <Card title="Coverage">
          {total === 0 ? (
            <p className="muted">Apply a methodology to generate a checklist. Coverage feeds the report so the client sees what was tested, not only what was found.</p>
          ) : (
            <>
              <div className="progress">
                {(["passed", "failed", "not_applicable", "blocked", "in_progress", "not_started"] as TestStatus[]).map((k) =>
                  counts[k] ? <span key={k} className={`progress-seg t-${k}`} style={{ flexGrow: counts[k] }} title={`${TEST_STATUSES[k]}: ${counts[k]}`} /> : null,
                )}
              </div>
              <div className="legend">
                {(Object.keys(TEST_STATUSES) as TestStatus[]).map((k) => (
                  <button key={k} className={`legend-item ${filter.status === k ? "on" : ""}`} onClick={() => setFilter({ ...filter, status: filter.status === k ? "" : k })}>
                    <span className={`dot t-${k}`} /> {TEST_STATUSES[k]} <strong>{counts[k] ?? 0}</strong>
                  </button>
                ))}
              </div>
              <p className="small"><strong>{Math.round((done / total) * 100)}%</strong> complete ({done}/{total})</p>
            </>
          )}
        </Card>
        {canWrite && (
          <Card title="Apply methodology">
            <div className="form-grid single">
              <Field label="Checklist">
                <select value={methodology} onChange={(e) => setMethodology(e.target.value)}>
                  <option value="">Choose...</option>
                  {methods.data?.map((m) => (
                    <option key={m.id} value={m.id}>{m.name} ({m.case_count})</option>
                  ))}
                </select>
              </Field>
              <Field label="For a specific target (optional)" hint="Apply once per web app or host to track each separately">
                <select value={applyTarget} onChange={(e) => setApplyTarget(e.target.value)}>
                  <option value="">Whole engagement</option>
                  {targets.data?.filter((t) => t.scope_status === "in_scope").map((t) => (
                    <option key={t.id} value={t.id}>{t.value}</option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="actions">
              <Button variant="primary" disabled={!methodology} loading={apply.isPending} onClick={() => apply.mutate(undefined)}>Apply</Button>
              <Button onClick={() => setAdding(true)}>Custom check</Button>
            </div>
          </Card>
        )}
      </div>

      <div className="toolbar">
        <select value={filter.methodology} onChange={(e) => setFilter({ ...filter, methodology: e.target.value })}>
          <option value="">All checklists</option>
          {[...new Set(tests.data?.map((t) => t.methodology))].map((m) => <option key={m} value={m}>{methodName(m)}</option>)}
        </select>
        <label className="check">
          <input type="checkbox" checked={filter.mine} onChange={(e) => setFilter({ ...filter, mine: e.target.checked })} /> Assigned to me
        </label>
        {filter.status && <Button size="sm" variant="ghost" onClick={() => setFilter({ ...filter, status: "" })}>Clear status filter</Button>}
      </div>

      {tests.isLoading ? (
        <Loading />
      ) : rows.length === 0 ? (
        <Card><Empty title="No test cases" /></Card>
      ) : (
        [...groups.entries()].map(([key, cats]) => {
          const [m, tid] = key.split("|");
          return (
            <Card key={key} title={<>{methodName(m!)} {tid && <span className="muted mono small">· {targetName(Number(tid))}</span>}</>}>
              {[...cats.entries()].map(([cat, items]) => (
                <div key={cat} className="test-group">
                  <h3>{cat}</h3>
                  <table className="table tests">
                    <colgroup>
                      <col className="c-ref" />
                      <col />
                      <col className="c-status" />
                      <col className="c-who" />
                      <col className="c-act" />
                    </colgroup>
                    <tbody>
                      {items.map((t) => (
                        <TestRow
                          key={t.id}
                          t={t}
                          expanded={expanded === t.id}
                          onToggle={() => setExpanded(expanded === t.id ? null : t.id)}
                          canWrite={canWrite}
                          members={members.data?.map((x) => x.user) ?? []}
                          onPatch={(patch) => update.mutate({ id: t.id, patch })}
                          onRaise={() => navigate(`../findings/new?test=${t.id}&title=${encodeURIComponent(t.title)}${t.target_id ? `&target=${t.target_id}` : ""}`)}
                          onOpenFinding={() => navigate(`../findings/${t.finding_id}`)}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}
            </Card>
          );
        })
      )}
      {adding && <CustomTest onClose={() => setAdding(false)} />}
    </>
  );
}

function TestRow({
  t,
  expanded,
  onToggle,
  canWrite,
  members,
  onPatch,
  onRaise,
  onOpenFinding,
}: {
  t: TestCase;
  expanded: boolean;
  onToggle: () => void;
  canWrite: boolean;
  members: { id: number; full_name: string }[];
  onPatch: (p: Record<string, unknown>) => void;
  onRaise: () => void;
  onOpenFinding: () => void;
}) {
  const [notes, setNotes] = useState(t.notes);
  return (
    <>
      <tr className={`t-row t-row-${t.status}`}>
        <td className="mono small nowrap">{t.ref}</td>
        <td>
          <button className="link strong" onClick={onToggle}>{t.title}</button>
          {t.notes && !expanded && <div className="muted small clamp">{t.notes}</div>}
        </td>
        <td className="nowrap">
          <select value={t.status} disabled={!canWrite} className={`status-select s-${t.status}`} onChange={(e) => onPatch({ status: e.target.value })}>
            {Object.entries(TEST_STATUSES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </td>
        <td className="nowrap">
          <select value={t.assignee?.id ?? ""} disabled={!canWrite} onChange={(e) => onPatch({ assignee_id: e.target.value ? Number(e.target.value) : null })}>
            <option value="">Unassigned</option>
            {members.map((m) => <option key={m.id} value={m.id}>{m.full_name}</option>)}
          </select>
        </td>
        <td className="right nowrap">
          {t.finding_id ? (
            <Button size="sm" variant="ghost" onClick={onOpenFinding}>View finding</Button>
          ) : (
            canWrite && t.status === "failed" && <Button size="sm" onClick={onRaise}>Raise finding</Button>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="t-detail">
          <td />
          <td colSpan={4}>
            {t.description && <p className="muted">{t.description}</p>}
            <textarea rows={3} placeholder="Notes: what you tried, payloads, why it passed..." value={notes} disabled={!canWrite} onChange={(e) => setNotes(e.target.value)} />
            {canWrite && notes !== t.notes && <Button size="sm" variant="primary" onClick={() => onPatch({ notes })}>Save notes</Button>}
          </td>
        </tr>
      )}
    </>
  );
}

function CustomTest({ onClose }: { onClose: () => void }) {
  const { base } = useEngagement();
  const [form, setForm] = useState({ category: "General", title: "", description: "" });
  const add = useApiMutation(() => api.post(`${base}/tests`, { ...form, methodology: "custom" }), {
    invalidate: [[base, "tests"], [base, "summary"]],
    success: "Check added",
    onSuccess: onClose,
  });
  return (
    <Modal
      title="Custom check"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!form.title} loading={add.isPending} onClick={() => add.mutate(undefined)}>Add</Button>
        </>
      }
    >
      <div className="form-grid single">
        <Field label="Category"><input value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} /></Field>
        <Field label="Title"><input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} autoFocus /></Field>
        <Field label="Description"><textarea rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
      </div>
    </Modal>
  );
}
