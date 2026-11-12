import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { api } from "../../api";
import { CvssBuilder, useCvssScore } from "../../components/CvssBuilder";
import { RichField, RichText } from "../../components/RichText";
import {
  Button,
  Card,
  ConfirmButton,
  DownloadLink,
  Badge,
  Field,
  Lightbox,
  Loading,
  ScopeBadge,
  SeverityBadge,
  useApiMutation,
} from "../../components/ui";
import { FINDING_STATUSES, fmtBytes, fmtDate, fmtDateTime, RETEST_RESULTS, SEVERITIES, titleCase } from "../../lib/format";
import type { Evidence, Finding, FindingStatus, Retest, RetestResult, Severity } from "../../types";
import { evidenceImages, evidenceUrl, uploadEvidence, useEngagement, useTargets } from "./context";

export function FindingEditor() {
  const { findingId } = useParams();
  const { base } = useEngagement();
  const q = useQuery({
    queryKey: [base, "finding", findingId],
    queryFn: () => api.get<Finding>(`${base}/findings/${findingId}`),
    enabled: !!findingId,
  });
  if (findingId && q.isLoading) return <Loading />;
  return <Editor key={q.data?.updated_at ?? "new"} finding={q.data ?? null} />;
}

function Editor({ finding }: { finding: Finding | null }) {
  const { base, engagement } = useEngagement();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const targets = useTargets(base);
  const [form, setForm] = useState({
    title: finding?.title ?? params.get("title") ?? "",
    status: (finding?.status ?? "draft") as FindingStatus,
    severity: (finding?.severity ?? "medium") as Severity,
    cvss_vector: finding?.cvss_vector ?? "",
    cwe: finding?.cwe ?? "",
    description: finding?.description ?? "",
    impact: finding?.impact ?? "",
    steps_to_reproduce: finding?.steps_to_reproduce ?? "",
    remediation: finding?.remediation ?? "",
    references: finding?.references ?? "",
  });
  const [severityTouched, setSeverityTouched] = useState(false);
  const [targetIds, setTargetIds] = useState<number[]>(
    finding?.targets.map((t) => t.id) ?? (params.get("target") ? [Number(params.get("target"))] : []),
  );
  const [targetSearch, setTargetSearch] = useState("");
  const score = useCvssScore(form.cvss_vector);
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const setText = (k: keyof typeof form) => (value: string) => setForm((f) => ({ ...f, [k]: value }));

  // Severity follows the CVSS score until someone overrides it by hand.
  const effectiveSeverity: Severity = !severityTouched && form.cvss_vector && score.data ? score.data.severity : form.severity;
  const invalidate = [[base, "findings"], [base, "summary"], [base], ["dashboard"], [base, "tests"]];

  const save = useApiMutation(
    async () => {
      const body: Record<string, unknown> = { ...form, target_ids: targetIds };
      if (!severityTouched && form.cvss_vector) delete body.severity;
      if (finding) {
        if (form.cvss_vector === finding.cvss_vector) delete body.cvss_vector;
        if (!severityTouched) delete body.severity;
        return api.patch<Finding>(`${base}/findings/${finding.id}`, body);
      }
      const created = await api.post<Finding>(`${base}/findings`, body);
      const testId = params.get("test");
      if (testId) await api.patch(`${base}/tests/${testId}`, { finding_id: created.id });
      return created;
    },
    {
      invalidate,
      success: (f) => `Saved ${f.ref}`,
      onSuccess: (f) => {
        if (!finding) navigate(`../findings/${f.id}`, { replace: true });
      },
    },
  );
  const remove = useApiMutation(() => api.del(`${base}/findings/${finding!.id}`), {
    invalidate,
    success: "Finding deleted",
    onSuccess: () => navigate("../findings"),
  });
  const toTemplate = useApiMutation(() => api.post(`${base}/findings/${finding!.id}/save-as-template`), {
    invalidate: [["finding-templates"]],
    success: "Saved to the finding library",
  });

  const shownTargets = (targets.data ?? []).filter(
    (t) => targetIds.includes(t.id) || t.value.toLowerCase().includes(targetSearch.toLowerCase()),
  );

  return (
    <>
      <div className="editor-head">
        <Link to="../findings" className="muted">← Findings</Link>
        <h2>
          {finding ? <span className="mono muted">{finding.ref}</span> : "New finding"} <SeverityBadge severity={effectiveSeverity} score={form.cvss_vector ? score.data?.score : null} />
        </h2>
        <div className="actions">
          {finding && <Button onClick={() => toTemplate.mutate(undefined)} loading={toTemplate.isPending}>Save to library</Button>}
          <Button variant="primary" disabled={!form.title} loading={save.isPending} onClick={() => save.mutate(undefined)}>
            {finding ? "Save changes" : "Create finding"}
          </Button>
        </div>
      </div>
      <div className="grid-2-1 align-start">
        <Card>
          <div className="form-grid">
            <Field label="Title" wide>
              <input className="input-lg" value={form.title} onChange={set("title")} autoFocus={!finding} placeholder="e.g. Stored XSS in support ticket subject" />
            </Field>
            <Field label="Status">
              <select value={form.status} onChange={set("status")}>
                {Object.entries(FINDING_STATUSES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </Field>
            <Field label="Severity" hint={!severityTouched && form.cvss_vector ? "Derived from CVSS" : "Set manually"}>
              <select
                value={effectiveSeverity}
                onChange={(e) => {
                  setSeverityTouched(true);
                  setForm({ ...form, severity: e.target.value as Severity });
                }}
              >
                {SEVERITIES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
              </select>
            </Field>
            <Field label="CVSS base score" wide hint="CVSS v3.1 or v4.0">
              <CvssBuilder value={form.cvss_vector} onChange={(v) => setForm((f) => ({ ...f, cvss_vector: v }))} />
            </Field>
            <Field label="CWE">
              <input className="mono" value={form.cwe} onChange={set("cwe")} placeholder="CWE-79" />
            </Field>
            <RichField label="Description" hint="What is wrong and where" rows={6} value={form.description} onChange={setText("description")} />
            <RichField label="Impact" hint="What an attacker can achieve, in business terms" value={form.impact} onChange={setText("impact")} />
            <RichField label="Steps to reproduce" hint="Unformatted text is kept as a code block" rows={6} mono value={form.steps_to_reproduce} onChange={setText("steps_to_reproduce")} />
            <RichField label="Remediation" value={form.remediation} onChange={setText("remediation")} />
            <Field label="References" wide hint="One per line">
              <textarea rows={3} className="mono" value={form.references} onChange={set("references")} />
            </Field>
          </div>
        </Card>
        <div className="stack">
          <Card title={`Affected assets (${targetIds.length})`}>
            <input placeholder="Filter targets" value={targetSearch} onChange={(e) => setTargetSearch(e.target.value)} />
            <div className="checklist">
              {shownTargets.length === 0 && <p className="muted small">No targets yet. Add them in the Targets tab.</p>}
              {shownTargets.map((t) => (
                <label key={t.id} className="check">
                  <input
                    type="checkbox"
                    checked={targetIds.includes(t.id)}
                    onChange={(e) => setTargetIds(e.target.checked ? [...targetIds, t.id] : targetIds.filter((x) => x !== t.id))}
                  />
                  <span className="mono small">{t.value}</span>
                  {t.scope_status !== "in_scope" && <ScopeBadge status={t.scope_status} />}
                </label>
              ))}
            </div>
          </Card>
          {finding ? <EvidencePanel finding={finding} /> : <Card title="Evidence"><p className="muted small">Create the finding first, then attach screenshots and request/response pairs.</p></Card>}
          {finding && <RetestPanel finding={finding} />}
          {finding && (
            <Card title="Record">
              <dl className="dl small">
                <dt>Source</dt><dd>{finding.source}</dd>
                <dt>Created</dt><dd>{fmtDateTime(finding.created_at)}</dd>
                <dt>Updated</dt><dd>{fmtDateTime(finding.updated_at)}</dd>
              </dl>
              <ConfirmButton variant="danger" size="sm" message={`Delete ${finding.ref}? Linked evidence is kept but unlinked.`} onConfirm={() => remove.mutate(undefined)}>
                Delete finding
              </ConfirmButton>
            </Card>
          )}
          <p className="muted small">Findings in Draft or False positive status are left out of the {engagement.code} report.</p>
        </div>
      </div>
    </>
  );
}

function EvidencePanel({ finding }: { finding: Finding }) {
  const { base } = useEngagement();
  const key = [base, "evidence", { finding: finding.id }];
  const q = useQuery({ queryKey: key, queryFn: () => api.get<Evidence[]>(`${base}/evidence?finding_id=${finding.id}`) });
  const input = useRef<HTMLInputElement>(null);
  const [pasting, setPasting] = useState(false);
  const [preview, setPreview] = useState<number | null>(null);
  const [text, setText] = useState({ filename: "request-response.txt", content: "", description: "" });
  const invalidate = [key, [base, "evidence"], [base, "findings"], [base, "finding", String(finding.id)]];

  const upload = useApiMutation((files: FileList) => uploadEvidence(base, files, { finding_id: finding.id }), {
    invalidate,
    success: "Evidence uploaded",
    onSuccess: () => input.current && (input.current.value = ""),
  });
  const paste = useApiMutation(() => api.post(`${base}/evidence/text`, { ...text, finding_id: finding.id }), {
    invalidate,
    success: "Evidence saved",
    onSuccess: () => {
      setPasting(false);
      setText({ filename: "request-response.txt", content: "", description: "" });
    },
  });
  const unlink = useApiMutation((id: number) => api.patch(`${base}/evidence/${id}`, { finding_id: null }), { invalidate });
  const images = (q.data ?? []).filter((e) => e.is_image);

  return (
    <Card title={`Evidence (${q.data?.length ?? 0})`}>
      <div className="evidence-list">
        {q.data?.map((e) => (
          <div key={e.id} className="evidence-item">
            {e.is_image ? (
              <button type="button" className="thumb-btn" onClick={() => setPreview(images.indexOf(e))} title="Preview">
                <img src={evidenceUrl(base, e, true)} alt={e.filename} />
              </button>
            ) : (
              <div className="file-icon">{e.filename.split(".").pop()?.toUpperCase().slice(0, 4)}</div>
            )}
            <div className="evidence-meta">
              <DownloadLink href={evidenceUrl(base, e)} filename={e.filename} className="strong small">{e.filename}</DownloadLink>
              <div className="muted small">{fmtBytes(e.size)} · <span className="mono" title={e.sha256}>{e.sha256.slice(0, 12)}</span></div>
              {e.description && <div className="small">{e.description}</div>}
            </div>
            <button className="link small" onClick={() => unlink.mutate(e.id)}>Unlink</button>
          </div>
        ))}
      </div>
      <div className="actions">
        <input ref={input} type="file" multiple hidden onChange={(e) => e.target.files?.length && upload.mutate(e.target.files)} />
        <Button size="sm" loading={upload.isPending} onClick={() => input.current?.click()}>Upload files</Button>
        <Button size="sm" variant="ghost" onClick={() => setPasting(!pasting)}>Paste text</Button>
      </div>
      {pasting && (
        <div className="form-grid single">
          <Field label="File name"><input value={text.filename} onChange={(e) => setText({ ...text, filename: e.target.value })} /></Field>
          <Field label="Content"><textarea rows={6} className="mono" value={text.content} onChange={(e) => setText({ ...text, content: e.target.value })} placeholder="Paste HTTP request/response, tool output..." /></Field>
          <Field label="Description"><input value={text.description} onChange={(e) => setText({ ...text, description: e.target.value })} /></Field>
          <Button size="sm" variant="primary" disabled={!text.content} loading={paste.isPending} onClick={() => paste.mutate(undefined)}>Save evidence</Button>
        </div>
      )}
      {preview !== null && <Lightbox images={evidenceImages(base, images)} start={preview} onClose={() => setPreview(null)} />}
    </Card>
  );
}

const RETEST_TONES: Record<RetestResult, string> = { resolved: "green", partially_resolved: "amber", not_resolved: "red" };

export function RetestBadge({ result }: { result: RetestResult }) {
  return <Badge tone={RETEST_TONES[result]}>{RETEST_RESULTS[result]}</Badge>;
}

function RetestPanel({ finding }: { finding: Finding }) {
  const { base } = useEngagement();
  const today = new Date().toISOString().slice(0, 10);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ tested_on: today, result: "resolved" as RetestResult, notes: "" });
  // The status follows the latest retest (by date; on the same date, the newest entry).
  const lastDate = finding.retests.length ? finding.retests[finding.retests.length - 1].tested_on : "";
  const latest = form.tested_on >= lastDate;
  const invalidate = [[base, "findings"], [base, "finding", String(finding.id)], [base, "summary"], [base]];
  const add = useApiMutation(() => api.post<Retest>(`${base}/findings/${finding.id}/retests`, form), {
    invalidate,
    success: (r) => `Retest recorded: ${RETEST_RESULTS[r.result].toLowerCase()}`,
    onSuccess: () => {
      setAdding(false);
      setForm({ tested_on: today, result: "resolved", notes: "" });
    },
  });
  const remove = useApiMutation((id: number) => api.del(`${base}/findings/${finding.id}/retests/${id}`), {
    invalidate,
    success: "Retest removed",
  });

  return (
    <Card title={`Retests (${finding.retests.length})`}>
      {finding.retests.length === 0 && !adding && <p className="muted small">Not retested yet. Record each retest after the client ships a fix.</p>}
      <div className="retests">
        {finding.retests.map((r) => (
          <div key={r.id} className="retest">
            <div className="retest-head">
              <RetestBadge result={r.result} />
              <span className="small">{fmtDate(r.tested_on)}</span>
              {r.tester && <span className="muted small">{r.tester}</span>}
              <ConfirmButton variant="ghost" size="sm" message="Remove this retest?" onConfirm={() => remove.mutate(r.id)}>Remove</ConfirmButton>
            </div>
            {r.notes && <RichText text={r.notes} />}
          </div>
        ))}
      </div>
      {adding ? (
        <div className="form-grid single">
          <Field label="Tested on"><input type="date" value={form.tested_on} max={today} onChange={(e) => setForm({ ...form, tested_on: e.target.value })} /></Field>
          <Field label="Result">
            <select value={form.result} onChange={(e) => setForm({ ...form, result: e.target.value as RetestResult })}>
              {Object.entries(RETEST_RESULTS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>
          <RichField label="Notes" rows={3} value={form.notes} onChange={(notes) => setForm({ ...form, notes })} placeholder="What you checked and what you saw" />
          {latest && form.result === "resolved" && (finding.status === "confirmed" || finding.status === "reported") && (
            <p className="muted small">The finding will be marked remediated.</p>
          )}
          {latest && form.result !== "resolved" && finding.status === "remediated" && (
            <p className="muted small">The finding will be reopened as reported.</p>
          )}
          {!latest && <p className="muted small">An earlier retest than the latest one: the status won't change.</p>}
          <div className="actions">
            <Button size="sm" variant="primary" disabled={!form.tested_on} loading={add.isPending} onClick={() => add.mutate(undefined)}>Record retest</Button>
            <Button size="sm" variant="ghost" onClick={() => setAdding(false)}>Cancel</Button>
          </div>
        </div>
      ) : (
        <div className="actions"><Button size="sm" onClick={() => setAdding(true)}>Record a retest</Button></div>
      )}
    </Card>
  );
}
