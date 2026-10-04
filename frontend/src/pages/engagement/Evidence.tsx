import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api";
import { Button, Card, ConfirmButton, CopyButton, DownloadLink, Empty, Field, Lightbox, Loading, useApiMutation } from "../../components/ui";
import { fmtBytes, fmtDateTime } from "../../lib/format";
import type { Evidence } from "../../types";
import { evidenceImages, evidenceUrl, uploadEvidence, useEngagement, useFindings, useTargets } from "./context";

export function EvidencePage() {
  const { base } = useEngagement();
  const q = useQuery({ queryKey: [base, "evidence"], queryFn: () => api.get<Evidence[]>(`${base}/evidence`) });
  const findings = useFindings(base);
  const targets = useTargets(base);
  const input = useRef<HTMLInputElement>(null);
  const [meta, setMeta] = useState({ description: "", finding_id: "", target_id: "" });
  const [text, setText] = useState({ filename: "", content: "" });
  const [filter, setFilter] = useState<"all" | "unlinked" | "images">("all");
  const [preview, setPreview] = useState<number | null>(null);
  const invalidate = [[base, "evidence"], [base, "findings"], [base, "summary"]];

  const upload = useApiMutation((files: FileList) => uploadEvidence(base, files, meta), {
    invalidate,
    success: (n) => `Uploaded ${n} file(s)`,
    onSuccess: () => input.current && (input.current.value = ""),
  });
  const paste = useApiMutation(
    () =>
      api.post(`${base}/evidence/text`, {
        filename: text.filename || "evidence.txt",
        content: text.content,
        description: meta.description,
        finding_id: meta.finding_id ? Number(meta.finding_id) : null,
        target_id: meta.target_id ? Number(meta.target_id) : null,
      }),
    { invalidate, success: "Text evidence saved", onSuccess: () => setText({ filename: "", content: "" }) },
  );
  const relink = useApiMutation(
    (v: { id: number; finding_id: number | null }) => api.patch(`${base}/evidence/${v.id}`, { finding_id: v.finding_id }),
    { invalidate },
  );
  const remove = useApiMutation((id: number) => api.del(`${base}/evidence/${id}`), { invalidate, success: "Evidence deleted" });

  const rows = (q.data ?? []).filter((e) => (filter === "unlinked" ? !e.finding_id : filter === "images" ? e.is_image : true));
  const images = rows.filter((e) => e.is_image);
  const targetName = (id: number | null) => targets.data?.find((t) => t.id === id)?.value;

  return (
    <div className="grid-1-2">
      <div className="stack">
        <Card title="Add evidence">
          <div className="form-grid single">
            <Field label="Link to finding (optional)">
              <select value={meta.finding_id} onChange={(e) => setMeta({ ...meta, finding_id: e.target.value })}>
                <option value="">None</option>
                {findings.data?.map((f) => <option key={f.id} value={f.id}>{f.ref} {f.title}</option>)}
              </select>
            </Field>
            <Field label="Link to target (optional)">
              <select value={meta.target_id} onChange={(e) => setMeta({ ...meta, target_id: e.target.value })}>
                <option value="">None</option>
                {targets.data?.map((t) => <option key={t.id} value={t.id}>{t.value}</option>)}
              </select>
            </Field>
            <Field label="Description">
              <input value={meta.description} onChange={(e) => setMeta({ ...meta, description: e.target.value })} placeholder="What does this prove?" />
            </Field>
          </div>
          <input ref={input} type="file" multiple hidden onChange={(e) => e.target.files?.length && upload.mutate(e.target.files)} />
          <Button variant="primary" loading={upload.isPending} onClick={() => input.current?.click()}>Upload files</Button>
          <hr />
          <Field label="Or paste text (HTTP request/response, shell output)">
            <input placeholder="file name, e.g. sqli-request.txt" value={text.filename} onChange={(e) => setText({ ...text, filename: e.target.value })} />
          </Field>
          <textarea rows={6} className="mono" value={text.content} onChange={(e) => setText({ ...text, content: e.target.value })} />
          <Button disabled={!text.content} loading={paste.isPending} onClick={() => paste.mutate(undefined)}>Save text evidence</Button>
        </Card>
        <p className="muted small">
          Each file is encrypted into the vault as it streams in, and its SHA-256 is recorded so you and your client can
          check that a file is the one the report cites. Images render inline in the report; everything else is listed
          with its hash. Active content (HTML, SVG) is only ever served as a download.
        </p>
      </div>
      <Card
        title={`Evidence locker (${q.data?.length ?? 0})`}
        actions={
          <div className="seg">
            {([["all", "All"], ["unlinked", "Unlinked"], ["images", "Images"]] as const).map(([f, label]) => (
              <button key={f} className={filter === f ? "on" : ""} onClick={() => setFilter(f)}>{label}</button>
            ))}
          </div>
        }
      >
        {q.isLoading ? (
          <Loading />
        ) : rows.length === 0 ? (
          <Empty title="No evidence" />
        ) : (
          <div className="evidence-grid">
            {rows.map((e) => (
              <div key={e.id} className="evidence-card">
                {e.is_image ? (
                  <button type="button" className="thumb" onClick={() => setPreview(images.indexOf(e))} title="Preview">
                    <img src={evidenceUrl(base, e, true)} alt={e.filename} loading="lazy" />
                  </button>
                ) : (
                  <div className="thumb file-icon">{e.filename.split(".").pop()?.toUpperCase().slice(0, 5)}</div>
                )}
                <div className="evidence-meta">
                  <DownloadLink className="strong small" href={evidenceUrl(base, e)} filename={e.filename}>{e.filename}</DownloadLink>
                  {e.description && <div className="small">{e.description}</div>}
                  <div className="muted small">
                    {fmtBytes(e.size)} · {fmtDateTime(e.created_at)}
                  </div>
                  <div className="hash">
                    <span className="mono small" title={e.sha256}>sha256 {e.sha256.slice(0, 16)}…</span>
                    <CopyButton text={e.sha256} label="Copy hash" />
                  </div>
                  {e.target_id && <div className="small muted">Target: <span className="mono">{targetName(e.target_id)}</span></div>}
                  <select value={e.finding_id ?? ""} onChange={(ev) => relink.mutate({ id: e.id, finding_id: ev.target.value ? Number(ev.target.value) : null })}>
                    <option value="">Not linked to a finding</option>
                    {findings.data?.map((f) => <option key={f.id} value={f.id}>{f.ref} {f.title}</option>)}
                  </select>
                  <div className="actions">
                    {e.finding_id && <Link to={`../findings/${e.finding_id}`} className="small">View finding</Link>}
                    <ConfirmButton size="sm" variant="ghost" message={`Delete ${e.filename}? This is recorded in the activity log.`} onConfirm={() => remove.mutate(e.id)}>
                      Delete
                    </ConfirmButton>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
      {preview !== null && <Lightbox images={evidenceImages(base, images)} start={preview} onClose={() => setPreview(null)} />}
    </div>
  );
}
