import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api } from "../../api";
import { Button, Card, Empty, Field, Loading, useApiMutation } from "../../components/ui";
import { fmtDateTime } from "../../lib/format";
import type { ReconImport } from "../../types";
import { useEngagement } from "./context";

const TOOLS = {
  nmap: { label: "Nmap XML", accept: ".xml", hint: "nmap -sV -O -oX scan.xml <range>" },
  nuclei: { label: "nuclei JSONL / JSON", accept: ".json,.jsonl,.txt", hint: "nuclei -l hosts.txt -jsonl -o nuclei.jsonl" },
  list: { label: "Host / URL list", accept: ".txt,.lst,.csv", hint: "subfinder -d example.com -o hosts.txt · httpx -l hosts.txt -o live.txt" },
} as const;
type Tool = keyof typeof TOOLS;

export function Recon() {
  const { base, canWrite, engagement } = useEngagement();
  const q = useQuery({ queryKey: [base, "imports"], queryFn: () => api.get<ReconImport[]>(`${base}/imports`) });
  const [tool, setTool] = useState<Tool>("nmap");
  const [skip, setSkip] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [last, setLast] = useState<ReconImport | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const upload = useApiMutation(
    () => {
      const fd = new FormData();
      fd.append("tool", tool);
      fd.append("skip_out_of_scope", String(skip));
      fd.append("file", file!);
      return api.post<ReconImport>(`${base}/imports`, fd);
    },
    {
      invalidate: [[base, "imports"], [base, "targets"], [base, "findings"], [base, "summary"], [base, "evidence"]],
      success: "Import complete",
      onSuccess: (r) => {
        setLast(r);
        setFile(null);
        if (input.current) input.current.value = "";
      },
    },
  );

  return (
    <div className="grid-1-2">
      <div className="stack">
        {canWrite && (
          <Card title="Import tool output">
            <div className="form-grid single">
              <Field label="Tool">
                <select value={tool} onChange={(e) => setTool(e.target.value as Tool)}>
                  {Object.entries(TOOLS).map(([k, v]) => (
                    <option key={k} value={k}>{v.label}</option>
                  ))}
                </select>
              </Field>
              <Field label="File" hint={<code className="mono">{TOOLS[tool].hint}</code>}>
                <input ref={input} type="file" accept={TOOLS[tool].accept} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              </Field>
              <label className="check">
                <input type="checkbox" checked={skip} onChange={(e) => setSkip(e.target.checked)} />
                Skip hosts outside scope (excluded hosts are always skipped)
              </label>
            </div>
            <Button variant="primary" disabled={!file} loading={upload.isPending} onClick={() => upload.mutate(undefined)}>
              Import
            </Button>
            {last && <ImportStats rec={last} />}
          </Card>
        )}
        <Card title="Automate it">
          <p className="muted small">Create an API token in Settings, then push results from your attack box:</p>
          <pre className="code">{`curl -H "Authorization: Bearer $OFFSECHUB_TOKEN" \\
  -F tool=nmap -F file=@scan.xml \\
  ${window.location.origin}${base}/imports`}</pre>
          <p className="muted small">
            nuclei results become <strong>draft findings</strong> grouped by template, one finding with every affected
            host. Triage them in Findings. Raw files are kept as evidence with a SHA-256.
          </p>
          <p className="muted small">Engagement ID: <span className="mono">{engagement.id}</span></p>
        </Card>
      </div>
      <Card title="Import history">
        {q.isLoading ? (
          <Loading />
        ) : !q.data?.length ? (
          <Empty title="Nothing imported yet" />
        ) : (
          <table className="table">
            <thead>
              <tr><th>When</th><th>Tool</th><th>File</th><th>Result</th><th>By</th></tr>
            </thead>
            <tbody>
              {q.data.map((r) => (
                <tr key={r.id}>
                  <td className="small">{fmtDateTime(r.created_at)}</td>
                  <td>{r.tool}</td>
                  <td className="mono small">
                    {r.evidence_id ? (
                      <a href={`${base}/evidence/${r.evidence_id}/download`}>{r.filename}</a>
                    ) : (
                      r.filename
                    )}
                  </td>
                  <td className="small"><StatsLine rec={r} /></td>
                  <td className="small">{r.created_by?.full_name ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

function StatsLine({ rec }: { rec: ReconImport }) {
  const s = rec.stats;
  const skipped = s.skipped_out_of_scope + s.skipped_excluded;
  return (
    <>
      +{s.targets_created} targets, +{s.services_created} services
      {rec.tool === "nuclei" && <>, +{s.findings_created} findings</>}
      {skipped > 0 && <span className="warn-text">, {skipped} skipped (scope)</span>}
      {s.errors.length > 0 && <span className="error-text">, {s.errors.length} errors</span>}
    </>
  );
}

function ImportStats({ rec }: { rec: ReconImport }) {
  const s = rec.stats;
  return (
    <div className="import-result">
      <div className="stats compact">
        <div><strong>{s.hosts_seen}</strong><span>hosts seen</span></div>
        <div><strong>{s.targets_created}</strong><span>new targets</span></div>
        <div><strong>{s.services_created}</strong><span>new services</span></div>
        <div><strong>{s.findings_created}</strong><span>new findings</span></div>
        <div className={s.skipped_excluded ? "warn-text" : ""}><strong>{s.skipped_excluded}</strong><span>excluded</span></div>
        <div className={s.skipped_out_of_scope ? "warn-text" : ""}><strong>{s.skipped_out_of_scope}</strong><span>out of scope</span></div>
      </div>
      {s.errors.length > 0 && (
        <ul className="error-text small">{s.errors.map((e) => <li key={e}>{e}</li>)}</ul>
      )}
    </div>
  );
}
