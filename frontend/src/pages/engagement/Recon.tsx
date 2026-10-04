import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api } from "../../api";
import { Button, Card, CopyButton, DownloadLink, Empty, Field, Loading, useApiMutation } from "../../components/ui";
import { fmtDateTime } from "../../lib/format";
import type { ReconImport } from "../../types";
import { useEngagement } from "./context";

const TOOLS = {
  nmap: { label: "Nmap XML", accept: ".xml", hint: "nmap -sV -O -oX scan.xml <range>", sample: "scan.xml" },
  nuclei: { label: "nuclei JSONL / JSON", accept: ".json,.jsonl,.txt", hint: "nuclei -l hosts.txt -jsonl -o nuclei.jsonl", sample: "nuclei.jsonl" },
  list: { label: "Host / URL list", accept: ".txt,.lst,.csv", hint: "subfinder -d example.com -o hosts.txt · httpx -l hosts.txt -o live.txt", sample: "hosts.txt" },
} as const;
type Tool = keyof typeof TOOLS;

/** Quote a value for a POSIX shell unless it is plainly safe. */
const shellArg = (s: string) => (/^[\w.@%+=:,/-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

export function Recon() {
  const { base, engagement } = useEngagement();
  const q = useQuery({ queryKey: [base, "imports"], queryFn: () => api.get<ReconImport[]>(`${base}/imports`) });
  const [tool, setTool] = useState<Tool>("nmap");
  const [skip, setSkip] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [last, setLast] = useState<ReconImport | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const cli = `offsechub import ${shellArg(engagement.code)} ${TOOLS[tool].sample} --tool ${tool}`;

  const upload = useApiMutation(
    () => api.upload<ReconImport>(`${base}/imports/upload`, file!, { tool, skip_out_of_scope: skip }),
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
        <Card title="From the terminal" actions={<CopyButton text={cli} />}>
          <p className="muted small">
            While OffsecHub is running and this vault is unlocked, import straight from a shell on the same machine:
          </p>
          <pre className="code">{cli}</pre>
          <p className="muted small">
            nuclei results become <strong>draft findings</strong> grouped by template, one finding with every affected
            host. Triage them in Findings. Raw files are kept as evidence with a SHA-256.
          </p>
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
              <tr><th>When</th><th>Tool</th><th>File</th><th>Result</th></tr>
            </thead>
            <tbody>
              {q.data.map((r) => (
                <tr key={r.id}>
                  <td className="small">{fmtDateTime(r.created_at)}</td>
                  <td>{r.tool}</td>
                  <td className="mono small">
                    {r.evidence_id ? (
                      <DownloadLink href={`${base}/evidence/${r.evidence_id}/download`} filename={r.filename}>{r.filename}</DownloadLink>
                    ) : (
                      r.filename
                    )}
                  </td>
                  <td className="small"><StatsLine rec={r} /></td>
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
      {s.errors.length > 0 && <span className="error-text">, {s.errors.length} {s.errors.length === 1 ? "error" : "errors"}</span>}
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
