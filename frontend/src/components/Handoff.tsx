import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../api";
import { joinPath, useDesktopBridge } from "../lib/desktop";
import { fmtBytes } from "../lib/format";
import { PathField } from "../vault/common";
import { useAppInfo } from "../vault/context";
import { Button, CopyButton, Field, Modal, useApiMutation } from "./ui";

const ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"; // no 0/O, 1/I/L, U

/** 6 groups of 4 from a 30-symbol alphabet: about 118 bits, easy to read out. */
export function newPassphrase(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(48));
  const chars = [...bytes].filter((b) => b < 240).map((b) => ALPHABET[b % 30]);
  while (chars.length < 24) chars.push(ALPHABET[crypto.getRandomValues(new Uint8Array(1))[0]! % 30]!);
  return Array.from({ length: 6 }, (_, i) => chars.slice(i * 4, i * 4 + 4).join("")).join("-");
}

interface ExportResult {
  path: string;
  bytes: number;
  findings: number;
  evidence_files: number;
}

export function HandoffExportButton({ base, code }: { base: string; code: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" onClick={() => setOpen(true)}>Hand off</Button>
      {open && <HandoffExport base={base} code={code} onClose={() => setOpen(false)} />}
    </>
  );
}

function HandoffExport({ base, code, onClose }: { base: string; code: string; onClose: () => void }) {
  const info = useAppInfo();
  const bridge = useDesktopBridge();
  const [folder, setFolder] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState(newPassphrase);
  const dir = folder ?? info.data?.default_vault_dir ?? "";
  const run = useApiMutation(() => api.post<ExportResult>(`${base}/handoff`, { directory: dir, passphrase }), {
    success: (r) => `Hand-off file written to ${r.path}`,
  });
  return (
    <Modal title={`Hand off ${code}`} onClose={onClose}>
      {run.data ? (
        <div className="stack">
          <p>
            Written to <span className="mono">{run.data.path}</span> ({fmtBytes(run.data.bytes)}, {run.data.findings} finding(s),{" "}
            {run.data.evidence_files} evidence file(s)).
          </p>
          <p className="small">Send the file, and send the passphrase another way (a call, a different messenger). Anyone with both can read the engagement.</p>
          <div className="passphrase"><span className="mono">{passphrase}</span> <CopyButton text={passphrase} label="Copy passphrase" /></div>
          <div className="actions"><Button variant="primary" onClick={onClose}>Done</Button></div>
        </div>
      ) : (
        <div className="form-grid single">
          <p className="muted small">
            Writes this engagement, with its evidence, to one encrypted file another OffsecHub vault can import. It is encrypted
            with AES-256-GCM under a key derived from the passphrase (Argon2id). This vault is not changed.
          </p>
          <PathField label="Save in" value={dir} onChange={setFolder} pick={bridge ? () => bridge.pick_folder() : undefined} />
          {dir && <p className="small muted">Writes <span className="mono">{joinPath(dir, `${code}.ohengagement`)}</span></p>}
          <Field label="Passphrase" hint="At least 12 characters. The generated one is strong; you can type your own.">
            <div className="row">
              <input className="mono" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
              <Button size="sm" variant="ghost" onClick={() => setPassphrase(newPassphrase())}>New</Button>
              <CopyButton text={passphrase} label="Copy" />
            </div>
          </Field>
          <div className="actions">
            <Button variant="primary" disabled={!dir || passphrase.length < 12} loading={run.isPending} onClick={() => run.mutate(undefined)}>
              Write hand-off file
            </Button>
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

interface ImportResult {
  engagement_id: number;
  code: string;
  renamed: boolean;
  findings: number;
  evidence_files: number;
}

export function HandoffImportButton() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>Import hand-off file</Button>
      {open && <HandoffImport onClose={() => setOpen(false)} />}
    </>
  );
}

function HandoffImport({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const run = useApiMutation(
    () => api.upload<ImportResult>("/api/handoff/import", file!, {}, { "X-Handoff-Passphrase": passphrase }),
    {
      success: (r) => (r.renamed ? `Imported as ${r.code} (the original code is already in use)` : `Imported ${r.code}`),
      onSuccess: (r) => {
        qc.invalidateQueries();
        onClose();
        navigate(`/engagements/${r.engagement_id}`);
      },
    },
  );
  return (
    <Modal title="Import a hand-off file" onClose={onClose}>
      <div className="form-grid single">
        <p className="muted small">
          Adds the engagement in a <span className="mono">.ohengagement</span> file (with its evidence) to this vault. Nothing is
          added unless the whole file decrypts and checks out.
        </p>
        <div className="row">
          <input ref={input} type="file" accept=".ohengagement" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          <Button onClick={() => input.current?.click()}>{file ? "Choose another file" : "Choose file"}</Button>
          {file && <span className="small mono">{file.name} · {fmtBytes(file.size)}</span>}
        </div>
        <Field label="Passphrase">
          <input className="mono" type="password" autoComplete="off" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
        </Field>
        <div className="actions">
          <Button variant="primary" disabled={!file || !passphrase} loading={run.isPending} onClick={() => run.mutate(undefined)}>Import</Button>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </Modal>
  );
}
