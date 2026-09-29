import { useState } from "react";
import { api } from "../../api";
import {
  Badge,
  Button,
  Card,
  ConfirmButton,
  Empty,
  ErrorBox,
  Field,
  Loading,
  Modal,
  ScopeBadge,
  useApiMutation,
  useToast,
} from "../../components/ui";
import { TARGET_KINDS, TARGET_STATUSES, titleCase } from "../../lib/format";
import type { Service, Target, TargetKind, TargetStatus } from "../../types";
import { useEngagement, useTargets } from "./context";

export function Targets() {
  const { base } = useEngagement();
  const q = useTargets(base);
  const [search, setSearch] = useState("");
  const [scope, setScope] = useState("");
  const [adding, setAdding] = useState(false);
  const [openId, setOpenId] = useState<number | null>(null);
  const toast = useToast();
  const setStatus = useApiMutation(
    (v: { id: number; status: TargetStatus }) => api.patch(`${base}/targets/${v.id}`, { status: v.status }),
    { invalidate: [[base, "targets"], [base, "summary"]] },
  );

  const rows = (q.data ?? []).filter((t) => {
    const hay = `${t.value} ${t.hostname} ${t.ip} ${t.os} ${t.tags.join(" ")} ${t.services.map((s) => `${s.port} ${s.name} ${s.product}`).join(" ")}`.toLowerCase();
    return hay.includes(search.toLowerCase()) && (!scope || t.scope_status === scope);
  });
  const outOfScope = (q.data ?? []).filter((t) => t.scope_status !== "in_scope").length;
  const open = q.data?.find((t) => t.id === openId) ?? null;

  return (
    <>
      {outOfScope > 0 && (
        <div className="alert alert-warn">
          {outOfScope} target(s) are not in scope. Do not test them unless scope is updated in writing.
        </div>
      )}
      <div className="toolbar">
        <input placeholder="Search host, IP, OS, port, service, tag" value={search} onChange={(e) => setSearch(e.target.value)} />
        <div className="seg">
          {[["", "All"], ["in_scope", "In scope"], ["out_of_scope", "Out of scope"], ["excluded", "Excluded"]].map(([v, l]) => (
            <button key={v} className={scope === v ? "on" : ""} onClick={() => setScope(v)}>{l}</button>
          ))}
        </div>
        <Button variant="primary" onClick={() => setAdding(true)}>Add target</Button>
      </div>
      <Card>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <ErrorBox error={q.error} />
        ) : rows.length === 0 ? (
          <Empty title="No targets">Add them manually or import Nmap, nuclei or host lists from the Recon tab.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Kind</th>
                <th>IP / hostname</th>
                <th>OS</th>
                <th>Open services</th>
                <th>Scope</th>
                <th>Findings</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.id} className="clickable" onClick={() => setOpenId(t.id)}>
                  <td>
                    <span className="mono strong">{t.value}</span>
                    {t.tags.length > 0 && (
                      <div className="tags">{t.tags.map((tag) => <Badge key={tag}>{tag}</Badge>)}</div>
                    )}
                  </td>
                  <td>{t.kind}</td>
                  <td className="mono small">
                    {t.ip !== t.value && t.ip}
                    {t.hostname && t.hostname !== t.value && <div className="muted">{t.hostname}</div>}
                  </td>
                  <td className="small">{t.os || "-"}</td>
                  <td className="mono small">{t.services.map((s) => `${s.port}/${s.protocol}`).join(", ") || "-"}</td>
                  <td><ScopeBadge status={t.scope_status} /></td>
                  <td>{t.finding_count || "-"}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <select
                      value={t.status}
                      className={t.status === "compromised" ? "select-danger" : ""}
                      onChange={(e) => {
                        setStatus.mutate({ id: t.id, status: e.target.value as TargetStatus });
                        if (e.target.value === "compromised") toast("success", `${t.value} marked compromised. Log it in the op log.`);
                      }}
                    >
                      {Object.entries(TARGET_STATUSES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {adding && <AddTarget onClose={() => setAdding(false)} />}
      {open && <TargetDetail target={open} onClose={() => setOpenId(null)} />}
    </>
  );
}

function AddTarget({ onClose }: { onClose: () => void }) {
  const { base } = useEngagement();
  const toast = useToast();
  const [form, setForm] = useState({ kind: "host" as TargetKind, value: "", hostname: "", ip: "", os: "", tags: "", notes: "" });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const add = useApiMutation(
    () => api.post<Target>(`${base}/targets`, { ...form, tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean) }),
    {
      invalidate: [[base, "targets"], [base, "summary"]],
      onSuccess: (t) => {
        if (t.scope_status === "in_scope") toast("success", `Added ${t.value}`);
        else toast("error", `Added ${t.value}, but it is ${t.scope_status.replace(/_/g, " ")}. Do not test it.`);
        onClose();
      },
    },
  );
  return (
    <Modal
      title="Add target"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!form.value} loading={add.isPending} onClick={() => add.mutate(undefined)}>Add</Button>
        </>
      }
    >
      <div className="form-grid">
        <Field label="Target (IP, hostname or URL)" wide>
          <input className="mono" value={form.value} onChange={set("value")} autoFocus placeholder="203.0.113.10 or https://app.example.com" />
        </Field>
        <Field label="Kind">
          <select value={form.kind} onChange={set("kind")}>
            {TARGET_KINDS.map((k) => <option key={k}>{k}</option>)}
          </select>
        </Field>
        <Field label="IP">
          <input className="mono" value={form.ip} onChange={set("ip")} />
        </Field>
        <Field label="Hostname">
          <input className="mono" value={form.hostname} onChange={set("hostname")} />
        </Field>
        <Field label="OS">
          <input value={form.os} onChange={set("os")} />
        </Field>
        <Field label="Tags" hint="Comma separated" wide>
          <input value={form.tags} onChange={set("tags")} placeholder="prod, pci, crown-jewel" />
        </Field>
        <Field label="Notes" wide>
          <textarea rows={3} value={form.notes} onChange={set("notes")} />
        </Field>
      </div>
    </Modal>
  );
}

const EMPTY_SERVICE = { port: "", protocol: "tcp", name: "", product: "", version: "" };

function TargetDetail({ target: t, onClose }: { target: Target; onClose: () => void }) {
  const { base } = useEngagement();
  const [form, setForm] = useState({ kind: t.kind, hostname: t.hostname, ip: t.ip, os: t.os, tags: t.tags.join(", "), notes: t.notes });
  const [svc, setSvc] = useState(EMPTY_SERVICE);
  const invalidate = [[base, "targets"], [base, "summary"]];
  const save = useApiMutation(
    () => api.patch(`${base}/targets/${t.id}`, { ...form, tags: form.tags.split(",").map((x) => x.trim()).filter(Boolean) }),
    { invalidate, success: "Target saved" },
  );
  const remove = useApiMutation(() => api.del(`${base}/targets/${t.id}`), { invalidate, success: "Target deleted", onSuccess: onClose });
  const addSvc = useApiMutation(
    () => api.post<Service>(`${base}/targets/${t.id}/services`, { ...svc, port: Number(svc.port) }),
    { invalidate, success: "Service added", onSuccess: () => setSvc(EMPTY_SERVICE) },
  );
  const delSvc = useApiMutation((id: number) => api.del(`${base}/targets/${t.id}/services/${id}`), { invalidate });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  return (
    <Modal
      title={t.value}
      onClose={onClose}
      wide
      footer={
        <>
          <ConfirmButton variant="danger" className="mr-auto" message={`Delete ${t.value} and its services?`} onConfirm={() => remove.mutate(undefined)}>
            Delete target
          </ConfirmButton>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>
        </>
      }
    >
      <div className="detail-meta">
        <ScopeBadge status={t.scope_status} /> <Badge>{TARGET_STATUSES[t.status]}</Badge> <span className="muted small">source: {t.source}</span>
      </div>
      <div className="form-grid">
        <Field label="Kind">
          <select value={form.kind} onChange={set("kind")}>
            {TARGET_KINDS.map((k) => <option key={k}>{k}</option>)}
          </select>
        </Field>
        <Field label="IP"><input className="mono" value={form.ip} onChange={set("ip")} /></Field>
        <Field label="Hostname"><input className="mono" value={form.hostname} onChange={set("hostname")} /></Field>
        <Field label="OS"><input value={form.os} onChange={set("os")} /></Field>
        <Field label="Tags" wide><input value={form.tags} onChange={set("tags")} /></Field>
        <Field label="Notes" wide><textarea rows={3} value={form.notes} onChange={set("notes")} /></Field>
      </div>

      <h3>Services</h3>
      {t.services.length === 0 ? (
        <p className="muted">No services recorded.</p>
      ) : (
        <table className="table">
          <thead>
            <tr><th>Port</th><th>State</th><th>Service</th><th>Product / version</th><th /></tr>
          </thead>
          <tbody>
            {t.services.map((s) => (
              <tr key={s.id}>
                <td className="mono">{s.port}/{s.protocol}</td>
                <td>{s.state}</td>
                <td>{s.name}</td>
                <td className="small">{[s.product, s.version, s.extra_info].filter(Boolean).join(" ")}</td>
                <td className="right">
                  <Button size="sm" variant="ghost" onClick={() => delSvc.mutate(s.id)}>Remove</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="inline-form">
        <input className="mono w-sm" placeholder="Port" value={svc.port} onChange={(e) => setSvc({ ...svc, port: e.target.value.replace(/\D/g, "") })} />
        <select value={svc.protocol} onChange={(e) => setSvc({ ...svc, protocol: e.target.value })}>
          <option>tcp</option><option>udp</option>
        </select>
        <input placeholder="Service (http)" value={svc.name} onChange={(e) => setSvc({ ...svc, name: e.target.value })} />
        <input placeholder="Product" value={svc.product} onChange={(e) => setSvc({ ...svc, product: e.target.value })} />
        <input placeholder="Version" value={svc.version} onChange={(e) => setSvc({ ...svc, version: e.target.value })} />
        <Button disabled={!svc.port} onClick={() => addSvc.mutate(undefined)}>Add service</Button>
      </div>
      <p className="muted small">Kind: {titleCase(t.kind)} · added {new Date(t.created_at).toLocaleString()}</p>
    </Modal>
  );
}
