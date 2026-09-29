import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { api, qs } from "../api";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  Field,
  Loading,
  Modal,
  PageHeader,
  SeverityCounts,
  StatusPill,
  useApiMutation,
} from "../components/ui";
import { ENGAGEMENT_STATUSES, ENGAGEMENT_TYPES, fmtDate, titleCase } from "../lib/format";
import type { Client, Engagement, EngagementType } from "../types";

export function Engagements() {
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [creating, setCreating] = useState(false);
  const q = useQuery({
    queryKey: ["engagements", status],
    queryFn: () => api.get<Engagement[]>(`/api/engagements${qs({ status })}`),
  });
  const rows = (q.data ?? []).filter((e) =>
    `${e.name} ${e.code} ${e.client.name}`.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <PageHeader
        title="Engagements"
        subtitle="Every assessment is a case: scope, targets, testing, evidence, findings and the report."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            New engagement
          </Button>
        }
      />
      <div className="toolbar">
        <input placeholder="Search name, code or client" value={search} onChange={(e) => setSearch(e.target.value)} />
        <div className="seg">
          {["", ...ENGAGEMENT_STATUSES].map((s) => (
            <button key={s} className={status === s ? "on" : ""} onClick={() => setStatus(s)}>
              {s ? titleCase(s) : "All"}
            </button>
          ))}
        </div>
      </div>
      <Card>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <ErrorBox error={q.error} />
        ) : rows.length === 0 ? (
          <Empty title="No engagements">{search || status ? "Nothing matches the filter." : "Create one to get started."}</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Code</th>
                <th>Engagement</th>
                <th>Client</th>
                <th>Type</th>
                <th>Status</th>
                <th>Window</th>
                <th>Findings (C/H/M/L/I)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{e.code}</td>
                  <td>
                    <Link className="strong" to={`/engagements/${e.id}`}>
                      {e.name}
                    </Link>
                  </td>
                  <td>{e.client.name}</td>
                  <td>{ENGAGEMENT_TYPES[e.type]}</td>
                  <td>
                    <StatusPill status={e.status} />
                  </td>
                  <td className="small">
                    {fmtDate(e.start_date)} to {fmtDate(e.end_date)}
                  </td>
                  <td>
                    <SeverityCounts counts={e.finding_counts} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {creating && <NewEngagement onClose={() => setCreating(false)} />}
    </>
  );
}

function NewEngagement({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const clients = useQuery({ queryKey: ["clients"], queryFn: () => api.get<Client[]>("/api/clients") });
  const [form, setForm] = useState({
    client_id: "",
    name: "",
    code: "",
    type: "web_application" as EngagementType,
    start_date: "",
    end_date: "",
    description: "",
    rules_of_engagement: "",
  });
  const [newClient, setNewClient] = useState("");
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  const create = useApiMutation(
    async () => {
      let clientId = Number(form.client_id);
      if (!clientId && newClient.trim()) {
        clientId = (await api.post<Client>("/api/clients", { name: newClient.trim() })).id;
      }
      return api.post<Engagement>("/api/engagements", {
        ...form,
        client_id: clientId,
        start_date: form.start_date || null,
        end_date: form.end_date || null,
      });
    },
    {
      invalidate: [["engagements"], ["clients"], ["dashboard"]],
      success: (e) => `Created ${e.code}`,
      onSuccess: (e) => navigate(`/engagements/${e.id}/scope`),
    },
  );

  return (
    <Modal
      title="New engagement"
      onClose={onClose}
      wide
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={!form.name || !form.code || (!form.client_id && !newClient.trim())}
            onClick={() => create.mutate(undefined)}
          >
            Create and define scope
          </Button>
        </>
      }
    >
      <div className="form-grid">
        <Field label="Client">
          <select value={form.client_id} onChange={set("client_id")}>
            <option value="">+ New client</option>
            {clients.data?.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </Field>
        {!form.client_id && (
          <Field label="New client name">
            <input value={newClient} onChange={(e) => setNewClient(e.target.value)} placeholder="ACME Corporation" />
          </Field>
        )}
        <Field label="Engagement name">
          <input value={form.name} onChange={set("name")} placeholder="External Penetration Test 2026" />
        </Field>
        <Field label="Code" hint="Used for finding IDs, e.g. ACME-EXT-26-001">
          <input className="mono" value={form.code} onChange={(e) => setForm({ ...form, code: e.target.value.toUpperCase() })} placeholder="ACME-EXT-26" />
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
        <Field label="Start date">
          <input type="date" value={form.start_date} onChange={set("start_date")} />
        </Field>
        <Field label="End date">
          <input type="date" value={form.end_date} onChange={set("end_date")} />
        </Field>
        <Field label="Description" wide>
          <textarea rows={3} value={form.description} onChange={set("description")} />
        </Field>
        <Field label="Rules of engagement" wide hint="Testing windows, forbidden techniques, emergency contacts, source IPs">
          <textarea rows={4} value={form.rules_of_engagement} onChange={set("rules_of_engagement")} />
        </Field>
      </div>
    </Modal>
  );
}
