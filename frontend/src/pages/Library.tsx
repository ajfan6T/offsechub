import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { canLead, useUser } from "../auth";
import { CvssBuilder } from "../components/CvssBuilder";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  Field,
  Loading,
  Modal,
  PageHeader,
  SeverityBadge,
  useApiMutation,
} from "../components/ui";
import { SEVERITIES, titleCase } from "../lib/format";
import type { FindingTemplate, Severity } from "../types";

export function Library() {
  const user = useUser();
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<FindingTemplate | "new" | null>(null);
  const q = useQuery({
    queryKey: ["finding-templates"],
    queryFn: () => api.get<FindingTemplate[]>("/api/finding-templates"),
  });
  const rows = (q.data ?? []).filter((t) =>
    `${t.title} ${t.category} ${t.cwe}`.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <PageHeader
        title="Finding library"
        subtitle="Reusable, reviewed write-ups. Consistent wording across reports and far less time writing."
        actions={
          canLead(user) && (
            <Button variant="primary" onClick={() => setEditing("new")}>
              New template
            </Button>
          )
        }
      />
      <div className="toolbar">
        <input placeholder="Search title, category or CWE" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      <Card>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <ErrorBox error={q.error} />
        ) : rows.length === 0 ? (
          <Empty title="No templates match" />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Category</th>
                <th>Severity</th>
                <th>CWE</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.id} className="clickable" onClick={() => setEditing(t)}>
                  <td className="strong">{t.title}</td>
                  <td>{t.category}</td>
                  <td>
                    <SeverityBadge severity={t.severity} score={t.cvss_score} />
                  </td>
                  <td className="mono">{t.cwe || "-"}</td>
                  <td className="right muted small">{canLead(user) ? "Edit" : "View"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {editing && (
        <TemplateForm
          template={editing === "new" ? null : editing}
          readOnly={!canLead(user)}
          onClose={() => setEditing(null)}
        />
      )}
    </>
  );
}

function TemplateForm({
  template,
  readOnly,
  onClose,
}: {
  template: FindingTemplate | null;
  readOnly: boolean;
  onClose: () => void;
}) {
  const [form, setForm] = useState({
    title: template?.title ?? "",
    category: template?.category ?? "Web Application",
    severity: (template?.severity ?? "medium") as Severity,
    cvss_vector: template?.cvss_vector ?? "",
    cwe: template?.cwe ?? "",
    description: template?.description ?? "",
    impact: template?.impact ?? "",
    remediation: template?.remediation ?? "",
    references: template?.references ?? "",
  });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const save = useApiMutation(
    () =>
      template
        ? api.patch(`/api/finding-templates/${template.id}`, form)
        : api.post("/api/finding-templates", form),
    { invalidate: [["finding-templates"]], success: "Template saved", onSuccess: onClose },
  );
  const remove = useApiMutation(() => api.del(`/api/finding-templates/${template!.id}`), {
    invalidate: [["finding-templates"]],
    success: "Template deleted",
    onSuccess: onClose,
  });

  return (
    <Modal
      title={template ? template.title : "New template"}
      onClose={onClose}
      wide
      footer={
        readOnly ? (
          <Button onClick={onClose}>Close</Button>
        ) : (
          <>
            {template && (
              <Button
                variant="danger"
                className="mr-auto"
                onClick={() => window.confirm("Delete this template?") && remove.mutate(undefined)}
              >
                Delete
              </Button>
            )}
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" loading={save.isPending} disabled={!form.title} onClick={() => save.mutate(undefined)}>
              Save
            </Button>
          </>
        )
      }
    >
      <fieldset disabled={readOnly} className="form-grid">
        <Field label="Title" wide>
          <input value={form.title} onChange={set("title")} />
        </Field>
        <Field label="Category">
          <input value={form.category} onChange={set("category")} list="template-categories" />
          <datalist id="template-categories">
            {["Web Application", "Infrastructure", "Active Directory", "Cloud", "Mobile", "API", "Wireless", "Social Engineering"].map((c) => (
              <option key={c} value={c} />
            ))}
          </datalist>
        </Field>
        <Field label="Default severity" hint="Overridden by the CVSS score when a vector is set">
          <select value={form.severity} onChange={set("severity")}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="CWE">
          <input className="mono" value={form.cwe} onChange={set("cwe")} placeholder="CWE-79" />
        </Field>
        <Field label="CVSS v3.1" wide>
          <CvssBuilder value={form.cvss_vector} onChange={(v) => setForm((f) => ({ ...f, cvss_vector: v }))} disabled={readOnly} />
        </Field>
        <Field label="Description" wide>
          <textarea rows={4} value={form.description} onChange={set("description")} />
        </Field>
        <Field label="Impact" wide>
          <textarea rows={3} value={form.impact} onChange={set("impact")} />
        </Field>
        <Field label="Remediation" wide>
          <textarea rows={3} value={form.remediation} onChange={set("remediation")} />
        </Field>
        <Field label="References" wide hint="One per line">
          <textarea rows={3} className="mono" value={form.references} onChange={set("references")} />
        </Field>
      </fieldset>
    </Modal>
  );
}
