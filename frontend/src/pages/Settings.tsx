import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type FormEvent, type ReactNode } from "react";
import { api } from "../api";
import {
  Button,
  Card,
  ConfirmButton,
  CopyButton,
  DownloadLink,
  ErrorBox,
  Field,
  Loading,
  Modal,
  PageHeader,
  useApiMutation,
} from "../components/ui";
import { joinPath, useDesktopBridge } from "../lib/desktop";
import { fmtBytes, fmtDate } from "../lib/format";
import type {
  BackupResult,
  Profile,
  RecoveryKeyResult,
  ReportBranding,
  ReportTemplate,
  UpdateCheck,
  VerifyResult,
} from "../types";
import { EMPTY_PASSWORD, isValidNewPassword, NewPasswordFields, PathField } from "../vault/common";
import {
  PROFILE_KEY,
  RECENT_KEY,
  STATUS_KEY,
  useAppInfo,
  useProfile,
  useRecentVaults,
  useVault,
  type RecoveryKeyReason,
} from "../vault/context";

const DOCS_URL = "https://github.com/ajfan6T/offsechub/blob/HEAD/docs";

export function Settings() {
  const { status } = useVault();
  return (
    <>
      <PageHeader
        title="Settings"
        subtitle={
          <>
            Vault <strong>{status.name}</strong> · <span className="mono">{status.path}</span>
          </>
        }
      />
      <div className="grid-2 align-start">
        <div className="stack">
          <ProfileCard />
          <BrandingCard />
          <TemplatesCard />
          <PasswordCard />
          <KeysCard />
        </div>
        <div className="stack">
          <SessionCard />
          <BackupCard />
          <PrivacyCard />
          <AboutCard />
        </div>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ profile

function ProfileCard() {
  const q = useProfile();
  return (
    <Card title="Profile">
      <p className="muted small">
        Printed on reports and recorded as the operator on op-log entries. Stored inside the vault.
      </p>
      {q.data ? <ProfileForm profile={q.data} /> : q.error ? <ErrorBox error={q.error} /> : <Loading />}
    </Card>
  );
}

function ProfileForm({ profile }: { profile: Profile }) {
  const qc = useQueryClient();
  const [form, setForm] = useState(profile);
  const save = useApiMutation(() => api.put<Profile>("/api/profile", form), {
    success: "Profile saved",
    onSuccess: (saved) => qc.setQueryData(PROFILE_KEY, saved),
  });
  const set = (k: keyof Profile) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const dirty = (Object.keys(form) as (keyof Profile)[]).some((k) => form[k] !== profile[k]);
  return (
    <>
      <div className="form-grid single">
        <Field label="Name">
          <input value={form.name} onChange={set("name")} placeholder="Your name" />
        </Field>
        <Field label="Email">
          <input type="email" value={form.email} onChange={set("email")} placeholder="you@example.com" />
        </Field>
        <Field label="Organization">
          <input value={form.organization} onChange={set("organization")} placeholder="Your consultancy or team" />
        </Field>
      </div>
      <Button variant="primary" disabled={!dirty} loading={save.isPending} onClick={() => save.mutate(undefined)}>
        Save profile
      </Button>
    </>
  );
}

// ----------------------------------------------------------------- security

function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState(EMPTY_PASSWORD);
  const change = useApiMutation(
    () => api.post("/api/vault/change-password", { current_password: current, new_password: next.password }),
    {
      success: "Password changed",
      onSuccess: () => {
        setCurrent("");
        setNext(EMPTY_PASSWORD);
      },
    },
  );
  return (
    <Card title="Password">
      <p className="muted small">
        Instant: only the wrapped vault key is rewritten, and the recovery key keeps working. Backups taken before the
        change still open with the old password.
      </p>
      <div className="form-grid single">
        <Field label="Current password">
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </Field>
        <NewPasswordFields label="New password" value={next} onChange={setNext} />
      </div>
      <Button
        variant="primary"
        disabled={!current || !isValidNewPassword(next)}
        loading={change.isPending}
        onClick={() => change.mutate(undefined)}
      >
        Change password
      </Button>
    </Card>
  );
}

type KeyAction = Extract<RecoveryKeyReason, "rotated" | "rekeyed">;

const KEY_ACTIONS: Record<KeyAction, { endpoint: string; title: string; confirm: string; note: string }> = {
  rotated: {
    endpoint: "/api/vault/recovery-key",
    title: "Generate a new recovery key",
    confirm: "Generate key",
    note: "The current recovery key stops working as soon as the new one is generated. It is shown once.",
  },
  rekeyed: {
    endpoint: "/api/vault/rekey",
    title: "Rekey vault",
    confirm: "Rekey vault",
    note: "A new master key replaces the current one and the database is re-encrypted under it. You get a new recovery key; the old one stops working. Your password stays the same.",
  },
};

function KeysCard() {
  const { showRecoveryKey } = useVault();
  const [action, setAction] = useState<KeyAction | null>(null);
  const run = async (reason: KeyAction, password: string) => {
    const res = await api.post<RecoveryKeyResult>(KEY_ACTIONS[reason].endpoint, { password });
    showRecoveryKey(res.recovery_key, reason);
  };
  return (
    <Card title="Recovery key and master key">
      <p className="muted small">
        The recovery key opens the vault if you forget the password. Generate a new one if you lost it or someone else
        may have seen it.
      </p>
      <Button onClick={() => setAction("rotated")}>Generate new recovery key</Button>
      <hr />
      <p className="muted small">
        <strong>Rekeying</strong> replaces the vault's master key after a suspected compromise, for example when your
        password, recovery key or a copy of the vault folder may have leaked. Old credentials and old copies of the
        header cannot decrypt anything written afterwards, and you get a new recovery key. Copies of the vault made
        earlier are not affected; change the password too if it may be known.
      </p>
      <Button variant="danger" onClick={() => setAction("rekeyed")}>
        Rekey vault…
      </Button>
      {action && (
        <PasswordPrompt
          title={KEY_ACTIONS[action].title}
          confirmLabel={KEY_ACTIONS[action].confirm}
          danger={action === "rekeyed"}
          onSubmit={(password) => run(action, password)}
          onClose={() => setAction(null)}
        >
          {KEY_ACTIONS[action].note}
        </PasswordPrompt>
      )}
    </Card>
  );
}

/** Re-enter the password to confirm a sensitive action; errors (wrong password) stay in the dialog. */
function PasswordPrompt({
  title,
  confirmLabel,
  danger,
  onSubmit,
  onClose,
  children,
}: {
  title: string;
  confirmLabel: string;
  danger?: boolean;
  onSubmit: (password: string) => Promise<void>;
  onClose: () => void;
  children: ReactNode;
}) {
  const [password, setPassword] = useState("");
  const run = useMutation({ mutationFn: () => onSubmit(password) });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (password) run.mutate();
  };
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="submit"
            form="password-prompt"
            variant={danger ? "danger" : "primary"}
            loading={run.isPending}
            disabled={!password}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <form id="password-prompt" className="form-grid single" onSubmit={submit}>
        <p className="muted small">{children}</p>
        {run.error && <ErrorBox error={run.error} />}
        <Field label="Vault password">
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
          />
        </Field>
      </form>
    </Modal>
  );
}

const AUTO_LOCK_CHOICES = [5, 15, 30, 60];
const autoLockLabel = (m: number) =>
  m === 0 ? "Never" : m === 1 ? "1 minute" : m === 60 ? "1 hour" : m % 60 === 0 ? `${m / 60} hours` : `${m} minutes`;

function SessionCard() {
  const qc = useQueryClient();
  const { status, lock, close } = useVault();
  const current = status.auto_lock_minutes;
  const choices = [...new Set([...AUTO_LOCK_CHOICES, current])].filter((m) => m > 0).sort((a, b) => a - b);
  const setAutoLock = useApiMutation(
    (auto_lock_minutes: number) => api.put<{ auto_lock_minutes: number }>("/api/vault/settings", { auto_lock_minutes }),
    {
      success: (s) =>
        s.auto_lock_minutes ? `Auto-lock after ${autoLockLabel(s.auto_lock_minutes)} idle` : "Auto-lock turned off",
      onSuccess: () => qc.invalidateQueries({ queryKey: STATUS_KEY }),
    },
  );
  const lockNow = useApiMutation(() => lock());
  const closeVault = useApiMutation(() => close());
  return (
    <Card title="Locking">
      <div className="form-grid single">
        <Field
          label="Auto-lock when idle"
          hint={
            current
              ? "Counts keyboard and mouse input in OffsecHub, not background refreshes."
              : "The vault stays unlocked until you lock it or quit OffsecHub."
          }
        >
          <select
            value={current}
            disabled={setAutoLock.isPending}
            onChange={(e) => setAutoLock.mutate(Number(e.target.value))}
          >
            {[...choices, 0].map((m) => (
              <option key={m} value={m}>
                {autoLockLabel(m)}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <p className="muted small">
        Locking saves pending changes, discards the keys from memory and closes the database. Closing also returns to
        the vault picker.
      </p>
      <div className="actions">
        <Button variant="primary" loading={lockNow.isPending} onClick={() => lockNow.mutate(undefined)}>
          Lock now
        </Button>
        <Button loading={closeVault.isPending} onClick={() => closeVault.mutate(undefined)}>
          Close vault
        </Button>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------- backup/integrity

function BackupCard() {
  const { status } = useVault();
  const info = useAppInfo();
  const bridge = useDesktopBridge();
  const [folder, setFolder] = useState<string | null>(null);
  const dir = folder ?? info.data?.default_vault_dir ?? "";
  const target = dir ? joinPath(dir, `${status.name}-backup-${new Date().toISOString().slice(0, 10)}.ohvault`) : "";
  const backup = useApiMutation(() => api.post<BackupResult>("/api/vault/backup", { path: target }), {
    success: (r) => `Backup written to ${r.path}`,
  });
  const verify = useApiMutation(() => api.post<VerifyResult>("/api/vault/verify"));
  return (
    <Card title="Backup and integrity">
      <p className="muted small">
        A backup is a complete copy of this vault, still encrypted and checked after writing. It opens with the current
        password and recovery key. Put it on another disk: a copy next to the vault will not survive a disk failure.
      </p>
      <div className="form-grid single">
        <PathField
          label="Backup location"
          value={dir}
          onChange={setFolder}
          pick={bridge ? () => bridge.pick_folder() : undefined}
        />
      </div>
      {target && (
        <p className="small muted">
          Writes <span className="mono">{target}</span>
        </p>
      )}
      <Button loading={backup.isPending} disabled={!target} onClick={() => backup.mutate(undefined)}>
        Export backup
      </Button>
      {backup.data && (
        <p className="small">
          {backup.data.evidence_files} evidence file(s), {fmtBytes(backup.data.bytes)} in total.
        </p>
      )}
      <hr />
      <p className="muted small">
        Decrypt every evidence file and check it against the SHA-256 recorded when it was added.
      </p>
      <Button loading={verify.isPending} onClick={() => verify.mutate(undefined)}>
        Verify evidence
      </Button>
      {verify.data && <VerifySummary result={verify.data} />}
    </Card>
  );
}

function VerifySummary({ result: r }: { result: VerifyResult }) {
  const damaged = [...r.missing.map((f) => `${f} (missing)`), ...r.corrupt.map((f) => `${f} (fails authentication)`)];
  return (
    <div className={`alert ${damaged.length ? "alert-error" : "alert-success"} small verify-result`}>
      {damaged.length ? (
        <>
          <strong>
            {damaged.length} of {r.evidence} evidence file(s) failed verification.
          </strong>
          <ul className="tight">
            {damaged.map((d) => (
              <li key={d}>{d}</li>
            ))}
          </ul>
          Restore them from a backup.
        </>
      ) : (
        `All ${r.evidence} evidence file(s) verified.`
      )}
      {r.orphaned_files > 0 && (
        <div className="muted">
          {r.orphaned_files} unreferenced file(s) in the vault folder were left alone; they may belong to a backup or a
          sync copy.
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ privacy

function PrivacyCard() {
  const recent = useRecentVaults();
  // Shown immediately; the server value takes over again if saving fails.
  const [remember, setRemember] = useState<boolean>();
  const saveRemember = useApiMutation((value: boolean) => api.put("/api/app/preferences", { remember_recent: value }), {
    invalidate: [RECENT_KEY],
    onError: () => setRemember(undefined),
  });
  const forgetAll = useApiMutation(() => api.post("/api/app/recent/forget", {}), {
    invalidate: [RECENT_KEY],
    success: "Recent vaults forgotten",
  });
  const count = recent.data?.vaults.length ?? 0;
  return (
    <Card title="Privacy">
      <label className="check">
        <input
          type="checkbox"
          checked={remember ?? recent.data?.remember_recent ?? false}
          disabled={!recent.data}
          onChange={(e) => {
            setRemember(e.target.checked);
            saveRemember.mutate(e.target.checked);
          }}
        />
        Remember recently opened vaults
      </label>
      <p className="muted small">
        The welcome screen lists them from OffsecHub's app config, which is not encrypted. Only folder paths are kept,
        but a path such as <span className="mono">ACME-2026.ohvault</span> can reveal who you work for.
      </p>
      <ConfirmButton
        size="sm"
        disabled={!count}
        loading={forgetAll.isPending}
        message="Forget all recent vaults? The vaults themselves are not touched."
        onConfirm={() => forgetAll.mutate(undefined)}
      >
        Forget all{count ? ` (${count})` : ""}
      </ConfirmButton>
    </Card>
  );
}

// -------------------------------------------------------------------- about

function AboutCard() {
  const info = useAppInfo();
  const { status } = useVault();
  return (
    <Card title="About">
      <dl className="dl">
        <dt>Version</dt>
        <dd>{info.data?.version ?? "-"}</dd>
        <dt>Platform</dt>
        <dd>{info.data ? `${info.data.platform}, ${info.data.desktop ? "desktop app" : "browser mode"}` : "-"}</dd>
        <dt>Vault</dt>
        <dd>
          <span className="mono small">{status.path}</span>{" "}
          {status.path && <CopyButton text={status.path} label="Copy path" />}
        </dd>
      </dl>
      <h3>Your data at rest</h3>
      <p className="small">
        Everything in this vault lives in one folder on this machine, encrypted with AES-256-GCM under a master key that
        only your password (via Argon2id) or your recovery key can unwrap. Each save and each evidence file gets its own
        key, and the vault header holds no client data. Decrypted data exists only in OffsecHub's memory while the vault
        is unlocked. There is no server, no account and no telemetry. The only network request OffsecHub ever makes is
        the update check below, and only when you click it.
      </p>
      <UpdateCheckButton />
      <p className="small muted">
        Not hidden: the folder name, the number and sizes of evidence files, and file timestamps.
      </p>
      <p className="small">
        <a href={`${DOCS_URL}/VAULT_FORMAT.md`} target="_blank" rel="noreferrer">
          Vault format
        </a>{" "}
        ·{" "}
        <a href={`${DOCS_URL}/ARCHITECTURE.md`} target="_blank" rel="noreferrer">
          Architecture and local API hardening
        </a>{" "}
        <span className="muted">(open in your browser)</span>
      </p>
    </Card>
  );
}

// ------------------------------------------------------------------ reports

const BRANDING_KEY = ["report-branding"];
const TEMPLATES_KEY = ["report-templates"];

export function useBranding() {
  return useQuery({ queryKey: BRANDING_KEY, queryFn: () => api.get<ReportBranding>("/api/report-branding") });
}

export function useReportTemplates() {
  return useQuery({ queryKey: TEMPLATES_KEY, queryFn: () => api.get<ReportTemplate[]>("/api/report-templates") });
}

function BrandingCard() {
  const q = useBranding();
  return (
    <Card title="Report branding">
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : <BrandingForm key={JSON.stringify(q.data)} branding={q.data!} />}
    </Card>
  );
}

function BrandingForm({ branding }: { branding: ReportBranding }) {
  const profile = useProfile();
  const [form, setForm] = useState({
    organization: branding.organization,
    classification: branding.classification,
    footer: branding.footer,
    accent: branding.accent,
  });
  const logoInput = useRef<HTMLInputElement>(null);
  const changed = (Object.keys(form) as (keyof typeof form)[]).some((k) => form[k] !== branding[k]);
  const validAccent = /^#[0-9a-fA-F]{6}$/.test(form.accent);
  const save = useApiMutation(() => api.put<ReportBranding>("/api/report-branding", form), {
    invalidate: [BRANDING_KEY],
    success: "Branding saved",
  });
  const upload = useApiMutation((file: File) => api.upload<ReportBranding>("/api/report-branding/logo", file), {
    invalidate: [BRANDING_KEY],
    success: "Logo uploaded",
    onSuccess: () => logoInput.current && (logoInput.current.value = ""),
  });
  const removeLogo = useApiMutation(() => api.del("/api/report-branding/logo"), { invalidate: [BRANDING_KEY], success: "Logo removed" });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  return (
    <div className="form-grid single">
      <p className="muted small">Applied to every report format (PDF, Word, HTML, Markdown). Stored inside this vault.</p>
      <Field label="Organization" hint={profile.data?.organization ? `Defaults to your profile: ${profile.data.organization}` : undefined}>
        <input value={form.organization} onChange={set("organization")} placeholder={profile.data?.organization || "Your company"} />
      </Field>
      <Field label="Classification" hint="Shown on the cover and in the page header; leave empty to omit">
        <input value={form.classification} onChange={set("classification")} placeholder="CONFIDENTIAL" />
      </Field>
      <Field label="Footer text">
        <input value={form.footer} onChange={set("footer")} placeholder="e.g. Example Security Ltd, registered in England 01234567" />
      </Field>
      <Field label="Accent colour" hint={validAccent ? undefined : "Use a colour like #0f766e"}>
        <div className="row">
          <input type="color" className="color-input" value={validAccent ? form.accent : "#0f766e"} onChange={set("accent")} aria-label="Pick the accent colour" />
          <input className="mono" value={form.accent} onChange={set("accent")} maxLength={7} />
        </div>
      </Field>
      <div className="logo-row">
        {branding.logo_id ? (
          <img className="logo-preview" src={`/api/report-branding/logo?v=${branding.logo_id}`} alt="Report logo" />
        ) : (
          <span className="muted small">No logo</span>
        )}
        <input ref={logoInput} type="file" accept="image/png,image/jpeg" hidden onChange={(e) => e.target.files?.[0] && upload.mutate(e.target.files[0])} />
        <Button size="sm" loading={upload.isPending} onClick={() => logoInput.current?.click()}>{branding.logo_id ? "Replace logo" : "Upload logo"}</Button>
        {branding.logo_id && <Button size="sm" variant="ghost" onClick={() => removeLogo.mutate(undefined)}>Remove</Button>}
      </div>
      <p className="muted small">PNG or JPEG, up to 1 MB.</p>
      <div className="actions">
        <Button variant="primary" disabled={!changed || !validAccent} loading={save.isPending} onClick={() => save.mutate(undefined)}>Save branding</Button>
      </div>
    </div>
  );
}

function TemplatesCard() {
  const templates = useReportTemplates();
  const branding = useBranding();
  const input = useRef<HTMLInputElement>(null);
  const [name, setName] = useState("");
  const upload = useApiMutation((file: File) => api.upload<ReportTemplate>("/api/report-templates/upload", file, { name }), {
    invalidate: [TEMPLATES_KEY],
    success: (t) => `Template "${t.name}" added`,
    onSuccess: () => {
      setName("");
      if (input.current) input.current.value = "";
    },
  });
  const setDefault = useApiMutation((id: number | null) => api.put("/api/report-branding", { default_template_id: id }), {
    invalidate: [BRANDING_KEY],
    success: "Default Word template updated",
  });
  const remove = useApiMutation((id: number) => api.del(`/api/report-templates/${id}`), {
    invalidate: [TEMPLATES_KEY, BRANDING_KEY],
    success: "Template deleted",
  });
  const defaultId = branding.data?.default_template_id ?? null;

  return (
    <Card title="Word report templates">
      <p className="small">
        Start from the built-in template, restyle it in Word (fonts, colours, cover, sections), then upload it. Templates use
        Jinja tags such as <code>{"{{ client.name }}"}</code>; see the{" "}
        <a href={`${DOCS_URL}/REPORT_TEMPLATES.md`} target="_blank" rel="noreferrer">template guide</a>.
      </p>
      <div className="actions">
        <DownloadLink className="btn btn-secondary btn-sm" href="/api/report-templates/builtin/download" filename="offsechub-report-template.docx">
          Download the built-in template
        </DownloadLink>
      </div>
      <table className="table compact">
        <tbody>
          <tr>
            <td>
              <label className="check">
                <input type="radio" name="default-template" checked={defaultId === null} onChange={() => setDefault.mutate(null)} /> Built-in
              </label>
            </td>
            <td className="muted small">OffsecHub default</td>
            <td />
          </tr>
          {templates.data?.map((t) => (
            <tr key={t.id}>
              <td>
                <label className="check">
                  <input type="radio" name="default-template" checked={defaultId === t.id} onChange={() => setDefault.mutate(t.id)} /> {t.name}
                </label>
              </td>
              <td className="muted small">{fmtBytes(t.size)} · {fmtDate(t.created_at)}</td>
              <td className="nowrap">
                <DownloadLink className="link small" href={`/api/report-templates/${t.id}/download`} filename={t.filename}>Download</DownloadLink>{" "}
                <ConfirmButton variant="ghost" size="sm" message={`Delete the template "${t.name}"?`} onConfirm={() => remove.mutate(t.id)}>Delete</ConfirmButton>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">The selected template is the default for Word exports; you can pick another when exporting.</p>
      <div className="row">
        <input placeholder="Name (optional)" value={name} onChange={(e) => setName(e.target.value)} aria-label="Template name" />
        <input ref={input} type="file" accept=".docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document" hidden onChange={(e) => e.target.files?.[0] && upload.mutate(e.target.files[0])} />
        <Button loading={upload.isPending} onClick={() => input.current?.click()}>Upload template</Button>
      </div>
    </Card>
  );
}

function UpdateCheckButton() {
  const check = useMutation({ mutationFn: () => api.post<UpdateCheck>("/api/app/update-check") });
  return (
    <div className="update-check">
      <Button size="sm" loading={check.isPending} onClick={() => check.mutate()}>Check for updates</Button>
      {check.data &&
        (check.data.newer ? (
          <span className="small">
            OffsecHub {check.data.latest} is available.{" "}
            <a href={check.data.download_url} target="_blank" rel="noreferrer">Download it</a> <span className="muted">(opens your browser)</span>
          </span>
        ) : (
          <span className="small muted">You have the latest version ({check.data.current}).</span>
        ))}
      {check.error && <span className="small error-text">{(check.error as Error).message}</span>}
      <p className="muted small">Asks GitHub for the latest release number. Nothing about your vault is sent, and nothing is downloaded or installed.</p>
    </div>
  );
}
