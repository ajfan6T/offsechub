import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";
import { api } from "../api";
import {
  Button,
  Card,
  ConfirmButton,
  CopyButton,
  ErrorBox,
  Field,
  Loading,
  Modal,
  PageHeader,
  useApiMutation,
} from "../components/ui";
import type { Profile, RecoveryKeyResult } from "../types";
import { EMPTY_PASSWORD, isValidNewPassword, NewPasswordFields } from "../vault/common";
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
          <PasswordCard />
          <KeysCard />
        </div>
        <div className="stack">
          <SessionCard />
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
      <p className="muted small">Printed on reports and recorded as the operator on op-log entries. Stored inside the vault.</p>
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
          <input value={form.name} onChange={set("name")} placeholder="Alex Tester" />
        </Field>
        <Field label="Email">
          <input type="email" value={form.email} onChange={set("email")} placeholder="alex@example.com" />
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
        Instant: only the wrapped vault key is rewritten, and the recovery key keeps working. Backups taken before the change
        still open with the old password.
      </p>
      <div className="form-grid single">
        <Field label="Current password">
          <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
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
        The recovery key opens the vault if you forget the password. Generate a new one if you lost it or someone else may
        have seen it.
      </p>
      <Button onClick={() => setAction("rotated")}>Generate new recovery key</Button>
      <hr />
      <p className="muted small">
        <strong>Rekeying</strong> replaces the vault's master key after a suspected compromise, for example when your
        password, recovery key or a copy of the vault folder may have leaked. Old credentials and old copies of the header
        cannot decrypt anything written afterwards, and you get a new recovery key. Copies of the vault made earlier are not
        affected; change the password too if it may be known.
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
          <Button type="submit" form="password-prompt" variant={danger ? "danger" : "primary"} loading={run.isPending} disabled={!password}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <form id="password-prompt" className="form-grid single" onSubmit={submit}>
        <p className="muted small">{children}</p>
        {run.error && <ErrorBox error={run.error} />}
        <Field label="Vault password">
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
        </Field>
      </form>
    </Modal>
  );
}

const AUTO_LOCK_CHOICES = [5, 15, 30, 60];
const autoLockLabel = (m: number) => (m === 0 ? "Never" : m === 60 ? "1 hour" : m % 60 === 0 ? `${m / 60} hours` : `${m} minutes`);

function SessionCard() {
  const qc = useQueryClient();
  const { status, lock, close } = useVault();
  const current = status.auto_lock_minutes;
  const choices = [...new Set([...AUTO_LOCK_CHOICES, current])].filter((m) => m > 0).sort((a, b) => a - b);
  const setAutoLock = useApiMutation(
    (auto_lock_minutes: number) => api.put<{ auto_lock_minutes: number }>("/api/vault/settings", { auto_lock_minutes }),
    {
      success: (s) => (s.auto_lock_minutes ? `Auto-lock after ${autoLockLabel(s.auto_lock_minutes)} idle` : "Auto-lock turned off"),
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
          hint={current ? "Counts keyboard and mouse input in OffsecHub, not background refreshes." : "The vault stays unlocked until you lock it or quit OffsecHub."}
        >
          <select value={current} disabled={setAutoLock.isPending} onChange={(e) => setAutoLock.mutate(Number(e.target.value))}>
            {[...choices, 0].map((m) => (
              <option key={m} value={m}>
                {autoLockLabel(m)}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <p className="muted small">
        Locking saves pending changes, discards the keys from memory and closes the database. Closing also returns to the
        vault picker.
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

// ------------------------------------------------------------------ privacy

function PrivacyCard() {
  const qc = useQueryClient();
  const recent = useRecentVaults();
  const refresh = () => qc.invalidateQueries({ queryKey: RECENT_KEY });
  const setRemember = useApiMutation((remember_recent: boolean) => api.put("/api/app/preferences", { remember_recent }), {
    onSuccess: refresh,
  });
  const forgetAll = useApiMutation(() => api.post("/api/app/recent/forget", {}), {
    success: "Recent vaults forgotten",
    onSuccess: refresh,
  });
  const count = recent.data?.vaults.length ?? 0;
  return (
    <Card title="Privacy">
      <label className="check">
        <input
          type="checkbox"
          checked={recent.data?.remember_recent ?? false}
          disabled={!recent.data || setRemember.isPending}
          onChange={(e) => setRemember.mutate(e.target.checked)}
        />
        Remember recently opened vaults
      </label>
      <p className="muted small">
        The welcome screen lists them from OffsecHub's app config, which is not encrypted. Only folder paths are kept, but a
        path such as <span className="mono">ACME-2026.ohvault</span> can reveal who you work for.
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
          <span className="mono small">{status.path}</span> {status.path && <CopyButton text={status.path} label="Copy path" />}
        </dd>
      </dl>
      <h3>Your data at rest</h3>
      <p className="small">
        Everything in this vault lives in one folder on this machine, encrypted with AES-256-GCM under a master key that only
        your password (via Argon2id) or your recovery key can unwrap. Each save and each evidence file gets its own key, and
        the vault header holds no client data. Decrypted data exists only in OffsecHub's memory while the vault is unlocked.
        Nothing is sent over the network: there is no server, no account and no telemetry.
      </p>
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
