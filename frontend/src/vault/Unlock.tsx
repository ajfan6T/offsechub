import { useState, type FormEvent, type ReactNode } from "react";
import { Button, Field, useApiMutation } from "../components/ui";
import { useDesktopBridge } from "../lib/desktop";
import type { VaultStatus } from "../types";
import { useVault } from "./context";
import { errorText, PathField, VaultScreen } from "./common";

/**
 * Password (or recovery key) form for one vault. With `editablePath` the path
 * is an input too, used by "Open vault" on the welcome screen.
 */
export function UnlockForm({
  path: initialPath,
  editablePath,
  secondary,
}: {
  path: string;
  editablePath?: boolean;
  secondary?: ReactNode;
}) {
  const { unlock } = useVault();
  const bridge = useDesktopBridge();
  const [path, setPath] = useState(initialPath);
  const [useRecovery, setUseRecovery] = useState(false);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await unlock(path.trim(), useRecovery ? { recovery_key: secret } : { password: secret });
    } catch (err) {
      // Wrong password, typo in the recovery key, vault open in another window...
      setError(errorText(err));
      setBusy(false);
    }
  };

  return (
    <form className="gate-form" onSubmit={submit}>
      {editablePath && (
        <PathField
          label="Vault folder"
          value={path}
          onChange={setPath}
          pick={bridge ? () => bridge.pick_vault() : undefined}
          placeholder="/home/you/OffsecHub/ACME-2026.ohvault"
          hint="The .ohvault folder"
          autoFocus={!path}
        />
      )}
      {error && <div className="alert alert-error">{error}</div>}
      {useRecovery ? (
        <Field label="Recovery key" hint="Dashes, spaces and letter case do not matter.">
          <input
            key="recovery"
            className="mono"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="OHRK-XXXXX-XXXXX-…"
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="characters"
            autoFocus
          />
        </Field>
      ) : (
        <Field label="Password">
          <input
            key="password"
            type="password"
            autoComplete="current-password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            autoFocus={!editablePath || !!path}
          />
        </Field>
      )}
      <Button variant="primary" type="submit" loading={busy} disabled={!secret || !path.trim()} className="btn-block">
        {busy ? "Unlocking" : "Unlock"}
      </Button>
      <div className="gate-links">
        <button
          type="button"
          className="link small"
          onClick={() => {
            setUseRecovery(!useRecovery);
            setSecret("");
            setError(null);
          }}
        >
          {useRecovery ? "Use password" : "Forgot the password? Use recovery key"}
        </button>
        {secondary}
      </div>
    </form>
  );
}

/** Explain an unexpected lock: the app unmounted, taking any unsaved form input with it. */
function lockMessage(status: VaultStatus, interrupted: boolean): string | null {
  const lost = "The page you were on was closed, and anything you had not saved was discarded.";
  if (status.lock_reason === "idle") return `Locked after ${status.auto_lock_minutes} minutes without activity. ${lost}`;
  return interrupted ? `The vault was locked. ${lost}` : null;
}

/** The locked state: the vault is known, only the secret is missing. */
export function Unlock({ interrupted }: { interrupted: boolean }) {
  const { status, close } = useVault();
  const closeVault = useApiMutation(() => close());
  const message = lockMessage(status, interrupted);
  return (
    <VaultScreen title={`Unlock ${status.name}`} subtitle={<span className="mono small">{status.path}</span>}>
      {message && <div className="alert alert-info">{message}</div>}
      <UnlockForm
        path={status.path ?? ""}
        secondary={
          <button
            type="button"
            className="link small"
            disabled={closeVault.isPending}
            onClick={() => closeVault.mutate(undefined)}
          >
            Open a different vault
          </button>
        }
      />
    </VaultScreen>
  );
}
