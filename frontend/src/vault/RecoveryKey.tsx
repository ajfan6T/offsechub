import { useEffect, useState } from "react";
import { Button, CopyButton } from "../components/ui";
import type { RecoveryKeyReason } from "./context";
import { VaultScreen } from "./common";

const COPY: Record<RecoveryKeyReason, { title: string; lead: string }> = {
  created: {
    title: "Save your recovery key",
    lead: "Your vault is ready. If you ever forget the password, this key is the only way back in. There is no account and no reset link.",
  },
  reset: {
    title: "Your new recovery key",
    lead: "Your new password is set. The recovery key you just typed in has been replaced by this one, and it no longer works.",
  },
  rotated: {
    title: "Your new recovery key",
    lead: "The previous recovery key no longer works. Replace every stored copy of it with this one.",
  },
  rekeyed: {
    title: "Vault rekeyed",
    lead: "The vault now has a new master key. Your password is unchanged, but the previous recovery key no longer works. This is the new one.",
  },
};

/** Shows a freshly generated recovery key exactly once, until the operator confirms it is stored. */
export function RecoveryKeyScreen({
  recoveryKey,
  reason,
  vaultName,
  vaultPath,
  onDone,
}: {
  recoveryKey: string;
  reason: RecoveryKeyReason;
  vaultName: string | null;
  vaultPath: string | null;
  onDone: () => void;
}) {
  const [stored, setStored] = useState(false);
  const [generated] = useState(() => new Date().toLocaleString());
  const { title, lead } = COPY[reason];

  // The key cannot be shown again: ask before a reload or window close discards it.
  useEffect(() => {
    if (stored) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [stored]);

  return (
    <VaultScreen wide>
      <div className="recovery-sheet">
        <h2 className="gate-title">{title}</h2>
        <p className="muted no-print">{lead}</p>
        <p className="print-only">OffsecHub vault recovery key. Keep this sheet somewhere safe and offline.</p>
        <div className="recovery-key mono" aria-label="Recovery key">
          {recoveryKey.split("-").map((group, i) => (
            <span key={i}>{group}</span>
          ))}
        </div>
        <dl className="dl small">
          <dt>Vault</dt>
          <dd>{vaultName ?? "-"}</dd>
          <dt>Location</dt>
          <dd className="mono">{vaultPath ?? "-"}</dd>
          <dt>Generated</dt>
          <dd>{generated}</dd>
        </dl>
        <ul className="small tight">
          <li>Print it or write it down, or put it in your password manager. Keep it away from the vault itself.</li>
          <li>Anyone with this key and a copy of the vault folder can decrypt it.</li>
          <li>It is shown only now. OffsecHub keeps no copy and cannot recover it for you.</li>
        </ul>
      </div>
      <div className="actions no-print">
        <CopyButton text={recoveryKey} label="Copy key" variant="secondary" />
        <Button onClick={() => window.print()}>Print</Button>
        <span className="muted small">If you copy it, clear your clipboard afterwards.</span>
      </div>
      <label className="check no-print">
        <input type="checkbox" checked={stored} onChange={(e) => setStored(e.target.checked)} />I have stored it somewhere safe
      </label>
      <Button variant="primary" className="btn-block no-print" disabled={!stored} onClick={onDone}>
        Continue
      </Button>
    </VaultScreen>
  );
}
