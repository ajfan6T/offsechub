import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, setApiEvents } from "../api";
import { Button, ErrorBox, Loading } from "../components/ui";
import type { VaultStatus } from "../types";
import { isAppQuery, RECENT_KEY, STATUS_KEY, VaultContext, type RecoveryKeyReason, type UnlockSecret, type VaultApi } from "./context";
import { VaultScreen } from "./common";
import { RecoveryKeyScreen } from "./RecoveryKey";
import { SetPassword } from "./SetPassword";
import { Unlock } from "./Unlock";
import { Welcome } from "./Welcome";

const STATUS_POLL_MS = 15_000; // GET /api/vault/status never resets the idle timer
const HEARTBEAT_MS = 30_000;
const WARN_BEFORE_LOCK_S = 60;
const INPUT_EVENTS = ["keydown", "pointerdown", "wheel", "touchstart"] as const;

/**
 * Decides what the window shows, from GET /api/vault/status:
 * none → Welcome, locked → Unlock, unlocked + must_set_password → SetPassword,
 * unlocked → the app. Also owns the app-wide reactions to 423 and 401, the
 * input heartbeat that drives auto-lock, and the auto-lock warning.
 */
export function VaultGate({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [sessionLost, setSessionLost] = useState(false);
  const [interrupted, setInterrupted] = useState(false);
  const [pendingKey, setPendingKey] = useState<{ key: string; reason: RecoveryKeyReason } | null>(null);
  const [typedRecoveryKey, setTypedRecoveryKey] = useState<string | null>(null);
  const [activityAt, setActivityAt] = useState(0);

  const statusQuery = useQuery({
    queryKey: STATUS_KEY,
    queryFn: () => api.get<VaultStatus>("/api/vault/status"),
    refetchInterval: sessionLost ? false : STATUS_POLL_MS,
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: true,
    staleTime: 0,
  });
  const status = statusQuery.data;
  const state = status?.state;

  useEffect(() => {
    setApiEvents({
      sessionLost: () => setSessionLost(true),
      locked: () => {
        // Some request found the vault locked before the next poll did: switch now.
        setInterrupted(true);
        qc.setQueryData<VaultStatus>(STATUS_KEY, (s) =>
          s?.state === "unlocked" ? { ...s, state: "locked", seconds_until_lock: null } : s,
        );
        void qc.invalidateQueries({ queryKey: STATUS_KEY });
      },
      activity: () => setActivityAt(Date.now()),
    });
    return () => setApiEvents({});
  }, [qc]);

  // Once the vault is not unlocked, drop every cached query and mutation: they
  // hold decrypted vault data, which should not outlive the key in this page.
  // Safe as an effect: by now the app has unmounted, and the screens rendered
  // instead only use "app" queries.
  useEffect(() => {
    if (state && state !== "unlocked") {
      qc.removeQueries({ predicate: (q) => !isAppQuery(q) });
      qc.getMutationCache().clear();
      setTypedRecoveryKey(null);
    }
  }, [state, qc]);

  useActivityHeartbeat(state === "unlocked" && !sessionLost);

  const setStatus = useCallback((s: VaultStatus) => void qc.setQueryData(STATUS_KEY, s), [qc]);
  const stayUnlocked = useCallback(() => void api.post("/api/app/activity").catch(() => undefined), []);
  const refreshStatus = useCallback(() => void qc.invalidateQueries({ queryKey: STATUS_KEY }), [qc]);
  const vault = useMemo<VaultApi | null>(
    () =>
      status
        ? {
            status,
            setStatus,
            showRecoveryKey: (key, reason) => setPendingKey({ key, reason }),
            unlock: async (path: string, secret: UnlockSecret) => {
              const next = await api.post<VaultStatus>("/api/vault/unlock", { path, ...secret });
              setTypedRecoveryKey("recovery_key" in secret ? secret.recovery_key : null);
              setInterrupted(false);
              setStatus(next);
              void qc.invalidateQueries({ queryKey: RECENT_KEY });
            },
            lock: async () => setStatus(await api.post<VaultStatus>("/api/vault/lock")),
            close: async () => {
              setInterrupted(false);
              setStatus(await api.post<VaultStatus>("/api/vault/close"));
            },
          }
        : null,
    [status, setStatus, qc],
  );

  if (sessionLost) return <SessionLost />;
  if (!vault) {
    return statusQuery.isPending ? (
      <div className="gate">
        <Loading label="Starting OffsecHub" />
      </div>
    ) : (
      <VaultScreen title="OffsecHub is not responding">
        <ErrorBox error={statusQuery.error} />
        <Button variant="primary" onClick={() => statusQuery.refetch()}>
          Try again
        </Button>
      </VaultScreen>
    );
  }

  const s = vault.status;
  let screen: ReactNode;
  if (pendingKey) {
    screen = (
      <RecoveryKeyScreen
        recoveryKey={pendingKey.key}
        reason={pendingKey.reason}
        vaultName={s.name}
        vaultPath={s.path}
        onDone={() => {
          setPendingKey(null);
          setTypedRecoveryKey(null);
        }}
      />
    );
  } else if (s.state === "none") screen = <Welcome />;
  else if (s.state === "locked") screen = <Unlock interrupted={interrupted} />;
  else if (s.must_set_password) screen = <SetPassword typedRecoveryKey={typedRecoveryKey} />;
  else screen = children;

  // The server's idle deadline, as of the last poll or the last request that reset it.
  const deadline =
    s.seconds_until_lock == null
      ? null
      : Math.max(statusQuery.dataUpdatedAt + s.seconds_until_lock * 1000, activityAt + s.auto_lock_minutes * 60_000);

  return (
    <VaultContext.Provider value={vault}>
      {screen}
      {s.state === "unlocked" && (
<AutoLockWarning deadline={deadline} onStay={stayUnlocked} onExpired={refreshStatus} />
      )}
    </VaultContext.Provider>
  );
}

/**
 * Report real keyboard, mouse and touch input to the backend, throttled, so that
 * auto-lock follows the operator rather than background polling.
 */
function useActivityHeartbeat(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    let last = 0;
    const onInput = (e: Event) => {
      const now = Date.now();
      if (!e.isTrusted || now - last < HEARTBEAT_MS) return;
      last = now;
      api.post("/api/app/activity").catch(() => {
        /* the next input after the throttle window retries */
      });
    };
    const opts: AddEventListenerOptions = { capture: true, passive: true };
    for (const type of INPUT_EVENTS) window.addEventListener(type, onInput, opts);
    return () => {
      for (const type of INPUT_EVENTS) window.removeEventListener(type, onInput, opts);
    };
  }, [enabled]);
}

function AutoLockWarning({
  deadline,
  onStay,
  onExpired,
}: {
  deadline: number | null;
  onStay: () => void;
  onExpired: () => void;
}) {
  const [now, setNow] = useState(Date.now);
  const left = deadline == null ? null : Math.max(0, Math.ceil((deadline - now) / 1000));

  // Sleep until the warning is due, then tick every second. Past the deadline,
  // poll the status once per tick: the backend locks within a few seconds.
  useEffect(() => {
    if (deadline == null) return;
    const warnAt = deadline - WARN_BEFORE_LOCK_S * 1000;
    const id = setTimeout(
      () => {
        if (Date.now() >= deadline) onExpired();
        setNow(Date.now());
      },
      Math.max(250, Date.now() < warnAt ? warnAt - Date.now() : 1000),
    );
    return () => clearTimeout(id);
  }, [deadline, now, onExpired]);

  if (left == null || left > WARN_BEFORE_LOCK_S) return null;
  return (
    <div className="autolock" role="alert">
      <span>
        No activity: the vault locks in <strong>{left} s</strong>.
      </span>
      <Button size="sm" variant="primary" onClick={onStay}>
        Stay unlocked
      </Button>
    </div>
  );
}

function SessionLost() {
  return (
    <VaultScreen title="Restart OffsecHub">
      <p>
        This window has lost its session with OffsecHub, usually because the app was restarted or its session cookie was
        cleared. For security, a session can only be created when OffsecHub launches.
      </p>
      <p className="muted small">
        Close this window and start OffsecHub again. In browser mode, run <code>offsechub open</code> for a fresh one-time
        link. Your vault is safe: everything saved is already encrypted on disk.
      </p>
    </VaultScreen>
  );
}
