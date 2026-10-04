import { useMutation, useQueryClient, type QueryKey } from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ButtonHTMLAttributes,
  type MouseEvent,
  type ReactNode,
} from "react";
import { ApiError } from "../api";
import { useDesktopBridge } from "../lib/desktop";
import { FINDING_STATUSES, TEST_STATUSES, titleCase } from "../lib/format";
import type { FindingStatus, ScopeStatus, Severity, TestStatus } from "../types";

// ---------------------------------------------------------------- buttons

type Variant = "primary" | "secondary" | "danger" | "ghost";

export function Button({
  variant = "secondary",
  size,
  loading,
  children,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: "sm"; loading?: boolean }) {
  return (
    <button
      className={`btn btn-${variant} ${size === "sm" ? "btn-sm" : ""} ${className}`}
      disabled={loading || rest.disabled}
      {...rest}
    >
      {loading && <span className="spinner" aria-hidden />}
      {children}
    </button>
  );
}

export function ConfirmButton({
  message,
  onConfirm,
  children,
  ...rest
}: Omit<Parameters<typeof Button>[0], "onClick"> & { message: string; onConfirm: () => void }) {
  return (
    <Button
      {...rest}
      onClick={() => {
        if (window.confirm(message)) onConfirm();
      }}
    >
      {children}
    </Button>
  );
}

export function Logo() {
  return (
    <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden>
      <path
        d="M16 4 6 8.5v6.7c0 6.5 4.2 11.3 10 13 5.8-1.7 10-6.5 10-13V8.5z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="15" r="3.4" fill="currentColor" />
    </svg>
  );
}

// ----------------------------------------------------------------- badges

export function Badge({ tone = "neutral", children }: { tone?: string; children: ReactNode }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function SeverityBadge({ severity, score }: { severity: Severity; score?: number | null }) {
  return (
    <span className={`sev sev-${severity}`}>
      {severity === "info" ? "Info" : titleCase(severity)}
      {score != null && <span className="sev-score">{score.toFixed(1)}</span>}
    </span>
  );
}

const FINDING_STATUS_TONE: Record<FindingStatus, string> = {
  draft: "neutral",
  confirmed: "red",
  reported: "blue",
  remediated: "green",
  risk_accepted: "amber",
  false_positive: "muted",
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return <Badge tone={FINDING_STATUS_TONE[status]}>{FINDING_STATUSES[status]}</Badge>;
}

const SCOPE_TONE: Record<ScopeStatus, [string, string]> = {
  in_scope: ["green", "In scope"],
  out_of_scope: ["amber", "Out of scope"],
  excluded: ["red", "Excluded"],
};

export function ScopeBadge({ status }: { status: ScopeStatus }) {
  const [tone, label] = SCOPE_TONE[status];
  return <Badge tone={tone}>{label}</Badge>;
}

const TEST_TONE: Record<TestStatus, string> = {
  not_started: "neutral",
  in_progress: "blue",
  passed: "green",
  failed: "red",
  not_applicable: "muted",
  blocked: "amber",
};

export function TestStatusBadge({ status }: { status: TestStatus }) {
  return <Badge tone={TEST_TONE[status]}>{TEST_STATUSES[status]}</Badge>;
}

export function StatusPill({ status }: { status: string }) {
  const tone: Record<string, string> = {
    planning: "neutral",
    active: "green",
    reporting: "blue",
    review: "amber",
    delivered: "teal",
    closed: "muted",
  };
  return <Badge tone={tone[status] ?? "neutral"}>{titleCase(status)}</Badge>;
}

// ----------------------------------------------------------------- layout

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

export function Card({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-header">
          {title && <h2>{title}</h2>}
          {actions && <div className="actions">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children && <div className="muted">{children}</div>}
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="loading">
      <span className="spinner" /> {label}...
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return <div className="alert alert-error">{error instanceof Error ? error.message : String(error)}</div>;
}

export function Field({
  label,
  hint,
  children,
  wide,
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
  wide?: boolean;
}) {
  // The hint sits outside the <label>, so a control's accessible name is just
  // its label, not the label plus help text, strength meters or errors.
  return (
    <div className={`field ${wide ? "field-wide" : ""}`}>
      <label className="field-control">
        <span className="field-label">{label}</span>
        {children}
      </label>
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  );
}

export function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? "modal-wide" : ""}`} role="dialog" aria-modal aria-label={title}>
        <header className="modal-header">
          <h2>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-footer">{footer}</footer>}
      </div>
    </div>
  );
}

export function SeverityBar({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((n, s) => n + (counts[s] ?? 0), 0);
  if (!total) return <span className="muted small">No findings</span>;
  return (
    <div className="sevbar" title={order.map((s) => `${s}: ${counts[s] ?? 0}`).join(", ")}>
      {order.map((s) =>
        counts[s] ? <span key={s} className={`sevbar-seg sev-bg-${s}`} style={{ flexGrow: counts[s] }} /> : null,
      )}
    </div>
  );
}

export function SeverityCounts({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return (
    <span className="sevcounts">
      {order.map((s) => (
        <span key={s} className={`sevcount ${counts[s] ? `sev-fg-${s}` : "zero"}`} title={s}>
          {counts[s] ?? 0}
        </span>
      ))}
    </span>
  );
}

export function CopyButton({
  text,
  label = "Copy",
  variant = "ghost",
}: {
  text: string;
  label?: string;
  variant?: Variant;
}) {
  const [result, setResult] = useState<"Copied" | "Copy failed" | null>(null);
  return (
    <Button
      size="sm"
      variant={variant}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setResult("Copied");
        } catch {
          setResult("Copy failed");
        }
        setTimeout(() => setResult(null), 1500);
      }}
    >
      {result ?? label}
    </Button>
  );
}

export interface LightboxImage {
  src: string;
  title: string;
  caption?: string;
  /** Download URL for the original file. */
  href?: string;
}

/**
 * In-app image viewer. Evidence must never open in a new window: the desktop
 * webview hands target="_blank" links to the system browser, which has no session.
 */
export function Lightbox({ images, start, onClose }: { images: LightboxImage[]; start: number; onClose: () => void }) {
  const [index, setIndex] = useState(start);
  const count = images.length;
  const step = useCallback((d: number) => setIndex((i) => (i + d + count) % count), [count]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      else if (e.key === "ArrowRight") step(1);
      else if (e.key === "ArrowLeft") step(-1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, step]);
  const img = images[index];
  if (!img) return null;
  return (
    <div className="lightbox" role="dialog" aria-modal aria-label={img.title} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <img src={img.src} alt={img.title} />
      <div className="lightbox-bar">
        <div className="lightbox-title">
          <strong>{img.title}</strong>
          {img.caption && <span className="muted"> · {img.caption}</span>}
        </div>
        <div className="actions">
          {count > 1 && (
            <>
              <Button size="sm" onClick={() => step(-1)} aria-label="Previous image">
                ←
              </Button>
              <span className="muted small">
                {index + 1} / {count}
              </span>
              <Button size="sm" onClick={() => step(1)} aria-label="Next image">
                →
              </Button>
            </>
          )}
          {img.href && (
            <DownloadLink className="btn btn-secondary btn-sm" href={img.href} filename={img.title}>
              Download
            </DownloadLink>
          )}
          <Button size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}

/**
 * A file download that works in both shells. In a browser it is a plain
 * same-origin download link. The desktop window has its engine's downloads
 * switched off, so there it opens a native "save as" dialog and the shell
 * fetches the file from the local API.
 */
export function DownloadLink({
  href,
  filename,
  className,
  children,
}: {
  href: string;
  filename: string;
  className?: string;
  children: ReactNode;
}) {
  const bridge = useDesktopBridge();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const onClick = async (e: MouseEvent<HTMLAnchorElement>) => {
    if (!bridge) return; // the browser handles it
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    try {
      const saved = await bridge.save_download(href, filename);
      if (saved) toast("success", `Saved to ${saved}`);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <a href={href} download={filename} className={className} onClick={onClick} aria-busy={busy || undefined}>
      {children}
    </a>
  );
}

// ------------------------------------------------------------------ toasts

interface Toast {
  id: number;
  tone: "error" | "success";
  message: string;
}

const ToastContext = createContext<(tone: Toast["tone"], message: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((tone: Toast["tone"], message: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, tone, message }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === "error" ? 6000 : 3000);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" role="status">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.tone}`}>
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

/** useMutation with error toasts, optional success toast and cache invalidation. */
export function useApiMutation<TVars, TData = unknown>(
  fn: (vars: TVars) => Promise<TData>,
  opts: {
    invalidate?: QueryKey[];
    success?: string | ((data: TData) => string);
    onSuccess?: (data: TData, vars: TVars) => void;
    onError?: (err: unknown) => void;
  } = {},
) {
  const qc = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: fn,
    onSuccess: (data, vars) => {
      opts.invalidate?.forEach((key) => qc.invalidateQueries({ queryKey: key }));
      if (opts.success) toast("success", typeof opts.success === "function" ? opts.success(data) : opts.success);
      opts.onSuccess?.(data, vars);
    },
    onError: (err) => {
      opts.onError?.(err);
      // 423 and 401 get a full-screen explanation from the VaultGate instead.
      if (err instanceof ApiError && (err.status === 423 || err.status === 401)) return;
      toast("error", err instanceof Error ? err.message : String(err));
    },
  });
}
