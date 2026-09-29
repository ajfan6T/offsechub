import { useEffect, useState } from "react";

/**
 * Native dialogs exposed by the desktop shell (backend/app/desktop.py) through
 * pywebview's JS bridge. Everything else goes over the local HTTP API, so the
 * bridge stays this small on purpose.
 */
export interface DesktopBridge {
  /** "Choose folder" dialog. Resolves to a directory path, or null if cancelled. */
  pick_folder(): Promise<string | null>;
  /** "Open vault" dialog. Resolves to an existing *.ohvault directory, or null. */
  pick_vault(): Promise<string | null>;
}

declare global {
  interface Window {
    pywebview?: { api?: Partial<DesktopBridge> };
  }
}

function currentBridge(): DesktopBridge | null {
  const bridge = window.pywebview?.api;
  return typeof bridge?.pick_folder === "function" && typeof bridge.pick_vault === "function"
    ? (bridge as DesktopBridge)
    : null;
}

/**
 * The native bridge, or null outside the desktop shell (--browser mode, Vite dev).
 * pywebview injects its API asynchronously and announces it with `pywebviewready`,
 * so callers re-render once it arrives. Until then, and without it, plain text
 * inputs are the fallback.
 */
export function useDesktopBridge(): DesktopBridge | null {
  const [bridge, setBridge] = useState(currentBridge);
  useEffect(() => {
    if (bridge) return;
    const onReady = () => setBridge(currentBridge());
    window.addEventListener("pywebviewready", onReady);
    return () => window.removeEventListener("pywebviewready", onReady);
  }, [bridge]);
  return bridge;
}

/** Join a directory and a file name using the directory's own separator. */
export function joinPath(dir: string, name: string): string {
  const sep = dir.includes("\\") && !dir.includes("/") ? "\\" : "/";
  const trimmed = dir.replace(/[\\/]+$/, "");
  return `${trimmed || sep}${trimmed ? sep : ""}${name}`;
}

/** Make a vault name safe to use as a file name on Windows, macOS and Linux. */
export function safeFileName(name: string): string {
  return name
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, "-")
    .replace(/^[\s.]+|[\s.]+$/g, "");
}
