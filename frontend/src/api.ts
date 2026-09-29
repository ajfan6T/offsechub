export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

type Detail = string | { loc?: (string | number)[]; msg: string }[] | undefined;

function formatDetail(detail: Detail, fallback: string): string {
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  return detail
    .map((d) => {
      const field = (d.loc ?? []).filter((p) => p !== "body").join(".");
      return field ? `${field}: ${d.msg}` : d.msg;
    })
    .join("; ");
}

let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  // The custom header is required by the backend's CSRF protection.
  const headers: Record<string, string> = { "X-Requested-With": "OffsecHub" };
  let payload: BodyInit | undefined;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  if (res.status === 401 && !path.startsWith("/api/auth/")) onUnauthorized?.();
  if (!res.ok) {
    let message = res.statusText || `HTTP ${res.status}`;
    try {
      message = formatDetail((await res.json()).detail, message);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message);
  }
  if (res.status === 204) return undefined as T;
  const ctype = res.headers.get("content-type") ?? "";
  return (ctype.includes("application/json") ? res.json() : res.text()) as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  del: (path: string) => request<void>("DELETE", path),
};

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") s.set(k, String(v));
  }
  const out = s.toString();
  return out ? `?${out}` : "";
}
