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
  if (typeof detail === "string") return detail.charAt(0).toUpperCase() + detail.slice(1);
  return detail
    .map((d) => {
      const field = (d.loc ?? []).filter((p) => p !== "body").join(".");
      return field ? `${field}: ${d.msg}` : d.msg;
    })
    .join("; ");
}

/** App-wide reactions to responses, registered once by the VaultGate. */
export interface ApiEvents {
  /** 423: the vault was locked underneath us (idle timeout, Lock button, app exit). */
  locked(): void;
  /** 401: the session cookie is gone. Only a fresh launch of the app can restore it. */
  sessionLost(): void;
  /** An unsafe request reached the backend, which resets its idle timer. */
  activity(): void;
}

let events: Partial<ApiEvents> = {};
export function setApiEvents(handlers: Partial<ApiEvents>) {
  events = handlers;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  // The custom header is required by the backend's CSRF protection.
  const headers: Record<string, string> = { "X-Requested-With": "OffsecHub" };
  let payload: BodyInit | undefined;
  if (body instanceof Blob) {
    // Raw request body: the backend streams it straight into the vault's encryptor.
    // Multipart would be spooled to a plaintext temp file first.
    headers["Content-Type"] = body.type || "application/octet-stream";
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  if (res.status === 401) events.sessionLost?.();
  else if (res.status === 423) events.locked?.();
  else if (method !== "GET") events.activity?.();
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

type Params = Record<string, string | number | boolean | null | undefined>;

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  del: (path: string) => request<void>("DELETE", path),
  /** Upload one file as the raw request body; metadata travels in the query string. */
  upload: <T>(path: string, file: File, params: Params = {}) =>
    request<T>("POST", `${path}${qs({ filename: file.name, ...params })}`, file),
};

export function qs(params: Params): string {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") s.set(k, String(v));
  }
  const out = s.toString();
  return out ? `?${out}` : "";
}
