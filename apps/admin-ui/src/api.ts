/**
 * Centralised fetch helpers for the admin UI.
 *
 * - Holds the current session CSRF token (set by App after login/session load).
 * - `apiMutate` sends X-CSRF-Token; on a 403 whose error code is `csrf_failed` it
 *   refreshes the token via GET /api/v1/auth/me once and retries the request once.
 * - A 401 from any helper invokes the registered unauthorized handler.
 * - `ApiError` carries the backend error envelope `{ error: { code, message, request_id, fields, users, permissions } }`;
 *   `errorMessage` turns it into a plain sentence via `copy/errors.ts`.
 */
import type { Language } from "./i18n";
import { errorSentence } from "./copy/errors";

let csrfToken = "";
let unauthorizedHandler: () => void = () => undefined;
let refreshInFlight: Promise<boolean> | null = null;

export function setCsrfToken(token: string) {
  csrfToken = token;
}

export function getCsrfToken() {
  return csrfToken;
}

export function setUnauthorizedHandler(handler: () => void) {
  unauthorizedHandler = handler;
}

export function hasPermission(permissions: readonly string[], permission: string) {
  return permissions.includes("*") || permissions.includes(permission);
}

/** Re-fetch /auth/me to obtain the current CSRF token. Concurrent callers share one request. */
export function refreshCsrf(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    try {
      const response = await fetch("/api/v1/auth/me", {
        headers: { Accept: "application/json" },
        cache: "no-store"
      });
      if (response.status === 401) {
        unauthorizedHandler();
        return false;
      }
      if (!response.ok) return false;
      const payload = (await response.json()) as { csrf_token?: string };
      if (!payload.csrf_token) return false;
      csrfToken = payload.csrf_token;
      return true;
    } catch {
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

/** Read the backend error code without consuming the response body. */
async function peekErrorCode(response: Response): Promise<string | null> {
  try {
    const payload = (await response.clone().json()) as { error?: { code?: unknown } };
    return typeof payload.error?.code === "string" ? payload.error.code : null;
  } catch {
    return null;
  }
}

type MutateOptions = {
  method?: "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
  /** Skip calling the unauthorized handler on 401 (e.g. logout). */
  silentUnauthorized?: boolean;
  /** Refresh CSRF and retry once on a `csrf_failed` 403 (default true). */
  retryOnForbidden?: boolean;
};

/** Perform a state-changing request with CSRF protection and one-shot CSRF recovery. */
export async function apiMutate(path: string, options: MutateOptions = {}): Promise<Response> {
  const { method = "POST", body, signal, silentUnauthorized = false, retryOnForbidden = true } = options;
  const send = () => {
    const headers: Record<string, string> = { Accept: "application/json", "X-CSRF-Token": csrfToken };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: "no-store",
      signal
    });
  };
  let response = await send();
  // Only a CSRF failure is worth retrying; a permission denial would just fail again.
  if (
    retryOnForbidden &&
    response.status === 403 &&
    (await peekErrorCode(response)) === "csrf_failed" &&
    (await refreshCsrf())
  ) {
    response = await send();
  }
  if (response.status === 401 && !silentUnauthorized) unauthorizedHandler();
  return response;
}

/** Perform a read request; a 401 invokes the unauthorized handler. */
export async function apiGet(path: string, signal?: AbortSignal): Promise<Response> {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    cache: "no-store",
    signal
  });
  if (response.status === 401) unauthorizedHandler();
  return response;
}

/** Rotate the session cookie (extends the session) and adopt the new CSRF token. */
export async function refreshSession(): Promise<boolean> {
  try {
    const response = await apiMutate("/api/v1/auth/refresh", { method: "POST" });
    if (!response.ok) return false;
    const payload = (await response.json()) as { csrf_token?: string };
    if (payload.csrf_token) csrfToken = payload.csrf_token;
    return true;
  } catch {
    return false;
  }
}

export function isAbortError(error: unknown) {
  return (error instanceof DOMException || error instanceof Error) && error.name === "AbortError";
}

/** One field problem of a form error (docs/34 §2): `{field, reason_code, params?}`. */
export type FieldIssue = { field: string; reason_code: string; params?: Record<string, unknown> };

/** Extra parts of the error envelope some endpoints send. */
export type ApiErrorExtras = {
  fields?: FieldIssue[];
  /** `role_in_use`: who still has the role. */
  users?: unknown[] | null;
  /** `permission_escalation`: the permissions the caller doesn't hold. */
  permissions?: string[] | null;
  requestId?: string | null;
  /** Every other key of `error` (except code/message/fields/field/reason/request_id/users/permissions). */
  extra?: Record<string, unknown>;
};

/**
 * An HTTP failure carrying the backend error envelope
 * `{error: {code, message, request_id, fields?, users?, permissions?, …}}`.
 * `field` is the first field issue (so describeError can name it); `reason` stays empty so the
 * code's own sentence is used (per-field sentences come from `fieldMessages`).
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: string;
  readonly fields: FieldIssue[];
  readonly users: unknown[] | null;
  readonly permissions: string[] | null;
  readonly requestId: string | null;
  readonly extra: Record<string, unknown>;
  readonly field?: string;
  readonly reason?: string;

  constructor(status: number, code: string, detail: string, extras: ApiErrorExtras = {}) {
    super(detail || code || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.fields = extras.fields ?? [];
    this.users = extras.users ?? null;
    this.permissions = extras.permissions ?? null;
    this.requestId = extras.requestId ?? null;
    this.extra = extras.extra ?? {};
    this.field = this.fields[0]?.field;
  }
}

const ENVELOPE_KEYS = new Set(["code", "message", "fields", "field", "reason", "request_id", "users", "permissions", "params"]);

/** Parse an error body (`{error: {...}}`) into an ApiError. */
export function apiErrorFromBody(status: number, body: unknown): ApiError {
  const error = (body && typeof body === "object" ? (body as { error?: unknown }).error : null) as Record<string, unknown> | null;
  if (!error || typeof error !== "object") return new ApiError(status, "", "");
  const code = typeof error.code === "string" ? error.code : "";
  const detail = typeof error.message === "string" ? error.message : "";
  let fields: FieldIssue[] = [];
  if (Array.isArray(error.fields)) {
    fields = (error.fields as unknown[])
      .filter((item): item is FieldIssue => typeof item === "object" && item !== null && typeof (item as FieldIssue).field === "string")
      .map((item) => ({ field: item.field, reason_code: String(item.reason_code ?? ""), params: item.params ?? undefined }));
  } else if (error.fields && typeof error.fields === "object") {
    // Some engines send `fields` as a map: {"data.address": "invalid_ip"} or {"ttl": {reason_code, params}}.
    fields = Object.entries(error.fields as Record<string, unknown>).map(([field, value]) => {
      if (value && typeof value === "object") {
        const item = value as { reason_code?: unknown; code?: unknown; params?: Record<string, unknown> };
        return { field, reason_code: String(item.reason_code ?? item.code ?? ""), params: item.params ?? undefined };
      }
      return { field, reason_code: typeof value === "string" ? value : "" };
    });
  } else if (typeof error.field === "string") {
    fields = [{ field: error.field, reason_code: typeof error.reason === "string" ? error.reason : "", params: (error.params as Record<string, unknown> | undefined) ?? undefined }];
  }
  const extra: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(error)) if (!ENVELOPE_KEYS.has(key)) extra[key] = value;
  return new ApiError(status, code, detail, {
    fields,
    users: Array.isArray(error.users) ? (error.users as unknown[]) : null,
    permissions: Array.isArray(error.permissions) ? (error.permissions as unknown[]).map(String) : null,
    requestId: typeof error.request_id === "string" ? error.request_id : null,
    extra
  });
}

export async function toApiError(response: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // non-JSON error body
  }
  return apiErrorFromBody(response.status, body);
}

/** Return the response when it is OK; otherwise throw an ApiError built from its body. */
export async function ensureOk(response: Response): Promise<Response> {
  if (response.ok) return response;
  throw await toApiError(response);
}

/** GET + ensureOk + JSON in one step. */
export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await ensureOk(await apiGet(path, signal));
  return (await response.json()) as T;
}

/** apiMutate + ensureOk; returns parsed JSON (or null for empty bodies). */
export async function mutateJson<T = unknown>(path: string, options: MutateOptions = {}): Promise<T> {
  const response = await ensureOk(await apiMutate(path, options));
  if (response.status === 204) return null as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : null) as T;
}

/**
 * Turn any thrown value into a localized, user-facing sentence.
 * The wording lives in `copy/errors.ts` (one plain sentence per backend code). The backend
 * English `detail` is never appended; FriendlyError shows it in Advanced «جزئیات فنی» only.
 */
export function errorMessage(language: Language, error: unknown): string {
  return errorSentence(language, error);
}

/** Copy text to the clipboard, falling back to a hidden textarea when the async API is unavailable. */
export async function copyText(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // fall through to the legacy path
  }
  try {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    textarea.style.insetInlineStart = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

/**
 * Client registry endpoints derived from the admin page location.
 * - Domain deployments (admin.example.org) map to sibling npm./pypi. subdomains (same scheme).
 * - IP / localhost / explicit-port deployments map to the same host on ports 4873 / 3141.
 *   Those registry ports are served by the appliance over plain HTTP, so http: is used.
 */
export function registryEndpoints(publicUrls: { npm?: string | null; pypi?: string | null } = {}) {
  const derived = derivedRegistryEndpoints();
  // docs/35 §4: a service's own public address (its main domain) wins over the guess from this page.
  const npmUrl = publicRegistryUrl(publicUrls.npm, "npm");
  const pypiUrl = publicRegistryUrl(publicUrls.pypi, "pypi");
  if (!npmUrl && !pypiUrl) return derived;
  const npm = npmUrl ?? derived.npm;
  const pypi = pypiUrl ?? derived.pypi;
  // Plain-HTTP addresses still need pip/uv "trusted host" flags (`portBased` keeps that meaning).
  const insecure = [npm, pypi].some((url) => url.startsWith("http:"));
  return { npm, pypi, portBased: insecure };
}

/** A service `public_url` → the registry address clients use (npm: `…/`, PyPI: `…/root/pypi/+simple/`). */
function publicRegistryUrl(value: string | null | undefined, kind: "npm" | "pypi"): string | null {
  const raw = (value ?? "").trim();
  if (!raw) return null;
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  const base = `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}`;
  if (kind === "npm") return `${base}/`;
  return /\/\+simple$/.test(base) ? `${base}/` : `${base}/root/pypi/+simple/`;
}

function derivedRegistryEndpoints() {
  const { protocol, hostname, port } = window.location;
  const isAddress =
    hostname === "localhost" ||
    !hostname.includes(".") ||
    hostname.includes(":") ||
    hostname.startsWith("[") ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  if (port || isAddress) {
    return {
      npm: `http://${hostname}:4873/`,
      pypi: `http://${hostname}:3141/root/pypi/+simple/`,
      portBased: true
    };
  }
  const labels = hostname.split(".");
  const base = labels.length > 2 ? labels.slice(1).join(".") : hostname;
  return {
    npm: `${protocol}//npm.${base}/`,
    pypi: `${protocol}//pypi.${base}/root/pypi/+simple/`,
    portBased: false
  };
}
