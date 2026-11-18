// Fetch wrapper for the Olympos BFF API (docs/openapi.yaml).
// - same-origin cookies only (the SPA never sees tokens)
// - X-CSRF-Token from the olympos_csrf cookie on every state-changing request
// - 401 → full-page redirect to /login?return_to=<current path>
// - errors shaped {error, fields} become ApiError with field messages

export const API_BASE = '/api/v1';
export const CSRF_COOKIE = 'olympos_csrf';
export const CSRF_HEADER = 'X-CSRF-Token';

export class ApiError extends Error {
  readonly status: number;
  readonly fields: Record<string, string>;
  constructor(status: number, message: string, fields: Record<string, string> = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fields = fields;
  }
  get isForbidden() {
    return this.status === 403;
  }
  get isNotFound() {
    return this.status === 404;
  }
}

export function readCookie(name: string, cookieString: string = typeof document === 'undefined' ? '' : document.cookie): string {
  for (const part of cookieString.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}

/** Current SPA location as a same-origin relative path (used for return_to). */
export function currentPath(): string {
  const { pathname, search, hash } = window.location;
  return pathname + search + hash;
}

export function loginUrl(returnTo: string): string {
  const safe = returnTo.startsWith('/') && !returnTo.startsWith('//') && !returnTo.startsWith('/login') ? returnTo : '/';
  return '/login?return_to=' + encodeURIComponent(safe);
}

let redirecting = false;
/** Navigates to the login page. Exposed for tests. */
export const nav = {
  toLogin(returnTo: string) {
    if (redirecting) return;
    redirecting = true;
    window.location.assign(loginUrl(returnTo));
  },
  reset() {
    redirecting = false;
  },
};

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  signal?: AbortSignal;
  /** Do not redirect to /login on 401 (e.g. the login page probing /me). */
  noRedirect?: boolean;
}

export function buildUrl(path: string, query?: RequestOptions['query']): string {
  const url = (path.startsWith('/api/') || path.startsWith('/auth/') ? path : API_BASE + path);
  if (!query) return url;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue;
    qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `${url}?${s}` : url;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  let body: BodyInit | undefined;
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  if (MUTATING.has(method)) {
    const csrf = readCookie(CSRF_COOKIE);
    if (csrf) headers[CSRF_HEADER] = csrf;
  }
  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), { method, headers, body, credentials: 'same-origin', signal: opts.signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    throw new ApiError(0, 'Could not reach the Olympos server. Check your network connection and try again.');
  }
  if (res.status === 401) {
    if (!opts.noRedirect) nav.toLogin(currentPath());
    throw new ApiError(401, 'Your session has ended. Sign in again.');
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
  }
  if (!res.ok) {
    const d = (data ?? {}) as { error?: string; fields?: Record<string, string> };
    throw new ApiError(res.status, d.error || defaultMessage(res.status), d.fields ?? {});
  }
  return data as T;
}

function defaultMessage(status: number): string {
  if (status === 403) return 'Your role does not allow this action.';
  if (status === 404) return 'Not found, or outside your access scope.';
  if (status === 409) return 'This conflicts with the current state. Reload and try again.';
  if (status === 422) return 'Some fields are not valid.';
  if (status >= 500) return 'The Olympos server failed to handle the request. Try again; if it keeps failing, check the server logs.';
  return `Request failed (${status}).`;
}

export const api = {
  get: <T>(path: string, query?: RequestOptions['query'], signal?: AbortSignal) => request<T>(path, { query, signal }),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: body ?? {} }),
  patch: <T>(path: string, body: unknown) => request<T>(path, { method: 'PATCH', body }),
  put: <T>(path: string, body: unknown) => request<T>(path, { method: 'PUT', body }),
  del: <T = void>(path: string) => request<T>(path, { method: 'DELETE' }),
};

/** Ends the BFF session. /auth/logout is outside /api/v1 but still gets the CSRF header. */
export async function logout(): Promise<void> {
  try {
    await request<void>('/auth/logout', { method: 'POST', noRedirect: true });
  } catch {
    /* even if the server is gone, leave the app */
  }
  window.location.assign('/login');
}

/** Human message for any thrown error. */
export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return 'Something went wrong.';
}
