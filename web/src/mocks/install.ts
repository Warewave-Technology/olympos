// DEV-ONLY fetch interceptor. Enabled by VITE_MOCK (see main.tsx):
//   VITE_MOCK=1         every /api/v1 call is answered from fixtures (no server needed)
//   VITE_MOCK=fallback  endpoints the backend already implements go to the real server
//                       (through the Vite proxy); the rest are answered from fixtures
// Switch the mocked role: localStorage.setItem('olympos.mock.role', 'viewer' | 'operator' | 'maker' | 'approver' | 'admin')
// Empty states: localStorage.setItem('olympos.mock.noImages', '1')  (no images; Scan now answers 409)
//               localStorage.setItem('olympos.mock.noMounts', '1')  (GET /destinations/mounts is empty)
import { match } from './handlers';

/** Backend modules not implemented yet (M2–M5). In fallback mode only these are mocked. */
const UNIMPLEMENTED = ['/backup/', '/destinations', '/vaults', '/change-requests', '/audit/', '/findings', '/images', '/security/', '/registries', '/notifications/'];

export function installMocks(mode: string) {
  const realFetch = window.fetch.bind(window);
  const full = mode !== 'fallback';
  // eslint-disable-next-line no-console
  console.info(`[olympos] mock API enabled (${full ? 'all endpoints' : 'unimplemented endpoints only'})`);

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, window.location.origin);
    const method = (init?.method ?? 'GET').toUpperCase();

    if (url.pathname === '/auth/logout' && full) {
      localStorage.setItem('olympos.mock.signedOut', '1');
      return new Response(null, { status: 204 });
    }
    if (!url.pathname.startsWith('/api/v1/')) return realFetch(input, init);
    const path = url.pathname.slice('/api/v1'.length);
    if (!full && !UNIMPLEMENTED.some((p) => path.startsWith(p))) return realFetch(input, init);
    if (full && localStorage.getItem('olympos.mock.signedOut') === '1') {
      return json(401, { error: 'not signed in' });
    }

    await new Promise((r) => setTimeout(r, 120 + Math.random() * 200));
    const m = match(method, path);
    if (!m) return json(404, { error: 'not found' });
    let body: unknown = undefined;
    if (typeof init?.body === 'string') {
      try {
        body = JSON.parse(init.body);
      } catch {
        return json(400, { error: 'invalid JSON' });
      }
    }
    if (method !== 'GET') {
      const h = new Headers(init?.headers);
      if (!h.get('X-CSRF-Token') && full) return json(403, { error: 'missing or invalid CSRF token' });
    }
    const res = await m.h({ method, path, query: url.searchParams, body }, m.params);
    return res.status === 204 || res.status === 202 && res.body === undefined ? new Response(null, { status: res.status === 202 ? 202 : 204 }) : json(res.status, res.body);
  };

  if (full && !document.cookie.includes('olympos_csrf=')) document.cookie = 'olympos_csrf=mock-csrf; path=/; SameSite=Strict';
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body ?? {}), { status, headers: { 'Content-Type': 'application/json' } });
}
