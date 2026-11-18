import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api, buildUrl, loginUrl, nav, readCookie, request } from '../api/client';

function jsonResponse(status: number, body?: unknown) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

describe('fetch wrapper', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    document.cookie = 'olympos_csrf=tok-123; path=/';
    nav.reset();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    document.cookie = 'olympos_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
  });

  it('reads the CSRF cookie', () => {
    expect(readCookie('olympos_csrf', 'a=1; olympos_csrf=abc%3D; b=2')).toBe('abc=');
    expect(readCookie('missing', 'a=1')).toBe('');
  });

  it('sends X-CSRF-Token on state-changing requests, same-origin credentials', async () => {
    fetchMock.mockResolvedValue(jsonResponse(201, { ok: true }));
    await api.post('/grants', { object_id: 'x' });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/grants');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('same-origin');
    expect(init.headers['X-CSRF-Token']).toBe('tok-123');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(init.body)).toEqual({ object_id: 'x' });
  });

  it.each(['PATCH', 'PUT', 'DELETE'] as const)('sends the CSRF header on %s', async (method) => {
    fetchMock.mockResolvedValue(jsonResponse(204));
    await request('/clusters/1', { method, body: method === 'DELETE' ? undefined : {} });
    expect(fetchMock.mock.calls[0][1].headers['X-CSRF-Token']).toBe('tok-123');
  });

  it('does not send the CSRF header on GET', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { items: [] }));
    await api.get('/clusters', { status: 'online', empty: '' });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/clusters?status=online');
    expect(init.headers['X-CSRF-Token']).toBeUndefined();
    expect(init.credentials).toBe('same-origin');
  });

  it('redirects to /login with return_to on 401', async () => {
    const spy = vi.spyOn(nav, 'toLogin').mockImplementation(() => {});
    window.history.pushState({}, '', '/vaults?vault=abc');
    fetchMock.mockResolvedValue(jsonResponse(401, { error: 'session expired' }));
    await expect(api.get('/vaults')).rejects.toMatchObject({ status: 401 });
    expect(spy).toHaveBeenCalledWith('/vaults?vault=abc');
    expect(loginUrl('/vaults?vault=abc')).toBe('/login?return_to=%2Fvaults%3Fvault%3Dabc');
  });

  it('does not redirect when noRedirect is set', async () => {
    const spy = vi.spyOn(nav, 'toLogin').mockImplementation(() => {});
    fetchMock.mockResolvedValue(jsonResponse(401, { error: 'not signed in' }));
    await expect(request('/me', { noRedirect: true })).rejects.toBeInstanceOf(ApiError);
    expect(spy).not.toHaveBeenCalled();
  });

  it('never builds an off-site return_to', () => {
    expect(loginUrl('//evil.example/x')).toBe('/login?return_to=%2F');
    expect(loginUrl('https://evil.example')).toBe('/login?return_to=%2F');
    expect(loginUrl('/login?x=1')).toBe('/login?return_to=%2F');
  });

  it('surfaces {error, fields} as ApiError', async () => {
    fetchMock.mockResolvedValue(jsonResponse(422, { error: 'invalid grant', fields: { roles: 'Select at least one role.' } }));
    const err = (await api.post('/grants', {}).catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(422);
    expect(err.message).toBe('invalid grant');
    expect(err.fields.roles).toBe('Select at least one role.');
  });

  it('gives a readable message when the server is unreachable', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
    const err = (await api.get('/me').catch((e) => e)) as ApiError;
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/Could not reach the Olympos server/);
  });

  it('keeps absolute /auth paths', () => {
    expect(buildUrl('/auth/logout')).toBe('/auth/logout');
  });
});
