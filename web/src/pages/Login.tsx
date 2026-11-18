import { useEffect } from 'react';
import { request } from '../api/client';
import type { Me } from '../api/types';
import logoUrl from '../assets/logo.svg';
import { loginRoute } from '../router';
import { IconMicrosoft } from '../ui/icons';

const ERRORS: Record<string, { title: string; body: string }> = {
  no_access: {
    title: 'You do not have access to Olympos yet',
    body: 'Your sign-in worked, but no Olympos admin has granted your account a role. Ask an admin to add you in Settings › Access, then sign in again.',
  },
  token: {
    title: 'Sign-in was rejected',
    body: 'The Entra ID token did not pass validation (for example it came from another tenant, or it expired). Sign in with an account from your organization’s tenant.',
  },
  state: {
    title: 'Sign-in expired',
    body: 'The sign-in took longer than 10 minutes or was started in another tab. Start again.',
  },
  idp_unavailable: {
    title: 'Microsoft Entra ID is not reachable',
    body: 'The Olympos server could not reach login.microsoftonline.com. Try again in a moment; if it keeps failing, check the server’s outbound network access.',
  },
  idp_error: {
    title: 'Microsoft Entra ID refused the sign-in',
    body: 'Your account may not be assigned to the Olympos enterprise app (assignment is required). Ask your Entra ID admin to assign you.',
  },
  exchange: {
    title: 'Sign-in could not be completed',
    body: 'Exchanging the authorization code with Entra ID failed. Start again; if it keeps failing, check the app registration’s redirect URL.',
  },
  server: {
    title: 'The server could not complete sign-in',
    body: 'The OIDC client secret could not be read from Key Vault. An operator should check the server logs and its managed identity.',
  },
  sso_not_configured: {
    title: 'Single sign-on is not configured',
    body: 'This server has no Entra ID settings. An operator must set olympos.entra in the server configuration.',
  },
};

export function LoginPage() {
  const { error, return_to } = loginRoute.useSearch();
  const returnTo = return_to && return_to.startsWith('/') && !return_to.startsWith('//') ? return_to : '/';
  const err = error ? ERRORS[error] ?? { title: 'Sign-in failed', body: 'Something went wrong during sign-in. Start again.' } : null;

  // Already signed in? Go straight back.
  useEffect(() => {
    if (error) return;
    let cancelled = false;
    request<Me>('/me', { noRedirect: true })
      .then(() => {
        if (!cancelled) window.location.replace(returnTo);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [error, returnTo]);

  // Full fixture mode has no server to sign in against; fallback mode uses the real /auth.
  const mock = import.meta.env.VITE_MOCK === '1';
  const href = mock ? returnTo : `/auth/login?return_to=${encodeURIComponent(returnTo)}`;

  return (
    <div className="fullpage">
      <main className="login">
        <div className="logo">
          <img src={logoUrl} alt="" width={96} height={84} />
          <span className="wordmark">olympos</span>
          <span className="mono tagline">KUBERNETES FLEET CONTROL</span>
        </div>
        <section className="card" aria-labelledby="signin-t">
          <h1 id="signin-t">Sign in</h1>
          {err && (
            <div className="note crit" role="alert">
              <div className="note-title">{err.title}</div>
              <div>{err.body}</div>
            </div>
          )}
          <a
            className="btn pri"
            href={href}
            onClick={() => {
              if (import.meta.env.VITE_MOCK === '1') localStorage.removeItem('olympos.mock.signedOut');
            }}
          >
            <IconMicrosoft />
            Sign in with Microsoft
          </a>
          <p className="muted" style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55 }}>
            Only accounts from your organization’s Entra ID tenant that an Olympos admin has granted access can sign in.
          </p>
          {import.meta.env.DEV && !mock && (
            <p className="muted small" style={{ margin: 0 }}>
              Development server:{' '}
              <a href={`/auth/dev-login?oid=00000000-0000-0000-0000-00000000ad01&name=Dev%20Admin&upn=dev.admin%40olympos.local&return_to=${encodeURIComponent(returnTo)}`}>
                sign in as Dev Admin
              </a>
            </p>
          )}
        </section>
        <p className="muted small" style={{ margin: 0 }}>
          Olympos {__APP_VERSION__} · self-hosted
        </p>
      </main>
    </div>
  );
}
