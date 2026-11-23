// "Copy as curl" for a synthetic HTTP step (docs/design/monitoring-run.html). The credential's value never
// reaches the browser: its place is taken by shell variables the user sets themselves ($TOKEN, $USERNAME,
// $PASSWORD). Variables from earlier steps (${item}) are left as they are.
import type { ScenarioStep, SyntheticCredentialRef } from '../api/types';

/** Single-quoted for a POSIX shell: nothing inside is expanded. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The header a credential of this kind is sent in (its value before $TOKEN), or null for basic (curl -u). */
function credentialHeader(cred: Pick<SyntheticCredentialRef, 'kind' | 'header_name'>): { name: string; prefix: string } | null {
  switch (cred.kind) {
    case 'basic':
      return null;
    case 'header':
      return { name: cred.header_name || 'X-Api-Key', prefix: '' };
    default:
      // bearer and oauth2_client_credentials: the probe sends the token (or the token it fetched) as a bearer
      return { name: 'Authorization', prefix: 'Bearer ' };
  }
}

/**
 * The curl command of an HTTP step. `cred` defaults to the step's own credential reference. Returns '' for a step
 * that is not HTTP. Headers and body that are hidden from the caller (null) are left out.
 */
export function toCurl(step: ScenarioStep, cred?: Pick<SyntheticCredentialRef, 'kind' | 'header_name'> | null): string {
  const h = step.http;
  if (step.kind !== 'http' || !h) return '';
  const c = cred ?? step.credential ?? null;
  const parts: string[] = ['curl'];
  if (h.method === 'HEAD') parts.push('--head');
  else if (h.method && h.method !== 'GET') parts.push('-X', h.method);
  if (h.follow_redirects) parts.push('-L', '--max-redirs', '5');
  parts.push(shellQuote(h.url));
  const credHeader = c ? credentialHeader(c) : null;
  const headers = Object.entries(h.headers ?? {});
  for (const [name, value] of headers) {
    // the credential's own header is always the variable, whatever the step says
    if (credHeader && name.toLowerCase() === credHeader.name.toLowerCase()) continue;
    parts.push('-H', shellQuote(`${name}: ${value}`));
  }
  // the name and prefix single-quoted (nothing in them expands), the token a shell variable: 'X-Api-Key: '"$TOKEN"
  if (credHeader) parts.push('-H', `${shellQuote(`${credHeader.name}: ${credHeader.prefix}`)}"$TOKEN"`);
  if (c?.kind === 'basic') parts.push('-u', '"$USERNAME:$PASSWORD"');
  if (h.body) {
    if (h.body_type === 'json' && !headers.some(([n]) => n.toLowerCase() === 'content-type')) parts.push('-H', shellQuote('Content-Type: application/json'));
    parts.push('--data-raw', shellQuote(h.body));
  }
  return parts.join(' ');
}
