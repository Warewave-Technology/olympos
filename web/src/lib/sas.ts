// Client-side SAS token inspection (SPEC §10.3) for instant feedback while typing.
// Only non-secret parameters are read (sp, se, sr, ss, srt); the signature is ignored
// and nothing parsed here is ever stored.

export const REQUIRED_SAS = ['r', 'c', 'w', 't'] as const;
export const FORBIDDEN_SAS = ['d', 'l'] as const;

export interface SasCheck {
  valid: boolean;
  permissions: string[];
  missing: string[];
  extra: string[];
  scope: 'container' | 'account' | 'service' | 'unknown';
  expiresAt: string | null;
  expired: boolean;
  daysLeft: number | null;
}

export function parseSas(token: string, now: number = Date.now()): SasCheck {
  const raw = token.trim().replace(/^\?/, '');
  const q = new URLSearchParams(raw.includes('?') ? raw.slice(raw.indexOf('?') + 1) : raw);
  const sp = q.get('sp') ?? '';
  const perms = Array.from(new Set(sp.split('').filter(Boolean)));
  const se = q.get('se');
  const exp = se ? new Date(se) : null;
  const expMs = exp && !Number.isNaN(exp.getTime()) ? exp.getTime() : null;
  let scope: SasCheck['scope'] = 'unknown';
  if (q.get('srt') || q.get('ss')) scope = 'account';
  else if (q.get('sr') === 'c') scope = 'container';
  else if (q.get('sr')) scope = 'service';
  return {
    valid: sp !== '' && q.has('sig'),
    permissions: perms,
    missing: REQUIRED_SAS.filter((p) => !perms.includes(p)),
    extra: FORBIDDEN_SAS.filter((p) => perms.includes(p)),
    scope,
    expiresAt: expMs !== null ? new Date(expMs).toISOString() : null,
    expired: expMs !== null && expMs <= now,
    daysLeft: expMs !== null ? Math.floor((expMs - now) / 86400000) : null,
  };
}

// Label helpers moved to ./labels (Kubernetes label syntax); re-exported for existing imports.
export { formatLabels, matchesSelector, parseLabels } from './labels';
