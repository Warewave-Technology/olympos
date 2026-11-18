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

/** "env=prod, team=data" ↔ {env: "prod", team: "data"} */
export function parseLabels(src: string): { labels: Record<string, string>; error: string | null } {
  const labels: Record<string, string> = {};
  const re = /^[A-Za-z0-9]([A-Za-z0-9._/-]{0,62})?$/;
  for (const part of src.split(',').map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf('=');
    if (i <= 0) return { labels, error: `"${part}" is not key=value` };
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (!re.test(k)) return { labels, error: `Label key "${k}" is not valid` };
    if (v && !/^[A-Za-z0-9]([A-Za-z0-9._-]{0,62})?$/.test(v)) return { labels, error: `Label value "${v}" is not valid` };
    labels[k] = v;
  }
  return { labels, error: null };
}

export function formatLabels(labels: Record<string, string> | null | undefined): string {
  return Object.entries(labels ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');
}

/** Very small label-selector matcher for "env=prod,team=data" (equality only), used for scope previews. */
export function matchesSelector(selector: string, labels: Record<string, string>): boolean {
  const s = selector.trim();
  if (s === '' || s === 'all') return true;
  return s
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean)
    .every((p) => {
      const ne = p.split('!=');
      if (ne.length === 2) return labels[ne[0].trim()] !== ne[1].trim();
      const [k, v] = p.split('=').map((x) => x.trim());
      return v === undefined ? k in labels : labels[k] === v;
    });
}
