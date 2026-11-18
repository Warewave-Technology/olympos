// Kubernetes label syntax (https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
// and a small label-selector parser used for scope previews (equality and set-based terms).

const NAME = /^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$/;
const DNS_SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;

/** null when valid, else a sentence explaining what is wrong. */
export function validateLabelKey(key: string): string | null {
  if (!key) return 'The label key is empty.';
  const slash = key.indexOf('/');
  let name = key;
  if (slash >= 0) {
    const prefix = key.slice(0, slash);
    name = key.slice(slash + 1);
    if (!prefix) return `Label key "${key}" has an empty prefix before "/".`;
    if (prefix.length > 253 || !DNS_SUBDOMAIN.test(prefix)) return `Label key prefix "${prefix}" must be a DNS subdomain (lowercase letters, digits, "-" and ".").`;
    if (name.includes('/')) return `Label key "${key}" may contain only one "/".`;
  }
  if (!name) return `Label key "${key}" has an empty name after "/".`;
  if (name.length > 63) return `Label key name "${name}" is longer than 63 characters.`;
  if (!NAME.test(name)) return `Label key "${key}" may use letters, digits, "-", "_" and ".", and must start and end with a letter or digit.`;
  return null;
}

export function validateLabelValue(value: string): string | null {
  if (value === '') return null;
  if (value.length > 63) return `Label value "${value}" is longer than 63 characters.`;
  if (!NAME.test(value)) return `Label value "${value}" may use letters, digits, "-", "_" and ".", and must start and end with a letter or digit.`;
  return null;
}

export type LabelTerm = { ok: true; key: string; value: string } | { ok: false; error: string };

/** Parses one "key=value" term. */
export function parseLabelTerm(raw: string): LabelTerm {
  const t = raw.trim();
  const i = t.indexOf('=');
  if (i < 0) return { ok: false, error: `"${t}" is not key=value.` };
  if (t[i + 1] === '=' || t[i - 1] === '!') return { ok: false, error: `"${t}": use a single "=" (key=value).` };
  const key = t.slice(0, i).trim();
  const value = t.slice(i + 1).trim();
  const ke = validateLabelKey(key);
  if (ke) return { ok: false, error: ke };
  const ve = validateLabelValue(value);
  if (ve) return { ok: false, error: ve };
  return { ok: true, key, value };
}

/** Splits pasted text such as "a=b,c=d" or "a=b c=d" into terms. */
export function splitTerms(text: string): string[] {
  return text
    .split(/[,;\n\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** "env=prod, team=data" ↔ {env: "prod", team: "data"} */
export function parseLabels(src: string): { labels: Record<string, string>; error: string | null } {
  const labels: Record<string, string> = {};
  for (const part of src.split(',').map((s) => s.trim()).filter(Boolean)) {
    const t = parseLabelTerm(part);
    if (!t.ok) return { labels, error: t.error.replace(/\.$/, '') };
    labels[t.key] = t.value;
  }
  return { labels, error: null };
}

export function formatLabels(labels: Record<string, string> | null | undefined, sep = ', '): string {
  return Object.entries(labels ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(sep);
}

// ------------------------------------------------------------ selectors

export type SelectorReq =
  | { op: '='; key: string; value: string }
  | { op: '!='; key: string; value: string }
  | { op: 'in'; key: string; values: string[] }
  | { op: 'notin'; key: string; values: string[] }
  | { op: 'exists'; key: string }
  | { op: '!'; key: string };

/** Splits on commas outside parentheses. */
function splitTop(s: string): string[] | null {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (depth < 0) return null;
    if (ch === ',' && depth === 0) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (depth !== 0) return null;
  out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}

/** Parses a label selector ("env=prod,tier in (a,b),!legacy"). "" and "all" select everything. */
export function parseSelector(src: string): { reqs: SelectorReq[]; error: string | null } {
  const s = src.trim();
  if (s === '' || s === 'all') return { reqs: [], error: null };
  const parts = splitTop(s);
  if (!parts) return { reqs: [], error: 'Unbalanced parentheses.' };
  const reqs: SelectorReq[] = [];
  for (const p of parts) {
    let m = /^(\S+?)\s+(in|notin)\s*\(([^)]*)\)$/.exec(p);
    if (m) {
      const values = m[3].split(',').map((v) => v.trim()).filter(Boolean);
      const bad = validateLabelKey(m[1]) ?? values.map(validateLabelValue).find(Boolean) ?? (values.length ? null : `"${p}" needs at least one value.`);
      if (bad) return { reqs: [], error: bad };
      reqs.push({ op: m[2] as 'in' | 'notin', key: m[1], values });
      continue;
    }
    m = /^([^!=\s]+)\s*(==|=|!=)\s*(\S*)$/.exec(p);
    if (m) {
      const bad = validateLabelKey(m[1]) ?? validateLabelValue(m[3]);
      if (bad) return { reqs: [], error: bad };
      reqs.push({ op: m[2] === '!=' ? '!=' : '=', key: m[1], value: m[3] });
      continue;
    }
    m = /^(!?)\s*([^\s!=()]+)$/.exec(p);
    if (m) {
      const bad = validateLabelKey(m[2]);
      if (bad) return { reqs: [], error: bad };
      reqs.push(m[1] ? { op: '!', key: m[2] } : { op: 'exists', key: m[2] });
      continue;
    }
    return { reqs: [], error: `"${p}" is not a valid selector term.` };
  }
  return { reqs, error: null };
}

export function matchReqs(reqs: SelectorReq[], labels: Record<string, string>): boolean {
  return reqs.every((r) => {
    const has = Object.prototype.hasOwnProperty.call(labels, r.key);
    switch (r.op) {
      case '=':
        return has && labels[r.key] === r.value;
      case '!=':
        return !has || labels[r.key] !== r.value;
      case 'in':
        return has && r.values.includes(labels[r.key]);
      case 'notin':
        return !has || !r.values.includes(labels[r.key]);
      case 'exists':
        return has;
      case '!':
        return !has;
    }
  });
}

/** True when `labels` match `selector`. An invalid selector matches nothing. */
export function matchesSelector(selector: string, labels: Record<string, string>): boolean {
  const p = parseSelector(selector);
  if (p.error) return false;
  return matchReqs(p.reqs, labels ?? {});
}

/** When the selector only has key=value terms, returns them as a map (for chip mode); else null. */
export function equalityTerms(selector: string): Record<string, string> | null {
  const p = parseSelector(selector);
  if (p.error) return null;
  const out: Record<string, string> = {};
  for (const r of p.reqs) {
    if (r.op !== '=' || r.key in out) return null;
    out[r.key] = r.value;
  }
  return out;
}

/** Labels set by users: drops the reserved olympos.io/ keys (e.g. olympos.io/cluster), which repeat the name. */
export function userLabels(labels: Record<string, string> | undefined | null): [string, string][] {
  return Object.entries(labels ?? {}).filter(([k]) => !k.startsWith('olympos.io/'));
}
