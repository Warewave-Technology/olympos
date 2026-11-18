// Pretty-printer for audit tool output (kubescape / polaris / kube-bench). Kubescape logs are
// zap JSON lines ({"level":"info","ts":"…","msg":"…"}); older servers concatenated several of
// them onto one line after a prefix such as "kubescape failed: exit status 1:". Plain text
// segments (e.g. the final "Error: framework 'x' not found") are kept as text entries.

export interface LogEntry {
  kind: 'json' | 'text';
  /** Normalized: debug | info | warn | error | fatal | '' */
  level: string;
  /** ISO string or the original value. */
  time: string;
  msg: string;
  error: string;
  /** Remaining fields, in order, as display strings. */
  fields: [string, string][];
  raw: string;
}

const LEVELS: Record<string, string> = { debug: 'debug', trace: 'debug', info: 'info', information: 'info', warn: 'warn', warning: 'warn', error: 'error', err: 'error', fatal: 'fatal', panic: 'fatal', dpanic: 'fatal', critical: 'fatal' };

/** Splits text into JSON objects and the text around them (braces inside strings are respected). */
export function splitJson(line: string): (string | Record<string, unknown>)[] {
  const out: (string | Record<string, unknown>)[] = [];
  let i = 0;
  let textStart = 0;
  while (i < line.length) {
    if (line[i] !== '{') {
      i++;
      continue;
    }
    let depth = 0;
    let inStr = false;
    let j = i;
    for (; j < line.length; j++) {
      const c = line[j];
      if (inStr) {
        if (c === '\\') j++;
        else if (c === '"') inStr = false;
        continue;
      }
      if (c === '"') inStr = true;
      else if (c === '{') depth++;
      else if (c === '}' && --depth === 0) break;
    }
    if (depth !== 0 || j >= line.length) break; // unbalanced: the rest is text
    const candidate = line.slice(i, j + 1);
    try {
      const v = JSON.parse(candidate);
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        const before = line.slice(textStart, i);
        if (before.trim()) out.push(before);
        out.push(v as Record<string, unknown>);
        textStart = j + 1;
      }
    } catch {
      /* not JSON: keep scanning after this brace */
    }
    i = j + 1;
  }
  const rest = line.slice(textStart);
  if (rest.trim()) out.push(rest);
  return out;
}

function str(v: unknown): string {
  if (v === undefined || v === null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
}

function time(v: unknown): string {
  if (typeof v === 'number' && Number.isFinite(v)) {
    // zap's default epoch encoder: seconds (float); some loggers use milliseconds
    const ms = v > 1e12 ? v : v * 1000;
    return new Date(ms).toISOString();
  }
  return str(v);
}

function entryOf(o: Record<string, unknown>, raw: string): LogEntry {
  const take = (...keys: string[]) => {
    for (const k of keys) if (k in o) return { k, v: o[k] };
    return null;
  };
  const lv = take('level', 'lvl', 'severity', 'L');
  const ts = take('ts', 'time', 'timestamp', '@timestamp', 'T');
  const msg = take('msg', 'message', 'M');
  const err = take('error', 'err');
  const used = new Set([lv?.k, ts?.k, msg?.k, err?.k].filter(Boolean) as string[]);
  return {
    kind: 'json',
    level: LEVELS[str(lv?.v).toLowerCase()] ?? str(lv?.v).toLowerCase(),
    time: time(ts?.v),
    msg: str(msg?.v),
    error: str(err?.v),
    fields: Object.entries(o)
      .filter(([k]) => !used.has(k))
      .map(([k, v]) => [k, str(v)]),
    raw,
  };
}

function textEntry(t: string): LogEntry {
  const s = t.trim().replace(/:$/, '').trim();
  const m = /^(error|fatal|panic|warn(?:ing)?)\b[:\s]/i.exec(s);
  return { kind: 'text', level: m ? (LEVELS[m[1].toLowerCase()] ?? '') : '', time: '', msg: s, error: '', fields: [], raw: t };
}

/** Log text → entries, one per JSON object or text segment. */
export function parseLog(log: string | null | undefined): LogEntry[] {
  const out: LogEntry[] = [];
  for (const line of (log ?? '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    for (const seg of splitJson(line)) out.push(typeof seg === 'string' ? textEntry(seg) : entryOf(seg, JSON.stringify(seg)));
  }
  return out;
}

/** True when the log has JSON lines worth pretty-printing. */
export function isStructured(entries: LogEntry[]): boolean {
  return entries.some((e) => e.kind === 'json');
}

/** One readable line per entry ("pretty" text for copy). */
export function formatEntries(entries: LogEntry[]): string {
  return entries
    .map((e) => {
      if (e.kind === 'text') return e.msg;
      const extra = e.fields.map(([k, v]) => `${k}=${v}`).join(' ');
      return [e.time, e.level.toUpperCase(), e.msg, e.error ? `error=${e.error}` : '', extra].filter(Boolean).join('  ');
    })
    .join('\n');
}

/**
 * One-line reason for a failed run, never the raw log: prefers an "Error: …" text line, then the
 * last error-level JSON entry, then the first text segment.
 */
export function shortReason(error: string | null | undefined, max = 90): string {
  const src = (error ?? '').trim();
  if (!src) return '';
  const entries = parseLog(src);
  const texts = entries.filter((e) => e.kind === 'text');
  const errText = [...texts].reverse().find((e) => e.level === 'error' || e.level === 'fatal');
  const errJson = [...entries].reverse().find((e) => e.kind === 'json' && (e.level === 'error' || e.level === 'fatal'));
  let r = errText ? errText.msg.replace(/^error:\s*/i, '') : errJson ? errJson.error || errJson.msg : (texts[0]?.msg ?? entries[0]?.msg ?? src);
  r = r.replace(/\s+/g, ' ').trim();
  if (r.length > max) r = r.slice(0, max - 1).trimEnd() + '…';
  return r;
}

export const LEVEL_TONE: Record<string, 'mute' | 'info' | 'warn' | 'crit'> = { debug: 'mute', info: 'info', warn: 'warn', error: 'crit', fatal: 'crit' };
