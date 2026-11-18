// Formatting helpers. All times are RFC 3339 strings from the API.

export function plural(n: number, one: string, many = one + 's'): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
}

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
/** Decimal bytes (backup sizes): 3.1 GB. */
export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  if (n < 1000) return `${n} B`;
  let i = 0;
  let v = n;
  while (v >= 1000 && i < UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1).replace(/\.0$/, '')} ${UNITS[i]}`;
}

const IUNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
/** Binary bytes (memory): 5.6 TiB. */
export function ibytes(n: number | null | undefined): string {
  if (!n) return '0 B';
  let i = 0;
  let v = n;
  while (v >= 1024 && i < IUNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1).replace(/\.0$/, '')} ${IUNITS[i]}`;
}

export function vcpu(milli: number): string {
  return `${Math.round(milli / 1000).toLocaleString('en-US')} vCPU`;
}

/** Duration in seconds → "4 m 12 s", "11 s", "2 h 5 m". */
export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || seconds < 0 || Number.isNaN(seconds)) return '—';
  const s = Math.round(seconds);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m} m ${s % 60} s` : `${m} m`;
  const h = Math.floor(m / 60);
  return m % 60 ? `${h} h ${m % 60} m` : `${h} h`;
}

export function between(start: string | null | undefined, end: string | null | undefined): number | null {
  if (!start || !end) return null;
  return (new Date(end).getTime() - new Date(start).getTime()) / 1000;
}

/** Compact age: "40 s", "5 min", "2 h", "3 days". */
export function age(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '—';
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h`;
  const d = Math.round(h / 24);
  return plural(d, 'day');
}

export function ago(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'never';
  return `${age(iso, now)} ago`;
}

/** Time left until iso: "68 h left", "12 min left", "expired". */
export function timeLeft(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '—';
  const s = Math.round((new Date(iso).getTime() - now) / 1000);
  if (s <= 0) return 'expired';
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min left`;
  if (s < 3600 * 96) return `${Math.round(s / 3600)} h left`;
  return `${Math.round(s / 86400)} days left`;
}

export function daysUntil(iso: string | null | undefined, now: number = Date.now()): number | null {
  if (!iso) return null;
  return Math.floor((new Date(iso).getTime() - now) / 86400000);
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number) => String(n).padStart(2, '0');

/** "Nov 18 16:41" (local time). */
export function dateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${MONTHS[d.getMonth()]} ${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** "Today 08:00", "Yesterday 03:30", else "Nov 16 04:00". */
export function relDateTime(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const sameDay = (a: Date, b: Date) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  const y = new Date(now);
  y.setDate(now.getDate() - 1);
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (sameDay(d, now)) return `Today ${hm}`;
  if (sameDay(d, y)) return `Yesterday ${hm}`;
  return dateTime(iso);
}

/** "Nov 30, 2026". */
export function date(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
}

/** "Oct 02". */
export function shortDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${MONTHS[d.getMonth()]} ${pad(d.getDate())}`;
}

/** "9a2f…41bd" for object IDs and digests. */
export function shortId(id: string | null | undefined, head = 4, tail = 4): string {
  if (!id) return '—';
  const raw = id.replace(/-/g, '');
  if (raw.length <= head + tail + 1) return id;
  return `${raw.slice(0, head)}…${raw.slice(-tail)}`;
}

export function shortDigest(digest: string | null | undefined): string {
  if (!digest) return '—';
  const [algo, hex] = digest.includes(':') ? digest.split(':', 2) : ['sha256', digest];
  return `${algo}:${shortId(hex)}`;
}

export function money(n: number | null | undefined, currency = 'USD'): string {
  if (n === null || n === undefined) return '—';
  return `${n.toFixed(2)} ${currency}`;
}

export function capitalize(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

export const ENGINE_LABEL: Record<string, string> = {
  postgresql: 'PostgreSQL',
  clickhouse: 'ClickHouse',
  vault: 'Vault',
  openbao: 'OpenBao',
};

export function engineLabel(engine: string, version?: string, provider?: string): string {
  let name = ENGINE_LABEL[engine] ?? engine;
  if (engine === 'vault' && provider === 'openbao') name = 'OpenBao';
  return version ? `${name} ${version}` : name;
}

/** Display name for a principal: UPN when known, else display name, else object ID. */
export function personName(p: { upn?: string; display_name?: string; object_id?: string } | null | undefined): string {
  if (!p) return '—';
  return p.upn || p.display_name || shortId(p.object_id);
}
