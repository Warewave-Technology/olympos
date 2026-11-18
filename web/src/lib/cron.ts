// Cron helpers for the schedule UI. The server is the authority on schedules
// (/backup/schedule-preview); these give instant feedback and power the mocks.
// Supports standard 5-field cron: minute hour day-of-month month day-of-week,
// with *, lists (1,2), ranges (1-5) and steps (*/6, 0-30/10). Sunday = 0 or 7.

export interface CronPreset {
  id: string;
  label: string;
  cron: string;
}

export const CRON_PRESETS: CronPreset[] = [
  { id: 'hourly', label: 'Hourly', cron: '0 * * * *' },
  { id: '6h', label: 'Every 6 h', cron: '0 */6 * * *' },
  { id: 'daily', label: 'Daily 02:00', cron: '0 2 * * *' },
  { id: 'weekly', label: 'Weekly Sun 03:00', cron: '0 3 * * 0' },
];

export function presetFor(cron: string): CronPreset | undefined {
  const n = normalize(cron);
  return CRON_PRESETS.find((p) => p.cron === n);
}

export function normalize(cron: string): string {
  return cron.trim().split(/\s+/).join(' ');
}

interface Field {
  min: number;
  max: number;
}
const FIELDS: Field[] = [
  { min: 0, max: 59 },
  { min: 0, max: 23 },
  { min: 1, max: 31 },
  { min: 1, max: 12 },
  { min: 0, max: 7 },
];
const NAMES = ['minute', 'hour', 'day of month', 'month', 'day of week'];

export interface ParsedCron {
  minutes: Set<number>;
  hours: Set<number>;
  days: Set<number>;
  months: Set<number>;
  weekdays: Set<number>;
  domStar: boolean;
  dowStar: boolean;
}

export class CronError extends Error {}

function parseField(src: string, f: Field, name: string): Set<number> {
  const out = new Set<number>();
  for (const part of src.split(',')) {
    const [rangeSrc, stepSrc] = part.split('/');
    const step = stepSrc === undefined ? 1 : Number(stepSrc);
    if (!Number.isInteger(step) || step < 1) throw new CronError(`Invalid step in ${name}: "${part}"`);
    let lo: number;
    let hi: number;
    if (rangeSrc === '*') {
      lo = f.min;
      hi = f.max;
    } else if (rangeSrc.includes('-')) {
      const [a, b] = rangeSrc.split('-').map(Number);
      lo = a;
      hi = b;
    } else {
      lo = Number(rangeSrc);
      hi = stepSrc === undefined ? lo : f.max;
    }
    if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < f.min || hi > f.max || lo > hi) {
      throw new CronError(`Invalid ${name}: "${part}" (allowed ${f.min}–${f.max})`);
    }
    for (let v = lo; v <= hi; v += step) out.add(v);
  }
  return out;
}

export function parseCron(cron: string): ParsedCron {
  const parts = normalize(cron).split(' ');
  if (parts.length !== 5 || parts[0] === '') {
    throw new CronError('A cron expression has 5 fields: minute hour day-of-month month day-of-week');
  }
  const sets = parts.map((p, i) => parseField(p, FIELDS[i], NAMES[i]));
  const weekdays = new Set([...sets[4]].map((d) => (d === 7 ? 0 : d)));
  return {
    minutes: sets[0],
    hours: sets[1],
    days: sets[2],
    months: sets[3],
    weekdays,
    domStar: parts[2] === '*',
    dowStar: parts[4] === '*',
  };
}

export function validateCron(cron: string): string | null {
  try {
    parseCron(cron);
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}

interface WallClock {
  year: number;
  month: number; // 1-12
  day: number;
  hour: number;
  minute: number;
  weekday: number; // 0 = Sunday
}

const WD: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
const fmtCache = new Map<string, Intl.DateTimeFormat>();
function wallClock(t: number, timeZone: string): WallClock {
  let f = fmtCache.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      weekday: 'short',
    });
    fmtCache.set(timeZone, f);
  }
  const p: Record<string, string> = {};
  for (const part of f.formatToParts(new Date(t))) p[part.type] = part.value;
  return {
    year: Number(p.year),
    month: Number(p.month),
    day: Number(p.day),
    hour: Number(p.hour) % 24,
    minute: Number(p.minute),
    weekday: WD[p.weekday] ?? 0,
  };
}

function dayMatches(c: ParsedCron, w: WallClock): boolean {
  const dom = c.days.has(w.day);
  const dow = c.weekdays.has(w.weekday);
  // Vixie cron semantics: if both are restricted, either may match.
  if (!c.domStar && !c.dowStar) return dom || dow;
  if (!c.domStar) return dom;
  if (!c.dowStar) return dow;
  return true;
}

/** Next `count` run instants (ISO) strictly after `from`, evaluated in `timeZone`. */
export function nextRuns(cron: string, count = 5, from: Date = new Date(), timeZone = 'UTC'): string[] {
  const c = parseCron(cron);
  const out: string[] = [];
  const MIN = 60_000;
  let t = Math.floor(from.getTime() / MIN) * MIN + MIN;
  const limit = t + 400 * 86400_000 * 2; // two years
  while (out.length < count && t < limit) {
    const w = wallClock(t, timeZone);
    if (!c.months.has(w.month) || !dayMatches(c, w)) {
      t += (60 - w.minute) * MIN + (23 - w.hour) * 60 * MIN; // jump to next local midnight (approx.)
      continue;
    }
    if (!c.hours.has(w.hour)) {
      t += (60 - w.minute) * MIN;
      continue;
    }
    if (c.minutes.has(w.minute)) out.push(new Date(t).toISOString());
    t += MIN;
  }
  return out;
}

const DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const pad = (n: number) => String(n).padStart(2, '0');

/** Short human text for common shapes: "Daily 02:00", "Every 6 h", "Weekly Sun 03:00". */
export function describeCron(cron: string): string {
  let c: ParsedCron;
  try {
    c = parseCron(cron);
  } catch {
    return cron;
  }
  const parts = normalize(cron).split(' ');
  const one = (s: Set<number>) => (s.size === 1 ? [...s][0] : null);
  const m = one(c.minutes);
  const h = one(c.hours);
  const allMonths = parts[3] === '*';
  if (!allMonths) return normalize(cron);
  if (m !== null && parts[1] === '*' && c.domStar && c.dowStar) return m === 0 ? 'Hourly' : `Hourly at :${pad(m)}`;
  const stepH = /^\*\/(\d+)$/.exec(parts[1]);
  if (m !== null && stepH && c.domStar && c.dowStar) return `Every ${stepH[1]} h`;
  if (m !== null && h !== null) {
    const hm = `${pad(h)}:${pad(m)}`;
    if (c.domStar && c.dowStar) return `Daily ${hm}`;
    if (c.domStar && !c.dowStar) {
      const days = [...c.weekdays].sort();
      if (days.length === 1) return `Weekly ${DOW[days[0]]} ${hm}`;
      return `${days.map((d) => DOW[d]).join(', ')} ${hm}`;
    }
    if (!c.domStar && c.dowStar && c.days.size === 1) {
      const d = [...c.days][0];
      return d === 1 ? `Monthly 1st ${hm}` : `Monthly day ${d} ${hm}`;
    }
  }
  return normalize(cron);
}

/** Approximate runs per 30-day month (for transfer estimates). */
export function runsPerMonth(cron: string): number {
  try {
    const start = new Date(Date.UTC(2026, 0, 1));
    const runs = nextRuns(cron, 2000, new Date(start.getTime() - 60_000), 'UTC');
    const end = start.getTime() + 30 * 86400_000;
    return runs.filter((r) => new Date(r).getTime() < end).length;
  } catch {
    return 0;
  }
}

/** Offset label for a timezone: "UTC+03:00". */
export function tzOffsetLabel(timeZone: string, at: Date = new Date()): string {
  try {
    const f = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'longOffset' });
    const name = f.formatToParts(at).find((p) => p.type === 'timeZoneName')?.value ?? 'GMT';
    const off = name.replace('GMT', '');
    return `UTC${off || '+00:00'}`;
  } catch {
    return '';
  }
}

export function timeZones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] };
  const list = intl.supportedValuesOf ? intl.supportedValuesOf('timeZone') : [];
  const common = ['UTC', 'Europe/Istanbul', 'Europe/Berlin', 'Europe/London', 'Europe/Amsterdam', 'America/New_York', 'Asia/Singapore'];
  return Array.from(new Set([...common, ...list]));
}

/** "Nov 19 02:00" in the given timezone. */
export function formatInZone(iso: string, timeZone: string): string {
  try {
    const f = new Intl.DateTimeFormat('en-US', { timeZone, month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
    const p: Record<string, string> = {};
    for (const part of f.formatToParts(new Date(iso))) p[part.type] = part.value;
    return `${p.month} ${p.day} ${p.hour}:${p.minute}`;
  } catch {
    return iso;
  }
}
