import { describe, expect, it } from 'vitest';
import { CRON_PRESETS, describeCron, formatInZone, nextRuns, parseCron, presetFor, runsPerMonth, validateCron } from '../lib/cron';
import { parseLabels, parseSas, matchesSelector } from '../lib/sas';

describe('cron helpers', () => {
  it('validates field count and ranges', () => {
    expect(validateCron('0 2 * * *')).toBeNull();
    expect(validateCron('0 2 * *')).toMatch(/5 fields/);
    expect(validateCron('61 2 * * *')).toMatch(/minute/);
    expect(validateCron('0 24 * * *')).toMatch(/hour/);
    expect(validateCron('*/0 * * * *')).toMatch(/step/);
  });

  it('parses lists, ranges, steps and Sunday as 7', () => {
    const c = parseCron('0,30 9-17/4 * * 7');
    expect([...c.minutes]).toEqual([0, 30]);
    expect([...c.hours]).toEqual([9, 13, 17]);
    expect([...c.weekdays]).toEqual([0]);
  });

  it('describes the presets the way the UI labels them', () => {
    for (const p of CRON_PRESETS) expect(describeCron(p.cron)).toBe(p.label);
    expect(describeCron('0 1 1 * *')).toBe('Monthly 1st 01:00');
    expect(describeCron('15 * * * *')).toBe('Hourly at :15');
    expect(presetFor(' 0  2 * * * ')?.id).toBe('daily');
  });

  it('computes next runs in UTC', () => {
    const from = new Date('2026-11-18T10:00:00Z');
    expect(nextRuns('0 2 * * *', 3, from, 'UTC')).toEqual(['2026-11-19T02:00:00.000Z', '2026-11-20T02:00:00.000Z', '2026-11-21T02:00:00.000Z']);
    expect(nextRuns('0 */6 * * *', 2, from, 'UTC')).toEqual(['2026-11-18T12:00:00.000Z', '2026-11-18T18:00:00.000Z']);
    expect(nextRuns('0 3 * * 0', 1, from, 'UTC')).toEqual(['2026-11-22T03:00:00.000Z']);
  });

  it('computes next runs in a timezone (Europe/Istanbul is UTC+3)', () => {
    const from = new Date('2026-11-18T10:00:00Z');
    const [first] = nextRuns('0 2 * * *', 1, from, 'Europe/Istanbul');
    expect(first).toBe('2026-11-18T23:00:00.000Z');
    expect(formatInZone(first, 'Europe/Istanbul')).toBe('Nov 19 02:00');
  });

  it('estimates runs per month', () => {
    expect(runsPerMonth('0 2 * * *')).toBe(30);
    expect(runsPerMonth('0 */6 * * *')).toBe(120);
    expect(runsPerMonth('not a cron')).toBe(0);
  });
});

describe('SAS inspection', () => {
  it('flags missing r/c/w/t, forbidden d/l and expiry', () => {
    const now = Date.parse('2026-11-18T00:00:00Z');
    const ok = parseSas('sv=2025-01-05&sr=c&sp=rcwt&se=2026-11-30T00:00:00Z&sig=abc', now);
    expect(ok.missing).toEqual([]);
    expect(ok.extra).toEqual([]);
    expect(ok.scope).toBe('container');
    expect(ok.daysLeft).toBe(12);
    const bad = parseSas('?sp=rwdl&se=2026-11-01&sig=x', now);
    expect(bad.missing).toEqual(['c', 't']);
    expect(bad.extra).toEqual(['d', 'l']);
    expect(bad.expired).toBe(true);
  });

  it('parses labels and matches selectors', () => {
    expect(parseLabels('env=prod, team=data')).toEqual({ labels: { env: 'prod', team: 'data' }, error: null });
    expect(parseLabels('nope').error).toMatch(/key=value/);
    expect(matchesSelector('env=prod', { env: 'prod', team: 'x' })).toBe(true);
    expect(matchesSelector('env=prod,team=data', { env: 'prod', team: 'x' })).toBe(false);
    expect(matchesSelector('all', {})).toBe(true);
  });
});
