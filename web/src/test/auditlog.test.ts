import { describe, expect, it } from 'vitest';
import { formatEntries, isStructured, parseLog, shortReason, splitJson } from '../lib/auditLog';

const KS_LOG = [
  '{"level":"info","ts":"2026-11-18T19:18:30Z","msg":"Kubescape scanner initializing..."}',
  '{"level":"warn","ts":"2026-11-18T19:18:31Z","msg":"failed to load framework from cache","framework":"cis-v1.23-t1.0.1"}',
  '{"level":"error","ts":1763493512.25,"msg":"failed to download framework","error":"framework \'cis-v1.23-t1.0.1\' not found","attempt":3}',
  "Error: framework 'cis-v1.23-t1.0.1' not found",
].join('\n');

describe('audit log pretty-printer', () => {
  it('parses zap JSON lines with level, time, message, error and extra fields', () => {
    const e = parseLog(KS_LOG);
    expect(e).toHaveLength(4);
    expect(isStructured(e)).toBe(true);
    expect(e[0]).toMatchObject({ kind: 'json', level: 'info', time: '2026-11-18T19:18:30Z', msg: 'Kubescape scanner initializing...' });
    expect(e[1].fields).toEqual([['framework', 'cis-v1.23-t1.0.1']]);
    expect(e[2]).toMatchObject({ level: 'error', error: "framework 'cis-v1.23-t1.0.1' not found", time: '2025-11-18T19:18:32.250Z' });
    expect(e[2].fields).toEqual([['attempt', '3']]);
    expect(e[3]).toMatchObject({ kind: 'text', level: 'error', msg: "Error: framework 'cis-v1.23-t1.0.1' not found" });
  });

  it('splits several JSON objects concatenated on one line after a prefix', () => {
    const line = 'kubescape failed: exit status 1: {"level":"info","msg":"a {brace} \\"q\\""} {"level":"info","msg":"b"} Error: boom';
    const parts = splitJson(line);
    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe('kubescape failed: exit status 1: ');
    expect(parts[1]).toEqual({ level: 'info', msg: 'a {brace} "q"' });
    expect(parseLog(line).map((x) => x.kind)).toEqual(['text', 'json', 'json', 'text']);
    expect(parseLog(line)[0].msg).toBe('kubescape failed: exit status 1');
  });

  it('keeps plain text logs as text and survives broken JSON', () => {
    const e = parseLog('line one\n{not json}\n{"level":"info"');
    expect(isStructured(e)).toBe(false);
    expect(e.map((x) => x.msg)).toEqual(['line one', '{not json}', '{"level":"info"']);
  });

  it('formats a readable copy', () => {
    expect(formatEntries(parseLog(KS_LOG)).split('\n')[2]).toBe("2025-11-18T19:18:32.250Z  ERROR  failed to download framework  error=framework 'cis-v1.23-t1.0.1' not found  attempt=3");
  });

  it('reduces a raw error to one short reason', () => {
    expect(shortReason('agent_offline')).toBe('agent_offline');
    expect(shortReason(`kubescape failed: exit status 1: ${KS_LOG.split('\n').join(' ')}`)).toBe("framework 'cis-v1.23-t1.0.1' not found");
    expect(shortReason('kubescape failed: exit status 1: {"level":"error","msg":"x","error":"no route to host"}')).toBe('no route to host');
    expect(shortReason('a'.repeat(200), 40)).toHaveLength(40);
    expect(shortReason('')).toBe('');
  });
});
