// kube-bench results of one node: every check grouped by CIS section, filterable by status, with
// the remediation and actual vs expected values kube-bench reported.
import { useMemo, useState } from 'react';
import type { BenchCheck, BenchNode } from '../api/types';
import { plural } from '../lib/format';
import { Badge, EmptyState, Modal } from './kit';

type Status = BenchCheck['status'];
const ORDER: Status[] = ['FAIL', 'WARN', 'PASS', 'INFO'];
const TONE: Record<Status, 'crit' | 'warn' | 'ok' | 'mute'> = { FAIL: 'crit', WARN: 'warn', PASS: 'ok', INFO: 'mute' };
const LABEL: Record<Status, string> = { FAIL: 'Fail', WARN: 'Warn', PASS: 'Pass', INFO: 'Info' };

export function BenchNodeDialog({ node, onClose }: { node: BenchNode; onClose: () => void }) {
  const checks = useMemo(() => node.checks ?? [], [node.checks]);
  const counts = useMemo(() => {
    const c: Record<Status, number> = { FAIL: 0, WARN: 0, PASS: 0, INFO: 0 };
    for (const x of checks) c[x.status] = (c[x.status] ?? 0) + 1;
    return c;
  }, [checks]);
  const [status, setStatus] = useState<Status | 'all'>(() => (counts.FAIL ? 'FAIL' : counts.WARN ? 'WARN' : 'all'));
  const [q, setQ] = useState('');

  const sections = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    const shown = checks.filter((c) => (status === 'all' || c.status === status) && words.every((w) => `${c.id} ${c.description} ${c.section_text}`.toLowerCase().includes(w)));
    const by = new Map<string, { section: string; text: string; nodeType: string; items: BenchCheck[] }>();
    for (const c of shown) {
      const k = `${c.node_type}/${c.section}`;
      if (!by.has(k)) by.set(k, { section: c.section, text: c.section_text, nodeType: c.node_type, items: [] });
      by.get(k)!.items.push(c);
    }
    const num = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
    return [...by.values()].sort((a, b) => num(a.section, b.section)).map((s) => ({ ...s, items: s.items.sort((a, b) => num(a.id, b.id)) }));
  }, [checks, status, q]);

  return (
    <Modal open onClose={onClose} size="xl" eyebrow={`kube-bench · ${node.benchmark}`} title={<span className="mono">{node.node_name}</span>} description={`${node.pass} pass · ${node.fail} fail · ${node.warn} warn${node.control_plane_na ? ' · control plane N/A (managed)' : ''}`}>
      {checks.length === 0 ? (
        <EmptyState title="No check details for this run">This run was stored before Olympos kept each check. Run the kube-bench schedule again to see what failed or warned.</EmptyState>
      ) : (
        <div className="stack-sm" style={{ gap: 14 }}>
          <div className="spread" style={{ flexWrap: 'wrap', gap: 10 }}>
            <div className="pills" role="group" aria-label="Show checks">
              <button type="button" className="pill" aria-pressed={status === 'all'} onClick={() => setStatus('all')}>
                All · {checks.length}
              </button>
              {ORDER.filter((s) => counts[s] > 0).map((s) => (
                <button key={s} type="button" className="pill" aria-pressed={status === s} onClick={() => setStatus(s)}>
                  {LABEL[s]} · {counts[s]}
                </button>
              ))}
            </div>
            <input className="in" style={{ maxWidth: 280 }} type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find a check (id or text)" aria-label="Find a check" />
          </div>
          {sections.length === 0 ? (
            <EmptyState title="No checks match">Change the filter or the search.</EmptyState>
          ) : (
            sections.map((s) => (
              <section key={`${s.nodeType}/${s.section}`} className="bench-sec" aria-label={`${s.section} ${s.text}`}>
                <h3 className="bench-sec-h">
                  <span className="mono">{s.section}</span> {s.text}
                  <span className="muted small"> · {s.nodeType} · {plural(s.items.length, 'check')}</span>
                </h3>
                <ul className="bench-checks">
                  {s.items.map((c) => (
                    <li key={c.id}>
                      <details open={c.status === 'FAIL' && s.items.length <= 3}>
                        <summary>
                          <Badge tone={TONE[c.status]}>{LABEL[c.status]}</Badge>
                          <span className="mono bench-id">{c.id}</span>
                          <span className="bench-desc">{c.description}</span>
                          {!c.scored && <span className="muted small">not scored</span>}
                        </summary>
                        <CheckBody c={c} />
                      </details>
                    </li>
                  ))}
                </ul>
              </section>
            ))
          )}
          <p className="muted small">Not scored checks (usually WARN) need a manual review: kube-bench cannot decide them from the node alone.</p>
        </div>
      )}
    </Modal>
  );
}

function CheckBody({ c }: { c: BenchCheck }) {
  const hasValues = !!(c.expected_result || c.actual_value);
  return (
    <div className="bench-body">
      {hasValues && (
        <dl className="bench-kv">
          {c.expected_result && (
            <>
              <dt>Expected</dt>
              <dd className="mono">{c.expected_result}</dd>
            </>
          )}
          {c.actual_value && (
            <>
              <dt>Actual</dt>
              <dd className="mono">{c.actual_value}</dd>
            </>
          )}
        </dl>
      )}
      {c.reason && (
        <p className="small">
          <span className="muted">Reason · </span>
          {c.reason}
        </p>
      )}
      {c.remediation ? (
        <>
          <div className="lbl small">Remediation</div>
          <pre className="bench-fix">{c.remediation}</pre>
        </>
      ) : (
        <p className="muted small">No remediation text in the benchmark.</p>
      )}
    </div>
  );
}
