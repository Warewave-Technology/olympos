import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { AuditRun } from '../api/types';
import { LEVEL_TONE, formatEntries, isStructured, parseLog, shortReason, type LogEntry } from '../lib/auditLog';
import { between, capitalize, dateTime, duration } from '../lib/format';
import { Badge, CopyButton, Modal, QueryView } from './kit';

const TOOL_LABEL: Record<string, string> = { kubescape: 'Kubescape', polaris: 'Polaris', 'kube-bench': 'kube-bench' };
export const toolLabel = (t: string) => TOOL_LABEL[t] ?? t;

function clock(t: string): string {
  const d = new Date(t);
  if (!t || Number.isNaN(d.getTime())) return t;
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/** The log of a run as a readable list (zap/kubescape JSON lines) or monospace text. */
export function LogView({ log }: { log: string }) {
  const entries = useMemo(() => parseLog(log), [log]);
  const structured = isStructured(entries);
  const [mode, setMode] = useState<'pretty' | 'raw'>(structured ? 'pretty' : 'raw');
  const text = mode === 'pretty' && structured ? formatEntries(entries) : log;
  return (
    <div className="logv">
      <div className="logv-bar">
        <span className="muted small">
          {entries.length} {entries.length === 1 ? 'line' : 'lines'}
          {structured ? ' · JSON log' : ''}
        </span>
        <span className="inline-sm">
          {structured && (
            <div className="pills" role="group" aria-label="Log format">
              <button type="button" className="pill" aria-pressed={mode === 'pretty'} onClick={() => setMode('pretty')}>
                Pretty
              </button>
              <button type="button" className="pill" aria-pressed={mode === 'raw'} onClick={() => setMode('raw')}>
                Raw
              </button>
            </div>
          )}
          <CopyButton text={text} label="Copy log" className="btn sm" />
        </span>
      </div>
      {mode === 'pretty' && structured ? (
        <ol className="logv-list" aria-label="Log">
          {entries.map((e, i) => (
            <LogLine key={i} e={e} />
          ))}
        </ol>
      ) : (
        <pre className="code logv-raw" tabIndex={0} aria-label="Raw log">
          {log}
        </pre>
      )}
    </div>
  );
}

function LogLine({ e }: { e: LogEntry }) {
  const tone = LEVEL_TONE[e.level] ?? 'mute';
  return (
    <li className={`logv-row${e.level === 'error' || e.level === 'fatal' ? ' err' : ''}`}>
      <span className="logv-lvl">{e.level ? <Badge tone={tone}>{e.level.toUpperCase()}</Badge> : e.kind === 'text' ? <Badge tone="mute">TEXT</Badge> : null}</span>
      <span className="logv-time mono small muted" title={e.time}>
        {e.time ? clock(e.time) : ''}
      </span>
      <span className="logv-msg">
        <span className={e.kind === 'text' ? 'mono' : undefined}>{e.msg || <span className="muted">(no message)</span>}</span>
        {e.error && <span className="logv-err mono">error: {e.error}</span>}
        {e.fields.length > 0 && (
          <span className="logv-fields mono small">
            {e.fields.map(([k, v]) => (
              <span key={k}>
                <span className="muted">{k}=</span>
                {v}
              </span>
            ))}
          </span>
        )}
      </span>
    </li>
  );
}

/** Failed (or any) audit run: reason, facts and the full log from GET /audit/runs/{id}. */
export function AuditRunDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['audit-run', id], queryFn: () => api.get<AuditRun>(`/audit/runs/${id}`) });
  const r = q.data;
  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      eyebrow={r ? `${toolLabel(r.tool)} run · ${r.cluster_name}` : 'Audit run'}
      eyebrowTone={r?.status === 'failed' ? 'crit' : undefined}
      title={r ? (r.status === 'failed' ? 'Run failed' : `Run ${r.status}`) : 'Audit run'}
      description={r ? `${dateTime(r.started_at)}${r.finished_at ? ` · ${duration(between(r.started_at, r.finished_at))}` : ''}` : undefined}
    >
      <QueryView q={q} what="this run" isEmpty={() => false}>
        {(d) => (
          <>
            {d.status === 'failed' && (
              <div className="note crit" role="note">
                <div className="note-title">Reason</div>
                <span className="err-text">{shortReason(d.error, 300) || 'The run failed without a reason. See the log below.'}</span>
              </div>
            )}
            <dl className="dl narrow">
              <dt>Status</dt>
              <dd>
                <Badge tone={d.status === 'failed' ? 'crit' : d.status === 'succeeded' ? 'ok' : 'info'}>{capitalize(d.status)}</Badge>
              </dd>
              <dt>Cluster</dt>
              <dd className="mono">{d.cluster_name}</dd>
              {d.score != null && (
                <>
                  <dt>Score</dt>
                  <dd>{d.score.toFixed(1)}%</dd>
                </>
              )}
              {Array.isArray(d.details?.frameworks) && (
                <>
                  <dt>Frameworks</dt>
                  <dd className="mono">{(d.details!.frameworks as string[]).join(', ')}</dd>
                </>
              )}
              {typeof d.details?.trigger === 'string' && (
                <>
                  <dt>Trigger</dt>
                  <dd>{d.details!.trigger as string}</dd>
                </>
              )}
            </dl>
            <div>
              <div className="lbl">Log</div>
              {d.log ? <LogView log={d.log} /> : <p className="muted small" style={{ margin: 0 }}>{d.error ? <span className="mono">{d.error}</span> : 'No log was stored for this run.'}</p>}
            </div>
            <div className="end">
              <button type="button" className="btn pri" onClick={onClose}>
                Close
              </button>
            </div>
          </>
        )}
      </QueryView>
    </Modal>
  );
}

/** "Failed · reason" as a button that opens the run's log; never the raw log text. */
export function FailedRunButton({ run, onOpen, compact }: { run: Pick<AuditRun, 'id' | 'error' | 'tool' | 'cluster_name'>; onOpen: (id: string) => void; compact?: boolean }) {
  const reason = shortReason(run.error, 80);
  return (
    <button type="button" className="fail-btn" onClick={() => onOpen(run.id)} aria-label={`Failed${reason ? `: ${reason}` : ''}. Show the log of the ${toolLabel(run.tool)} run on ${run.cluster_name}`} title={reason || undefined}>
      <Badge tone="crit">Failed</Badge>
      {!compact && reason && <span className="fail-why">{reason}</span>}
    </button>
  );
}
