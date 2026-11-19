import type { ReactNode } from 'react';
import type { BackupRun, ChangeRequest, Cluster, Severity, Target } from '../api/types';
import { age, capitalize } from '../lib/format';
import { Badge, type Tone } from './kit';

export function PageHead({ title, sub, actions, crumbs }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode; crumbs?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        {crumbs && <div className="crumbs">{crumbs}</div>}
        <h1 style={crumbs ? { marginTop: 6 } : undefined}>{title}</h1>
        {sub && <p className="sub">{sub}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function ClusterStatusBadge({ c, now = Date.now() }: { c: Pick<Cluster, 'status' | 'last_seen_at'>; now?: number }) {
  switch (c.status) {
    case 'online':
      return <Badge tone="ok">Online</Badge>;
    case 'offline':
      return <Badge tone="crit">Offline{c.last_seen_at ? ` · ${age(c.last_seen_at, now)}` : ''}</Badge>;
    case 'pending':
      return <Badge tone="info">Waiting for agent</Badge>;
    case 'revoked':
      return <Badge tone="mute">Revoked</Badge>;
    default:
      return <Badge>{String(c.status)}</Badge>;
  }
}

export function TlsBadge({ t }: { t: Pick<Target, 'tls_ok'> }) {
  if (t.tls_ok === null || t.tls_ok === undefined) return <Badge tone="mute">Not probed</Badge>;
  return t.tls_ok ? <Badge tone="ok">Yes</Badge> : <Badge tone="warn">No</Badge>;
}

const RUN_TONE: Record<string, Tone> = { succeeded: 'ok', failed: 'crit', missed: 'crit', running: 'info', queued: 'mute' };

export function RunBadge({ run }: { run: Pick<BackupRun, 'status' | 'error'> }) {
  const label = capitalize(run.status) + (run.status === 'failed' && run.error ? ` · ${run.error}` : '');
  return <Badge tone={RUN_TONE[run.status] ?? 'mute'}>{label}</Badge>;
}

const CR_LABEL: Record<string, [string, Tone]> = {
  pending: ['Pending approval', 'warn'],
  approved: ['Approved', 'info'],
  applying: ['Applying', 'info'],
  applied: ['Applied', 'ok'],
  rejected: ['Rejected', 'crit'],
  expired: ['Expired', 'mute'],
  failed: ['Apply failed', 'crit'],
  cancelled: ['Cancelled', 'mute'],
};
export function CrStatusBadge({ cr }: { cr: Pick<ChangeRequest, 'status'> }) {
  const [label, tone] = CR_LABEL[cr.status] ?? [cr.status, 'mute'];
  return <Badge tone={tone}>{label}</Badge>;
}

const SEV_TONE: Record<string, Tone> = { critical: 'crit', high: 'crit', medium: 'warn', low: 'info', info: 'mute' };
export function SeverityBadge({ s }: { s: Severity | string }) {
  return <Badge tone={SEV_TONE[s] ?? 'mute'}>{capitalize(s)}</Badge>;
}

export function opLabel(op: string): string {
  return op === 'destroy_history' ? 'Destroy history' : capitalize(op);
}
export function OpBadge({ op }: { op: string }) {
  const tone: Tone = op === 'destroy_history' ? 'crit' : op === 'delete' ? 'warn' : op === 'create' ? 'ok' : 'info';
  return <Badge tone={tone}>{opLabel(op)}</Badge>;
}

/** CR display id: server number when present, else first 8 chars. */
export function crLabel(cr: Pick<ChangeRequest, 'id' | 'number'>): string {
  return cr.number || `CR-${cr.id.slice(0, 8)}`;
}

/** Time + result of the last attempt (registry pull, channel delivery); "Not yet" before the first (F10). */
export function LastResultCell({ at, ok, error, okText = 'OK' }: { at?: string | null; ok?: boolean | null; error?: string; okText?: string }) {
  if (!at) return <span className="muted">Not yet</span>;
  return (
    <span title={error || undefined}>
      {ok ? <Badge tone="ok">{okText}</Badge> : <Badge tone="crit">Failed</Badge>} <span className="muted small">{age(at)} ago</span>
      {!ok && error && <div className="muted small wrap">{error}</div>}
    </span>
  );
}
