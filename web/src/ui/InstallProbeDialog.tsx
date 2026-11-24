// "Install probe" (Settings › Clusters & agents; docs/design/synthetic-monitoring.md §2.2 and decision 1): a
// one-time, probe-only token for a cluster whose agent runs without the probe, as a helm upgrade of the agent
// release. The command holds the token: it lives in this dialog's state only (no query cache) and goes with it.
import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { Cluster, InstallResponse, ProbeStatus } from '../api/types';
import { age } from '../lib/format';
import { CheckIcon } from './icons';
import { Badge, CopyButton, FormError, Modal, Spinner, useAction, useNow, type Tone } from './kit';

/** Install tokens live one hour (inventory.EnrollTokenTTL). */
const TOKEN_TTL_MS = 3600_000;

/** "Token expires in 59 min · single use" for a one-time install token. */
export function tokenCountdown(expiresAt: string, now: number): { text: string; expired: boolean } {
  const s = Math.round((new Date(expiresAt).getTime() - now) / 1000);
  if (s <= 0) return { text: 'Token expired', expired: true };
  const m = Math.floor(s / 60);
  return { text: m >= 1 ? `Token expires in ${m} min · single use` : `Token expires in ${s} s · single use`, expired: false };
}

type ProbeOf = Pick<Cluster, 'status' | 'probe_status' | 'probe_version' | 'probe_last_seen_at'>;

/**
 * The probe state of a cluster: installed (online), not installed, offline, enrolling or revoked. A cluster still
 * waiting for its first agent gets the probe with it (the add cluster command installs both).
 */
export function probeState(c: ProbeOf, now = Date.now()): { text: string; tone: Tone } {
  if (c.status === 'pending') return { text: 'Installs with the agent', tone: 'info' };
  const s: ProbeStatus = c.probe_status;
  switch (s) {
    case 'online':
      return { text: 'Installed', tone: 'ok' };
    case 'offline':
      return { text: `Offline${c.probe_last_seen_at ? ` · ${age(c.probe_last_seen_at, now)}` : ''}`, tone: 'crit' };
    case 'pending':
      return { text: 'Enrolling', tone: 'info' };
    case 'revoked':
      return { text: 'Revoked', tone: 'mute' };
    case 'not_installed':
      return { text: 'Not installed', tone: 'mute' };
    default:
      return { text: String(s || 'unknown'), tone: 'mute' };
  }
}

/** The version, when a probe is (or was last) running. */
export function probeVersion(c: ProbeOf): string {
  return c.status !== 'pending' && c.probe_status !== 'revoked' && c.probe_status !== 'not_installed' ? c.probe_version : '';
}

export function ProbeBadge({ c, now }: { c: ProbeOf; now?: number }) {
  const p = probeState(c, now);
  return <Badge tone={p.tone}>{p.text}</Badge>;
}

/** The second line of a cluster's status cell: "Probe installed (0.3.0)", "Probe offline · 2 h", "Probe not installed". */
export function ProbeLine({ c, now }: { c: ProbeOf; now?: number }) {
  const p = probeState(c, now);
  const v = c.status !== 'pending' && c.probe_status === 'online' ? c.probe_version : '';
  const cls = p.tone === 'crit' ? 'ico-crit' : p.tone === 'warn' ? 'ico-warn' : 'muted';
  return (
    <div className={`probe-line small ${cls}`}>
      Probe {p.text.charAt(0).toLowerCase() + p.text.slice(1)}
      {v && (
        <>
          {' '}
          <span className="mono nowrap">({v})</span>
        </>
      )}
    </div>
  );
}

/**
 * Whether the probe a new token enrolls has connected. It went through pending (enrolled) since the token was
 * issued, or it was seen after the token's issue time on a cluster whose earlier probe could not connect any more
 * (none, or revoked). An earlier probe that was only offline and merely reconnects is not the new one.
 */
export function probeConnected(p: { before: ProbeStatus; polled?: Pick<Cluster, 'probe_status' | 'probe_last_seen_at'>; sawEnrolling: boolean; tokenExpiresAt: string }): boolean {
  if (p.polled?.probe_status !== 'online') return false;
  if (p.sawEnrolling) return true;
  // the token's issue time on the server clock: it lives one hour (EnrollTokenTTL)
  const issuedAt = new Date(p.tokenExpiresAt).getTime() - TOKEN_TTL_MS;
  const seenAfter = !!p.polled.probe_last_seen_at && new Date(p.polled.probe_last_seen_at).getTime() > issuedAt;
  const couldReconnect = p.before === 'offline' || p.before === 'pending' || p.before === 'online';
  return seenAfter && !couldReconnect;
}

export function InstallProbeDialog({ cluster, onClose }: { cluster: Cluster; onClose: () => void }) {
  const qc = useQueryClient();
  const issue = useAction<InstallResponse>();
  const [install, setInstall] = useState<InstallResponse | null>(null);
  // Whether the poll saw the new probe enrolled (pending) after the token was issued.
  const [sawEnrolling, setSawEnrolling] = useState(false);
  const now = useNow(1000);

  const run = async () => {
    const r = await issue.run(() => api.post<InstallResponse>(`/clusters/${cluster.id}/probe-token`));
    if (r) {
      setSawEnrolling(false);
      setInstall(r);
    }
  };

  const statusQ = useQuery({
    queryKey: ['clusters', cluster.id, 'probe-enroll', install?.expires_at],
    queryFn: () => api.get<Cluster>(`/clusters/${cluster.id}`),
    enabled: !!install,
    refetchInterval: 3000,
  });
  const polled = install ? statusQ.data : undefined;
  useEffect(() => {
    if (polled?.probe_status === 'pending') setSawEnrolling(true);
  }, [polled?.probe_status]);
  const online = polled?.probe_status === 'online';
  const connected = !!install && probeConnected({ before: cluster.probe_status, polled, sawEnrolling, tokenExpiresAt: install.expires_at });
  const oldBack = online && !connected;
  useEffect(() => {
    if (connected) void qc.invalidateQueries({ queryKey: ['clusters'] });
  }, [connected, qc]);

  const cd = install ? tokenCountdown(install.expires_at, now) : null;
  const again = cluster.probe_status !== 'not_installed';

  return (
    <Modal
      open
      onClose={onClose}
      size="wide"
      eyebrow="Install probe"
      title={`Install the synthetic probe on ${cluster.name}`}
      description="Upgrades the agent release with the probe enabled. The agent enrolls the probe with a one-time token; the probe dials out to Olympos, so no inbound port is needed on the cluster."
    >
      <div className="stack-sm" style={{ gap: 18 }}>
        {!install && (
          <>
            <div className="note">
              The command keeps the values the agent was installed with (<span className="mono">--reuse-values</span>) and adds the server’s install settings, such as an image mirror. The token is valid for one hour and enrolls one probe.
              {again && ' Issuing it withdraws earlier probe tokens of this cluster that were not used yet.'}
            </div>
            <FormError error={issue.error} />
          </>
        )}
        {install && cd && (
          <>
            <div>
              <div className="spread" style={{ marginBottom: 6 }}>
                <span className="lbl" style={{ margin: 0 }}>
                  Run on the cluster
                </span>
                <span aria-live="polite">
                  <Badge tone={cd.expired ? 'crit' : 'warn'}>{cd.text}</Badge>
                </span>
              </div>
              <pre className="code scroll" aria-label="Helm upgrade command" tabIndex={0}>
                {install.command}
              </pre>
            </div>
            {connected ? (
              <div className="panel" role="status">
                <CheckIcon ok label="Connected" />
                <span>
                  Probe connected. <span className="mono">{cluster.name}</span> runs probe <span className="mono">{polled?.probe_version || '—'}</span>; scenarios include it from their next run.
                </span>
              </div>
            ) : cd.expired ? (
              <div className="panel" role="status">
                <Badge tone="crit">Expired</Badge>
                <span>The token expired before the probe connected. Issue a new command and run it again.</span>
                <button type="button" className="btn sm" onClick={run} disabled={issue.pending}>
                  Issue new command
                </button>
              </div>
            ) : (
              <div className="panel dashed" role="status" aria-live="polite">
                <Spinner label="Waiting" />
                <span>
                  {oldBack
                    ? 'The earlier probe of this cluster is online again. Waiting for the new probe to enroll with this token…'
                    : polled?.probe_status === 'pending'
                      ? 'The probe enrolled. Waiting for it to connect…'
                      : 'Waiting for the probe to connect…'}
                </span>
                {statusQ.isError && <span className="muted small">Could not check status; retrying.</span>}
              </div>
            )}
            <FormError error={issue.error} />
          </>
        )}
        <div className="end">
          {install ? (
            <>
              <CopyButton text={install.command} label="Copy command" />
              <button type="button" className="btn pri" onClick={onClose}>
                Done
              </button>
            </>
          ) : (
            <>
              <button type="button" className="btn" onClick={onClose}>
                Cancel
              </button>
              <button type="button" className="btn pri" onClick={run} disabled={issue.pending}>
                {issue.pending ? 'Creating…' : 'Create install command'}
              </button>
            </>
          )}
        </div>
      </div>
    </Modal>
  );
}
