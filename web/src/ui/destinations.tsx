// Display helpers shared by Settings › Destinations and the backup wizard.
import type { BackupJob, Destination, DestinationKind, DestinationLastSuccess, DestinationTest } from '../api/types';
import { age, daysUntil, plural, relDateTime } from '../lib/format';
import { CheckIcon, IconGroup } from './icons';
import { Badge } from './kit';

export const KIND_LABEL: Record<DestinationKind, string> = { azure_blob: 'Azure Blob', s3: 'S3', nfs: 'NFS' };

export function KindBadge({ kind }: { kind: DestinationKind }) {
  return <Badge tone="mute">{KIND_LABEL[kind] ?? kind}</Badge>;
}

/** A destination group's name with the group marker (screen readers hear "Destination group"). */
export function GroupName({ name, mono = true }: { name: string; mono?: boolean }) {
  return (
    <span className="grp">
      <IconGroup className="ico-warn" label="Destination group" />
      <span className={mono ? 'mono' : undefined}>{name}</span>
    </span>
  );
}

/** Where a job writes: its destination, or its group with the marker. */
export function JobDestination({ job }: { job: Pick<BackupJob, 'destination' | 'destination_group'> }) {
  if (job.destination_group) return <GroupName name={job.destination_group.name} />;
  return <span className="mono">{job.destination?.name ?? '—'}</span>;
}
export const jobDestinationName = (job: Pick<BackupJob, 'destination' | 'destination_group'>) => job.destination_group?.name ?? job.destination?.name ?? '';

/** One line per destination of a group: when its last successful copy was written (job rows, the self card). */
export function LastCopies({ items, label }: { items: DestinationLastSuccess[]; label: string }) {
  return (
    <ul className="muted small" aria-label={label} style={{ listStyle: 'none', margin: '2px 0 0', padding: 0 }}>
      {items.map((d) => (
        <li key={d.destination_id}>
          <span className="mono">{d.name}</span> ·{' '}
          {d.last_success_at ? <span title={relDateTime(d.last_success_at)}>last copy {age(d.last_success_at)} ago</span> : 'no copy yet'}
        </li>
      ))}
    </ul>
  );
}

/** Settings › Destinations "Used by": jobs, plus the groups the destination is in. */
export function usedByLabel(d: Pick<Destination, 'jobs' | 'groups'>): string {
  const jobs = plural(d.jobs, 'job');
  return d.groups ? `${jobs} · in ${plural(d.groups, 'group')}` : jobs;
}

/** Why the server refuses to delete a destination, or null when it may go (same order as the API). */
export function deleteRefusal(d: Pick<Destination, 'jobs' | 'groups' | 'copies'>): string | null {
  if (d.groups) return `It is in ${plural(d.groups, 'destination group')}; remove it there first.`;
  if (d.jobs > 0) return d.jobs === 1 ? '1 backup job uses it; move it to another destination first.' : `${plural(d.jobs, 'backup job')} use it; move them to another destination first.`;
  if (d.copies) return `It holds copies of ${plural(d.copies, 'backup run')}. It is kept so their restore commands stay valid.`;
  return null;
}

export function endpointHost(url: string | undefined): string {
  if (!url) return '';
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** Kind-appropriate "where": account/container, endpoint/bucket, mount path. */
export function destLocation(d: Destination): { where: string; detail: string } {
  if (d.kind === 's3') {
    return { where: `${endpointHost(d.endpoint_override) || 'AWS S3'} / ${d.bucket ?? ''}`, detail: [d.region || (d.endpoint_override ? '' : 'us-east-1'), d.path_style ? 'path-style' : ''].filter(Boolean).join(' · ') };
  }
  if (d.kind === 'nfs') return { where: d.path ?? '', detail: 'server mount' };
  return { where: `${d.account} / ${d.container}`, detail: d.endpoint_override ? `endpoint ${endpointHost(d.endpoint_override)}` : '' };
}

export function authLabel(d: Destination): string {
  if (d.kind === 's3') return `Access key${d.secret_key_source === 'keyvault_ref' ? ' · Key Vault' : d.secret_key_source === 'stored' ? ' · stored' : ''}`;
  if (d.kind === 'nfs') return 'Server mount';
  return d.auth === 'managed_identity' ? 'Managed Identity' : `SAS token${d.sas_source === 'keyvault_ref' ? ' · Key Vault' : d.sas_source === 'stored' ? ' · stored' : ''}`;
}

export function DestinationStatus({ d }: { d: Destination }) {
  const days = daysUntil(d.sas_expires_at);
  const sas = d.kind === 'azure_blob' && d.auth === 'sas_token';
  if (sas && days !== null && days < 0) return <Badge tone="crit">SAS expired</Badge>;
  if (d.last_test_ok === false) return <Badge tone="crit">Test failed</Badge>;
  if (sas && days !== null && days <= 14) return <Badge tone="warn">SAS expires in {days} days</Badge>;
  if (d.last_test_ok === null) return <Badge tone="mute">Not tested</Badge>;
  return <Badge tone="ok">Healthy</Badge>;
}

export function DeleteRefused({ d }: { d: Destination }) {
  // NFS: always shown (deviation #13): a file system has no "write but not delete".
  if (d.kind === 'nfs') return <Badge tone="warn" title="Olympos can delete files on NFS. Protect backups with storage-side snapshots or WORM.">No · protect on storage</Badge>;
  if (!d.last_test) return <span className="muted">Not tested</span>;
  return d.last_test.can_delete ? <Badge tone="crit">No · can delete</Badge> : <Badge tone="ok">Yes</Badge>;
}

const STEP_LABEL: Record<string, (k: DestinationKind) => string> = {
  endpoint: (k) => (k === 's3' ? 'Reach the S3 endpoint' : 'Reach the blob endpoint'),
  path: () => 'Path exists and is writable by the server',
  write: (k) => (k === 'nfs' ? 'Write a probe file' : k === 's3' ? 'Write a probe object' : 'Write a probe blob'),
  read: () => 'Read it back',
  tag: (k) => (k === 's3' ? 'Set object tag olympos-tier' : 'Set index tag olympos-tier'),
  delete_refused: () => 'Delete refused (as it should be)',
  sas_permissions: () => 'SAS permissions',
  sas_expiry: () => 'SAS expiry',
};

/** The destination test step report (write, read, tag, delete refused, …). */
export function TestReport({ report, kind, at, note }: { report: DestinationTest; kind: DestinationKind; at?: string | null; note?: string }) {
  const nfsDelete = (s: { name: string; ok: boolean }) => kind === 'nfs' && s.name === 'delete_refused' && !s.ok;
  return (
    <div className={`note report${report.ok ? (report.can_delete && kind !== 'nfs' ? ' crit' : '') : ' crit'}`} aria-live="polite">
      <b className="note-title">
        Test destination{at ? ` · ${relDateTime(at)}` : ''} · {report.ok ? 'passed' : 'failed'}
      </b>
      {note && <span className="muted small">{note}</span>}
      <ul className="plain-list">
        {report.steps.map((s) => (
          <li className="chk" key={s.name} style={{ padding: '3px 0', alignItems: 'flex-start' }}>
            <CheckIcon ok={s.ok} warn={nfsDelete(s)} label={nfsDelete(s) ? 'Warning' : undefined} />
            <span>
              {s.name === 'delete_refused' && !s.ok ? (kind === 'nfs' ? 'Delete is possible (expected on NFS)' : 'Delete was NOT refused') : (STEP_LABEL[s.name]?.(kind) ?? s.name)}
              {s.detail && <span className="mono muted"> · {s.detail}</span>}
            </span>
          </li>
        ))}
      </ul>
      {report.error && <div className="ico-crit">{report.error}</div>}
      {report.probe_path && (
        <div className="muted small">
          Probe path <span className="mono">{report.probe_path}</span>
        </div>
      )}
    </div>
  );
}
