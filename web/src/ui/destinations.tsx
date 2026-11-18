// Display helpers shared by Settings › Destinations and the backup wizard.
import type { Destination, DestinationKind, DestinationTest } from '../api/types';
import { daysUntil, relDateTime } from '../lib/format';
import { CheckIcon } from './icons';
import { Badge } from './kit';

export const KIND_LABEL: Record<DestinationKind, string> = { azure_blob: 'Azure Blob', s3: 'S3', nfs: 'NFS' };

export function KindBadge({ kind }: { kind: DestinationKind }) {
  return <Badge tone="mute">{KIND_LABEL[kind] ?? kind}</Badge>;
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
