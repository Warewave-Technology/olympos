// Shared pieces of restore requests (docs/design/ui-restore.md): the status
// badge, the engine-specific notes, progress and the result.
import type { RestoreEngine, RestoreItem, RestoreProgress, RestoreRequest, RestoreResult, RestoreStatus } from '../api/types';
import { bytes, duration } from '../lib/format';
import { Badge, ClampedError, type Tone } from './kit';

const STATUS: Record<RestoreStatus, [string, Tone]> = {
  pending: ['Pending approval', 'warn'],
  approved: ['Approved · waiting to start', 'info'],
  running: ['Running', 'info'],
  succeeded: ['Succeeded', 'ok'],
  failed: ['Failed', 'crit'],
  rejected: ['Rejected', 'crit'],
  expired: ['Expired', 'mute'],
  cancelled: ['Cancelled', 'mute'],
};

export function RestoreStatusBadge({ status }: { status: RestoreStatus }) {
  const [label, tone] = STATUS[status] ?? [status, 'mute'];
  return <Badge tone={tone}>{label}</Badge>;
}

export function restoreEngineName(engine: RestoreEngine | string, provider?: string): string {
  if (engine === 'postgresql') return 'PostgreSQL';
  if (engine === 'clickhouse') return 'ClickHouse';
  if (engine === 'vault') return provider === 'openbao' ? 'OpenBao' : provider === 'hashicorp' ? 'Vault' : 'Vault/OpenBao';
  return engine;
}

/** "cluster / namespace / service" of a request's source or target. */
export const restorePath = (x: { cluster_name: string; namespace: string; service: string }) => `${x.cluster_name} / ${x.namespace} / ${x.service}`;

/** What a Vault/OpenBao token of the new Vault needs (the dialog and the detail say the same). */
export function VaultTokenNeeds() {
  return (
    <>
      Needs the <span className="mono">default</span> policy plus <b>update</b> and <b>sudo</b> on <span className="mono">sys/storage/raft/snapshot-force</span>.
    </>
  );
}

/** The scope of a ClickHouse restore (a design decision: databases and tables with their data only). */
export function ClickHouseScopeNote() {
  return (
    <div className="note">
      <div className="note-title">What a ClickHouse restore creates</div>
      Databases and tables (MergeTree family, Log, Memory) with their data. Views, materialized views, dictionaries, tables of other engines, and secondary table features (defaults, TTL, indexes, codecs, settings) are
      not restored: the result lists each one so you can re-apply it from your schema. A materialized view&apos;s data goes into a table named <span className="mono">&lt;view&gt;__restored_data</span>.
    </div>
  );
}

/** What a native ClickHouse restore creates (docs/design/restore-native.html). */
export function NativeScopeNote() {
  return (
    <div className="note">
      <div className="note-title">What a native restore creates</div>
      ClickHouse restores the selected databases from the backup itself, with their tables, views, materialized views and dictionaries as they were defined. An object that could reach outside the target, or that
      Olympos cannot read with certainty, is left out, with the reason in the check. Left out objects are re-applied by hand after the restore. A Replicated table gets a Keeper path of its own (
      <span className="mono">/olympos-restore/&lt;request id&gt;/&lt;db&gt;/&lt;table&gt;</span>), so it never joins the source&apos;s replicas.
    </div>
  );
}

/** Shown before and after a Vault restore: the snapshot brings the source's seal, root token and policies. */
export function VaultUnsealNote({ after }: { after?: boolean }) {
  return (
    <div className="note warn" role="note">
      <div className="note-title">{after ? "Next: unseal the new Vault with the source's keys" : 'After the restore'}</div>
      <ul className="note-list">
        <li>
          The snapshot replaces all of the target&apos;s data. Unseal it with the <b>source</b> Vault&apos;s unseal keys, or by the source&apos;s auto-unseal (the same seal key). Its own unseal keys no longer apply.
        </li>
        <li>Its root token, policies, auth methods and secrets become the source&apos;s.</li>
        <li>The token given for this request most likely stops working.</li>
      </ul>
    </div>
  );
}

const PHASES: Record<string, string> = {
  verify: "Verifying the backup's checksum",
  check: 'Checking the target again',
  globals: 'Restoring roles (globals.sql)',
  restore: 'Restoring',
};

export function RestoreProgressView({ progress, engine }: { progress: RestoreProgress | null; engine: RestoreEngine }) {
  const p = progress ?? {};
  const phase = p.phase ? (PHASES[p.phase] ?? p.phase) : 'Starting';
  const where = [p.database, p.table].filter(Boolean).join('.');
  const total = p.total ?? 0;
  // Never more read than the copy holds, whatever the server reports.
  const read = total > 0 ? Math.min(p.bytes ?? 0, total) : (p.bytes ?? 0);
  const pct = total > 0 ? Math.round((read / total) * 100) : null;
  return (
    <div className="stack-sm" role="group" aria-labelledby="rs-prog-t">
      <div className="spread small">
        <span id="rs-prog-t">
          {phase}
          {where && p.phase === 'restore' && engine !== 'vault' ? (
            <>
              {' '}
              <span className="mono">{where}</span>
            </>
          ) : null}
        </span>
        <span className="mono muted">{total > 0 ? `${bytes(read)} of ${bytes(total)} read` : read > 0 ? `${bytes(read)} read` : ''}</span>
      </div>
      {pct !== null && (
        <div className="bar" role="progressbar" aria-label="Backup read" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
          <span style={{ width: `${pct}%` }} />
        </div>
      )}
      {((p.done?.length ?? 0) > 0 || (p.created?.length ?? 0) > 0) && (
        <div className="muted small">
          {(p.done?.length ?? 0) > 0 && (
            <>
              Done: <span className="mono">{p.done!.join(', ')}</span>
            </>
          )}
          {(p.done?.length ?? 0) > 0 && (p.created?.length ?? 0) > 0 && ' · '}
          {(p.created?.length ?? 0) > 0 && (
            <>
              Created on the target: <span className="mono">{p.created!.join(', ')}</span>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function ItemStatus({ status }: { status: RestoreItem['status'] }) {
  if (status === 'succeeded') return <Badge tone="ok">Succeeded</Badge>;
  if (status === 'failed') return <Badge tone="crit">Failed</Badge>;
  return <Badge tone="mute">Skipped</Badge>;
}

/** The result of a finished restore: one row per database (or the snapshot), what was not restored, notes, created databases. */
export function RestoreResultView({ rq }: { rq: Pick<RestoreRequest, 'engine' | 'status' | 'result' | 'error'> }) {
  const r: RestoreResult = rq.result ?? {};
  const items = r.items ?? [];
  const notes = r.notes ?? [];
  const created = r.created ?? [];
  const isCH = rq.engine === 'clickhouse';
  const isVault = rq.engine === 'vault';
  const withSkipped = items.filter((i) => (i.skipped?.length ?? 0) > 0);
  return (
    <div className="stack-sm" style={{ gap: 14 }}>
      {isVault && rq.status === 'succeeded' && <VaultUnsealNote after />}
      {rq.error && (
        <div className="note crit" role="alert">
          <div className="note-title">The restore failed</div>
          <ClampedError text={rq.error} />
        </div>
      )}
      {items.length > 0 && (
        <div className="boxed tight table-wrap">
          <table className="t cards-sm" role="table" aria-label="Restore result">
            <thead>
              <tr role="row">
                <th role="columnheader">{isVault ? 'Item' : 'Database'}</th>
                <th role="columnheader">Status</th>
                <th role="columnheader" className="num">
                  Size
                </th>
                <th role="columnheader" className="num">
                  Duration
                </th>
                {!isVault && (
                  <th role="columnheader" className="num">
                    Tables
                  </th>
                )}
                {isCH && (
                  <th role="columnheader" className="num">
                    Rows
                  </th>
                )}
                <th role="columnheader">Error</th>
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr role="row" key={i.name}>
                  <td role="cell" data-label={isVault ? 'Item' : 'Database'} className="mono">
                    {i.name}
                  </td>
                  <td role="cell" data-label="Status">
                    <ItemStatus status={i.status} />
                  </td>
                  <td role="cell" data-label="Size" className="num">
                    {i.bytes ? bytes(i.bytes) : '—'}
                  </td>
                  <td role="cell" data-label="Duration" className="num">
                    {duration(i.duration_seconds)}
                  </td>
                  {!isVault && (
                    <td role="cell" data-label="Tables" className="num">
                      {i.tables}
                    </td>
                  )}
                  {isCH && (
                    <td role="cell" data-label="Rows" className="num">
                      {i.rows.toLocaleString('en-US')}
                    </td>
                  )}
                  <td role="cell" data-label="Error" className="wrap err-cell">
                    {i.error ? <ClampedError text={i.error} /> : <span className="muted">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {withSkipped.map((i) => (
        <div className="note warn" role="group" key={`skip-${i.name}`} aria-label={`Not restored in ${i.name}`}>
          <div className="note-title">
            Not restored in <span className="mono">{i.name}</span> ({i.skipped!.length}){isCH ? ' · recreate or re-apply from your schema' : ''}
          </div>
          <ul className="note-list">
            {i.skipped!.map((s, k) => (
              <li key={k} className="break">
                {s}
              </li>
            ))}
          </ul>
        </div>
      ))}
      {notes.length > 0 && (
        <div className="note" role="group" aria-label="Notes from the restore">
          <div className="note-title">Notes</div>
          <ul className="note-list">
            {notes.map((n, k) => (
              <li key={k} className="break">
                {n}
              </li>
            ))}
          </ul>
        </div>
      )}
      {created.length > 0 && (
        <p className="small" style={{ margin: 0 }}>
          Created on the target: <span className="mono">{created.join(', ')}</span>
          {rq.status === 'failed' && <span className="muted"> · They stay there after the failure; drop them if you do not need them.</span>}
        </p>
      )}
      {isCH && rq.status === 'succeeded' && (
        <p className="muted small" style={{ margin: 0 }}>
          ClickHouse restores databases and tables with their data. Views, materialized views, dictionaries, other engines and secondary table features are listed above, never dropped silently.
        </p>
      )}
    </div>
  );
}
