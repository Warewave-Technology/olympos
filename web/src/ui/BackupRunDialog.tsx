// Details of one backup run and, for a restorable run, the ready-to-copy
// restore commands for exactly that run (F19). A run of a destination group has
// one copy per member: the copies table shows each, and the restore guide can be
// built from any succeeded copy. *Restore…* opens the restore dialog: the copy
// is loaded into a new, discovered target after a second person approves it
// (docs/design/ui-restore.md).
import { useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { BackupRun, BackupRunCopy, BackupRunDetail, RestoreCopy, RestoreGuide } from '../api/types';
import { useCan } from '../auth/me';
import { between, bytes, dateTime, duration, relDateTime } from '../lib/format';
import { Badge, ClampedError, CopyButton, FormError, Modal, QueryView } from './kit';
import { DocLink, WithDocLinks } from './DocLinks';
import { GroupName, KindBadge } from './destinations';
import { RestoreDialog } from './RestoreDialog';
import { RunBadge } from './status';

export { ClampedError };

export function RestoreSteps({ guide }: { guide: RestoreGuide }) {
  return (
    <div className="stack-sm restore-steps">
      <p className="muted small">
        To restore by hand, these commands are filled in for this run. Placeholders in <span className="mono">&lt;angle brackets&gt;</span> are yours to fill. Full procedure: <DocLink path={guide.doc} />.
      </p>
      <ol className="restore-cmds">
        {guide.steps.map((s, i) => (
          <li key={i}>
            <div className="spread">
              <b>{s.title}</b>
              <CopyButton text={s.commands} label="Copy" className="btn sm" />
            </div>
            <pre className="code">{s.commands}</pre>
            {s.note && (
              <p className="muted small">
                <WithDocLinks text={s.note} />
              </p>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

/** The run that wrote the guide's own copies: they come first, repairs after. */
const guideRunId = (guide: RestoreGuide, runId?: string) => runId ?? guide.copies?.[0]?.run_id;

/** One line of the copy selector: a destination of this run, its own copy and a later repair's copy. */
type CopyOption = { destination_id: string; name: string; kind: RestoreCopy['kind']; own?: RestoreCopy; repair?: RestoreCopy };

/**
 * The run's destinations in member order: the run's copy rows when known (a failed one stays in the
 * list, disabled), otherwise the guide's own copies. Repair copies hang off the destination they
 * completed and are never offered as if this run had written them.
 */
function copyOptions(guide: RestoreGuide, own: string | undefined, runCopies?: BackupRunCopy[]): CopyOption[] {
  const copies = guide.copies ?? [];
  const mine = (d: string) => copies.find((c) => c.destination_id === d && (!own || c.run_id === own));
  const repair = (d: string) => copies.filter((c) => c.destination_id === d && own && c.run_id !== own).at(-1);
  const rows = runCopies?.length
    ? runCopies.map((c) => ({ destination_id: c.destination_id, name: c.destination_name, kind: c.destination_kind }))
    : copies.filter((c) => !own || c.run_id === own).map((c) => ({ destination_id: c.destination_id, name: c.name, kind: c.kind }));
  return rows.map((r) => ({ ...r, own: mine(r.destination_id), repair: repair(r.destination_id) }));
}

/**
 * Restore commands with a copy selector when the run wrote to more than one destination. A
 * destination whose copy failed in this run is listed but cannot be chosen; when a repair completed
 * it later, `onOpenRepair` opens that repair run (or, without it, the repair's copy is selected).
 * `onSelect` refetches the guide for that destination (`?copy=<destination id>`).
 */
export function RestoreWithCopies({
  guide,
  runId,
  runCopies,
  onSelect,
  onOpenRepair,
  pending,
  error,
}: {
  guide: RestoreGuide;
  runId?: string;
  runCopies?: BackupRunCopy[];
  onSelect: (destinationId: string) => void;
  onOpenRepair?: (runId: string) => void;
  pending?: boolean;
  error?: unknown;
}) {
  const own = guideRunId(guide, runId);
  const options = copyOptions(guide, own, runCopies);
  const selected = (guide.copies ?? []).find((c) => c.selected);
  const fromRepair = selected && own && selected.run_id !== own ? selected : undefined;
  const firstOwn = options.find((o) => o.own)?.destination_id;
  return (
    <div className="stack-sm" style={{ gap: 12 }}>
      {options.length > 1 && (
        <fieldset className="opts" aria-busy={pending || undefined}>
          <legend className="lbl">Restore from copy</legend>
          {options.map((o) => {
            const hintId = `copy-hint-${o.destination_id}`;
            return (
              <label className="opt" key={o.destination_id}>
                <input
                  type="radio"
                  name="restore-copy"
                  checked={!!o.own && !!o.own.selected}
                  onChange={() => onSelect(o.destination_id)}
                  disabled={pending || !o.own}
                  aria-describedby={hintId}
                />
                <span style={{ minWidth: 0 }}>
                  <span className="inline-sm">
                    <span className="t1 mono">{o.name}</span>
                    <KindBadge kind={o.kind} />
                    {!o.own && <Badge tone="crit">Failed</Badge>}
                  </span>
                  <span className="t2" id={hintId}>
                    {o.own
                      ? `${o.destination_id === firstOwn ? 'First successful copy in member order · ' : ''}taken ${relDateTime(o.own.taken_at)}`
                      : 'This run has no copy here.'}
                    {!o.own && o.repair && (
                      <>
                        {' '}
                        A repair wrote one at {relDateTime(o.repair.taken_at)}:{' '}
                        <button
                          type="button"
                          className="link-btn"
                          disabled={pending}
                          onClick={() => (onOpenRepair ? onOpenRepair(o.repair!.run_id) : onSelect(o.destination_id))}
                        >
                          {onOpenRepair ? 'open the repair run' : 'use the repair\'s copy'}
                        </button>
                      </>
                    )}
                  </span>
                </span>
              </label>
            );
          })}
        </fieldset>
      )}
      {fromRepair && (
        <p className="small" style={{ margin: 0 }}>
          Commands use the copy a repair wrote to <span className="mono">{fromRepair.name}</span> at {relDateTime(fromRepair.taken_at)}: a later dump than this run.
        </p>
      )}
      {options.length > 1 && (
        <p className="muted small" style={{ margin: 0 }}>
          Commands use the selected copy&apos;s destination. A destination whose copy failed in this run cannot be chosen.
        </p>
      )}
      <FormError error={error} />
      <RestoreSteps guide={guide} />
    </div>
  );
}

const shortHash = (h: string) => (h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-4)}` : h);

/** One row per destination of a run (the run dialog, and the last olympos-self run on its card). */
export function CopiesTable({ copies, isRepair, native = false, title = 'Copies', id = 'run-copies' }: { copies: BackupRunCopy[]; isRepair: boolean; native?: boolean; title?: string; id?: string }) {
  return (
    <div>
      <h3 id={id} className="small" style={{ margin: '0 0 8px', fontWeight: 600 }}>
        {title}
      </h3>
      {/* cards-sm: one card per copy on phones, so the error is never off-screen; explicit roles keep the table semantics there */}
      <div className="boxed tight table-wrap">
        <table className="t cards-sm" role="table" aria-labelledby={id}>
          <thead>
            <tr role="row">
              <th role="columnheader">Destination</th>
              <th role="columnheader">Status</th>
              <th role="columnheader" className="num">
                Size
              </th>
              <th role="columnheader">SHA-256</th>
              <th role="columnheader">Tier</th>
              <th role="columnheader">Error</th>
            </tr>
          </thead>
          <tbody>
            {copies.map((c) => (
              <tr key={c.destination_id} role="row">
                <td role="cell" data-label="Destination">
                  <span className="inline-sm">
                    <span className="mono">{c.destination_name}</span>
                    <KindBadge kind={c.destination_kind} />
                    {isRepair && <Badge tone="mute">Repair</Badge>}
                  </span>
                </td>
                <td role="cell" data-label="Status">
                  {c.status === 'succeeded' ? <Badge tone="ok">Succeeded</Badge> : <Badge tone="crit">Failed</Badge>}
                </td>
                <td role="cell" data-label="Size" className="num">
                  {c.status === 'succeeded' && c.bytes ? bytes(c.bytes) : '—'}
                </td>
                <td role="cell" data-label="SHA-256" className="mono" title={c.sha256 || undefined}>
                  {c.status === 'succeeded' && c.sha256 ? shortHash(c.sha256) : <span className="muted">—</span>}
                </td>
                <td role="cell" data-label="Tier">
                  {c.status === 'succeeded' && c.tier ? c.tier : <span className="muted">—</span>}
                </td>
                <td role="cell" data-label="Error" className="wrap err-cell">
                  {c.error ? <ClampedError text={c.error} /> : <span className="muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small" style={{ margin: '8px 0 0' }}>
        {native
          ? "Each copy is verified by size and hash. A native copy is the run's directory; its SHA-256 is the signed manifest's."
          : 'Each copy is verified by size and hash. A copy completed by a repair comes from a later dump, so its SHA-256 differs.'}
      </p>
    </div>
  );
}

/** What happened to the missing copies of a partial run, or what a repair run is. */
function RepairNote({ run, onOpen }: { run: BackupRunDetail; onOpen: (id: string) => void }) {
  if (run.repair_of) {
    return (
      <div className="note">
        This is a repair run: it wrote only the copies an earlier partial run missed.{' '}
        <button type="button" className="link-btn" onClick={() => onOpen(run.repair_of!)}>
          Open the original run
        </button>
      </div>
    );
  }
  if (run.status !== 'partial') return null;
  if (run.method === 'native') return <div className="note warn">Not every copy was written. A native run is not repaired: the next run is a full backup.</div>;
  const repaired = (run.restore?.copies ?? []).filter((c) => c.run_id !== run.id);
  if (repaired.length) {
    return (
      <div className="note">
        Missing {repaired.length === 1 ? 'copy' : 'copies'} completed by a repair:{' '}
        {repaired.map((c, i) => (
          <span key={c.destination_id + c.run_id}>
            {i > 0 && ', '}
            <span className="mono">{c.name}</span> at {relDateTime(c.taken_at)}
          </span>
        ))}
        . The run itself stays <Badge tone="warn">Partial</Badge> as the record of what happened.
      </div>
    );
  }
  if (run.next_repair_at && Date.parse(run.next_repair_at) <= Date.now()) {
    return (
      <div className="note warn">
        Not every copy was written. Repair due now; it starts when a worker is free (and the agent is connected). It writes only to the destinations that failed.
      </div>
    );
  }
  if (run.next_repair_at) {
    return (
      <div className="note warn">
        Not every copy was written. Repair queued: next attempt at {dateTime(run.next_repair_at)}. It writes only to the destinations that failed.
      </div>
    );
  }
  return (
    <div className="note warn">
      Not every copy was written. Olympos completes missing copies with repair runs inside the job&apos;s retry window; when they are used up, the copy stays missing until the next scheduled run.
    </div>
  );
}

const isGroupRun = (r: Pick<BackupRun, 'copies'>) => (r.copies?.length ?? 0) > 1;

/** Engines the UI restores into a new target (docs/design/ui-restore.md "Engines"). */
const RESTORABLE_ENGINES = ['postgresql', 'clickhouse', 'vault'];

/**
 * A run can be restored from the UI when it has a restore guide (a succeeded or partial run that is
 * not a dry run, with at least one succeeded copy) of an engine the server restores. Olympos' own
 * database is restored with the server stopped (docs/restore-olympos.md).
 */
export const uiRestorable = (run: BackupRunDetail) =>
  // R38: native ClickHouse runs are refused as a source until native restore lands
  !!run.restore && (run.restore.copies?.length ?? 1) > 0 && RESTORABLE_ENGINES.includes(run.engine) && run.target_service !== 'olympos-self' && run.method !== 'native';

export function BackupRunDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const [runId, setRunId] = useState(id);
  const [copy, setCopy] = useState('');
  const [restoring, setRestoring] = useState(false);
  // Coming back from the restore dialog, focus returns to Restore… (the button it was opened from).
  const [backFromRestore, setBackFromRestore] = useState(false);
  const restoreBtn = useRef<HTMLButtonElement>(null);
  // Opening a restore needs operate on the target's cluster (and read here): hidden without operate anywhere.
  const mayRestore = useCan('operate');
  const q = useQuery({
    queryKey: ['backup-run', runId, copy],
    queryFn: () => api.get<BackupRunDetail>(`/backup/runs/${runId}`, { copy: copy || undefined }),
    // switching the restore copy keeps the dialog on screen while the guide reloads
    placeholderData: (prev, prevQuery) => (prevQuery?.queryKey[1] === runId ? prev : undefined),
  });
  const r = q.data;
  const open = (other: string) => {
    setCopy('');
    setRunId(other);
  };
  // The restore dialog replaces the run dialog while it is open (one modal at a time); closing it comes back here.
  if (restoring && r && !q.isPlaceholderData)
    return (
      <RestoreDialog
        run={r}
        onClose={() => {
          setRestoring(false);
          setBackFromRestore(true);
        }}
      />
    );
  return (
    <Modal
      initialFocus={backFromRestore ? restoreBtn : undefined}
      open
      onClose={onClose}
      size="xl"
      eyebrow="Backup run"
      title={r ? <span className="mono">{r.target_service}</span> : 'Backup run'}
      description={r ? `${r.cluster_name} · ${r.trigger} · ${relDateTime(r.started_at ?? r.scheduled_for)}` : undefined}
    >
      <QueryView q={q} what="the run">
        {(run) => {
          // ClickHouse BACKUP through the ingest endpoint: a run directory per copy, no commands to restore it by hand
          const native = run.method === 'native';
          return (
          <div className="stack-sm" style={{ gap: 14 }}>
            <dl className="kv">
              <dt>Result</dt>
              <dd>
                {/* the status alone: a long error would run past the dialog in a badge */}
                <RunBadge run={{ status: run.status, error: '', not_before: run.not_before }} />
                {isGroupRun(run) && (
                  <span className="muted small">
                    {' '}
                    {run.copies!.filter((c) => c.status === 'succeeded').length} of {run.copies!.length} copies
                  </span>
                )}
                {(run.status === 'failed' || run.status === 'partial') && run.error && (
                  <div className="small" style={{ marginTop: 4 }}>
                    <ClampedError text={run.error} />
                  </div>
                )}
              </dd>
              {native && (
                <>
                  <dt>Method</dt>
                  <dd>
                    <Badge tone="info">Native</Badge>
                    {run.objects != null && <span className="muted small"> · {run.objects.toLocaleString('en-US')} {run.objects === 1 ? 'object' : 'objects'}</span>}
                  </dd>
                </>
              )}
              {run.destination_name && (
                <>
                  <dt>Destination</dt>
                  <dd>{isGroupRun(run) ? <GroupName name={run.destination_name} /> : <span className="mono">{run.destination_name}</span>}</dd>
                </>
              )}
              <dt>Size</dt>
              <dd>{run.bytes ? bytes(run.bytes) : '—'}</dd>
              <dt>Duration</dt>
              <dd>{duration(between(run.started_at, run.finished_at))}</dd>
              {run.blob_path && !isGroupRun(run) && (
                <>
                  <dt>{native ? 'Directory' : 'Blob'}</dt>
                  <dd className="mono small break">{run.blob_path}</dd>
                  <dt>SHA-256</dt>
                  <dd className="mono small break">{run.sha256}</dd>
                </>
              )}
            </dl>
            {(isGroupRun(run) || !!run.repair_of) && run.copies && run.copies.length > 0 && <CopiesTable copies={run.copies} isRepair={!!run.repair_of} native={native} />}
            <RepairNote run={run} onOpen={open} />
            {run.restore && mayRestore && uiRestorable(run) && (
              <div className="spread" style={{ alignItems: 'center' }}>
                <p className="small" style={{ margin: 0 }}>
                  <b>Restore…</b> loads this backup into a new target after a second person approves it. Or restore by hand with the commands below.
                </p>
                <button ref={restoreBtn} type="button" className="btn pri" onClick={() => setRestoring(true)} disabled={q.isPlaceholderData}>
                  Restore…
                </button>
              </div>
            )}
            {native && run.restore ? (
              <p className="muted small">Native restore is not available yet; the backup is kept. A native backup has no commands to restore by hand.</p>
            ) : run.restore ? (
              <RestoreWithCopies guide={run.restore} runId={run.id} runCopies={run.copies} onSelect={setCopy} onOpenRepair={open} pending={q.isPlaceholderData} />
            ) : run.status !== 'succeeded' && run.status !== 'partial' ? null : run.trigger === 'test' ? (
              <p className="muted small">Dry runs only check the setup; they are not restorable backups.</p>
            ) : (
              // a run from before destination groups of a job that moved to a group: no copy row says where it went
              <p className="muted small">
                Restore commands are unavailable: the job no longer writes to the destination this run used.
                {run.blob_path && (
                  <>
                    {' '}
                    The backup is at <span className="mono break">{run.blob_path}</span> in that destination.
                  </>
                )}
              </p>
            )}
          </div>
          );
        }}
      </QueryView>
    </Modal>
  );
}
