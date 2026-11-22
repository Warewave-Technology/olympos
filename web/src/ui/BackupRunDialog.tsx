// Details of one backup run and, for a restorable run, the ready-to-copy
// restore commands for exactly that run (F19). A run of a destination group has
// one copy per member: the copies table shows each, and the restore guide can be
// built from any succeeded copy. Restore through the UI (to a new target,
// maker/checker) is planned for v0.2.
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { BackupRun, BackupRunCopy, BackupRunDetail, RestoreCopy, RestoreGuide } from '../api/types';
import { between, bytes, dateTime, duration, relDateTime } from '../lib/format';
import { Badge, CopyButton, FormError, Modal, QueryView } from './kit';
import { DocLink, WithDocLinks } from './DocLinks';
import { GroupName, KindBadge } from './destinations';
import { RunBadge } from './status';

export function RestoreSteps({ guide }: { guide: RestoreGuide }) {
  return (
    <div className="stack-sm restore-steps">
      <p className="muted small">
        Restore is manual in v0.1: these commands are filled in for this run. Placeholders in <span className="mono">&lt;angle brackets&gt;</span> are yours to fill. Full procedure: <DocLink path={guide.doc} />.
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

function copyHint(c: RestoreCopy, i: number, ownRun: string | undefined): string {
  const at = relDateTime(c.taken_at);
  if (ownRun && c.run_id !== ownRun) return `Completed later by a repair, taken at ${at}`;
  return i === 0 ? `First successful copy in member order · taken ${at}` : `Taken ${at}`;
}

/**
 * Restore commands with a copy selector when the run has more than one succeeded copy.
 * `onSelect` refetches the guide for that destination (`?copy=<destination id>`).
 */
export function RestoreWithCopies({ guide, runId, onSelect, pending, error }: { guide: RestoreGuide; runId?: string; onSelect: (destinationId: string) => void; pending?: boolean; error?: unknown }) {
  const copies = guide.copies ?? [];
  const own = guideRunId(guide, runId);
  return (
    <div className="stack-sm" style={{ gap: 12 }}>
      {copies.length > 1 && (
        <fieldset className="opts" aria-busy={pending || undefined}>
          <legend className="lbl">Restore from copy</legend>
          {copies.map((c, i) => (
            <label className="opt" key={`${c.destination_id}-${c.run_id}`}>
              <input type="radio" name="restore-copy" checked={c.selected} onChange={() => onSelect(c.destination_id)} disabled={pending} />
              <span style={{ minWidth: 0 }}>
                <span className="inline-sm">
                  <span className="t1 mono">{c.name}</span>
                  <KindBadge kind={c.kind} />
                </span>
                <span className="t2">{copyHint(c, i, own)}</span>
              </span>
            </label>
          ))}
        </fieldset>
      )}
      {copies.length > 1 && (
        <p className="muted small" style={{ margin: 0 }}>
          Commands use the selected copy&apos;s destination. Failed copies are not listed.
        </p>
      )}
      <FormError error={error} />
      <RestoreSteps guide={guide} />
    </div>
  );
}

const shortHash = (h: string) => (h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-4)}` : h);

/** Errors longer than this are clamped to three lines with a toggle for the rest. */
const LONG_ERROR = 120;

/** An error that wraps anywhere; a long one is clamped to three lines, the full text one click away (and in the tooltip). */
export function ClampedError({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const long = text.length > LONG_ERROR;
  return (
    <span className="clamp-wrap">
      <span className={`clamp ico-crit${long && !open ? ' clamp-3' : ''}`} title={long ? text : undefined}>
        {text}
      </span>
      {long && (
        <button type="button" className="link-btn small" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? 'Show less' : 'Show the full error'}
        </button>
      )}
    </span>
  );
}

/** One row per destination of a run (the run dialog, and the last olympos-self run on its card). */
export function CopiesTable({ copies, isRepair, title = 'Copies', id = 'run-copies' }: { copies: BackupRunCopy[]; isRepair: boolean; title?: string; id?: string }) {
  return (
    <div>
      <h3 id={id} className="small" style={{ margin: '0 0 8px', fontWeight: 600 }}>
        {title}
      </h3>
      {/* stack-sm: one card per copy on phones, so the error is never off-screen; explicit roles keep the table semantics there */}
      <div className="boxed tight table-wrap">
        <table className="t stack-sm" role="table" aria-labelledby={id}>
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
        Each copy is verified by size and hash. A copy completed by a repair comes from a later dump, so its SHA-256 differs.
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

export function BackupRunDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const [runId, setRunId] = useState(id);
  const [copy, setCopy] = useState('');
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
  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      eyebrow="Backup run"
      title={r ? <span className="mono">{r.target_service}</span> : 'Backup run'}
      description={r ? `${r.cluster_name} · ${r.trigger} · ${relDateTime(r.started_at ?? r.scheduled_for)}` : undefined}
    >
      <QueryView q={q} what="the run">
        {(run) => (
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
                  <dt>Blob</dt>
                  <dd className="mono small break">{run.blob_path}</dd>
                  <dt>SHA-256</dt>
                  <dd className="mono small break">{run.sha256}</dd>
                </>
              )}
            </dl>
            {(isGroupRun(run) || !!run.repair_of) && run.copies && run.copies.length > 0 && <CopiesTable copies={run.copies} isRepair={!!run.repair_of} />}
            <RepairNote run={run} onOpen={open} />
            {run.restore ? (
              <RestoreWithCopies guide={run.restore} runId={run.id} onSelect={setCopy} pending={q.isPlaceholderData} />
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
        )}
      </QueryView>
    </Modal>
  );
}
