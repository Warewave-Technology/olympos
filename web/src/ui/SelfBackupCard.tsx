// The built-in olympos-self job: Olympos' own database, backed up to a
// destination the admin chooses once. It cannot be deleted (lock icon).
import { useEffect, useRef, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { BackupRun, BackupRunCopy, Destination, DestinationGroup, ItemList, SelfBackup, SelfBackupInput } from '../api/types';
import { useCan } from '../auth/me';
import { describeCron } from '../lib/cron';
import { age, bytes, relDateTime } from '../lib/format';
import { IconLock } from './icons';
import { Badge, ErrorState, Modal, useToast } from './kit';
import { CopiesTable, RestoreWithCopies } from './BackupRunDialog';
import { GroupName, KIND_LABEL, LastCopies } from './destinations';
import { RunBadge } from './status';
import { Select } from './Select';
import { DocLink } from './DocLinks';

/** A repair waiting for its not_before (5 min, 30 min, 2 h after the run before it). */
const waiting = (r: BackupRun) => r.status === 'queued' && !!r.not_before && Date.parse(r.not_before) > Date.now();
/** Running, or queued and due: a waiting repair does not keep Run now from starting. */
const active = (r: BackupRun) => r.status === 'running' || (r.status === 'queued' && !waiting(r));

export function SelfBackupCard({ focus }: { focus?: boolean }) {
  const isAdmin = useCan('admin_global');
  const canOperate = useCan('operate_global');
  const qc = useQueryClient();
  const toast = useToast();
  const ref = useRef<HTMLElement>(null);
  const q = useQuery({
    queryKey: ['backup-self'],
    queryFn: () => api.get<SelfBackup>('/backup/self'),
    refetchInterval: (query) => (query.state.data?.runs.some(active) ? 3_000 : 30_000),
  });
  const destQ = useQuery({
    queryKey: ['destinations'],
    queryFn: () => api.get<ItemList<Destination>>('/destinations'),
    enabled: isAdmin,
  });
  const groupsQ = useQuery({
    queryKey: ['destination-groups'],
    queryFn: () => api.get<ItemList<DestinationGroup>>('/destination-groups'),
    enabled: isAdmin,
  });
  // Picker value: "d:<destination id>" or "g:<group id>".
  const [dest, setDest] = useState('');
  const [editing, setEditing] = useState(false);
  const [showRestore, setShowRestore] = useState(false);
  useEffect(() => {
    if (focus) ref.current?.scrollIntoView?.({ block: 'start' });
  }, [focus, q.isSuccess]);

  const save = useMutation({
    mutationFn: (in_: SelfBackupInput) => api.put<SelfBackup>('/backup/self', in_),
    onSuccess: (v) => {
      qc.setQueryData(['backup-self'], v);
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
      setEditing(false);
      toast(`The Olympos database is backed up to ${v.job?.destination_name ?? 'the destination'}.`, 'ok');
    },
    onError: (e) => toast(errorMessage(e), 'crit'),
  });
  const run = useMutation({
    mutationFn: () => api.post('/backup/self/run'),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['backup-self'] });
      toast('Olympos database backup started.', 'ok');
    },
    onError: (e) => toast(errorMessage(e), 'crit'),
  });

  const v = q.data;
  if (!v) return null;
  // the job's last run, as on job rows: a repair waiting to start is not it yet
  const last = v.runs.find((r) => !waiting(r));
  // A partial run is restorable (some copies exist), so it counts here; it is shown as Partial.
  const lastOk = v.runs.find((r) => !r.repair_of && (r.status === 'succeeded' || r.status === 'partial'));
  const busy = v.runs.some(active);
  const dests = destQ.data?.items ?? [];
  const groups = groupsQ.data?.items ?? [];
  const loadingLists = destQ.isPending || groupsQ.isPending;
  const current = v.job?.destination_group_id ? `g:${v.job.destination_group_id}` : v.job?.destination_id ? `d:${v.job.destination_id}` : '';
  const choice = dest || current;
  // Only a loaded option is shown: never the raw "g:<id>" / "d:<id>" while the lists load or after they failed.
  const known = (c: string) => (c.startsWith('g:') ? groups.some((g) => `g:${g.id}` === c) : dests.some((d) => `d:${d.id}` === c));
  const input = (c: string): SelfBackupInput => (c.startsWith('g:') ? { destination_group_id: c.slice(2) } : { destination_id: c.slice(2) });
  const picker = (
    <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
      <Select
        aria-label="Destination"
        value={known(choice) ? choice : ''}
        onChange={setDest}
        placeholder={loadingLists ? 'Loading destinations…' : dests.length ? 'Choose a destination or a group' : destQ.isError ? 'Destinations could not be loaded' : 'No destinations yet'}
        options={[
          ...dests.map((d) => ({ value: `d:${d.id}`, label: d.name, text: d.name, hint: KIND_LABEL[d.kind] })),
          ...groups.map((g) => ({ value: `g:${g.id}`, label: <GroupName name={g.name} mono={false} />, text: g.name, hint: `Group · ${g.members.map((m) => m.name).join(' → ')}` })),
        ]}
        disabled={loadingLists || !dests.length}
      />
      <button type="button" className="btn pri" disabled={!known(choice) || save.isPending} onClick={() => save.mutate(input(choice))}>
        {v.configured ? 'Save' : 'Back up Olympos here'}
      </button>
      {v.configured && (
        <button type="button" className="btn" onClick={() => setEditing(false)}>
          Cancel
        </button>
      )}
      {!loadingLists && !dests.length && !destQ.isError && (
        <Link to="/settings/destinations" className="small">
          Add a destination
        </Link>
      )}
      {destQ.isError && <ErrorState what="destinations" error={destQ.error} onRetry={() => void destQ.refetch()} />}
      {groupsQ.isError && !destQ.isError && <p className="muted small">Destination groups could not be loaded; single destinations are still available.</p>}
    </div>
  );

  return (
    <section ref={ref} className={`card self-backup${!v.configured ? ' attention-card' : ''}`} aria-labelledby="self-t">
      <div className="card-head">
        <h2 id="self-t">
          <IconLock className="lock" label="Built-in job, cannot be deleted" /> Olympos database
        </h2>
        <span className="muted small">olympos-self · built in, cannot be deleted</span>
      </div>
      <div className="card-body stack-sm">
        <p className="muted small">
          Grants, the internal CA, clusters, jobs and change requests live in Olympos&apos; own PostgreSQL. This job dumps it (<span className="mono">pg_dump -Fc</span>) with the same manifest, tags and retention as
          every backup. A dump is only usable with the same Key Vault key: keep purge protection on. See <DocLink path="docs/restore-olympos.md" />.
        </p>
        {!v.configured ? (
          <>
            <div className="note warn" role="note">
              <b>Not backed up yet.</b> {isAdmin ? 'Choose where the Olympos database is backed up (daily at 02:30 UTC by default).' : 'An admin has to choose a destination.'}
            </div>
            {isAdmin && picker}
          </>
        ) : (
          <>
            <dl className="kv">
              <dt>Destination</dt>
              <dd>
                {editing && isAdmin ? picker : v.job?.destination_group_id ? <GroupName name={v.job.destination_name} /> : v.job?.destination_name}
                {!editing && isAdmin && (
                  <button type="button" className="btn sm ghost" style={{ marginLeft: 8 }} onClick={() => setEditing(true)}>
                    Change
                  </button>
                )}
              </dd>
              <dt>Schedule</dt>
              <dd>
                {v.job?.enabled ? describeCron(v.job.cron) : <Badge tone="mute">Disabled</Badge>} <span className="muted small">{v.job?.timezone}</span>
              </dd>
              <dt>Last success</dt>
              <dd>
                {lastOk?.finished_at ? (
                  <span title={relDateTime(lastOk.finished_at)}>
                    {age(lastOk.finished_at)} ago · {bytes(lastOk.bytes)}
                    {lastOk.status === 'partial' && (
                      <>
                        {' '}
                        <Badge tone="warn">Partial</Badge>
                      </>
                    )}
                  </span>
                ) : (
                  <span className="muted">Not yet</span>
                )}
              </dd>
              <dt>Last run</dt>
              <dd>{last ? <RunBadge run={last} /> : <span className="muted">Not yet</span>}</dd>
              {v.job?.destination_group_id && !!v.destinations_last_success?.length && (
                <>
                  <dt>Last copy</dt>
                  <dd>
                    <LastCopies items={v.destinations_last_success} label="Last copy per destination of the Olympos database" />
                  </dd>
                </>
              )}
            </dl>
            {last?.copies && (last.copies.length > 1 || !!last.repair_of) && last.copies.length > 0 && (
              <CopiesTable copies={last.copies} isRepair={!!last.repair_of} title="Copies of the last run" id="self-copies" />
            )}
            <div className="row" style={{ gap: 8 }}>
              {canOperate && (
                <button type="button" className="btn" disabled={busy || run.isPending} onClick={() => run.mutate()}>
                  {busy ? 'Running…' : 'Run now'}
                </button>
              )}
              {v.restore && (
                <button type="button" className="btn" onClick={() => setShowRestore(true)}>
                  Restore commands
                </button>
              )}
            </div>
            {showRestore && v.restore && (
              <SelfRestore guide={v.restore} runId={lastOk?.id} runCopies={lastOk?.copies} onClose={() => setShowRestore(false)} />
            )}
          </>
        )}
      </div>
    </section>
  );
}

/** Restore commands of the latest restorable dump; another copy refetches `/backup/self?copy=`. */
function SelfRestore({ guide, runId, runCopies, onClose }: { guide: NonNullable<SelfBackup['restore']>; runId?: string; runCopies?: BackupRunCopy[]; onClose: () => void }) {
  const [copy, setCopy] = useState('');
  const q = useQuery({
    queryKey: ['backup-self', { copy }],
    queryFn: () => api.get<SelfBackup>('/backup/self', { copy }),
    enabled: !!copy,
    placeholderData: (prev) => prev,
  });
  const shown = (copy && q.data?.restore) || guide;
  return (
    <Modal open onClose={onClose} size="xl" eyebrow="olympos-self" title="Restore the Olympos database" description="Latest restorable dump. The same Key Vault (KEK) is required.">
      <RestoreWithCopies guide={shown} runId={runId} runCopies={runCopies} onSelect={setCopy} pending={q.isFetching} error={q.isError ? q.error : undefined} />
    </Modal>
  );
}
