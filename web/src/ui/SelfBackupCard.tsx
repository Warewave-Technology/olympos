// The built-in olympos-self job: Olympos' own database, backed up to a
// destination the admin chooses once. It cannot be deleted (lock icon).
import { useEffect, useRef, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { Destination, ItemList, SelfBackup, SelfBackupInput } from '../api/types';
import { useCan } from '../auth/me';
import { describeCron } from '../lib/cron';
import { age, bytes, relDateTime } from '../lib/format';
import { IconLock } from './icons';
import { Badge, Modal, useToast } from './kit';
import { RestoreSteps } from './BackupRunDialog';
import { RunBadge } from './status';
import { Select } from './Select';
import { DocLink } from './DocLinks';

export function SelfBackupCard({ focus }: { focus?: boolean }) {
  const isAdmin = useCan('admin_global');
  const canOperate = useCan('operate_global');
  const qc = useQueryClient();
  const toast = useToast();
  const ref = useRef<HTMLElement>(null);
  const q = useQuery({
    queryKey: ['backup-self'],
    queryFn: () => api.get<SelfBackup>('/backup/self'),
    refetchInterval: (query) => (query.state.data?.runs.some((r) => r.status === 'queued' || r.status === 'running') ? 3_000 : 30_000),
  });
  const destQ = useQuery({
    queryKey: ['destinations'],
    queryFn: () => api.get<ItemList<Destination>>('/destinations'),
    enabled: isAdmin,
  });
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
  const last = v.runs[0];
  const lastOk = v.runs.find((r) => r.status === 'succeeded');
  const busy = v.runs.some((r) => r.status === 'queued' || r.status === 'running');
  const dests = destQ.data?.items ?? [];
  const picker = (
    <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
      <Select
        aria-label="Destination"
        value={dest || v.job?.destination_id || ''}
        onChange={setDest}
        placeholder={dests.length ? 'Choose a destination' : 'No destinations yet'}
        options={dests.map((d) => ({
          value: d.id,
          label: d.name,
          hint: d.kind,
        }))}
        disabled={!dests.length}
      />
      <button type="button" className="btn pri" disabled={!(dest || v.job?.destination_id) || save.isPending} onClick={() => save.mutate({ destination_id: dest || v.job?.destination_id })}>
        {v.configured ? 'Save' : 'Back up Olympos here'}
      </button>
      {v.configured && (
        <button type="button" className="btn" onClick={() => setEditing(false)}>
          Cancel
        </button>
      )}
      {!dests.length && (
        <Link to="/settings/destinations" className="small">
          Add a destination
        </Link>
      )}
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
                {editing && isAdmin ? picker : v.job?.destination_name}
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
                  </span>
                ) : (
                  <span className="muted">Not yet</span>
                )}
              </dd>
              <dt>Last run</dt>
              <dd>{last ? <RunBadge run={last} /> : <span className="muted">Not yet</span>}</dd>
            </dl>
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
              <Modal open onClose={() => setShowRestore(false)} size="xl" eyebrow="olympos-self" title="Restore the Olympos database" description="Latest successful dump. The same Key Vault (KEK) is required.">
                <RestoreSteps guide={v.restore} />
              </Modal>
            )}
          </>
        )}
      </div>
    </section>
  );
}
