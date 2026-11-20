// Details of one backup run and, for a successful run, the ready-to-copy
// restore commands for exactly that run (F19). Restore through the UI (to a
// new target, maker/checker) is planned for v0.2.
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { BackupRunDetail, RestoreGuide } from '../api/types';
import { between, bytes, duration, relDateTime } from '../lib/format';
import { CopyButton, Modal, QueryView } from './kit';
import { DocLink, WithDocLinks } from './DocLinks';
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

export function BackupRunDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({
    queryKey: ['backup-run', id],
    queryFn: () => api.get<BackupRunDetail>(`/backup/runs/${id}`),
  });
  const r = q.data;
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
                <RunBadge run={run} />
              </dd>
              <dt>Size</dt>
              <dd>{run.bytes ? bytes(run.bytes) : '—'}</dd>
              <dt>Duration</dt>
              <dd>{duration(between(run.started_at, run.finished_at))}</dd>
              {run.blob_path && (
                <>
                  <dt>Blob</dt>
                  <dd className="mono small break">{run.blob_path}</dd>
                  <dt>SHA-256</dt>
                  <dd className="mono small break">{run.sha256}</dd>
                </>
              )}
            </dl>
            {run.restore ? <RestoreSteps guide={run.restore} /> : run.status === 'succeeded' ? <p className="muted small">Dry runs only check the setup; they are not restorable backups.</p> : null}
          </div>
        )}
      </QueryView>
    </Modal>
  );
}
