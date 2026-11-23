// A restore request on the Approvals page: the request as the checker sees it,
// the decision (approve, reject, withdraw), progress while it runs and the
// result (docs/design/ui-restore.md "API, UI, notifications").
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { DestinationKind, RestoreRequest } from '../api/types';
import { useMe } from '../auth/me';
import { isSelf } from '../auth/permissions';
import { dateTime, personName, relDateTime, shortId } from '../lib/format';
import { KindBadge } from '../ui/destinations';
import { Badge, ErrorState, Field, FormError, Loading, aria, fieldError, useToast } from '../ui/kit';
import { ClickHouseScopeNote, RestoreProgressView, RestoreResultView, RestoreStatusBadge, VaultTokenNeeds, VaultUnsealNote, restoreEngineName, restorePath } from '../ui/restore';

const KNOWN_KINDS = ['azure_blob', 's3', 'nfs'];

function Who({ p }: { p: RestoreRequest['maker'] }) {
  return (
    <>
      {personName(p)} <span className="mono muted">oid {shortId(p.object_id)}</span>
    </>
  );
}

type TrailEntry = { at: string | null; text: React.ReactNode; detail?: string; tone?: 'ok' | 'crit' | 'muted' | 'orange' | '' };

function trail(rq: RestoreRequest): TrailEntry[] {
  const out: TrailEntry[] = [{ at: rq.created_at, text: <>Opened by <b>{personName(rq.maker)}</b></>, detail: 'the open-time check passed; the credential is held encrypted until the request ends' }];
  if (rq.break_glass) {
    out.push({ at: rq.decided_at, text: <>Started at once as <b>break-glass</b> by <b>{personName(rq.maker)}</b></>, detail: 'no checker · restore.break_glass sent', tone: 'crit' });
  } else if (rq.checker && rq.status === 'rejected') {
    out.push({ at: rq.decided_at, text: <>Rejected by <b>{personName(rq.checker)}</b></>, detail: rq.decision_comment ? `“${rq.decision_comment}”` : undefined, tone: 'crit' });
  } else if (rq.checker) {
    out.push({ at: rq.decided_at, text: <>Approved by <b>{personName(rq.checker)}</b></>, detail: rq.decision_comment ? `“${rq.decision_comment}”` : undefined, tone: 'ok' });
  }
  if (rq.status === 'cancelled') out.push({ at: rq.finished_at, text: <>Withdrawn by <b>{personName(rq.maker)}</b></>, tone: 'muted' });
  if (rq.status === 'expired')
    out.push({ at: rq.finished_at, text: rq.decided_at ? <>Expired: approved but not started within 24 hours</> : <>Expired without a decision</>, detail: 'the credential and token were wiped', tone: 'muted' });
  if (rq.started_at) out.push({ at: rq.started_at, text: <>Restore started</> });
  if (rq.status === 'succeeded') out.push({ at: rq.finished_at, text: <>Restore succeeded</>, detail: 'the credential and token were wiped', tone: 'ok' });
  if (rq.status === 'failed') out.push({ at: rq.finished_at, text: <>Restore failed</>, detail: 'the credential and token were wiped', tone: 'crit' });
  if (rq.status === 'pending') out.push({ at: null, text: <>Waiting for a checker other than the maker</>, detail: 'needs operate on the backup’s and the target’s cluster; guests cannot approve', tone: 'orange' });
  if (rq.status === 'approved') out.push({ at: null, text: <>Waiting to start</>, detail: rq.approved_expires_at ? `the backup worker starts it when the target's agent is connected; expires ${dateTime(rq.approved_expires_at)}` : undefined, tone: 'orange' });
  return out;
}

export function RestoreDetail({ id }: { id: string }) {
  const me = useMe();
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({
    queryKey: ['restores', id],
    queryFn: () => api.get<RestoreRequest>(`/restores/${id}`),
    // follow an approved request until it starts, and a running one until it ends
    refetchInterval: (query) => (query.state.data?.status === 'running' || query.state.data?.status === 'approved' ? 5_000 : false),
  });
  const [comment, setComment] = useState('');
  const [commentErr, setCommentErr] = useState<string | undefined>();
  const done = (msg: (rq: RestoreRequest) => string) => (rq: RestoreRequest) => {
    setComment('');
    qc.setQueryData(['restores', id], rq);
    void qc.invalidateQueries({ queryKey: ['restores'] });
    toast(msg(rq), 'ok');
  };
  // A refused decision (409: expired, decided by someone else, target busy) means the request changed: reload it.
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ['restores', id] });
    void qc.invalidateQueries({ queryKey: ['restores'] });
  };
  const approve = useMutation({
    mutationFn: () => api.post<RestoreRequest>(`/restores/${id}/approve`, { comment }),
    onSuccess: done(() => 'Restore approved. It starts when the target’s agent is connected.'),
    onError: refresh,
  });
  const reject = useMutation({ mutationFn: () => api.post<RestoreRequest>(`/restores/${id}/reject`, { comment }), onSuccess: done(() => 'Restore request rejected.'), onError: refresh });
  const cancel = useMutation({ mutationFn: () => api.post<RestoreRequest>(`/restores/${id}/cancel`), onSuccess: done(() => 'Restore request withdrawn. The target is free again.'), onError: refresh });

  if (q.isPending)
    return (
      <section className="card">
        <Loading label="Loading restore request…" />
      </section>
    );
  if (q.isError)
    return (
      <section className="card">
        <ErrorState what="this restore request" error={q.error} onRetry={() => q.refetch()} />
      </section>
    );
  const rq = q.data;
  const mine = isSelf(me, rq.maker);
  const pending = rq.status === 'pending';
  // Checker controls: never for the maker (they withdraw instead); the server decides can_approve.
  const mayDecide = pending && !mine && rq.can_approve;
  const whyNot = pending && !mine && !rq.can_approve ? rq.approve_disabled_reason : '';
  const err = approve.error ?? reject.error ?? cancel.error;
  const busy = approve.isPending || reject.isPending || cancel.isPending;
  const kind = restoreEngineName(rq.engine, rq.target.vault_provider);
  const isVault = rq.engine === 'vault';
  const nonSuper = rq.engine === 'postgresql' && rq.options.superuser === false;
  const notes = rq.options.notes ?? [];
  const destKind = KNOWN_KINDS.includes(rq.source.destination_kind) ? (rq.source.destination_kind as DestinationKind) : null;

  return (
    <>
      <section className="card pad-lg" aria-labelledby="rs-t" style={{ gap: 20 }}>
        <div className="card-title">
          <div>
            <div className="eyebrow">Restore request</div>
            <div className="inline">
              <h2 id="rs-t">{kind} restore</h2>
              <RestoreStatusBadge status={rq.status} />
              {rq.break_glass && <Badge tone="crit">Break-glass</Badge>}
            </div>
            <div className="muted" style={{ fontSize: 13, marginTop: 6 }}>
              Opened by {personName(rq.maker)} · {relDateTime(rq.created_at)}
              {pending ? ` · expires ${dateTime(rq.expires_at)}` : ''}
              {rq.status === 'approved' && rq.approved_expires_at ? ` · must start before ${dateTime(rq.approved_expires_at)}` : ''}
            </div>
          </div>
        </div>

        {rq.break_glass && (
          <div className="note crit">
            Started without a checker (break-glass) by {personName(rq.maker)}
            {rq.decided_at ? ` at ${dateTime(rq.decided_at)}` : ''}. It is recorded in the audit log and a critical notification (<span className="mono">restore.break_glass</span>) was sent.
          </div>
        )}

        <dl className="dl narrow">
          <dt>Backup</dt>
          <dd>
            <span className="mono">{restorePath(rq.source)}</span>
            <div className="muted small">
              copy <span className="mono">{rq.source.destination_name}</span> {destKind && <KindBadge kind={destKind} />} · run <span className="mono">{shortId(rq.source.run_id)}</span>
              {rq.source.copy_run_id && rq.source.copy_run_id !== rq.source.run_id ? (
                <>
                  {' '}
                  (written by repair <span className="mono">{shortId(rq.source.copy_run_id)}</span>)
                </>
              ) : null}
            </div>
          </dd>
          <dt>Target</dt>
          <dd>
            <span className="mono">
              {restorePath(rq.target)}:{rq.target.port}
            </span>
            {rq.options.server_version ? <span className="muted"> · {kind} {rq.options.server_version}</span> : null}
          </dd>
          <dt>{isVault ? 'Restores' : 'Databases'}</dt>
          <dd>
            {isVault ? (
              'The whole snapshot (it replaces all of the target’s data)'
            ) : (
              <span className="mono">{rq.databases.join(', ')}</span>
            )}
          </dd>
          {rq.engine === 'postgresql' && (
            <>
              <dt>Roles</dt>
              <dd>{rq.options.globals ? <>Restored from <span className="mono">globals.sql</span> (superuser credential)</> : nonSuper ? 'Not restored: the credential is not a superuser' : 'Not restored: turned off for this request'}</dd>
            </>
          )}
          <dt>{isVault ? 'Token' : 'Credential'}</dt>
          <dd>
            {isVault ? (
              rq.has_vault_token ? (
                <>
                  A token of the new Vault is held, sealed, until the request ends. <span className="muted small"><VaultTokenNeeds /></span>
                </>
              ) : (
                <span className="muted">Wiped (the request has ended)</span>
              )
            ) : rq.credential ? (
              <>
                <span className="mono">{rq.credential.username}</span> ·{' '}
                {rq.credential.source === 'keyvault_ref' ? (
                  <>
                    Key Vault reference <span className="mono">{rq.credential.ref}</span>
                  </>
                ) : (
                  'stored in Olympos, encrypted'
                )}{' '}
                <span className="muted small">· deleted when the request ends</span>
              </>
            ) : (
              <span className="muted">Deleted (the request has ended)</span>
            )}
          </dd>
          {rq.options.tls_ca_pem && (
            <>
              <dt>Target CA</dt>
              <dd>
                <details>
                  <summary className="small">Certificate given to verify the target (PEM)</summary>
                  <pre className="code small break">{rq.options.tls_ca_pem}</pre>
                </details>
              </dd>
            </>
          )}
          <dt>Maker</dt>
          <dd>
            <Who p={rq.maker} />
          </dd>
          <dt>Justification</dt>
          <dd className="break">{rq.justification || <span className="muted">—</span>}</dd>
          {rq.checker && (
            <>
              <dt>Checker</dt>
              <dd>
                <Who p={rq.checker} />
                {rq.decided_at ? ` · ${dateTime(rq.decided_at)}` : ''}
              </dd>
            </>
          )}
          {rq.decision_comment && (
            <>
              <dt>Comment</dt>
              <dd>{rq.decision_comment}</dd>
            </>
          )}
        </dl>

        {notes.length > 0 && (
          <div className={`note${nonSuper ? ' warn' : ''}`}>
            <div className="note-title">{nonSuper ? 'Not a superuser: owners, privileges and roles are not restored' : 'Found by the open-time check'}</div>
            <ul className="note-list">
              {notes.map((n, i) => (
                <li key={i}>{n}</li>
              ))}
            </ul>
          </div>
        )}
        {pending && rq.engine === 'clickhouse' && <ClickHouseScopeNote />}
        {pending && isVault && <VaultUnsealNote />}

        {pending && mayDecide && (
          <>
            <div className="note">
              Approving lets the server restore this backup into the target as soon as its agent is connected; it must start within 24 hours. The backup&apos;s checksum is verified before anything is written, and the
              target is checked again when the restore starts.
            </div>
            <Field label="Comment (required to reject)" htmlFor="rs-comment" error={commentErr ?? fieldError(reject.error, 'comment')}>
              <textarea
                className="in"
                rows={2}
                {...aria('rs-comment', commentErr ?? fieldError(reject.error, 'comment'))}
                value={comment}
                onChange={(e) => {
                  setComment(e.target.value);
                  setCommentErr(undefined);
                }}
                placeholder="Optional note for the audit trail"
              />
            </Field>
          </>
        )}
        <FormError error={err && !fieldError(err, 'comment') ? err : null} />
        {(mayDecide || rq.can_cancel || (pending && mine) || whyNot) && (
          <div className="end" style={{ alignItems: 'center' }}>
            {pending && mine && (
              <span className="muted small" id="rs-why-not">
                You opened this request. Another person with operate on both clusters must decide.
              </span>
            )}
            {whyNot && (
              <span className="muted small" id="rs-why-not">
                {whyNot}
              </span>
            )}
            {rq.can_cancel && (
              <button type="button" className="btn" onClick={() => cancel.mutate()} disabled={busy}>
                Withdraw request
              </button>
            )}
            {mayDecide && (
              <>
                <button
                  type="button"
                  className="btn rej"
                  disabled={busy}
                  onClick={() => {
                    if (!comment.trim()) {
                      setCommentErr('Explain why you reject the request.');
                      return;
                    }
                    reject.mutate();
                  }}
                >
                  Reject
                </button>
                <button type="button" className="btn pri" disabled={busy} onClick={() => approve.mutate()}>
                  {approve.isPending ? 'Approving…' : 'Approve restore'}
                </button>
              </>
            )}
          </div>
        )}
      </section>

      {rq.status === 'running' && (
        <section className="card pad" aria-labelledby="rs-progress-t">
          <h2 id="rs-progress-t" className="title">
            Progress
          </h2>
          <RestoreProgressView progress={rq.progress} engine={rq.engine} />
          <p className="muted small" style={{ margin: '10px 0 0' }}>
            Verify the backup&apos;s checksum, check the target again, then restore. This page updates every few seconds.
          </p>
        </section>
      )}

      {(rq.status === 'succeeded' || rq.status === 'failed') && (
        <section className="card pad" aria-labelledby="rs-result-t">
          <h2 id="rs-result-t" className="title">
            Result
          </h2>
          <RestoreResultView rq={rq} />
        </section>
      )}

      <section className="card pad" aria-labelledby="rs-trail-t">
        <h2 id="rs-trail-t" className="title">
          Trail
        </h2>
        <ol className="trail">
          {trail(rq).map((e, i) => (
            <li className="tl" key={i}>
              <span className={`dot ${e.tone ?? ''}`} aria-hidden="true" />
              <div>
                <div>{e.text}</div>
                {(e.at || e.detail) && (
                  <div className="muted mono small" style={{ marginTop: 2 }}>
                    {e.at ? dateTime(e.at) : ''}
                    {e.at && e.detail ? ' · ' : ''}
                    {e.detail ?? ''}
                  </div>
                )}
              </div>
            </li>
          ))}
        </ol>
      </section>
    </>
  );
}
