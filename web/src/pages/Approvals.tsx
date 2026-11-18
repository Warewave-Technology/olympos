import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { ChangeRequest, ItemList, Vault } from '../api/types';
import { useMe } from '../auth/me';
import { approveControl, can, isSelf, rejectControl } from '../auth/permissions';
import { dateTime, personName, relDateTime, shortId, timeLeft } from '../lib/format';
import { approvalsRoute } from '../router';
import { Badge, DetailPlaceholder, EmptyState, ErrorState, Field, FormError, Loading, QueryView, aria, fieldError, useNow, useToast } from '../ui/kit';
import { CrStatusBadge, OpBadge, PageHead, crLabel, opLabel } from '../ui/status';
import { VaultIdentity, vaultPath } from '../ui/vault';

type View = 'waiting' | 'mine' | 'all';

function summary(cr: ChangeRequest): string {
  if (cr.items.length === 1) {
    const i = cr.items[0];
    return i.op === 'destroy_history' ? `Destroy history of ${i.mount}${i.path}` : `${opLabel(i.op)} ${i.key}`;
  }
  const counts = new Map<string, number>();
  for (const i of cr.items) counts.set(i.op, (counts.get(i.op) ?? 0) + 1);
  const words: Record<string, string> = { create: 'add', replace: 'replace', delete: 'delete', destroy_history: 'destroy history' };
  const parts = [...counts.entries()].map(([op, n]) => `${words[op] ?? op} ${n}${op === 'destroy_history' ? '' : n === 1 ? ' key' : ' keys'}`);
  const s = parts.join(', ');
  return s[0].toUpperCase() + s.slice(1);
}

/** Namespace of the CR's vault: from the CR when the server sends it, else from GET /vaults. */
function useVaultNamespaces(): (cr: ChangeRequest) => string | undefined {
  const q = useQuery({ queryKey: ['vaults'], queryFn: () => api.get<ItemList<Vault>>('/vaults'), staleTime: 60_000 });
  return (cr) => cr.vault.namespace || q.data?.items.find((v) => v.id === cr.vault.id)?.target.namespace;
}

export function crVaultPath(cr: ChangeRequest, ns?: string): string {
  return vaultPath({ cluster: cr.vault.cluster_name, namespace: ns, service: cr.vault.name });
}

function pathOf(cr: ChangeRequest): string {
  const paths = Array.from(new Set(cr.items.map((i) => `${i.mount}${i.path.split('/')[0]}`)));
  return paths.join(', ');
}

export function ApprovalsPage() {
  const me = useMe();
  const search = approvalsRoute.useSearch();
  const navigate = useNavigate({ from: '/approvals' });
  const canApprove = can(me, 'vault_approve');
  const view: View = search.view ?? (canApprove ? 'waiting' : 'mine');
  const now = useNow(30_000);
  const params = view === 'waiting' ? { waiting_for_me: true, status: 'pending' } : view === 'mine' ? { mine: true } : {};
  const listQ = useQuery({ queryKey: ['change-requests', params], queryFn: () => api.get<ItemList<ChangeRequest>>('/change-requests', params), refetchInterval: 30_000 });
  const items = listQ.data?.items ?? [];
  const selectedId = search.cr ?? items[0]?.id;
  const nsOf = useVaultNamespaces();

  const views: { id: View; label: string }[] = [
    ...(canApprove ? [{ id: 'waiting' as const, label: 'Waiting for me' }] : []),
    { id: 'mine', label: 'Opened by me' },
    { id: 'all', label: 'All' },
  ];

  return (
    <>
      <PageHead title="Approvals" sub="Vault changes wait here for a second person. You cannot approve a request you opened." />
      <div className="split">
        <aside className="card split-list" aria-label="Change requests">
          <div className="pills" role="group" aria-label="Show" style={{ padding: '4px 4px 10px' }}>
            {views.map((v) => (
              <button key={v.id} type="button" className="pill" aria-pressed={view === v.id} onClick={() => navigate({ search: { view: v.id }, replace: true })}>
                {v.label}
                {v.id === 'waiting' && view === 'waiting' && listQ.data ? ` · ${items.length}` : ''}
              </button>
            ))}
          </div>
          <QueryView
            q={listQ}
            what="change requests"
            isEmpty={(d) => d.items.length === 0}
            empty={
              <EmptyState title={view === 'waiting' ? 'Nothing waits for you' : view === 'mine' ? 'You have not opened any requests' : 'No change requests yet'}>
                {view === 'waiting' ? 'When someone else opens a vault change in your scope, it shows up here. You also get the Slack link.' : 'Open one from Vaults: pick a key and choose Replace, Add key or Delete.'}
              </EmptyState>
            }
          >
            {(d) =>
              d.items.map((cr) => {
                const mine = isSelf(me, cr.maker);
                return (
                  <button key={cr.id} type="button" className="li" aria-current={cr.id === selectedId} onClick={() => navigate({ search: (s) => ({ ...s, cr: cr.id }), replace: true })}>
                    <div className="l1">
                      <span className="mono">{crLabel(cr)}</span>
                      {cr.status === 'pending' ? (
                        mine ? (
                          <Badge tone="mute">Awaiting other</Badge>
                        ) : (
                          <span className="muted small">{timeLeft(cr.expires_at, now)}</span>
                        )
                      ) : (
                        <CrStatusBadge cr={cr} />
                      )}
                    </div>
                    <div className="l2">{summary(cr)}</div>
                    <div className="l3 mono">{crVaultPath(cr, nsOf(cr))}</div>
                    <div className="l3">
                      {mine && cr.status === 'pending' ? `Approve disabled: you are the maker · ${pathOf(cr)}` : `${personName(cr.maker)} · ${pathOf(cr)}`}
                    </div>
                  </button>
                );
              })
            }
          </QueryView>
        </aside>
        <div className="split-detail">
          {selectedId ? (
            <CrDetail id={selectedId} key={selectedId} />
          ) : (
            <DetailPlaceholder title={listQ.isPending ? 'Loading change requests…' : view === 'waiting' ? 'Nothing to review right now' : 'No change request selected'}>
              {view === 'waiting'
                ? 'When a request waits for you, its keys, operations and value fingerprints open here, with Approve & apply and Reject.'
                : view === 'mine'
                  ? 'Requests you open from Vaults show up in the list; pick one to follow its approval trail.'
                  : 'Pick a request from the list to see what it changes and who decided.'}
            </DetailPlaceholder>
          )}
        </div>
      </div>
    </>
  );
}

function CrDetail({ id }: { id: string }) {
  const me = useMe();
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({
    queryKey: ['change-requests', id],
    queryFn: () => api.get<ChangeRequest>(`/change-requests/${id}`),
    // 'applying' is settled within minutes (outcome recorded or reconciled).
    refetchInterval: (query) => (query.state.data?.status === 'applying' ? 15_000 : false),
  });
  const nsOf = useVaultNamespaces();
  const [comment, setComment] = useState('');
  const [commentErr, setCommentErr] = useState<string | undefined>();
  const done = (verb: string) => (cr: ChangeRequest) => {
    setComment('');
    qc.setQueryData(['change-requests', id], cr);
    void qc.invalidateQueries({ queryKey: ['change-requests'] });
    void qc.invalidateQueries({ queryKey: ['vault-secret'] });
    if (cr.status === 'applying') {
      toast(`${crLabel(cr)} approved. Olympos is still confirming the write with the vault; this page updates when it is settled.`, 'warn');
      return;
    }
    toast(cr.status === 'failed' ? `Approved, but applying failed: ${cr.failure}` : `${crLabel(cr)} ${verb}.`, cr.status === 'failed' ? 'crit' : 'ok');
  };
  const approve = useMutation({ mutationFn: () => api.post<ChangeRequest>(`/change-requests/${id}/approve`, { comment }), onSuccess: done('approved and applied') });
  const reject = useMutation({ mutationFn: () => api.post<ChangeRequest>(`/change-requests/${id}/reject`, { comment }), onSuccess: done('rejected') });
  const cancel = useMutation({ mutationFn: () => api.post<ChangeRequest>(`/change-requests/${id}/cancel`), onSuccess: done('cancelled') });

  if (q.isPending) return <section className="card"><Loading label="Loading change request…" /></section>;
  if (q.isError) return <section className="card"><ErrorState what="this change request" error={q.error} onRetry={() => q.refetch()} /></section>;
  const cr = q.data;
  const ap = approveControl(me, cr);
  const canReject = rejectControl(me, cr);
  const err = approve.error ?? reject.error ?? cancel.error;
  const busy = approve.isPending || reject.isPending || cancel.isPending;

  return (
    <>
      <section className="card pad-lg" aria-labelledby="cr-t" style={{ gap: 20 }}>
        <div className="card-title">
          <div>
            <div className="eyebrow">Change request</div>
            <div className="inline">
              <h2 id="cr-t" className="mono">
                {crLabel(cr)}
              </h2>
              <CrStatusBadge cr={cr} />
            </div>
            <div className="muted" style={{ fontSize: 13, marginTop: 6 }}>
              Opened by {personName(cr.maker)} · {relDateTime(cr.created_at)}
              {cr.status === 'pending' ? ` · expires ${dateTime(cr.expires_at)}` : ''}
            </div>
          </div>
        </div>

        <dl className="dl narrow">
          <dt>Vault</dt>
          <dd>
            <VaultIdentity cluster={cr.vault.cluster_name} namespace={nsOf(cr)} service={cr.vault.name} provider={cr.vault.provider} version={cr.vault.version} compact />
          </dd>
          <dt>Maker</dt>
          <dd>
            {personName(cr.maker)} <span className="mono muted">oid {shortId(cr.maker.object_id)}</span>
          </dd>
          <dt>Justification</dt>
          <dd>{cr.justification || <span className="muted">—</span>}</dd>
          {cr.checker && (
            <>
              <dt>Checker</dt>
              <dd>
                {personName(cr.checker)} <span className="mono muted">oid {shortId(cr.checker.object_id)}</span>
                {cr.decided_at ? ` · ${dateTime(cr.decided_at)}` : ''}
              </dd>
            </>
          )}
          {cr.decision_comment && (
            <>
              <dt>Comment</dt>
              <dd>{cr.decision_comment}</dd>
            </>
          )}
          {cr.failure && (
            <>
              <dt>Failure</dt>
              <dd className="ico-crit">{cr.failure}</dd>
            </>
          )}
        </dl>

        <div className="boxed tight table-wrap">
          <table className="t">
            <thead>
              <tr>
                <th>Path</th>
                <th>Key</th>
                <th>Operation</th>
                <th>New value</th>
                <th>Base version</th>
              </tr>
            </thead>
            <tbody>
              {cr.items.map((i) => (
                <tr key={i.id}>
                  <td className="mono wrap break">
                    {i.mount}
                    {i.path}
                  </td>
                  <td className="mono">{i.key ?? <span className="muted">all keys</span>}</td>
                  <td>
                    <OpBadge op={i.op} />
                  </td>
                  <td className="mono">
                    {i.op === 'destroy_history' ? (
                      <span className="ico-crit">versions {i.versions.map((v) => `v${v}`).join(', ')}</span>
                    ) : i.op === 'delete' ? (
                      <span className="muted">key removed</span>
                    ) : (
                      <span aria-label={`HMAC fingerprint ${i.fingerprint}`}>{i.fingerprint}</span>
                    )}
                  </td>
                  <td className="mono">v{i.base_version} (cas check)</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small" style={{ margin: '-8px 0 0' }}>
          You see a fingerprint, not the value. Compare it with the maker over a separate channel if needed. If the secret changes before you approve, the apply fails and the request is closed.
        </p>
        {cr.items.some((i) => i.op === 'destroy_history') && (
          <div className="note crit">This request permanently destroys whole versions, including every other key stored in them. It cannot be undone.</div>
        )}

        {(ap.visible || canReject || cr.can_cancel) && cr.status === 'pending' && (
          <>
            {(canReject || (ap.visible && ap.enabled)) && (
              <Field label="Comment (required to reject)" htmlFor="cr-comment" error={commentErr ?? fieldError(reject.error, 'comment')}>
                <textarea
                  className="in"
                  rows={2}
                  {...aria('cr-comment', commentErr ?? fieldError(reject.error, 'comment'))}
                  value={comment}
                  onChange={(e) => {
                    setComment(e.target.value);
                    setCommentErr(undefined);
                  }}
                  placeholder="Optional note for the audit trail"
                />
              </Field>
            )}
            <FormError error={err && !fieldError(err, 'comment') ? err : null} />
            <div className="end" style={{ alignItems: 'center' }}>
              {ap.visible && !ap.enabled && (
                <span className="muted small" id="approve-why">
                  {ap.reason}
                </span>
              )}
              {cr.can_cancel && (
                <button type="button" className="btn" onClick={() => cancel.mutate()} disabled={busy}>
                  Withdraw request
                </button>
              )}
              {canReject && (
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
              )}
              {ap.visible && (
                <button type="button" className="btn pri" disabled={!ap.enabled || busy} aria-describedby={!ap.enabled ? 'approve-why' : undefined} onClick={() => approve.mutate()}>
                  {approve.isPending ? 'Applying…' : 'Approve & apply'}
                </button>
              )}
            </div>
          </>
        )}
      </section>

      <section className="card pad" aria-labelledby="trail-t">
        <h2 id="trail-t" className="title">
          Trail
        </h2>
        {cr.events.length === 0 ? (
          <p className="muted small">No events recorded.</p>
        ) : (
          <ol className="trail">
            {cr.events.map((e, i) => (
              <li className="tl" key={i}>
                <span className={`dot ${e.kind === 'applied' || e.kind === 'approved' ? 'ok' : e.kind === 'rejected' || e.kind === 'failed' ? 'crit' : e.kind === 'expired' || e.kind === 'cancelled' ? 'muted' : ''}`} aria-hidden="true" />
                <div>
                  <div>{eventText(e)}</div>
                  <div className="muted mono small" style={{ marginTop: 2 }}>
                    {dateTime(e.at)}
                    {eventDetail(e) ? ` · ${eventDetail(e)}` : ''}
                  </div>
                </div>
              </li>
            ))}
            {cr.status === 'pending' && (
              <li className="tl">
                <span className="dot orange" aria-hidden="true" />
                <div>
                  <div>Waiting for an approver other than the maker</div>
                  <div className="muted mono small" style={{ marginTop: 2 }}>
                    {cr.eligible_approvers !== undefined ? `eligible: ${cr.eligible_approvers} people with vault-approver` : 'needs vault-approver in scope of the vault’s cluster'}
                  </div>
                </div>
              </li>
            )}
          </ol>
        )}
      </section>
    </>
  );
}

function eventText(e: ChangeRequest['events'][number]) {
  const who = <b>{e.actor_name}</b>;
  switch (e.kind) {
    case 'opened':
      return <>Opened by {who}</>;
    case 'approved':
      return <>Approved by {who}</>;
    case 'rejected':
      return <>Rejected by {who}</>;
    case 'applying':
      return <>Writing to the vault</>;
    case 'applied':
      return e.details?.reconciled ? <>Applied to Vault (confirmed from the vault metadata)</> : <>Applied to Vault</>;
    case 'failed':
      return <>Apply failed</>;
    case 'expired':
      return <>Expired without a decision</>;
    case 'cancelled':
      return <>Withdrawn by {who}</>;
    case 'notified':
      return (
        <>
          Slack notice sent to <b>{String(e.details?.channel ?? 'the routed channel')}</b>
        </>
      );
    default:
      return (
        <>
          {e.kind} · {who}
        </>
      );
  }
}

function eventDetail(e: ChangeRequest['events'][number]): string {
  const d = e.details ?? {};
  if (e.kind === 'opened' && d.sealed_with) return `value sealed with ${String(d.sealed_with)}`;
  if (e.kind === 'opened') return 'value sealed with the Key Vault key';
  if (e.kind === 'notified') return 'link only, no approve button';
  if (e.kind === 'applied' && d.version) return `new version v${String(d.version)}`;
  if ((e.kind === 'approved' || e.kind === 'rejected') && d.comment) return `“${String(d.comment)}”`;
  if (e.kind === 'failed' && d.failure) return String(d.failure);
  if (e.kind === 'failed' && d.error) return String(d.error);
  return '';
}
