import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { ItemList, SecretDetail, SecretSummary, Vault } from '../api/types';
import { useCan } from '../auth/me';
import { ago, age, engineLabel, shortDate } from '../lib/format';
import { vaultsRoute } from '../router';
import { Badge, EmptyState, ErrorState, Loading, QueryView, SecretValue, useToast } from '../ui/kit';
import { PageHead } from '../ui/status';
import { Select } from '../ui/Select';
import { ChangeRequestDrawer, DeleteDestroyDialog, VaultConfigureDialog } from './VaultDialogs';

function vaultStatus(v: Vault) {
  switch (v.status) {
    case 'configured':
      return <Badge tone="ok">Configured</Badge>;
    case 'discovered':
      return <Badge tone="info">Discovered</Badge>;
    case 'error':
      return <Badge tone="crit">Error</Badge>;
    default:
      return <Badge tone="mute">Gone</Badge>;
  }
}

interface TreeNode {
  dir: string;
  items: SecretSummary[];
}
function groupTree(list: SecretSummary[]): TreeNode[] {
  const m = new Map<string, SecretSummary[]>();
  for (const s of list) {
    const i = s.path.lastIndexOf('/');
    const dir = i >= 0 ? s.path.slice(0, i + 1) : '';
    m.set(dir, [...(m.get(dir) ?? []), s]);
  }
  return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([dir, items]) => ({ dir, items: items.sort((a, b) => a.path.localeCompare(b.path)) }));
}

type Action = { kind: 'replace'; key: string } | { kind: 'add' } | { kind: 'delete'; key: string } | { kind: 'destroy' } | { kind: 'configure' } | null;

export function VaultsPage() {
  const search = vaultsRoute.useSearch();
  const navigate = useNavigate({ from: '/vaults' });
  const canMake = useCan('vault_make');
  const canAdmin = useCan('admin');
  const [action, setAction] = useState<Action>(null);

  const vaultsQ = useQuery({ queryKey: ['vaults'], queryFn: () => api.get<ItemList<Vault>>('/vaults') });
  const vaults = vaultsQ.data?.items ?? [];
  const vault = vaults.find((v) => v.id === search.vault) ?? vaults.find((v) => v.status === 'configured') ?? vaults[0];
  const v2 = (vault?.kv_mounts ?? []).filter((m) => m.version === 2 && m.managed);
  const v1 = (vault?.kv_mounts ?? []).filter((m) => m.version === 1);
  const mount = search.mount && v2.some((m) => m.path === search.mount) ? search.mount : v2[0]?.path;

  const treeQ = useQuery({
    queryKey: ['vault-tree', vault?.id, mount],
    queryFn: () => api.get<ItemList<SecretSummary>>(`/vaults/${vault!.id}/tree`, { mount }),
    enabled: !!vault && vault.status === 'configured' && !!mount,
  });
  const tree = useMemo(() => groupTree(treeQ.data?.items ?? []), [treeQ.data]);
  const path = search.path && treeQ.data?.items.some((s) => s.path === search.path) ? search.path : treeQ.data?.items[0]?.path;

  const secretQ = useQuery({
    queryKey: ['vault-secret', vault?.id, mount, path],
    queryFn: () => api.get<SecretDetail>(`/vaults/${vault!.id}/secrets/${path!.split('/').map(encodeURIComponent).join('/')}`, { mount }),
    enabled: !!vault && !!mount && !!path,
  });
  const secret = secretQ.data;

  const select = (patch: { vault?: string; mount?: string; path?: string }) => navigate({ search: (s) => ({ ...s, ...patch }), replace: true });
  useEffect(() => setAction(null), [vault?.id, path]);

  const qc = useQueryClient();
  const toast = useToast();
  const refresh = useMutation({
    mutationFn: () => api.post(`/vaults/${vault!.id}/refresh`),
    onSuccess: () => {
      toast('Index refresh started.');
      setTimeout(() => void qc.invalidateQueries({ queryKey: ['vault-tree'] }), 1500);
    },
    onError: () => toast('Could not start an index refresh.', 'crit'),
  });

  return (
    <>
      <PageHead title="Vaults" sub="You see keys, never values. Every change needs approval from a second person." />
      {vaultsQ.isPending && <Loading label="Loading vaults…" />}
      {vaultsQ.isError && (
        <section className="card">
          <ErrorState what="vaults" error={vaultsQ.error} onRetry={() => vaultsQ.refetch()} />
        </section>
      )}
      {vaultsQ.data && vaults.length === 0 && (
        <section className="card">
          <EmptyState title="No vaults discovered yet">
            Annotate the Vault or OpenBao Service with <span className="mono">olympos.io/vault: hashicorp</span> (or <span className="mono">openbao</span>). It appears here as Discovered; an admin then configures it with a root token used once.
          </EmptyState>
        </section>
      )}
      {vault && (
        <div className="split">
          <aside className="card split-list" aria-label="Vault instances">
            <div className="eyebrow">Instances</div>
            {vaults.map((v) => (
              <button key={v.id} type="button" className="li" aria-current={v.id === vault.id} onClick={() => select({ vault: v.id, mount: undefined, path: undefined })}>
                <div className="l1">
                  <span className="mono">{v.target.service}</span>
                  {vaultStatus(v)}
                </div>
                <div className="l3">
                  {v.target.cluster_name} · {engineLabel('vault', v.version, v.provider)}
                  {v.drift > 0 && (
                    <>
                      {' '}
                      · <span className="ico-warn">{v.drift} unmanaged change{v.drift > 1 ? 's' : ''}</span>
                    </>
                  )}
                </div>
              </button>
            ))}
            {vault.status === 'configured' && (
              <>
                <div className="divider" />
                {v2.length > 1 && (
                  <div style={{ padding: '0 8px 8px' }}>
                    <label className="lbl" htmlFor="v-mount" id="v-mount-label">
                      Mount
                    </label>
                    <Select id="v-mount" mono value={mount ?? ''} onChange={(v) => select({ mount: v, path: undefined })} options={v2.map((m) => ({ value: m.path, label: m.path }))} />
                  </div>
                )}
                <div className="eyebrow" style={{ padding: '0 8px 6px' }}>
                  Paths · {mount ?? '—'} (v2)
                </div>
                <QueryView q={treeQ} what="the path tree" isEmpty={(d) => d.items.length === 0} empty={<p className="muted small" style={{ padding: '0 8px' }}>No secrets in this mount yet.</p>}>
                  {() => (
                    <nav className="tree" aria-label="Secret paths">
                      {tree.map((n) => (
                        <div key={n.dir}>
                          {n.dir && (
                            <div className="mono muted small" style={{ padding: '7px 10px 3px' }}>
                              {n.dir}
                            </div>
                          )}
                          {n.items.map((s) => (
                            <button key={s.path} type="button" aria-current={s.path === path} style={{ paddingLeft: n.dir ? 24 : 10 }} onClick={() => select({ path: s.path })}>
                              {s.path.slice(n.dir.length)}
                              {!s.managed && <span className="sr-only"> (unmanaged change)</span>}
                              {!s.managed && (
                                <span className="ico-warn" aria-hidden="true">
                                  {' '}
                                  ⚠
                                </span>
                              )}
                            </button>
                          ))}
                        </div>
                      ))}
                    </nav>
                  )}
                </QueryView>
                {v1.map((m) => (
                  <div key={m.path} className="note" style={{ margin: '10px 4px 0' }}>
                    <span className="mono">{m.path}</span> <Badge tone="mute">KV v1</Badge>
                    <div style={{ marginTop: 6 }}>Read-only, keys not listed. Upgrade to KV v2 to manage this mount.</div>
                  </div>
                ))}
              </>
            )}
          </aside>

          <div className="split-detail">
            {vault.status !== 'configured' ? (
              <section className="card pad-lg">
                <div className="card-title">
                  <div>
                  <div className="eyebrow">{vault.status === 'discovered' ? 'Discovered' : vault.status === 'error' ? 'Error' : 'Gone'}</div>
                  <h2 className="mono">
                    {vault.target.service} · {vault.target.cluster_name}
                  </h2>
                  </div>
                </div>
                {vault.status === 'discovered' && (
                  <p className="muted" style={{ margin: 0 }}>
                    Olympos found this {vault.provider === 'openbao' ? 'OpenBao' : 'Vault'} by annotation but has no access yet. Configuring it creates a narrow <span className="mono">olympos</span> policy and AppRole; the root token is used once and not stored.
                  </p>
                )}
                {vault.status === 'error' && <div className="note crit">{vault.last_error || 'The last index refresh failed.'} Check that the AppRole secret_id in Key Vault is valid, or configure the vault again.</div>}
                {vault.status === 'gone' && <div className="note warn">The agent no longer reports this Service. If it moved, check the annotation on the new Service.</div>}
                {canAdmin && vault.status !== 'gone' ? (
                  <div className="end">
                    <button type="button" className="btn pri" onClick={() => setAction({ kind: 'configure' })}>
                      Configure
                    </button>
                  </div>
                ) : (
                  vault.status === 'discovered' && <p className="muted small" style={{ margin: 0 }}>An Olympos admin must configure this vault.</p>
                )}
              </section>
            ) : !path ? (
              <section className="card">
                {treeQ.isPending ? (
                  <Loading label="Loading secrets…" />
                ) : treeQ.isError ? (
                  <ErrorState what="the secret index" error={treeQ.error} onRetry={() => treeQ.refetch()} />
                ) : (
                  <EmptyState title={mount ? `No secrets in ${mount}` : 'No managed KV v2 mount'} action={canMake && mount ? <button type="button" className="btn" onClick={() => refresh.mutate()}>Refresh index</button> : undefined}>
                    {mount ? 'Secrets written in Vault appear after the next index refresh (every 10 min).' : 'Configure the vault again and select at least one KV v2 mount.'}
                  </EmptyState>
                )}
              </section>
            ) : (
              <SecretPanel
                vault={vault}
                mount={mount!}
                path={path}
                q={secretQ}
                canMake={canMake}
                onAction={setAction}
                onRefresh={() => refresh.mutate()}
              />
            )}
          </div>
        </div>
      )}

      {vault && action?.kind === 'configure' && <VaultConfigureDialog open onClose={() => setAction(null)} vault={vault} />}
      {vault && mount && path && (action?.kind === 'replace' || action?.kind === 'add') && (
        <ChangeRequestDrawer
          key={action.kind === 'replace' ? action.key : '+'}
          open
          onClose={() => setAction(null)}
          vault={vault}
          secret={secret}
          mount={mount}
          path={path}
          keyName={action.kind === 'replace' ? action.key : null}
        />
      )}
      {vault && secret && (action?.kind === 'delete' || action?.kind === 'destroy') && (
        <DeleteDestroyDialog key={action.kind === 'delete' ? action.key : '#'} open onClose={() => setAction(null)} vault={vault} secret={secret} keyName={action.kind === 'delete' ? action.key : null} />
      )}
    </>
  );
}

function SecretPanel({
  vault,
  mount,
  path,
  q,
  canMake,
  onAction,
  onRefresh,
}: {
  vault: Vault;
  mount: string;
  path: string;
  q: ReturnType<typeof useQuery<SecretDetail>>;
  canMake: boolean;
  onAction: (a: Action) => void;
  onRefresh: () => void;
}) {
  const s = q.data;
  return (
    <>
      <section className="card" aria-labelledby="sec-t">
        <div className="card-head">
          <div>
            <h2 id="sec-t" className="mono">
              {mount}
              {path}
            </h2>
            {s && (
              <div className="desc">
                Secret version {s.current_version} · updated {ago(s.updated_time)}
                {s.updated_by_name ? ` by ${s.updated_by_name}` : ''}
              </div>
            )}
          </div>
          <div className="inline">
            {canMake && (
              <button type="button" className="btn" onClick={() => onAction({ kind: 'add' })} disabled={!s}>
                Add key
              </button>
            )}
          </div>
        </div>
        {s && !s.managed && (
          <div className="note warn" style={{ margin: '8px 20px' }}>
            <b>Unmanaged change.</b> Version v{s.current_version} was not written by Olympos (direct Vault access, e.g. break-glass). It is recorded as a <span className="mono">vault-drift</span> finding.
          </div>
        )}
        <QueryView q={q} what="this secret" isEmpty={(d) => d.keys.length === 0} empty={<EmptyState title="This secret has no keys">Add a key with a change request.</EmptyState>}>
          {(d) => (
            <div className="table-wrap">
              <table className="t">
                <thead>
                  <tr>
                    <th>Key</th>
                    <th>Value</th>
                    <th>Last changed</th>
                    <th>Change request</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {d.keys.map((k) => {
                    const info = d.key_info?.find((i) => i.key === k);
                    const pending = info?.pending_cr_id;
                    return (
                      <tr key={k} className={pending ? 'sel' : undefined}>
                        <td className="mono">{k}</td>
                        <td>
                          <SecretValue />
                        </td>
                        <td className="mono">{info ? `v${info.version} · ${shortDate(info.updated_time)}` : `v${d.current_version}`}</td>
                        <td>
                          {pending ? (
                            <Link to="/approvals" search={{ view: 'all', cr: pending }}>
                              <Badge tone="warn">Pending · {info?.pending_cr_label ?? 'open'}</Badge>
                            </Link>
                          ) : info?.last_cr_id ? (
                            <Link to="/approvals" search={{ view: 'all', cr: info.last_cr_id }} className="mono">
                              {info.last_cr_label ?? 'view'}
                            </Link>
                          ) : (
                            <span className="muted">—</span>
                          )}
                        </td>
                        <td className="actions">
                          {canMake && (
                            <>
                              <button
                                type="button"
                                className="btn sm"
                                onClick={() => onAction({ kind: 'replace', key: k })}
                                disabled={!!pending}
                                title={pending ? 'A change request for this key is already pending' : undefined}
                                aria-label={pending ? `Replace ${k} (a change request is already pending)` : `Replace ${k}`}
                              >
                                Replace
                              </button>
                              <button type="button" className="btn sm" onClick={() => onAction({ kind: 'delete', key: k })} disabled={!!pending} aria-label={`Delete ${k}`}>
                                Delete
                              </button>
                            </>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </QueryView>
        <div className="card-foot spread">
          <span>
            Values are never shown, not even to admins. Olympos’s Vault token has no read on values.
            {vault.last_index_at ? ` Index refreshed ${age(vault.last_index_at)} ago.` : ''}
          </span>
          {canMake && (
            <button type="button" className="link-btn small" onClick={onRefresh}>
              Refresh index
            </button>
          )}
        </div>
      </section>

      {s && (
        <section className="card" aria-labelledby="ver-t">
          <div className="card-head">
            <h2 id="ver-t">Versions</h2>
            {canMake && s.versions.some((v) => v.version < s.current_version && !v.destroyed) && (
              <button type="button" className="btn sm danger" onClick={() => onAction({ kind: 'destroy' })}>
                Destroy history…
              </button>
            )}
          </div>
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th>Version</th>
                  <th>Created</th>
                  <th>Written by</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {s.versions
                  .slice()
                  .sort((a, b) => b.version - a.version)
                  .slice(0, 8)
                  .map((v) => (
                    <tr key={v.version}>
                      <td className="mono">
                        v{v.version}
                        {v.version === s.current_version ? ' (current)' : ''}
                      </td>
                      <td className="mono">{shortDate(v.created_time)}</td>
                      <td>{v.by_olympos ? 'Olympos change request' : <Badge tone="warn">Outside Olympos</Badge>}</td>
                      <td>{v.destroyed ? <Badge tone="mute">Destroyed</Badge> : v.deletion_time ? <Badge tone="mute">Soft-deleted</Badge> : <Badge tone="ok">Kept</Badge>}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          <div className="card-foot">Every write creates a new version of the whole secret. Deleting a key leaves its value in older versions until their history is destroyed.</div>
        </section>
      )}
    </>
  );
}
