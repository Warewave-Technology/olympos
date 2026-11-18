import { useMemo } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { Cluster, Dashboard } from '../api/types';
import { useCan } from '../auth/me';
import { age, ibytes, plural, vcpu } from '../lib/format';
import { dashboardRoute } from '../router';
import { Badge, EmptyState, ErrorState, Loading, useNow } from '../ui/kit';
import { SpaLink } from '../ui/SpaLink';
import { ClusterStatusBadge, PageHead } from '../ui/status';
import { AddClusterDialog } from './AddClusterDialog';

function minorOf(v: string): string {
  const m = /^v?(\d+)\.(\d+)/.exec(v);
  return m ? `${m[1]}.${m[2]}` : '';
}

function zonesText(c: Cluster): string {
  const zones = (c.zones ?? []).map((z) => z.replace(c.region + '-', '').replace(c.region, '')).filter(Boolean);
  if (!c.region) return '—';
  return zones.length ? `${c.region} · ${zones.join(',')}` : c.region;
}

function sizesText(c: Cluster): string {
  if (!c.instance_types?.length) return c.nodes ? plural(c.nodes, 'node') : '—';
  return c.instance_types.map((t) => `${t.instance_type} ×${t.count}`).join(', ');
}

function providerCell(c: Cluster) {
  if (c.provider === 'onprem' || c.provider === '') return <Badge tone="mute">On-prem</Badge>;
  return <>{c.provider_label || c.provider}</>;
}

export function DashboardPage() {
  const search = dashboardRoute.useSearch();
  const navigate = useNavigate({ from: '/' });
  const canAdd = useCan('admin_global');
  const now = useNow(10_000);
  const q = useQuery({ queryKey: ['dashboard'], queryFn: () => api.get<Dashboard>('/dashboard'), refetchInterval: 30_000 });
  const d = q.data;

  const setSearch = (patch: Partial<typeof search>) => navigate({ search: (s) => ({ ...s, ...patch }), replace: true });

  const clusters = useMemo(() => (d?.clusters ?? []).filter((c) => c.status !== 'revoked'), [d]);
  const prov = search.provider ?? '';
  const ver = search.version ?? '';
  const filtered = useMemo(() => {
    const term = (search.q ?? '').toLowerCase().trim();
    return clusters.filter((c) => {
      if (search.filter === 'eol' && !c.eol) return false;
      if (search.filter === 'skew' && !c.version_skew) return false;
      if (search.filter === 'offline' && c.status !== 'offline') return false;
      if (prov && (c.provider || 'onprem') !== prov) return false;
      if (ver && minorOf(c.api_version) !== ver) return false;
      if (!term) return true;
      const hay = [c.name, c.region, c.provider_label, c.api_version, ...(c.zones ?? []), ...(c.instance_types ?? []).map((t) => t.instance_type), ...Object.entries(c.labels ?? {}).map(([k, v]) => `${k}=${v}`)]
        .join(' ')
        .toLowerCase();
      return hay.includes(term);
    });
  }, [clusters, search.q, search.filter, prov, ver]);

  const regions = useMemo(() => {
    const m = new Map<string, { provider: string; label: string; region: string; clusters: number; nodes: number }>();
    for (const c of clusters) {
      const p = c.provider || 'onprem';
      const key = `${p}|${c.region}`;
      const row = m.get(key) ?? { provider: p, label: c.provider_label || 'On-prem', region: c.region, clusters: 0, nodes: 0 };
      row.clusters++;
      row.nodes += c.nodes;
      m.set(key, row);
    }
    return [...m.values()].sort((a, b) => b.clusters - a.clusters || a.label.localeCompare(b.label));
  }, [clusters]);

  const providers = useMemo(() => Array.from(new Map(clusters.map((c) => [c.provider || 'onprem', c.provider_label || 'On-prem'])).entries()), [clusters]);
  const versions = useMemo(() => (d?.version_matrix ?? []).map((v) => v.minor).sort((a, b) => Number(b.split('.')[1]) - Number(a.split('.')[1])), [d]);

  const total = d?.totals;
  const eolVersions = (d?.version_matrix ?? []).filter((v) => v.eol).map((v) => `v${v.minor}`);
  const matrix = [...(d?.version_matrix ?? [])].sort((a, b) => Number(b.minor.split('.')[1]) - Number(a.minor.split('.')[1]));
  const matrixTotal = matrix.reduce((s, v) => s + v.clusters, 0) || 1;

  return (
    <>
      <PageHead
        title="Fleet overview"
        sub={
          total ? (
            <>
              {plural(total.clusters, 'cluster')} reporting
              {d?.refreshed_at ? ` · inventory refreshed ${age(d.refreshed_at, now)} ago` : ''}
            </>
          ) : (
            'Clusters, versions and where they run'
          )
        }
        actions={
          <>
            <label className="sr-only" htmlFor="dash-q">
              Search clusters
            </label>
            <input id="dash-q" className="in search" type="search" placeholder="Search clusters, nodes, regions…" value={search.q ?? ''} onChange={(e) => setSearch({ q: e.target.value || undefined })} />
            {canAdd && (
              <button type="button" className="btn pri" onClick={() => setSearch({ add: true })}>
                Add cluster
              </button>
            )}
          </>
        }
      />

      {q.isPending && <Loading label="Loading fleet overview…" />}
      {q.isError && (
        <section className="card">
          <ErrorState what="the fleet overview" error={q.error} onRetry={() => q.refetch()} />
        </section>
      )}

      {d && (
        <>
          {d.attention.length > 0 && (
            <section aria-label="Needs attention" className="attention">
              {d.attention.map((a, i) => (
                <SpaLink key={i} href={a.link || '/'} className={a.severity}>
                  <Badge tone={a.severity}>{a.label}</Badge>
                  <span>{a.detail}</span>
                </SpaLink>
              ))}
            </section>
          )}

          {clusters.length === 0 ? (
            <section className="card">
              <EmptyState
                title="No clusters yet"
                action={
                  canAdd ? (
                    <button type="button" className="btn pri" onClick={() => setSearch({ add: true })}>
                      Add cluster
                    </button>
                  ) : undefined
                }
              >
                {canAdd
                  ? 'Add a cluster to get a one-time Helm command for the agent. The agent dials out, so no inbound port is needed.'
                  : 'No clusters are in your access scope yet. Ask an Olympos admin to add a cluster or extend your grant.'}
              </EmptyState>
            </section>
          ) : (
            <>
              <section className="stats" aria-label="Fleet totals">
                <div className="card stat">
                  <div className="k">Clusters</div>
                  <div className="v">{total!.clusters}</div>
                  <div className="d">{plural(total!.agents_online, 'agent')} online</div>
                </div>
                <div className="card stat">
                  <div className="k">Nodes</div>
                  <div className="v">{total!.nodes.toLocaleString('en-US')}</div>
                  <div className="d">
                    {vcpu(total!.cpu_milli)} · {ibytes(total!.mem_bytes)} RAM
                  </div>
                </div>
                <div className="card stat">
                  <div className="k">K8s versions</div>
                  <div className="v">{total!.versions}</div>
                  <div className="d">{total!.version_min ? (total!.version_min === total!.version_max ? total!.version_min : `${total!.version_min} → ${total!.version_max}`) : 'no inventory yet'}</div>
                </div>
                <div className="card stat">
                  <div className="k">Version skew</div>
                  <div className={`v${total!.skew_clusters > 0 ? ' warn' : ''}`}>{total!.skew_clusters}</div>
                  <div className="d">clusters, kubelet behind API</div>
                </div>
                <div className="card stat">
                  <div className="k">Agent offline</div>
                  <div className={`v${total!.offline_agents > 0 ? ' crit' : ''}`}>{total!.offline_agents}</div>
                  <div className="d">{total!.offline_detail || 'all agents reporting'}</div>
                </div>
              </section>

              <section className="row gap-sm">
                <div className="card pad half">
                  <h2 className="title" style={{ marginBottom: 16 }}>
                    Version matrix
                  </h2>
                  {matrix.length === 0 ? (
                    <p className="muted small" style={{ margin: 0 }}>
                      No API versions reported yet. Versions appear after the first inventory from each agent.
                    </p>
                  ) : (
                    <div className="bars">
                      {matrix.map((v) => (
                        <div className="bar-row" key={v.minor}>
                          <span className="mono">v{v.minor}</span>
                          <div className="bar" role="img" aria-label={`${v.clusters} of ${matrixTotal} clusters${v.eol ? ', end of life' : ''}`}>
                            <span className={v.eol ? 'eol' : undefined} style={{ width: `${Math.max(4, (v.clusters / matrixTotal) * 100)}%` }} />
                          </div>
                          <span className="count">
                            {v.eol && (
                              <Badge tone="warn" className="eol-badge">
                                EOL
                              </Badge>
                            )}{' '}
                            {plural(v.clusters, 'cluster')}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  {eolVersions.length > 0 && (
                    <p className="muted small" style={{ margin: '16px 0 0' }}>
                      {eolVersions.join(', ')} {eolVersions.length === 1 ? 'is' : 'are'} past upstream end of life. Bars in orange (marked EOL) need an upgrade plan.
                    </p>
                  )}
                </div>

                <div className="card pad half">
                  <h2 className="title" style={{ marginBottom: 16 }}>
                    Where clusters run
                  </h2>
                  <div className="table-wrap">
                    <table className="t">
                      <thead>
                        <tr>
                          <th>Provider</th>
                          <th>Region</th>
                          <th className="num">Clusters</th>
                          <th className="num">Nodes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {regions.map((r) => (
                          <tr key={r.provider + r.region}>
                            <td>{r.provider === 'onprem' ? <Badge tone="mute">On-prem</Badge> : r.label}</td>
                            <td className={r.region ? 'mono' : 'muted'}>{r.region || (r.provider === 'onprem' ? 'No providerID' : '—')}</td>
                            <td className="num">{r.clusters}</td>
                            <td className="num">{r.nodes}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </section>

              <section className="card" aria-labelledby="clusters-t">
                <div className="card-head" style={{ paddingTop: 18, paddingBottom: 8 }}>
                  <h2 id="clusters-t">Clusters</h2>
                  <div className="inline" style={{ gap: 8 }}>
                    {search.filter && (
                      <button type="button" className="btn sm" onClick={() => setSearch({ filter: undefined })} aria-label={`Clear filter ${search.filter}`}>
                        Filter: {search.filter === 'eol' ? 'end of life' : search.filter} ✕
                      </button>
                    )}
                    <label className="sr-only" htmlFor="f-prov">
                      Provider
                    </label>
                    <select id="f-prov" className="in" style={{ width: 'auto' }} value={prov} onChange={(e) => setSearch({ provider: e.target.value || undefined })}>
                      <option value="">All providers</option>
                      {providers.map(([p, l]) => (
                        <option key={p} value={p}>
                          {l}
                        </option>
                      ))}
                    </select>
                    <label className="sr-only" htmlFor="f-ver">
                      Version
                    </label>
                    <select id="f-ver" className="in" style={{ width: 'auto' }} value={ver} onChange={(e) => setSearch({ version: e.target.value || undefined })}>
                      <option value="">All versions</option>
                      {versions.map((v) => (
                        <option key={v} value={v}>
                          v{v}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="table-wrap">
                  <table className="t">
                    <thead>
                      <tr>
                        <th>Cluster</th>
                        <th>Provider</th>
                        <th>Region / zones</th>
                        <th>API</th>
                        <th>Kubelet</th>
                        <th className="num">Nodes</th>
                        <th>Node sizes</th>
                        <th>Agent</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((c) => (
                        <tr key={c.id}>
                          <td>
                            <Link to="/settings/clusters" search={{ cluster: c.id }}>
                              {c.name}
                            </Link>
                          </td>
                          <td>{providerCell(c)}</td>
                          <td className={c.region ? 'mono' : 'muted'}>{zonesText(c)}</td>
                          <td className="mono">{c.api_version || '—'}</td>
                          <td className="mono">{c.min_kubelet || '—'}</td>
                          <td className="num">{c.nodes}</td>
                          <td className="mono">{sizesText(c)}</td>
                          <td>
                            <span className="inline-sm">
                              <ClusterStatusBadge c={c} now={now} />
                              {c.version_skew && <Badge tone="warn">Skew</Badge>}
                              {c.eol && <Badge tone="warn">EOL</Badge>}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filtered.length === 0 && (
                    <EmptyState title="No clusters match">
                      Nothing matches the current search or filters.{' '}
                      <button type="button" className="link-btn" onClick={() => navigate({ to: '/', search: {}, replace: true })}>
                        Clear search and filters
                      </button>
                    </EmptyState>
                  )}
                </div>
                <div className="card-foot">
                  Showing {filtered.length} of {clusters.length} · provider is read from node providerID; set it by hand for on-prem clusters
                </div>
              </section>
            </>
          )}
        </>
      )}

      <AddClusterDialog open={!!search.add && canAdd} onClose={() => setSearch({ add: undefined })} />
    </>
  );
}
