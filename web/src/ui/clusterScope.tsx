// Cluster-first navigation shared by Security, Audit and Backups (and the Vaults cluster filter):
// a searchable cluster overview, a breadcrumb "Area / <cluster>", and a cluster switcher. The
// choice lives in the URL (?cluster=<id> | all); no cluster param = the overview.
import { useMemo, useState, type ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { Cluster, ItemList } from '../api/types';
import { DataTable, type Column } from './DataTable';
import { EmptyState } from './kit';
import { Select } from './Select';
import { ClusterStatusBadge } from './status';

export const ALL_CLUSTERS = 'all';

export type Scope = { mode: 'overview' } | { mode: 'all' } | { mode: 'cluster'; id: string };

/**
 * `?cluster=` → what the page shows. Without it the cluster overview is the landing page, unless
 * the URL deep-links into a fleet-wide detail (e.g. ?tab=runs from the dashboard).
 */
export function resolveScope(cluster: string | undefined, deepLink = false): Scope {
  if (cluster === ALL_CLUSTERS) return { mode: 'all' };
  if (cluster) return { mode: 'cluster', id: cluster };
  return deepLink ? { mode: 'all' } : { mode: 'overview' };
}

/** The `cluster` search value for a scope (undefined = overview). */
export function scopeParam(s: Scope): string | undefined {
  return s.mode === 'all' ? ALL_CLUSTERS : s.mode === 'cluster' ? s.id : undefined;
}

export type ClusterInfo = Pick<Cluster, 'id' | 'name' | 'labels' | 'provider' | 'provider_label' | 'region' | 'status' | 'last_seen_at'>;

const PROVIDER_LABEL: Record<string, string> = { azure: 'Azure', aws: 'AWS', gcp: 'GCP', oracle: 'Oracle Cloud', huawei: 'Huawei Cloud', onprem: 'On-prem' };
export const providerText = (c: Pick<ClusterInfo, 'provider' | 'provider_label'> | undefined) => (c ? c.provider_label || PROVIDER_LABEL[c.provider] || c.provider || '—' : '—');

/** Text a cluster is found by: name, provider, region and labels (k=v, k:v, v). */
export function clusterHaystack(c: Partial<ClusterInfo> & { name: string }): string {
  const labels = Object.entries(c.labels ?? {})
    .map(([k, v]) => `${k}=${v} ${k}:${v} ${v}`)
    .join(' ');
  return `${c.name} ${c.provider ?? ''} ${c.provider_label ?? ''} ${PROVIDER_LABEL[c.provider ?? ''] ?? ''} ${c.region ?? ''} ${labels}`.toLowerCase();
}

/** Every word must appear (AND), so "prod azure" or "team=data" narrow the list. */
export function matchesCluster(c: Partial<ClusterInfo> & { name: string }, q: string): boolean {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = clusterHaystack(c);
  return words.every((w) => hay.includes(w));
}

export function useClusterList() {
  const q = useQuery({ queryKey: ['clusters'], queryFn: () => api.get<ItemList<Cluster>>('/clusters') });
  const list = useMemo(() => (q.data?.items ?? []).filter((c) => c.status !== 'revoked').sort((a, b) => a.name.localeCompare(b.name)), [q.data]);
  return { q, list };
}

export function findCluster(list: ClusterInfo[], idOrName: string | undefined): ClusterInfo | undefined {
  if (!idOrName) return undefined;
  return list.find((c) => c.id === idOrName) ?? list.find((c) => c.name === idOrName);
}

/** Cluster switcher: "All clusters" + every cluster, searchable by name, provider and labels. */
export function ClusterSwitcher({ value, clusters, onChange, id, extra }: { value: string; clusters: ClusterInfo[]; onChange: (v: string) => void; id?: string; extra?: { value: string; label: string }[] }) {
  return (
    <Select<string>
      id={id}
      className="cluster-switch"
      size="sm"
      searchable
      searchLabel="Find a cluster"
      aria-label="Cluster"
      value={value}
      onChange={onChange}
      placeholder="Choose a cluster"
      options={[
        ...(extra ?? []),
        { value: ALL_CLUSTERS, label: 'All clusters', text: 'All clusters fleet' },
        ...clusters.map((c) => {
          const labels = Object.entries(c.labels ?? {}).map(([k, v]) => `${k}=${v}`);
          return { value: c.id, label: c.name, text: clusterHaystack(c), hint: [providerText(c), ...labels].join(' · ') };
        }),
      ]}
    />
  );
}

/** "Security / prod-aks-weu-01" — the area links back to the cluster overview. */
export function ScopeCrumbs({ area, to, scope, cluster, children }: { area: string; to: '/security' | '/audit' | '/backups'; scope: Scope; cluster?: ClusterInfo; children?: ReactNode }) {
  return (
    <nav aria-label="Breadcrumb" className="crumbs-nav">
      <Link to={to} search={{}}>
        {area}
      </Link>
      <span aria-hidden="true"> / </span>
      {children ? (
        <>
          <Link to={to} search={{ cluster: scopeParam(scope) }} className="mono">
            {scope.mode === 'all' ? 'All clusters' : (cluster?.name ?? 'cluster')}
          </Link>
          {children}
        </>
      ) : (
        <span className={scope.mode === 'cluster' ? 'mono' : undefined} aria-current="page">
          {scope.mode === 'all' ? 'All clusters' : (cluster?.name ?? (scope.mode === 'cluster' ? scope.id : ''))}
        </span>
      )}
    </nav>
  );
}

export function ClusterCell({ c, name }: { c?: ClusterInfo; name: string }) {
  return (
    <div className="cl-cell">
      <div className="cl-name">
        <span className="mono strong">{name}</span>
        {c && c.status !== 'online' && <ClusterStatusBadge c={c} />}
      </div>
      <div className="cl-meta">
        <span className="muted small">{providerText(c)}</span>
        {Object.entries(c?.labels ?? {}).map(([k, v]) => (
          <span key={k} className="chip">
            {k}={v}
          </span>
        ))}
      </div>
    </div>
  );
}

export type OverviewRow<R> = R & { _c?: ClusterInfo };

/**
 * Cluster overview: one row per cluster with the area's summary columns; search by name,
 * provider or labels; a row opens the area filtered to that cluster.
 */
export function ClusterOverview<R extends { cluster_id: string; cluster_name: string }>({
  label,
  what,
  rows,
  clusters,
  columns,
  loading,
  error,
  onRetry,
  onOpen,
  onAll,
  initialSort,
  empty,
  intro,
}: {
  label: string;
  what: string;
  rows: R[] | undefined;
  clusters: ClusterInfo[];
  columns: Column<OverviewRow<R>>[];
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  onOpen: (clusterId: string) => void;
  onAll: () => void;
  initialSort?: { id: string; dir: 'asc' | 'desc' };
  empty?: ReactNode;
  intro?: ReactNode;
}) {
  const [q, setQ] = useState('');
  const joined = useMemo<OverviewRow<R>[] | undefined>(() => rows?.map((r) => ({ ...r, _c: findCluster(clusters, r.cluster_id) ?? findCluster(clusters, r.cluster_name) })), [rows, clusters]);
  const cols: Column<OverviewRow<R>>[] = [
    {
      id: 'cluster',
      header: 'Cluster',
      sortValue: (r) => r.cluster_name,
      style: { minWidth: 220 },
      className: 'wrap',
      cell: (r) => <ClusterCell c={r._c} name={r.cluster_name} />,
    },
    ...columns,
  ];
  return (
    <section className="card" aria-label={label}>
      <div className="card-head">
        <div>
          <h2>Clusters</h2>
          <div className="desc">{intro ?? 'Pick a cluster to see its details, or view every cluster at once.'}</div>
        </div>
        <div className="inline">
          <label className="sr-only" htmlFor={`${what}-cl-q`}>
            Search clusters
          </label>
          <input id={`${what}-cl-q`} type="search" className="in search-sm" placeholder="Search cluster, provider or label…" value={q} onChange={(e) => setQ(e.target.value)} />
          <button type="button" className="btn sm" onClick={onAll}>
            All clusters
          </button>
        </div>
      </div>
      <DataTable
        label={label}
        what={what}
        rows={joined}
        loading={loading}
        error={error}
        onRetry={onRetry}
        columns={cols}
        rowKey={(r) => r.cluster_id}
        filterText={q}
        filterFn={(r, text) => matchesCluster({ ...(r._c ?? {}), name: r.cluster_name, provider: r._c?.provider ?? (r as { provider?: string }).provider ?? '' } as ClusterInfo, text)}
        onRowClick={(r) => onOpen(r.cluster_id)}
        rowLabel={(r) => `Open ${r.cluster_name}`}
        initialSort={initialSort ?? { id: 'cluster', dir: 'asc' }}
        empty={empty ?? <EmptyState title="No clusters yet">Add a cluster on the Dashboard; its agent reports within a minute.</EmptyState>}
        noMatch={<EmptyState title="No cluster matches">Search by cluster name, provider (e.g. azure) or label (e.g. env=prod).</EmptyState>}
      />
    </section>
  );
}
