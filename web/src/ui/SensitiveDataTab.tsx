// Security › Sensitive data (F2): credential-like values found in
// ConfigMaps by the agent. Only where and which rule: Olympos never stores,
// shows or edits the value or the ConfigMap.
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { Finding, ItemList } from '../api/types';
import { age, relDateTime } from '../lib/format';
import { DataTable, type Column } from './DataTable';
import { Badge, EmptyState } from './kit';

const detail = (f: Finding, k: string) => String(f.details?.[k] ?? '');

export function useSensitiveData(cluster: string | undefined) {
  return useQuery({
    queryKey: ['findings', 'sensitive-data', { cluster }],
    queryFn: () => api.get<ItemList<Finding>>('/findings', { source: 'sensitive-data', status: 'open', cluster, limit: 1000 }),
  });
}

export function SensitiveDataTab({ q, oneCluster }: { q: ReturnType<typeof useSensitiveData>; oneCluster: boolean }) {
  const columns: Column<Finding>[] = [
    { id: 'cluster', header: 'Cluster', hidden: oneCluster, sortValue: (f) => f.cluster_name, cell: (f) => <span className="mono">{f.cluster_name}</span> },
    { id: 'ns', header: 'Namespace', sortValue: (f) => detail(f, 'namespace'), cell: (f) => <span className="mono">{detail(f, 'namespace')}</span> },
    { id: 'cm', header: 'ConfigMap', sortValue: (f) => detail(f, 'config_map'), cell: (f) => <span className="mono">{detail(f, 'config_map')}</span> },
    { id: 'key', header: 'Key', sortValue: (f) => detail(f, 'key'), cell: (f) => <span className="mono strong">{detail(f, 'key')}</span> },
    {
      id: 'rule',
      header: 'Rule',
      sortValue: (f) => f.control_id,
      className: 'wrap',
      searchText: (f) => `${f.control_id} ${detail(f, 'rule_description')} ${detail(f, 'namespace')} ${detail(f, 'config_map')} ${detail(f, 'key')} ${f.cluster_name}`,
      cell: (f) => (
        <>
          <span className="mono small">{f.control_id}</span>
          <div className="muted small">{detail(f, 'rule_description')}</div>
        </>
      ),
    },
    {
      id: 'conf',
      header: 'Confidence',
      sortValue: (f) => (f.severity === 'high' ? 1 : 0),
      defaultDir: 'desc',
      cell: (f) => (f.details?.confidence === 'high' ? <Badge tone="crit">High · pattern</Badge> : <Badge tone="warn">Medium · key name</Badge>),
    },
    { id: 'seen', header: 'First seen', sortValue: (f) => f.first_seen_at, defaultDir: 'desc', cell: (f) => <span title={relDateTime(f.first_seen_at)}>{age(f.first_seen_at)} ago</span> },
  ];
  return (
    <section className="card" aria-labelledby="sd-t">
      <div className="card-head">
        <h2 id="sd-t">Sensitive data in ConfigMaps</h2>
      </div>
      <div className="card-body stack-sm">
        <p className="muted small">
          The agent scans ConfigMap values with the gitleaks rules and key names such as <span className="mono">password</span> or <span className="mono">token</span>. Values never leave the cluster: Olympos only knows where a match is and which rule matched.
          For each row: <b>move this value to a Secret or Vault and remove it from the ConfigMap.</b> Olympos never edits or deletes ConfigMaps; a row resolves by itself once the key is gone.
        </p>
      </div>
      <DataTable
        label="Sensitive data in ConfigMaps"
        what="sensitive data findings"
        rows={q.data?.items}
        loading={q.isPending}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        rowKey={(f) => f.id}
        columns={columns}
        pageSize={25}
        initialSort={{ id: 'conf', dir: 'desc' }}
        empty={<EmptyState title="No credentials found in ConfigMaps">The agent checks every ConfigMap when it changes and all of them every 6 hours (system namespaces excluded).</EmptyState>}
      />
    </section>
  );
}
