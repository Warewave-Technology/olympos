// Security › Kubernetes secrets (F3): the opt-in, metadata-only Secret
// inventory. Names, key names and references only; Olympos never reads,
// shows or deletes a Secret's value.
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { SecretInventory, SecretRow } from '../api/types';
import { age, relDateTime } from '../lib/format';
import { DataTable, type Column } from './DataTable';
import { Badge, EmptyState } from './kit';

export function useSecretInventory(cluster: string | undefined) {
  return useQuery({ queryKey: ['security-secrets', { cluster }], queryFn: () => api.get<SecretInventory>('/security/secrets', { cluster }) });
}

const FINDING: Record<string, [string, 'warn' | 'info' | 'mute']> = {
  'secret.legacy_sa_token': ['Legacy SA token', 'warn'],
  'secret.unused': ['Unused 7+ days', 'info'],
  'secret.unmanaged': ['Only in cluster', 'mute'],
};

function EnableHelp() {
  return (
    <div className="card-body stack-sm">
      <p>
        The Secret inventory is <b>off</b> for this cluster. It lists Secrets with their <b>key names</b> (never values), which workloads use them and which operator manages them, so unused data can be removed.
      </p>
      <pre className="code">helm upgrade olympos-agent … --reuse-values --set secretsInventory.enabled=true</pre>
      <p className="muted small">
        Kubernetes RBAC has no “metadata only” permission: turning this on grants the agent <span className="mono">list</span> and <span className="mono">watch</span> on Secrets. Olympos only makes metadata-only requests
        and reads key names from managedFields, but a stolen agent token could read values with a normal request. That is why it is opt-in.
      </p>
    </div>
  );
}

export function SecretsTab({ q, oneCluster }: { q: ReturnType<typeof useSecretInventory>; oneCluster: boolean }) {
  const enabled = (q.data?.clusters ?? []).filter((c) => c.enabled);
  const columns: Column<SecretRow>[] = [
    { id: 'cluster', header: 'Cluster', hidden: oneCluster, sortValue: (s) => s.cluster_name, cell: (s) => <span className="mono">{s.cluster_name}</span> },
    { id: 'ns', header: 'Namespace', sortValue: (s) => s.namespace, cell: (s) => <span className="mono">{s.namespace}</span> },
    {
      id: 'name',
      header: 'Name',
      sortValue: (s) => s.name,
      searchText: (s) => `${s.namespace} ${s.name} ${s.type} ${s.keys.join(' ')} ${s.referenced_by.join(' ')} ${s.managed_by} ${s.cluster_name}`,
      cell: (s) => <span className="mono strong">{s.name}</span>,
    },
    { id: 'type', header: 'Type', sortValue: (s) => s.type, cell: (s) => (s.type ? <span className="mono small">{s.type}</span> : <span className="muted small">unknown</span>) },
    {
      id: 'keys',
      header: 'Keys',
      className: 'wrap',
      cell: (s) =>
        s.keys_unknown ? (
          <span className="muted small">unknown (no managedFields)</span>
        ) : (
          <span className="chips">
            {s.keys.map((k) => (
              <span key={k} className="chip mono">
                {k}
              </span>
            ))}
          </span>
        ),
    },
    {
      id: 'refs',
      header: 'Referenced by',
      className: 'wrap',
      sortValue: (s) => s.referenced_by.length,
      cell: (s) => (s.referenced_by.length ? <span className="small">{s.referenced_by.join(', ')}</span> : <span className="muted small">nothing</span>),
    },
    { id: 'managed', header: 'Managed by', sortValue: (s) => s.managed_by || null, cell: (s) => s.managed_by || <span className="muted small">only in the cluster</span> },
    { id: 'age', header: 'Age', sortValue: (s) => s.created_at, cell: (s) => (s.created_at ? <span title={relDateTime(s.created_at)}>{age(s.created_at)}</span> : '—') },
    {
      id: 'findings',
      header: 'Findings',
      sortValue: (s) => s.findings.length,
      defaultDir: 'desc',
      cell: (s) => (
        <span className="sev-chips">
          {s.findings.map((f) => (
            <Badge key={f} tone={FINDING[f]?.[1] ?? 'mute'}>
              {FINDING[f]?.[0] ?? f}
            </Badge>
          ))}
        </span>
      ),
    },
  ];
  return (
    <section className="card" aria-labelledby="ks-t">
      <div className="card-head">
        <h2 id="ks-t">Kubernetes secrets</h2>
      </div>
      {q.data && enabled.length === 0 ? (
        <EnableHelp />
      ) : (
        <>
          <div className="card-body">
            <p className="muted small">
              Names and key names only (metadata-only requests). <b>Olympos does not delete Secrets. Remove unused ones with your usual change process.</b>
              {!oneCluster && q.data && enabled.length < q.data.clusters.length && ` Inventory on for ${enabled.length} of ${q.data.clusters.length} clusters.`}
            </p>
          </div>
          <DataTable
            label="Kubernetes secrets"
            what="Kubernetes secrets"
            rows={q.data?.items}
            loading={q.isPending}
            error={q.isError ? q.error : undefined}
            onRetry={() => q.refetch()}
            rowKey={(s) => `${s.cluster_id}/${s.namespace}/${s.name}`}
            columns={columns}
            pageSize={25}
            initialSort={{ id: 'findings', dir: 'desc' }}
            empty={<EmptyState title="No Secrets reported yet">The agent sends the inventory within a minute of starting.</EmptyState>}
          />
        </>
      )}
    </section>
  );
}
