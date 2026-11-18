import { useNavigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { Destination, ItemList } from '../../api/types';
import { useCan } from '../../auth/me';
import { destinationsRoute } from '../../router';
import { DeleteRefused, DestinationStatus, KindBadge, authLabel, destLocation } from '../../ui/destinations';
import { EmptyState } from '../../ui/kit';
import { DestinationDialog } from './DestinationDialog';
import { SettingsLayout } from './SettingsLayout';
import { DataTable } from '../../ui/DataTable';

export function DestinationsPage() {
  const { id } = destinationsRoute.useSearch();
  const navigate = useNavigate({ from: '/settings/destinations' });
  const canAdmin = useCan('admin_global');
  const q = useQuery({ queryKey: ['destinations'], queryFn: () => api.get<ItemList<Destination>>('/destinations') });
  const selected = id === 'new' ? undefined : q.data?.items.find((d) => d.id === id);
  const dialogOpen = canAdmin && (id === 'new' || !!selected);
  const openNew = () => navigate({ search: { id: 'new' } });
  const close = () => navigate({ search: {} });

  return (
    <SettingsLayout
      current="destinations"
      sub="Destinations · the Olympos server is the only writer to backup storage"
      actions={
        canAdmin && (
          <button type="button" className="btn pri" onClick={openNew}>
            New destination
          </button>
        )
      }
    >
      <section className="card" aria-labelledby="dst-t">
        <div className="card-head">
          <div>
            <h2 id="dst-t">Destinations</h2>
            <div className="desc">Azure Blob containers, S3 buckets (AWS or S3-compatible) and NFS shares mounted into the server.</div>
          </div>
        </div>
        <DataTable
          label="Destinations"
          what="destinations"
          rows={q.data?.items}
          loading={q.isPending}
          error={q.isError ? q.error : undefined}
          onRetry={() => q.refetch()}
          rowKey={(x) => x.id}
          rowClassName={(x) => (x.id === id ? 'sel' : undefined)}
          initialSort={{ id: 'name', dir: 'asc' }}
          empty={
            <EmptyState
              title="No destinations yet"
              action={
                canAdmin ? (
                  <button type="button" className="btn pri" onClick={openNew}>
                    New destination
                  </button>
                ) : undefined
              }
            >
              Backups need somewhere to go: an Azure Blob container (Managed Identity recommended: read, write and tag, but no delete), an S3 bucket on AWS or any S3-compatible service, or an NFS share mounted into the server.
            </EmptyState>
          }
          columns={[
            { id: 'name', header: 'Name', sortValue: (x) => x.name, className: 'mono wrap', style: { minWidth: 110 }, cell: (x) => x.name },
            { id: 'kind', header: 'Kind', sortValue: (x) => x.kind, cell: (x) => <KindBadge kind={x.kind} /> },
            {
              id: 'loc',
              header: 'Location',
              sortValue: (x) => destLocation(x).where,
              className: 'wrap break',
              style: { minWidth: 160 },
              cell: (x) => {
                const loc = destLocation(x);
                return (
                  <>
                    <span className="mono">{loc.where}</span>
                    {loc.detail && <div className="muted small">{loc.detail}</div>}
                  </>
                );
              },
            },
            { id: 'auth', header: 'Auth', sortValue: authLabel, className: 'wrap', cell: authLabel },
            { id: 'del', header: 'Delete refused', sortValue: (x) => (x.last_test ? (x.last_test.can_delete ? 0 : 1) : null), cell: (x) => <DeleteRefused d={x} /> },
            { id: 'jobs', header: 'Used by', sortValue: (x) => x.jobs, defaultDir: 'desc', cell: (x) => (x.jobs === 1 ? '1 job' : `${x.jobs} jobs`) },
            { id: 'status', header: 'Status', sortValue: (x) => (x.last_test_ok === false ? 0 : x.last_test_ok === null ? 1 : 2), cell: (x) => <DestinationStatus d={x} /> },
            {
              id: 'actions',
              header: 'Actions',
              srOnlyHeader: true,
              align: 'actions',
              hidden: !canAdmin,
              cell: (x) => (
                <button type="button" className="btn sm" onClick={() => navigate({ search: { id: x.id } })} aria-label={`Edit ${x.name}`}>
                  Edit
                </button>
              ),
            },
          ]}
        />
        <div className="card-foot">Every save runs the destination test: a probe is written, read back, tagged and a delete is attempted. A credential that can delete is saved with a warning, never silently.</div>
      </section>
      {dialogOpen && <DestinationDialog key={id} dest={selected} onClose={close} />}
    </SettingsLayout>
  );
}
