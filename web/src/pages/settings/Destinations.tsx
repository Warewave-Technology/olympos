import { useNavigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { Destination, ItemList } from '../../api/types';
import { useCan } from '../../auth/me';
import { destinationsRoute } from '../../router';
import { DeleteRefused, DestinationStatus, KindBadge, authLabel, destLocation } from '../../ui/destinations';
import { EmptyState, QueryView } from '../../ui/kit';
import { DestinationDialog } from './DestinationDialog';
import { SettingsLayout } from './SettingsLayout';

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
        <QueryView
          q={q}
          what="destinations"
          isEmpty={(d) => d.items.length === 0}
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
        >
          {(d) => (
            <div className="table-wrap">
              <table className="t">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Kind</th>
                    <th>Location</th>
                    <th>Auth</th>
                    <th>Delete refused</th>
                    <th>Used by</th>
                    <th>Status</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {d.items.map((x) => {
                    const loc = destLocation(x);
                    return (
                      <tr key={x.id} className={x.id === id ? 'sel' : undefined}>
                        <td className="mono wrap" style={{ minWidth: 110 }}>{x.name}</td>
                        <td>
                          <KindBadge kind={x.kind} />
                        </td>
                        <td className="wrap break" style={{ minWidth: 160 }}>
                          <span className="mono">{loc.where}</span>
                          {loc.detail && <div className="muted small">{loc.detail}</div>}
                        </td>
                        <td className="wrap">{authLabel(x)}</td>
                        <td>
                          <DeleteRefused d={x} />
                        </td>
                        <td>{x.jobs === 1 ? '1 job' : `${x.jobs} jobs`}</td>
                        <td>
                          <DestinationStatus d={x} />
                        </td>
                        <td className="actions">
                          {canAdmin && (
                            <button type="button" className="btn sm" onClick={() => navigate({ search: { id: x.id } })} aria-label={`Edit ${x.name}`}>
                              Edit
                            </button>
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
        <div className="card-foot">Every save runs the destination test: a probe is written, read back, tagged and a delete is attempted. A credential that can delete is saved with a warning, never silently.</div>
      </section>
      {dialogOpen && <DestinationDialog key={id} dest={selected} onClose={close} />}
    </SettingsLayout>
  );
}
