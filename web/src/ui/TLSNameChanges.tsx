// Targets whose olympos.io/tls-server-name changed after Olympos first saw
// them (security review #1). The pinned name stays the one verified until an
// admin of the cluster accepts the new one.
import { useEffect, useRef } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { ItemList, Target } from '../api/types';
import { useCan } from '../auth/me';
import { ago } from '../lib/format';
import { useToast } from './kit';

const defaultName = (t: Target) => `${t.service}.${t.namespace}.svc`;

export function TLSNameChanges({ focus }: { focus?: boolean }) {
  const isAdmin = useCan('admin');
  const qc = useQueryClient();
  const toast = useToast();
  const ref = useRef<HTMLElement>(null);
  const q = useQuery({ queryKey: ['targets', 'tls-pending'], queryFn: () => api.get<ItemList<Target>>('/targets', { tls_pending: '1' }) });
  useEffect(() => {
    if (focus) ref.current?.scrollIntoView?.({ block: 'start' });
  }, [focus, q.isSuccess]);
  const accept = useMutation({
    mutationFn: (t: Target) => api.post(`/targets/${encodeURIComponent(t.id)}/accept-tls-name`, { name: t.tls_server_name_pending ?? '' }),
    onSuccess: (_, t) => {
      void qc.invalidateQueries({ queryKey: ['targets'] });
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
      toast(`${t.namespace}/${t.service} is now verified as ${t.tls_server_name_pending || defaultName(t)}.`, 'ok');
    },
    onError: (e) => {
      void qc.invalidateQueries({ queryKey: ['targets', 'tls-pending'] });
      toast(errorMessage(e), 'crit');
    },
  });
  const items = q.data?.items ?? [];
  if (!items.length) return null;
  return (
    <section ref={ref} className="card attention-card" aria-labelledby="tls-changes-t">
      <div className="card-head">
        <h2 id="tls-changes-t">TLS name changed</h2>
        <span className="muted small">held for an admin</span>
      </div>
      <div className="card-body stack-sm">
        <p className="muted small">
          The <span className="mono">olympos.io/tls-server-name</span> annotation of these Services changed. Backups and Vault calls keep verifying the name Olympos first saw. Anyone who can edit a Service can change the
          annotation: accept only a change you expected, otherwise revert the annotation and check who edited the Service.
        </p>
        <table className="tbl">
          <thead>
            <tr>
              <th>Target</th>
              <th>Verified name</th>
              <th>Requested name</th>
              <th>Changed</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {items.map((t) => (
              <tr key={t.id}>
                <td>
                  <span className="mono">
                    {t.namespace}/{t.service}
                  </span>{' '}
                  <span className="muted small">{t.cluster_name}</span>
                </td>
                <td className="mono">{t.tls_server_name || defaultName(t)}</td>
                <td className="mono">{t.tls_server_name_pending || `${defaultName(t)} (annotation removed)`}</td>
                <td className="muted small">{ago(t.tls_server_name_changed_at)}</td>
                <td>
                  {isAdmin && (
                    <button type="button" className="btn sm" disabled={accept.isPending} onClick={() => accept.mutate(t)}>
                      Accept new name
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
