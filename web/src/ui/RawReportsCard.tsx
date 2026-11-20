// Where raw Kubescape, Polaris and kube-bench reports are kept (settings key
// audit.raw_destination_id). Every reader sees it; a global admin changes it.
import { useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { AuditSettings, AuditSettingsInput, Destination, ItemList } from '../api/types';
import { useCan } from '../auth/me';
import { useToast } from './kit';
import { Select } from './Select';
import { DocLink } from './DocLinks';

export function RawReportsCard() {
  const isAdmin = useCan('admin_global');
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ['audit-settings'], queryFn: () => api.get<AuditSettings>('/audit/settings') });
  const destQ = useQuery({ queryKey: ['destinations'], queryFn: () => api.get<ItemList<Destination>>('/destinations'), enabled: isAdmin });
  const [editing, setEditing] = useState(false);
  const [dest, setDest] = useState('');
  const save = useMutation({
    mutationFn: (in_: AuditSettingsInput) => api.put<AuditSettings>('/audit/settings', in_),
    onSuccess: (v) => {
      qc.setQueryData(['audit-settings'], v);
      setEditing(false);
      setDest('');
      toast(v.raw_destination ? `Raw reports are stored on ${v.raw_destination.name}.` : 'Raw reports are no longer stored.', 'ok');
    },
    onError: (e) => toast(errorMessage(e), 'crit'),
  });
  const current = q.data?.raw_destination ?? null;
  const dests = destQ.data?.items ?? [];

  return (
    <section className="card pad stack-sm" aria-labelledby="raw-t">
      <div className="spread">
        <h2 id="raw-t">Raw reports</h2>
        {isAdmin && !editing && (
          <button type="button" className="btn sm" onClick={() => setEditing(true)}>
            {current ? 'Change' : 'Choose a destination'}
          </button>
        )}
      </div>
      <p className="muted small" style={{ margin: 0 }}>
        The full JSON of every Kubescape, Polaris and kube-bench run, redacted (ConfigMap and Secret data, env values), at <span className="mono">audit/&lt;cluster&gt;/&lt;tool&gt;/&lt;run&gt;.json</span>. Findings are
        kept either way. Olympos never deletes them: add a lifecycle rule for <span className="mono">audit/</span> (<DocLink path="docs/install.md#audit-raw-results">how</DocLink>).
      </p>
      {!editing ? (
        <p style={{ margin: 0 }}>
          {current ? (
            <>
              Stored on <span className="mono">{current.name}</span> <span className="muted small">({current.kind})</span>
            </>
          ) : (
            <span className="muted">Not stored{isAdmin ? '' : '. An admin can choose a destination.'}</span>
          )}
        </p>
      ) : (
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <Select
            aria-label="Raw reports destination"
            value={dest || current?.id || ''}
            onChange={setDest}
            placeholder={dests.length ? 'Choose a destination' : 'No destinations yet'}
            options={dests.map((d) => ({ value: d.id, label: d.name, hint: d.kind }))}
            disabled={!dests.length}
          />
          <button type="button" className="btn pri" disabled={!(dest || current) || save.isPending} onClick={() => save.mutate({ raw_destination_id: dest || current!.id })}>
            Save
          </button>
          {current && (
            <button type="button" className="btn" disabled={save.isPending} onClick={() => save.mutate({ raw_destination_id: null })}>
              Stop storing
            </button>
          )}
          <button type="button" className="btn ghost" onClick={() => setEditing(false)}>
            Cancel
          </button>
          {!dests.length && (
            <Link to="/settings/destinations" className="small">
              Add a destination
            </Link>
          )}
        </div>
      )}
    </section>
  );
}
