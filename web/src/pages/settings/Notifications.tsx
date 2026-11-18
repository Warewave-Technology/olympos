import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../../api/client';
import type { Channel, ItemList, Routes } from '../../api/types';
import { useCan } from '../../auth/me';
import { Badge, Chip, EmptyState, Field, FormError, Modal, QueryView, aria, fieldError, useToast } from '../../ui/kit';
import { SettingsLayout } from './SettingsLayout';

/** Settings › Notifications: Slack channels and event routing (SPEC §14). */
export function SettingsNotificationsPage() {
  const canRoute = useCan('operate_global');
  const routesQ = useQuery({ queryKey: ['routes'], queryFn: () => api.get<Routes>('/notifications/routes'), retry: false });
  const chanQ = useQuery({ queryKey: ['channels'], queryFn: () => api.get<ItemList<Channel>>('/notifications/channels') });
  return (
    <SettingsLayout current="notifications" sub="Notifications · Slack channels are defined once; any event can be routed to them">
      <NotificationsSection routesQ={routesQ} chanQ={chanQ} canRoute={canRoute} />
    </SettingsLayout>
  );
}

function NotificationsSection({ routesQ, chanQ, canRoute }: { routesQ: ReturnType<typeof useQuery<Routes>>; chanQ: ReturnType<typeof useQuery<ItemList<Channel>>>; canRoute: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState<Record<string, Set<string>> | null>(null);
  const channels = chanQ.data?.items ?? [];
  const catalog = routesQ.data?.catalog ?? [];
  const saved = useMemo(() => {
    const m: Record<string, Set<string>> = {};
    for (const r of routesQ.data?.routes ?? []) m[r.event_type] = new Set(r.channel_ids);
    return m;
  }, [routesQ.data]);
  const current = draft ?? saved;
  const dirty = draft !== null;

  const testCh = useMutation({
    mutationFn: (c: Channel) => api.post<{ ok: boolean; error?: string }>(`/notifications/channels/${c.id}/test`),
    onSuccess: (r, c) => toast(r.ok ? `Test message sent to ${c.name}.` : `Slack refused the test message: ${r.error}`, r.ok ? 'ok' : 'crit'),
    onError: (e) => toast(`Test failed: ${errorMessage(e)}`, 'crit'),
  });
  const delCh = useMutation({
    mutationFn: (c: Channel) => api.del(`/notifications/channels/${c.id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['channels'] });
      void qc.invalidateQueries({ queryKey: ['routes'] });
    },
    onError: (e) => toast(`Could not delete the channel: ${errorMessage(e)}`, 'crit'),
  });
  const save = useMutation({
    mutationFn: () => api.put<Routes>('/notifications/routes', { routes: catalog.map((e) => ({ event_type: e.event_type, channel_ids: [...(current[e.event_type] ?? [])] })) }),
    onSuccess: () => {
      setDraft(null);
      toast('Routing saved.');
      void qc.invalidateQueries({ queryKey: ['routes'] });
      void qc.invalidateQueries({ queryKey: ['channels'] });
    },
  });
  const toggle = (ev: string, ch: string) => {
    const base = draft ?? Object.fromEntries(Object.entries(saved).map(([k, v]) => [k, new Set(v)]));
    const s = new Set(base[ev] ?? []);
    if (s.has(ch)) s.delete(ch);
    else s.add(ch);
    setDraft({ ...base, [ev]: s });
  };

  return (
    <>
    <section className="card" aria-labelledby="notif-t">
      <div className="card-head">
        <div>
          <h2 id="notif-t">Slack channels</h2>
          <div className="desc">Defined once; any event can be routed to them. Messages carry a link only, never values.</div>
        </div>
        {canRoute && (
          <button type="button" className="btn" onClick={() => setAdding(true)}>
            Add channel
          </button>
        )}
      </div>
      <QueryView
        q={chanQ}
        what="notification channels"
        isEmpty={(d) => d.items.length === 0}
        empty={
          <EmptyState title="No channels yet" action={canRoute ? <button type="button" className="btn" onClick={() => setAdding(true)}>Add channel</button> : undefined}>
            Add a Slack channel (the Olympos app must be invited to it), then route events such as backup.failed to it.
          </EmptyState>
        }
      >
        {(d) => (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th>Channel</th>
                  <th>Events routed here</th>
                  <th>Slack ID</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {d.items.map((c) => (
                  <tr key={c.id}>
                    <td className="mono">{c.name}</td>
                    <td className="wrap">{c.routes.length ? c.routes.map((r) => <Chip key={r}>{r}</Chip>) : <span className="muted">nothing routed yet</span>}</td>
                    <td className="mono muted">{c.slack_channel_id}</td>
                    <td className="actions">
                      {canRoute && (
                        <>
                          <button type="button" className="btn sm" onClick={() => testCh.mutate(c)} disabled={testCh.isPending}>
                            Send test
                          </button>
                          <button type="button" className="btn sm" onClick={() => delCh.mutate(c)} disabled={delCh.isPending} aria-label={`Delete channel ${c.name}`}>
                            Delete
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </QueryView>
      <div className="card-spacer" />
    </section>

      {channels.length > 0 && (
        <section className="card" aria-labelledby="matrix-t">
          <div className="card-head">
            <div>
              <h2 id="matrix-t">Routing</h2>
              <div className="desc">Which events go to which channel. Opt-in events are off until you route them.</div>
            </div>
            {canRoute && dirty && (
              <div className="inline">
                <button type="button" className="btn sm" onClick={() => setDraft(null)}>
                  Discard
                </button>
                <button type="button" className="btn sm pri" onClick={() => save.mutate()} disabled={save.isPending}>
                  Save routing
                </button>
              </div>
            )}
          </div>
          <QueryView q={routesQ} what="routing" isEmpty={(r) => r.catalog.length === 0}>
            {() => (
              <div className="table-wrap">
                <table className="t" aria-labelledby="matrix-t">
                  <thead>
                    <tr>
                      <th>Event</th>
                      {channels.map((c) => (
                        <th key={c.id} className="mono" style={{ textTransform: 'none' }}>
                          {c.name}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {catalog.map((e) => (
                      <tr key={e.event_type}>
                        <td className="wrap">
                          <span className="mono">{e.event_type}</span>
                          {e.opt_in && (
                            <>
                              {' '}
                              <Badge tone="mute">opt-in</Badge>
                            </>
                          )}
                          <div className="muted small">{e.description}</div>
                        </td>
                        {channels.map((c) => {
                          const on = current[e.event_type]?.has(c.id) ?? false;
                          return (
                            <td key={c.id}>
                              {canRoute ? (
                                <input type="checkbox" checked={on} onChange={() => toggle(e.event_type, c.id)} aria-label={`Route ${e.event_type} to ${c.name}`} style={{ width: 16, height: 16, accentColor: 'var(--accent-strong)' }} />
                              ) : on ? (
                                'Routed'
                              ) : (
                                <span className="muted">—</span>
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </QueryView>
          <FormError error={save.error} />
          <div className="card-foot">Backup jobs and audit schedules can override the channel with their own. Delivery is at-least-once with retries.</div>
        </section>
      )}
      {adding && <ChannelDialog onClose={() => setAdding(false)} />}
    </>
  );
}

function ChannelDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState('#');
  const [sid, setSid] = useState('');
  const create = useMutation({
    mutationFn: () => api.post<Channel>('/notifications/channels', { name: name.trim(), slack_channel_id: sid.trim() }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['channels'] });
      void qc.invalidateQueries({ queryKey: ['routes'] });
      onClose();
    },
  });
  return (
    <Modal open onClose={onClose} size="narrow" eyebrow="Notifications" title="Add Slack channel" description="Invite the Olympos Slack app to the channel first, or messages will fail.">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
        className="stack-sm"
        style={{ gap: 18 }}
        noValidate
      >
        <Field label="Channel name" htmlFor="ch-name" error={fieldError(create.error, 'name')}>
          <input className="in mono" {...aria('ch-name', fieldError(create.error, 'name'))} value={name} onChange={(e) => setName(e.target.value)} data-autofocus />
        </Field>
        <Field label="Slack channel ID" htmlFor="ch-id" error={fieldError(create.error, 'slack_channel_id')} hint="Channel details › About, e.g. C0123ABCD">
          <input className="in mono" {...aria('ch-id', fieldError(create.error, 'slack_channel_id'), true)} value={sid} onChange={(e) => setSid(e.target.value)} />
        </Field>
        <FormError error={create.error && !Object.keys((create.error as { fields?: object }).fields ?? {}).length ? create.error : null} />
        <div className="end">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn pri" disabled={create.isPending}>
            Add channel
          </button>
        </div>
      </form>
    </Modal>
  );
}
