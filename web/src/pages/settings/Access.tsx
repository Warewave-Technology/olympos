import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../../api/client';
import type { Channel, Cluster, DirectoryUser, Grant, ItemList, Role } from '../../api/types';
import { ROLES } from '../../api/types';
import { useCan, useMe } from '../../auth/me';
import { GUEST_FORBIDDEN_ROLES, isSelf } from '../../auth/permissions';
import { age, personName, plural, shortDate, shortId } from '../../lib/format';
import { parseSelector } from '../../lib/labels';
import { ScopeInput } from '../../ui/TagInput';
import { Badge, Chip, EmptyState, Field, FormError, Modal, QueryView, aria, fieldError, useToast } from '../../ui/kit';
import { SettingsLayout } from './SettingsLayout';

interface PersonRow {
  key: string;
  principal: Grant['principal'];
  is_guest: boolean;
  scope: string;
  grants: Grant[];
  stale: boolean;
}

function groupGrants(gs: Grant[]): PersonRow[] {
  const m = new Map<string, PersonRow>();
  for (const g of gs) {
    const key = `${g.principal.object_id}|${g.scope}`;
    const row = m.get(key) ?? { key, principal: g.principal, is_guest: g.is_guest, scope: g.scope, grants: [], stale: false };
    row.grants.push(g);
    row.stale = row.stale || g.stale;
    m.set(key, row);
  }
  const order = (r: Role) => ROLES.indexOf(r);
  return [...m.values()].map((r) => ({ ...r, grants: r.grants.sort((a, b) => order(b.role) - order(a.role)) })).sort((a, b) => personName(a.principal).localeCompare(personName(b.principal)));
}

function scopeLabel(scope: string) {
  return !scope || scope === 'all' ? 'All clusters' : <span className="mono">{scope}</span>;
}

export function SettingsAccessPage() {
  const canAdmin = useCan('admin_global');
  const navigate = useNavigate();
  useEffect(() => {
    // Notifications used to live at /settings#notifications.
    if (window.location.hash === '#notifications') void navigate({ to: '/settings/notifications', replace: true });
  }, [navigate]);
  const [granting, setGranting] = useState(false);
  const [revoking, setRevoking] = useState<PersonRow | null>(null);
  const grantsQ = useQuery({ queryKey: ['grants'], queryFn: () => api.get<ItemList<Grant>>('/grants') });
  const rows = useMemo(() => groupGrants(grantsQ.data?.items ?? []), [grantsQ.data]);
  const chanQ = useQuery({ queryKey: ['channels'], queryFn: () => api.get<ItemList<Channel>>('/notifications/channels') });
  const accessChannel = chanQ.data?.items.find((c) => c.routes.includes('grant.changed'))?.name;

  return (
    <SettingsLayout current="access" sub="Access is granted to people by Entra object ID · tokens from other tenants are refused">
      <section className="card" aria-labelledby="grants-t">
        <div className="card-head">
          <div>
            <h2 id="grants-t">Access grants</h2>
            <div className="desc">Granted to people (Entra object ID), not groups.{accessChannel ? ` Every change is posted to ${accessChannel}.` : ' Every change is recorded in the activity log.'}</div>
          </div>
          {canAdmin && (
            <button type="button" className="btn pri" onClick={() => setGranting(true)}>
              Grant access
            </button>
          )}
        </div>
        <QueryView q={grantsQ} what="access grants" isEmpty={(d) => d.items.length === 0} empty={<EmptyState title="No grants">Only the bootstrap admins from the server configuration can sign in until someone is granted access.</EmptyState>}>
          {() => (
            <div className="table-wrap">
              <table className="t">
                <thead>
                  <tr>
                    <th>Person</th>
                    <th>Object ID</th>
                    <th>Roles</th>
                    <th>Scope</th>
                    <th>Granted</th>
                    <th>Status</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const first = r.grants[r.grants.length - 1];
                    return (
                      <tr key={r.key}>
                        <td>
                          <span className="inline-sm">
                            {personName(r.principal)}
                            {r.is_guest && <Badge tone="warn">Guest</Badge>}
                          </span>
                          {r.principal.display_name && r.principal.upn && <div className="muted small">{r.principal.display_name}</div>}
                        </td>
                        <td className="mono muted" title={r.principal.object_id}>
                          {shortId(r.principal.object_id)}
                        </td>
                        <td className="wrap">
                          {r.grants.map((g) => (
                            <Chip key={g.id}>{g.role}</Chip>
                          ))}
                        </td>
                        <td>{scopeLabel(r.scope)}</td>
                        <td className="mono">{first.granted_by ? `${shortDate(first.granted_at)} · ${(first.granted_by_name || '').split('@')[0] || 'admin'}` : 'Bootstrap'}</td>
                        <td>{r.stale ? <Badge tone="warn">Stale · account disabled</Badge> : <Badge tone="ok">Active</Badge>}</td>
                        <td className="actions">
                          {canAdmin && (
                            <button type="button" className="btn sm" onClick={() => setRevoking(r)} aria-label={`Revoke access for ${personName(r.principal)}`}>
                              Revoke
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
        <div className="card-foot">vault-approver and admin cannot be given to guest (#EXT#) accounts · Entra app requires assignment, so unassigned users get no token · stale grants do not authorize</div>
      </section>

      {granting && <GrantDialog onClose={() => setGranting(false)} channelName={accessChannel} />}
      {revoking && <RevokeDialog row={revoking} onClose={() => setRevoking(null)} />}
    </SettingsLayout>
  );
}

// ------------------------------------------------------------ grant dialog

function GrantDialog({ onClose, channelName }: { onClose: () => void; channelName?: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [q, setQ] = useState('');
  const [debounced, setDebounced] = useState('');
  const [person, setPerson] = useState<DirectoryUser | null>(null);
  const [roles, setRoles] = useState<Set<Role>>(new Set(['viewer']));
  const [selector, setSelector] = useState('');
  const [scopeDraftErr, setScopeDraftErr] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);
  const searchQ = useQuery({
    queryKey: ['principals', debounced],
    queryFn: () => api.get<ItemList<DirectoryUser>>('/principals/search', { q: debounced }),
    enabled: debounced.length >= 2,
  });
  const clustersQ = useQuery({ queryKey: ['clusters'], queryFn: () => api.get<ItemList<Cluster>>('/clusters') });
  const clusters = clustersQ.data ? clustersQ.data.items.filter((c) => c.status !== 'revoked') : undefined;
  const scopeAll = selector.trim() === '' || selector.trim() === 'all';

  useEffect(() => {
    if (person?.is_guest) setRoles((r) => new Set([...r].filter((x) => !GUEST_FORBIDDEN_ROLES.includes(x))));
  }, [person]);

  const create = useMutation({
    mutationFn: () => api.post<{ ids: string[] }>('/grants', { object_id: person!.object_id, roles: [...roles], scope: scopeAll ? 'all' : selector.trim() }),
    onSuccess: () => {
      toast(`Access granted to ${person!.display_name}.`);
      void qc.invalidateQueries({ queryKey: ['grants'] });
      onClose();
    },
  });
  const [localErr, setLocalErr] = useState<Record<string, string>>({});
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const er: Record<string, string> = {};
    if (!person) er.object_id = 'Search and pick a person.';
    if (roles.size === 0) er.roles = 'Select at least one role.';
    if (scopeDraftErr) er.scope = 'Fix or remove the label you are typing.';
    else if (!scopeAll && parseSelector(selector).error) er.scope = parseSelector(selector).error!;
    setLocalErr(er);
    if (Object.keys(er).length) return;
    create.mutate();
  };
  const fe = (n: string) => localErr[n] ?? fieldError(create.error, n);
  const results = searchQ.data?.items ?? [];

  return (
    <Modal open onClose={onClose} eyebrow="Access" title="Grant access to a person" description="Grants are by Entra object ID. Group membership is ignored." initialFocus={searchRef}>
      <form onSubmit={submit} className="stack-sm" style={{ gap: 18 }} noValidate>
        <div>
          <Field label="Person" htmlFor="ga-q" error={fe('object_id')} hint={q.trim().length < 2 ? 'Type at least 2 letters of a name or e-mail.' : undefined}>
            <input
              ref={searchRef}
              type="search"
              className="in"
              {...aria('ga-q', fe('object_id'), q.trim().length < 2)}
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPerson(null);
              }}
              autoComplete="off"
              role="combobox"
              aria-expanded={results.length > 0}
              aria-controls="ga-results"
            />
          </Field>
          {debounced.length >= 2 && (
            <div className="boxed tight" style={{ marginTop: 8 }} id="ga-results" role="listbox" aria-label="Directory results">
              {searchQ.isPending ? (
                <div className="state" style={{ padding: 14 }}>
                  <span className="muted">Searching Entra ID…</span>
                </div>
              ) : searchQ.isError ? (
                <div className="state error" style={{ padding: 14 }} role="alert">
                  {errorMessage(searchQ.error)}
                </div>
              ) : results.length === 0 ? (
                <div className="state" style={{ padding: 14 }}>
                  <span className="muted">Nobody found for “{debounced}”. Check the spelling or search by e-mail.</span>
                </div>
              ) : (
                results.map((u, i) => {
                  const sel = person?.object_id === u.object_id;
                  return (
                    <button
                      key={u.object_id}
                      type="button"
                      role="option"
                      aria-selected={sel}
                      className="li"
                      disabled={!u.account_enabled}
                      style={{ borderRadius: 0, borderTop: i ? '1px solid var(--border)' : undefined, background: sel ? 'var(--bg-hover)' : undefined }}
                      onClick={() => setPerson(u)}
                    >
                      <div className="l1">
                        <span style={{ fontSize: 13 }}>
                          {u.display_name} · {u.upn}
                        </span>
                        <span className="inline-sm">
                          {u.is_guest && <Badge tone="warn">Guest</Badge>}
                          {!u.account_enabled && <Badge tone="mute">Disabled</Badge>}
                          {sel && <Badge tone="ok">Selected</Badge>}
                        </span>
                      </div>
                      <div className="mono muted small">
                        oid {shortId(u.object_id)} · {u.user_type || 'Member'}
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          )}
        </div>
        <fieldset className="plain" aria-describedby={fe('roles') ? 'ga-roles-err' : undefined}>
          <legend className="lbl">Roles</legend>
          <div className="grid-2" style={{ gap: '4px 16px' }}>
            {ROLES.map((r) => {
              const blocked = !!person?.is_guest && GUEST_FORBIDDEN_ROLES.includes(r);
              return (
                <label className="chk" key={r}>
                  <input
                    type="checkbox"
                    checked={roles.has(r)}
                    disabled={blocked}
                    onChange={(e) =>
                      setRoles((p) => {
                        const n = new Set(p);
                        if (e.target.checked) n.add(r);
                        else n.delete(r);
                        return n;
                      })
                    }
                  />
                  <span className="mono">{r}</span>
                  {GUEST_FORBIDDEN_ROLES.includes(r) && <span className="muted small">{blocked ? '(blocked: guest account)' : '(not for guests)'}</span>}
                </label>
              );
            })}
          </div>
          {fe('roles') && (
            <div className="field-error" id="ga-roles-err" role="alert">
              {fe('roles')}
            </div>
          )}
        </fieldset>
        <Field label="Scope (cluster labels)" htmlFor="ga-sel" error={fe('scope')} hint="Every label must match. No labels = all clusters, including ones added later.">
          <ScopeInput id="ga-sel" value={selector} onChange={setSelector} clusters={clusters} error={fe('scope')} hintId="ga-sel-hint" onDraftError={setScopeDraftErr} />
        </Field>
        <FormError error={create.error && !fieldError(create.error, 'roles') && !fieldError(create.error, 'object_id') && !fieldError(create.error, 'scope') ? create.error : null} />
        <div className="note">{channelName ? <>This change is posted to <span className="mono">{channelName}</span> and recorded in the activity log.</> : 'This change is recorded in the activity log and emits grant.changed.'}</div>
        <div className="end">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn pri" disabled={create.isPending}>
            Grant access
          </button>
        </div>
      </form>
    </Modal>
  );
}

function RevokeDialog({ row, onClose }: { row: PersonRow; onClose: () => void }) {
  const me = useMe();
  const qc = useQueryClient();
  const toast = useToast();
  const [sel, setSel] = useState<Set<string>>(new Set(row.grants.map((g) => g.id)));
  const revoke = useMutation({
    mutationFn: async () => {
      for (const id of sel) await api.del(`/grants/${id}`);
    },
    onSuccess: () => {
      toast(`Access revoked for ${personName(row.principal)}.`);
      void qc.invalidateQueries({ queryKey: ['grants'] });
      onClose();
    },
    onError: () => void qc.invalidateQueries({ queryKey: ['grants'] }),
  });
  const self = isSelf(me, row.principal);
  return (
    <Modal open onClose={onClose} size="narrow" eyebrow="Access" title={`Revoke access for ${personName(row.principal)}`} description={<>Scope: {scopeLabel(row.scope)} · signed-in sessions without remaining grants end immediately.</>}>
      <fieldset className="plain">
        <legend className="lbl">Roles to revoke</legend>
        {row.grants.map((g) => (
          <label className="chk" key={g.id}>
            <input
              type="checkbox"
              checked={sel.has(g.id)}
              onChange={(e) =>
                setSel((p) => {
                  const n = new Set(p);
                  if (e.target.checked) n.add(g.id);
                  else n.delete(g.id);
                  return n;
                })
              }
            />
            <span className="mono">{g.role}</span>
            <span className="muted small">granted {age(g.granted_at)} ago</span>
          </label>
        ))}
      </fieldset>
      {self && <div className="note warn">This is your own access. Revoking admin can lock you out of these settings.</div>}
      <FormError error={revoke.error} />
      <div className="end">
        <button type="button" className="btn" onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="btn danger" onClick={() => revoke.mutate()} disabled={sel.size === 0 || revoke.isPending}>
          Revoke {plural(sel.size, 'role')}
        </button>
      </div>
    </Modal>
  );
}
