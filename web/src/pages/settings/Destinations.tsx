import { useRef, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { Destination, DestinationInput, DestinationTest, ItemList } from '../../api/types';
import { useCan } from '../../auth/me';
import { date, daysUntil, relDateTime } from '../../lib/format';
import { parseSas, type SasCheck } from '../../lib/sas';
import { destinationsRoute } from '../../router';
import { CheckIcon } from '../../ui/icons';
import { Badge, EmptyState, Field, FormError, Modal, QueryView, aria, fieldError, useAction, useToast } from '../../ui/kit';
import { SettingsLayout } from './SettingsLayout';

function statusBadge(d: Destination) {
  const days = daysUntil(d.sas_expires_at);
  if (d.auth === 'sas_token' && days !== null && days < 0) return <Badge tone="crit">SAS expired</Badge>;
  if (d.last_test_ok === false) return <Badge tone="crit">Test failed</Badge>;
  if (d.auth === 'sas_token' && days !== null && days <= 14) return <Badge tone="warn">SAS expires in {days} days</Badge>;
  if (d.last_test_ok === null) return <Badge tone="mute">Not tested</Badge>;
  return <Badge tone="ok">Healthy</Badge>;
}

const STEP_LABEL: Record<string, string> = {
  write: 'Write probe blob',
  read: 'Read it back',
  tag: 'Set index tag olympos-tier',
  delete_refused: 'Delete refused (as it should be)',
  sas_permissions: 'SAS permissions',
  sas_expiry: 'SAS expiry',
};

export function DestinationsPage() {
  const { id } = destinationsRoute.useSearch();
  const navigate = useNavigate({ from: '/settings/destinations' });
  const canAdmin = useCan('admin_global');
  const q = useQuery({ queryKey: ['destinations'], queryFn: () => api.get<ItemList<Destination>>('/destinations') });
  const selected = id === 'new' ? null : q.data?.items.find((d) => d.id === id);
  const editing = canAdmin && (id === 'new' || !!selected);

  return (
    <SettingsLayout
      current="destinations"
      sub="Destinations · the Olympos server is the only writer to backup storage"
      actions={
        canAdmin && (
          <button type="button" className="btn pri" onClick={() => navigate({ search: { id: 'new' } })}>
            New destination
          </button>
        )
      }
    >
      <section className="card" aria-labelledby="dst-t">
        <div className="card-head">
          <h2 id="dst-t">Destinations</h2>
        </div>
        <QueryView
          q={q}
          what="destinations"
          isEmpty={(d) => d.items.length === 0}
          empty={
            <EmptyState title="No destinations yet" action={canAdmin ? <button type="button" className="btn pri" onClick={() => navigate({ search: { id: 'new' } })}>New destination</button> : undefined}>
              Backups need an Azure Blob container. Managed Identity is recommended: the server’s identity gets read, write and tag, but no delete.
            </EmptyState>
          }
        >
          {(d) => (
            <div className="table-wrap">
              <table className="t">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Storage account / container</th>
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
                  {d.items.map((x) => (
                    <tr key={x.id} className={x.id === id ? 'sel' : undefined}>
                      <td className="mono">{x.name}</td>
                      <td className="mono">
                        {x.account} / {x.container}
                      </td>
                      <td>{x.auth === 'managed_identity' ? <Badge tone="info">Managed Identity</Badge> : <Badge tone="mute">SAS token</Badge>}</td>
                      <td>{!x.last_test ? <span className="muted">Not tested</span> : x.last_test.can_delete ? <Badge tone="crit">No · can delete</Badge> : <Badge tone="ok">Yes</Badge>}</td>
                      <td>{x.jobs === 1 ? '1 job' : `${x.jobs} jobs`}</td>
                      <td>{statusBadge(x)}</td>
                      <td className="actions">
                        {canAdmin && (
                          <button type="button" className="btn sm" onClick={() => navigate({ search: { id: x.id } })} aria-label={`Edit ${x.name}`}>
                            Edit
                          </button>
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
      {editing && <DestinationForm key={id} dest={selected ?? undefined} onDone={() => navigate({ search: {} })} />}
    </SettingsLayout>
  );
}

function DestinationForm({ dest, onDone }: { dest?: Destination; onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState(dest?.name ?? '');
  const [account, setAccount] = useState(dest?.account ?? '');
  const [container, setContainer] = useState(dest?.container ?? '');
  const [prefix, setPrefix] = useState(dest?.prefix ?? 'olympos/');
  const [auth, setAuth] = useState<DestinationInput['auth']>(dest?.auth ?? 'managed_identity');
  const [sasSource, setSasSource] = useState<'stored' | 'keyvault_ref'>(dest?.sas_source === 'keyvault_ref' ? 'keyvault_ref' : 'stored');
  const [sasRef, setSasRef] = useState(dest?.sas_ref ?? '');
  // The SAS token itself stays in the DOM input; only its non-secret parse lives in state.
  const sasRef$ = useRef<HTMLInputElement>(null);
  const [parsed, setParsed] = useState<SasCheck | null>(null);
  const [report, setReport] = useState<DestinationTest | null>(dest?.last_test ?? null);
  const [reportAt, setReportAt] = useState<string | null>(dest?.last_test_at ?? null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const test = useAction<DestinationTest>();
  const save = useAction<Destination>();
  const del = useAction<boolean>();

  const body = (): DestinationInput => {
    const sasValue = sasRef$.current?.value ?? '';
    return {
      name: name.trim(),
      account: account.trim(),
      container: container.trim(),
      prefix: prefix.trim(),
      auth,
      ...(auth === 'sas_token'
        ? { sas: sasSource === 'keyvault_ref' ? { source: 'keyvault_ref' as const, ref: sasRef.trim() } : sasValue ? { source: 'stored' as const, value: sasValue } : { source: 'stored' as const } }
        : {}),
    };
  };
  const sasChanged = () => !!sasRef$.current?.value;

  const runTest = async () => {
    const b = body();
    const r = await test.run(() => (dest && !sasChanged() && b.auth === dest.auth ? api.post<DestinationTest>(`/destinations/${dest.id}/test`) : api.post<DestinationTest>('/destinations/test', b)));
    if (r) {
      setReport(r);
      setReportAt(new Date().toISOString());
    }
  };
  const doSave = async () => {
    const b = body();
    const r = await save.run(() => (dest ? api.patch<Destination>(`/destinations/${dest.id}`, b) : api.post<Destination>('/destinations', b)));
    if (r) {
      if (sasRef$.current) sasRef$.current.value = '';
      setParsed(null);
      void qc.invalidateQueries({ queryKey: ['destinations'] });
      toast(r.last_test?.can_delete ? `Saved ${r.name} — WARNING: this credential can delete backups.` : `Saved ${r.name}.`, r.last_test?.can_delete ? 'crit' : 'ok');
      onDone();
    }
  };
  const doDelete = async () => {
    if (!dest) return;
    const ok = await del.run(async () => {
      await api.del(`/destinations/${dest.id}`);
      return true;
    });
    setConfirmDelete(false);
    if (ok) {
      void qc.invalidateQueries({ queryKey: ['destinations'] });
      toast(`Deleted ${dest.name}.`);
      onDone();
    }
  };

  const fe = (n: string) => fieldError(save.error, n) ?? fieldError(test.error, n);
  const sas = parsed;
  const storedHint = dest?.auth === 'sas_token' && dest.sas_source === 'stored' ? `A token is stored (permissions ${dest.sas_permissions || '?'}, expires ${date(dest.sas_expires_at)}). Paste a new one to replace it.` : 'Paste a container-scoped SAS token. It is envelope-encrypted and never shown again.';

  return (
    <section className="card pad-lg" aria-labelledby="dst-edit-t">
      <div>
        <div className="muted small">{dest ? 'Edit destination' : 'New destination'}</div>
        <h2 id="dst-edit-t" className="mono" style={{ margin: '4px 0 0', fontSize: 16, fontWeight: 500 }}>
          {dest?.name ?? (name || 'unnamed')}
        </h2>
      </div>
      <div className="grid-2">
        <Field label="Name" htmlFor="d-name" error={fe('name')}>
          <input className="in mono" {...aria('d-name', fe('name'))} value={name} onChange={(e) => setName(e.target.value)} placeholder="blob-weu-backups" />
        </Field>
        <div />
      </div>
      <div className="grid-3">
        <Field label="Storage account" htmlFor="d-acc" error={fe('account')}>
          <input className="in mono" {...aria('d-acc', fe('account'))} value={account} onChange={(e) => setAccount(e.target.value)} placeholder="stolympweu01" spellCheck={false} />
        </Field>
        <Field label="Container" htmlFor="d-con" error={fe('container')}>
          <input className="in mono" {...aria('d-con', fe('container'))} value={container} onChange={(e) => setContainer(e.target.value)} placeholder="backups" spellCheck={false} />
        </Field>
        <Field label="Prefix" htmlFor="d-pre" error={fe('prefix')}>
          <input className="in mono" {...aria('d-pre', fe('prefix'))} value={prefix} onChange={(e) => setPrefix(e.target.value)} spellCheck={false} />
        </Field>
      </div>
      <fieldset className="opts">
        <legend className="lbl">Authentication</legend>
        <label className="opt">
          <input type="radio" name="auth" checked={auth === 'managed_identity'} onChange={() => setAuth('managed_identity')} />
          <span>
            <span className="t1">Managed Identity</span> <Badge tone="ok">Recommended</Badge>
            <span className="t2">The server's identity with a custom role (read, write, tag; no delete). Lets you disable shared key on the account.</span>
          </span>
        </label>
        <label className="opt">
          <input type="radio" name="auth" checked={auth === 'sas_token'} onChange={() => setAuth('sas_token')} />
          <span>
            <span className="t1">SAS token</span>
            <span className="t2">Container-scoped SAS you create. Used only by the server, never sent to clusters.</span>
          </span>
        </label>
      </fieldset>

      {auth === 'sas_token' && (
        <>
          <fieldset className="plain">
            <legend className="lbl">SAS token source</legend>
            <div className="inline">
              <label className="chk">
                <input type="radio" name="sas-src" checked={sasSource === 'keyvault_ref'} onChange={() => setSasSource('keyvault_ref')} /> Key Vault reference
              </label>
              <label className="chk">
                <input type="radio" name="sas-src" checked={sasSource === 'stored'} onChange={() => setSasSource('stored')} /> Store in Olympos
              </label>
            </div>
          </fieldset>
          {sasSource === 'keyvault_ref' ? (
            <Field label="Key Vault reference" htmlFor="d-ref" error={fe('ref') ?? fe('sas')} hint="kv://<vault>/<secret>; the secret holds the SAS token. Permissions and expiry are checked by Test destination.">
              <input className="in mono" {...aria('d-ref', fe('ref') ?? fe('sas'), true)} value={sasRef} onChange={(e) => setSasRef(e.target.value)} placeholder="kv://kv-platform-weu/backup-sas" spellCheck={false} />
            </Field>
          ) : (
            <Field label="SAS token" htmlFor="d-sas" error={fe('sas') ?? fe('value')} hint={storedHint}>
              <input
                ref={sasRef$}
                type="password"
                className="in mono"
                {...aria('d-sas', fe('sas') ?? fe('value'), true)}
                onChange={(e) => setParsed(e.target.value ? parseSas(e.target.value) : null)}
                autoComplete="off"
                spellCheck={false}
              />
            </Field>
          )}
        </>
      )}

      {(sas || report) && (
        <div className="grid-2" style={{ gap: 16 }}>
          {sas ? (
            <div className="note" style={{ display: 'flex', flexDirection: 'column', gap: 4 }} aria-live="polite">
              <b className="note-title">Parsed from token</b>
              <div className="chk">
                <CheckIcon ok={sas.scope === 'container'} warn={sas.scope !== 'container'} />
                <span>
                  Scope: {sas.scope === 'container' ? <>container {container && <span className="mono">{container}</span>}</> : sas.scope === 'account' ? 'account SAS (needs shared key on the account)' : sas.scope}
                </span>
              </div>
              <div className="chk">
                <CheckIcon ok={sas.missing.length === 0} />
                <span>
                  Permissions <span className="mono">{sas.permissions.join(' ') || 'none'}</span>
                  {sas.missing.length > 0 && <> · missing <span className="mono">{sas.missing.join(' ')}</span></>}
                </span>
              </div>
              <div className="chk">
                <CheckIcon ok={!sas.extra.includes('d')} />
                <span>{sas.extra.includes('d') ? <>Has delete (<span className="mono">d</span>): Olympos must not be able to delete backups</> : <>No delete (<span className="mono">d</span>) permission</>}</span>
              </div>
              {sas.extra.includes('l') && (
                <div className="chk">
                  <CheckIcon ok={false} warn />
                  <span>
                    List (<span className="mono">l</span>) is not needed; remove it
                  </span>
                </div>
              )}
              <div className="chk">
                <CheckIcon ok={!!sas.expiresAt && !sas.expired} />
                <span>{!sas.expiresAt ? 'No expiry (se) found' : sas.expired ? `Expired ${date(sas.expiresAt)}` : `Expires ${date(sas.expiresAt)} · alerts at 14 and 3 days`}</span>
              </div>
            </div>
          ) : (
            <div />
          )}
          {report && (
            <div className={`note${report.can_delete ? ' crit' : ''}`} style={{ display: 'flex', flexDirection: 'column', gap: 4 }} aria-live="polite">
              <b className="note-title">Test destination{reportAt ? ` · ${relDateTime(reportAt)}` : ''}</b>
              {report.steps.map((s) => (
                <div className="chk" key={s.name}>
                  <CheckIcon ok={s.ok} />
                  <span>
                    {s.name === 'delete_refused' && !s.ok ? 'Delete was NOT refused' : STEP_LABEL[s.name] ?? s.name}
                    {s.detail && s.name.startsWith('sas') ? <span className="mono"> · {s.detail}</span> : null}
                  </span>
                </div>
              ))}
              {report.error && <div className="ico-crit">{report.error}</div>}
            </div>
          )}
        </div>
      )}
      {report?.can_delete && (
        <div className="note crit" role="alert">
          <b>This credential can delete blobs.</b> Olympos must not be able to delete backups (retention is done by lifecycle rules). Remove the delete permission (SAS without <span className="mono">d</span>, or a custom role without <span className="mono">blobs/delete</span>). Saving is possible, but the destination stays flagged.
        </div>
      )}
      {test.pending && <p className="muted small" role="status">Testing: writing a probe blob, reading it back, tagging it and trying to delete it…</p>}
      <FormError error={save.error ?? test.error ?? del.error} />
      {auth === 'sas_token' ? (
        <div className="note warn">SAS tokens of this type need shared key access enabled on the storage account. With Managed Identity you can turn shared key off. Retention is enforced by the account's lifecycle rules, not by Olympos.</div>
      ) : (
        <div className="note">Give the server's managed identity a custom data-plane role on the container with read, write, add and tag permissions, and no delete. Retention is enforced by the account's lifecycle rules, not by Olympos.</div>
      )}
      <div className="foot-actions">
        <div className="inline">
          {dest && (
            <button type="button" className="btn danger" onClick={() => setConfirmDelete(true)}>
              Delete
            </button>
          )}
          <button type="button" className="btn" onClick={onDone}>
            Cancel
          </button>
        </div>
        <div className="inline">
          <button type="button" className="btn" onClick={() => void runTest()} disabled={test.pending}>
            Test destination
          </button>
          <button type="button" className="btn pri" onClick={() => void doSave()} disabled={save.pending}>
            {save.pending ? 'Testing and saving…' : 'Save'}
          </button>
        </div>
      </div>
      {confirmDelete && dest && (
        <Modal open onClose={() => setConfirmDelete(false)} size="narrow" eyebrow="Destinations" title={`Delete ${dest.name}?`} description="Only the destination definition is removed. Backups already in the container are not touched (Olympos cannot delete blobs).">
          {dest.jobs > 0 && <div className="note warn">{dest.jobs} backup jobs use this destination. Move them to another destination first; the server refuses otherwise.</div>}
          <div className="end">
            <button type="button" className="btn" onClick={() => setConfirmDelete(false)}>
              Cancel
            </button>
            <button type="button" className="btn danger" onClick={() => void doDelete()} disabled={del.pending || dest.jobs > 0}>
              Delete destination
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}
