import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../../api/client';
import type { Registry, RegistryInput, UnmatchedRegistry } from '../../api/types';
import { useCan } from '../../auth/me';
import { plural } from '../../lib/format';
import { Badge, EmptyState, Field, FormError, Modal, QueryView, aria, fieldError, useAction, useToast } from '../../ui/kit';
import { Select } from '../../ui/Select';
import { SettingsLayout } from './SettingsLayout';

type Source = 'keyvault_ref' | 'stored' | 'managed_identity';
interface RegistriesResponse {
  items: Registry[];
  unmatched: UnmatchedRegistry[];
}

function credCell(r: Registry) {
  const src = r.credential_source as string;
  if (src === 'managed_identity') return <span className="inline-sm"><Badge tone="info">Managed Identity</Badge><span className="muted">AcrPull</span></span>;
  if (src === 'keyvault_ref') return <span className="inline-sm"><Badge tone="mute">Key Vault ref</Badge><span className="mono muted">{r.credential_ref.replace(/^kv:\/\/[^/]+\//, '')}</span></span>;
  if (src === 'stored') return <span className="inline-sm"><Badge tone="mute">Stored</Badge><span className="mono muted">{r.username}</span></span>;
  return <span className="muted">Anonymous</span>;
}

export function RegistriesPage() {
  const canAdmin = useCan('admin_global');
  const qc = useQueryClient();
  const toast = useToast();
  const [prefill, setPrefill] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Registry | null>(null);
  const q = useQuery({ queryKey: ['registries'], queryFn: () => api.get<RegistriesResponse>('/registries') });
  const unmatched = q.data?.unmatched ?? [];
  const del = useMutation({
    mutationFn: (r: Registry) => api.del(`/registries/${r.id}`),
    onSuccess: () => {
      setDeleting(null);
      toast('Registry credential removed.');
      void qc.invalidateQueries({ queryKey: ['registries'] });
    },
    onError: (e) => toast(`Could not remove it: ${errorMessage(e)}`, 'crit'),
  });

  return (
    <SettingsLayout current="registries" sub="Registries · pull credentials for image scanning, used by the server only">
      <section className="card" aria-labelledby="reg-t">
        <div className="card-head">
          <h2 id="reg-t">Registries</h2>
          {canAdmin && (
            <button type="button" className="btn pri" onClick={() => setPrefill('')}>
              Add registry
            </button>
          )}
        </div>
        <QueryView
          q={q}
          what="registries"
          isEmpty={(d) => d.items.length === 0}
          empty={<EmptyState title="No registry credentials yet">Public images are scanned anonymously. Add a read-only credential for each private registry so trivy can pull its images.</EmptyState>}
        >
          {(d) => (
            <div className="table-wrap">
              <table className="t">
                <thead>
                  <tr>
                    <th>Host pattern</th>
                    <th>Credential</th>
                    <th className="num">Images</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {d.items.map((r) => (
                    <tr key={r.id}>
                      <td className="mono">{r.host_pattern}</td>
                      <td>{credCell(r)}</td>
                      <td className="num">{r.images}</td>
                      <td className="actions">
                        {canAdmin && (
                          <button type="button" className="btn sm" onClick={() => setDeleting(r)} aria-label={`Remove credential for ${r.host_pattern}`}>
                            Remove
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

      {q.data && unmatched.length > 0 && (
        <section className="card pad-lg" aria-labelledby="unm-t">
          <div className="card-title">
            <div>
              <div className="eyebrow">Unmatched images</div>
              <h2 id="unm-t">
                {plural(unmatched.length, 'registry has', 'registries have')} no credential
              </h2>
            </div>
            <Badge tone="warn">{plural(unmatched.reduce((s, u) => s + u.images, 0), 'image')} not scanned</Badge>
          </div>
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th>Registry host</th>
                  <th>Example</th>
                  <th className="num">Images</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {unmatched.map((u) => (
                  <tr key={u.host}>
                    <td className="mono">{u.host}</td>
                    <td className="mono muted">{u.example_repo}</td>
                    <td className="num">{u.images}</td>
                    <td className="actions">
                      {canAdmin && (
                        <button type="button" className="btn sm pri" onClick={() => setPrefill(u.example_repo ? u.example_repo.split('/').slice(0, -1).join('/') + '/*' : u.host)}>
                          Add credential
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="note">The agent never reads imagePullSecrets. Give Olympos a read-only robot account per registry. On-prem registries are pulled through the agent tunnel when they are not reachable from the server.</div>
        </section>
      )}

      {prefill !== null && <RegistryDialog host={prefill} onClose={() => setPrefill(null)} />}
      {deleting && (
        <Modal open onClose={() => setDeleting(null)} size="narrow" eyebrow="Registries" title={`Remove credential for ${deleting.host_pattern}?`} description="Images from this registry show Missing credential and are no longer scanned.">
          <div className="end">
            <button type="button" className="btn" onClick={() => setDeleting(null)}>
              Cancel
            </button>
            <button type="button" className="btn danger" onClick={() => del.mutate(deleting)} disabled={del.isPending}>
              Remove
            </button>
          </div>
        </Modal>
      )}
    </SettingsLayout>
  );
}

/** Add registry credential. The password stays in the DOM input and is wiped after save. */
function RegistryDialog({ host: initialHost, onClose }: { host: string; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [host, setHost] = useState(initialHost);
  const [source, setSource] = useState<Source>('keyvault_ref');
  const [username, setUsername] = useState('');
  const [ref, setRef] = useState('');
  const pwRef = useRef<HTMLInputElement>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; error?: string } | null>(null);
  const save = useAction<Registry>();
  const test = useAction<{ ok: boolean; error?: string }>();

  const body = (): RegistryInput => ({
    host_pattern: host.trim(),
    username: source === 'managed_identity' ? '' : username.trim(),
    password: source === 'keyvault_ref' ? { source: 'keyvault_ref', ref: ref.trim() } : source === 'stored' ? { source: 'stored', value: pwRef.current?.value ?? '' } : ({ source: 'managed_identity' } as never),
  });
  const doTest = async () => {
    const r = await test.run(() => api.post<{ ok: boolean; error?: string }>('/registries/test', body()));
    if (r) setTestResult(r);
  };
  const doSave = async (e: React.FormEvent) => {
    e.preventDefault();
    const b = body();
    if (pwRef.current) pwRef.current.value = '';
    const r = await save.run(() => api.post<Registry>('/registries', b));
    if (r) {
      toast(`Credential for ${r.host_pattern} saved. Matching images are scanned next.`);
      void qc.invalidateQueries({ queryKey: ['registries'] });
      void qc.invalidateQueries({ queryKey: ['images'] });
      onClose();
    }
  };
  const fe = (n: string) => fieldError(save.error, n) ?? fieldError(test.error, n);

  return (
    <Modal open onClose={onClose} eyebrow="Registries" title="Add registry credential" description="Used by the server's trivy only. Never sent to clusters.">
      <form onSubmit={doSave} className="stack-sm" style={{ gap: 18 }} noValidate>
        <div className="grid-2">
          <Field label="Host pattern" htmlFor="r-host" error={fe('host_pattern')} hint="e.g. harbor.factory.local/mes/* or *.azurecr.io">
            <input className="in mono" {...aria('r-host', fe('host_pattern'), true)} value={host} onChange={(e) => setHost(e.target.value)} data-autofocus spellCheck={false} />
          </Field>
          <Field label="Credential source" htmlFor="r-src">
            <Select<Source>
              id="r-src"
              value={source}
              onChange={setSource}
              options={[
                { value: 'keyvault_ref', label: 'Key Vault reference', hint: 'Read at scan time; nothing stored in Olympos' },
                { value: 'stored', label: 'Store in Olympos', hint: 'Envelope-encrypted with a Key Vault key' },
              ]}
            />
          </Field>
          {source !== 'managed_identity' && (
            <Field label="Username" htmlFor="r-user" error={fe('username')}>
              <input className="in mono" {...aria('r-user', fe('username'))} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="robot$olympos-scan" spellCheck={false} autoComplete="off" />
            </Field>
          )}
          {source === 'keyvault_ref' && (
            <Field label="Key Vault secret" htmlFor="r-ref" error={fe('ref') ?? fe('password')} hint="kv://<vault>/<secret>">
              <input className="in mono" {...aria('r-ref', fe('ref') ?? fe('password'), true)} value={ref} onChange={(e) => setRef(e.target.value)} placeholder="kv://kv-platform-weu/harbor-factory-scan" spellCheck={false} />
            </Field>
          )}
          {source === 'stored' && (
            <Field label="Password or token" htmlFor="r-pw" error={fe('password') ?? fe('value')} hint="Envelope-encrypted; never shown again.">
              <input ref={pwRef} type="password" className="in mono" {...aria('r-pw', fe('password') ?? fe('value'), true)} autoComplete="new-password" />
            </Field>
          )}
        </div>
        {source === 'managed_identity' && <div className="note">Grant the server's managed identity <span className="mono">AcrPull</span> on the registry. Works for Azure Container Registry only.</div>}
        {testResult && (
          <div className={`note ${testResult.ok ? 'ok' : 'crit'}`} role="status">
            {testResult.ok ? 'Test pull succeeded: the credential can read manifests.' : `Test pull failed: ${testResult.error}`}
          </div>
        )}
        <FormError error={(save.error && !Object.keys((save.error as { fields?: object }).fields ?? {}).length ? save.error : null) ?? test.error} />
        <div className="end">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn" onClick={() => void doTest()} disabled={test.pending}>
            {test.pending ? 'Testing…' : 'Test pull'}
          </button>
          <button type="submit" className="btn pri" disabled={save.pending}>
            Save
          </button>
        </div>
      </form>
    </Modal>
  );
}
