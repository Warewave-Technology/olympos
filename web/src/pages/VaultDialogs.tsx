import { useRef, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import { ApiError, api, errorMessage } from '../api/client';
import type { ChangeItemInput, ChangeRequest, SecretDetail, Vault, VaultInspect } from '../api/types';
import { shortDate } from '../lib/format';
import { CheckIcon } from '../ui/icons';
import { Badge, Drawer, Field, FormError, Modal, TypeToConfirm, aria, fieldError, useAction } from '../ui/kit';
import { crLabel } from '../ui/status';
import { VaultIdentity, vaultIdentityProps, vaultPath } from '../ui/vault';

const KEY_RE = /^[A-Za-z0-9_.-]{1,128}$/;

function useCrSubmit() {
  const qc = useQueryClient();
  const a = useAction<ChangeRequest>();
  const submit = (body: { vault_id: string; justification: string; items: ChangeItemInput[] }) =>
    a.run(async () => {
      const r = await api.post<ChangeRequest>('/change-requests', body);
      void qc.invalidateQueries({ queryKey: ['change-requests'] });
      void qc.invalidateQueries({ queryKey: ['vault-secret'] });
      return r;
    });
  return { ...a, submit };
}

function Submitted({ cr, vault, onClose }: { cr: ChangeRequest; vault: Vault; onClose: () => void }) {
  return (
    <>
      <div className="note ok" role="status">
        <div className="note-title">
          Submitted <span className="mono">{crLabel(cr)}</span> for approval
        </div>
        For <span className="mono">{vaultPath({ cluster: vault.target.cluster_name, namespace: vault.target.namespace, service: vault.target.service })}</span> ({vault.provider === 'openbao' ? 'OpenBao' : 'HashiCorp Vault'} {vault.version}). The value is sealed until a second person approves it. It is never shown again, also not to you.
      </div>
      {cr.items.some((i) => i.fingerprint) && (
        <div>
          <div className="lbl">Fingerprint (HMAC) · share with the approver if needed</div>
          {cr.items
            .filter((i) => i.fingerprint)
            .map((i) => (
              <div key={i.id} className="inline">
                <span className="mono">{i.key}</span>
                <span className="mono strong">{i.fingerprint}</span>
              </div>
            ))}
        </div>
      )}
      <div className="drawer-foot" style={{ marginTop: 0 }}>
        <Link to="/approvals" search={{ view: 'mine', cr: cr.id }} className="btn">
          Open request
        </Link>
        <button type="button" className="btn pri" onClick={onClose}>
          Done
        </button>
      </div>
    </>
  );
}

/**
 * Change-request drawer (SPEC §11.4): New value + Confirm value. The inputs are
 * uncontrolled, so the value never enters React state or any query cache; it is read
 * from the DOM once at submit and the fields are wiped right after.
 */
export function ChangeRequestDrawer({
  open,
  onClose,
  vault,
  secret,
  mount,
  path,
  keyName,
}: {
  open: boolean;
  onClose: () => void;
  vault: Vault;
  secret?: SecretDetail;
  mount: string;
  path: string;
  keyName: string | null; // null = add key
}) {
  const valueRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);
  const keyRef = useRef<HTMLInputElement>(null);
  const [newKey, setNewKey] = useState('');
  const [why, setWhy] = useState('');
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [done, setDone] = useState<ChangeRequest | null>(null);
  const s = useCrSubmit();
  const adding = keyName === null;
  const baseVersion = secret?.current_version ?? 0;

  const close = () => {
    if (valueRef.current) valueRef.current.value = '';
    if (confirmRef.current) confirmRef.current.value = '';
    setNewKey('');
    setWhy('');
    setErrs({});
    setDone(null);
    s.reset();
    onClose();
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const value = valueRef.current?.value ?? '';
    const confirm = confirmRef.current?.value ?? '';
    const key = adding ? newKey.trim() : keyName!;
    const er: Record<string, string> = {};
    if (adding && !KEY_RE.test(key)) er.key = 'Use letters, digits, dot, dash or underscore (max 128).';
    if (adding && secret?.keys.includes(key)) er.key = 'This key already exists. Use Replace on it instead.';
    if (!value) er.value = 'Enter the new value.';
    else if (value !== confirm) er.confirm = 'The two values do not match.';
    if (why.trim().length < 10) er.justification = 'Explain why in at least 10 characters (a ticket number helps the approver).';
    setErrs(er);
    if (Object.keys(er).length) {
      if (er.confirm && confirmRef.current) confirmRef.current.value = '';
      return;
    }
    const op = adding ? 'create' : 'replace';
    const body = { vault_id: vault.id, justification: why.trim(), items: [{ mount, path, key, op, value, base_version: baseVersion } as ChangeItemInput] };
    // Wipe the DOM fields before the request leaves; the only copy is in `body` for this call.
    if (valueRef.current) valueRef.current.value = '';
    if (confirmRef.current) confirmRef.current.value = '';
    const r = await s.submit(body);
    body.items[0].value = undefined;
    if (r) setDone(r);
  };

  const fe = (n: string) => errs[n] ?? fieldError(s.error, n);
  const full = `${mount}${path}`;
  return (
    <Drawer
      open={open}
      onClose={close}
      eyebrow="New change request"
      title={
        adding ? (
          <>
            Add key to <span className="mono">{full}</span>
          </>
        ) : (
          <>
            Replace <span className="mono" style={{ fontSize: 16 }}>{keyName}</span>
          </>
        )
      }
      initialFocus={adding ? keyRef : valueRef}
    >
      <div className="id-box" style={{ marginTop: -6 }}>
        <div className="eyebrow" style={{ marginBottom: 6 }}>
          Changes go to
        </div>
        <VaultIdentity {...vaultIdentityProps(vault)} compact />
        <div className="mono small" style={{ marginTop: 6 }}>
          <span className="muted">path</span> {full}
        </div>
      </div>
      {done ? (
        <Submitted cr={done} vault={vault} onClose={close} />
      ) : (
        <form onSubmit={submit} className="stack-sm" style={{ gap: 18, flex: 1 }} noValidate autoComplete="off">
          <div className="inline-sm">
            <Badge tone="mute">Base version v{baseVersion} · cas</Badge>
            <Badge tone="info">Approval required</Badge>
          </div>
          {adding && (
            <Field label="Key" htmlFor="cr-key" error={fe('key')}>
              <input ref={keyRef} className="in mono" {...aria('cr-key', fe('key'))} value={newKey} onChange={(e) => setNewKey(e.target.value)} spellCheck={false} />
            </Field>
          )}
          <Field label="New value" htmlFor="cr-val" error={fe('value')}>
            <input ref={valueRef} type="password" className="in mono" {...aria('cr-val', fe('value'))} autoComplete="new-password" spellCheck={false} />
          </Field>
          <Field label="Confirm value" htmlFor="cr-val2" error={fe('confirm')}>
            <input ref={confirmRef} type="password" className="in mono" {...aria('cr-val2', fe('confirm'))} autoComplete="new-password" spellCheck={false} />
          </Field>
          <Field label="Justification" htmlFor="cr-why" error={fe('justification')}>
            <textarea className="in" rows={3} {...aria('cr-why', fe('justification'))} value={why} onChange={(e) => setWhy(e.target.value)} placeholder="Why, and a ticket number" />
          </Field>
          <FormError error={s.error && !fieldError(s.error, 'justification') ? s.error : null} />
          <div className="note">
            The value is sealed with a Key Vault key until approved, then applied and deleted. After you submit, only its HMAC fingerprint is shown. The request expires in 72 h. You cannot approve your own request.
          </div>
          <div className="muted small" id="cr-target-confirm">
            Submitting a change to <span className="mono strong">{vaultPath({ cluster: vault.target.cluster_name, namespace: vault.target.namespace, service: vault.target.service })}</span> · <span className="mono">{full}</span>
          </div>
          <div className="drawer-foot" style={{ marginTop: 0 }}>
            <button type="button" className="btn" onClick={close}>
              Cancel
            </button>
            <button type="submit" className="btn pri" disabled={s.pending} aria-describedby="cr-target-confirm">
              {s.pending ? 'Submitting…' : 'Submit for approval'}
            </button>
          </div>
        </form>
      )}
    </Drawer>
  );
}

// ------------------------------------------------------------ delete key / destroy history

export function DeleteDestroyDialog({
  open,
  onClose,
  vault,
  secret,
  keyName,
}: {
  open: boolean;
  onClose: () => void;
  vault: Vault;
  secret: SecretDetail;
  keyName: string | null; // null = destroy history only
}) {
  const [phase, setPhase] = useState<'delete' | 'destroy'>(keyName ? 'delete' : 'destroy');
  const [alsoDestroy, setAlsoDestroy] = useState(false);
  const [why, setWhy] = useState('');
  const [confirm, setConfirm] = useState('');
  const cur = secret.current_version;
  // With a key delete, the delete writes v(cur+1) first, so v(cur) becomes destroyable too.
  const newest = keyName ? cur : cur - 1; // kept for rollback by default
  const [selected, setSelected] = useState<Set<number>>(
    () => new Set(secret.versions.filter((v) => !v.destroyed && v.version < newest).map((v) => v.version)),
  );
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [done, setDone] = useState<ChangeRequest | null>(null);
  const s = useCrSubmit();
  const full = `${secret.mount}${secret.path}`;

  const close = () => {
    setDone(null);
    s.reset();
    onClose();
  };

  const items = (withDestroy: boolean): ChangeItemInput[] => [
    ...(keyName ? [{ mount: secret.mount, path: secret.path, key: keyName, op: 'delete' as const, base_version: cur }] : []),
    ...(withDestroy ? [{ mount: secret.mount, path: secret.path, op: 'destroy_history' as const, base_version: cur, versions: [...selected].sort((a, b) => a - b) }] : []),
  ];

  const submitDelete = async (e: React.FormEvent) => {
    e.preventDefault();
    if (why.trim().length < 10) {
      setErrs({ justification: 'Explain why in at least 10 characters.' });
      return;
    }
    setErrs({});
    if (alsoDestroy) {
      setPhase('destroy');
      return;
    }
    const r = await s.submit({ vault_id: vault.id, justification: why.trim(), items: items(false) });
    if (r) setDone(r);
  };
  const submitDestroy = async (e: React.FormEvent) => {
    e.preventDefault();
    const er: Record<string, string> = {};
    if (selected.size === 0) er.versions = 'Select at least one version to destroy.';
    if (confirm !== full) er.confirm = `Type ${full} exactly.`;
    if (why.trim().length < 10) er.justification = 'Explain why in at least 10 characters.';
    setErrs(er);
    if (Object.keys(er).length) return;
    const r = await s.submit({ vault_id: vault.id, justification: why.trim(), items: items(true) });
    if (r) setDone(r);
  };
  const toggle = (v: number) =>
    setSelected((p) => {
      const n = new Set(p);
      if (n.has(v)) n.delete(v);
      else n.add(v);
      return n;
    });

  if (done) {
    return (
      <Modal open={open} onClose={close} size="narrow" eyebrow="Change request" title="Submitted for approval">
        <div className="note ok" role="status">
          <span className="mono">{crLabel(done)}</span> for <span className="mono">{vaultPath({ cluster: vault.target.cluster_name, namespace: vault.target.namespace, service: vault.target.service })}</span> waits for a second person with <span className="mono">vault-approver</span>. Nothing changes in Vault until it is approved.
        </div>
        <div className="end">
          <Link to="/approvals" search={{ view: 'mine', cr: done.id }} className="btn">
            Open request
          </Link>
          <button type="button" className="btn pri" onClick={close}>
            Done
          </button>
        </div>
      </Modal>
    );
  }

  if (phase === 'delete' && keyName) {
    return (
      <Modal
        open={open}
        onClose={close}
        size="narrow"
        eyebrow="Change request"
        title={
          <>
            Delete key <span className="mono" style={{ fontSize: 16 }}>{keyName}</span>?
          </>
        }
        description={
          <span className="mono small">
            {vaultPath({ cluster: vault.target.cluster_name, namespace: vault.target.namespace, service: vault.target.service })} · {full} · current version v{cur}
          </span>
        }
      >
        <form onSubmit={submitDelete} className="stack-sm" style={{ gap: 18 }} noValidate>
          <div className="note warn">
            This creates <b>v{cur + 1} without the key</b>. The old value <b>still exists in versions {cur > 1 ? `v1–v${cur}` : 'v1'}</b> and can be read by anyone with access to history. To erase it, also request Destroy history.
          </div>
          <label className="opt">
            <input type="checkbox" checked={alsoDestroy} onChange={(e) => setAlsoDestroy(e.target.checked)} />
            <span>
              <span className="t1">Also request Destroy history</span>
              <span className="t2">Adds a second, irreversible item to this request.</span>
            </span>
          </label>
          <Field label="Justification" htmlFor="dd-why" error={errs.justification ?? fieldError(s.error, 'justification')}>
            <textarea className="in" rows={2} {...aria('dd-why', errs.justification)} value={why} onChange={(e) => setWhy(e.target.value)} />
          </Field>
          <FormError error={s.error} />
          <div className="end">
            <button type="button" className="btn" onClick={close}>
              Cancel
            </button>
            <button type="submit" className="btn pri" disabled={s.pending}>
              {alsoDestroy ? 'Next: choose versions' : 'Submit for approval'}
            </button>
          </div>
        </form>
      </Modal>
    );
  }

  return (
    <Modal
      open={open}
      onClose={close}
      danger
      eyebrow="Irreversible"
      eyebrowTone="crit"
      title={
        <>
          Destroy history of <span className="mono" style={{ fontSize: 16 }}>{full}</span>
        </>
      }
      description={<span className="mono small">{vaultPath({ cluster: vault.target.cluster_name, namespace: vault.target.namespace, service: vault.target.service })}</span>}
    >
      <form onSubmit={submitDestroy} className="stack-sm" style={{ gap: 18 }} noValidate>
        <div className="note crit" role="note">
          Destroying a version removes <b>every key</b> stored in it, not only {keyName ? 'the one you delete' : 'one key'}. This cannot be undone, not even by a Vault admin.
        </div>
        <fieldset className="plain" aria-describedby={errs.versions ? 'dd-ver-err' : undefined}>
          <legend className="sr-only">Versions to destroy</legend>
          <div className="boxed tight">
            <table className="t">
              <thead>
                <tr>
                  <th>
                    <span className="sr-only">Destroy</span>
                  </th>
                  <th>Version</th>
                  <th>Created</th>
                  <th>Keys</th>
                </tr>
              </thead>
              <tbody>
                {secret.versions
                  .slice()
                  .sort((a, b) => a.version - b.version)
                  .map((v) => {
                    const isCur = v.version === cur && !keyName;
                    return (
                      <tr key={v.version}>
                        <td>
                          <input
                            type="checkbox"
                            checked={selected.has(v.version)}
                            onChange={() => toggle(v.version)}
                            disabled={isCur || v.destroyed}
                            aria-label={isCur ? `v${v.version} is the current version` : `Destroy v${v.version}`}
                          />
                        </td>
                        <td className="mono">v{v.version}</td>
                        <td className="mono">{shortDate(v.created_time)}</td>
                        <td className="wrap">
                          {v.destroyed ? (
                            <span className="muted">already destroyed</span>
                          ) : isCur ? (
                            <span className="muted">current, cannot be destroyed here</span>
                          ) : (
                            <>
                              {v.keys !== undefined ? `${v.keys} keys` : 'all keys'}
                              {v.version === newest && !selected.has(v.version) && <span className="muted"> · kept for rollback</span>}
                            </>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                {keyName && (
                  <tr>
                    <td>
                      <input type="checkbox" disabled aria-label={`v${cur + 1} will be the current version`} />
                    </td>
                    <td className="mono">v{cur + 1}</td>
                    <td className="mono">after approval</td>
                    <td className="muted">current, without the key</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {errs.versions && (
            <div className="field-error" id="dd-ver-err" role="alert">
              {errs.versions}
            </div>
          )}
        </fieldset>
        {!keyName && (
          <Field label="Justification" htmlFor="ds-why" error={errs.justification}>
            <textarea className="in" rows={2} {...aria('ds-why', errs.justification)} value={why} onChange={(e) => setWhy(e.target.value)} />
          </Field>
        )}
        <div>
          <TypeToConfirm id="ds-confirm" expected={full} value={confirm} onChange={setConfirm} label="Type the path to confirm" />
          {errs.confirm && (
            <div className="field-error" role="alert">
              {errs.confirm}
            </div>
          )}
        </div>
        <FormError error={s.error} />
        <div className="end">
          <button type="button" className="btn" onClick={keyName ? () => setPhase('delete') : close}>
            {keyName ? 'Back' : 'Cancel'}
          </button>
          <button type="submit" className="btn danger" disabled={s.pending || confirm !== full || selected.size === 0}>
            Request destroy · needs approval
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ------------------------------------------------------------ configure

/**
 * Vault configure (SPEC §11.1). The root token lives only in the password input (DOM),
 * never in React state; it is sent for inspect and configure and wiped after configure.
 */
export function VaultConfigureDialog({ open, onClose, vault }: { open: boolean; onClose: () => void; vault: Vault }) {
  const qc = useQueryClient();
  const tokenRef = useRef<HTMLInputElement>(null);
  const [mounts, setMounts] = useState<VaultInspect | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [tokenErr, setTokenErr] = useState<string | undefined>();
  const [done, setDone] = useState<Vault | null>(null);
  const inspect = useAction<VaultInspect>();
  const configure = useAction<Vault>();

  const wipe = () => {
    if (tokenRef.current) tokenRef.current.value = '';
  };
  const close = () => {
    wipe();
    setMounts(null);
    setChosen(new Set());
    setDone(null);
    setTokenErr(undefined);
    inspect.reset();
    configure.reset();
    onClose();
  };

  const doInspect = async () => {
    const token = tokenRef.current?.value ?? '';
    if (!token) {
      setTokenErr('Paste a root token (or one with sys policy and auth admin rights).');
      return;
    }
    setTokenErr(undefined);
    const r = await inspect.run(() => api.post<VaultInspect>(`/vaults/${vault.id}/inspect`, { root_token: token }));
    if (r) {
      setMounts(r);
      setChosen(new Set(r.mounts.filter((m) => m.version === 2).map((m) => m.path)));
    }
  };
  const doConfigure = async () => {
    const token = tokenRef.current?.value ?? '';
    if (!token) {
      setTokenErr('Paste the token again: it was cleared.');
      return;
    }
    wipe(); // used once: gone from the page before the request completes
    const r = await configure.run(() => api.post<Vault>(`/vaults/${vault.id}/configure`, { root_token: token, mounts: [...chosen] }));
    if (r) {
      setDone(r);
      void qc.invalidateQueries({ queryKey: ['vaults'] });
    }
  };

  const tErr = tokenErr ?? fieldError(inspect.error, 'root_token') ?? fieldError(configure.error, 'root_token');
  const provider = vault.provider === 'openbao' ? 'OpenBao' : 'HashiCorp Vault';
  return (
    <Modal
      open={open}
      onClose={close}
      eyebrow="Configure vault"
      title={<span className="mono" style={{ fontSize: 17 }}>{vaultPath({ cluster: vault.target.cluster_name, namespace: vault.target.namespace, service: vault.target.service })}</span>}
      description={
        <>
          {provider} {mounts?.version || vault.version} · raft · {vault.target.tls_ok ? 'TLS verified' : vault.target.tls_ok === false ? 'no TLS' : 'TLS not probed'}
        </>
      }
      initialFocus={tokenRef}
    >
      {done ? (
        <>
          <div className="note ok" role="status">
            <div className="note-title">Configured</div>
            Policy and AppRole <span className="mono">olympos</span> were created and the AppRole login was verified. The root token was discarded; you can revoke it now.
          </div>
          <div className="end">
            <button type="button" className="btn pri" onClick={close}>
              Done
            </button>
          </div>
        </>
      ) : (
        <>
          <Field label="Root token (or a token with sys policy and auth admin rights)" htmlFor="vc-token" error={tErr}>
            <input ref={tokenRef} type="password" className="in mono" {...aria('vc-token', tErr)} autoComplete="off" spellCheck={false} placeholder="hvs.…" />
          </Field>
          <div className="note">
            Root token is used once to set up access and is not stored. It stays in memory on the server for the setup below only; it never reaches the database, logs or Key Vault. You can revoke it right after.
          </div>
          <div className="boxed">
            <b style={{ marginBottom: 4 }}>Olympos will create</b>
            <div className="chk">
              <CheckIcon ok />
              <span>
                Policy <span className="mono">olympos</span>: list paths, read key names, patch values. <b>No read on values.</b>
              </span>
            </div>
            <div className="chk">
              <CheckIcon ok />
              <span>
                AppRole <span className="mono">olympos</span>, token TTL 1 h, secret_id rotated monthly
              </span>
            </div>
            <div className="chk">
              <CheckIcon ok />
              <span>secret_id stored in the server’s Key Vault</span>
            </div>
            <div className="chk">
              <CheckIcon ok />
              <span>Snapshot permission for raft backups</span>
            </div>
          </div>
          <fieldset className="plain">
            <legend className="lbl">KV mounts to manage</legend>
            {!mounts && <p className="muted small" style={{ margin: 0 }}>Paste the token and list the mounts to choose which KV v2 mounts Olympos manages.</p>}
            {mounts?.sealed && <div className="note crit">This vault is sealed. Unseal it, then list the mounts again.</div>}
            {mounts?.mounts.length === 0 && <p className="muted small">No KV mounts found.</p>}
            {mounts?.mounts.map((m) => (
              <label className="chk" key={m.path}>
                <input
                  type="checkbox"
                  checked={m.version === 2 && chosen.has(m.path)}
                  disabled={m.version !== 2}
                  onChange={(e) =>
                    setChosen((p) => {
                      const n = new Set(p);
                      if (e.target.checked) n.add(m.path);
                      else n.delete(m.path);
                      return n;
                    })
                  }
                />
                <span className="mono">{m.path}</span>
                {m.version === 2 ? <Badge tone="ok">KV v2</Badge> : <Badge tone="mute">KV v1 · read-only. Upgrade to KV v2 to manage this mount</Badge>}
              </label>
            ))}
            {fieldError(configure.error, 'mounts') && <div className="field-error">{fieldError(configure.error, 'mounts')}</div>}
          </fieldset>
          <ServerErrorNote error={(inspect.error && !fieldError(inspect.error, 'root_token') ? inspect.error : null) ?? (configure.error && !fieldError(configure.error, 'root_token') && !fieldError(configure.error, 'mounts') ? configure.error : null)} clusterId={vault.target.cluster_id} clusterName={vault.target.cluster_name} />
          <div className="end">
            <button type="button" className="btn" onClick={close}>
              Cancel
            </button>
            {!mounts ? (
              <button type="button" className="btn pri" onClick={() => void doInspect()} disabled={inspect.pending}>
                {inspect.pending ? 'Listing mounts…' : 'List KV mounts'}
              </button>
            ) : (
              <button type="button" className="btn pri" onClick={() => void doConfigure()} disabled={configure.pending || chosen.size === 0 || mounts.sealed}>
                {configure.pending ? 'Configuring…' : 'Configure'}
              </button>
            )}
          </div>
        </>
      )}
    </Modal>
  );
}

/** Mentions of TLS in a server message (handshake, plain HTTP to HTTPS, x509). */
export const mentionsTls = (msg: string) => /\btls\b|https|x509|certificate|plain http/i.test(msg);

/**
 * A server error shown as sent: multi-line text keeps its lines. When it is about TLS,
 * a short hint links to the cluster's transfer mode.
 */
export function ServerErrorNote({ error, clusterId, clusterName }: { error: unknown; clusterId?: string; clusterName?: string }) {
  if (!error) return null;
  const msg = errorMessage(error);
  const text = msg ? msg[0].toUpperCase() + msg.slice(1) : msg;
  const fields = error instanceof ApiError ? Object.keys(error.fields) : [];
  return (
    <div className="note crit" role="alert">
      <pre className="err-text">{text}</pre>
      {fields.length > 0 && <div className="muted small">Check the highlighted fields.</div>}
      {mentionsTls(msg) && (
        <div className="err-hint small">
          Olympos only talks to a vault over TLS, because the root token and secret values would otherwise cross the agent in clear. Enable TLS on the vault listener, or change the transfer mode of{' '}
          {clusterId ? (
            <Link to="/settings/clusters" search={{ cluster: clusterId }}>
              {clusterName ?? 'this cluster'} in Settings › Clusters
            </Link>
          ) : (
            <Link to="/settings/clusters">the cluster in Settings › Clusters</Link>
          )}
          .
        </div>
      )}
    </div>
  );
}
