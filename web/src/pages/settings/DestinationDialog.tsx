import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, api } from '../../api/client';
import type { Destination, DestinationInput, DestinationKind, DestinationMount, DestinationTest, DestinationTestFailed, ItemList, SecretSourceInput } from '../../api/types';
import { date } from '../../lib/format';
import { parseSas, type SasCheck } from '../../lib/sas';
import { KIND_LABEL, TestReport } from '../../ui/destinations';
import { CheckIcon } from '../../ui/icons';
import { Badge, Field, FormError, Modal, aria, fieldError, useAction, useToast } from '../../ui/kit';
import { Select } from '../../ui/Select';

type Source = 'keyvault_ref' | 'stored';

const KINDS: { id: DestinationKind; label: string; hint: string }[] = [
  { id: 'azure_blob', label: 'Azure Blob', hint: 'Storage account container · Azurite' },
  { id: 's3', label: 'S3 / S3-compatible', hint: 'AWS, MinIO, Ceph RGW, Wasabi…' },
  { id: 'nfs', label: 'NFS', hint: 'A share mounted into the server' },
];

function isTestFailed(b: unknown): b is DestinationTestFailed & { test: DestinationTest } {
  return !!b && typeof b === 'object' && 'test' in b && !!(b as DestinationTestFailed).test;
}

const trimSlashes = (s: string) => s.trim().replace(/^\/+|\/+$/g, '');

export function joinMountPath(mount: string, sub: string): string {
  const base = mount.replace(/\/+$/, '');
  const rest = trimSlashes(sub);
  return rest ? `${base}/${rest}` : base;
}

function splitMountPath(path: string, mounts: DestinationMount[]): { mount: string; sub: string } | null {
  const sorted = [...mounts].sort((a, b) => b.path.length - a.path.length);
  for (const m of sorted) {
    const base = m.path.replace(/\/+$/, '');
    if (path === base) return { mount: m.name, sub: '' };
    if (path.startsWith(base + '/')) return { mount: m.name, sub: path.slice(base.length + 1) };
  }
  return null;
}

/** Strings compare as trimmed text; empty and absent are the same. */
const same = (a: unknown, b: unknown) => (typeof a === 'boolean' || typeof b === 'boolean' ? !!a === !!b : String(a ?? '').trim() === String(b ?? '').trim());

/**
 * Add or edit a backup destination (SPEC §10.3, extended to S3 and NFS). Secrets (SAS
 * token, S3 secret key) live only in uncontrolled password inputs; they are read when a
 * request is built and the inputs are cleared after Save, so no secret stays in React
 * state or a query/mutation cache.
 */
export function DestinationDialog({ dest, onClose }: { dest?: Destination; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const editing = !!dest;
  const [kind, setKind] = useState<DestinationKind>(dest?.kind ?? 'azure_blob');
  const [name, setName] = useState(dest?.name ?? '');
  const [prefix, setPrefix] = useState(dest?.prefix ?? 'olympos/');
  const [endpoint, setEndpoint] = useState(dest?.endpoint_override ?? '');
  // azure_blob
  const [account, setAccount] = useState(dest?.account ?? '');
  const [container, setContainer] = useState(dest?.container ?? '');
  const [auth, setAuth] = useState<'managed_identity' | 'sas_token'>(dest?.auth === 'sas_token' ? 'sas_token' : 'managed_identity');
  const [sasSource, setSasSource] = useState<Source>(dest?.sas_source === 'stored' ? 'stored' : 'keyvault_ref');
  const [sasRef, setSasRef] = useState(dest?.sas_ref ?? '');
  const [sasParsed, setSasParsed] = useState<SasCheck | null>(null);
  const sasInput = useRef<HTMLInputElement>(null);
  // s3
  const [region, setRegion] = useState(dest?.region ?? '');
  const [bucket, setBucket] = useState(dest?.bucket ?? '');
  const [pathStyle, setPathStyle] = useState(dest?.path_style ?? false);
  const [pathStyleTouched, setPathStyleTouched] = useState(editing);
  const [accessKeyId, setAccessKeyId] = useState(dest?.access_key_id ?? '');
  const [secretSource, setSecretSource] = useState<Source>(dest?.secret_key_source === 'stored' ? 'stored' : 'keyvault_ref');
  const [secretRef, setSecretRef] = useState(dest?.secret_key_ref ?? '');

  const secretInput = useRef<HTMLInputElement>(null);
  // nfs
  const [mountName, setMountName] = useState('');
  const [subPath, setSubPath] = useState(dest?.kind === 'nfs' ? '' : 'olympos');
  const [localErr, setLocalErr] = useState<Record<string, string>>({});

  const [report, setReport] = useState<DestinationTest | null>(dest?.last_test ?? null);
  const [reportAt, setReportAt] = useState<string | null>(dest?.last_test_at ?? null);
  const [reportNote, setReportNote] = useState<string | undefined>();
  const [saved, setSaved] = useState<Destination | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const test = useAction<DestinationTest>();
  const save = useAction<Destination>();
  const del = useAction<boolean>();

  const mountsQ = useQuery({ queryKey: ['destination-mounts'], queryFn: () => api.get<ItemList<DestinationMount>>('/destinations/mounts'), enabled: kind === 'nfs' });
  const mounts = mountsQ.data?.items ?? [];
  const mount = mounts.find((m) => m.name === mountName);

  // Editing an NFS destination: split its path into mount + sub-path once mounts load.
  useEffect(() => {
    if (!mountsQ.data || mountName) return;
    if (dest?.kind === 'nfs' && dest.path) {
      const sp = splitMountPath(dest.path, mountsQ.data.items);
      if (sp) {
        setMountName(sp.mount);
        setSubPath(sp.sub);
      }
    } else if (!dest) {
      const first = mountsQ.data.items.find((m) => m.writable);
      if (first) setMountName(first.name);
    }
  }, [mountsQ.data, dest, mountName]);

  // Most S3-compatible services need path-style addressing; AWS does not.
  useEffect(() => {
    if (!pathStyleTouched) setPathStyle(endpoint.trim() !== '');
  }, [endpoint, pathStyleTouched]);

  const nfsPath = mount ? joinMountPath(mount.path, subPath) : '';

  const secretValue = (r: React.RefObject<HTMLInputElement | null>) => r.current?.value ?? '';
  const sasBody = (): SecretSourceInput => {
    if (sasSource === 'keyvault_ref') return { source: 'keyvault_ref', ref: sasRef.trim() };
    const v = secretValue(sasInput);
    return v ? { source: 'stored', value: v } : { source: 'stored' };
  };
  const secretKeyBody = (): SecretSourceInput => {
    if (secretSource === 'keyvault_ref') return { source: 'keyvault_ref', ref: secretRef.trim() };
    const v = secretValue(secretInput);
    return v ? { source: 'stored', value: v } : { source: 'stored' };
  };

  /** Full input for the chosen kind (create, or testing unsaved settings). */
  const fullBody = (): DestinationInput => {
    const common = { name: name.trim(), kind, prefix: prefix.trim() };
    if (kind === 's3') {
      return { ...common, endpoint_override: endpoint.trim(), region: region.trim(), bucket: bucket.trim(), path_style: pathStyle, auth: 'access_key', access_key_id: accessKeyId.trim(), secret_key: secretKeyBody() };
    }
    if (kind === 'nfs') return { ...common, auth: 'none', path: nfsPath };
    return { ...common, account: account.trim(), container: container.trim(), endpoint_override: endpoint.trim(), auth, ...(auth === 'sas_token' ? { sas: sasBody() } : {}) };
  };

  /** PATCH body: only what changed; secrets only when replaced (absent = keep). */
  const patchBody = (d: Destination): DestinationInput => {
    const full = fullBody();
    const out: DestinationInput = {};
    const cmp: (keyof DestinationInput)[] = ['name', 'prefix', 'endpoint_override', 'account', 'container', 'auth', 'bucket', 'region', 'path_style', 'access_key_id', 'path'];
    for (const k of cmp) {
      if (!(k in full)) continue;
      if (!same(full[k], d[k as keyof Destination])) (out as Record<string, unknown>)[k] = full[k];
    }
    if (kind === 'azure_blob' && auth === 'sas_token') {
      const changed = d.auth !== 'sas_token' || d.sas_source !== sasSource || (sasSource === 'keyvault_ref' ? !same(sasRef, d.sas_ref) : !!secretValue(sasInput));
      if (changed) out.sas = full.sas;
    }
    if (kind === 's3') {
      const changed = d.secret_key_source !== secretSource || (secretSource === 'keyvault_ref' ? !same(secretRef, d.secret_key_ref) : !!secretValue(secretInput));
      if (changed) out.secret_key = full.secret_key;
    }
    return out;
  };

  const clearSecrets = () => {
    if (sasInput.current) sasInput.current.value = '';
    if (secretInput.current) secretInput.current.value = '';
    setSasParsed(null);
  };

  const validate = (): boolean => {
    const e: Record<string, string> = {};
    if (kind === 'nfs') {
      if (!mount) e.path = mounts.length ? 'Pick a mount.' : 'No NFS mount is available on the server.';
      else if (trimSlashes(subPath).split('/').some((p) => p === '..')) e.path = 'The path must stay below the mount (no "..").';
    }
    setLocalErr(e);
    return Object.keys(e).length === 0;
  };

  const runTest = async () => {
    if (!validate()) return;
    const patch = dest ? patchBody(dest) : null;
    const secretChanged = !!patch && ('sas' in patch || 'secret_key' in patch);
    const useSaved = !!dest && !secretChanged;
    const r = await test.run(() => (useSaved ? api.post<DestinationTest>(`/destinations/${dest!.id}/test`) : api.post<DestinationTest>('/destinations/test', fullBody())));
    if (r) {
      setReport(r);
      setReportAt(new Date().toISOString());
      setReportNote(useSaved && patch && Object.keys(patch).length > 0 ? 'Tested the saved settings (the stored secret is never sent back). Save tests your changes.' : undefined);
    }
  };

  const doSave = async () => {
    if (!validate()) return;
    const body = dest ? patchBody(dest) : fullBody();
    clearSecrets(); // the secret now lives only in `body` until the request finishes
    const r = await save.run(async () => {
      try {
        return dest ? await api.patch<Destination>(`/destinations/${dest.id}`, body) : await api.post<Destination>('/destinations', body);
      } catch (e) {
        if (e instanceof ApiError && e.status === 422 && isTestFailed(e.body)) {
          setReport(e.body.test);
          setReportAt(new Date().toISOString());
          setReportNote(undefined);
        }
        throw e;
      }
    });
    if (!r) return;
    void qc.invalidateQueries({ queryKey: ['destinations'] });
    if (r.last_test) {
      setReport(r.last_test);
      setReportAt(r.last_test_at ?? new Date().toISOString());
    }
    if (r.warnings && r.warnings.length > 0) {
      setSaved(r);
      return;
    }
    toast(`Saved ${r.name}. The destination test passed.`);
    onClose();
  };

  const doDelete = async () => {
    if (!dest) return;
    const ok = await del.run(async () => {
      await api.del(`/destinations/${dest.id}`);
      return true;
    });
    if (ok) {
      void qc.invalidateQueries({ queryKey: ['destinations'] });
      toast(`Deleted ${dest.name}.`);
      onClose();
    }
  };

  const fe = (n: string) => localErr[n] ?? fieldError(save.error, n) ?? fieldError(test.error, n);

  const title = editing ? `Edit ${dest!.name}` : 'New destination';

  // ------------------------------------------------------------ saved with warnings
  if (saved) {
    return (
      <Modal open onClose={onClose} size="xl" eyebrow={`Destinations · ${KIND_LABEL[saved.kind]}`} title={`Saved ${saved.name} with warnings`} description="The destination test passed and the destination is saved. Read these before backups use it.">
        <div className="note warn" role="alert">
          <ul className="plain-list stack-sm" style={{ gap: 6 }}>
            {saved.warnings!.map((w) => (
              <li key={w} className="chk" style={{ padding: 0, alignItems: 'flex-start' }}>
                <CheckIcon ok={false} warn />
                <span>{w}</span>
              </li>
            ))}
          </ul>
        </div>
        {report && <TestReport report={report} kind={saved.kind} at={reportAt} />}
        <div className="end">
          <button type="button" className="btn pri" onClick={onClose} data-autofocus>
            Done
          </button>
        </div>
      </Modal>
    );
  }

  const sas = sasParsed;
  const sasStoredHint =
    dest?.kind === 'azure_blob' && dest.auth === 'sas_token' && dest.sas_source === 'stored'
      ? `A token is stored (permissions ${dest.sas_permissions || '?'}, expires ${date(dest.sas_expires_at)}). Paste a new one to replace it; leave empty to keep it.`
      : 'Paste a container-scoped SAS token. It is envelope-encrypted and never shown again.';
  const secretStoredHint =
    dest?.kind === 's3' && dest.secret_key_source === 'stored' ? 'A secret key is stored. Paste a new one to replace it; leave empty to keep it.' : 'Envelope-encrypted in Olympos and never shown again.';

  return (
    <Modal open onClose={onClose} size="xl" eyebrow={editing ? `Destinations · ${KIND_LABEL[dest!.kind]}` : 'Destinations'} title={title} description="The Olympos server is the only writer to backup storage. Save runs the destination test first.">
      <form
        className="stack"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          void doSave();
        }}
      >
        {!editing ? (
          <fieldset className="kinds">
            <legend className="lbl">Kind</legend>
            {KINDS.map((k) => (
              <label className="kind" key={k.id}>
                <input type="radio" name="dst-kind" value={k.id} checked={kind === k.id}
                  onChange={() => {
                    setKind(k.id);
                    setReport(null); // a report belongs to the kind it tested
                    setReportNote(undefined);
                    test.reset();
                    save.reset();
                  }} data-autofocus={kind === k.id ? '' : undefined} />
                <span className="t1">{k.label}</span>
                <span className="t2">{k.hint}</span>
              </label>
            ))}
          </fieldset>
        ) : (
          <p className="muted small" style={{ margin: 0 }}>
            Kind <b>{KIND_LABEL[dest!.kind]}</b> · the kind of a destination cannot change; create a new destination instead.
          </p>
        )}

        <div className="grid-2">
          <Field label="Name" htmlFor="d-name" error={fe('name')}>
            <input className="in mono" {...aria('d-name', fe('name'))} value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === 's3' ? 'minio-backups' : kind === 'nfs' ? 'nas-backups' : 'blob-weu-backups'} spellCheck={false} autoComplete="off" />
          </Field>
          <Field label="Prefix" htmlFor="d-pre" error={fe('prefix')} hint="Folder for every backup path; may be empty.">
            <input className="in mono" {...aria('d-pre', fe('prefix'), true)} value={prefix} onChange={(e) => setPrefix(e.target.value)} spellCheck={false} autoComplete="off" />
          </Field>
        </div>

        {/* ------------------------------------------------ Azure Blob */}
        {kind === 'azure_blob' && (
          <>
            <div className="grid-2">
              <Field label="Storage account" htmlFor="d-acc" error={fe('account')}>
                <input className="in mono" {...aria('d-acc', fe('account'))} value={account} onChange={(e) => setAccount(e.target.value)} placeholder="stolympweu01" spellCheck={false} autoComplete="off" />
              </Field>
              <Field label="Container" htmlFor="d-con" error={fe('container')}>
                <input className="in mono" {...aria('d-con', fe('container'))} value={container} onChange={(e) => setContainer(e.target.value)} placeholder="backups" spellCheck={false} autoComplete="off" />
              </Field>
            </div>
            <Field
              label="Endpoint override (optional)"
              htmlFor="d-ep"
              error={fe('endpoint_override')}
              hint={
                <>
                  Empty = <span className="mono">https://{account || '<account>'}.blob.core.windows.net</span>. For Azurite, sovereign clouds or private DNS, e.g. <span className="mono">http://azurite.olympos.svc:10000/devstoreaccount1</span>.
                </>
              }
            >
              <input className="in mono" {...aria('d-ep', fe('endpoint_override'), true)} value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="https://stolympweu01.blob.core.windows.net" spellCheck={false} autoComplete="off" inputMode="url" />
            </Field>
            <fieldset className="opts">
              <legend className="lbl">Authentication</legend>
              <label className="opt">
                <input type="radio" name="dst-auth" checked={auth === 'managed_identity'} onChange={() => setAuth('managed_identity')} />
                <span>
                  <span className="t1">Managed Identity</span> <Badge tone="ok">Recommended</Badge>
                  <span className="t2">The server's identity with a custom role (read, write, tag; no delete). Lets you disable shared key on the account.</span>
                </span>
              </label>
              <label className="opt">
                <input type="radio" name="dst-auth" checked={auth === 'sas_token'} onChange={() => setAuth('sas_token')} />
                <span>
                  <span className="t1">SAS token</span>
                  <span className="t2">Container-scoped SAS you create. Used only by the server, never sent to clusters.</span>
                </span>
              </label>
            </fieldset>
            {auth === 'sas_token' && (
              <div className="form-cols">
                <div className="stack-sm" style={{ gap: 14 }}>
                  <SourcePicker name="sas-src" value={sasSource} onChange={setSasSource} what="SAS token" />
                  {sasSource === 'keyvault_ref' ? (
                    <Field label="Key Vault reference" htmlFor="d-ref" error={fe('ref') ?? fe('sas')} hint="kv://<vault>/<secret>; the secret holds the SAS token. Permissions and expiry are checked by the test.">
                      <input className="in mono" {...aria('d-ref', fe('ref') ?? fe('sas'), true)} value={sasRef} onChange={(e) => setSasRef(e.target.value)} placeholder="kv://kv-platform-weu/backup-sas" spellCheck={false} autoComplete="off" />
                    </Field>
                  ) : (
                    <Field label="SAS token" htmlFor="d-sas" error={fe('sas') ?? fe('value')} hint={sasStoredHint}>
                      <input
                        ref={sasInput}
                        type="password"
                        className="in mono"
                        {...aria('d-sas', fe('sas') ?? fe('value'), true)}
                        onChange={(e) => setSasParsed(e.target.value ? parseSas(e.target.value) : null)}
                        autoComplete="off"
                        spellCheck={false}
                      />
                    </Field>
                  )}
                </div>
                {sas ? <SasParse sas={sas} container={container} /> : <div className="note">Required permissions: <span className="mono">r c w t</span> (read, create, write, tag). <span className="mono">d</span> (delete) and <span className="mono">l</span> (list) are flagged.</div>}
              </div>
            )}
            {auth === 'sas_token' ? (
              <div className="note warn">SAS tokens of this type need shared key access enabled on the storage account. With Managed Identity you can turn shared key off. Retention is enforced by the account's lifecycle rules, not by Olympos.</div>
            ) : (
              <div className="note">Give the server's managed identity a custom data-plane role on the container with read, write, add and tag permissions, and no delete. Retention is enforced by the account's lifecycle rules, not by Olympos.</div>
            )}
          </>
        )}

        {/* ------------------------------------------------ S3 */}
        {kind === 's3' && (
          <>
            <div className="grid-2">
              <Field
                label="Endpoint override"
                htmlFor="d-s3ep"
                error={fe('endpoint_override')}
                hint={<>Empty = AWS S3. Any S3-compatible service: MinIO, Ceph RGW, Wasabi, StorageGRID, e.g. <span className="mono">https://minio.storage.svc:9000</span>.</>}
              >
                <input className="in mono" {...aria('d-s3ep', fe('endpoint_override'), true)} value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="AWS S3" spellCheck={false} autoComplete="off" inputMode="url" />
              </Field>
              <Field label="Region" htmlFor="d-reg" error={fe('region')} hint="Empty = us-east-1. Most S3-compatible services accept any value.">
                <input className="in mono" {...aria('d-reg', fe('region'), true)} value={region} onChange={(e) => setRegion(e.target.value)} placeholder="eu-central-1" spellCheck={false} autoComplete="off" />
              </Field>
              <Field label="Bucket" htmlFor="d-bkt" error={fe('bucket')}>
                <input className="in mono" {...aria('d-bkt', fe('bucket'))} value={bucket} onChange={(e) => setBucket(e.target.value)} placeholder="olympos-backups" spellCheck={false} autoComplete="off" />
              </Field>
              <label className="opt" style={{ alignSelf: 'end' }}>
                <input
                  type="checkbox"
                  checked={pathStyle}
                  onChange={(e) => {
                    setPathStyleTouched(true);
                    setPathStyle(e.target.checked);
                  }}
                  aria-describedby="d-ps-hint"
                />
                <span>
                  <span className="t1">Path-style addressing</span>
                  <span className="t2" id="d-ps-hint">
                    Requests go to <span className="mono">endpoint/bucket/key</span> instead of <span className="mono">bucket.endpoint/key</span>. Most S3-compatible services (MinIO, Ceph) need it; AWS does not.
                  </span>
                </span>
              </label>
            </div>
            <div className="form-cols">
              <Field label="Access key ID" htmlFor="d-akid" error={fe('access_key_id')} hint="Not secret; shown in the destination list.">
                <input className="in mono" {...aria('d-akid', fe('access_key_id'), true)} value={accessKeyId} onChange={(e) => setAccessKeyId(e.target.value)} placeholder="AKIA… or a MinIO access key" spellCheck={false} autoComplete="off" />
              </Field>
              <div className="stack-sm" style={{ gap: 14 }}>
                <SourcePicker name="s3-src" value={secretSource} onChange={setSecretSource} what="secret key" />
                {secretSource === 'keyvault_ref' ? (
                  <Field label="Key Vault reference" htmlFor="d-skref" error={fe('ref') ?? fe('secret_key')} hint="kv://<vault>/<secret>; the secret holds the S3 secret key.">
                    <input className="in mono" {...aria('d-skref', fe('ref') ?? fe('secret_key'), true)} value={secretRef} onChange={(e) => setSecretRef(e.target.value)} placeholder="kv://kv-platform-weu/minio-secret-key" spellCheck={false} autoComplete="off" />
                  </Field>
                ) : (
                  <Field label="Secret key" htmlFor="d-sk" error={fe('secret_key') ?? fe('value')} hint={secretStoredHint}>
                    <input ref={secretInput} type="password" className="in mono" {...aria('d-sk', fe('secret_key') ?? fe('value'), true)} autoComplete="new-password" spellCheck={false} />
                  </Field>
                )}
              </div>
            </div>
            <div className="note">
              Give the key <span className="mono">s3:PutObject</span>, <span className="mono">s3:GetObject</span> and <span className="mono">s3:PutObjectTagging</span> on the bucket, and no <span className="mono">s3:DeleteObject</span>. Retention is enforced by bucket lifecycle rules (or Object Lock), not by Olympos.

            </div>
          </>
        )}

        {/* ------------------------------------------------ NFS */}
        {kind === 'nfs' && (
          <>
            {mountsQ.isPending ? (
              <p className="muted small" role="status">
                Loading server mounts…
              </p>
            ) : mountsQ.isError ? (
              <FormError error={mountsQ.error} />
            ) : mounts.length === 0 ? (
              <div className="note warn" role="status">
                <b>No NFS mounts on the server yet.</b> Mount the share into the Olympos server with the Helm value <span className="mono">nfsMounts</span> (a name, the NFS server and export path), then upgrade the release. Each mount shows up here as a choice.
              </div>
            ) : (
              <div className="grid-2">
                <Field label="Mount" htmlFor="d-mount" error={fe('path')} hint="Volumes mounted into the server (Helm nfsMounts).">
                  <Select
                    {...aria('d-mount', fe('path'), true)}
                    mono
                    value={mountName}
                    onChange={setMountName}
                    placeholder="Pick a mount"
                    options={mounts.map((m) => ({ value: m.name, label: m.name, hint: <span className="mono">{m.path}{m.writable ? '' : ' · read-only'}</span>, disabled: !m.writable, text: m.name }))}
                  />
                </Field>
                <Field label="Path below the mount" htmlFor="d-sub" hint={nfsPath ? <>Backups go to <span className="mono">{joinMountPath(nfsPath, prefix)}</span></> : undefined}>
                  <input className="in mono" {...aria('d-sub', undefined, !!nfsPath)} value={subPath} onChange={(e) => setSubPath(e.target.value)} placeholder="olympos" spellCheck={false} autoComplete="off" />
                </Field>
              </div>
            )}
            <div className="note warn">
              <b>Olympos can delete files on this mount.</b> Unlike Blob and S3, a file share has no permission that allows write but not delete, so the test reports a warning. Enforce retention and WORM on the storage (snapshots, immutable or SnapLock volumes).
            </div>
          </>
        )}

        {report && <TestReport report={report} kind={kind} at={reportAt} note={reportNote} />}
        {report?.can_delete && kind !== 'nfs' && (
          <div className="note crit" role="alert">
            <b>This credential can delete backups.</b> Olympos must not be able to delete backups (retention is done by lifecycle rules). Remove the delete permission ({kind === 's3' ? <>no <span className="mono">s3:DeleteObject</span></> : <>SAS without <span className="mono">d</span>, or a custom role without <span className="mono">blobs/delete</span></>}). Saving is possible, but the destination stays flagged.
          </div>
        )}
        {test.pending && (
          <p className="muted small" role="status" style={{ margin: 0 }}>
            Testing: {kind === 'nfs' ? 'checking the path, writing a probe file, reading it back and trying to delete it' : 'reaching the endpoint, writing a probe, reading it back, tagging it and trying to delete it'}…
          </p>
        )}
        <FormError error={save.error ?? test.error ?? del.error} />

        {confirmDelete && dest && (
          <div className="note crit" role="alertdialog" aria-labelledby="dst-del-t">
            <b id="dst-del-t">Delete {dest.name}?</b> Only the destination definition is removed; backups already stored there are not touched.
            {dest.jobs > 0 && <> {dest.jobs} backup jobs use it — move them to another destination first; the server refuses otherwise.</>}
            <div className="end" style={{ marginTop: 10 }}>
              <button type="button" className="btn sm" onClick={() => setConfirmDelete(false)}>
                Keep it
              </button>
              <button type="button" className="btn sm danger" onClick={() => void doDelete()} disabled={del.pending || dest.jobs > 0}>
                Delete destination
              </button>
            </div>
          </div>
        )}

        <div className="foot-actions">
          <div className="inline">
            {dest && !confirmDelete && (
              <button type="button" className="btn danger" onClick={() => setConfirmDelete(true)}>
                Delete
              </button>
            )}
            <button type="button" className="btn" onClick={onClose}>
              Cancel
            </button>
          </div>
          <div className="inline">
            <button type="button" className="btn" onClick={() => void runTest()} disabled={test.pending || save.pending}>
              {test.pending ? 'Testing…' : 'Test destination'}
            </button>
            <button type="submit" className="btn pri" disabled={save.pending || test.pending}>
              {save.pending ? 'Testing and saving…' : 'Save'}
            </button>
          </div>
        </div>
      </form>
    </Modal>
  );
}

function SourcePicker({ name, value, onChange, what }: { name: string; value: Source; onChange: (s: Source) => void; what: string }) {
  return (
    <fieldset className="plain">
      <legend className="lbl">Where the {what} comes from</legend>
      <div className="inline">
        <label className="chk">
          <input type="radio" name={name} checked={value === 'keyvault_ref'} onChange={() => onChange('keyvault_ref')} /> Key Vault reference <Badge tone="ok">Recommended</Badge>
        </label>
        <label className="chk">
          <input type="radio" name={name} checked={value === 'stored'} onChange={() => onChange('stored')} /> Store in Olympos
        </label>
      </div>
    </fieldset>
  );
}

function SasParse({ sas, container }: { sas: SasCheck; container: string }) {
  return (
    <div className="note report" aria-live="polite">
      <b className="note-title">Parsed from the token</b>
      <div className="chk">
        <CheckIcon ok={sas.scope === 'container'} warn={sas.scope !== 'container'} />
        <span>Scope: {sas.scope === 'container' ? <>container {container && <span className="mono">{container}</span>}</> : sas.scope === 'account' ? 'account SAS (needs shared key on the account)' : sas.scope}</span>
      </div>
      <div className="chk">
        <CheckIcon ok={sas.missing.length === 0} />
        <span>
          Permissions <span className="mono">{sas.permissions.join(' ') || 'none'}</span>
          {sas.missing.length > 0 && (
            <>
              {' '}
              · missing <span className="mono">{sas.missing.join(' ')}</span> (r c w t are required)
            </>
          )}
        </span>
      </div>
      <div className="chk">
        <CheckIcon ok={!sas.extra.includes('d')} />
        <span>
          {sas.extra.includes('d') ? (
            <>
              Has delete (<span className="mono">d</span>): Olympos must not be able to delete backups
            </>
          ) : (
            <>
              No delete (<span className="mono">d</span>) permission
            </>
          )}
        </span>
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
  );
}
