// Restore a run's copy into a new, discovered target (docs/design/ui-restore.md).
// The open-time checks run inline (POST /restores/check) before the request can be
// submitted; a second person approves it, or an admin starts it at once as
// break-glass. The target's password and the Vault token live only in their
// password inputs (DOM), never in React state or a query cache: they are read when
// a request leaves and wiped when the dialog closes or the request is opened.
import { useRef, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type {
  BackupJob,
  BackupRunDetail,
  CredentialInput,
  DestinationKind,
  ItemList,
  RestoreCheck,
  RestoreInput,
  RestoreNativeObject,
  RestoreRequest,
  RestoreTargetReport,
  Target,
  Vault,
} from '../api/types';
import { useMaybeMe } from '../auth/me';
import { can } from '../auth/permissions';
import { dateTime, engineLabel, relDateTime } from '../lib/format';
import { CheckIcon } from './icons';
import { Badge, Field, FormError, Modal, aria, fieldError, useAction } from './kit';
import { KindBadge } from './destinations';
import { Select } from './Select';
import { ClickHouseScopeNote, NativeScopeNote, VaultTokenNeeds, VaultUnsealNote, restoreEngineName } from './restore';

/** Justification bounds (the server's approvals.ValidateJustification). */
const MIN_WHY = 10;
const MAX_WHY = 2000;

type Engine = 'postgresql' | 'clickhouse' | 'vault';

interface CopyRow {
  destination_id: string;
  name: string;
  kind: DestinationKind;
  /** The succeeded copy for this destination: the run's own, or a later repair's. */
  takenAt?: string | null;
  repair: boolean;
  enabled: boolean;
}

/** The run's destinations: a failed copy is listed but cannot be chosen; a repair's copy can. */
function copyRows(run: BackupRunDetail): CopyRow[] {
  const guide = run.restore?.copies ?? [];
  const src = (d: string) => guide.find((c) => c.destination_id === d && c.run_id === run.id) ?? guide.find((c) => c.destination_id === d);
  const rows = run.copies?.length
    ? run.copies.map((c) => ({ destination_id: c.destination_id, name: c.destination_name, kind: c.destination_kind }))
    : guide.map((c) => ({ destination_id: c.destination_id, name: c.name, kind: c.kind }));
  const seen = new Set<string>();
  return rows
    .filter((r) => !seen.has(r.destination_id) && seen.add(r.destination_id))
    .map((r) => {
      const s = src(r.destination_id);
      return { ...r, takenAt: s?.taken_at, repair: !!s && s.run_id !== run.id, enabled: !!s };
    });
}

const sentenceCase = (m: string) => (m ? m[0].toUpperCase() + m.slice(1) : m);

/**
 * A server message for people: without a leading machine code ("agent_offline: …") and
 * without a final period, in sentence case.
 */
export const readable = (m: string) => sentenceCase(m.replace(/^[a-z][a-z0-9_]*:\s+/, '').replace(/\.$/, ''));

const KV_RE = /^[a-zA-Z0-9-]{3,24}$/;
const SECRET_RE = /^[a-zA-Z0-9-]{1,127}$/;

/** What the checks found about each database on the target: data, empty, or new (absent). */
type Known = Record<string, 'data' | 'empty' | 'new'>;

/** Where a database stands on the target. A database no check looked at has no badge. */
function DbState({ state }: { state: Known[string] | undefined }) {
  if (!state) return null;
  if (state === 'new') return <Badge tone="ok">New</Badge>;
  return state === 'data' ? (
    <>
      <Badge tone="crit">Exists with data</Badge> <span className="muted small">deselect it: nothing on the target is overwritten</span>
    </>
  ) : (
    <>
      <Badge tone="mute">Exists, empty</Badge> <span className="muted small">restored into, without CREATE DATABASE</span>
    </>
  );
}

/** Merges a check's findings (the databases it inspected) into what is known for the target. */
function learn(prev: Known, checkedDbs: string[] | null, r: RestoreTargetReport | null): Known {
  if (!r || !checkedDbs) return prev;
  const next = { ...prev };
  for (const d of checkedDbs) next[d] = d in r.existing ? (r.existing[d] ? 'data' : 'empty') : 'new';
  return next;
}

const KIND_NAME: Record<string, string> = { table: 'table', view: 'view', materialized_view: 'materialized view', dictionary: 'dictionary', other: 'other' };

/** "4 of 6 objects restored" */
const restoredOf = (objs: RestoreNativeObject[]) => `${objs.filter((o) => o.allowed).length} of ${objs.length} ${objs.length === 1 ? 'object' : 'objects'} restored`;

/**
 * The objects of one database of a native backup and what the restore does with each (docs/design/restore-native.html).
 * The maker selects databases; a left out object shows its reason and has no control of its own.
 */
function NativeObjects({ db, objects }: { db: string; objects: RestoreNativeObject[] }) {
  return (
    <ul className="plain-list native-objs" aria-label={`Objects of ${db}`}>
      {objects.map((o) => (
        <li key={o.name} className={o.allowed ? undefined : 'out'} aria-disabled={o.allowed ? undefined : true}>
          <span className="what">
            <span className="mono">{o.name}</span> <span className="muted small">{KIND_NAME[o.kind] ?? o.kind}</span>
          </span>
          {o.allowed ? <Badge tone="ok">Restored</Badge> : <Badge tone="mute">Left out</Badge>}
          {!o.allowed && o.reason && <span className="why">{sentenceCase(o.reason)}</span>}
        </li>
      ))}
    </ul>
  );
}

/** A native check's objects by database, in the order the server listed them. */
function byDatabase(objects: RestoreNativeObject[]): [string, RestoreNativeObject[]][] {
  const m = new Map<string, RestoreNativeObject[]>();
  for (const o of objects) m.set(o.database, [...(m.get(o.database) ?? []), o]);
  return [...m];
}

/** The Vault checks in the order the server applies them; after the first failure the rest were not reached. */
function VaultChecks({ r }: { r: RestoreTargetReport }) {
  const rows: { label: React.ReactNode; ok: boolean }[] = [
    { label: 'Initialized', ok: r.initialized },
    { label: 'Unsealed', ok: !r.sealed },
    { label: 'Active node (not an HA standby)', ok: !r.standby },
    {
      label: r.capabilities_denied ? (
        <>
          Token capabilities could not be read (<span className="mono">sys/capabilities-self</span> refused the token)
        </>
      ) : (
        <>
          Token holds update and sudo on <span className="mono">sys/storage/raft/snapshot-force</span>
        </>
      ),
      ok: !r.capabilities_denied && r.can_snapshot_force,
    },
  ];
  const firstFail = rows.findIndex((x) => !x.ok);
  return (
    <ul className="plain-list stack-sm" aria-label="Vault checks">
      {rows.map((x, i) => {
        const reached = firstFail < 0 || i <= firstFail;
        return (
          <li className="chk" key={i}>
            <CheckIcon ok={reached ? x.ok : null} label={reached ? (x.ok ? 'Passed' : 'Failed') : 'Not checked'} />
            <span>{x.label}</span>
          </li>
        );
      })}
    </ul>
  );
}

export function RestoreDialog({ run, onClose }: { run: BackupRunDetail; onClose: () => void }) {
  const me = useMaybeMe();
  const qc = useQueryClient();
  const engine = run.engine as Engine;
  const isVault = engine === 'vault';
  // A native ClickHouse backup: the check lists every object and what the restore does with it.
  const native = run.method === 'native';
  const mayBreakGlass = can(me, 'admin') && !me?.is_guest;

  const copies = copyRows(run);
  const [copy, setCopy] = useState(() => run.restore?.copies?.find((c) => c.selected)?.destination_id ?? copies.find((c) => c.enabled)?.destination_id ?? '');
  const [targetId, setTargetId] = useState('');
  const [source, setSource] = useState<'keyvault_ref' | 'stored'>('keyvault_ref');
  const [username, setUsername] = useState('');
  const [kvName, setKvName] = useState('');
  const [secretName, setSecretName] = useState('');
  const [ca, setCa] = useState('');
  const [globals, setGlobals] = useState(true);
  /** null: all the databases in the backup (until the check lists them). */
  const [databases, setDatabases] = useState<string[] | null>(null);
  const [why, setWhy] = useState('');
  const [breakGlass, setBreakGlass] = useState(false);
  const [errs, setErrs] = useState<Record<string, string>>({});
  const passwordRef = useRef<HTMLInputElement>(null);
  const tokenRef = useRef<HTMLInputElement>(null);
  // Every change to what the check looked at bumps rev: a check is current only for the rev it ran on.
  const [rev, setRev] = useState(0);
  const [checked, setChecked] = useState<{ rev: number; res: RestoreCheck } | null>(null);
  // What the checks found per database, for the target they ran on (a new target starts empty).
  const [known, setKnown] = useState<{ target: string; dbs: Known }>({ target: '', dbs: {} });
  const [done, setDone] = useState<RestoreRequest | null>(null);
  const check = useAction<RestoreCheck>();
  const submit = useAction<RestoreRequest>();
  const touch = () => setRev((r) => r + 1);
  // A filled form is not dropped by a stray click next to the dialog (Esc and Cancel still close it).
  const dirty = rev > 0 || why.trim() !== '' || breakGlass;

  const targetsQ = useQuery({ queryKey: ['targets', { engine }], queryFn: () => api.get<ItemList<Target>>('/targets', { engine }), staleTime: 30_000 });
  // The backup's own target, by id (from the run's job). Until it is known (or if the job cannot be read) nothing is
  // hidden for it: the server refuses the backup's own target anyway.
  const jobQ = useQuery({ queryKey: ['backup-jobs', run.job_id], queryFn: () => api.get<BackupJob>(`/backup/jobs/${run.job_id}`), staleTime: 60_000, retry: false });
  const ownTargetId = jobQ.data?.target.id;
  // Vaults configured in Olympos are never restore targets (the server refuses them too).
  const vaultsQ = useQuery({ queryKey: ['vaults'], queryFn: () => api.get<ItemList<Vault>>('/vaults'), staleTime: 60_000, enabled: isVault, retry: false });
  const configuredVaults = new Set((vaultsQ.data?.items ?? []).filter((v) => v.status === 'configured').map((v) => v.target.id));
  // The list waits for what it filters on, so the backup's own target never flashes up as a choice.
  const listing = targetsQ.isPending || jobQ.isPending || (isVault && vaultsQ.isPending);
  // Never the backup's own target, a gone one, or (Vault) one configured in Olympos.
  const targets = (listing ? [] : (targetsQ.data?.items ?? []))
    .filter((t) => t.engine === engine && t.status !== 'gone' && t.id !== ownTargetId && !(isVault && configuredVaults.has(t.id)))
    .sort((a, b) => `${a.cluster_name}/${a.namespace}/${a.service}`.localeCompare(`${b.cluster_name}/${b.namespace}/${b.service}`));
  const target = targets.find((t) => t.id === targetId);

  const wipe = () => {
    if (passwordRef.current) passwordRef.current.value = '';
    if (tokenRef.current) tokenRef.current.value = '';
  };
  const close = () => {
    wipe();
    onClose();
  };

  const credential = (): CredentialInput => {
    if (source === 'keyvault_ref') return { source, ref: `kv://${kvName.trim()}/${secretName.trim()}`, username: username.trim() };
    return { source, username: username.trim(), password: passwordRef.current?.value ?? '' };
  };

  /** Client-side checks of what the server check needs; justification only when opening. */
  const validate = (opening: boolean): Record<string, string> => {
    const e: Record<string, string> = {};
    if (!targetId) e.target_id = 'Choose the target to restore into.';
    if (isVault) {
      if (!tokenRef.current?.value.trim()) e.vault_token = 'Paste a token of the new Vault.';
    } else {
      if (!username.trim()) e['credential.username'] = 'Enter an admin login of the new database.';
      if (source === 'keyvault_ref') {
        if (!KV_RE.test(kvName.trim())) e['credential.ref'] = 'Key Vault names are 3–24 letters, digits and dashes.';
        else if (!SECRET_RE.test(secretName.trim())) e.secretName = 'Secret names use letters, digits and dashes.';
      } else if (!passwordRef.current?.value) e['credential.password'] = 'Enter the password of this login.';
      if (databases && databases.length === 0) e.databases = 'Select at least one database.';
    }
    if (ca.trim() && !ca.includes('-----BEGIN CERTIFICATE-----')) e.tls_ca_pem = 'Paste a PEM certificate (-----BEGIN CERTIFICATE-----), or leave it empty.';
    if (opening) {
      const n = why.trim().length;
      if (n < MIN_WHY) e.justification = `Explain why in at least ${MIN_WHY} characters (an incident or ticket number helps the checker).`;
      else if (n > MAX_WHY) e.justification = `Keep the justification under ${MAX_WHY} characters.`;
    }
    return e;
  };

  const body = (): RestoreInput => {
    const inBackup = checked?.res.databases_in_backup ?? [];
    const subset = databases && !(databases.length === inBackup.length && inBackup.every((d) => databases.includes(d)));
    return {
      run_id: run.id,
      copy_destination_id: copy || null,
      target_id: targetId,
      ...(isVault ? { vault_token: tokenRef.current?.value.trim() ?? '' } : { credential: credential(), databases: subset ? databases! : [] }),
      ...(engine === 'postgresql' ? { globals } : {}),
      ...(ca.trim() ? { tls_ca_pem: ca.trim() } : {}),
      justification: why.trim(),
    };
  };
  /** Drops the secrets from a request body once it has been sent. */
  const scrub = (b: RestoreInput) => {
    if (b.credential) b.credential.password = undefined;
    b.vault_token = undefined;
  };

  const runCheck = async () => {
    const e = validate(false);
    setErrs(e);
    if (Object.keys(e).length) return;
    const at = rev;
    const b = body();
    const res = await check.run(() => api.post<RestoreCheck>('/restores/check', b));
    scrub(b);
    if (!res) return;
    setChecked({ rev: at, res });
    setKnown((k) => ({ target: b.target_id, dbs: learn(k.target === b.target_id ? k.dbs : {}, res.databases, res.report) }));
    // The first check lists the databases in the backup: all of them are selected. Later checks keep the selection
    // to what this copy holds (another copy may hold other databases); an empty result selects all again.
    const inBackup = res.databases_in_backup;
    if (inBackup) {
      setDatabases((cur) => {
        const kept = cur?.filter((d) => inBackup.includes(d)) ?? [];
        return kept.length ? kept : [...inBackup];
      });
    }
  };

  const open = async (e: React.FormEvent) => {
    e.preventDefault();
    const v = validate(true);
    setErrs(v);
    if (Object.keys(v).length) return;
    const b = { ...body(), ...(breakGlass ? { break_glass: true } : {}) };
    const r = await submit.run(() => api.post<RestoreRequest>('/restores', b));
    scrub(b);
    if (r) {
      wipe();
      setDone(r);
      void qc.invalidateQueries({ queryKey: ['restores'] });
    }
  };

  const current = checked && checked.rev === rev ? checked.res : null;
  const res = checked?.res ?? null;
  const stale = !!checked && checked.rev !== rev;
  const ready = !!current?.ok;
  const fe = (n: string) => errs[n] ?? (current?.fields ?? {})[n] ?? fieldError(submit.error, n) ?? fieldError(check.error, n);
  const credErr = fe('credential');
  // A refusal the check reports as its message too (agent offline, the target check failed) is shown once, in the
  // check panel; the Target field only points at it.
  const targetErrRaw = fe('target_id');
  const targetErrInPanel = !!targetErrRaw && !!current?.error && current.error === current.fields?.target_id;
  const targetErr = errs.target_id ?? (targetErrRaw && !targetErrInPanel ? readable(targetErrRaw) : undefined);
  const sourceErr = fe('run_id') ?? fe('copy_destination_id');
  const title = `Restore ${run.target_service} into a new target`;
  const kind = restoreEngineName(engine);

  if (done) {
    return (
      <Modal open onClose={close} size="narrow" eyebrow="Restore request" title={done.break_glass ? 'Break-glass restore started' : 'Submitted for approval'}>
        <div className={`note ${done.break_glass ? 'warn' : 'ok'}`} role="status">
          {done.break_glass ? (
            <>
              The restore into <span className="mono">{done.target.service}</span> is approved and starts as soon as the target&apos;s agent is connected (within 24 h). It is recorded in the audit log and a critical
              notification (<span className="mono">restore.break_glass</span>) was sent.
            </>
          ) : (
            <>
              The restore into <span className="mono">{done.target.service}</span> waits for a second person with operate on both clusters. It expires {dateTime(done.expires_at)} if nobody decides. Nothing is written
              to the target before it is approved.
            </>
          )}
        </div>
        <p className="muted small" style={{ margin: 0 }}>
          The credential{isVault ? ' (the token)' : ''} is kept encrypted while the request is open and deleted when it ends. It is never shown again.
        </p>
        <div className="end">
          <Link to="/approvals" search={{ view: 'mine', restore: done.id }} className="btn">
            Open request
          </Link>
          <button type="button" className="btn pri" onClick={close}>
            Done
          </button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal open onClose={close} closeOnBackdrop={!dirty} size="wide" eyebrow={`Restore · ${run.target_service}`} title={title} description={`${kind}${native ? ' · native backup' : ''} · run of ${relDateTime(run.started_at ?? run.scheduled_for)} · ${run.cluster_name}`}>
      <form onSubmit={open} className="stack-sm" style={{ gap: 18 }} noValidate autoComplete="off">
        <div className="note">
          {isVault ? (
            <>
              A snapshot replaces all of the target&apos;s data: there is no database selection. The target must be a new Vault or OpenBao that is not configured in Olympos, initialized, unsealed and the active node.
            </>
          ) : (
            <>
              The backup is loaded into a new target that Olympos discovered, in any cluster, never the backup&apos;s own. Nothing on the target is dropped or replaced: a database that exists there with data in it
              stops the request.
            </>
          )}{' '}
          A second person with operate on both clusters approves it before anything is written.
        </div>
        {sourceErr && (
          <div className="note crit" role="alert">
            {sourceErr}
          </div>
        )}

        {copies.length > 1 && (
          <fieldset className="opts">
            <legend className="lbl">Copy</legend>
            {copies.map((c) => (
              <label className="opt" key={c.destination_id}>
                <input
                  type="radio"
                  name="restore-dialog-copy"
                  checked={copy === c.destination_id}
                  disabled={!c.enabled}
                  onChange={() => {
                    setCopy(c.destination_id);
                    // another copy may hold other databases: the next check lists them again
                    setDatabases(null);
                    setKnown({ target: '', dbs: {} });
                    touch();
                  }}
                />
                <span style={{ minWidth: 0 }}>
                  <span className="inline-sm">
                    <span className="t1 mono">{c.name}</span>
                    <KindBadge kind={c.kind} />
                    {c.repair && <Badge tone="mute">Repair</Badge>}
                    {!c.enabled && <Badge tone="crit">Failed</Badge>}
                  </span>
                  <span className="t2">{!c.enabled ? 'This run has no copy here.' : c.repair ? `Written by a repair ${relDateTime(c.takenAt)} (a later dump)` : `Taken ${relDateTime(c.takenAt)}`}</span>
                </span>
              </label>
            ))}
          </fieldset>
        )}

        <Field
          label={`Target (${kind})`}
          htmlFor="rs-target"
          error={targetErr}
          hint={
            targetsQ.isSuccess && !listing && targets.length === 0 ? (
              <>
                No other discovered {kind} target. Deploy the new server, annotate its Service with <span className="mono">olympos.io/backup: {engine}</span>, and wait for its agent to report it.
              </>
            ) : (
              'Discovered targets of the same engine, in any cluster.'
            )
          }
        >
          <Select
            id="rs-target"
            value={targetId}
            onChange={(v) => {
              setTargetId(v);
              touch();
            }}
            mono
            searchable={targets.length > 8}
            invalid={!!targetErrRaw}
            aria-describedby={targetErr ? 'rs-target-err' : targetErrInPanel ? 'rs-check-err' : 'rs-target-hint'}
            placeholder={listing ? 'Loading targets…' : 'Choose a target'}
            options={targets.map((t) => ({
              value: t.id,
              label: `${t.cluster_name} / ${t.namespace} / ${t.service}`,
              hint: `${engineLabel(engine, t.detected_version, t.vault_provider)}${t.status === 'configured' ? ' · has a backup job' : ''}`,
            }))}
          />
        </Field>

        {isVault ? (
          <Field label="Token of the new Vault" htmlFor="rs-token" error={fe('vault_token')} hint={<><VaultTokenNeeds /> Sealed until the request ends, then wiped; never shown again.</>}>
            <input ref={tokenRef} type="password" className="in mono" {...aria('rs-token', fe('vault_token'), true)} onChange={touch} autoComplete="off" spellCheck={false} placeholder="hvs.…" />
          </Field>
        ) : (
          <>
            <fieldset className="opts" aria-describedby={credErr ? 'rs-cred-err' : undefined}>
              <legend className="lbl">Target credential (an admin login of the new database)</legend>
              <label className="opt">
                <input
                  type="radio"
                  name="rs-src"
                  checked={source === 'keyvault_ref'}
                  onChange={() => {
                    setSource('keyvault_ref');
                    touch();
                  }}
                />
                <span>
                  <span className="t1">Azure Key Vault reference</span> <Badge tone="ok">Recommended</Badge>
                  <span className="t2">Read when the restore runs, with the server&apos;s managed identity. Nothing stored in Olympos.</span>
                </span>
              </label>
              <label className="opt">
                <input
                  type="radio"
                  name="rs-src"
                  checked={source === 'stored'}
                  onChange={() => {
                    setSource('stored');
                    touch();
                  }}
                />
                <span>
                  <span className="t1">Store in Olympos</span>
                  <span className="t2">Envelope-encrypted while the request is open, deleted when it ends.</span>
                </span>
              </label>
              {credErr && (
                <div className="field-error" id="rs-cred-err" role="alert">
                  {credErr}
                </div>
              )}
            </fieldset>
            <div className={source === 'keyvault_ref' ? 'grid-3' : 'grid-2'}>
              <Field label="Username" htmlFor="rs-user" error={fe('credential.username')}>
                <input
                  className="in mono"
                  {...aria('rs-user', fe('credential.username'))}
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    touch();
                  }}
                  placeholder="postgres"
                  autoComplete="off"
                  spellCheck={false}
                />
              </Field>
              {source === 'keyvault_ref' ? (
                <>
                  <Field label="Key Vault" htmlFor="rs-kv" error={fe('credential.ref')}>
                    <input
                      className="in mono"
                      {...aria('rs-kv', fe('credential.ref'))}
                      value={kvName}
                      onChange={(e) => {
                        setKvName(e.target.value);
                        touch();
                      }}
                      placeholder="kv-dr-neu"
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </Field>
                  <Field label="Secret name (holds the password)" htmlFor="rs-sec" error={fe('secretName')}>
                    <input
                      className="in mono"
                      {...aria('rs-sec', fe('secretName'))}
                      value={secretName}
                      onChange={(e) => {
                        setSecretName(e.target.value);
                        touch();
                      }}
                      placeholder={target ? `${target.service}-admin` : 'new-db-admin'}
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </Field>
                </>
              ) : (
                <Field label="Password" htmlFor="rs-pw" error={fe('credential.password')} hint="Sent over TLS, never shown again.">
                  <input ref={passwordRef} className="in mono" type="password" {...aria('rs-pw', fe('credential.password'), true)} onChange={touch} autoComplete="new-password" />
                </Field>
              )}
            </div>
            {engine === 'postgresql' && (
              <label className="chk">
                <input
                  type="checkbox"
                  checked={globals && current?.options.superuser !== false}
                  disabled={current?.options.superuser === false}
                  onChange={(e) => {
                    setGlobals(e.target.checked);
                    touch();
                  }}
                />
                <span>
                  Restore roles (<span className="mono">globals.sql</span>)
                  <span className="muted small" style={{ display: 'block' }}>
                    {current?.options.superuser === false
                      ? 'Off: the credential is not a superuser, so roles are not restored.'
                      : 'Only with a superuser. Roles that already exist on the target are left alone and listed in the result.'}
                  </span>
                </span>
              </label>
            )}
          </>
        )}

        <Field label="CA certificate of the target (PEM, optional)" htmlFor="rs-ca" error={fe('tls_ca_pem')} hint="Verifies the new target's certificate: a new target has no job that carries one. The checker sees it.">
          <textarea
            className="in mono"
            rows={2}
            {...aria('rs-ca', fe('tls_ca_pem'), true)}
            value={ca}
            onChange={(e) => {
              setCa(e.target.value);
              touch();
            }}
            placeholder="-----BEGIN CERTIFICATE-----"
            spellCheck={false}
          />
        </Field>

        <div className="end">
          <button type="button" className={`btn${ready ? '' : ' pri'}`} onClick={() => void runCheck()} disabled={check.pending}>
            {check.pending ? 'Checking the target…' : checked ? 'Check again' : 'Check target'}
          </button>
        </div>
        <FormError error={check.error} />

        {res && (
          <section className="boxed stack-sm" aria-labelledby="rs-check-t" style={{ gap: 12 }}>
            <div className="spread">
              <b id="rs-check-t">Target check</b>
              <span className="muted mono small">
                {res.report?.server_version ? `${engineLabel(engine === 'vault' ? 'vault' : engine, res.report.server_version, target?.vault_provider)} · ` : ''}nothing was written
              </span>
            </div>
            {stale && <p className="small ico-warn" style={{ margin: 0 }}>You changed the request since this check. Check again before you submit.</p>}
            {res.ok && !stale && (
              <div className="chk">
                <CheckIcon ok />
                <span>The target can take this restore.</span>
              </div>
            )}
            {!res.ok && res.error && (
              <div className="chk" role="alert" id="rs-check-err">
                <CheckIcon ok={false} />
                <span>
                  {readable(res.error)}.{Object.entries(res.fields ?? {}).some(([, v]) => v !== res.error) ? ' Check the highlighted fields.' : ''}
                </span>
              </div>
            )}
            {res.native && (res.databases_in_backup?.length ?? 0) > 0 && (
              <div className="chk">
                <CheckIcon ok />
                <span>The backup&apos;s signed manifests verify: this run and every run it is based on</span>
              </div>
            )}
            {isVault && res.report && <VaultChecks r={res.report} />}
            {!isVault && res.report && (
              <div className="chk">
                <CheckIcon ok />
                <span>
                  The credential works{engine === 'postgresql' ? (res.report.superuser ? ' · superuser: owners, privileges and roles are kept' : ' · not a superuser') : ''}
                </span>
              </div>
            )}
            {!isVault && databases && (res.databases_in_backup?.length ?? 0) > 0 && (
              <fieldset className="plain" aria-describedby={fe('databases') ? 'rs-dbs-err' : undefined}>
                <legend className="lbl">
                  Databases ({databases.length} of {res.databases_in_backup!.length} in the backup selected){res.native ? ' and what is restored' : ''}
                </legend>
                {res.databases_in_backup!.map((d) => {
                  const box = (
                    <>
                      <input
                        type="checkbox"
                        checked={databases.includes(d)}
                        onChange={(e) => {
                          setDatabases(e.target.checked ? [...databases, d] : databases.filter((x) => x !== d));
                          touch();
                        }}
                      />
                      <span className="mono">{d}</span> <DbState state={known.target === targetId ? known.dbs[d] : undefined} />
                    </>
                  );
                  if (!res.native)
                    return (
                      <label className="chk" key={d}>
                        {box}
                      </label>
                    );
                  // the decisions are for the databases the check was given
                  const objs = res.native.objects.filter((o) => o.database === d);
                  const checkedHere = res.databases?.includes(d) ?? false;
                  return (
                    <div className="native-db" key={d}>
                      <label className="chk native-db-head">
                        {box} <span className="muted small">{checkedHere ? restoredOf(objs) : 'not selected'}</span>
                      </label>
                      {objs.length > 0 && <NativeObjects db={d} objects={objs} />}
                    </div>
                  );
                })}
                {fe('databases') && (
                  <div className="field-error" id="rs-dbs-err" role="alert">
                    {sentenceCase(fe('databases')!)}. Change the selection and check again.
                  </div>
                )}
              </fieldset>
            )}
            {/* a backup that does not verify: what its own signed manifest lists, every object left out, nothing to select */}
            {res.native && !res.databases_in_backup?.length && res.native.objects.length > 0 && (
              <div>
                {byDatabase(res.native.objects).map(([d, objs]) => (
                  <div className="native-db" key={d}>
                    <div className="native-db-head small">
                      <span className="mono">{d}</span> <span className="muted small">{restoredOf(objs)}</span>
                    </div>
                    <NativeObjects db={d} objects={objs} />
                  </div>
                ))}
              </div>
            )}
            {!isVault && !databases && fe('databases') && (
              <div className="field-error" role="alert">
                {fe('databases')}
              </div>
            )}
            {(res.options.notes?.length ?? 0) > 0 && (
              <div className={`note ${engine === 'postgresql' && res.options.superuser === false ? 'warn' : ''}`}>
                <div className="note-title">{engine === 'postgresql' && res.options.superuser === false ? 'Not a superuser: owners, privileges and roles are not restored' : 'Found by the check'}</div>
                <ul className="note-list">
                  {res.options.notes!.map((n, i) => (
                    <li key={i}>{n}</li>
                  ))}
                </ul>
                <span className="muted small">The checker sees these notes with the request.</span>
              </div>
            )}
          </section>
        )}

        {engine === 'clickhouse' && (native ? <NativeScopeNote /> : <ClickHouseScopeNote />)}
        {isVault && <VaultUnsealNote />}

        <Field label="Justification" htmlFor="rs-why" error={fe('justification')} hint={`${MIN_WHY} to ${MAX_WHY} characters. The checker and the audit log see it.`}>
          <textarea className="in" rows={2} {...aria('rs-why', fe('justification'), true)} value={why} onChange={(e) => setWhy(e.target.value)} placeholder="What happened, and an incident or ticket number" />
        </Field>

        {mayBreakGlass && (
          <label className="opt opt-crit">
            <input type="checkbox" checked={breakGlass} onChange={(e) => setBreakGlass(e.target.checked)} />
            <span>
              <span className="t1 ico-crit">Break-glass: start now, without a checker</span>
              <span className="t2">
                Admins on both clusters only. Recorded in the audit log and sent as a critical notification (<span className="mono">restore.break_glass</span>). Use it when no second person can approve in time.
              </span>
            </span>
          </label>
        )}

        <FormError error={submit.error && !fieldError(submit.error, 'justification') ? submit.error : null} />
        <div className="end" style={{ alignItems: 'center' }}>
          <span className="muted small" id="rs-confirm">
            {target ? (
              <>
                Restoring <span className="mono">{run.target_service}</span> → <span className="mono strong">{`${target.cluster_name} / ${target.namespace} / ${target.service}`}</span>
              </>
            ) : ready ? null : (
              'Check the target before you submit.'
            )}
          </span>
          <button type="button" className="btn" onClick={close}>
            Cancel
          </button>
          <button type="submit" className={`btn ${breakGlass ? 'danger' : 'pri'}`} disabled={!ready || submit.pending} aria-describedby="rs-confirm">
            {submit.pending ? 'Submitting…' : breakGlass ? 'Break-glass: start now' : 'Submit for approval'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
