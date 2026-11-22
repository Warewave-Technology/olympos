import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { BackupJob, BackupJobInput, BackupRun, Channel, Cluster, ConnectionTest, CredentialInput, Destination, DestinationGroup, ItemList, SchedulePreview, Target, Vault } from '../api/types';
import { useCan } from '../auth/me';
import { CRON_PRESETS, describeCron, formatInZone, nextRuns, presetFor, timeZones, tzOffsetLabel, validateCron } from '../lib/cron';
import { age, between, bytes, daysUntil, duration, engineLabel, joinPath, money } from '../lib/format';
import { backupWizardRoute } from '../router';
import { CheckIcon } from '../ui/icons';
import { Badge, EmptyState, ErrorState, Field, FormError, Loading, Spinner, aria, fieldError, useAction, useToast } from '../ui/kit';
import { PageHead, RunBadge } from '../ui/status';
import { GroupName, KIND_LABEL, KindBadge, authLabel, destLocation } from '../ui/destinations';
import { Select } from '../ui/Select';
import { TagInput, validateDatabaseName } from '../ui/TagInput';

type Step = 1 | 2 | 3 | 4;
const STEPS: { n: Step; name: string; hint: string }[] = [
  { n: 1, name: 'Target', hint: '' },
  { n: 2, name: 'Credentials', hint: 'Where the password comes from' },
  { n: 3, name: 'Destination & schedule', hint: 'Storage, cron, retention' },
  { n: 4, name: 'Review & test run', hint: 'Dry run before enabling' },
];

interface Form {
  source: 'keyvault_ref' | 'stored';
  kvName: string;
  secretName: string;
  username: string;
  databases: string[];
  /** Exactly one of destinationId and groupId is set. */
  destinationId: string;
  groupId: string;
  cron: string;
  custom: boolean;
  timezone: string;
  daily: string;
  weekly: string;
  monthly: string;
  notifyChannelId: string;
  notifyOnSuccess: boolean;
}

const browserTz = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
})();

function parseRef(ref: string): { kv: string; secret: string } {
  const m = /^kv:\/\/([^/]+)\/(.+)$/.exec(ref);
  return m ? { kv: m[1], secret: m[2] } : { kv: '', secret: '' };
}

function initialForm(job?: BackupJob): Form {
  if (!job) {
    return { source: 'keyvault_ref', kvName: '', secretName: '', username: '', databases: [], destinationId: '', groupId: '', cron: '0 2 * * *', custom: false, timezone: browserTz, daily: '14', weekly: '8', monthly: '12', notifyChannelId: '', notifyOnSuccess: false };
  }
  const r = parseRef(job.credential.ref);
  const dbs = (job.engine_options?.databases as string[] | undefined) ?? [];
  return {
    source: job.credential.source === 'stored' ? 'stored' : 'keyvault_ref',
    kvName: r.kv,
    secretName: r.secret,
    username: job.credential.username,
    databases: dbs,
    destinationId: job.destination?.id ?? '',
    groupId: job.destination_group?.id ?? '',
    cron: job.cron,
    custom: !presetFor(job.cron),
    timezone: job.timezone || 'UTC',
    daily: String(job.retention.daily),
    weekly: String(job.retention.weekly),
    monthly: String(job.retention.monthly),
    notifyChannelId: job.notify_channel_id ?? '',
    notifyOnSuccess: !!job.notify_on_success,
  };
}

export function BackupWizardPage() {
  const { target: targetId, job: jobId } = backupWizardRoute.useSearch();
  const canOperate = useCan('operate');
  const jobQ = useQuery({ queryKey: ['backup-jobs', jobId], queryFn: () => api.get<BackupJob>(`/backup/jobs/${jobId}`), enabled: !!jobId });
  const targetsQ = useQuery({ queryKey: ['targets', { all: true }], queryFn: () => api.get<ItemList<Target>>('/targets'), enabled: !jobId && !!targetId });

  const crumbs = (
    <>
      <Link to="/backups">Backups</Link> / Configure
    </>
  );
  if (!canOperate) {
    return (
      <>
        <PageHead crumbs={crumbs} title="Configure backup" />
        <section className="card">
          <EmptyState title="Configuring backups needs the operator role">
            Your grants let you see backups but not configure them. Ask an Olympos admin for <span className="mono">operator</span> on this cluster’s scope.
          </EmptyState>
        </section>
      </>
    );
  }
  if (!targetId && !jobId) {
    return (
      <>
        <PageHead crumbs={crumbs} title="Configure backup" />
        <section className="card">
          <EmptyState title="Pick a target first" action={<Link to="/backups" className="btn pri">Go to candidates</Link>}>
            Start from a discovered database on the Backups › Candidates tab.
          </EmptyState>
        </section>
      </>
    );
  }
  const q = jobId ? jobQ : targetsQ;
  if (q.isPending) return <Loading label="Loading target…" />;
  if (q.isError)
    return (
      <>
        <PageHead crumbs={crumbs} title="Configure backup" />
        <section className="card">
          <ErrorState what={jobId ? 'the backup job' : 'the target'} error={q.error} onRetry={() => q.refetch()} />
        </section>
      </>
    );
  const job = jobId ? jobQ.data : undefined;
  const target = job?.target ?? targetsQ.data?.items.find((t) => t.id === targetId);
  if (!target) {
    return (
      <>
        <PageHead crumbs={crumbs} title="Configure backup" />
        <section className="card">
          <EmptyState title="Target not found" action={<Link to="/backups" className="btn">Back to candidates</Link>}>
            This target is gone or outside your access scope. The agent may have stopped reporting it (Service deleted or annotation removed).
          </EmptyState>
        </section>
      </>
    );
  }
  return <Wizard key={target.id + (job?.id ?? '')} target={target} job={job} crumbs={crumbs} />;
}

function Wizard({ target, job, crumbs }: { target: Target; job?: BackupJob; crumbs: React.ReactNode }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();
  const [step, setStep] = useState<Step>(1);
  const [maxStep, setMaxStep] = useState<Step>(job ? 4 : 1);
  const [f, setF] = useState<Form>(() => initialForm(job));
  // Kept outside `f`, cleared right after it was sent. Never cached anywhere.
  const [password, setPassword] = useState('');
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [savedJob, setSavedJob] = useState<BackupJob | undefined>(job);
  const [conn, setConn] = useState<ConnectionTest | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const isVault = target.engine === 'vault';
  const [dbDraftErr, setDbDraftErr] = useState<string | null>(null);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((p) => ({ ...p, [k]: v }));
  // Vault/OpenBao snapshots use the Olympos AppRole of that vault: it must be configured first.
  const vaultsQ = useQuery({ queryKey: ['vaults'], queryFn: () => api.get<ItemList<Vault>>('/vaults'), enabled: isVault });
  const vault = isVault ? findVault(vaultsQ.data?.items, target) : undefined;
  const vaultReady = !isVault || vault?.status === 'configured';

  const clusterQ = useQuery({ queryKey: ['clusters', target.cluster_id], queryFn: () => api.get<Cluster>(`/clusters/${target.cluster_id}`) });
  const destQ = useQuery({ queryKey: ['destinations'], queryFn: () => api.get<ItemList<Destination>>('/destinations') });
  const groupsQ = useQuery({ queryKey: ['destination-groups'], queryFn: () => api.get<ItemList<DestinationGroup>>('/destination-groups') });
  const chanQ = useQuery({ queryKey: ['channels'], queryFn: () => api.get<ItemList<Channel>>('/notifications/channels') });
  const cluster = clusterQ.data;
  const dest = f.groupId ? undefined : destQ.data?.items.find((d) => d.id === f.destinationId);
  const group = f.groupId ? groupsQ.data?.items.find((g) => g.id === f.groupId) : undefined;
  const pickDestination = (id: string) => setF((p) => ({ ...p, destinationId: id, groupId: '' }));
  const pickGroup = (id: string) => setF((p) => ({ ...p, destinationId: '', groupId: id }));
  const channel = chanQ.data?.items.find((c) => c.id === f.notifyChannelId);

  useEffect(() => {
    if (!f.destinationId && !f.groupId && destQ.data?.items.length) {
      const mi = destQ.data.items.find((d) => d.auth === 'managed_identity') ?? destQ.data.items[0];
      set('destinationId', mi.id);
    }
  }, [destQ.data, f.destinationId, f.groupId]);

  useEffect(() => {
    headingRef.current?.focus();
  }, [step]);

  const cronErr = validateCron(f.cron);
  const previewQ = useQuery({
    queryKey: ['schedule-preview', f.cron, f.timezone],
    queryFn: () => api.get<SchedulePreview>('/backup/schedule-preview', { cron: f.cron, timezone: f.timezone, count: 3 }),
    enabled: !cronErr,
    retry: false,
  });
  const localNext = useMemo(() => {
    if (cronErr) return [];
    try {
      return nextRuns(f.cron, 3, new Date(), f.timezone);
    } catch {
      return [];
    }
  }, [f.cron, f.timezone, cronErr]);

  const credential = (): CredentialInput | undefined => {
    if (isVault) return undefined;
    if (f.source === 'keyvault_ref') return { source: 'keyvault_ref', ref: `kv://${f.kvName.trim()}/${f.secretName.trim()}`, username: f.username.trim() };
    return { source: 'stored', username: f.username.trim(), ...(password ? { password } : {}) };
  };

  const validate = (s: Step): Record<string, string> => {
    const e: Record<string, string> = {};
    if (s === 2 && isVault && !vaultReady) {
      e.vault = vaultsQ.isPending ? 'Checking the vault…' : 'Configure this vault in Olympos first (Vaults › Configure). Backups use its Olympos AppRole.';
    }
    if (s === 2 && !isVault) {
      if (dbDraftErr) e.databases = dbDraftErr;
      if (!f.username.trim()) e.username = 'Enter the database user the backup connects as.';
      if (f.source === 'keyvault_ref') {
        if (!/^[a-zA-Z0-9-]{3,24}$/.test(f.kvName.trim())) e.kvName = 'Key Vault names are 3–24 letters, digits and dashes.';
        if (!/^[a-zA-Z0-9-]{1,127}$/.test(f.secretName.trim())) e.secretName = 'Secret names use letters, digits and dashes.';
      } else if (!password && !(savedJob && savedJob.credential.source === 'stored')) {
        e.password = 'Enter the password. It is encrypted with a Key Vault key and never shown again.';
      }
    }
    if (s === 3) {
      if (!f.destinationId && !f.groupId) e.destination_id = 'Pick a destination or a group. Add one in Settings › Destinations first if the list is empty.';
      if (cronErr) e.cron = cronErr;
      for (const k of ['daily', 'weekly', 'monthly'] as const) {
        const n = Number(f[k]);
        if (!Number.isInteger(n) || n < 0 || n > 1000) e[k] = 'Use a whole number from 0 to 1000.';
      }
    }
    return e;
  };

  const go = (to: Step) => {
    if (to > step) {
      for (let s = step; s < to; s++) {
        const e = validate(s as Step);
        if (Object.keys(e).length) {
          setErrs(e);
          setStep(s as Step);
          return;
        }
      }
    }
    setErrs({});
    setStep(to);
    setMaxStep((m) => (to > m ? to : m));
  };

  // --------------------------------------------------- connection test
  const test = useAction<ConnectionTest>();
  const runTest = async () => {
    const e = validate(2);
    setErrs(e);
    if (Object.keys(e).length) return;
    setConn(null);
    const cred = credential();
    const reuseStored = cred?.source === 'stored' && !password && savedJob;
    const body = cred && !reuseStored ? { target_id: target.id, credential: cred } : { target_id: target.id, credential_id: savedJob?.credential.id };
    const r = await test.run(() => api.post<ConnectionTest>('/backup/test-connection', body));
    if (r) setConn(r);
  };

  // --------------------------------------------------- save + dry run + enable
  const jobBody = (): BackupJobInput => ({
    target_id: target.id,
    credential: credential(),
    ...(f.groupId ? { destination_group_id: f.groupId } : { destination_id: f.destinationId }),
    engine_options: isVault ? {} : target.engine === 'postgresql' ? { databases: f.databases, globals: true } : { databases: f.databases },
    cron: f.cron.trim(),
    timezone: f.timezone,
    retention: { daily: Number(f.daily), weekly: Number(f.weekly), monthly: Number(f.monthly) },
    notify_channel_id: f.notifyChannelId || null,
    notify_on_success: f.notifyOnSuccess,
  });

  const save = useAction<BackupJob>();
  const saveJob = async (): Promise<BackupJob | undefined> => {
    const body = jobBody();
    const r = await save.run(() => (savedJob ? api.patch<BackupJob>(`/backup/jobs/${savedJob.id}`, body) : api.post<BackupJob>('/backup/jobs', { ...body, enabled: false })));
    if (r) {
      setPassword(''); // sent once; drop it
      setSavedJob(r);
      void qc.invalidateQueries({ queryKey: ['backup-jobs'] });
      void qc.invalidateQueries({ queryKey: ['targets'] });
    }
    return r;
  };

  const dry = useAction<BackupRun>();
  const startDryRun = async () => {
    const j = await saveJob();
    if (!j) return;
    setRunId(null);
    const r = await dry.run(() => api.post<BackupRun>(`/backup/jobs/${j.id}/run`, { trigger: 'test' }));
    if (r) setRunId(r.id);
  };
  const runQ = useQuery({
    queryKey: ['backup-runs', runId],
    queryFn: () => api.get<BackupRun>(`/backup/runs/${runId}`),
    enabled: !!runId,
    refetchInterval: (q) => (q.state.data && ['succeeded', 'failed', 'missed', 'partial'].includes(q.state.data.status) ? false : 1500),
  });
  const run = runQ.data;
  // A group dry run passes only when every copy was written; partial is not a pass.
  const dryOk = run?.status === 'succeeded';

  const enable = useAction<BackupJob>();
  const doEnable = async () => {
    if (!savedJob) return;
    const r = await enable.run(() => api.patch<BackupJob>(`/backup/jobs/${savedJob.id}`, { enabled: true }));
    if (r) {
      void qc.invalidateQueries({ queryKey: ['backup-jobs'] });
      toast(`Backup for ${target.service} enabled · ${describeCron(f.cron)}`);
      void navigate({ to: '/backups', search: { tab: 'jobs' } });
    }
  };
  const saveChanges = async () => {
    const r = await saveJob();
    if (r) {
      toast('Backup job saved.');
      void navigate({ to: '/backups', search: { tab: 'jobs' } });
    }
  };

  const fe = (name: string) => errs[name] ?? fieldError(save.error, name) ?? fieldError(test.error, name);
  const destErr = fe('destination_id') ?? fe('destination_group_id');
  const tlsHint = target.tls_ok ? 'TLS verified' : target.tls_ok === false ? 'no TLS' : 'TLS not probed';
  const stepHint = (n: Step) => (n === 1 ? `${target.service} · ${tlsHint}` : n === 2 && isVault ? 'Olympos AppRole, no password' : STEPS[n - 1].hint);
  const annotation = [
    'metadata:',
    '  annotations:',
    `    olympos.io/backup: ${target.engine}`,
    ...(target.vault_provider ? [`    olympos.io/vault: ${target.vault_provider}`] : []),
    ...(target.port_name || target.port ? [`    olympos.io/port: ${target.port_name || target.port}`] : []),
    ...(target.tls_server_name ? [`    olympos.io/tls-server-name: ${target.tls_server_name}`] : []),
  ].join('\n');
  const major = (target.detected_version || '').split('.')[0];
  const tzList = useMemo(() => timeZones(), []);
  const tzOptions = useMemo(() => tzList.map((z) => ({ value: z, label: `${z} (${tzOffsetLabel(z)})`, text: `${z} ${tzOffsetLabel(z)}` })), [tzList]);
  const nextList = previewQ.data?.next ?? (previewQ.isError ? localNext : []);

  return (
    <>
      <PageHead
        crumbs={crumbs}
        title={
          <>
            {job ? 'Edit backup' : 'Configure backup'} · <span className="mono" style={{ fontSize: 20 }}>{target.service}</span>
          </>
        }
        sub={
          <>
            {target.cluster_name} / {target.namespace} · {engineLabel(target.engine, target.detected_version, target.vault_provider)} · discovered by annotation {age(target.first_seen_at)} ago
          </>
        }
      />
      <div className="wizard">
        <ol aria-label="Steps" className="card steps">
          {STEPS.map((s) => {
            const done = s.n < step || (s.n <= maxStep && s.n !== step && s.n < maxStep);
            const cls = s.n === step ? 'on' : done ? 'done' : '';
            const reachable = s.n <= maxStep && s.n !== step;
            return (
              <li key={s.n} className={`step ${cls}`} aria-current={s.n === step ? 'step' : undefined}>
                <span className="num" aria-hidden="true">
                  {done ? '✓' : s.n}
                </span>
                <span>
                  {reachable ? (
                    <button type="button" className="name" onClick={() => go(s.n)}>
                      {s.name}
                      {done && <span className="sr-only"> (completed)</span>}
                    </button>
                  ) : (
                    <span className="name">{s.name}</span>
                  )}
                  <span className="hint">{stepHint(s.n)}</span>
                </span>
              </li>
            );
          })}
        </ol>

        <section className="card pad-xl wizard-body" aria-labelledby="step-t">
          <div className="card-title" style={{ display: 'block' }}>
            <div className="eyebrow">
              Step {step} of {STEPS.length}
            </div>
            <h2 className="section-title" id="step-t" ref={headingRef} tabIndex={-1}>
              {STEPS[step - 1].name}
            </h2>
            <p className="section-sub">
              {step === 1 && 'What the agent found. Check it is the right database before adding credentials.'}
              {step === 2 && (isVault ? 'Snapshots are taken by the server through the agent tunnel, with the Olympos AppRole of this vault.' : 'The server connects to the database through the agent tunnel. The password is used on the server only.')}
              {step === 3 && 'Where backups go, how often, and how long they are kept.'}
              {step === 4 && (target.engine === 'postgresql' ? 'A dry run takes a schema-only dump end to end, so problems show up now and not at night.' : 'A dry run takes a small test backup end to end, so problems show up now and not at night.')}
            </p>
          </div>

          {/* ------------------------------------------------ step 1 */}
          {step === 1 && (
            <>
              <dl className="dl">
                <dt>Service</dt>
                <dd className="mono">
                  {target.namespace}/{target.service} : {target.port}
                  {target.port_name ? ` (port "${target.port_name}")` : ''}
                </dd>
                <dt>Cluster</dt>
                <dd className="mono">
                  {target.cluster_name}
                  {cluster?.region ? ` · ${cluster.region}` : ''}
                </dd>
                <dt>Engine</dt>
                <dd>
                  {engineLabel(target.engine, target.detected_version || 'version not detected yet', target.vault_provider)}
                  {target.engine === 'postgresql' && major && <span className="muted"> → pg_dump {major} will be used</span>}
                  {target.engine === 'vault' && <span className="muted"> → raft snapshot via the Olympos AppRole</span>}
                </dd>
                <dt>TLS</dt>
                <dd>
                  <span className="inline-sm">
                    {target.tls_ok ? <Badge tone="ok">Verified</Badge> : target.tls_ok === false ? <Badge tone="warn">No TLS</Badge> : <Badge tone="mute">Not probed yet</Badge>}
                    {target.tls_server_name && <span className="mono muted">CN={target.tls_server_name}</span>}
                  </span>
                </dd>
                <dt>Transfer mode</dt>
                <dd>
                  {cluster ? (
                    cluster.transfer_mode === 'compressed' ? (
                      <span className="inline-sm">
                        <Badge tone="warn">compressed</Badge>
                        <span className="muted">cluster setting · agent can see backup data, zstd on the tunnel</span>
                      </span>
                    ) : (
                      <span className="inline-sm">
                        <Badge tone="ok">e2e-tls</Badge>
                        <span className="muted">cluster default · agent sees ciphertext only</span>
                      </span>
                    )
                  ) : (
                    <span className="muted">—</span>
                  )}
                </dd>
              </dl>
              {target.tls_ok === false && (
                <div className="note warn">
                  This target has no TLS. Backups are allowed, but the target gets a <span className="mono">tls.missing</span> finding and shows <i>TLS: No</i> under Backups. Enable TLS on the database and set <span className="mono">olympos.io/tls-server-name</span> to fix it.
                </div>
              )}
              {target.status === 'gone' && <div className="note crit">The agent no longer reports this Service. Jobs referencing it are paused.</div>}
              <div>
                <div className="lbl">Discovered from</div>
                <pre className="code">{annotation}</pre>
              </div>
              {target.engine === 'postgresql' && <div className="note">Backups connect to the primary through the Service. To back up from a replica, point the annotation at a read-only Service instead.</div>}
              <div className="foot-actions">
                <Link to="/backups" className="btn">
                  Cancel
                </Link>
                <button type="button" className="btn pri" onClick={() => go(2)} disabled={target.status === 'gone'}>
                  Next: credentials
                </button>
              </div>
            </>
          )}

          {/* ------------------------------------------------ step 2 */}
          {step === 2 && (
            <>
              {isVault ? (
                <VaultCredentialStep vault={vault} target={target} loading={vaultsQ.isPending} error={vaultsQ.isError ? vaultsQ.error : null} onRetry={() => vaultsQ.refetch()} />
              ) : (
                <>
                  <fieldset className="opts">
                    <legend className="lbl">Credential source</legend>
                    <label className="opt">
                      <input type="radio" name="src" checked={f.source === 'keyvault_ref'} onChange={() => set('source', 'keyvault_ref')} />
                      <span>
                        <span className="t1">Azure Key Vault reference</span> <Badge tone="ok">Recommended</Badge>
                        <span className="t2">Read at run time with the server's managed identity. Nothing stored in Olympos.</span>
                      </span>
                    </label>
                    <label className="opt">
                      <input type="radio" name="src" checked={f.source === 'stored'} onChange={() => set('source', 'stored')} />
                      <span>
                        <span className="t1">Store in Olympos</span>
                        <span className="t2">Encrypted with a Key Vault key (envelope). Use when no secret exists yet.</span>
                      </span>
                    </label>
                  </fieldset>
                  <div className={f.source === 'keyvault_ref' ? 'grid-3' : 'grid-2'} data-testid="w-cred-fields">
                    <Field label="Username" htmlFor="w-user" error={fe('username')}>
                      <input className="in mono" {...aria('w-user', fe('username'))} value={f.username} onChange={(e) => set('username', e.target.value)} placeholder="backup_ro" autoComplete="off" spellCheck={false} />
                    </Field>
                    {f.source === 'keyvault_ref' ? (
                      <>
                        <Field label="Key Vault" htmlFor="w-kv" error={fe('kvName') ?? fe('ref')}>
                          <input className="in mono" {...aria('w-kv', fe('kvName') ?? fe('ref'))} value={f.kvName} onChange={(e) => set('kvName', e.target.value)} placeholder="kv-platform-weu" autoComplete="off" spellCheck={false} />
                        </Field>
                        <Field label="Secret name (holds the password)" htmlFor="w-sec" error={fe('secretName')}>
                          <input className="in mono" {...aria('w-sec', fe('secretName'))} value={f.secretName} onChange={(e) => set('secretName', e.target.value)} placeholder={`${target.service}-backup`} autoComplete="off" spellCheck={false} />
                        </Field>
                      </>
                    ) : (
                      <Field label="Password" htmlFor="w-pw" error={fe('password')} hint={savedJob?.credential.source === 'stored' ? 'A password is stored. Leave empty to keep it.' : 'Sent once over TLS, envelope-encrypted, never shown again.'}>
                        <input className="in mono" type="password" {...aria('w-pw', fe('password'), true)} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
                      </Field>
                    )}
                  </div>
                  <Field
                    label="Databases"
                    htmlFor="w-dbs"
                    error={fe('databases')}
                    hint={
                      <>
                        {f.databases.length === 0 ? <b>All databases will be backed up.</b> : `${f.databases.length === 1 ? '1 database' : `${f.databases.length} databases`} selected.`} Press Enter, comma or space after each name; leave empty for all databases.
                        {target.engine === 'postgresql' ? ' Globals (roles) are always included.' : ''}
                      </>
                    }
                  >
                    <TagInput
                      id="w-dbs"
                      mode="values"
                      value={f.databases}
                      onChange={(v) => set('databases', v)}
                      validate={validateDatabaseName}
                      placeholder={f.databases.length ? undefined : 'All databases · type a name to limit, e.g. orders'}
                      listLabel="Databases to back up"
                      onDraftError={setDbDraftErr}
                      aria-describedby={fe('databases') ? undefined : 'w-dbs-hint'}
                    />
                  </Field>
                  {conn?.ok && conn.databases.some((d) => !f.databases.includes(d)) && (
                    <div className="inline-sm small" style={{ marginTop: -8 }}>
                      <span className="muted">Visible on the server:</span>
                      {conn.databases
                        .filter((d) => !f.databases.includes(d))
                        .map((d) => (
                          <button key={d} type="button" className="pill mono" style={{ minHeight: 26, padding: '2px 10px' }} onClick={() => set('databases', [...f.databases, d])} aria-label={`Add database ${d}`}>
                            + {d}
                          </button>
                        ))}
                    </div>
                  )}
                </>
              )}

              {test.pending && (
                <div className="panel" role="status">
                  <Spinner label="Testing" /> Testing the connection through the agent tunnel…
                </div>
              )}
              {!test.pending && test.error ? <FormError error={test.error} /> : null}
              {conn && !test.pending && (
                <div className="panel" role="status" style={{ alignItems: 'flex-start', flexDirection: 'column', gap: 8 }}>
                  <div className="inline">
                    {conn.ok ? <Badge tone="ok">Connected</Badge> : <Badge tone="crit">Failed</Badge>}
                    <span>
                      {conn.ok ? (
                        <>
                          {engineLabel(target.engine, conn.server_version)} · {conn.tls ? 'TLS end-to-end, agent sees ciphertext only' : 'no TLS on this connection'}
                        </>
                      ) : (
                        <>
                          {conn.error} <span className="muted">Check the username and the secret value, then test again.</span>
                        </>
                      )}
                    </span>
                  </div>
                  {conn.privileges.length > 0 && (
                    <ul className="plain-list" aria-label="Privileges">
                      {conn.privileges.map((p) => (
                        <li key={p.name} className="chk" style={{ padding: '2px 0' }}>
                          <CheckIcon ok={p.ok} label={p.ok ? 'Granted' : 'Missing'} />
                          <span className="mono">{p.name}</span>
                          <span className="muted">{p.detail}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  {conn.ok && conn.databases.length > 0 && (
                    <div className="muted small">
                      Databases visible: <span className="mono">{conn.databases.join(', ')}</span>
                    </div>
                  )}
                </div>
              )}

              <div className="foot-actions">
                <button type="button" className="btn" onClick={() => go(1)}>
                  Back
                </button>
                <div className="inline">
                  {isVault && !vaultReady && !vaultsQ.isPending && (
                    <span className="muted small" id="w-next-why">
                      Configure the vault first
                    </span>
                  )}
                  {!isVault && (
                    <button type="button" className="btn" onClick={() => void runTest()} disabled={test.pending}>
                      Test connection
                    </button>
                  )}
                  <button type="button" className="btn pri" onClick={() => go(3)} disabled={!vaultReady} aria-describedby={isVault && !vaultReady ? 'w-next-why' : undefined}>
                    Next: destination
                  </button>
                </div>
              </div>
            </>
          )}

          {/* ------------------------------------------------ step 3 */}
          {step === 3 && (
            <>
              <fieldset className="opts" aria-describedby={destErr ? 'w-dest-err' : undefined}>
                <legend className="lbl">Destination</legend>
                {destQ.isPending && <Loading label="Loading destinations…" />}
                {destQ.isError && <ErrorState what="destinations" error={destQ.error} onRetry={() => destQ.refetch()} />}
                {destQ.data?.items.length === 0 && (
                  <div className="note warn">
                    No destination yet. An admin must add one in <Link to="/settings/destinations">Settings › Destinations</Link> before backups can run.
                  </div>
                )}
                {destQ.data?.items.map((d) => {
                  const days = daysUntil(d.sas_expires_at);
                  const sas = d.kind === 'azure_blob' && d.auth === 'sas_token';
                  return (
                    <label className="opt" key={d.id}>
                      <input type="radio" name="dst" checked={!f.groupId && f.destinationId === d.id} onChange={() => pickDestination(d.id)} />
                      <span style={{ minWidth: 0 }}>
                        <span className="inline-sm">
                          <span className="t1 mono">{d.name}</span>
                          <KindBadge kind={d.kind} />
                        </span>
                        <span className="t2">
                          <span className="mono">{destLocation(d).where}</span> · {authLabel(d)}
                          {sas && days !== null ? (days < 0 ? ' · SAS expired' : ` · expires in ${days} days`) : ''}
                          {d.kind === 'nfs' ? ' · retention must be enforced by the storage' : ''}
                        </span>
                      </span>
                    </label>
                  );
                })}
                {groupsQ.data?.items.map((g) => (
                  <label className="opt" key={g.id}>
                    <input type="radio" name="dst" checked={f.groupId === g.id} onChange={() => pickGroup(g.id)} />
                    <span style={{ minWidth: 0 }}>
                      <span className="inline-sm">
                        <span className="t1">
                          <GroupName name={g.name} />
                        </span>
                        <Badge tone="mute">Group</Badge>
                      </span>
                      <span className="t2">
                        One dump to every member, in order: {g.members.map((m, i) => `${i + 1} ${m.name} (${KIND_LABEL[m.kind]})`).join(' → ')}
                        {g.members.some((m) => m.kind === 'nfs') ? ' · retention on NFS must be enforced by the storage' : ''}
                      </span>
                    </span>
                  </label>
                ))}
                {groupsQ.isError && <p className="muted small">Destination groups could not be loaded; single destinations are still available.</p>}
              </fieldset>
              {destErr && (
                <div className="field-error" id="w-dest-err" role="alert">
                  {destErr}
                </div>
              )}

              <div className="form-cols">
              <div className="form-section">
                <h3 id="w-sched-l">Schedule</h3>
                <div>
                <div className="pills" role="group" aria-labelledby="w-sched-l" style={{ marginBottom: 12 }}>
                  {CRON_PRESETS.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      className="pill"
                      aria-pressed={!f.custom && f.cron === p.cron}
                      onClick={() => setF((s) => ({ ...s, cron: p.cron, custom: false }))}
                    >
                      {p.label}
                    </button>
                  ))}
                  <button type="button" className="pill" aria-pressed={f.custom || !presetFor(f.cron)} onClick={() => set('custom', true)}>
                    Custom
                  </button>
                </div>
                <div className="grid-2">
                  <Field label="Cron" htmlFor="w-cron" error={fe('cron')} hint={!cronErr ? describeCron(f.cron) : undefined}>
                    <input
                      className="in mono"
                      {...aria('w-cron', fe('cron'), !cronErr)}
                      value={f.cron}
                      onChange={(e) => setF((s) => ({ ...s, cron: e.target.value, custom: true }))}
                      spellCheck={false}
                      autoComplete="off"
                    />
                  </Field>
                  <Field label="Timezone" htmlFor="w-tz">
                    <Select id="w-tz" searchable searchLabel="Filter time zones" value={f.timezone} onChange={(v) => set('timezone', v)} options={tzOptions} />
                  </Field>
                </div>
                <div className="muted small" style={{ marginTop: 8 }} aria-live="polite">
                  {cronErr ? (
                    <span className="ico-crit">{cronErr}</span>
                  ) : previewQ.isPending ? (
                    'Computing next runs…'
                  ) : nextList.length ? (
                    <>
                      Next runs: {nextList.map((n) => formatInZone(n, f.timezone)).join(' · ')}
                      {previewQ.isError && ' (computed in the browser; the server preview is unavailable)'}
                    </>
                  ) : (
                    'This schedule never runs.'
                  )}
                </div>
                </div>
              </div>

              <div className="form-section">
                <h3>Retention &amp; notifications</h3>
                <p className="muted small" style={{ margin: 0 }}>
                  {group
                    ? 'Kept per tier (GFS) on every member, enforced by each destination’s lifecycle rules (on NFS, by the storage).'
                    : dest?.kind === 'nfs'
                    ? 'Kept per tier (GFS). On NFS the storage must protect old backups; Olympos can delete there.'
                    : dest?.kind === 's3'
                      ? 'Kept per tier (GFS), enforced by bucket lifecycle rules via object tags.'
                      : 'Kept per tier (GFS), enforced by Blob lifecycle rules via index tags.'}
                </p>
                <div className="grid-3">
                  <Field label="Daily" htmlFor="w-rd" error={fe('daily')}>
                    <input className="in" inputMode="numeric" {...aria('w-rd', fe('daily'))} value={f.daily} onChange={(e) => set('daily', e.target.value)} />
                  </Field>
                  <Field label="Weekly (Sunday)" htmlFor="w-rw" error={fe('weekly')}>
                    <input className="in" inputMode="numeric" {...aria('w-rw', fe('weekly'))} value={f.weekly} onChange={(e) => set('weekly', e.target.value)} />
                  </Field>
                  <Field label="Monthly (1st)" htmlFor="w-rm" error={fe('monthly')}>
                    <input className="in" inputMode="numeric" {...aria('w-rm', fe('monthly'))} value={f.monthly} onChange={(e) => set('monthly', e.target.value)} />
                  </Field>
                </div>
                <Field label="Notify" htmlFor="w-nc" hint={chanQ.isError ? 'Channels could not be loaded; you can set this later.' : undefined}>
                  <Select
                    {...aria('w-nc', undefined, chanQ.isError)}
                    value={f.notifyChannelId}
                    onChange={(v) => set('notifyChannelId', v)}
                    options={[
                      { value: '', label: 'Default routing', hint: 'Settings › Notifications' },
                      ...(chanQ.data?.items ?? []).map((c) => ({ value: c.id, label: c.name, hint: 'on failure and missed run' })),
                    ]}
                  />
                </Field>
                <label className="opt">
                  <input type="checkbox" checked={f.notifyOnSuccess} onChange={(e) => set('notifyOnSuccess', e.target.checked)} />
                  <span>Also notify on success</span>
                </label>
              </div>
              </div>

              <div className="foot-actions">
                <button type="button" className="btn" onClick={() => go(2)}>
                  Back
                </button>
                <button type="button" className="btn pri" onClick={() => go(4)}>
                  Next: review
                </button>
              </div>
            </>
          )}

          {/* ------------------------------------------------ step 4 */}
          {step === 4 && (
            <>
              <dl className="dl">
                <dt>Target</dt>
                <dd className="mono">
                  {target.cluster_name} / {target.namespace} / {target.service}
                </dd>
                {!isVault && (
                  <>
                    <dt>Databases</dt>
                    <dd className="mono">
                      {f.databases.length ? f.databases.join(', ') : 'all databases'}
                      {target.engine === 'postgresql' ? ' + globals' : ''}
                    </dd>
                    <dt>Credentials</dt>
                    <dd>
                      {f.source === 'keyvault_ref' ? (
                        <>
                          Key Vault{' '}
                          <span className="mono">
                            {f.kvName} / {f.secretName}
                          </span>
                        </>
                      ) : (
                        'Stored in Olympos (envelope-encrypted)'
                      )}{' '}
                      · user <span className="mono">{f.username}</span>
                    </dd>
                  </>
                )}
                {isVault && (
                  <>
                    <dt>Credentials</dt>
                    <dd>
                      Olympos AppRole of <span className="mono">{vault ? `${vault.target.cluster_name} / ${vault.target.namespace} / ${vault.target.service}` : target.service}</span> · raft snapshot
                    </dd>
                  </>
                )}
                <dt>Destination</dt>
                {group ? (
                  <dd>
                    <GroupName name={group.name} /> <span className="muted">· every member, in order:</span> <span className="mono">{group.members.map((m) => m.name).join(' → ')}</span>
                    <div className="mono small muted">{joinPath(target.cluster_name, target.namespace, target.service, target.engine)}/ below each member&apos;s prefix</div>
                  </dd>
                ) : (
                  <dd className="mono">{dest ? `${dest.name} · ${joinPath(dest.prefix, target.cluster_name, target.namespace, target.service, target.engine)}/` : '—'}</dd>
                )}
                <dt>Schedule</dt>
                <dd>
                  <span className="mono">{f.cron}</span> {f.timezone} <span className="muted">· {describeCron(f.cron)}</span>
                </dd>
                <dt>Retention</dt>
                <dd>
                  {f.daily} daily · {f.weekly} weekly · {f.monthly} monthly
                </dd>
                <dt>Notify</dt>
                <dd className="mono">
                  {channel ? channel.name : 'default routing'}
                  {f.notifyOnSuccess ? ' · also on success' : ''}
                </dd>
              </dl>

              <div className="boxed" aria-live="polite">
                <div className="spread" style={{ marginBottom: 6 }}>
                  <b style={{ fontWeight: 600 }}>Dry run</b>
                  {run ? (
                    run.status === 'succeeded' ? (
                      <Badge tone="ok">Passed · {duration(between(run.started_at, run.finished_at))}</Badge>
                    ) : (
                      <RunBadge run={run} />
                    )
                  ) : save.pending || dry.pending ? (
                    <Badge tone="info">Starting…</Badge>
                  ) : (
                    <Badge tone="mute">Not run yet</Badge>
                  )}
                </div>
                {!run && !save.pending && !dry.pending && (
                  <p className="muted small" style={{ margin: 0 }}>
                    {savedJob ? 'Run a dry run to check the setup end to end.' : 'Creates the job disabled, then runs a small test backup end to end. Nothing is scheduled until you enable it.'}
                  </p>
                )}
                {run && (
                  <ul className="plain-list">
                    {(run.steps && run.steps.length > 0
                      ? run.steps
                      : run.status === 'queued'
                        ? [{ name: 'queued', ok: null as unknown as boolean, detail: 'Queued, waiting for a worker…' }]
                        : run.status === 'running'
                          ? [{ name: 'running', ok: null as unknown as boolean, detail: 'Running through the agent tunnel…' }]
                          : run.status === 'succeeded'
                            ? [
                                { name: 'ok', ok: true, detail: `Test backup written: ${bytes(run.bytes)}, ${bytes(run.wire_bytes)} on the wire` },
                                ...(run.blob_path ? [{ name: 'blob', ok: true, detail: `Blob ${run.blob_path}` }] : []),
                              ]
                            : [{ name: 'err', ok: false, detail: run.error || 'The dry run failed.' }]
                    ).map((s, i) => (
                      <li key={i} className="chk">
                        <CheckIcon ok={s.ok} />
                        <span>{s.detail || s.name}</span>
                      </li>
                    ))}
                    {/* the server's checklist has an upload and a manifest step per copy; list copies only without one */}
                    {!run.steps?.length && (run.copies ?? []).map((c) => (
                      <li key={c.destination_id} className="chk">
                        <CheckIcon ok={c.status === 'succeeded'} />
                        <span>{`${c.destination_name}: ${c.status === 'succeeded' ? `${bytes(c.bytes)} written and verified` : `copy failed${c.error ? ` · ${c.error}` : ''}`}`}</span>
                      </li>
                    ))}
                    {(run.status === 'queued' || run.status === 'running') && (
                      <li className="chk">
                        <Spinner label="Dry run in progress" />
                        <span className="muted">In progress…</span>
                      </li>
                    )}
                  </ul>
                )}
                {run?.status === 'failed' && <p className="field-error">Fix the problem (credentials in step 2, destination in step 3), then run the dry run again.</p>}
                {run?.status === 'partial' && <p className="field-error">Not every destination of the group was written. Fix the failed destination (Settings › Destinations) or pick another group in step 3, then run the dry run again.</p>}
              </div>

              <FormError error={save.error ?? dry.error ?? enable.error} />

              {savedJob && (savedJob.estimated_monthly_bytes > 0 || cluster?.egress_rate_per_gb != null) && (
                <div className="note">
                  {savedJob.estimated_monthly_bytes > 0 ? `Estimated monthly transfer: ~${bytes(savedJob.estimated_monthly_bytes)}` : 'Transfer estimate appears after the first runs'}
                  {savedJob.estimated_monthly_cost != null
                    ? ` · ≈ ${money(savedJob.estimated_monthly_cost)} egress at ${cluster?.egress_rate_per_gb ?? '?'} USD/GB.`
                    : cluster?.egress_rate_per_gb == null
                      ? ' · no egress rate set for this cluster, so no cost estimate.'
                      : '.'}
                </div>
              )}

              <div className="foot-actions">
                <button type="button" className="btn" onClick={() => go(3)}>
                  Back
                </button>
                <div className="inline">
                  {job ? (
                    <>
                      <button type="button" className="btn" onClick={() => void startDryRun()} disabled={save.pending || dry.pending || run?.status === 'running' || run?.status === 'queued'}>
                        {run ? 'Run dry run again' : 'Save and run dry run'}
                      </button>
                      <button type="button" className="btn pri" onClick={() => void saveChanges()} disabled={save.pending}>
                        Save changes
                      </button>
                    </>
                  ) : (
                    <>
                      <button type="button" className="btn" onClick={() => void startDryRun()} disabled={save.pending || dry.pending || run?.status === 'running' || run?.status === 'queued'}>
                        {savedJob ? 'Run dry run again' : 'Create job and run dry run'}
                      </button>
                      <button type="button" className="btn pri" onClick={() => void doEnable()} disabled={!dryOk || enable.pending} aria-describedby={!dryOk ? 'enable-why' : undefined}>
                        Enable backup
                      </button>
                    </>
                  )}
                </div>
              </div>
              {!job && !dryOk && (
                <p id="enable-why" className="muted small" style={{ margin: '-10px 0 0', textAlign: 'right' }}>
                  Enable becomes available after a passing dry run.
                </p>
              )}
            </>
          )}
        </section>
      </div>
    </>
  );
}

/** The vault behind a Vault/OpenBao backup target (same target, else same Service). */
export function findVault(list: Vault[] | undefined, t: Target): Vault | undefined {
  if (!list) return undefined;
  return list.find((v) => v.target.id === t.id) ?? list.find((v) => v.target.cluster_id === t.cluster_id && v.target.namespace === t.namespace && v.target.service === t.service);
}

function VaultCredentialStep({ vault, target, loading, error, onRetry }: { vault: Vault | undefined; target: Target; loading: boolean; error: unknown; onRetry: () => void }) {
  const name = target.vault_provider === 'openbao' ? 'OpenBao' : 'Vault';
  if (loading) return <Loading label="Checking the vault…" />;
  if (error) return <ErrorState what="vaults" error={error} onRetry={onRetry} />;
  const id = (
    <span className="mono">
      {target.cluster_name} / {target.namespace} / {target.service}
    </span>
  );
  if (vault?.status === 'configured') {
    return (
      <div className="note ok" role="status">
        <div className="note-title">No credentials needed</div>
        This job uses the Olympos AppRole of {id}, created when the {name} was configured{vault.configured_at ? ` (${age(vault.configured_at)} ago by ${vault.configured_by_name || 'an admin'})` : ''}. Its policy only allows <span className="mono">sys/storage/raft/snapshot</span> read; nothing is stored for this job.
      </div>
    );
  }
  return (
    <div className="note warn" role="alert">
      <div className="note-title">
        {vault?.status === 'error' ? `The ${name} reports an error` : `This ${name} is not configured in Olympos yet`}
      </div>
      Backups of {id} use the Olympos AppRole of that {name}, so it has to be configured first. An admin configures it once with a root token, which is not stored.
      {vault?.last_error && <div className="mono small" style={{ marginTop: 6 }}>{vault.last_error}</div>}
      <div style={{ marginTop: 8 }}>
        {vault ? (
          <Link to="/vaults" search={{ vault: vault.id }}>
            Open Vaults › Configure
          </Link>
        ) : (
          <>
            Olympos has not discovered this {name} yet: annotate the Service with <span className="mono">olympos.io/vault: {target.vault_provider || 'hashicorp'}</span>, then <Link to="/vaults">open Vaults</Link>.
          </>
        )}
      </div>
    </div>
  );
}
