import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { BackupJob, BackupJobInput, BackupRun, Channel, Cluster, ConnectionTest, CredentialInput, Destination, ItemList, SchedulePreview, Target } from '../api/types';
import { useCan } from '../auth/me';
import { CRON_PRESETS, describeCron, formatInZone, nextRuns, presetFor, timeZones, tzOffsetLabel, validateCron } from '../lib/cron';
import { age, between, bytes, daysUntil, duration, engineLabel, money } from '../lib/format';
import { backupWizardRoute } from '../router';
import { CheckIcon } from '../ui/icons';
import { Badge, EmptyState, ErrorState, Field, FormError, Loading, Spinner, aria, fieldError, useAction, useToast } from '../ui/kit';
import { PageHead, RunBadge } from '../ui/status';

type Step = 1 | 2 | 3 | 4;
const STEPS: { n: Step; name: string; hint: string }[] = [
  { n: 1, name: 'Target', hint: '' },
  { n: 2, name: 'Credentials', hint: 'Where the password comes from' },
  { n: 3, name: 'Destination & schedule', hint: 'Blob, cron, retention' },
  { n: 4, name: 'Review & test run', hint: 'Dry run before enabling' },
];

interface Form {
  source: 'keyvault_ref' | 'stored';
  kvName: string;
  secretName: string;
  username: string;
  databases: string;
  destinationId: string;
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
    return { source: 'keyvault_ref', kvName: '', secretName: '', username: '', databases: '', destinationId: '', cron: '0 2 * * *', custom: false, timezone: browserTz, daily: '14', weekly: '8', monthly: '12', notifyChannelId: '', notifyOnSuccess: false };
  }
  const r = parseRef(job.credential.ref);
  const dbs = (job.engine_options?.databases as string[] | undefined) ?? [];
  return {
    source: job.credential.source === 'stored' ? 'stored' : 'keyvault_ref',
    kvName: r.kv,
    secretName: r.secret,
    username: job.credential.username,
    databases: dbs.join(', '),
    destinationId: job.destination.id,
    cron: job.cron,
    custom: !presetFor(job.cron),
    timezone: job.timezone || 'UTC',
    daily: String(job.retention.daily),
    weekly: String(job.retention.weekly),
    monthly: String(job.retention.monthly),
    notifyChannelId: job.notify_channel_id ?? '',
    notifyOnSuccess: Boolean((job as unknown as { notify_on_success?: boolean }).notify_on_success),
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
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((p) => ({ ...p, [k]: v }));

  const clusterQ = useQuery({ queryKey: ['clusters', target.cluster_id], queryFn: () => api.get<Cluster>(`/clusters/${target.cluster_id}`) });
  const destQ = useQuery({ queryKey: ['destinations'], queryFn: () => api.get<ItemList<Destination>>('/destinations') });
  const chanQ = useQuery({ queryKey: ['channels'], queryFn: () => api.get<ItemList<Channel>>('/notifications/channels') });
  const cluster = clusterQ.data;
  const dest = destQ.data?.items.find((d) => d.id === f.destinationId);
  const channel = chanQ.data?.items.find((c) => c.id === f.notifyChannelId);

  useEffect(() => {
    if (!f.destinationId && destQ.data?.items.length) {
      const mi = destQ.data.items.find((d) => d.auth === 'managed_identity') ?? destQ.data.items[0];
      set('destinationId', mi.id);
    }
  }, [destQ.data, f.destinationId]);

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
    if (s === 2 && !isVault) {
      if (!f.username.trim()) e.username = 'Enter the database user the backup connects as.';
      if (f.source === 'keyvault_ref') {
        if (!/^[a-zA-Z0-9-]{3,24}$/.test(f.kvName.trim())) e.kvName = 'Key Vault names are 3–24 letters, digits and dashes.';
        if (!/^[a-zA-Z0-9-]{1,127}$/.test(f.secretName.trim())) e.secretName = 'Secret names use letters, digits and dashes.';
      } else if (!password && !(savedJob && savedJob.credential.source === 'stored')) {
        e.password = 'Enter the password. It is encrypted with a Key Vault key and never shown again.';
      }
    }
    if (s === 3) {
      if (!f.destinationId) e.destination_id = 'Pick a destination. Add one in Settings › Destinations first if the list is empty.';
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
    destination_id: f.destinationId,
    engine_options: isVault
      ? {}
      : target.engine === 'postgresql'
        ? { databases: f.databases.split(',').map((s) => s.trim()).filter(Boolean), globals: true }
        : { databases: f.databases.split(',').map((s) => s.trim()).filter(Boolean) },
    cron: f.cron.trim(),
    timezone: f.timezone,
    retention: { daily: Number(f.daily), weekly: Number(f.weekly), monthly: Number(f.monthly) },
    notify_channel_id: f.notifyChannelId || null,
    ...({ notify_on_success: f.notifyOnSuccess } as object),
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
    refetchInterval: (q) => (q.state.data && ['succeeded', 'failed', 'missed'].includes(q.state.data.status) ? false : 1500),
  });
  const run = runQ.data;
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
  const tlsHint = target.tls_ok ? 'TLS verified' : target.tls_ok === false ? 'no TLS' : 'TLS not probed';
  const stepHint = (n: Step) => (n === 1 ? `${target.service} · ${tlsHint}` : STEPS[n - 1].hint);
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
      <div className="row" style={{ gap: 24 }}>
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
          <div>
            <h2 className="section-title" id="step-t" ref={headingRef} tabIndex={-1}>
              {STEPS[step - 1].name}
            </h2>
            <p className="section-sub">
              {step === 1 && 'What the agent found. Check it is the right database before adding credentials.'}
              {step === 2 && 'The server connects to the database through the agent tunnel. The password is used on the server only.'}
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
                  This target has no TLS. Backups are allowed, but the target gets a <span className="mono">tls.missing</span> finding in Security. Enable TLS on the database and set <span className="mono">olympos.io/tls-server-name</span> to fix it.
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
                <div className="note">
                  Raft snapshots use the Olympos AppRole created when this vault was configured (Vaults › Configure). The policy only allows <span className="mono">sys/storage/raft/snapshot</span> read; no credential is needed here.
                </div>
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
                  <div className="grid-2">
                    {f.source === 'keyvault_ref' ? (
                      <>
                        <Field label="Key Vault" htmlFor="w-kv" error={fe('kvName') ?? fe('ref')}>
                          <input className="in mono" {...aria('w-kv', fe('kvName') ?? fe('ref'))} value={f.kvName} onChange={(e) => set('kvName', e.target.value)} placeholder="kv-platform-weu" autoComplete="off" spellCheck={false} />
                        </Field>
                        <Field label="Secret name" htmlFor="w-sec" error={fe('secretName')} hint="The secret holds the password.">
                          <input className="in mono" {...aria('w-sec', fe('secretName'), true)} value={f.secretName} onChange={(e) => set('secretName', e.target.value)} placeholder={`${target.service}-backup`} autoComplete="off" spellCheck={false} />
                        </Field>
                      </>
                    ) : (
                      <Field
                        label="Password"
                        htmlFor="w-pw"
                        error={fe('password')}
                        hint={savedJob?.credential.source === 'stored' ? 'A password is stored. Leave empty to keep it.' : 'Sent once over TLS, envelope-encrypted, never shown again.'}
                        className="grid-span"
                      >
                        <input className="in mono" type="password" {...aria('w-pw', fe('password'), true)} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
                      </Field>
                    )}
                    <Field label="Username" htmlFor="w-user" error={fe('username')}>
                      <input className="in mono" {...aria('w-user', fe('username'))} value={f.username} onChange={(e) => set('username', e.target.value)} placeholder="backup_ro" autoComplete="off" spellCheck={false} />
                    </Field>
                    <Field label="Databases" htmlFor="w-dbs" error={fe('databases')} hint={target.engine === 'postgresql' ? 'Comma separated. Empty = all databases. Globals (roles) are always included.' : 'Comma separated. Empty = all databases.'}>
                      <input className="in mono" {...aria('w-dbs', fe('databases'), true)} value={f.databases} onChange={(e) => set('databases', e.target.value)} placeholder={conn?.databases.join(', ') || 'orders, orders_archive'} autoComplete="off" spellCheck={false} />
                    </Field>
                  </div>
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
                  <button type="button" className="btn" onClick={() => void runTest()} disabled={test.pending}>
                    Test connection
                  </button>
                  <button type="button" className="btn pri" onClick={() => go(3)}>
                    Next: destination
                  </button>
                </div>
              </div>
            </>
          )}

          {/* ------------------------------------------------ step 3 */}
          {step === 3 && (
            <>
              <fieldset className="opts" aria-describedby={fe('destination_id') ? 'w-dest-err' : undefined}>
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
                  return (
                    <label className="opt" key={d.id}>
                      <input type="radio" name="dst" checked={f.destinationId === d.id} onChange={() => set('destinationId', d.id)} />
                      <span>
                        <span className="t1 mono">{d.name}</span>
                        <span className="t2">
                          {d.auth === 'managed_identity' ? 'Managed Identity' : 'SAS token'} · <span className="mono">{d.account}</span>
                          {d.auth === 'sas_token' && days !== null ? (days < 0 ? ' · SAS expired' : ` · expires in ${days} days`) : ''}
                        </span>
                      </span>
                    </label>
                  );
                })}
              </fieldset>
              {fe('destination_id') && (
                <div className="field-error" id="w-dest-err" role="alert">
                  {fe('destination_id')}
                </div>
              )}

              <div>
                <div className="lbl" id="w-sched-l">
                  Schedule
                </div>
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
                    <select className="in" id="w-tz" value={f.timezone} onChange={(e) => set('timezone', e.target.value)}>
                      {tzList.map((z) => (
                        <option key={z} value={z}>
                          {z} ({tzOffsetLabel(z)})
                        </option>
                      ))}
                    </select>
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

              <div>
                <div className="lbl">Retention (enforced by Blob lifecycle rules via tags)</div>
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
              </div>

              <div className="grid-2">
                <Field label="Notify" htmlFor="w-nc" hint={chanQ.isError ? 'Channels could not be loaded; you can set this later.' : undefined}>
                  <select className="in" {...aria('w-nc', undefined, chanQ.isError)} value={f.notifyChannelId} onChange={(e) => set('notifyChannelId', e.target.value)}>
                    <option value="">Default routing (Settings › Notifications)</option>
                    {chanQ.data?.items.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name} · on failure and missed run
                      </option>
                    ))}
                  </select>
                </Field>
                <label className="opt" style={{ alignSelf: 'end' }}>
                  <input type="checkbox" checked={f.notifyOnSuccess} onChange={(e) => set('notifyOnSuccess', e.target.checked)} />
                  <span>Also notify on success</span>
                </label>
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
                      {f.databases.trim() || 'all databases'}
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
                <dt>Destination</dt>
                <dd className="mono">
                  {dest ? `${dest.name} · ${dest.prefix || ''}${target.cluster_name}/${target.namespace}/${target.service}/${target.engine}/` : '—'}
                </dd>
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
                    {(run.status === 'queued' || run.status === 'running') && (
                      <li className="chk">
                        <Spinner label="Dry run in progress" />
                        <span className="muted">In progress…</span>
                      </li>
                    )}
                  </ul>
                )}
                {run?.status === 'failed' && <p className="field-error">Fix the problem (credentials in step 2, destination in step 3), then run the dry run again.</p>}
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
