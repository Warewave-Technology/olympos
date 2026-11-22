import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { BackupClusterSummary, BackupJob, BackupRun, ItemList, Target } from '../api/types';
import { useCan } from '../auth/me';
import { describeCron, formatInZone } from '../lib/cron';
import { age, between, bytes, duration, engineLabel, money, plural, relDateTime } from '../lib/format';
import { backupsRoute } from '../router';
import { Badge, EmptyState, QueryView, Tabs, useToast } from '../ui/kit';
import { PageHead, RunBadge, TlsBadge } from '../ui/status';
import { Select } from '../ui/Select';
import { DataTable, type Column } from '../ui/DataTable';
import { SelfBackupCard } from '../ui/SelfBackupCard';
import { TLSNameChanges } from '../ui/TLSNameChanges';
import { BackupRunDialog } from '../ui/BackupRunDialog';
import { GroupName, JobDestination, jobDestinationName } from '../ui/destinations';
import { ClusterOverview, ScopeCrumbs, ClusterOfflineNote, findCluster, resolveScope, scopeParam, useClusterList, type ClusterInfo, type OverviewRow, type Scope } from '../ui/clusterScope';

type Tab = 'candidates' | 'jobs' | 'runs';
const ENGINES = [
  { id: '', label: 'All engines' },
  { id: 'postgresql', label: 'PostgreSQL' },
  { id: 'clickhouse', label: 'ClickHouse' },
  { id: 'vault', label: 'Vault / OpenBao' },
] as const;

function targetEngine(t: Target) {
  return engineLabel(t.engine, t.detected_version, t.vault_provider) + (t.engine === 'vault' ? ' (raft)' : '');
}

function jobStatus(j: BackupJob) {
  if (j.paused_reason) return <Badge tone="warn">Paused · {j.paused_reason === 'target_gone' ? 'target gone' : j.paused_reason}</Badge>;
  if (!j.enabled) return <Badge tone="mute">Disabled</Badge>;
  if (j.last_run && (j.last_run.status === 'failed' || j.last_run.status === 'missed')) return <Badge tone="crit">Last run {j.last_run.status}</Badge>;
  // partial needs attention (a copy is missing) but is not a failure: a restorable backup exists
  if (j.last_run?.status === 'partial') return <Badge tone="warn">Last run partial</Badge>;
  return <Badge tone="ok">{describeCron(j.cron)}</Badge>;
}

export function BackupsPage() {
  const { tab, cluster, self, tls } = backupsRoute.useSearch();
  const scope = resolveScope(cluster, !!tab);
  const { list: clusters, q: clustersQ } = useClusterList();
  return scope.mode === 'overview' ? <BackupsOverview clusters={clusters} clustersLoading={clustersQ.isPending} focusSelf={!!self} focusTLS={!!tls} /> : <BackupsDetail scope={scope} clusters={clusters} />;
}

function DestinationsLink() {
  return (
    <Link to="/settings/destinations" className="btn">
      Destinations
    </Link>
  );
}

function BackupsOverview({ clusters, clustersLoading, focusSelf, focusTLS }: { clusters: ClusterInfo[]; clustersLoading: boolean; focusSelf: boolean; focusTLS: boolean }) {
  const navigate = useNavigate({ from: '/backups' });
  const q = useQuery({ queryKey: ['backup-clusters'], queryFn: () => api.get<ItemList<BackupClusterSummary>>('/backup/clusters') });
  const rows = q.data?.items ?? [];
  const failing = rows.filter((r) => r.last_24h.failed + r.last_24h.missed > 0).length;
  const columns: Column<OverviewRow<BackupClusterSummary>>[] = [
    {
      id: 'jobs',
      header: 'Jobs',
      align: 'num',
      sortValue: (r) => r.jobs,
      defaultDir: 'desc',
      cell: (r) => (
        <>
          <span className="n">{r.jobs}</span>
          {r.jobs > 0 && r.jobs_enabled < r.jobs && <div className="muted small">{r.jobs - r.jobs_enabled} paused</div>}
        </>
      ),
    },
    { id: 'cand', header: 'Candidates', align: 'num', sortValue: (r) => r.candidates, defaultDir: 'desc', cell: (r) => (r.candidates ? <Badge tone="info">{r.candidates} new</Badge> : <span className="muted">0</span>) },
    {
      id: 'day',
      header: 'Last 24 h',
      sortValue: (r) => r.last_24h.failed * 1000 + r.last_24h.missed * 100 + (r.last_24h.partial ?? 0) * 10 - r.last_24h.succeeded,
      defaultDir: 'desc',
      className: 'wrap',
      cell: (r) =>
        r.last_24h.succeeded + r.last_24h.failed + r.last_24h.missed + (r.last_24h.partial ?? 0) === 0 ? (
          <span className="muted">No runs</span>
        ) : (
          <span className="sev-chips">
            {r.last_24h.succeeded > 0 && <Badge tone="ok">{r.last_24h.succeeded} succeeded</Badge>}
            {r.last_24h.failed > 0 && <Badge tone="crit">{r.last_24h.failed} failed</Badge>}
            {r.last_24h.missed > 0 && <Badge tone="crit">{r.last_24h.missed} missed</Badge>}
            {(r.last_24h.partial ?? 0) > 0 && <Badge tone="warn">{r.last_24h.partial} partial</Badge>}
          </span>
        ),
    },
    {
      id: 'success',
      header: 'Last success',
      sortValue: (r) => r.last_success_at,
      defaultDir: 'desc',
      cell: (r) => (r.last_success_at ? <span title={relDateTime(r.last_success_at)}>{age(r.last_success_at)} ago</span> : <span className="muted">{r.jobs ? 'Never' : '—'}</span>),
    },
    { id: 'bytes', header: 'Backed up · 30 d', align: 'num', sortValue: (r) => r.bytes_30d || null, defaultDir: 'desc', cell: (r) => (r.bytes_30d ? bytes(r.bytes_30d) : '—') },
  ];
  return (
    <>
      <PageHead title="Backups" sub="Jobs run on the server and reach targets through the agent tunnel. Credentials are never stored in a cluster or sent to the agent." actions={<DestinationsLink />} />
      {failing > 0 && (
        <div className="note crit" role="note">
          <b>{plural(failing, 'cluster')} with failed or missed runs in the last 24 hours.</b> Open a cluster to see its runs.
        </div>
      )}
      <TLSNameChanges focus={focusTLS} />
      <SelfBackupCard focus={focusSelf} />
      <ClusterOverview<BackupClusterSummary>
        label="Backups by cluster"
        what="backup-clusters"
        rows={q.data?.items}
        clusters={clusters}
        loading={q.isPending || clustersLoading}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        columns={columns}
        onOpen={(id) => navigate({ search: { cluster: id } })}
        onAll={() => navigate({ search: { cluster: 'all' } })}
        initialSort={{ id: 'day', dir: 'desc' }}
        intro="Backup jobs, new candidates and the last 24 hours of runs per cluster."
      />
      <section className="card" aria-labelledby="rr-t">
        <div className="card-head">
          <h2 id="rr-t">Recent runs · all clusters</h2>
          <Link to="/backups" search={{ cluster: 'all', tab: 'runs' }} className="small">
            All runs
          </Link>
        </div>
        <RunsTable limit={8} compact showCluster />
        <div className="card-spacer" />
      </section>
    </>
  );
}

function BackupsDetail({ scope, clusters }: { scope: Exclude<Scope, { mode: 'overview' }>; clusters: ClusterInfo[] }) {
  const { tab = 'candidates' } = backupsRoute.useSearch();
  const navigate = useNavigate({ from: '/backups' });
  const [engine, setEngine] = useState('');
  const canOperate = useCan('operate');
  const one = scope.mode === 'cluster';
  const info = one ? findCluster(clusters, scope.id) : undefined;
  const cid = info?.id ?? (one ? scope.id : undefined);
  const inCluster = (clusterId: string) => !one || clusterId === cid;

  const candQ = useQuery({
    queryKey: ['targets', { status: 'candidate', engine }],
    queryFn: () => api.get<ItemList<Target>>('/targets', { status: 'candidate', engine }),
  });
  const jobsQ = useQuery({ queryKey: ['backup-jobs'], queryFn: () => api.get<ItemList<BackupJob>>('/backup/jobs') });
  const candidates = (candQ.data?.items ?? []).filter((t) => t.engine !== '' && inCluster(t.cluster_id));
  const param = scopeParam(scope);

  return (
    <>
      <PageHead
        crumbs={<ScopeCrumbs area="Backups" to="/backups" scope={scope} cluster={info} />}
        title={one ? <span className="mono">{info?.name ?? scope.id}</span> : 'All clusters'}
        sub="Jobs run on the server and reach targets through the agent tunnel. Credentials are never stored in a cluster or sent to the agent."
        actions={<DestinationsLink />}
      />
      <ClusterOfflineNote cluster={one ? info : undefined} />
      <Tabs<Tab>
        label="Backup sections"
        value={tab}
        onChange={(t) => navigate({ search: { tab: t === 'candidates' ? undefined : t, cluster: param }, replace: true })}
        tabs={[
          {
            id: 'candidates',
            label: <>Candidates {candidates.length > 0 && <Badge tone="info">{candidates.length} new</Badge>}</>,
          },
          { id: 'jobs', label: 'Jobs' },
          { id: 'runs', label: 'Runs' },
        ]}
      />
      {tab === 'candidates' && <CandidatesTab candQ={candQ} jobsQ={jobsQ} engine={engine} setEngine={setEngine} canOperate={canOperate} inCluster={inCluster} clusterName={info?.name} scopeParam={param} />}
      {tab === 'jobs' && <JobsTab jobsQ={jobsQ} canOperate={canOperate} inCluster={inCluster} />}
      {tab === 'runs' && <RunsTab clusterName={one ? (info?.name ?? '\u0000') : undefined} />}
    </>
  );
}

type Q<T> = ReturnType<typeof useQuery<T>>;

function CandidatesTab({
  candQ,
  jobsQ,
  engine,
  setEngine,
  canOperate,
  inCluster,
  clusterName,
  scopeParam: param,
}: {
  candQ: Q<ItemList<Target>>;
  jobsQ: Q<ItemList<BackupJob>>;
  engine: string;
  setEngine: (e: string) => void;
  canOperate: boolean;
  inCluster: (clusterId: string) => boolean;
  clusterName?: string;
  scopeParam?: string;
}) {
  const jobs = (jobsQ.data?.items ?? []).filter((j) => (!engine || j.engine === engine) && inCluster(j.target.cluster_id));
  return (
    <section className="card" aria-labelledby="cand-t">
      <div className="card-head">
        <h2 id="cand-t">Discovered by annotation</h2>
        <div className="inline">
          <span className="mono muted small">olympos.io/backup: postgresql | vault | clickhouse</span>
          <Select id="cand-engine" inline size="sm" aria-label="Engine" value={engine} onChange={setEngine} options={ENGINES.map((e) => ({ value: e.id, label: e.label }))} />
        </div>
      </div>
      <QueryView
        q={candQ}
        what="backup candidates"
        isEmpty={(d) => d.items.filter((t) => t.engine && inCluster(t.cluster_id)).length === 0 && jobs.length === 0}
        empty={
          <EmptyState title={clusterName ? `No backup candidates on ${clusterName} yet` : 'No backup candidates yet'}>
            Annotate the Service in front of a database with <span className="mono">olympos.io/backup: postgresql</span> (or <span className="mono">clickhouse</span>, <span className="mono">vault</span>). The agent
            reports it within a minute and it shows up here.
          </EmptyState>
        }
      >
        {(d) => (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Cluster / namespace</th>
                  <th>Engine</th>
                  <th>TLS</th>
                  <th>Status</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {d.items
                  .filter((t) => t.engine && inCluster(t.cluster_id))
                  .map((t) => (
                    <tr key={t.id}>
                      <td className="mono">{t.service}</td>
                      <td className="mono">
                        {t.cluster_name} / {t.namespace}
                      </td>
                      <td>{targetEngine(t)}</td>
                      <td>
                        <TlsBadge t={t} />
                      </td>
                      <td>
                        <Badge tone="mute">Not configured</Badge>
                      </td>
                      <td className="actions">
                        {canOperate && (
                          <Link to="/backups/new" search={{ target: t.id }} className="btn sm pri" aria-label={`Configure backup for ${t.service}`}>
                            Configure
                          </Link>
                        )}
                      </td>
                    </tr>
                  ))}
                {jobs.map((j) => (
                  <tr key={j.id}>
                    <td className="mono">{j.target.service}</td>
                    <td className="mono">
                      {j.target.cluster_name} / {j.target.namespace}
                    </td>
                    <td>{targetEngine(j.target)}</td>
                    <td>
                      <TlsBadge t={j.target} />
                    </td>
                    <td>{jobStatus(j)}</td>
                    <td className="actions">
                      {canOperate && (
                        <Link to="/backups/new" search={{ job: j.id }} className="btn sm" aria-label={`Edit backup job for ${j.target.service}`}>
                          Edit
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {jobsQ.isError && <p className="card-foot">Configured jobs could not be loaded: {errorMessage(jobsQ.error)}</p>}
          </div>
        )}
      </QueryView>
      <div className="card-head" style={{ paddingTop: 20, paddingBottom: 8 }}>
        <h2>Recent runs</h2>
        <Link to="/backups" search={{ tab: 'runs', cluster: param }} className="small">
          All runs
        </Link>
      </div>
      <RunsTable limit={clusterName ? 500 : 5} show={5} compact clusterName={clusterName} />
      <div className="card-spacer" />
    </section>
  );
}

function JobsTab({ jobsQ, canOperate, inCluster }: { jobsQ: Q<ItemList<BackupJob>>; canOperate: boolean; inCluster: (clusterId: string) => boolean }) {
  const jobs = jobsQ.data ? jobsQ.data.items.filter((j) => inCluster(j.target.cluster_id)) : undefined;
  const qc = useQueryClient();
  const toast = useToast();
  const runNow = useMutation({
    mutationFn: (id: string) => api.post<BackupRun>(`/backup/jobs/${id}/run`, { trigger: 'manual' }),
    onSuccess: () => {
      toast('Manual run queued.');
      void qc.invalidateQueries({ queryKey: ['backup-runs'] });
    },
    onError: (e) => toast(`Could not queue the run: ${errorMessage(e)}`, 'crit'),
  });
  const toggle = useMutation({
    mutationFn: (j: BackupJob) => api.patch<BackupJob>(`/backup/jobs/${j.id}`, { enabled: !j.enabled }),
    onSuccess: (j) => {
      toast(j.enabled ? 'Backup job enabled.' : 'Backup job paused.');
      void qc.invalidateQueries({ queryKey: ['backup-jobs'] });
    },
    onError: (e) => toast(`Could not change the job: ${errorMessage(e)}`, 'crit'),
  });
  const [text, setText] = useState('');
  const jobColumns: Column<BackupJob>[] = [
    {
      id: 'target',
      header: 'Target',
      sortValue: (j) => j.target.service,
      searchText: (j) => `${j.target.service} ${j.target.cluster_name} ${j.target.namespace} ${j.engine} ${jobDestinationName(j)}`,
      cell: (j) => (
        <>
          <div className="mono">{j.target.service}</div>
          <div className="mono muted small">
            {j.target.cluster_name} / {j.target.namespace} · {engineLabel(j.engine)}
          </div>
        </>
      ),
    },
    {
      id: 'cron',
      header: 'Schedule',
      sortValue: (j) => j.cron,
      cell: (j) => (
        <>
          <span className="mono">{j.cron}</span> <span className="muted small">{j.timezone}</span>
        </>
      ),
    },
    { id: 'dest', header: 'Destination', sortValue: (j) => jobDestinationName(j), cell: (j) => <JobDestination job={j} /> },
    { id: 'next', header: 'Next run', sortValue: (j) => (j.enabled ? j.next_run_at : null), className: 'mono', cell: (j) => (j.enabled && j.next_run_at ? formatInZone(j.next_run_at, j.timezone) : '—') },
    { id: 'last', header: 'Last run', sortValue: (j) => j.last_run?.status ?? null, cell: (j) => (j.last_run ? <RunBadge run={j.last_run} /> : <span className="muted">Never</span>) },
    {
      id: 'bytes',
      header: 'Est. monthly transfer',
      align: 'num',
      sortValue: (j) => j.estimated_monthly_bytes || null,
      defaultDir: 'desc',
      cell: (j) => (j.estimated_monthly_bytes ? bytes(j.estimated_monthly_bytes) : '—'),
    },
    {
      id: 'cost',
      header: 'Est. cost',
      align: 'num',
      sortValue: (j) => j.estimated_monthly_cost,
      defaultDir: 'desc',
      cell: (j) => (j.estimated_monthly_cost != null ? `≈ ${money(j.estimated_monthly_cost)}` : <span className="muted">no rate</span>),
    },
    {
      id: 'status',
      header: 'Status',
      // failed first, then partial (needs attention, not failed), paused, disabled, healthy
      sortValue: (j) => (j.paused_reason ? 2 : !j.enabled ? 3 : j.last_run?.status === 'partial' ? 1 : j.last_run && j.last_run.status !== 'succeeded' ? 0 : 4),
      cell: jobStatus,
    },
    {
      id: 'actions',
      header: 'Actions',
      srOnlyHeader: true,
      align: 'actions',
      hidden: !canOperate,
      cell: (j) => (
        <>
          <button type="button" className="btn sm" onClick={() => runNow.mutate(j.id)} disabled={runNow.isPending || !j.enabled} aria-label={`Run ${j.target.service} now`}>
            Run now
          </button>
          <button type="button" className="btn sm" onClick={() => toggle.mutate(j)} disabled={toggle.isPending}>
            {j.enabled ? 'Pause' : 'Enable'}
          </button>
          <Link to="/backups/new" search={{ job: j.id }} className="btn sm">
            Edit
          </Link>
        </>
      ),
    },
  ];
  const totalBytes = (jobs ?? []).reduce((s, j) => s + (j.estimated_monthly_bytes || 0), 0);
  const totalCost = (jobs ?? []).reduce((s, j) => s + (j.estimated_monthly_cost ?? 0), 0);
  return (
    <section className="card" aria-labelledby="jobs-t">
      <div className="card-head">
        <div>
          <h2 id="jobs-t">Backup jobs</h2>
          {totalBytes > 0 && (
            <div className="desc">
              Est. monthly transfer {bytes(totalBytes)}
              {totalCost > 0 ? ` · ≈ ${money(totalCost)} egress` : ''}
            </div>
          )}
        </div>
        <span>
          <label className="sr-only" htmlFor="jobs-q">
            Search jobs
          </label>
          <input id="jobs-q" type="search" className="in search-sm" placeholder="Search target, cluster, destination…" value={text} onChange={(e) => setText(e.target.value)} />
        </span>
      </div>
      <DataTable
        label="Backup jobs"
        what="backup jobs"
        rows={jobs}
        loading={jobsQ.isPending}
        error={jobsQ.isError ? jobsQ.error : undefined}
        onRetry={() => jobsQ.refetch()}
        rowKey={(j) => j.id}
        filterText={text}
        initialSort={{ id: 'target', dir: 'asc' }}
        empty={
          <EmptyState title="No backup jobs yet">
            Configure one from the <Link to="/backups">Candidates</Link> tab: pick a discovered database, add credentials, a destination and a schedule, then run a dry run.
          </EmptyState>
        }
        columns={jobColumns}
      />
      <div className="card-foot">Estimated transfer = wire bytes of recent runs × runs per month. Cost is shown where the cluster has an egress rate (Settings › Clusters & agents).</div>
    </section>
  );
}

function RunsTab({ clusterName }: { clusterName?: string }) {
  const [status, setStatus] = useState('');
  return (
    <section className="card" aria-labelledby="runs-t">
      <div className="card-head">
        <h2 id="runs-t">Runs</h2>
        <div className="pills" role="group" aria-label="Filter by result">
          {['', 'succeeded', 'partial', 'failed', 'missed', 'running'].map((s) => (
            <button key={s} type="button" className="pill" aria-pressed={status === s} onClick={() => setStatus(s)}>
              {s ? s[0].toUpperCase() + s.slice(1) : 'All'}
            </button>
          ))}
        </div>
      </div>
      <RunsTable limit={500} status={status} clusterName={clusterName} showCluster={!clusterName} />
      <div className="card-foot">Runs are append-only. Backups are never deleted by Olympos; retention is enforced by Blob lifecycle rules.</div>
    </section>
  );
}

function RunsTable({ limit, status = '', compact, clusterName, show, showCluster }: { limit: number; status?: string; compact?: boolean; clusterName?: string; show?: number; showCluster?: boolean }) {
  const q = useQuery({
    queryKey: ['backup-runs', { limit, status }],
    queryFn: () => api.get<ItemList<BackupRun>>('/backup/runs', { limit, status }),
    refetchInterval: 30_000,
  });
  // A run's job targets a group: shared with the Jobs tab (same query), for runs that wrote no copy.
  const jobsQ = useQuery({ queryKey: ['backup-jobs'], queryFn: () => api.get<ItemList<BackupJob>>('/backup/jobs') });
  const groupJobs = new Set((jobsQ.data?.items ?? []).filter((j) => j.destination_group).map((j) => j.id));
  // One copy: destination_name is that member, shown plainly. More, or none on a group job: the group.
  const isGroupRun = (r: BackupRun) => (r.copies?.length ?? 0) > 1 || ((r.copies?.length ?? 0) === 0 && !r.repair_of && groupJobs.has(r.job_id));
  const copiesOk = (r: BackupRun) => (r.copies ?? []).filter((c) => c.status === 'succeeded').length;
  const columns: Column<BackupRun>[] = [
    { id: 'started', header: 'Started', sortValue: (r) => r.started_at ?? r.scheduled_for, defaultDir: 'desc', className: 'mono', cell: (r) => relDateTime(r.started_at ?? r.scheduled_for) },
    {
      id: 'target',
      header: 'Target',
      sortValue: (r) => r.target_service,
      searchText: (r) => `${r.target_service} ${r.cluster_name} ${r.destination_name ?? ''} ${r.error}`,
      cell: (r) => (
        <>
          <span className="mono">{r.target_service}</span>
          {(showCluster ?? !compact) && <span className="mono muted small"> {r.cluster_name}</span>}
          {r.repair_of && (
            <>
              {' '}
              <Badge tone="mute" title="Completes the missing copies of an earlier partial run">
                Repair
              </Badge>
            </>
          )}
        </>
      ),
    },
    {
      id: 'trigger',
      header: 'Trigger',
      hidden: compact,
      sortValue: (r) => r.trigger,
      cell: (r) => (
        <>
          <span className="muted">{r.trigger === 'test' ? 'dry run' : r.trigger}</span>
          {r.tier && r.tier !== 'daily' ? <span className="chip">{r.tier}</span> : null}
          {r.attempt && r.attempt > 1 ? (
            <span className="chip" title="Retried after the agent reconnected">
              attempt {r.attempt}
            </span>
          ) : null}
        </>
      ),
    },
    {
      id: 'dest',
      header: 'Destination',
      sortValue: (r) => r.destination_name || null,
      cell: (r) => (!r.destination_name ? <span className="muted">—</span> : isGroupRun(r) ? <GroupName name={r.destination_name} mono={false} /> : r.destination_name),
    },
    { id: 'size', header: 'Size', align: 'num', sortValue: (r) => r.bytes || null, defaultDir: 'desc', cell: (r) => (r.bytes ? bytes(r.bytes) : '—') },
    { id: 'wire', header: 'On the wire', align: 'num', hidden: compact, sortValue: (r) => r.wire_bytes || null, defaultDir: 'desc', cell: (r) => (r.wire_bytes ? bytes(r.wire_bytes) : '—') },
    {
      id: 'dur',
      header: 'Duration',
      align: 'num',
      sortValue: (r) => between(r.started_at, r.finished_at),
      defaultDir: 'desc',
      cell: (r) => (r.status === 'running' || r.status === 'queued' ? 'in progress' : duration(between(r.started_at, r.finished_at))),
    },
    {
      id: 'result',
      header: 'Result',
      sortValue: (r) => r.status,
      className: 'wrap',
      cell: (r) => (
        <>
          <RunBadge run={r} />
          {(r.copies?.length ?? 0) > 1 && r.status !== 'queued' && r.status !== 'running' && (
            <span className="muted small">
              {' '}
              {copiesOk(r)} of {r.copies!.length} copies
            </span>
          )}
        </>
      ),
    },
  ];
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      {open && <BackupRunDialog id={open} onClose={() => setOpen(null)} />}
      <DataTable
        label={compact ? 'Recent runs' : 'Backup runs'}
        onRowClick={(r) => setOpen(r.id)}
        rowLabel={(r) => `${r.status === 'succeeded' || r.status === 'partial' ? 'Restore commands and details' : 'Details'} of the ${r.target_service} run of ${relDateTime(r.started_at ?? r.scheduled_for)}`}
        what="backup runs"
        rows={q.data ? (clusterName ? q.data.items.filter((r) => r.cluster_name === clusterName) : q.data.items).slice(0, show ?? limit) : undefined}
        loading={q.isPending}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        rowKey={(r) => r.id}
        columns={columns}
        pageSize={compact ? false : 25}
        stickyHeader={!compact}
        initialSort={{ id: 'started', dir: 'desc' }}
        resetKey={status}
        empty={
          <EmptyState title={status ? `No ${status} runs` : 'No runs yet'}>{status ? 'Try another filter.' : 'Runs appear here once a job runs on its schedule, or when you start a dry run or a manual run.'}</EmptyState>
        }
      />
    </>
  );
}
