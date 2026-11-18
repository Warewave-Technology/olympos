import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { BackupJob, BackupRun, ItemList, Target } from '../api/types';
import { useCan } from '../auth/me';
import { describeCron } from '../lib/cron';
import { between, bytes, duration, engineLabel, money, relDateTime } from '../lib/format';
import { backupsRoute } from '../router';
import { Badge, EmptyState, QueryView, Tabs, useToast } from '../ui/kit';
import { PageHead, RunBadge, TlsBadge } from '../ui/status';
import { Select } from '../ui/Select';
import { DataTable, type Column } from '../ui/DataTable';

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
  return <Badge tone="ok">{describeCron(j.cron)}</Badge>;
}

export function BackupsPage() {
  const { tab = 'candidates' } = backupsRoute.useSearch();
  const navigate = useNavigate({ from: '/backups' });
  const [engine, setEngine] = useState('');
  const canOperate = useCan('operate');

  const candQ = useQuery({
    queryKey: ['targets', { status: 'candidate', engine }],
    queryFn: () => api.get<ItemList<Target>>('/targets', { status: 'candidate', engine }),
  });
  const jobsQ = useQuery({ queryKey: ['backup-jobs'], queryFn: () => api.get<ItemList<BackupJob>>('/backup/jobs') });
  const candidates = (candQ.data?.items ?? []).filter((t) => t.engine !== '');

  return (
    <>
      <PageHead
        title="Backups"
        sub="Jobs run from the server, through the agent tunnel. Credentials never enter the cluster."
        actions={
          <Link to="/settings/destinations" className="btn">
            Destinations
          </Link>
        }
      />
      <Tabs<Tab>
        label="Backup sections"
        value={tab}
        onChange={(t) => navigate({ search: { tab: t === 'candidates' ? undefined : t }, replace: true })}
        tabs={[
          {
            id: 'candidates',
            label: (
              <>
                Candidates {candidates.length > 0 && <Badge tone="info">{candidates.length} new</Badge>}
              </>
            ),
          },
          { id: 'jobs', label: 'Jobs' },
          { id: 'runs', label: 'Runs' },
        ]}
      />
      {tab === 'candidates' && <CandidatesTab candQ={candQ} jobsQ={jobsQ} engine={engine} setEngine={setEngine} canOperate={canOperate} />}
      {tab === 'jobs' && <JobsTab jobsQ={jobsQ} canOperate={canOperate} />}
      {tab === 'runs' && <RunsTab />}
    </>
  );
}

type Q<T> = ReturnType<typeof useQuery<T>>;

function CandidatesTab({ candQ, jobsQ, engine, setEngine, canOperate }: { candQ: Q<ItemList<Target>>; jobsQ: Q<ItemList<BackupJob>>; engine: string; setEngine: (e: string) => void; canOperate: boolean }) {
  const jobs = (jobsQ.data?.items ?? []).filter((j) => !engine || j.engine === engine);
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
        isEmpty={(d) => d.items.filter((t) => t.engine).length === 0 && jobs.length === 0}
        empty={
          <EmptyState title="No backup candidates yet">
            Annotate the Service in front of a database with <span className="mono">olympos.io/backup: postgresql</span> (or <span className="mono">clickhouse</span>, <span className="mono">vault</span>). The agent reports it within a minute and it shows up here.
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
                  .filter((t) => t.engine)
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
        <Link to="/backups" search={{ tab: 'runs' }} className="small">
          All runs
        </Link>
      </div>
      <RunsTable limit={5} compact />
      <div className="card-spacer" />
    </section>
  );
}

function JobsTab({ jobsQ, canOperate }: { jobsQ: Q<ItemList<BackupJob>>; canOperate: boolean }) {
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
      searchText: (j) => `${j.target.service} ${j.target.cluster_name} ${j.target.namespace} ${j.engine} ${j.destination.name}`,
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
    { id: 'dest', header: 'Destination', sortValue: (j) => j.destination.name, className: 'mono', cell: (j) => j.destination.name },
    { id: 'next', header: 'Next run', sortValue: (j) => (j.enabled ? j.next_run_at : null), className: 'mono', cell: (j) => (j.enabled && j.next_run_at ? relDateTime(j.next_run_at) : '—') },
    { id: 'last', header: 'Last run', sortValue: (j) => j.last_run?.status ?? null, cell: (j) => (j.last_run ? <RunBadge run={j.last_run} /> : <span className="muted">Never</span>) },
    { id: 'bytes', header: 'Est. monthly transfer', align: 'num', sortValue: (j) => j.estimated_monthly_bytes || null, defaultDir: 'desc', cell: (j) => (j.estimated_monthly_bytes ? bytes(j.estimated_monthly_bytes) : '—') },
    { id: 'cost', header: 'Est. cost', align: 'num', sortValue: (j) => j.estimated_monthly_cost, defaultDir: 'desc', cell: (j) => (j.estimated_monthly_cost != null ? `≈ ${money(j.estimated_monthly_cost)}` : <span className="muted">no rate</span>) },
    { id: 'status', header: 'Status', sortValue: (j) => (j.paused_reason ? 1 : !j.enabled ? 2 : j.last_run && j.last_run.status !== 'succeeded' ? 0 : 3), cell: jobStatus },
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
  const totalBytes = (jobsQ.data?.items ?? []).reduce((s, j) => s + (j.estimated_monthly_bytes || 0), 0);
  const totalCost = (jobsQ.data?.items ?? []).reduce((s, j) => s + (j.estimated_monthly_cost ?? 0), 0);
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
        rows={jobsQ.data?.items}
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

function RunsTab() {
  const [status, setStatus] = useState('');
  return (
    <section className="card" aria-labelledby="runs-t">
      <div className="card-head">
        <h2 id="runs-t">Runs</h2>
        <div className="pills" role="group" aria-label="Filter by result">
          {['', 'succeeded', 'failed', 'missed', 'running'].map((s) => (
            <button key={s} type="button" className="pill" aria-pressed={status === s} onClick={() => setStatus(s)}>
              {s ? s[0].toUpperCase() + s.slice(1) : 'All'}
            </button>
          ))}
        </div>
      </div>
      <RunsTable limit={500} status={status} />
      <div className="card-foot">Runs are append-only. Backups are never deleted by Olympos; retention is enforced by Blob lifecycle rules.</div>
    </section>
  );
}

function RunsTable({ limit, status = '', compact }: { limit: number; status?: string; compact?: boolean }) {
  const q = useQuery({
    queryKey: ['backup-runs', { limit, status }],
    queryFn: () => api.get<ItemList<BackupRun>>('/backup/runs', { limit, status }),
    refetchInterval: 30_000,
  });
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
          {!compact && <span className="mono muted small"> {r.cluster_name}</span>}
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
        </>
      ),
    },
    { id: 'dest', header: 'Destination', sortValue: (r) => r.destination_name || null, cell: (r) => r.destination_name || <span className="muted">—</span> },
    { id: 'size', header: 'Size', align: 'num', sortValue: (r) => r.bytes || null, defaultDir: 'desc', cell: (r) => (r.bytes ? bytes(r.bytes) : '—') },
    { id: 'wire', header: 'On the wire', align: 'num', hidden: compact, sortValue: (r) => r.wire_bytes || null, defaultDir: 'desc', cell: (r) => (r.wire_bytes ? bytes(r.wire_bytes) : '—') },
    { id: 'dur', header: 'Duration', align: 'num', sortValue: (r) => between(r.started_at, r.finished_at), defaultDir: 'desc', cell: (r) => (r.status === 'running' || r.status === 'queued' ? 'in progress' : duration(between(r.started_at, r.finished_at))) },
    { id: 'result', header: 'Result', sortValue: (r) => r.status, cell: (r) => <RunBadge run={r} /> },
  ];
  return (
    <DataTable
      label={compact ? 'Recent runs' : 'Backup runs'}
      what="backup runs"
      rows={q.data?.items}
      loading={q.isPending}
      error={q.isError ? q.error : undefined}
      onRetry={() => q.refetch()}
      rowKey={(r) => r.id}
      columns={columns}
      pageSize={compact ? false : 25}
      stickyHeader={!compact}
      initialSort={{ id: 'started', dir: 'desc' }}
      resetKey={status}
      empty={<EmptyState title={status ? `No ${status} runs` : 'No runs yet'}>{status ? 'Try another filter.' : 'Runs appear here once a job runs on its schedule, or when you start a dry run or a manual run.'}</EmptyState>}
    />
  );
}
