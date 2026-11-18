import { useMemo, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { AuditClusterRun, AuditClusterSummary, AuditRun, AuditSchedule, AuditScheduleInput, AuditTool, BenchNode, Channel, Cluster, Finding, ItemList } from '../api/types';
import { useCan } from '../auth/me';
import { CRON_PRESETS, describeCron, validateCron } from '../lib/cron';
import { age, dateTime, duration, plural } from '../lib/format';
import { matchesSelector } from '../lib/sas';
import { auditRoute } from '../router';
import { AuditRunDialog, FailedRunButton } from '../ui/AuditRunDialog';
import { BenchNodeDialog } from '../ui/BenchNodeDialog';
import { CLUSTER_LABEL, ClusterOverview, ScopeCrumbs, findCluster, resolveScope, useClusterList, type ClusterInfo, type OverviewRow, type Scope } from '../ui/clusterScope';
import { Badge, EmptyState, Field, FormError, Modal, QueryView, aria, fieldError, useToast } from '../ui/kit';
import { PageHead, SeverityBadge } from '../ui/status';
import { Select } from '../ui/Select';
import { ScopeInput } from '../ui/TagInput';
import { DataTable, type Column } from '../ui/DataTable';

const TOOL_LABEL: Record<string, string> = { kubescape: 'Kubescape', polaris: 'Polaris', 'kube-bench': 'kube-bench' };

function LastResult({ r, onOpen }: { r: Pick<AuditRun, 'id' | 'status' | 'error' | 'tool' | 'cluster_name' | 'new_findings' | 'resolved_findings'> | null | undefined; onOpen: (id: string) => void }) {
  if (!r) return <Badge tone="mute">Not run yet</Badge>;
  if (r.status === 'failed') return <FailedRunButton run={r} onOpen={onOpen} />;
  if (r.status === 'running' || r.status === 'queued') return <Badge tone="info">{r.status === 'running' ? 'Running' : 'Queued'}</Badge>;
  if (r.new_findings > 0) return <Badge tone="warn">+{r.new_findings} new failed</Badge>;
  if (r.resolved_findings > 0) return <Badge tone="ok">−{r.resolved_findings} resolved</Badge>;
  return <Badge tone="ok">No change</Badge>;
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function ksColumns(oneCluster: boolean, onOpen: (id: string) => void): Column<AuditRun>[] {
  return [
    {
      id: 'run',
      header: 'Run',
      sortValue: (r) => r.started_at,
      defaultDir: 'desc',
      cell: (r) => (
        <span className="inline-sm">
          <span className="mono">{dateTime(r.started_at)}</span>
          {r.status === 'failed' ? <FailedRunButton run={r} onOpen={onOpen} compact /> : r.status !== 'succeeded' ? <Badge tone="info">{r.status}</Badge> : null}
        </span>
      ),
    },
    { id: 'cluster', header: 'Cluster', hidden: oneCluster, sortValue: (r) => r.cluster_name, className: 'mono', cell: (r) => r.cluster_name },
    { id: 'score', header: 'Score', align: 'num', sortValue: (r) => r.score, defaultDir: 'desc', cell: (r) => (r.score != null ? `${r.score.toFixed(1)}%` : '—') },
    { id: 'new', header: 'New', align: 'num', sortValue: (r) => r.new_findings, defaultDir: 'desc', className: (r) => (r.new_findings > 0 ? 'up' : undefined), cell: (r) => (r.new_findings > 0 ? `+${r.new_findings}` : 0) },
    { id: 'resolved', header: 'Resolved', align: 'num', sortValue: (r) => r.resolved_findings, defaultDir: 'desc', className: (r) => (r.resolved_findings > 0 ? 'down' : undefined), cell: (r) => (r.resolved_findings > 0 ? `−${r.resolved_findings}` : 0) },
  ];
}

function findingColumns(oneCluster: boolean): Column<Finding>[] {
  return [
    {
      id: 'control',
      header: 'Control',
      sortValue: (f) => f.control_id,
      className: 'wrap',
      cell: (f) => (
        <>
          <span className="mono">{f.control_id}</span> {f.title}
        </>
      ),
    },
    { id: 'sev', header: 'Severity', sortValue: (f) => SEV_ORDER.indexOf(f.severity), cell: (f) => <SeverityBadge s={f.severity} /> },
    { id: 'cluster', header: 'Cluster', hidden: oneCluster, sortValue: (f) => f.cluster_name, className: 'mono', cell: (f) => f.cluster_name },
    { id: 'res', header: 'Resource', sortValue: (f) => f.resource_ref, className: 'mono wrap break', cell: (f) => f.resource_ref },
  ];
}

function benchColumns(r: AuditRun, oneCluster: boolean): Column<BenchNode>[] {
  const ran = (n: BenchNode) => n.state === 'done' || n.state === 'succeeded';
  return [
    { id: 'node', header: 'Node', sortValue: (n) => n.node_name, className: 'mono', cell: (n) => n.node_name },
    { id: 'cluster', header: 'Cluster', hidden: oneCluster, sortValue: (n) => n.cluster_name ?? r.cluster_name, className: 'mono', cell: (n) => n.cluster_name ?? r.cluster_name },
    {
      id: 'bench',
      header: 'Benchmark',
      sortValue: (n) => n.benchmark,
      cell: (n) => (
        <span className="inline-sm">
          <span className="mono">
            {n.benchmark}
            {n.control_plane_na ? ' (auto)' : ''}
          </span>
          {n.control_plane_na && <Badge tone="mute">Control plane N/A · managed</Badge>}
        </span>
      ),
    },
    { id: 'pass', header: 'Pass', align: 'num', sortValue: (n) => (ran(n) ? n.pass : null), defaultDir: 'desc', className: (n) => (ran(n) ? undefined : 'muted'), cell: (n) => (ran(n) ? n.pass : '—') },
    { id: 'fail', header: 'Fail', align: 'num', sortValue: (n) => (ran(n) ? n.fail : null), defaultDir: 'desc', className: (n) => (ran(n) ? (n.fail > 0 ? 'up' : undefined) : 'muted'), cell: (n) => (ran(n) ? n.fail : '—') },
    { id: 'warn', header: 'Warn', align: 'num', sortValue: (n) => (ran(n) ? n.warn : null), defaultDir: 'desc', className: (n) => (ran(n) ? undefined : 'muted'), cell: (n) => (ran(n) ? n.warn : '—') },
    {
      id: 'job',
      header: 'Job',
      sortValue: (n) => n.state,
      cell: (n) =>
        ran(n) ? (
          <Badge tone="ok">Done{n.duration_s ? ` · ${duration(n.duration_s)}` : ''} · cleaned up</Badge>
        ) : n.state === 'running' ? (
          <Badge tone="info">Running</Badge>
        ) : (
          <Badge tone="crit">
            {n.state === 'skipped' ? 'Skipped' : 'Failed'}
            {n.message ? ` · ${n.message}` : ''}
          </Badge>
        ),
    },
  ];
}

/** Latest run of one tool in a cluster summary row. */
function ToolCell({ run, onOpen, enabled = true, cluster = '' }: { run: AuditClusterRun | undefined; onOpen: (id: string) => void; enabled?: boolean; cluster?: string }) {
  if (!enabled) return <Badge tone="mute">Not enabled</Badge>;
  if (!run) return <span className="muted">Not run</span>;
  if (run.status === 'failed') return <FailedRunButton run={{ id: run.run_id, error: '', tool: run.tool, cluster_name: cluster }} onOpen={onOpen} compact />;
  if (run.status === 'running' || run.status === 'queued') return <Badge tone="info">{run.status === 'running' ? 'Running' : 'Queued'}</Badge>;
  return (
    <>
      <span className="n">{run.score != null ? `${run.score.toFixed(1)}%` : 'Done'}</span>
      <div className="muted small">
        {run.new_findings > 0 ? <span className="ico-warn">+{run.new_findings} new</span> : 'no new'}
        {run.finished_at ? ` · ${age(run.finished_at)} ago` : ''}
      </div>
    </>
  );
}

function OpenFindings({ f }: { f: AuditClusterSummary['open_findings'] }) {
  const parts = (['critical', 'high', 'medium', 'low'] as const).filter((s) => f[s] > 0);
  if (!parts.length) return <Badge tone="ok">None open</Badge>;
  return (
    <span className="sev-chips">
      {parts.map((s) => (
        <Badge key={s} tone={s === 'critical' || s === 'high' ? 'crit' : s === 'medium' ? 'warn' : 'info'}>
          {f[s]} {s}
        </Badge>
      ))}
    </span>
  );
}

export function AuditPage() {
  const search = auditRoute.useSearch();
  const navigate = useNavigate({ from: '/audit' });
  const scope = resolveScope(search.cluster);
  const { list: clusters, q: clustersQ } = useClusterList();
  const openRun = (id: string) => navigate({ search: (s) => ({ ...s, run: id }) });
  return (
    <>
      {scope.mode === 'overview' ? <AuditOverview clusters={clusters} clustersLoading={clustersQ.isPending} openRun={openRun} /> : <AuditDetail scope={scope} clusters={clusters} openRun={openRun} />}
      {search.run && <AuditRunDialog id={search.run} onClose={() => navigate({ search: (s) => ({ ...s, run: undefined }) })} />}
    </>
  );
}

function useAuditBasics() {
  const qc = useQueryClient();
  const toast = useToast();
  const schedQ = useQuery({ queryKey: ['audit-schedules'], queryFn: () => api.get<ItemList<AuditSchedule>>('/audit/schedules') });
  const clustersQ = useQuery({ queryKey: ['clusters'], queryFn: () => api.get<ItemList<Cluster>>('/clusters') });
  const chanQ = useQuery({ queryKey: ['channels'], queryFn: () => api.get<ItemList<Channel>>('/notifications/channels') });
  const runNow = useMutation({
    mutationFn: ({ s, cluster }: { s: AuditSchedule; cluster?: string }) => api.post<ItemList<AuditRun>>(`/audit/schedules/${s.id}/run`, cluster ? { cluster_id: cluster } : {}),
    onSuccess: (r, { s }) => {
      toast(`${TOOL_LABEL[s.tool]}: ${plural(r.items.length, 'run')} queued.`);
      void qc.invalidateQueries({ queryKey: ['audit-schedules'] });
      void qc.invalidateQueries({ queryKey: ['audit-runs'] });
      void qc.invalidateQueries({ queryKey: ['audit-clusters'] });
    },
    onError: (e) => toast(`Could not start the run: ${errorMessage(e)}`, 'crit'),
  });
  const clusters = (clustersQ.data?.items ?? []).filter((c) => c.status !== 'revoked');
  return { schedQ, clustersQ, chanQ, runNow, clusters };
}

function NewScheduleAction({ onClick }: { onClick: () => void }) {
  return (
    <button type="button" className="btn pri" onClick={onClick}>
      New schedule
    </button>
  );
}

function SchedulesCard({
  schedQ,
  clusters,
  scoped,
  lastRun,
  canOperate,
  onRun,
  running,
  onOpenRun,
  channels,
  pinned,
}: {
  schedQ: ReturnType<typeof useQuery<ItemList<AuditSchedule>>>;
  clusters: Cluster[];
  /** One cluster: only schedules whose scope matches it. */
  scoped?: Cluster;
  lastRun: (s: AuditSchedule) => Pick<AuditRun, 'id' | 'status' | 'error' | 'tool' | 'cluster_name' | 'new_findings' | 'resolved_findings'> | null | undefined;
  canOperate: boolean;
  onRun: (s: AuditSchedule) => void;
  running: boolean;
  onOpenRun: (id: string) => void;
  channels: Channel[];
  /** Cluster page: its name (null while loading), so a schedule pinned to it keeps its scope locked when edited. */
  pinned?: string | null;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<AuditSchedule | null>(null);
  const [deleting, setDeleting] = useState<AuditSchedule | null>(null);
  const del = useMutation({
    mutationFn: (s: AuditSchedule) => api.del(`/audit/schedules/${s.id}`),
    onSuccess: (_r, s) => {
      toast(`${TOOL_LABEL[s.tool]} schedule deleted.`);
      setDeleting(null);
      void qc.invalidateQueries({ queryKey: ['audit-schedules'] });
      void qc.invalidateQueries({ queryKey: ['audit-clusters'] });
    },
  });
  const benchOn = clusters.filter((c) => c.bench_enabled);
  const scopeText = (s: AuditSchedule) => {
    const sel = s.scope_selector || 'all';
    if (scoped) return sel === 'all' ? 'Every cluster' : <span className="mono">{sel}</span>;
    const n = s.tool === 'kube-bench' ? benchOn.filter((c) => matchesSelector(sel, c.labels)).length : s.clusters;
    if (s.tool === 'kube-bench') return `${plural(n, 'opted-in cluster')} · all nodes`;
    return sel === 'all' ? (
      `All ${plural(n, 'cluster')}`
    ) : (
      <>
        <span className="mono">{sel}</span> ({n})
      </>
    );
  };
  const applies = (s: AuditSchedule) => !scoped || (matchesSelector(s.scope_selector || 'all', scoped.labels) && (s.tool !== 'kube-bench' || scoped.bench_enabled));
  return (
    <section className="card" aria-labelledby="sched-t">
      <div className="card-head">
        <div>
          <h2 id="sched-t">Schedules</h2>
          {scoped && <div className="desc">Schedules whose scope includes {scoped.name}; the last result is this cluster’s.</div>}
        </div>
      </div>
      <QueryView
        q={schedQ}
        what="audit schedules"
        isEmpty={(d) => d.items.filter(applies).length === 0}
        empty={
          <EmptyState title={scoped ? 'No schedule covers this cluster' : 'No audit schedules yet'}>
            {scoped ? 'Add a schedule whose scope matches its labels, or an "all clusters" schedule.' : 'Add a schedule for Kubescape (NSA, CIS, MITRE), Polaris or kube-bench. Kubescape and Polaris run on the server through the agent’s read-only API proxy.'}
          </EmptyState>
        }
      >
        {(d) => (
          <div className="table-wrap">
            <table className="t sched-t">
              <thead>
                <tr>
                  <th>Check</th>
                  <th>Framework</th>
                  <th>Scope</th>
                  <th>Schedule</th>
                  <th>Runs how</th>
                  <th>Last result</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {d.items.filter(applies).map((s) => (
                  <tr key={s.id}>
                    <td>
                      {TOOL_LABEL[s.tool] ?? s.tool}
                      {!s.enabled && (
                        <>
                          {' '}
                          <Badge tone="mute">Paused</Badge>
                        </>
                      )}
                    </td>
                    <td className="mono">{s.tool === 'kubescape' ? (s.frameworks ?? []).map((f) => f.toUpperCase()).join(', ') || 'NSA' : s.tool === 'polaris' ? 'Best practices' : 'CIS (auto per provider)'}</td>
                    <td>{scopeText(s)}</td>
                    <td className="mono">{describeCron(s.cron ?? '')}</td>
                    <td>{s.tool === 'kube-bench' ? <Badge tone="warn">Node Job · opt-in</Badge> : <Badge tone="ok">Remote via agent</Badge>}</td>
                    <td className="last-cell">
                      <LastResult r={lastRun(s)} onOpen={onOpenRun} />
                    </td>
                    <td className="actions">
                      {canOperate && (
                        <span className="inline-sm">
                          <button type="button" className="btn sm" onClick={() => onRun(s)} disabled={running} aria-label={`Run ${TOOL_LABEL[s.tool]} now${scoped ? ` on ${scoped.name}` : ''}`}>
                            Run now
                          </button>
                          <button type="button" className="btn sm" onClick={() => setEditing(s)} aria-label={`Edit ${TOOL_LABEL[s.tool]} schedule`}>
                            Edit
                          </button>
                          <button type="button" className="btn sm danger" onClick={() => setDeleting(s)} aria-label={`Delete ${TOOL_LABEL[s.tool]} schedule`}>
                            Delete
                          </button>
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </QueryView>
      <div className="card-foot">
        kube-bench must read node files, so it is the one check that runs as a Job on each node. It is off until enabled per cluster with the agent Helm value <span className="mono">bench.enabled</span>.
      </div>
      {editing && pinned !== null && <ScheduleDialog editing={editing} onClose={() => setEditing(null)} channels={channels} clusters={clusters} pinned={pinned && editing.scope_selector === `${CLUSTER_LABEL}=${pinned}` ? pinned : undefined} />}
      {deleting && (
        <Modal open onClose={() => setDeleting(null)} size="narrow" danger eyebrow="Audit" title={`Delete the ${TOOL_LABEL[deleting.tool]} schedule?`} description={`Scope ${deleting.scope_selector || 'all'} · ${describeCron(deleting.cron ?? '')}. Run history and findings are kept; queued runs are cancelled.`}>
          <FormError error={del.error} />
          <div className="end">
            <button type="button" className="btn" onClick={() => setDeleting(null)}>
              Cancel
            </button>
            <button type="button" className="btn danger" onClick={() => del.mutate(deleting)} disabled={del.isPending}>
              Delete schedule
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}

function ActivityCard() {
  return (
    <section className="card pad spread">
      <div>
        <h2>Platform activity</h2>
        <p className="muted" style={{ margin: '4px 0 0', fontSize: 13 }}>
          Logins, grants, change requests and drift findings, append-only.
        </p>
      </div>
      <Link to="/activity" className="btn">
        Open activity log
      </Link>
    </section>
  );
}

// ------------------------------------------------------------ overview

function AuditOverview({ clusters, clustersLoading, openRun }: { clusters: ClusterInfo[]; clustersLoading: boolean; openRun: (id: string) => void }) {
  const navigate = useNavigate({ from: '/audit' });
  const canOperate = useCan('operate');
  const [creating, setCreating] = useState(false);
  const { schedQ, chanQ, runNow, clusters: allClusters } = useAuditBasics();
  const q = useQuery({ queryKey: ['audit-clusters'], queryFn: () => api.get<ItemList<AuditClusterSummary>>('/audit/clusters') });
  const run = (r: AuditClusterSummary, tool: string) => r.last_runs.find((x) => x.tool === tool);
  const columns: Column<OverviewRow<AuditClusterSummary>>[] = [
    { id: 'kubescape', header: 'Kubescape', sortValue: (r) => run(r, 'kubescape')?.score ?? (run(r, 'kubescape')?.status === 'failed' ? -1 : null), cell: (r) => <ToolCell run={run(r, 'kubescape')} onOpen={openRun} cluster={r.cluster_name} /> },
    { id: 'polaris', header: 'Polaris', sortValue: (r) => run(r, 'polaris')?.score ?? null, cell: (r) => <ToolCell run={run(r, 'polaris')} onOpen={openRun} cluster={r.cluster_name} /> },
    { id: 'bench', header: 'kube-bench', sortValue: (r) => (r.bench_enabled ? (run(r, 'kube-bench')?.score ?? 0) : null), cell: (r) => <ToolCell run={run(r, 'kube-bench')} onOpen={openRun} enabled={r.bench_enabled} cluster={r.cluster_name} /> },
    {
      id: 'findings',
      header: 'Open findings',
      sortValue: (r) => r.open_findings.critical * 1e6 + r.open_findings.high * 1e4 + r.open_findings.medium * 100 + r.open_findings.low,
      defaultDir: 'desc',
      className: 'wrap',
      cell: (r) => <OpenFindings f={r.open_findings} />,
    },
  ];
  const failed = (q.data?.items ?? []).filter((r) => r.last_runs.some((x) => x.status === 'failed')).length;
  return (
    <>
      <PageHead title="Audit" sub="Scheduled checks with full history, per cluster. What matters is what changed since the last run." actions={canOperate && <NewScheduleAction onClick={() => setCreating(true)} />} />
      {failed > 0 && (
        <div className="note crit" role="note">
          <b>{plural(failed, 'cluster')} with a failed last run.</b> Open “Failed” to see the reason and the tool’s log.
        </div>
      )}
      <ClusterOverview<AuditClusterSummary>
        label="Audit by cluster"
        what="audit-clusters"
        rows={q.data?.items}
        clusters={clusters}
        loading={q.isPending || clustersLoading}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        columns={columns}
        onOpen={(id) => navigate({ search: { cluster: id } })}
        onAll={() => navigate({ search: { cluster: 'all' } })}
        initialSort={{ id: 'findings', dir: 'desc' }}
        intro="Latest Kubescape, Polaris and kube-bench result per cluster, and its open findings."
      />
      <SchedulesCard
        schedQ={schedQ}
        clusters={allClusters}
        lastRun={(s) => s.last_run}
        canOperate={canOperate}
        onRun={(s) => runNow.mutate({ s })}
        running={runNow.isPending}
        onOpenRun={openRun}
        channels={chanQ.data?.items ?? []}
      />
      <ActivityCard />
      {creating && <ScheduleDialog onClose={() => setCreating(false)} channels={chanQ.data?.items ?? []} clusters={allClusters} />}
    </>
  );
}

// ------------------------------------------------------------ one cluster / all clusters

function AuditDetail({ scope, clusters, openRun }: { scope: Exclude<Scope, { mode: 'overview' }>; clusters: ClusterInfo[]; openRun: (id: string) => void }) {
  const navigate = useNavigate({ from: '/audit' });
  const canOperate = useCan('operate');
  const [creating, setCreating] = useState(false);
  const [benchNode, setBenchNode] = useState<BenchNode | null>(null);
  const { schedQ, chanQ, runNow, clusters: allClusters } = useAuditBasics();
  const one = scope.mode === 'cluster';
  const info = one ? findCluster(clusters, scope.id) : undefined;
  const full = one ? allClusters.find((c) => c.id === info?.id) : undefined;
  const cid = info?.id ?? (one ? scope.id : undefined);
  // A schedule made here is pinned to this cluster, so wait for its name.
  const pinName = info?.name ?? full?.name;
  // every run of this cluster (all tools): history + latest per tool, with the short error
  const runsQ = useQuery({ queryKey: ['audit-runs', { cluster: cid ?? 'all', tool: one ? '' : 'kubescape' }], queryFn: () => api.get<ItemList<AuditRun>>('/audit/runs', { cluster_id: cid, tool: one ? undefined : 'kubescape', limit: 100 }) });
  const runs = runsQ.data?.items ?? [];
  const ksRuns = useMemo(() => runs.filter((r) => r.tool === 'kubescape'), [runs]);
  const latestOf = (tool: string) => runs.find((r) => r.tool === tool);
  const benchRun = one ? latestOf('kube-bench') : undefined;
  const benchQ = useQuery({ queryKey: ['audit-run', benchRun?.id], queryFn: () => api.get<AuditRun>(`/audit/runs/${benchRun!.id}`), enabled: !!benchRun });
  const summaryQ = useQuery({ queryKey: ['audit-clusters'], queryFn: () => api.get<ItemList<AuditClusterSummary>>('/audit/clusters'), enabled: !one });
  const lastKs = one ? ksRuns.find((r) => r.status === 'succeeded') : undefined;
  const newQ = useQuery({
    queryKey: ['findings', one ? { run_id: lastKs?.id, cluster: cid } : { source: 'kubescape', status: 'open' }],
    queryFn: () => (one ? api.get<ItemList<Finding>>('/findings', { run_id: lastKs!.id, cluster: cid, status: 'open', limit: 200 }) : api.get<ItemList<Finding>>('/findings', { source: 'kubescape', status: 'open', limit: 500 })),
    enabled: !one || !!lastKs,
  });
  const channelName = (id: string | null | undefined) => chanQ.data?.items.find((c) => c.id === id)?.name;
  const benchClusters = (summaryQ.data?.items ?? []).filter((r) => r.bench_enabled);

  return (
    <>
      <PageHead
        crumbs={<ScopeCrumbs area="Audit" to="/audit" scope={scope} cluster={info} />}
        title={one ? <span className="mono">{info?.name ?? scope.id}</span> : 'All clusters'}
        sub={one ? `${info ? `${info.provider_label || info.provider} · ` : ''}Scheduled checks of this cluster with full history.` : 'Scheduled checks with full history. What matters is what changed since the last run.'}
        actions={canOperate && (!one || pinName) && <NewScheduleAction onClick={() => setCreating(true)} />}
      />

      <SchedulesCard
        schedQ={schedQ}
        clusters={allClusters}
        scoped={full}
        lastRun={(s) => (one ? latestOf(s.tool) : s.last_run)}
        canOperate={canOperate}
        onRun={(s) => runNow.mutate({ s, cluster: one ? cid : undefined })}
        running={runNow.isPending}
        onOpenRun={openRun}
        channels={chanQ.data?.items ?? []}
        pinned={one ? (pinName ?? null) : undefined}
      />

      <section className="card" aria-labelledby="kb-t">
        <div className="card-head">
          <div>
            <h2 id="kb-t">{one ? 'kube-bench · last run per node' : 'kube-bench · last run per cluster'}</h2>
            <div className="desc">Short-lived Job per node, spec built into the agent, image pinned by digest, host paths read-only</div>
          </div>
          {!one && summaryQ.data && <Badge tone="warn">Exception · enabled on {benchClusters.length} of {summaryQ.data.items.length} clusters</Badge>}
          {one && full && <Badge tone={full.bench_enabled ? 'warn' : 'mute'}>{full.bench_enabled ? 'Exception · enabled on this cluster' : 'Not enabled on this cluster'}</Badge>}
        </div>
        {one ? (
          benchRun ? (
            <QueryView q={benchQ} what="kube-bench results" isEmpty={(r) => !r.bench_nodes?.length} empty={<EmptyState title="No node results in the last run">The run had no nodes in scope.</EmptyState>}>
              {(r) => (
                <>
                  {r.status === 'failed' && (
                    <div className="note crit" style={{ margin: '0 14px 12px' }}>
                      <FailedRunButton run={r} onOpen={openRun} />
                    </div>
                  )}
                  <DataTable
                    label="kube-bench nodes"
                    what="node results"
                    rows={r.bench_nodes!}
                    rowKey={(n) => n.node_name + (n.cluster_name ?? '')}
                    columns={benchColumns(r, true)}
                    initialSort={{ id: 'fail', dir: 'desc' }}
                    onRowClick={(n) => setBenchNode(n)}
                    rowLabel={(n) => `Show kube-bench checks of ${n.node_name}`}
                  />
                </>
              )}
            </QueryView>
          ) : (
            <QueryView q={runsQ} what="kube-bench runs" isEmpty={() => true} empty={<EmptyState title="kube-bench has not run on this cluster">{full && !full.bench_enabled ? <>Enable it with the agent Helm value <span className="mono">bench.enabled=true</span>, then add or run a kube-bench schedule.</> : 'Run the kube-bench schedule now, or wait for its next run.'}</EmptyState>}>
              {() => null}
            </QueryView>
          )
        ) : (
          <DataTable<AuditClusterSummary>
            label="kube-bench per cluster"
            what="kube-bench results"
            rows={summaryQ.data ? benchClusters : undefined}
            loading={summaryQ.isPending}
            error={summaryQ.isError ? summaryQ.error : undefined}
            onRetry={() => summaryQ.refetch()}
            rowKey={(r) => r.cluster_id}
            onRowClick={(r) => navigate({ search: { cluster: r.cluster_id } })}
            rowLabel={(r) => `Open kube-bench results of ${r.cluster_name}`}
            pageSize={10}
            pageSizes={[10, 25, 50]}
            initialSort={{ id: 'score', dir: 'asc' }}
            empty={<EmptyState title="kube-bench is not enabled on any cluster">Enable it on a cluster (Helm value <span className="mono">bench.enabled=true</span>) and add a kube-bench schedule.</EmptyState>}
            columns={[
              { id: 'cluster', header: 'Cluster', sortValue: (r) => r.cluster_name, className: 'mono', cell: (r) => r.cluster_name },
              {
                id: 'status',
                header: 'Last run',
                sortValue: (r) => r.last_runs.find((x) => x.tool === 'kube-bench')?.finished_at ?? null,
                cell: (r) => {
                  const run = r.last_runs.find((x) => x.tool === 'kube-bench');
                  if (!run) return <span className="muted">Not run</span>;
                  if (run.status === 'failed') return <FailedRunButton run={{ id: run.run_id, error: '', tool: run.tool, cluster_name: r.cluster_name }} onOpen={openRun} compact />;
                  if (run.status !== 'succeeded') return <Badge tone="info">{run.status === 'running' ? 'Running' : 'Queued'}</Badge>;
                  return <span className="muted">{run.finished_at ? `${age(run.finished_at)} ago` : 'Done'}</span>;
                },
              },
              { id: 'score', header: 'Pass rate', align: 'num', sortValue: (r) => r.last_runs.find((x) => x.tool === 'kube-bench')?.score ?? null, cell: (r) => { const s = r.last_runs.find((x) => x.tool === 'kube-bench')?.score; return s != null ? `${s.toFixed(1)}%` : '—'; } },
            ]}
          />
        )}
        <div className="card-spacer" />
      </section>

      <div className="cols-2">
        <section className="card" aria-labelledby="ksh-t">
          <div className="card-head">
            <h2 id="ksh-t">Kubescape run history</h2>
          </div>
          <DataTable
            label="Kubescape run history"
            what="Kubescape runs"
            rows={runsQ.data ? ksRuns : undefined}
            loading={runsQ.isPending}
            error={runsQ.isError ? runsQ.error : undefined}
            onRetry={() => runsQ.refetch()}
            rowKey={(r) => r.id}
            columns={ksColumns(one, openRun)}
            onRowClick={(r) => openRun(r.id)}
            rowLabel={(r) => `${r.status === 'failed' ? 'Failed run' : 'Run'} of ${dateTime(r.started_at)}${one ? '' : ` on ${r.cluster_name}`}: show details`}
            pageSize={10}
            pageSizes={[10, 25, 50]}
            initialSort={{ id: 'run', dir: 'desc' }}
            empty={<EmptyState title="No Kubescape runs yet">Runs appear after the first scheduled or manual run.</EmptyState>}
          />
          <div className="card-foot">Raw reports kept in Blob for 400 days. Open a run for its log.</div>
        </section>

        <section className="card" aria-labelledby="new-t">
          <div className="card-head">
            <h2 id="new-t">{one ? `New since last run${lastKs ? ` · ${dateTime(lastKs.started_at).slice(0, 6)}` : ''}` : 'Open Kubescape findings'}</h2>
            {(() => {
              const sched = schedQ.data?.items.find((s) => s.tool === 'kubescape');
              const ch = channelName(sched?.notify_channel_id);
              return ch ? <span className="muted small">sent to {ch}</span> : null;
            })()}
          </div>
          {one && !lastKs ? (
            <EmptyState title="Nothing to compare yet">New findings are listed after a successful Kubescape run.</EmptyState>
          ) : (
            <QueryView q={newQ} what="findings" isEmpty={(d) => d.items.length === 0} empty={<EmptyState title={one ? 'No new findings' : 'No open findings'}>{one ? 'The last run found nothing that was not already open.' : 'Kubescape found nothing open on any cluster.'}</EmptyState>}>
              {(d) => <DataTable label={one ? 'New findings' : 'Open findings'} what="findings" rows={d.items} rowKey={(f) => f.id} columns={findingColumns(one)} pageSize={10} pageSizes={[10, 25, 50]} initialSort={{ id: 'sev', dir: 'asc' }} />}
            </QueryView>
          )}
          <div className="card-spacer" />
        </section>
      </div>

      <ActivityCard />

      {benchNode && <BenchNodeDialog node={benchNode} onClose={() => setBenchNode(null)} />}
      {creating && (!one || pinName) && <ScheduleDialog onClose={() => setCreating(false)} channels={chanQ.data?.items ?? []} clusters={allClusters} pinned={one ? pinName : undefined} />}
    </>
  );
}


/**
 * New or edited audit schedule. `pinned`: opened from a cluster's page, so the scope is that
 * cluster and cannot be changed. The check (tool) of an existing schedule cannot change.
 */
function ScheduleDialog({ onClose, channels, clusters, pinned, editing }: { onClose: () => void; channels: Channel[]; clusters: Cluster[]; pinned?: string; editing?: AuditSchedule }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [tool, setTool] = useState<AuditTool>(editing?.tool ?? 'kubescape');
  const [frameworks, setFrameworks] = useState<Set<'nsa' | 'cis' | 'mitre'>>(new Set(editing?.tool === 'kubescape' && editing.frameworks?.length ? editing.frameworks : ['nsa', 'cis', 'mitre']));
  const [scope, setScope] = useState(pinned ? `${CLUSTER_LABEL}=${pinned}` : editing && editing.scope_selector !== 'all' ? (editing.scope_selector ?? '') : '');
  const [scopeDraftErr, setScopeDraftErr] = useState<string | null>(null);
  const [cron, setCron] = useState(editing?.cron ?? '0 4 * * *');
  const [notify, setNotify] = useState(editing?.notify_channel_id ?? '');
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const cronErr = validateCron(cron);
  const create = useMutation({
    mutationFn: (b: AuditScheduleInput) => (editing ? api.patch<AuditSchedule>(`/audit/schedules/${editing.id}`, b) : api.post<AuditSchedule>('/audit/schedules', b)),
    onSuccess: () => {
      toast(editing ? 'Audit schedule saved.' : 'Audit schedule created.');
      void qc.invalidateQueries({ queryKey: ['audit-schedules'] });
      onClose();
    },
  });
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (cronErr || scopeDraftErr) return;
    const body: AuditScheduleInput = { frameworks: tool === 'kubescape' ? [...frameworks] : [], scope_selector: scope.trim() || 'all', cron, timezone: editing?.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone, enabled, notify_channel_id: notify || null };
    create.mutate(editing ? body : { ...body, tool });
  };
  return (
    <Modal open onClose={onClose} eyebrow="Audit" title={editing ? `Edit ${TOOL_LABEL[editing.tool]} schedule` : 'New audit schedule'}>
      <form onSubmit={submit} className="stack-sm" style={{ gap: 18 }} noValidate>
        <fieldset className="opts" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
          <legend className="lbl">Check</legend>
          {(['kubescape', 'polaris', 'kube-bench'] as AuditTool[]).map((t) => (
            <label className="opt" key={t}>
              <input type="radio" name="tool" checked={tool === t} onChange={() => setTool(t)} disabled={!!editing && t !== tool} />
              <span>
                <span className="t1">{TOOL_LABEL[t]}</span>
                <span className="t2">{t === 'kube-bench' ? 'Job per node, opt-in clusters' : 'Remote via agent API proxy'}</span>
              </span>
            </label>
          ))}
        </fieldset>
        {tool === 'kubescape' && (
          <fieldset className="plain">
            <legend className="lbl">Frameworks</legend>
            <div className="inline">
              {(['nsa', 'cis', 'mitre'] as const).map((f) => (
                <label className="chk" key={f}>
                  <input
                    type="checkbox"
                    checked={frameworks.has(f)}
                    onChange={(e) =>
                      setFrameworks((p) => {
                        const n = new Set(p);
                        if (e.target.checked) n.add(f);
                        else n.delete(f);
                        return n;
                      })
                    }
                  />
                  {f.toUpperCase()}
                </label>
              ))}
            </div>
          </fieldset>
        )}
        <div className="grid-2">
          <Field label="Scope (cluster labels)" htmlFor="as-scope" error={fieldError(create.error, 'scope_selector')} hint={pinned ? undefined : 'No labels = all clusters'}>
            <ScopeInput
              id="as-scope"
              value={scope}
              onChange={setScope}
              clusters={clusters}
              error={fieldError(create.error, 'scope_selector')}
              hintId="as-scope-hint"
              onDraftError={setScopeDraftErr}
              locked={
                pinned && (
                  <>
                    Only {pinned}. For other clusters, create it from{' '}
                    <Link to="/audit" onClick={onClose}>
                      Audit
                    </Link>
                    .
                  </>
                )
              }
            />
          </Field>
          <Field label="Cron" htmlFor="as-cron" error={cronErr ?? fieldError(create.error, 'cron')} hint={!cronErr ? describeCron(cron) : undefined}>
            <input className="in mono" {...aria('as-cron', cronErr ?? undefined, !cronErr)} value={cron} onChange={(e) => setCron(e.target.value)} />
          </Field>
        </div>
        <div className="pills" role="group" aria-label="Schedule presets">
          {CRON_PRESETS.map((p) => (
            <button key={p.id} type="button" className="pill" aria-pressed={cron === p.cron} onClick={() => setCron(p.cron)}>
              {p.label}
            </button>
          ))}
        </div>
        <Field label="Notify" htmlFor="as-nc">
          <Select id="as-nc" value={notify} onChange={setNotify} options={[{ value: '', label: 'Default routing' }, ...channels.map((c) => ({ value: c.id, label: c.name }))]} />
        </Field>
        {editing && (
          <label className="chk">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enabled (unchecked pauses the schedule; manual runs still work)
          </label>
        )}
        <FormError error={create.error} />
        <div className="end">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn pri" disabled={create.isPending || !!cronErr || (tool === 'kubescape' && frameworks.size === 0)}>
            {editing ? 'Save changes' : 'Create schedule'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
