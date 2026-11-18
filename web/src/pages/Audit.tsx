import { useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import type { AuditRun, AuditSchedule, AuditScheduleInput, AuditTool, Channel, Cluster, Finding, ItemList } from '../api/types';
import { useCan } from '../auth/me';
import { CRON_PRESETS, describeCron, validateCron } from '../lib/cron';
import { dateTime, duration, plural } from '../lib/format';
import { matchesSelector } from '../lib/sas';
import { Badge, EmptyState, Field, FormError, Modal, QueryView, aria, fieldError, useToast } from '../ui/kit';
import { PageHead, SeverityBadge } from '../ui/status';

const TOOL_LABEL: Record<string, string> = { kubescape: 'Kubescape', polaris: 'Polaris', 'kube-bench': 'kube-bench' };

function lastResult(r: AuditRun | null) {
  if (!r) return <Badge tone="mute">Not run yet</Badge>;
  if (r.status === 'failed') return <Badge tone="crit">Failed{r.error ? ` · ${r.error}` : ''}</Badge>;
  if (r.status === 'running' || r.status === 'queued') return <Badge tone="info">{r.status === 'running' ? 'Running' : 'Queued'}</Badge>;
  if (r.new_findings > 0) return <Badge tone="warn">+{r.new_findings} new failed</Badge>;
  if (r.resolved_findings > 0) return <Badge tone="ok">−{r.resolved_findings} resolved</Badge>;
  return <Badge tone="ok">No change</Badge>;
}

export function AuditPage() {
  const canOperate = useCan('operate');
  const qc = useQueryClient();
  const toast = useToast();
  const [creating, setCreating] = useState(false);
  const schedQ = useQuery({ queryKey: ['audit-schedules'], queryFn: () => api.get<ItemList<AuditSchedule>>('/audit/schedules') });
  const clustersQ = useQuery({ queryKey: ['clusters'], queryFn: () => api.get<ItemList<Cluster>>('/clusters') });
  const ksRunsQ = useQuery({ queryKey: ['audit-runs', 'kubescape'], queryFn: () => api.get<ItemList<AuditRun>>('/audit/runs', { tool: 'kubescape', limit: 8 }) });
  const benchRunsQ = useQuery({ queryKey: ['audit-runs', 'kube-bench'], queryFn: () => api.get<ItemList<AuditRun>>('/audit/runs', { tool: 'kube-bench', limit: 1 }) });
  const benchId = benchRunsQ.data?.items[0]?.id;
  const benchQ = useQuery({ queryKey: ['audit-runs', benchId], queryFn: () => api.get<AuditRun>(`/audit/runs/${benchId}`), enabled: !!benchId });
  const lastKs = ksRunsQ.data?.items.find((r) => r.status === 'succeeded');
  const newQ = useQuery({
    queryKey: ['findings', { run_id: lastKs?.id }],
    queryFn: () => api.get<ItemList<Finding>>('/findings', { run_id: lastKs!.id, status: 'open', limit: 20 }),
    enabled: !!lastKs,
  });
  const chanQ = useQuery({ queryKey: ['channels'], queryFn: () => api.get<ItemList<Channel>>('/notifications/channels') });

  const runNow = useMutation({
    mutationFn: (s: AuditSchedule) => api.post<ItemList<AuditRun>>(`/audit/schedules/${s.id}/run`, {}),
    onSuccess: (r, s) => {
      toast(`${TOOL_LABEL[s.tool]}: ${plural(r.items.length, 'run')} queued.`);
      void qc.invalidateQueries({ queryKey: ['audit-schedules'] });
      void qc.invalidateQueries({ queryKey: ['audit-runs'] });
    },
    onError: (e) => toast(`Could not start the run: ${errorMessage(e)}`, 'crit'),
  });

  const clusters = (clustersQ.data?.items ?? []).filter((c) => c.status !== 'revoked');
  const benchOn = clusters.filter((c) => c.bench_enabled).length;
  const scopeText = (s: AuditSchedule) => {
    const sel = s.scope_selector || 'all';
    const n = s.tool === 'kube-bench' ? clusters.filter((c) => c.bench_enabled && matchesSelector(sel, c.labels)).length : s.clusters;
    if (s.tool === 'kube-bench') return `${n} opted-in clusters · all nodes`;
    return sel === 'all' ? `All ${plural(n, 'cluster')}` : (
      <>
        <span className="mono">{sel}</span> ({n})
      </>
    );
  };
  const channelName = (id: string | null | undefined) => chanQ.data?.items.find((c) => c.id === id)?.name;

  return (
    <>
      <PageHead
        title="Audit"
        sub="Scheduled checks with full history. What matters is what changed since the last run."
        actions={
          canOperate && (
            <button type="button" className="btn pri" onClick={() => setCreating(true)}>
              New schedule
            </button>
          )
        }
      />

      <section className="card" aria-labelledby="sched-t">
        <div className="card-head">
          <h2 id="sched-t">Schedules</h2>
        </div>
        <QueryView
          q={schedQ}
          what="audit schedules"
          isEmpty={(d) => d.items.length === 0}
          empty={
            <EmptyState title="No audit schedules yet" action={canOperate ? <button type="button" className="btn pri" onClick={() => setCreating(true)}>New schedule</button> : undefined}>
              Add a schedule for Kubescape (NSA, CIS, MITRE), Polaris or kube-bench. Kubescape and Polaris run on the server through the agent’s read-only API proxy.
            </EmptyState>
          }
        >
          {(d) => (
            <div className="table-wrap">
              <table className="t">
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
                  {d.items.map((s) => (
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
                      <td className="mono wrap">{s.tool === 'kubescape' ? (s.frameworks ?? []).map((f) => f.toUpperCase()).join(', ') || 'NSA' : s.tool === 'polaris' ? 'Best practices' : 'CIS (auto per provider)'}</td>
                      <td className="wrap">{scopeText(s)}</td>
                      <td className="mono">{describeCron(s.cron ?? '')}</td>
                      <td>{s.tool === 'kube-bench' ? <Badge tone="warn">Node Job · opt-in</Badge> : <Badge tone="ok">Remote via agent</Badge>}</td>
                      <td>{lastResult(s.last_run)}</td>
                      <td className="actions">
                        {canOperate && (
                          <button type="button" className="btn sm" onClick={() => runNow.mutate(s)} disabled={runNow.isPending} aria-label={`Run ${TOOL_LABEL[s.tool]} now`}>
                            Run now
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
        <div className="card-foot">
          kube-bench must read node files, so it is the one check that runs as a Job on each node. It is off until enabled per cluster with the agent Helm value <span className="mono">bench.enabled</span>.
        </div>
      </section>

      <section className="card" aria-labelledby="kb-t">
        <div className="card-head">
          <div>
            <h2 id="kb-t">kube-bench · last run per node</h2>
            <div className="desc">Short-lived Job per node, spec built into the agent, image pinned by digest, host paths read-only</div>
          </div>
          {clustersQ.data && <Badge tone="warn">Exception · enabled on {benchOn} of {clusters.length} clusters</Badge>}
        </div>
        {benchId ? (
          <QueryView q={benchQ} what="kube-bench results" isEmpty={(r) => !r.bench_nodes?.length} empty={<EmptyState title="No node results in the last run">The run had no nodes in scope. Check that bench.enabled is set on at least one cluster.</EmptyState>}>
            {(r) => (
              <div className="table-wrap">
                <table className="t">
                  <thead>
                    <tr>
                      <th>Node</th>
                      <th>Cluster</th>
                      <th>Benchmark</th>
                      <th className="num">Pass</th>
                      <th className="num">Fail</th>
                      <th className="num">Warn</th>
                      <th>Job</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.bench_nodes!.map((n) => {
                      const ran = n.state === 'done' || n.state === 'succeeded';
                      return (
                        <tr key={n.node_name + (n.cluster_name ?? '')}>
                          <td className="mono">{n.node_name}</td>
                          <td className="mono">{n.cluster_name ?? r.cluster_name}</td>
                          <td>
                            <span className="inline-sm">
                              <span className="mono">
                                {n.benchmark}
                                {n.control_plane_na ? ' (auto)' : ''}
                              </span>
                              {n.control_plane_na && <Badge tone="mute">Control plane N/A · managed</Badge>}
                            </span>
                          </td>
                          <td className={`num${ran ? '' : ' muted'}`}>{ran ? n.pass : '—'}</td>
                          <td className={`num${ran ? (n.fail > 0 ? ' up' : '') : ' muted'}`}>{ran ? n.fail : '—'}</td>
                          <td className={`num${ran ? '' : ' muted'}`}>{ran ? n.warn : '—'}</td>
                          <td>
                            {ran ? (
                              <Badge tone="ok">Done{n.duration_s ? ` · ${duration(n.duration_s)}` : ''} · cleaned up</Badge>
                            ) : n.state === 'running' ? (
                              <Badge tone="info">Running</Badge>
                            ) : (
                              <Badge tone="crit">
                                {n.state === 'skipped' ? 'Skipped' : 'Failed'}
                                {n.message ? ` · ${n.message}` : ''}
                              </Badge>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </QueryView>
        ) : (
          <QueryView q={benchRunsQ} what="kube-bench runs" isEmpty={() => true} empty={<EmptyState title="kube-bench has not run yet">Enable it on a cluster (Helm value <span className="mono">bench.enabled=true</span>) and add a kube-bench schedule.</EmptyState>}>
            {() => null}
          </QueryView>
        )}
        <div className="card-spacer" />
      </section>

      <div className="row">
        <section className="card" style={{ flex: '1 1 340px', minWidth: 0 }} aria-labelledby="ksh-t">
          <div className="card-head">
            <h2 id="ksh-t">Kubescape run history</h2>
          </div>
          <QueryView q={ksRunsQ} what="Kubescape runs" isEmpty={(d) => d.items.length === 0} empty={<EmptyState title="No Kubescape runs yet">Runs appear after the first scheduled or manual run.</EmptyState>}>
            {(d) => (
              <div className="table-wrap">
                <table className="t">
                  <thead>
                    <tr>
                      <th>Run</th>
                      <th className="num">Score</th>
                      <th className="num">New</th>
                      <th className="num">Resolved</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.items.map((r) => (
                      <tr key={r.id}>
                        <td className="mono">
                          {dateTime(r.started_at)}
                          {r.status !== 'succeeded' && (
                            <>
                              {' '}
                              <Badge tone={r.status === 'failed' ? 'crit' : 'info'}>{r.status}</Badge>
                            </>
                          )}
                        </td>
                        <td className="num">{r.score != null ? `${r.score.toFixed(1)}%` : '—'}</td>
                        <td className={`num${r.new_findings > 0 ? ' up' : ''}`}>{r.new_findings > 0 ? `+${r.new_findings}` : 0}</td>
                        <td className={`num${r.resolved_findings > 0 ? ' down' : ''}`}>{r.resolved_findings > 0 ? `−${r.resolved_findings}` : 0}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </QueryView>
          <div className="card-foot">Raw reports kept in Blob for 400 days</div>
        </section>

        <section className="card grow" aria-labelledby="new-t">
          <div className="card-head">
            <h2 id="new-t">New since last run{lastKs ? ` · ${dateTime(lastKs.started_at).slice(0, 6)}` : ''}</h2>
            {(() => {
              const sched = schedQ.data?.items.find((s) => s.tool === 'kubescape');
              const ch = channelName(sched?.notify_channel_id);
              return ch ? <span className="muted small">sent to {ch}</span> : null;
            })()}
          </div>
          {lastKs ? (
            <QueryView q={newQ} what="new findings" isEmpty={(d) => d.items.length === 0} empty={<EmptyState title="No new findings">The last run found nothing that was not already open.</EmptyState>}>
              {(d) => (
                <div className="table-wrap">
                  <table className="t">
                    <thead>
                      <tr>
                        <th>Control</th>
                        <th>Severity</th>
                        <th>Cluster</th>
                        <th>Resource</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.items.map((f) => (
                        <tr key={f.id}>
                          <td className="wrap">
                            <span className="mono">{f.control_id}</span> {f.title}
                          </td>
                          <td>
                            <SeverityBadge s={f.severity} />
                          </td>
                          <td className="mono">{f.cluster_name}</td>
                          <td className="mono">{f.resource_ref}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </QueryView>
          ) : (
            <EmptyState title="Nothing to compare yet">New findings are listed after the second Kubescape run.</EmptyState>
          )}
          <div className="card-spacer" />
        </section>
      </div>

      <section className="card pad spread">
        <div>
          <h2 className="title">Platform activity</h2>
          <p className="muted" style={{ margin: '4px 0 0', fontSize: 13 }}>
            Logins, grants, change requests and drift findings, append-only.
          </p>
        </div>
        <Link to="/activity" className="btn">
          Open activity log
        </Link>
      </section>

      {creating && <NewScheduleDialog onClose={() => setCreating(false)} channels={chanQ.data?.items ?? []} />}
    </>
  );
}

function NewScheduleDialog({ onClose, channels }: { onClose: () => void; channels: Channel[] }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [tool, setTool] = useState<AuditTool>('kubescape');
  const [frameworks, setFrameworks] = useState<Set<'nsa' | 'cis' | 'mitre'>>(new Set(['nsa', 'cis', 'mitre']));
  const [scope, setScope] = useState('all');
  const [cron, setCron] = useState('0 4 * * *');
  const [notify, setNotify] = useState('');
  const cronErr = validateCron(cron);
  const create = useMutation({
    mutationFn: (b: AuditScheduleInput) => api.post<AuditSchedule>('/audit/schedules', b),
    onSuccess: () => {
      toast('Audit schedule created.');
      void qc.invalidateQueries({ queryKey: ['audit-schedules'] });
      onClose();
    },
  });
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (cronErr) return;
    create.mutate({ tool, frameworks: tool === 'kubescape' ? [...frameworks] : [], scope_selector: scope.trim() || 'all', cron, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, enabled: true, notify_channel_id: notify || null });
  };
  return (
    <Modal open onClose={onClose} eyebrow="Audit" title="New audit schedule">
      <form onSubmit={submit} className="stack-sm" style={{ gap: 18 }} noValidate>
        <fieldset className="opts" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
          <legend className="lbl">Check</legend>
          {(['kubescape', 'polaris', 'kube-bench'] as AuditTool[]).map((t) => (
            <label className="opt" key={t}>
              <input type="radio" name="tool" checked={tool === t} onChange={() => setTool(t)} />
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
          <Field label="Scope (cluster labels)" htmlFor="as-scope" error={fieldError(create.error, 'scope_selector')} hint='"all" or a selector such as env=prod'>
            <input className="in mono" {...aria('as-scope', fieldError(create.error, 'scope_selector'), true)} value={scope} onChange={(e) => setScope(e.target.value)} />
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
          <select id="as-nc" className="in" value={notify} onChange={(e) => setNotify(e.target.value)}>
            <option value="">Default routing</option>
            {channels.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </Field>
        <FormError error={create.error} />
        <div className="end">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn pri" disabled={create.isPending || !!cronErr || (tool === 'kubescape' && frameworks.size === 0)}>
            Create schedule
          </button>
        </div>
      </form>
    </Modal>
  );
}
