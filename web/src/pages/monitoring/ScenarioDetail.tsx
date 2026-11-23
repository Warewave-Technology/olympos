// Scenario detail (docs/design/monitoring-scenario.html): the steps as cards with the failed step marked, the
// scenario on each cluster over 24 h, the alert rule and the alert history.
import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import { api, errorMessage } from '../../api/client';
import type { ItemList, Scenario, ScenarioClusterRow, ScenarioClusters, SyntheticAlert, TimelineBucket } from '../../api/types';
import { clockTime, duration, plural } from '../../lib/format';
import { Badge, ErrorState, FormError, Loading, Modal, QueryView, TypeToConfirm, useToast } from '../../ui/kit';
import { PageHead } from '../../ui/status';
import { HiddenNote, ScenarioStatusBadge, assertionsLine, clusterResult, intervalText, reasonText, stepTitle, TYPE_LABEL, variableSource } from '../../ui/synthetic';
import { ms, pct, useSyntheticOverview } from './SyntheticOverview';
import { MonitoringTabs } from './MonitoringPage';

export const scenarioKey = (id: string) => ['synthetic', 'scenario', id] as const;


export function ScenarioDetail({ id }: { id: string }) {
  const q = useQuery({ queryKey: scenarioKey(id), queryFn: () => api.get<Scenario>(`/synthetic/scenarios/${id}`) });
  const clustersQ = useQuery({ queryKey: ['synthetic', 'scenario', id, 'clusters'], queryFn: () => api.get<ScenarioClusters>(`/synthetic/scenarios/${id}/clusters`), refetchInterval: 30_000 });
  const overviewQ = useSyntheticOverview();
  if (q.isPending) return <Loading label="Loading the scenario…" />;
  if (q.isError)
    return (
      <>
        <Crumbs name="Scenario" />
        <ErrorState what="this scenario" error={q.error} onRetry={() => q.refetch()} />
      </>
    );
  const s = q.data;
  const row = overviewQ.data?.scenarios.find((x) => x.id === id);
  const rows = clustersQ.data?.items ?? [];
  // the failed step of each cluster whose last run failed
  const failedAt = new Map<number, string[]>();
  for (const r of rows) if (r.last_run?.failed_step != null && (r.state === 'failing' || r.state === 'degraded')) failedAt.set(r.last_run.failed_step, [...(failedAt.get(r.last_run.failed_step) ?? []), r.cluster_name]);
  const t = s.targets;
  const sub = [
    TYPE_LABEL[s.type] ?? s.type,
    s.type === 'http_flow' ? plural(s.steps.length, 'step') : '',
    `every ${intervalText(s.interval_seconds)}`,
    `timeout ${s.timeout_seconds} s`,
    `runs on ${plural(t.runs_on, 'cluster')}${t.excluded.length ? `, ${t.excluded.length} excluded` : ''}`,
    s.owner_selector ? `owner ${s.owner_selector}` : '',
  ].filter(Boolean);
  return (
    <>
      <PageHead
        crumbs={<CrumbLinks name={s.name} />}
        title={
          <span className="inline">
            <span>{s.name}</span>
            {row && <ScenarioStatusBadge status={row.status} failing={row.failing_clusters} degraded={row.degraded_clusters} of={t.runs_on} />}
          </span>
        }
        sub={sub.join(' · ')}
        actions={s.can_edit && <Actions s={s} />}
      />
      <MonitoringTabs active="synthetic" />
      <section className="card pad-lg" aria-labelledby="steps-h">
        <h2 id="steps-h">Steps</h2>
        <ol className="step-cards">
          {s.steps.map((st, i) => {
            const { title, detail } = stepTitle(st);
            const from = variableSource(s.steps, i);
            const failed = failedAt.get(i);
            const ex = st.extracts.filter((e) => e.name);
            return (
              <li key={i} className={`step-card${failed ? ' failed' : ''}`}>
                <div className="inline-sm">
                  <span className="snum">{i + 1}</span>
                  <b>{title}</b>
                </div>
                {ex.length > 0 ? (
                  <div className="mono muted small">{ex.map((e) => `extract ${e.expr} → ${e.name}`).join(' · ')}</div>
                ) : from ? (
                  <div className="mono muted small">uses value from step {from}</div>
                ) : (
                  detail && <div className="mono muted small break">{detail}</div>
                )}
                {st.assertions.length > 0 && <div className="small">{assertionsLine(st.assertions)}</div>}
                {st.kind === 'http' && st.hidden && <HiddenNote />}
                {st.kind === 'http' && !st.hidden && st.credential && (
                  <div className="muted small">
                    Auth: <span className="mono">{st.credential.name}</span>
                  </div>
                )}
                {failed && (
                  <div className="small ico-crit">
                    <span aria-hidden="true">✕ </span>Last run failed here on {failed.join(', ')}
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      </section>
      <ClustersCard q={clustersQ} />
      <div className="cols-2">
        <AlertRuleCard s={s} />
        <AlertsCard id={id} />
      </div>
    </>
  );
}

function Crumbs({ name }: { name: string }) {
  return (
    <div className="crumbs">
      <CrumbLinks name={name} />
    </div>
  );
}

export function CrumbLinks({ name, scenarioId, tail }: { name: string; scenarioId?: string; tail?: string }) {
  return (
    <nav aria-label="Breadcrumb" className="crumbs-nav">
      <Link to="/monitoring">Monitoring</Link> / <Link to="/monitoring">Synthetic</Link> /{' '}
      {scenarioId ? (
        <Link to="/monitoring" search={{ scenario: scenarioId }}>
          {name}
        </Link>
      ) : (
        <span aria-current="page">{name}</span>
      )}
      {tail && <> / <span aria-current="page">{tail}</span></>}
    </nav>
  );
}

function Actions({ s }: { s: Scenario }) {
  const [deleting, setDeleting] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ['synthetic'] });
  };
  const pause = useMutation({
    mutationFn: () => api.patch<Scenario>(`/synthetic/scenarios/${s.id}`, { enabled: !s.enabled }),
    onSuccess: (r) => {
      qc.setQueryData(scenarioKey(s.id), r);
      refresh();
      toast(r.enabled ? `Resumed ${r.name}.` : `Paused ${r.name}. It does not run and does not alert until you resume it.`);
    },
    onError: (e) => toast(`Could not ${s.enabled ? 'pause' : 'resume'} the scenario: ${errorMessage(e)}`, 'crit'),
  });
  const run = useMutation({
    mutationFn: () => api.post<{ run_ids: string[] }>(`/synthetic/scenarios/${s.id}/run`),
    onSuccess: (r) => {
      toast(`Run queued on ${plural(r.run_ids.length, 'cluster')}. It counts toward alerts.`);
      setTimeout(refresh, 1500);
    },
    onError: (e) => toast(`Could not run the scenario: ${errorMessage(e)}`, 'crit'),
  });
  return (
    <>
      <button type="button" className="btn" onClick={() => pause.mutate()} disabled={pause.isPending}>
        {s.enabled ? 'Pause' : 'Resume'}
      </button>
      <button type="button" className="btn" onClick={() => run.mutate()} disabled={run.isPending || !s.enabled} title={s.enabled ? 'One run on every cluster it runs on now; it counts toward alerts' : 'Resume the scenario first'}>
        {run.isPending ? 'Queueing…' : 'Run now'}
      </button>
      <button type="button" className="btn danger" onClick={() => setDeleting(true)}>
        Delete
      </button>
      <Link to="/monitoring/editor" search={{ scenario: s.id }} className="btn pri">
        Edit
      </Link>
      {deleting && <DeleteDialog s={s} onClose={() => setDeleting(false)} />}
    </>
  );
}

/** Delete a scenario: names it, says what goes with it, and asks for its name (docs/design/monitoring-scenario.html). */
function DeleteDialog({ s, onClose }: { s: Scenario; onClose: () => void }) {
  const [typed, setTyped] = useState('');
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const del = useMutation({
    mutationFn: () => api.del(`/synthetic/scenarios/${s.id}`),
    onSuccess: () => {
      qc.removeQueries({ queryKey: scenarioKey(s.id) });
      void qc.invalidateQueries({ queryKey: ['synthetic'] });
      toast(`Deleted ${s.name}.`);
      void navigate({ to: '/monitoring' });
    },
  });
  return (
    <Modal open onClose={onClose} danger size="narrow" eyebrow="Delete scenario" eyebrowTone="crit" title={`Delete ${s.name}?`} closeOnBackdrop={false}>
      <p className="muted" style={{ margin: 0 }}>
        The scenario stops running on every cluster. Its runs and its alert history are deleted with it; this cannot be undone. To stop it for a while instead, pause it.
      </p>
      <FormError error={del.error} />
      <TypeToConfirm id="del-name" expected={s.name} value={typed} onChange={setTyped} />
      <div className="end">
        <button type="button" className="btn" onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="btn danger" disabled={typed !== s.name || del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Deleting…' : 'Delete scenario'}
        </button>
      </div>
    </Modal>
  );
}

const STRIP_CLS: Record<TimelineBucket['state'], string> = { passed: 's-ok', failed: 's-fail', no_data: 's-off' };

function Strip({ row }: { row: ScenarioClusterRow }) {
  const t = row.timeline;
  const failed = t.filter((b) => b.state === 'failed').length;
  const passed = t.filter((b) => b.state === 'passed').length;
  const label = `Last 24 hours, 30 minute buckets: ${passed} passed, ${failed} with failures, ${t.length - passed - failed} without data`;
  return (
    <div className="strip" role="img" aria-label={label}>
      {t.map((b) => (
        <span key={b.start} className={STRIP_CLS[b.state]} title={`${clockTime(b.start)} · ${b.runs ? `${b.passed} passed, ${b.failed} failed` : 'no data'}`} />
      ))}
    </div>
  );
}

function ClustersCard({ q }: { q: UseQueryResult<ScenarioClusters> }) {
  const navigate = useNavigate({ from: '/monitoring' });
  const openRun = (id: string) => void navigate({ search: (s) => ({ ...s, run: id }) });
  return (
    <section className="card" aria-labelledby="by-cluster-h">
      <div className="card-head">
        <h2 id="by-cluster-h">By cluster · last 24 h</h2>
        <div className="legend" aria-hidden="true">
          <span>
            <i className="s-ok" />
            passed
          </span>
          <span>
            <i className="s-fail" />
            failed
          </span>
          <span>
            <i className="s-off" />
            no data
          </span>
        </div>
      </div>
      <QueryView q={q} what="the clusters of this scenario">
        {(d) => (
          <div className="table-wrap">
            <table className="t" aria-label="Scenario by cluster">
              <thead>
                <tr>
                  <th scope="col">Cluster</th>
                  <th scope="col">Last run</th>
                  <th scope="col">Result</th>
                  <th scope="col">Failed step</th>
                  <th scope="col">p50 / p95</th>
                  <th scope="col" className="num">
                    Availability
                  </th>
                  <th scope="col">Timeline (30 min buckets)</th>
                </tr>
              </thead>
              <tbody>
                {d.items.map((r) => {
                  const res = clusterResult(r);
                  const last = r.last_run;
                  const failed = last && last.failed_step !== null && last.status !== 'passed';
                  return (
                    <tr key={r.cluster_id}>
                      <td className="mono">{r.cluster_name}</td>
                      <td className="mono">{clockTime(last?.finished_at)}</td>
                      <td>
                        {last ? (
                          <button type="button" className={`badge ${res.tone} badge-btn`} onClick={() => openRun(last.id)} aria-label={`${res.text}: open the run on ${r.cluster_name}`}>
                            {res.text}
                          </button>
                        ) : (
                          <Badge tone={res.tone}>{res.text}</Badge>
                        )}
                        {r.blocked_reason && <div className="muted small">{reasonText(r.blocked_reason)}</div>}
                      </td>
                      <td className="wrap err-cell">{failed ? `${last.failed_step! + 1} · ${reasonText(last.failure_reason)}` : '—'}</td>
                      <td className="mono">{r.p50_ms === null && r.p95_ms === null ? '—' : `${r.p50_ms ?? '—'} / ${ms(r.p95_ms)}`}</td>
                      <td className="mono num">{pct(r.availability_24h)}</td>
                      <td className="strip-cell">
                        <Strip row={r} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </QueryView>
      <div className="card-spacer" />
    </section>
  );
}

function AlertRuleCard({ s }: { s: Scenario }) {
  const a = s.alerts;
  const channels = [a.channel_name || 'the routes of the synthetic events', a.critical_channel_name && a.critical_channel_name !== a.channel_name ? `${a.critical_channel_name} (critical)` : ''].filter(Boolean).join(' · ');
  return (
    <section className="card pad-lg" aria-labelledby="rule-h">
      <h2 id="rule-h">Alert rule</h2>
      <dl className="dl">
        <dt>Cluster alert</dt>
        <dd>{plural(a.cluster_fail_after, 'failed run')} in a row in a cluster</dd>
        <dt>Fleet alert (critical)</dt>
        <dd>{a.fleet_critical_clusters} or more clusters failing at the same time</dd>
        <dt>Channel</dt>
        <dd className={a.channel_name ? 'mono' : undefined}>{channels}</dd>
        <dt>Recovery message</dt>
        <dd>{a.send_recovery ? `Yes, after ${plural(a.recovery_after, 'passing run')}` : 'No'}</dd>
      </dl>
    </section>
  );
}

function alertText(a: SyntheticAlert): string {
  const what = a.fleet ? `Fleet · ${a.clusters.join(', ')}${a.clusters_total > a.clusters.length ? ` and ${a.clusters_total - a.clusters.length} more` : ''}` : a.cluster_name;
  const step = a.failed_step !== null ? `step ${a.failed_step + 1} ` : '';
  const why = a.reason ? `${step}${reasonText(a.reason)}` : '';
  const dur = a.state === 'resolved' && a.duration_seconds !== null ? duration(a.duration_seconds) : '';
  return [what, why, dur].filter(Boolean).join(' · ');
}

function AlertsCard({ id }: { id: string }) {
  const q = useQuery({ queryKey: ['synthetic', 'scenario', id, 'alerts'], queryFn: () => api.get<ItemList<SyntheticAlert>>(`/synthetic/scenarios/${id}/alerts`, { limit: 20 }) });
  const navigate = useNavigate({ from: '/monitoring' });
  return (
    <section className="card pad-lg" aria-labelledby="alerts-h">
      <h2 id="alerts-h">Alerts</h2>
      <QueryView q={q} what="the alerts" isEmpty={(d) => d.items.length === 0} empty={<p className="muted small">No alerts yet.</p>}>
        {(d) => (
          <ul className="plain-list alert-list" aria-label="Alert history">
            {d.items.map((a) => (
              <li key={a.id}>
                <Badge tone={a.state === 'firing' ? 'crit' : 'ok'}>{a.state === 'firing' ? 'Firing' : 'Resolved'}</Badge>
                <span className="mono">{clockTime(a.opened_at)}</span>
                <span className="alert-text">{alertText(a)}</span>
                {a.last_run_id && (
                  <button type="button" className="link-btn small" onClick={() => void navigate({ search: (s) => ({ ...s, run: a.last_run_id! }) })}>
                    Run
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </QueryView>
      <p className="muted small" style={{ margin: 0 }}>
        One message per alert and one on recovery. Repeats are grouped, not re-sent every minute.
      </p>
    </section>
  );
}
