// Monitoring › Synthetic (docs/design/monitoring-overview.html): KPIs, filter pills and the scenario × cluster
// matrix. Each cell is the latest counted run of the scenario in that cluster, as text and a symbol.
import { Link, useNavigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { SyntheticCell, SyntheticOverview as Overview, SyntheticOverviewScenario } from '../../api/types';
import { useCan } from '../../auth/me';
import { clockTime, plural } from '../../lib/format';
import { MONITORING_STATUS, monitoringRoute } from '../../router';
import { Badge, EmptyState, QueryView } from '../../ui/kit';
import { CELL, CellLegend, MatrixCell, ScenarioStatusBadge, reasonText, scenarioLine } from '../../ui/synthetic';

export const overviewQueryKey = ['synthetic', 'overview'] as const;

export function useSyntheticOverview() {
  return useQuery({ queryKey: overviewQueryKey, queryFn: () => api.get<Overview>('/synthetic/overview'), refetchInterval: 30_000 });
}

type Status = (typeof MONITORING_STATUS)[number];
const PILLS: { id: Status | undefined; label: string }[] = [
  { id: undefined, label: 'All' },
  { id: 'failing', label: 'Failing' },
  { id: 'degraded', label: 'Degraded' },
  { id: 'paused', label: 'Paused' },
];

export const pct = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${v} %`);
export const ms = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${v} ms`);

function cellDetail(c: SyntheticCell): string {
  // its runs end before they start: the last counted run is old news, and the overview does not know which
  // credential it is (the scenario page does)
  if (c.state === 'credential_error') return '';
  const parts: string[] = [];
  if (c.last_finished_at) parts.push(`last run ${clockTime(c.last_finished_at)}`);
  if (c.failed_step !== null && (c.state === 'failing' || c.state === 'degraded')) parts.push(`step ${c.failed_step + 1}: ${reasonText(c.failure_reason)}`);
  if (c.consecutive_failures > 1) parts.push(`${c.consecutive_failures} failed in a row`);
  if (c.blocked_reason) parts.push(reasonText(c.blocked_reason));
  return parts.join(' · ');
}

function matches(s: SyntheticOverviewScenario, status: Status | undefined, q: string): boolean {
  if (status === 'paused' && s.enabled) return false;
  if (status === 'failing' && s.status !== 'failing') return false;
  // the same count as the Degraded KPI: scenarios whose status is degraded
  if (status === 'degraded' && s.status !== 'degraded') return false;
  const t = q.trim().toLowerCase();
  return !t || [s.name, s.owner_selector, s.type].some((x) => x.toLowerCase().includes(t));
}

export function SyntheticOverview() {
  const search = monitoringRoute.useSearch();
  const navigate = useNavigate({ from: '/monitoring' });
  const canEdit = useCan('synthetic_edit');
  const q = useSyntheticOverview();
  const setSearch = (p: { status?: Status; q?: string }) => void navigate({ search: (s) => ({ ...s, ...p }), replace: true });
  return (
    <QueryView q={q} what="synthetic monitoring" isEmpty={(d) => d.scenarios.length === 0} empty={<NoScenarios canEdit={canEdit} />}>
      {(d) => {
        const k = d.kpis;
        const failingNames = d.scenarios.filter((s) => s.status === 'failing');
        const shown = d.scenarios.filter((s) => matches(s, search.status, search.q ?? ''));
        const count = (st: Status | undefined) => d.scenarios.filter((s) => matches(s, st, '')).length;
        return (
          <>
            <section className="stats four" aria-label="Synthetic monitoring totals">
              <div className="card stat">
                <div className="k">Scenarios</div>
                <div className="v">{k.scenarios}</div>
                <div className="d">
                  {k.active} active · {k.paused} paused
                </div>
              </div>
              <div className={`card stat${k.failing_scenarios ? ' crit-border' : ''}`}>
                <div className="k">Failing now</div>
                <div className={`v${k.failing_scenarios ? ' crit-large' : ''}`}>{k.failing_scenarios}</div>
                <div className="d">{k.failing_scenarios === 1 ? `${failingNames[0].name} · ${plural(failingNames[0].failing_clusters, 'cluster')}` : k.failing_scenarios ? `on ${plural(k.failing_clusters, 'cluster')}` : 'no alert firing'}</div>
              </div>
              <div className="card stat">
                <div className="k">Degraded</div>
                <div className={`v${k.degraded_scenarios ? ' warn' : ''}`}>{k.degraded_scenarios}</div>
                <div className="d">{k.degraded_scenarios ? `last run failed on ${plural(k.degraded_clusters, 'cluster')}, no alert yet` : 'none'}</div>
              </div>
              <div className="card stat">
                <div className="k">Probes</div>
                <div className="v">
                  {k.probes_online} / {k.probes_total}
                </div>
                <div className="d">{probesDetail(k)}</div>
              </div>
            </section>
            <div className="spread">
              <div className="inline wrap-gap">
                <label className="sr-only" htmlFor="syn-q">
                  Search scenarios
                </label>
                <input id="syn-q" type="search" className="in search" placeholder="Search scenarios or owner labels…" value={search.q ?? ''} onChange={(e) => setSearch({ q: e.target.value || undefined })} />
                <div className="pills" role="group" aria-label="Show scenarios">
                  {PILLS.map((p) => (
                    <button key={p.label} type="button" className="pill" aria-pressed={search.status === p.id} onClick={() => setSearch({ status: p.id })}>
                      {p.label} · {count(p.id)}
                    </button>
                  ))}
                </div>
              </div>
              <CellLegend />
            </div>
            <Matrix overview={d} rows={shown} />
          </>
        );
      }}
    </QueryView>
  );
}

function probesDetail(k: Overview['kpis']): string {
  const parts: string[] = [];
  if (k.probes_offline.length) parts.push(k.probes_offline.length <= 2 ? `${k.probes_offline.join(', ')} probe offline` : `${k.probes_offline.length} offline`);
  if (k.probes_not_installed.length) parts.push(k.probes_not_installed.length <= 2 ? `${k.probes_not_installed.join(', ')} not installed` : `${k.probes_not_installed.length} not installed`);
  return parts.join(' · ') || 'all online';
}

function NoScenarios({ canEdit }: { canEdit: boolean }) {
  return (
    <section className="card">
      <EmptyState
        title="No scenarios yet"
        action={
          canEdit && (
            <Link to="/monitoring/editor" className="btn pri">
              New scenario
            </Link>
          )
        }
      >
        A scenario is an HTTP flow, an HTTP request, a DNS lookup, a TCP connect or a TLS certificate check. It runs from the probe in every cluster and alerts when it fails.
        {!canEdit && ' Ask an admin for the synthetic-editor role to create one.'}
      </EmptyState>
    </section>
  );
}

function Matrix({ overview, rows }: { overview: Overview; rows: SyntheticOverviewScenario[] }) {
  const navigate = useNavigate({ from: '/monitoring' });
  const openRun = (id: string) => void navigate({ search: (s) => ({ ...s, run: id }) });
  const cols = overview.clusters;
  return (
    <section className="card">
      <div className="table-wrap">
        <table className="t matrix" aria-label="Scenarios by cluster">
          <thead>
            <tr>
              <th scope="col">Scenario</th>
              <th scope="col">Status</th>
              {cols.map((c) => (
                <th key={c.id} scope="col" className="mx-col">
                  <span className="mono vert" title={`${c.name} · probe ${c.probe_status.replace('_', ' ')}`}>
                    {c.name}
                  </span>
                </th>
              ))}
              <th scope="col" className="num">
                24 h availability
              </th>
              <th scope="col" className="num">
                p95
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={cols.length + 4}>
                  <EmptyState title="No scenario matches">Clear the search or choose All.</EmptyState>
                </td>
              </tr>
            )}
            {rows.map((s) => (
              <tr key={s.id}>
                <th scope="row" className="wrap mx-name">
                  <div className="strong">
                    <Link to="/monitoring" search={{ scenario: s.id }}>
                      {s.name}
                    </Link>
                    {s.cells.some((x) => x.state === 'credential_error') && <Badge tone="crit" className="inline-badge">Credential error</Badge>}
                  </div>
                  <div className="muted small">
                    {scenarioLine(s)}
                    {s.owner_selector && <span className="mono"> · {s.owner_selector}</span>}
                  </div>
                </th>
                <td>
                  <ScenarioStatusBadge status={s.status} failing={s.failing_clusters} degraded={s.degraded_clusters} />
                </td>
                {cols.map((col) => {
                  // matched by cluster id, not by position
                  const c = s.cells.find((x) => x.cluster_id === col.id);
                  return (
                    <td key={col.id} className="mx-cell">
                      {c ? <MatrixCell cluster={col.name} state={c.state} detail={cellDetail(c)} onOpen={c.last_run_id && c.state !== 'credential_error' ? () => openRun(c.last_run_id!) : undefined} /> : <MatrixCell cluster={col.name} state="no_data" />}
                    </td>
                  );
                })}
                <td className="num mono">{pct(s.availability_24h)}</td>
                <td className="num mono">{ms(s.p95_ms_24h)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card-foot">
        Each cell is the latest run of the scenario in that cluster: {Object.values(CELL)[0].symbol} passing, {CELL.failing.symbol} failing (alert firing), {CELL.degraded.symbol} degraded (the last run failed, no alert yet), {CELL.credential_error.symbol} credential error (a credential the scenario uses cannot be resolved). Hover for details, click a cell for its run, a scenario for its history.
      </div>
    </section>
  );
}
