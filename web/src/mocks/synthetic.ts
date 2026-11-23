// DEV-ONLY fixtures and handlers for Monitoring › Synthetic (docs/design/monitoring-*.html). Shapes follow the
// /synthetic routes of docs/openapi.yaml. Credential values never exist here: credentials are names and kinds.
import type {
  AllowRule,
  Cluster,
  HostCheck,
  Scenario,
  ScenarioAlertRule,
  ScenarioClusterRow,
  ScenarioInput,
  ScenarioPreview,
  ScenarioStep,
  SyntheticAlert,
  SyntheticCell,
  SyntheticCellState,
  SyntheticCredential,
  SyntheticOverview,
  SyntheticRunDetail,
  SyntheticStepResult,
  TimelineBucket,
} from '../api/types';
import { matchesSelector, parseSelector } from '../lib/labels';
import * as db from './db';
import type { MockReq, MockRes } from './handlers';

type Handler = (req: MockReq, params: Record<string, string>) => MockRes | Promise<MockRes>;
const ok = (body: unknown, status = 200): MockRes => ({ status, body });
const items = (list: unknown[]) => ok({ items: list });
const notFound = (): MockRes => ({ status: 404, body: { error: 'not found' } });
const forbidden = (): MockRes => ({ status: 403, body: { error: 'your role does not allow this action' } });
const invalid = (error: string, fields: Record<string, string>): MockRes => ({ status: 422, body: { error, fields } });
const MIN = 60_000;
const H = 60 * MIN;
const D = 24 * H;
const perms = () => db.me().permissions;

export const SCENARIO_CAP = 120;
export const CLUSTER_CAP = 600;

// ------------------------------------------------------------ settings: channels, allowlist, credentials

for (const name of ['#payments-alerts', '#platform-oncall']) {
  if (!db.channels.some((c) => c.name === name)) db.channels.push({ id: db.stableId(name), kind: 'slack', name, slack_channel_id: 'C0' + name.length + 'SYN', routes: ['synthetic.failing'], created_at: db.iso(20 * D) });
}
const chan = (name: string) => db.channels.find((c) => c.name === name)!;

function rule(pattern: string, kind: AllowRule['kind'], note: string, scenarios: number): AllowRule {
  return { id: db.stableId(`rule:${pattern}`), pattern, kind, note, scenarios, created_by: db.people.yigit.id, created_by_name: db.people.yigit.upn, created_at: db.iso(30 * D) };
}
export const allowlist: AllowRule[] = [
  rule('*.prod.wrw.com', 'wildcard', 'Production APIs', 3),
  rule('wrw.com', 'suffix', 'Everything under wrw.com', 6),
  rule('partner-sftp.acme.net', 'exact', 'Partner SFTP', 1),
  rule('*.data.svc.cluster.local', 'wildcard', 'In-cluster data services', 1),
];

function cred(name: string, kind: SyntheticCredential['kind'], bound: string, header_name = ''): SyntheticCredential {
  return {
    id: db.stableId(`cred:${name}`),
    name,
    kind,
    bound_hosts: [{ pattern: bound, kind: bound.startsWith('*.') ? 'wildcard' : 'exact' }],
    header_name,
    oauth_token_url: '',
    oauth_scopes: '',
    source: 'stored',
    expires_at: db.isoIn(80 * D),
    expired: false,
    rotated_at: null,
    scenarios: [],
    resolve_failures_24h: 0,
    last_resolve_failed_at: null,
    created_by: db.people.yigit.id,
    created_by_name: db.people.yigit.upn,
    created_at: db.iso(25 * D),
    updated_at: db.iso(25 * D),
  };
}
export const credentials: SyntheticCredential[] = [cred('catalog-monitor', 'bearer', '*.prod.wrw.com'), cred('search-api-key', 'header', 'search.wrw.com', 'X-Api-Key'), cred('reports-login', 'basic', 'reports.wrw.com')];
const credRef = (name: string) => {
  const c = credentials.find((x) => x.name === name)!;
  return { credential_id: c.id, credential: { id: c.id, name: c.name, kind: c.kind, header_name: c.header_name } };
};

/** Allowlist match on whole labels (docs/design/synthetic-monitoring.md §6.1). */
function ruleMatches(r: Pick<AllowRule, 'pattern' | 'kind'>, host: string): boolean {
  if (r.kind === 'exact') return host === r.pattern;
  if (r.kind === 'wildcard') return host.endsWith(r.pattern.slice(1)) && host.length > r.pattern.length - 1;
  return host === r.pattern || host.endsWith('.' + r.pattern);
}

export function checkHost(raw: string): HostCheck {
  let host = raw.trim();
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/i.exec(host);
  if (m) host = m[1];
  host = host.toLowerCase().replace(/\.$/, '');
  const out: HostCheck = { host, allowed: false, rule: null, also: [], denied_reason: '', message: '' };
  if (/^\[.*\]$/.test(host) || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return { ...out, denied_reason: 'ip_literal', message: 'IP addresses are always denied; use a host name.' };
  if (host === 'localhost' || host.endsWith('.localhost') || host === 'kubernetes' || host.startsWith('kubernetes.default.svc')) return { ...out, denied_reason: 'always_denied', message: 'localhost and the Kubernetes API are always denied, whatever the rules say.' };
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(host)) return { ...out, denied_reason: 'invalid_host', message: 'Not a valid host name.' };
  const hits = allowlist.filter((r) => ruleMatches(r, host));
  if (!hits.length) return { ...out, denied_reason: 'no_rule', message: `No rule matches ${host}.` };
  return { ...out, allowed: true, rule: hits[0], also: hits.slice(1) };
}

function notAllowedMessage(host: string): string {
  return perms().admin_global ? `Host ${host} is not allowed. Add a rule in Settings › Synthetic monitoring.` : `Host ${host} is not allowed. Ask an admin to add it to the synthetic allowlist.`;
}

// ------------------------------------------------------------ scenarios

const ALERTS = (p: Partial<ScenarioAlertRule> = {}): ScenarioAlertRule => ({ cluster_fail_after: 3, fleet_critical_clusters: 3, recovery_after: 2, send_recovery: true, channel_id: null, critical_channel_id: null, ...p });
const http = (method: 'GET' | 'POST', url: string, p: Partial<ScenarioStep> = {}, headers: Record<string, string> = {}): ScenarioStep => ({
  kind: 'http',
  http: { method, url, headers, body: '', body_type: 'text', follow_redirects: false },
  assertions: [{ subject: 'status_code', operator: 'equals', value: '200' }],
  extracts: [],
  ...p,
});

type Fx = { step: number; reason: string; n: number; ms?: number };
/** What the fixtures say happened: failing (alert firing) and degraded clusters with their last failure. */
interface Story {
  failing?: Record<string, Fx>;
  degraded?: Record<string, Fx>;
  p95: number;
  avail: number;
}

function scenario(name: string, p: Partial<Scenario> & Pick<Scenario, 'type' | 'steps'>): Scenario {
  const s: Scenario = {
    id: db.stableId(`scenario:${name}`),
    name,
    owner_selector: '',
    interval_seconds: 60,
    timeout_seconds: 10,
    step_retries: 0,
    enabled: true,
    store_responses: true,
    run_on: 'all',
    run_on_selector: '',
    exclude_selectors: [],
    alerts: ALERTS(),
    targets: { runs_on: 0, of: 0, clusters: [], excluded: [] },
    requests_per_minute: 0,
    can_edit: true,
    created_by: db.people.yigit.id,
    created_by_name: 'yigit',
    created_at: db.iso(20 * D),
    updated_at: db.iso(3 * D),
    ...p,
  };
  s.steps = s.steps.map((st, i) => ({ ...st, position: i }));
  return s;
}

const LAB = 'olympos.io/cluster=onprem-ist-lab';
export const scenarios: Scenario[] = [
  scenario('Checkout API flow', {
    type: 'http_flow',
    owner_selector: 'team=payments',
    step_retries: 1,
    exclude_selectors: [LAB],
    alerts: ALERTS({ channel_id: chan('#payments-alerts').id, critical_channel_id: chan('#platform-oncall').id }),
    steps: [
      { kind: 'dns', dns: { name: 'api.prod.wrw.com', record_type: 'A' }, assertions: [{ subject: 'record_count', operator: 'greater_than', value: '0' }], extracts: [] },
      http('GET', 'https://api.prod.wrw.com/healthz', { assertions: [{ subject: 'status_code', operator: 'equals', value: '200' }, { subject: 'latency_ms', operator: 'less_than', value: '300' }] }),
      http(
        'GET',
        'https://api.prod.wrw.com/v1/catalog?limit=1',
        {
          ...credRef('catalog-monitor'),
          assertions: [
            { subject: 'status_code', operator: 'equals', value: '200' },
            { subject: 'latency_ms', operator: 'less_than', value: '500' },
            { subject: 'json:$.items', operator: 'length_greater_than', value: '0' },
          ],
          extracts: [{ name: 'item', source: 'json_path', expr: '$.items[0].id' }],
        },
        { Accept: 'application/json' },
      ),
      http('GET', 'https://api.prod.wrw.com/v1/items/${item}', { ...credRef('catalog-monitor'), assertions: [{ subject: 'status_code', operator: 'equals', value: '200' }, { subject: 'body', operator: 'contains', value: 'price' }] }, { Accept: 'application/json' }),
    ],
  }),
  scenario('Internal DNS — api.prod.wrw.com', { type: 'dns', interval_seconds: 30, exclude_selectors: [LAB], steps: [{ kind: 'dns', dns: { name: 'api.prod.wrw.com', record_type: 'A' }, assertions: [{ subject: 'record_count', operator: 'greater_than', value: '0' }], extracts: [] }] }),
  scenario('Payments gateway TLS', {
    type: 'tls',
    interval_seconds: 3600,
    owner_selector: 'team=payments',
    run_on: 'selector',
    run_on_selector: 'env=prod',
    exclude_selectors: ['site=factory'],
    steps: [{ kind: 'tls', tls: { host: 'pay.wrw.com', port: 443, sni: '' }, assertions: [{ subject: 'tls_days_left', operator: 'greater_than', value: '14' }, { subject: 'chain_valid', operator: 'equals', value: 'true' }], extracts: [] }],
  }),
  scenario('Kafka brokers reachable', { type: 'tcp', owner_selector: 'team=data', steps: [{ kind: 'tcp', tcp: { host: 'kafka-0.kafka.data.svc.cluster.local', port: 9092 }, assertions: [{ subject: 'connects', operator: 'equals', value: 'true' }], extracts: [] }] }),
  scenario('Partner SFTP', { type: 'tcp', interval_seconds: 300, exclude_selectors: ['team=data', 'team=ml', LAB], steps: [{ kind: 'tcp', tcp: { host: 'partner-sftp.acme.net', port: 22 }, assertions: [{ subject: 'connects', operator: 'equals', value: 'true' }], extracts: [] }] }),
  scenario('Search API latency', {
    type: 'http_flow',
    owner_selector: 'team=web',
    exclude_selectors: [LAB],
    steps: [
      http('GET', 'https://search.wrw.com/healthz'),
      http('POST', 'https://search.wrw.com/v2/query', { ...credRef('search-api-key'), assertions: [{ subject: 'status_code', operator: 'equals', value: '200' }, { subject: 'latency_ms', operator: 'less_than', value: '500' }] }, { 'Content-Type': 'application/json' }),
    ],
  }),
  scenario('Legacy reports portal', { type: 'http', interval_seconds: 900, enabled: false, run_on: 'selector', run_on_selector: 'site=factory', steps: [http('GET', 'https://reports.wrw.com/login', credRef('reports-login'))] }),
];
// the POST body of the search step (visible to editors only: the step uses a credential)
scenarios[5].steps[1].http!.body = '{"q":"olympos","limit":5}';
scenarios[5].steps[1].http!.body_type = 'json';

const story: Record<string, Story> = {
  'Checkout API flow': {
    failing: { 'oke-fra-erp': { step: 2, reason: 'assertion_failed: latency 912 ms > 500 ms', n: 3, ms: 912 } },
    degraded: { 'onprem-factory-01': { step: 1, reason: 'connect_error: connect timeout', n: 1 } },
    p95: 412,
    avail: 99.12,
  },
  'Internal DNS — api.prod.wrw.com': { p95: 4, avail: 100 },
  'Payments gateway TLS': {
    degraded: Object.fromEntries(['prod-aks-weu-01', 'prod-aks-weu-02', 'oke-fra-erp', 'eks-fra-data', 'gke-euw1-web', 'eks-use1-ml', 'cce-ist-retail'].map((c) => [c, { step: 0, reason: 'assertion_failed: tls_days_left 12 < 14', n: 1 }])),
    p95: 0,
    avail: 100,
  },
  'Kafka brokers reachable': { p95: 9, avail: 99.98 },
  'Partner SFTP': { p95: 41, avail: 99.9 },
  'Search API latency': { degraded: { 'prod-aks-weu-02': { step: 1, reason: 'assertion_failed: latency 780 ms > 500 ms', n: 2, ms: 780 } }, p95: 780, avail: 99.7 },
  'Legacy reports portal': { p95: 0, avail: 0 },
};

// ------------------------------------------------------------ targeting, cells, stats

const fleet = () => db.clusters.filter((c) => c.status !== 'revoked').sort((a, b) => a.name.localeCompare(b.name));

type Targeting = Pick<ScenarioInput, 'run_on' | 'run_on_selector' | 'exclude_selectors'>;
function excluded(t: Targeting, c: Cluster): boolean {
  if (t.run_on === 'selector' && !matchesSelector(t.run_on_selector, c.labels)) return true;
  return t.exclude_selectors.some((x) => matchesSelector(x, c.labels));
}
function targetsOf(t: Targeting): Scenario['targets'] {
  const all = fleet();
  const runs = all.filter((c) => !excluded(t, c));
  // the "excluded" names are clusters an exclude selector removed (not the ones a run_on selector leaves out)
  const ex = all.filter((c) => (t.run_on === 'all' || matchesSelector(t.run_on_selector, c.labels)) && t.exclude_selectors.some((x) => matchesSelector(x, c.labels)));
  return { runs_on: runs.length, of: all.length, clusters: runs.map((c) => c.name), excluded: ex.map((c) => c.name) };
}

export function requestsPerMinute(s: Pick<ScenarioInput, 'steps' | 'interval_seconds' | 'step_retries'>): number {
  if (!s.interval_seconds) return 0;
  const attempts = 1 + Math.max(s.step_retries ?? 0, 0);
  let perRun = 0;
  const creds = new Set<string>();
  for (const st of s.steps) {
    perRun += attempts * (st.http?.follow_redirects ? 6 : 1);
    if (st.credential_id) creds.add(st.credential_id);
  }
  perRun += creds.size;
  return Math.round(((perRun * 60) / s.interval_seconds) * 10) / 10;
}

function cellState(s: Scenario, c: Cluster): SyntheticCellState {
  if (excluded(s, c)) return 'excluded';
  if (!s.enabled) return 'paused';
  if (c.probe_status === 'not_installed' || c.probe_status === 'revoked') return 'not_installed';
  if (c.probe_status === 'offline' || c.probe_status === 'pending') return 'probe_offline';
  const st = story[s.name];
  if (st?.failing?.[c.name]) return 'failing';
  if (st?.degraded?.[c.name]) return 'degraded';
  if (!st) return 'no_data';
  return 'passing';
}
const failureOf = (s: Scenario, c: Cluster): Fx | undefined => story[s.name]?.failing?.[c.name] ?? story[s.name]?.degraded?.[c.name];
const runId = (s: Scenario, c: Cluster) => db.stableId(`run:${s.id}:${c.name}`);
const hasRuns = (state: SyntheticCellState) => state === 'passing' || state === 'failing' || state === 'degraded' || state === 'probe_offline';

function cell(s: Scenario, c: Cluster): SyntheticCell {
  const state = cellState(s, c);
  const f = state === 'failing' || state === 'degraded' ? failureOf(s, c) : undefined;
  const last = hasRuns(state);
  const at = c.probe_status === 'offline' ? db.iso(2 * H + 3 * MIN) : db.iso(18_000);
  return {
    cluster_id: c.id,
    state,
    last_run_id: last ? runId(s, c) : null,
    last_status: last ? (f ? 'failed' : 'passed') : null,
    last_finished_at: last ? at : null,
    failed_step: f ? f.step : null,
    failure_reason: f?.reason ?? '',
    consecutive_failures: f?.n ?? 0,
    blocked_reason: '',
  };
}

function view(s: Scenario): Scenario {
  const canEdit = perms().synthetic_edit;
  const ch = (id: string | null) => db.channels.find((c) => c.id === id)?.name ?? '';
  return {
    ...s,
    alerts: { ...s.alerts, channel_name: ch(s.alerts.channel_id), critical_channel_name: ch(s.alerts.critical_channel_id) },
    targets: targetsOf(s),
    requests_per_minute: requestsPerMinute(s),
    can_edit: canEdit,
    // a viewer does not see the headers and body of a step that uses a credential
    steps: s.steps.map((st) => (st.credential_id && !canEdit ? { ...st, http: st.http ? { ...st.http, headers: null, body: null } : st.http, hidden: true } : { ...st, hidden: false })),
  };
}

function overview(): SyntheticOverview {
  const cs = fleet();
  const rows = scenarios.map((s) => {
    const cells = cs.map((c) => cell(s, c));
    const failing = cells.filter((x) => x.state === 'failing').length;
    const degraded = cells.filter((x) => x.state === 'degraded').length;
    const st = story[s.name];
    const status: SyntheticOverview['scenarios'][number]['status'] = !s.enabled ? 'paused' : failing ? 'failing' : degraded ? 'degraded' : cells.some((x) => x.state === 'passing') ? 'passing' : 'no_data';
    const runs = s.enabled ? Math.round((86_400 / s.interval_seconds) * cells.filter((x) => hasRuns(x.state)).length) : 0;
    return {
      id: s.id,
      name: s.name,
      type: s.type,
      owner_selector: s.owner_selector,
      interval_seconds: s.interval_seconds,
      enabled: s.enabled,
      steps: s.steps.length,
      status,
      failing_clusters: failing,
      degraded_clusters: degraded,
      cells,
      runs_24h: runs,
      availability_24h: runs ? (st?.avail ?? null) : null,
      p95_ms_24h: runs && st?.p95 ? st.p95 : null,
      can_edit: perms().synthetic_edit,
    };
  });
  return {
    kpis: {
      scenarios: scenarios.length,
      active: scenarios.filter((s) => s.enabled).length,
      paused: scenarios.filter((s) => !s.enabled).length,
      failing_scenarios: rows.filter((r) => r.status === 'failing').length,
      failing_clusters: new Set(rows.flatMap((r) => r.cells.filter((x) => x.state === 'failing').map((x) => x.cluster_id))).size,
      degraded_scenarios: rows.filter((r) => r.status === 'degraded').length,
      degraded_clusters: new Set(rows.flatMap((r) => r.cells.filter((x) => x.state === 'degraded').map((x) => x.cluster_id))).size,
      probes_online: cs.filter((c) => c.probe_status === 'online').length,
      probes_total: cs.length,
      probes_offline: cs.filter((c) => c.probe_status === 'offline' || c.probe_status === 'pending').map((c) => c.name),
      probes_not_installed: cs.filter((c) => c.probe_status === 'not_installed' || c.probe_status === 'revoked').map((c) => c.name),
    },
    clusters: cs.map((c) => ({ id: c.id, name: c.name, probe_status: c.probe_status, probe_version: c.probe_version, probe_last_seen_at: c.probe_last_seen_at })),
    scenarios: rows,
  };
}

function timeline(state: SyntheticCellState, f: Fx | undefined, perBucket: number): TimelineBucket[] {
  const start = Math.floor(Date.now() / (30 * MIN)) * 30 * MIN - 47 * 30 * MIN;
  return Array.from({ length: 48 }, (_, i) => {
    const b = { start: new Date(start + i * 30 * MIN).toISOString(), runs: 0, passed: 0, failed: 0, state: 'no_data' as TimelineBucket['state'] };
    if (!hasRuns(state) || (state === 'probe_offline' && i >= 44)) return b;
    const failedHere = (f && i >= 48 - Math.max(1, Math.ceil(f.n / Math.max(perBucket, 1)))) || (f && f.n >= 3 && i === 30);
    const runs = Math.max(perBucket, 1);
    return { ...b, runs, failed: failedHere ? Math.min(runs, f!.n) : 0, passed: failedHere ? runs - Math.min(runs, f!.n) : runs, state: failedHere ? 'failed' : 'passed' };
  });
}

function clusterRows(s: Scenario): ScenarioClusterRow[] {
  const st = story[s.name];
  return fleet().map((c) => {
    const state = cellState(s, c);
    const f = state === 'failing' || state === 'degraded' ? failureOf(s, c) : undefined;
    const x = cell(s, c);
    const runs = hasRuns(state) ? Math.round(86_400 / s.interval_seconds) : 0;
    const base = st?.p95 ? Math.round(st.p95 * 0.46) : null;
    return {
      cluster_id: c.id,
      cluster_name: c.name,
      probe_status: c.probe_status,
      state,
      last_run: x.last_run_id ? { id: x.last_run_id, status: x.last_status ?? 'passed', finished_at: x.last_finished_at!, failed_step: x.failed_step, failure_reason: x.failure_reason } : null,
      consecutive_failures: f?.n ?? 0,
      consecutive_passes: f ? 0 : runs ? 40 : 0,
      blocked_reason: '',
      runs_24h: runs,
      availability_24h: runs ? (f ? Math.round((100 - f.n * 1.2) * 10) / 10 : 100) : null,
      p50_ms: runs && base ? base + (f?.ms ? 400 : 0) : null,
      p95_ms: runs && st?.p95 ? (f?.ms ? f.ms + 18 : st.p95) : null,
      timeline: timeline(state, f, Math.round((30 * 60) / s.interval_seconds)),
    };
  });
}

function alertsOf(s: Scenario): SyntheticAlert[] {
  if (s.name !== 'Checkout API flow') return [];
  const erp = db.byName('oke-fra-erp');
  const factory = db.byName('onprem-factory-01');
  const weu2 = db.byName('prod-aks-weu-02');
  const a = (p: Partial<SyntheticAlert> & Pick<SyntheticAlert, 'cluster_name' | 'state' | 'reason' | 'opened_at'>): SyntheticAlert => ({
    id: db.stableId(`alert:${p.cluster_name}:${p.opened_at.slice(0, 13)}`),
    fleet: false,
    cluster_id: db.byName(p.cluster_name).id,
    resolved_at: null,
    duration_seconds: null,
    last_run_id: null,
    failed_step: null,
    clusters: [],
    clusters_total: 0,
    still_failing: null,
    notified: true,
    ...p,
  });
  return [
    a({ cluster_name: erp.name, state: 'firing', reason: 'assertion_failed: latency 912 ms > 500 ms', opened_at: db.iso(20_000), failed_step: 2, last_run_id: runId(s, erp) }),
    a({ cluster_name: factory.name, state: 'resolved', reason: 'connect_error: connect timeout', opened_at: db.iso(9 * H), resolved_at: db.iso(9 * H - 34 * MIN), duration_seconds: 34 * 60, failed_step: 1 }),
    a({ cluster_name: weu2.name, state: 'resolved', reason: 'assertion_failed: status 503 ≠ 200', opened_at: db.iso(D + 3 * H), resolved_at: db.iso(D + 3 * H - 6 * MIN), duration_seconds: 6 * 60, failed_step: 1 }),
  ];
}

// ------------------------------------------------------------ runs

/** Test runs and runs started with Run now, by id (scheduled runs are derived from the fixtures). */
const extraRuns = new Map<string, { detail: SyntheticRunDetail; readyAt: number }>();

const EXCERPT = 'HTTP/2 200\ncontent-type: application/json\nset-cookie: [redacted]\nx-request-id: 7f3c1e0a\n\n{"items":[{"id":"sku-4410","name":"…"}],"next":"…"}';

/** The step results of a run of `steps` on `cluster` that fails at `f` (or passes). */
function stepResults(steps: ScenarioStep[], f: Fx | undefined): SyntheticStepResult[] {
  const canEdit = perms().synthetic_edit;
  return steps.map((st, i) => {
    const req = st.credential_id && !canEdit ? { ...st, position: i, http: st.http ? { ...st.http, headers: null, body: null } : st.http, hidden: true } : { ...st, position: i, hidden: false };
    if (f && i > f.step) return { position: i, status: 'skipped', status_code: null, timings: null, assertions: [], excerpt: null, extracted_names: [], error: '', request: req };
    const failed = !!f && i === f.step;
    const ms = failed && f?.ms ? f.ms : st.kind === 'dns' ? 3 : st.kind === 'tcp' ? 9 : 141 + i * 30;
    const us = ms * 1000;
    const timings =
      st.kind === 'http'
        ? { dns_us: Math.round(us * 0.06), connect_us: Math.round(us * 0.12), tls_us: Math.round(us * 0.18), ttfb_us: Math.round(us * 0.58), download_us: Math.round(us * 0.06), total_us: us }
        : st.kind === 'dns'
          ? { dns_us: us, connect_us: 0, tls_us: 0, ttfb_us: 0, download_us: 0, total_us: us }
          : { dns_us: 1000, connect_us: us - 1000, tls_us: st.kind === 'tls' ? 20_000 : 0, ttfb_us: 0, download_us: 0, total_us: us };
    const connectFailed = failed && !f!.reason.startsWith('assertion_failed');
    const assertions = connectFailed
      ? []
      : st.assertions.map((a) => {
          const isLatency = a.subject === 'latency_ms';
          const actual = isLatency ? String(ms) : a.subject === 'status_code' ? '200' : a.subject === 'json:$.items' ? '1' : a.subject === 'tls_days_left' ? '12' : a.subject === 'record_count' ? '2' : 'true';
          const passed = !failed || !((isLatency && f!.reason.includes('latency')) || (a.subject === 'tls_days_left' && f!.reason.includes('tls_days_left')));
          return { subject: a.subject, operator: a.operator, expected: a.value, actual, passed };
        });
    return {
      position: i,
      status: failed ? 'failed' : 'passed',
      status_code: st.kind === 'http' && !connectFailed ? 200 : null,
      timings: connectFailed ? { dns_us: 2000, connect_us: 10_000_000, tls_us: 0, ttfb_us: 0, download_us: 0, total_us: 10_002_000 } : timings,
      assertions,
      excerpt: st.kind === 'http' && !connectFailed ? EXCERPT : null,
      extracted_names: st.extracts.map((e) => e.name),
      error: connectFailed ? reasonDetail(f!.reason) : '',
      request: req,
    };
  });
}
const reasonDetail = (r: string) => (r.includes(':') ? r.slice(r.indexOf(':') + 1).trim() : r);

function scheduledRun(id: string): SyntheticRunDetail | undefined {
  for (const s of scenarios)
    for (const c of fleet()) {
      if (runId(s, c) !== id) continue;
      const x = cell(s, c);
      if (!x.last_run_id) return undefined;
      const f = x.state === 'failing' || x.state === 'degraded' ? failureOf(s, c) : undefined;
      const steps = stepResults(s.steps, f);
      const total = steps.reduce((n, st) => n + (st.timings?.total_us ?? 0), 0);
      return {
        id,
        scenario_id: s.id,
        scenario_name: s.name,
        cluster_id: c.id,
        cluster_name: c.name,
        scheduled_for: db.iso(20_000),
        started_at: db.iso(19_000),
        finished_at: x.last_finished_at,
        status: f ? 'failed' : 'passed',
        failed_step: f ? f.step : null,
        failure_reason: f?.reason ?? '',
        total_ms: Math.round(total / 1000),
        test: false,
        manual: false,
        probe_version: c.probe_version,
        scenario_type: s.type,
        remote_ip: '20.50.2.14',
        probe_ip: '10.40.2.17',
        allowlist_version: 7,
        requested_by_name: '',
        consecutive_failures: f?.n ?? 0,
        alert: x.state === 'failing' ? { id: db.stableId(`alert:${c.name}`), state: 'firing', opened_at: db.iso(20_000), resolved_at: null } : null,
        definition: 'saved',
        steps,
      };
    }
  return undefined;
}

function runDetail(id: string): SyntheticRunDetail | undefined {
  const extra = extraRuns.get(id);
  if (extra) {
    if (Date.now() < extra.readyAt) return { ...extra.detail, status: 'running', finished_at: null, failed_step: null, failure_reason: '', total_ms: null, steps: extra.detail.steps.map((s) => ({ ...s, status: '', timings: null, assertions: [], excerpt: null })) };
    return extra.detail;
  }
  return scheduledRun(id);
}

function runItem(d: SyntheticRunDetail) {
  const { scenario_type: _t, remote_ip: _r, probe_ip: _p, allowlist_version: _a, requested_by_name: _q, consecutive_failures: _c, alert: _al, definition: _d, steps: _s, ...item } = d; // eslint-disable-line @typescript-eslint/no-unused-vars
  return item;
}

/** A run of a draft (test run) or of a saved scenario (Run now). On oke-fra-erp a latency check under 500 ms fails, as in the mockups. */
function startRun(steps: ScenarioStep[], s: Pick<Scenario, 'type' | 'name'> & { id: string | null }, c: Cluster, kind: 'test' | 'manual'): string {
  const id = db.uuid();
  let f: Fx | undefined;
  if (c.name === 'oke-fra-erp') {
    const i = steps.findIndex((st) => st.assertions.some((a) => a.subject === 'latency_ms' && a.operator === 'less_than' && Number(a.value) >= 500 && Number(a.value) < 912));
    if (i >= 0) f = { step: i, reason: `assertion_failed: latency 912 ms > ${steps[i].assertions.find((a) => a.subject === 'latency_ms')!.value} ms`, n: 1, ms: 912 };
  }
  const results = stepResults(steps, f);
  const now = new Date().toISOString();
  extraRuns.set(id, {
    readyAt: Date.now() + 1200,
    detail: {
      id,
      scenario_id: s.id,
      scenario_name: s.name || 'Untitled scenario',
      cluster_id: c.id,
      cluster_name: c.name,
      scheduled_for: now,
      started_at: now,
      finished_at: now,
      status: f ? 'failed' : 'passed',
      failed_step: f ? f.step : null,
      failure_reason: f?.reason ?? '',
      total_ms: Math.round(results.reduce((n, r) => n + (r.timings?.total_us ?? 0), 0) / 1000),
      test: kind === 'test',
      manual: kind === 'manual',
      probe_version: c.probe_version,
      scenario_type: s.type,
      remote_ip: '20.50.2.14',
      probe_ip: '10.40.2.17',
      allowlist_version: 7,
      requested_by_name: db.people.yigit.upn,
      consecutive_failures: f ? 1 : 0,
      alert: null,
      definition: kind === 'test' ? 'test' : 'saved',
      steps: results,
    },
  });
  return id;
}

// ------------------------------------------------------------ validation (save, test run)

function stepHosts(st: ScenarioStep, i: number): [string, string][] {
  if (st.kind === 'http') return [[`steps.${i}.http.url`, st.http?.url ?? '']];
  if (st.kind === 'dns') return [[`steps.${i}.dns.name`, st.dns?.name ?? '']];
  if (st.kind === 'tcp') return [[`steps.${i}.tcp.host`, st.tcp?.host ?? '']];
  const out: [string, string][] = [[`steps.${i}.tls.host`, st.tls?.host ?? '']];
  if (st.tls?.sni) out.push([`steps.${i}.tls.sni`, st.tls.sni]);
  return out;
}

function validateSteps(b: ScenarioInput, fields: Record<string, string>) {
  const steps = b.steps ?? [];
  if (!steps.length) fields.steps = 'Add at least one step.';
  if (steps.length > 10) fields.steps = 'At most 10 steps.';
  if (b.type !== 'http_flow' && (steps.length !== 1 || steps[0].kind !== b.type)) fields.steps = `A ${b.type} scenario has exactly one ${b.type} step.`;
  steps.forEach((st, i) => {
    for (const [key, raw] of stepHosts(st, i)) {
      if (!raw.trim()) {
        fields[key] = st.kind === 'http' ? 'Enter a URL.' : 'Enter a host.';
        continue;
      }
      if (st.kind === 'http' && !/^https?:\/\//i.test(raw)) {
        fields[key] = 'Use an http:// or https:// URL.';
        continue;
      }
      const h = checkHost(raw);
      if (h.host.includes('${')) fields[key] = 'A variable cannot be used in a host.';
      else if (h.denied_reason === 'no_rule') fields[key] = notAllowedMessage(h.host);
      else if (h.denied_reason) fields[key] = h.message;
    }
    if (st.kind === 'tcp' && !(st.tcp && st.tcp.port > 0 && st.tcp.port < 65536)) fields[`steps.${i}.tcp.port`] = 'Enter a port from 1 to 65535.';
    st.assertions.forEach((a, j) => {
      if (a.operator !== 'exists' && a.value.trim() === '') fields[`steps.${i}.assertions.${j}.value`] = 'Enter a value.';
    });
    st.extracts.forEach((e, j) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(e.name)) fields[`steps.${i}.extracts.${j}.name`] = 'Use letters, digits and _ (not starting with a digit).';
    });
  });
}

function validateSave(b: ScenarioInput, self: string | null): Record<string, string> {
  const fields: Record<string, string> = {};
  if (!b.name?.trim()) fields.name = 'Enter a name.';
  else if (scenarios.some((s) => s.name === b.name.trim() && s.id !== self)) fields.name = 'A scenario with this name exists.';
  if (b.owner_selector && !/^[A-Za-z0-9./_-]+=[A-Za-z0-9._-]*$/.test(b.owner_selector.trim())) fields.owner_selector = 'Use one key=value label, for example team=payments.';
  if (!(b.interval_seconds >= 30)) fields.interval_seconds = 'Run at most every 30 seconds.';
  if (!(b.timeout_seconds >= 1 && b.timeout_seconds <= 60)) fields.timeout_seconds = 'Use 1 to 60 seconds.';
  else if (b.timeout_seconds > b.interval_seconds) fields.timeout_seconds = 'The timeout cannot be longer than the interval.';
  if (!(b.step_retries >= 0 && b.step_retries <= 2)) fields.step_retries = 'At most 2 retries.';
  if (b.run_on === 'selector') {
    if (!b.run_on_selector?.trim()) fields.run_on_selector = 'Enter a label selector.';
    else if (parseSelector(b.run_on_selector).error) fields.run_on_selector = parseSelector(b.run_on_selector).error!;
  }
  (b.exclude_selectors ?? []).forEach((x, i) => {
    if (parseSelector(x).error) fields[`exclude_selectors.${i}`] = parseSelector(x).error!;
  });
  const al = b.alerts;
  if (al) for (const k of ['cluster_fail_after', 'fleet_critical_clusters', 'recovery_after'] as const) if (!(al[k] >= 1 && al[k] <= 1000)) fields[`alerts.${k}`] = 'Use 1 to 1000.';
  validateSteps(b, fields);
  if (!Object.keys(fields).length && b.enabled !== false) {
    const rpm = requestsPerMinute(b);
    if (rpm > SCENARIO_CAP)
      fields.interval_seconds = `The scenario makes up to ${rpm.toFixed(1)} requests per minute on each cluster; the cap is ${SCENARIO_CAP}. Run it less often, retry less or follow fewer redirects.`;
  }
  return fields;
}

function stored(b: ScenarioInput, prev?: Scenario): Scenario {
  const steps = (b.steps ?? []).map((st, i) => {
    const c = credentials.find((x) => x.id === st.credential_id);
    return { ...st, position: i, credential_id: c?.id ?? null, credential: c ? { id: c.id, name: c.name, kind: c.kind, header_name: c.header_name } : null, hidden: undefined };
  });
  return scenario(b.name.trim(), {
    ...(prev ?? {}),
    id: prev?.id ?? db.uuid(),
    type: b.type,
    owner_selector: b.owner_selector?.trim() ?? '',
    interval_seconds: b.interval_seconds,
    timeout_seconds: b.timeout_seconds,
    step_retries: b.step_retries,
    enabled: b.enabled ?? prev?.enabled ?? true,
    store_responses: b.store_responses ?? prev?.store_responses ?? true,
    run_on: b.run_on,
    run_on_selector: b.run_on === 'selector' ? b.run_on_selector.trim() : '',
    exclude_selectors: b.exclude_selectors ?? [],
    alerts: b.alerts ? ALERTS({ ...b.alerts, channel_name: undefined, critical_channel_name: undefined }) : (prev?.alerts ?? ALERTS()),
    steps,
    created_at: prev?.created_at ?? new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
}

function preview(b: ScenarioInput): MockRes {
  if (b.run_on === 'selector') {
    if (!b.run_on_selector?.trim()) return invalid('invalid targeting', { run_on_selector: 'Enter a label selector.' });
    const e = parseSelector(b.run_on_selector).error;
    if (e) return invalid('invalid targeting', { run_on_selector: e });
  }
  for (const [i, x] of (b.exclude_selectors ?? []).entries()) {
    const e = parseSelector(x).error;
    if (e) return invalid('invalid targeting', { [`exclude_selectors.${i}`]: e });
  }
  const rpm = requestsPerMinute(b);
  const p: ScenarioPreview = { ...targetsOf({ run_on: b.run_on, run_on_selector: b.run_on_selector ?? '', exclude_selectors: b.exclude_selectors ?? [] }), requests_per_minute: rpm, scenario_cap: SCENARIO_CAP, cluster_cap: CLUSTER_CAP, over_scenario_cap: rpm > SCENARIO_CAP, over_limit: [] };
  return ok(p);
}

// ------------------------------------------------------------ routes

const byId = (id: string) => scenarios.find((s) => s.id === id);

export const syntheticRoutes: [string, string, Handler][] = [
  ['GET', '/synthetic/overview', () => ok(overview())],
  [
    'GET',
    '/synthetic/scenarios',
    () =>
      items(
        scenarios.map((s) => {
          const v = view(s);
          return { id: v.id, name: v.name, type: v.type, owner_selector: v.owner_selector, interval_seconds: v.interval_seconds, timeout_seconds: v.timeout_seconds, enabled: v.enabled, run_on: v.run_on, run_on_selector: v.run_on_selector, exclude_selectors: v.exclude_selectors, steps: v.steps.length, targets: v.targets, can_edit: v.can_edit, created_at: v.created_at, updated_at: v.updated_at };
        }),
      ),
  ],
  [
    'POST',
    '/synthetic/scenarios',
    (r) => {
      if (!perms().synthetic_edit) return forbidden();
      const fields = validateSave(r.body as ScenarioInput, null);
      if (Object.keys(fields).length) return invalid('invalid scenario', fields);
      const s = stored(r.body as ScenarioInput);
      scenarios.push(s);
      db.record('synthetic.scenario_created', 'synthetic_scenario', s.id, s.name);
      return ok(view(s), 201);
    },
  ],
  ['POST', '/synthetic/scenarios/preview', (r) => (perms().synthetic_edit ? preview(r.body as ScenarioInput) : forbidden())],
  [
    'GET',
    '/synthetic/scenarios/:id',
    (_r, p) => {
      const s = byId(p.id);
      return s ? ok(view(s)) : notFound();
    },
  ],
  [
    'PUT',
    '/synthetic/scenarios/:id',
    (r, p) => {
      const s = byId(p.id);
      if (!s) return notFound();
      if (!perms().synthetic_edit) return forbidden();
      const fields = validateSave({ ...(r.body as ScenarioInput), enabled: (r.body as ScenarioInput).enabled ?? s.enabled }, s.id);
      if (Object.keys(fields).length) return invalid('invalid scenario', fields);
      const next = stored(r.body as ScenarioInput, s);
      scenarios[scenarios.indexOf(s)] = next;
      // a renamed scenario keeps its fixture story
      if (next.name !== s.name && story[s.name]) story[next.name] = story[s.name];
      db.record('synthetic.scenario_updated', 'synthetic_scenario', s.id, next.name);
      return ok(view(next));
    },
  ],
  [
    'PATCH',
    '/synthetic/scenarios/:id',
    (r, p) => {
      const s = byId(p.id);
      if (!s) return notFound();
      if (!perms().synthetic_edit) return forbidden();
      s.enabled = !!r.body?.enabled;
      s.updated_at = new Date().toISOString();
      db.record(s.enabled ? 'synthetic.scenario_resumed' : 'synthetic.scenario_paused', 'synthetic_scenario', s.id, s.name);
      return ok(view(s));
    },
  ],
  [
    'DELETE',
    '/synthetic/scenarios/:id',
    (_r, p) => {
      const s = byId(p.id);
      if (!s) return notFound();
      if (!perms().synthetic_edit) return forbidden();
      scenarios.splice(scenarios.indexOf(s), 1);
      return { status: 204 };
    },
  ],
  [
    'POST',
    '/synthetic/scenarios/:id/run',
    (r, p) => {
      const s = byId(p.id);
      if (!s) return notFound();
      if (!perms().synthetic_edit) return forbidden();
      if (!s.enabled) return { status: 409, body: { error: 'The scenario is paused; resume it first.' } };
      const cid = r.body?.cluster_id as string | undefined;
      const targets = fleet().filter((c) => !excluded(s, c));
      if (cid) {
        const c = fleet().find((x) => x.id === cid);
        if (!c) return invalid('invalid run', { cluster_id: 'unknown cluster' });
        if (!targets.includes(c)) return invalid('invalid run', { cluster_id: 'The scenario does not run on this cluster.' });
        if (c.probe_status !== 'online') return { status: 409, body: { error: `The cluster's probe is not online: ${c.name} is ${c.probe_status.replace('_', ' ')}` } };
        return { status: 202, body: { run_ids: [startRun(s.steps, s, c, 'manual')] } };
      }
      const online = targets.filter((c) => c.probe_status === 'online');
      if (!online.length) return { status: 409, body: { error: 'The scenario runs on no cluster now: none of its clusters has an online probe that the request caps leave room on.' } };
      return { status: 202, body: { run_ids: online.map((c) => startRun(s.steps, s, c, 'manual')) } };
    },
  ],
  ['GET', '/synthetic/scenarios/:id/clusters', (_r, p) => {
    const s = byId(p.id);
    if (!s) return notFound();
    return ok({ window_start: new Date(Date.now() - D).toISOString(), bucket_minutes: 30, buckets: 48, items: clusterRows(s) });
  }],
  ['GET', '/synthetic/scenarios/:id/alerts', (_r, p) => {
    const s = byId(p.id);
    return s ? items(alertsOf(s)) : notFound();
  }],
  [
    'POST',
    '/synthetic/test-runs',
    (r) => {
      if (!perms().synthetic_edit) return forbidden();
      const draft = r.body?.scenario as (ScenarioInput & { id?: string }) | undefined;
      const c = fleet().find((x) => x.id === r.body?.cluster_id);
      if (!draft) return invalid('invalid test run', { scenario: 'required' });
      if (!c) return invalid('invalid test run', { cluster_id: 'unknown cluster' });
      const fields: Record<string, string> = {};
      validateSteps(draft, fields);
      if (Object.keys(fields).length) return invalid('invalid test run', fields);
      if (c.probe_status !== 'online') return { status: 409, body: { error: `The cluster's probe is not online: ${c.name} is ${c.probe_status.replace('_', ' ')}` } };
      const steps = draft.steps.map((st) => ({ ...st, credential: credentials.find((x) => x.id === st.credential_id) ? credRef(credentials.find((x) => x.id === st.credential_id)!.name).credential : null }));
      return { status: 202, body: { run_id: startRun(steps, { id: draft.id ?? null, name: draft.name, type: draft.type }, c, 'test') } };
    },
  ],
  [
    'GET',
    '/synthetic/runs',
    (r) => {
      const sid = r.query.get('scenario_id');
      const cid = r.query.get('cluster_id');
      const all = [...[...extraRuns.keys()].map((id) => runDetail(id)!), ...scenarios.flatMap((s) => fleet().map((c) => scheduledRun(runId(s, c))).filter((x): x is SyntheticRunDetail => !!x))];
      return items(all.filter((x) => (!sid || x.scenario_id === sid) && (!cid || x.cluster_id === cid)).map(runItem));
    },
  ],
  [
    'GET',
    '/synthetic/runs/:id',
    (_r, p) => {
      const d = runDetail(p.id);
      return d ? ok(d) : notFound();
    },
  ],
  ['GET', '/synthetic/allowlist', () => (perms().synthetic_edit || perms().read ? ok({ items: allowlist, version: 7 }) : forbidden())],
  ['POST', '/synthetic/allowlist/check', (r) => (perms().synthetic_edit ? ok(checkHost(String(r.body?.host ?? ''))) : forbidden())],
  ['GET', '/synthetic/credentials', () => items(credentials.map((c) => ({ ...c, scenarios: scenarios.filter((s) => s.steps.some((st) => st.credential_id === c.id)).map((s) => ({ id: s.id, name: s.name })) })))],
];
