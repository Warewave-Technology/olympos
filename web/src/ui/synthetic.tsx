// Shared pieces of Monitoring › Synthetic (docs/design/monitoring-*.html): matrix cells with text and a
// symbol (never colour only), status badges, and readable text for the codes the API returns.
import type { ReactNode } from 'react';
import type { AssertionResult, ScenarioAssertion, ScenarioClusterRow, ScenarioStatus, ScenarioStep, ScenarioType, SyntheticCellState, SyntheticRun } from '../api/types';
import { plural } from '../lib/format';
import { Badge, type Tone } from './kit';

// ------------------------------------------------------------ matrix cells

export const CELL: Record<SyntheticCellState, { label: string; symbol: string; cls: string }> = {
  passing: { label: 'passing', symbol: '✓', cls: 'c-ok' },
  failing: { label: 'failing', symbol: '✕', cls: 'c-fail' },
  degraded: { label: 'degraded', symbol: '!', cls: 'c-warn' },
  probe_offline: { label: 'probe offline', symbol: '·', cls: 'c-off' },
  not_installed: { label: 'probe not installed', symbol: '∅', cls: 'c-off' },
  excluded: { label: 'excluded', symbol: '–', cls: 'c-ex' },
  paused: { label: 'paused', symbol: '‖', cls: 'c-ex' },
  no_data: { label: 'no data yet', symbol: '○', cls: 'c-off' },
};

/** The states the legend explains, in the mockup's order. */
export const LEGEND_STATES: SyntheticCellState[] = ['passing', 'failing', 'degraded', 'probe_offline', 'not_installed', 'excluded', 'paused', 'no_data'];

/** A matrix cell: the symbol on screen, "<cluster> <state>" for assistive tech and the tooltip. */
export function MatrixCell({ cluster, state, detail, onOpen }: { cluster: string; state: SyntheticCellState; detail?: string; onOpen?: () => void }) {
  const c = CELL[state] ?? CELL.no_data;
  const label = `${cluster} ${c.label}`;
  const title = `${cluster} · ${c.label}${detail ? ` · ${detail}` : ''}`;
  if (onOpen) {
    return (
      <button type="button" className={`cell ${c.cls}`} title={`${title} · open the last run`} aria-label={label} onClick={onOpen}>
        <span aria-hidden="true">{c.symbol}</span>
      </button>
    );
  }
  return (
    <span className={`cell ${c.cls}`} title={title} role="img" aria-label={label}>
      <span aria-hidden="true">{c.symbol}</span>
    </span>
  );
}

export function CellLegend() {
  return (
    <div className="legend" aria-label="Legend">
      {LEGEND_STATES.map((s) => (
        <span key={s}>
          <span className={`cell sm ${CELL[s].cls}`} aria-hidden="true">
            {CELL[s].symbol}
          </span>
          {CELL[s].label}
        </span>
      ))}
    </div>
  );
}

// ------------------------------------------------------------ status badges

export function ScenarioStatusBadge({ status, failing, degraded, of }: { status: ScenarioStatus; failing: number; degraded: number; of?: number }) {
  const n = (k: number) => (of ? `${k} of ${plural(of, 'cluster')}` : plural(k, 'cluster'));
  switch (status) {
    case 'failing':
      return <Badge tone="crit">{of ? `Failing in ${n(failing)}` : `Failing · ${n(failing)}`}</Badge>;
    case 'degraded':
      return <Badge tone="warn">{of ? `Degraded in ${n(degraded)}` : `Degraded · ${n(degraded)}`}</Badge>;
    case 'passing':
      return <Badge tone="ok">Passing</Badge>;
    case 'paused':
      return <Badge tone="mute">Paused</Badge>;
    default:
      return <Badge tone="mute">No data yet</Badge>;
  }
}

const CELL_TONE: Record<SyntheticCellState, Tone> = { passing: 'ok', failing: 'crit', degraded: 'warn', probe_offline: 'mute', not_installed: 'mute', excluded: 'mute', paused: 'mute', no_data: 'mute' };

/** Result column of the per-cluster table ("Failed · 3rd in a row", "Excluded", "Probe offline"). */
export function clusterResult(r: Pick<ScenarioClusterRow, 'state' | 'last_run' | 'consecutive_failures'>): { text: string; tone: Tone } {
  const last = r.last_run;
  if (r.state === 'excluded' || r.state === 'paused' || r.state === 'probe_offline' || r.state === 'not_installed' || !last) {
    const label = CELL[r.state]?.label ?? r.state;
    return { text: label.charAt(0).toUpperCase() + label.slice(1), tone: CELL_TONE[r.state] ?? 'mute' };
  }
  if (last.status === 'passed') return { text: 'Passed', tone: 'ok' };
  const word = last.status === 'error' ? 'Error' : 'Failed';
  const n = r.consecutive_failures;
  return { text: n > 1 ? `${word} · ${ordinal(n)} in a row` : `${word} · 1st`, tone: 'crit' };
}

export function ordinal(n: number): string {
  const s = n % 100 >= 11 && n % 100 <= 13 ? 'th' : ['th', 'st', 'nd', 'rd'][n % 10] ?? 'th';
  return `${n}${s}`;
}

const RUN_TONE: Record<string, Tone> = { passed: 'ok', failed: 'crit', error: 'crit', skipped: 'mute', running: 'info', scheduled: 'mute' };
export function SyntheticRunBadge({ run }: { run: Pick<SyntheticRun, 'status'> }) {
  const label = { passed: 'Passed', failed: 'Failed', error: 'Error', skipped: 'Skipped', running: 'Running', scheduled: 'Scheduled' }[run.status] ?? run.status;
  return <Badge tone={RUN_TONE[run.status] ?? 'mute'}>{label}</Badge>;
}

// ------------------------------------------------------------ codes → readable text

/** failure_reason prefixes of the probe, skip and error reasons of the server, blocked reasons (task-11 carries). */
export const REASON_TEXT: Record<string, string> = {
  // probe
  host_not_allowed: 'Host not on the allowlist',
  ip_denied: 'Address always denied (loopback, link-local or cloud metadata)',
  redirect_blocked: 'Redirected to a host outside the allowlist',
  dns_error: 'DNS lookup failed',
  connect_error: 'Could not connect',
  tls_error: 'TLS handshake failed',
  timeout: 'Timed out',
  assertion_failed: 'Assertion failed',
  invalid_request: 'The request is not valid',
  credential_error: 'The credential could not be used',
  runner_panic: 'The probe failed while running the step',
  // server: skipped
  probe_offline: 'Probe offline',
  probe_disconnected: 'The probe disconnected during the run',
  scenario_disabled: 'Scenario paused',
  credential_unavailable: 'The credential could not be read',
  not_dispatched: 'Not sent to the probe in time',
  probe_busy: 'The probe was busy (concurrency limit)',
  allowlist_stale: "The probe's allowlist was out of date",
  credentials_unreadable: 'The probe could not decrypt the credentials',
  invalid_scenario: 'The scenario is not valid',
  rejected: 'The probe refused the run',
  // server: error
  credential_expired: 'The credential has expired',
  dispatch_error: 'Could not send the run to the probe',
  no_result: 'No result from the probe',
  invalid_result: 'The probe sent an invalid result',
  // blocked
  rate_limit: 'Held back by a request cap',
  // alerts
  no_longer_monitored: 'No longer monitored',
};

/** "assertion_failed: latency 912 ms > 500 ms" → "latency 912 ms > 500 ms"; "timeout" → "Timed out". */
export function reasonText(reason: string | null | undefined): string {
  if (!reason) return '';
  const i = reason.indexOf(':');
  const code = (i < 0 ? reason : reason.slice(0, i)).trim();
  const detail = i < 0 ? '' : reason.slice(i + 1).trim();
  const label = REASON_TEXT[code];
  if (!label) return reason;
  if (!detail) return label;
  // an assertion's detail already says what failed
  return code === 'assertion_failed' ? detail : `${label}: ${detail}`;
}

/** A short word for a run title ("Failed at step 3 · latency"). */
export function reasonShort(reason: string | null | undefined): string {
  if (!reason) return '';
  const i = reason.indexOf(':');
  const code = (i < 0 ? reason : reason.slice(0, i)).trim();
  const detail = i < 0 ? '' : reason.slice(i + 1).trim();
  if (code === 'assertion_failed' && detail) return detail.split(/\s/)[0];
  return (REASON_TEXT[code] ?? reason).toLowerCase();
}

// ------------------------------------------------------------ scenarios and steps

export const TYPE_LABEL: Record<ScenarioType, string> = { http_flow: 'HTTP flow', http: 'HTTP', dns: 'DNS', tcp: 'TCP', tls: 'TLS certificate' };

export function intervalText(s: number): string {
  if (s % 3600 === 0) return `${s / 3600} h`;
  if (s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
}

/** "HTTP flow · 4 steps · every 1 min" */
export function scenarioLine(s: { type: ScenarioType; steps: number; interval_seconds: number }): string {
  return [TYPE_LABEL[s.type] ?? s.type, s.type === 'http_flow' ? plural(s.steps, 'step') : '', `every ${intervalText(s.interval_seconds)}`].filter(Boolean).join(' · ');
}

function urlParts(url: string): { origin: string; path: string } {
  const m = /^([a-z]+:\/\/[^/?#]*)(.*)$/i.exec(url);
  if (!m) return { origin: '', path: url };
  return { origin: m[1], path: m[2] || '/' };
}

/** The host of a URL (or a host as typed): lower case, no port. '' when there is none or it holds a variable. */
export function urlHost(url: string): string {
  const s = url.trim();
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/i.exec(s);
  const host = m ? m[1] : /^[^/:?#\s]+$/.test(s) ? s : '';
  if (!host || host.includes('${')) return '';
  return host.toLowerCase();
}

/** Title and detail of a step ("GET /healthz", "https://api.prod.wrw.com"). */
export function stepTitle(st: ScenarioStep): { title: string; detail: string } {
  switch (st.kind) {
    case 'http': {
      const h = st.http;
      if (!h) return { title: 'HTTP request', detail: '' };
      const { origin, path } = urlParts(h.url);
      return { title: `${h.method} ${path}`, detail: origin };
    }
    case 'dns':
      return { title: 'DNS resolve', detail: st.dns ? `${st.dns.name}${st.dns.record_type && st.dns.record_type !== 'A' ? ` · ${st.dns.record_type}` : ''}` : '' };
    case 'tcp':
      return { title: 'TCP connect', detail: st.tcp ? `${st.tcp.host}:${st.tcp.port}` : '' };
    case 'tls':
      return { title: 'TLS certificate', detail: st.tls ? `${st.tls.host}:${st.tls.port}${st.tls.sni ? ` · SNI ${st.tls.sni}` : ''}` : '' };
    default:
      return { title: String(st.kind), detail: '' };
  }
}

export const SUBJECT_LABEL: Record<string, string> = {
  status_code: 'Status code',
  latency_ms: 'Latency',
  body: 'Body',
  tls_days_left: 'TLS days left',
  record_count: 'Record count',
  record: 'Record',
  connects: 'Connects',
  chain_valid: 'Chain valid',
  hostname_matches: 'Hostname matches',
  tls_version: 'TLS version',
};

export const OPERATOR_LABEL: Record<string, string> = {
  equals: 'equals',
  not_equals: 'does not equal',
  contains: 'contains',
  matches: 'matches',
  less_than: 'less than',
  greater_than: 'greater than',
  exists: 'exists',
  length_greater_than: 'length greater than',
};

export function subjectText(subject: string): string {
  if (subject.startsWith('header:')) return `Header ${subject.slice(7)}`;
  if (subject.startsWith('json:')) return subject.slice(5);
  return SUBJECT_LABEL[subject] ?? subject;
}

function withUnit(subject: string, v: string): string {
  return subject === 'latency_ms' && v !== '' && /^\d+(\.\d+)?$/.test(v) ? `${v} ms` : v;
}

/** "Status code equals 200", "Latency less than 500 ms", "$.items length greater than 0". */
export function assertionText(a: { subject: string; operator: string; value?: string; expected?: string }): string {
  const v = a.value ?? a.expected ?? '';
  const op = OPERATOR_LABEL[a.operator] ?? a.operator;
  return a.operator === 'exists' ? `${subjectText(a.subject)} exists` : `${subjectText(a.subject)} ${op} ${withUnit(a.subject, v)}`.trim();
}

export function actualText(a: Pick<AssertionResult, 'subject' | 'actual'>): string {
  return withUnit(a.subject, a.actual);
}

/** "status = 200 · latency < 500 ms": the compact form on the step cards. */
export function assertionsLine(list: ScenarioAssertion[]): string {
  const sym: Record<string, string> = { equals: '=', not_equals: '≠', less_than: '<', greater_than: '>' };
  return list
    .map((a) => {
      const subj = a.subject === 'status_code' ? 'status' : a.subject === 'latency_ms' ? 'latency' : subjectText(a.subject);
      if (a.operator === 'exists') return `${subj} exists`;
      if (a.operator === 'length_greater_than') return `${subj} length > ${a.value}`;
      if (a.operator === 'contains') return `${subj} contains "${a.value}"`;
      return `${subj} ${sym[a.operator] ?? OPERATOR_LABEL[a.operator] ?? a.operator} ${withUnit(a.subject, a.value)}`;
    })
    .join(' · ');
}

/** "uses value from step 3" when a later step reads a variable an earlier one extracted. */
export function variableSource(steps: ScenarioStep[], index: number): number | null {
  const st = steps[index];
  const text = JSON.stringify([st.http?.url, st.http?.headers, st.http?.body]);
  for (let i = index - 1; i >= 0; i--) {
    if (steps[i].extracts.some((e) => e.name && text.includes('${' + e.name + '}'))) return i + 1;
  }
  return null;
}

/** "hidden" for a viewer: the step uses a credential, so its headers and body are not shown. */
export function HiddenNote({ children }: { children?: ReactNode }) {
  return (
    <span className="muted small">
      Headers and body: <b className="hidden-word">hidden</b>
      {children ?? ' (the step uses a credential)'}
    </span>
  );
}
