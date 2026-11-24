// Scenario editor (docs/design/monitoring-editor.html): basics, type, steps (method, URL, headers, auth,
// assertions, extracts, reorder) with an allowlist hint per host, schedule, "Runs on" with exclusions and the live
// count, alerting, and a test run on one cluster. Header values and bodies may hold secrets a user typed, so the
// save and the test run go through useAction (nothing in the mutation cache), and no query key holds them.
import { useEffect, useId, useState, type ReactNode } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, api, errorMessage } from '../../api/client';
import type {
  AssertionOperator,
  Channel,
  HostCheck,
  HttpMethod,
  ItemList,
  Scenario,
  ScenarioAlertRule,
  ScenarioAssertion,
  ScenarioExtract,
  ScenarioInput,
  ScenarioPreview,
  ScenarioStep,
  ScenarioType,
  StepKind,
  SyntheticCredential,
  SyntheticStepResult,
} from '../../api/types';
import { useMe } from '../../auth/me';
import { can } from '../../auth/permissions';
import { parseSelector } from '../../lib/labels';
import { plural } from '../../lib/format';
import { monitoringEditorRoute } from '../../router';
import { CheckIcon, IconArrowDown, IconArrowUp, IconClose } from '../../ui/icons';
import { ErrorState, ForbiddenState, Loading, Spinner, aria, sentence, useAction, useNow, useToast } from '../../ui/kit';
import { PageHead } from '../../ui/status';
import { TagInput } from '../../ui/TagInput';
import { HiddenNote, OPERATOR_LABEL, SUBJECT_LABEL, TYPE_LABEL, actualText, assertionText, reasonText, stepTitle, urlHost, withCredentialNames } from '../../ui/synthetic';
import { POLL_MARGIN_MS, RunDialog, useSyntheticRun } from './RunDialog';
import { CrumbLinks, scenarioKey } from './ScenarioDetail';
import { useSyntheticOverview } from './SyntheticOverview';

// ------------------------------------------------------------ model

/** A step while it is edited: headers as rows (a half-typed header keeps its place), and a stable key. */
interface EStep {
  key: string;
  step: ScenarioStep;
  headers: { name: string; value: string }[];
}
interface Draft {
  id?: string;
  name: string;
  type: ScenarioType;
  owner_selector: string;
  interval_seconds: number;
  timeout_seconds: number;
  step_retries: number;
  enabled: boolean;
  store_responses: boolean;
  run_on: 'all' | 'selector';
  run_on_selector: string;
  exclude_selectors: string[];
  steps: EStep[];
  alerts: ScenarioAlertRule;
}

let seq = 0;
const nextKey = () => `s${++seq}`;

const DEFAULT_ALERTS: ScenarioAlertRule = { cluster_fail_after: 3, fleet_critical_clusters: 3, recovery_after: 2, send_recovery: true, channel_id: null, critical_channel_id: null };

export function newStep(kind: StepKind): ScenarioStep {
  switch (kind) {
    case 'http':
      return { kind, http: { method: 'GET', url: 'https://', headers: {}, body: '', body_type: 'text', follow_redirects: false }, credential_id: null, assertions: [{ subject: 'status_code', operator: 'equals', value: '200' }], extracts: [] };
    case 'dns':
      return { kind, dns: { name: '', record_type: 'A' }, assertions: [{ subject: 'record_count', operator: 'greater_than', value: '0' }], extracts: [] };
    case 'tcp':
      return { kind, tcp: { host: '', port: 443 }, assertions: [{ subject: 'connects', operator: 'equals', value: 'true' }], extracts: [] };
    case 'tls':
      return { kind, tls: { host: '', port: 443, sni: '' }, assertions: [{ subject: 'tls_days_left', operator: 'greater_than', value: '14' }], extracts: [] };
  }
}

const wrap = (step: ScenarioStep): EStep => ({ key: nextKey(), step, headers: Object.entries(step.http?.headers ?? {}).map(([name, value]) => ({ name, value })) });

function fromScenario(s: Scenario): Draft {
  return {
    id: s.id,
    name: s.name,
    type: s.type,
    owner_selector: s.owner_selector,
    interval_seconds: s.interval_seconds,
    timeout_seconds: s.timeout_seconds,
    step_retries: s.step_retries,
    enabled: s.enabled,
    store_responses: s.store_responses,
    run_on: s.run_on,
    run_on_selector: s.run_on_selector,
    exclude_selectors: s.exclude_selectors,
    steps: s.steps.map(wrap),
    alerts: { ...DEFAULT_ALERTS, ...s.alerts },
  };
}

function blank(): Draft {
  return { name: '', type: 'http', owner_selector: '', interval_seconds: 60, timeout_seconds: 10, step_retries: 0, enabled: true, store_responses: true, run_on: 'all', run_on_selector: '', exclude_selectors: [], steps: [wrap(newStep('http'))], alerts: { ...DEFAULT_ALERTS } };
}

/** The step a draft step sends. A hidden step (headers and body not shown to the caller) is never rebuilt. */
function stepInput({ step, headers }: EStep): ScenarioStep {
  if (step.hidden) return step;
  const out: ScenarioStep = { kind: step.kind, assertions: step.assertions, extracts: step.extracts.filter((e) => e.name || e.expr) };
  if (step.kind === 'http' && step.http) {
    out.http = { ...step.http, headers: Object.fromEntries(headers.filter((h) => h.name.trim()).map((h) => [h.name.trim(), h.value])) };
    out.credential_id = step.credential_id || null;
  }
  if (step.kind === 'dns') out.dns = step.dns;
  if (step.kind === 'tcp') out.tcp = step.tcp;
  if (step.kind === 'tls') out.tls = step.tls;
  return out;
}

/**
 * The ScenarioInput of a draft (what PUT, POST and the test run send). With `initial` (a PUT), enabled and
 * store_responses are sent only when the user changed them: the server keeps the stored values when they are
 * omitted, so a pause made elsewhere meanwhile is not undone.
 */
function toInput(d: Draft, initial?: Draft): ScenarioInput & { id?: string } {
  const { steps: _s, id, enabled, store_responses, ...rest } = d; // eslint-disable-line @typescript-eslint/no-unused-vars
  return {
    ...rest,
    ...(id ? { id } : {}),
    ...(!initial || enabled !== initial.enabled ? { enabled } : {}),
    ...(!initial || store_responses !== initial.store_responses ? { store_responses } : {}),
    run_on_selector: d.run_on === 'selector' ? d.run_on_selector : '',
    steps: d.steps.map(stepInput),
  };
}

/** A field of a step as sent ("http.url", "http.headers.X-Token", "http.body", "tcp.host"…), to tell a stale error. */
function stepValue(st: ScenarioStep | undefined, rest: string): unknown {
  if (!st) return undefined;
  const [kind, field, ...more] = rest.split('.');
  const spec = (st as unknown as Record<string, Record<string, unknown> | null | undefined>)[kind];
  if (kind === 'credential_id') return st.credential_id ?? null;
  if (!spec || !field) return undefined;
  if (field === 'headers' && more.length) return (spec.headers as Record<string, string> | null)?.[more.join('.')];
  return spec[field];
}

/**
 * Field errors keyed by the step they belong to: "steps.N.rest" (or "scenario.steps.N.rest" from a test run)
 * becomes "#<step key>.rest" for the step that was at N when the request was sent, so a later reorder keeps each
 * error on its step. Messages that name a credential by id name it by name.
 */
function keyFields(raw: Record<string, string>, keys: string[], creds: { id: string; name: string }[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k0, v] of Object.entries(raw)) {
    const k = k0.replace(/^scenario\./, '');
    const m = /^steps\.(\d+)\.(.+)$/.exec(k);
    out[m && keys[Number(m[1])] ? `#${keys[Number(m[1])]}.${m[2]}` : k] = withCredentialNames(v, creds);
  }
  return out;
}

/** What the preview needs (targeting and the request rate), with no URL, header or body: safe in a query key. */
function previewBody(d: Draft) {
  return {
    ...(d.id ? { id: d.id } : {}),
    name: d.name || 'draft',
    type: d.type,
    interval_seconds: d.interval_seconds,
    timeout_seconds: d.timeout_seconds,
    step_retries: d.step_retries,
    enabled: d.enabled,
    run_on: d.run_on,
    run_on_selector: d.run_on === 'selector' ? d.run_on_selector : '',
    exclude_selectors: d.exclude_selectors,
    steps: d.steps.map(({ step }) => ({ kind: step.kind, credential_id: step.credential_id ?? null, assertions: [], extracts: [], ...(step.kind === 'http' ? { http: { method: step.http?.method ?? 'GET', url: '', headers: {}, body: '', follow_redirects: !!step.http?.follow_redirects } } : {}) })),
  };
}

// ------------------------------------------------------------ assertions

const SUBJECTS: Record<StepKind, string[]> = {
  http: ['status_code', 'latency_ms', 'header', 'body', 'json', 'tls_days_left'],
  dns: ['record_count', 'record', 'latency_ms'],
  tcp: ['connects', 'latency_ms'],
  tls: ['tls_days_left', 'chain_valid', 'hostname_matches', 'tls_version'],
};
const OPERATORS: Record<string, AssertionOperator[]> = {
  status_code: ['equals', 'not_equals', 'less_than', 'greater_than'],
  latency_ms: ['less_than', 'greater_than'],
  header: ['equals', 'contains', 'matches', 'exists'],
  body: ['contains', 'matches'],
  json: ['equals', 'not_equals', 'contains', 'matches', 'exists', 'length_greater_than', 'less_than', 'greater_than'],
  tls_days_left: ['greater_than', 'less_than'],
  record_count: ['equals', 'greater_than', 'less_than'],
  record: ['contains', 'equals', 'matches'],
  connects: ['equals'],
  chain_valid: ['equals'],
  hostname_matches: ['equals'],
  tls_version: ['equals'],
};
const BASE_LABEL: Record<string, string> = { ...SUBJECT_LABEL, header: 'Header', json: 'JSON path' };
const baseOf = (subject: string) => (subject.startsWith('header:') ? 'header' : subject.startsWith('json:') ? 'json' : subject);
const argOf = (subject: string) => (subject.includes(':') ? subject.slice(subject.indexOf(':') + 1) : '');

const INTERVALS = [30, 60, 300, 900, 3600];
const INTERVAL_LABEL: Record<number, string> = { 30: '30 s', 60: '1 min', 300: '5 min', 900: '15 min', 3600: '1 h' };
const METHODS: HttpMethod[] = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const KIND_LABEL: Record<StepKind, string> = { http: 'HTTP request', dns: 'DNS resolve', tcp: 'TCP connect', tls: 'TLS certificate' };
const CRED_KIND: Record<string, string> = { bearer: 'Bearer token', basic: 'Basic auth', header: 'Header', oauth2_client_credentials: 'OAuth2 client credentials' };

/** Whether a host is inside a credential's bound hosts (allowlist-style rules). */
function bound(c: SyntheticCredential, host: string): boolean {
  return c.bound_hosts.some((b) => (b.kind === 'exact' ? host === b.pattern : b.kind === 'wildcard' ? host.endsWith(b.pattern.replace(/^\*/, '')) && host !== b.pattern.replace(/^\*\./, '') : host === b.pattern || host.endsWith('.' + b.pattern)));
}

// ------------------------------------------------------------ messages

/** The settings link admins get under a "not allowed" message; everyone else is told to ask an admin. */
function AllowlistFollowUp({ admin, withText }: { admin: boolean; withText: boolean }) {
  if (admin)
    return (
      <>
        {withText ? ' Add a rule in ' : ' '}
        <Link to="/settings/synthetic">Settings › Synthetic monitoring</Link>
        {withText ? '.' : ''}
      </>
    );
  return withText ? <> Ask an admin to add it to the synthetic allowlist.</> : null;
}

/** A field message from the API; the allowlist message gets its settings link for admins. */
function ApiMessage({ text, admin }: { text: string; admin: boolean }) {
  const link = admin && text.includes('Settings › Synthetic monitoring');
  return (
    <>
      {link ? text.replace(/Add a rule in Settings › Synthetic monitoring\.?$/, 'Add a rule in ') : text}
      {link && (
        <>
          <Link to="/settings/synthetic">Settings › Synthetic monitoring</Link>.
        </>
      )}
    </>
  );
}

function FieldMsg({ id, text, admin }: { id: string; text?: string; admin: boolean }) {
  if (!text) return null;
  return (
    <div className="field-error" id={`${id}-err`} role="alert">
      <ApiMessage text={text} admin={admin} />
    </div>
  );
}

/** Names resolve as absolute names (no search list): a short or partial in-cluster name never works. */
function shortName(host: string): boolean {
  return !!host && (!host.includes('.') || /\.svc(\.cluster)?$/.test(host));
}

/** The allowlist hint under a URL or host, from POST /synthetic/allowlist/check. */
function HostHint({ value, admin }: { value: string; admin: boolean }) {
  const host = urlHost(value);
  const [debounced, setDebounced] = useState(host);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(host), 350);
    return () => clearTimeout(t);
  }, [host]);
  const q = useQuery({ queryKey: ['synthetic', 'allowlist-check', debounced], queryFn: () => api.post<HostCheck>('/synthetic/allowlist/check', { host: debounced }), enabled: !!debounced, staleTime: 60_000, retry: false });
  if (!host) return value.includes('${') && /:\/\/[^/]*\$\{/.test(value) ? <div className="hint-line ico-crit">A variable cannot be used in a host.</div> : null;
  const short = shortName(host) && (
    <div className="hint-line muted">Names are resolved as absolute names, without the search list: write in-cluster services in full, svc.ns.svc.cluster.local.</div>
  );
  if (host !== debounced || q.isPending)
    return (
      <>
        <div className="hint-line muted">
          <Spinner label="Checking the allowlist" /> Checking {host} against the allowlist…
        </div>
        {short}
      </>
    );
  if (q.isError) return <div className="hint-line muted">Could not check the allowlist now.</div>;
  const h = q.data;
  if (h.allowed && h.rule)
    return (
      <>
        <div className="hint-line">
          <CheckIcon ok label="Allowed" /> Host allowed by <span className="mono">{h.rule.pattern}</span>
          {h.rule.kind === 'suffix' && <span className="muted"> (suffix)</span>}
        </div>
        {short}
      </>
    );
  return (
    <>
      <div className="hint-line" role="status">
        <CheckIcon ok={false} label="Not allowed" /> <span>{h.message || `No rule matches ${h.host}.`}</span>
        {h.denied_reason === 'no_rule' && <AllowlistFollowUp admin={admin} withText />}
      </div>
      {short}
    </>
  );
}

const FIELD_NAMES: Record<string, string> = {
  name: 'Name',
  owner_selector: 'Owner label',
  type: 'Type',
  steps: 'Steps',
  interval_seconds: 'Every',
  timeout_seconds: 'Timeout',
  step_retries: 'Retry',
  run_on: 'Runs on',
  run_on_selector: 'Cluster labels',
  'alerts.cluster_fail_after': 'Alert a cluster after',
  'alerts.fleet_critical_clusters': 'Critical when failing in',
  'alerts.recovery_after': 'Recovery after',
  'alerts.channel_id': 'Channel',
  'alerts.critical_channel_id': 'Critical channel',
  cluster_id: 'Cluster',
};
function fieldLabel(k: string, stepKeys: string[] = []): string {
  const m = /^(?:scenario\.)?steps\.(\d+)\.(.*)$/.exec(k);
  if (m) return `Step ${Number(m[1]) + 1} ${m[2].replace(/^(http|dns|tcp|tls)\./, '').replace(/\./g, ' ')}`;
  const s = /^#([^.]+)\.(.*)$/.exec(k);
  if (s) {
    const i = stepKeys.indexOf(s[1]);
    const what = s[2].replace(/^(http|dns|tcp|tls)\./, '').replace(/^headers\./, 'header ').replace(/\./g, ' ');
    return i >= 0 ? `Step ${i + 1} ${what}` : `A removed step: ${what}`;
  }
  const x = /^exclude_selectors\.(\d+)$/.exec(k);
  if (x) return `Exclusion ${Number(x[1]) + 1}`;
  return FIELD_NAMES[k] ?? k;
}

const STEP_INLINE = /^(http\.url|http\.body|http\.headers\..+|dns\.name|tcp\.host|tcp\.port|tls\.host|tls\.sni|credential_id)$/;

/** Keys of top-level fields the form shows next to their input. */
function topInline(k: string): boolean {
  return /^(name|owner_selector|interval_seconds|timeout_seconds|step_retries|run_on_selector|alerts\.[a-z_]+)$/.test(k);
}

/**
 * Whether the form shows an error next to its field. A step's field is shown on its step card (the step opens), a
 * header error on the header row of that name, as long as the row still exists.
 */
function shownInline(k: string, steps: EStep[]): boolean {
  if (topInline(k)) return true;
  const m = /^#([^.]+)\.(.+)$/.exec(k);
  if (!m || !STEP_INLINE.test(m[2])) return false;
  const es = steps.find((s) => s.key === m[1]);
  if (!es || es.step.hidden) return false;
  if (m[2].startsWith('http.headers.')) return es.headers.some((h) => h.name.trim() === m[2].slice('http.headers.'.length));
  return true;
}

/** The message of a failed save or test run. `all`: list every field (the test-run panel), else the ones not highlighted. */
function ErrorSummary({ error, fields, steps, admin, title, all }: { error: unknown; fields: Record<string, string>; steps: EStep[]; admin: boolean; title?: string; all?: boolean }) {
  if (!error) return null;
  const keys = steps.map((s) => s.key);
  const rest = Object.entries(fields).filter(([k]) => all || !shownInline(k, steps));
  const inline = Object.keys(fields).filter((k) => shownInline(k, steps)).length;
  return (
    <div className="note crit" role="alert">
      <b>{title ?? sentence(error instanceof Error ? error.message : 'Could not save the scenario.')}</b>
      {inline > 0 && <span> Check the highlighted fields.</span>}
      {rest.length > 0 && (
        <ul className="note-list">
          {rest.map(([k, v]) => (
            <li key={k}>
              {fieldLabel(k, keys)}: <ApiMessage text={v} admin={admin} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** A query the form needs that failed: say so where its control is, with a retry. */
function LoadError({ what, q }: { what: string; q: { isError: boolean; error: unknown; refetch: () => unknown } }) {
  if (!q.isError) return null;
  return (
    <div className="field-error" role="alert">
      Could not load {what}: {errorMessage(q.error)}{' '}
      <button type="button" className="link-btn small" onClick={() => void q.refetch()}>
        Retry
      </button>
    </div>
  );
}

// ------------------------------------------------------------ page

export function ScenarioEditorPage() {
  const search = monitoringEditorRoute.useSearch();
  const me = useMe();
  const q = useQuery({ queryKey: scenarioKey(search.scenario ?? ''), queryFn: () => api.get<Scenario>(`/synthetic/scenarios/${search.scenario}`), enabled: !!search.scenario });
  if (!can(me, 'synthetic_edit')) return <ForbiddenState what="the scenario editor (it needs the synthetic-editor role)" />;
  if (search.scenario && q.isPending) return <Loading label="Loading the scenario…" />;
  if (search.scenario && q.isError) return <ErrorState what="this scenario" error={q.error} onRetry={() => q.refetch()} />;
  if (q.data && !q.data.can_edit)
    return (
      <>
        <PageHead crumbs={<CrumbLinks name={q.data.name} scenarioId={q.data.id} tail="Edit" />} title="Edit scenario" />
        <div className="note warn" role="note">
          You cannot edit this scenario: it runs on clusters outside your synthetic-editor scope. Ask an admin to change it or to extend your grant.
        </div>
      </>
    );
  // a fresh editor per scenario, so the draft starts from what was loaded
  return <Editor key={q.data?.id ?? 'new'} initial={q.data ? fromScenario(q.data) : blank()} testCluster={search.cluster} />;
}

function Editor({ initial, testCluster }: { initial: Draft; testCluster?: string }) {
  const me = useMe();
  const admin = can(me, 'admin_global');
  const globalEditor = can(me, 'synthetic_edit_global');
  const [d, setD] = useState<Draft>(initial);
  const [open, setOpen] = useState<string | null>(initial.steps.length === 1 ? initial.steps[0].key : null);
  const save = useAction<Scenario>();
  // Field errors of the last save or test run, keyed by step key (keyFields); `sent` holds each step as it was sent,
  // so an error on a field goes away once that field is changed.
  const [errState, setErrs] = useState<{ source: 'save' | 'test' | ''; fields: Record<string, string>; sent: Record<string, ScenarioStep> }>({ source: '', fields: {}, sent: {} });
  const navigate = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const fields = errState.fields;
  const credsQ = useQuery({ queryKey: ['synthetic', 'credentials'], queryFn: () => api.get<ItemList<SyntheticCredential>>('/synthetic/credentials'), retry: false });
  const channelsQ = useQuery({ queryKey: ['channels'], queryFn: () => api.get<ItemList<Channel>>('/notifications/channels') });
  const single = d.type !== 'http_flow';
  const hidden = d.steps.some((s) => s.step.hidden);
  /** Runs a request that sends the draft; its field errors go to the form. */
  const sending = async <R,>(source: 'save' | 'test', fn: () => Promise<R>): Promise<R> => {
    const keys = d.steps.map((s) => s.key);
    const sent = Object.fromEntries(d.steps.map((s) => [s.key, stepInput(s)]));
    try {
      const r = await fn();
      setErrs({ source: '', fields: {}, sent: {} });
      return r;
    } catch (e) {
      const raw = e instanceof ApiError ? e.fields : {};
      const f = keyFields(raw, keys, credsQ.data?.items ?? []);
      setErrs({ source, fields: f, sent });
      // a request that names a step's field opens that step
      const first = Object.keys(f).map((k) => /^#([^.]+)\./.exec(k)?.[1]).find(Boolean);
      if (first) setOpen(first);
      throw e;
    }
  };

  const set = (p: Partial<Draft>) => setD((x) => ({ ...x, ...p }));
  const setStep = (key: string, f: (s: EStep) => EStep) => setD((x) => ({ ...x, steps: x.steps.map((s) => (s.key === key ? f(s) : s)) }));
  const setType = (type: ScenarioType) =>
    setD((x) => {
      if (type === 'http_flow') return { ...x, type };
      const keep = x.steps.find((s) => s.step.kind === type);
      const steps = [keep ?? wrap(newStep(type))];
      setOpen(steps[0].key);
      return { ...x, type, steps };
    });
  const move = (i: number, by: number) =>
    setD((x) => {
      const steps = [...x.steps];
      const [s] = steps.splice(i, 1);
      steps.splice(i + by, 0, s);
      return { ...x, steps };
    });

  const onSave = async () => {
    const body = toInput(d, d.id ? initial : undefined);
    const r = await save.run(() => sending('save', () => (d.id ? api.put<Scenario>(`/synthetic/scenarios/${d.id}`, body) : api.post<Scenario>('/synthetic/scenarios', body))));
    if (!r) {
      window.scrollTo?.({ top: 0 });
      return;
    }
    qc.setQueryData(scenarioKey(r.id), r);
    void qc.invalidateQueries({ queryKey: ['synthetic'] });
    toast(`Saved ${r.name}.`);
    void navigate({ to: '/monitoring', search: { scenario: r.id } });
  };

  const stepErrors = (key: string) => Object.entries(fields).filter(([k]) => k.startsWith(`#${key}.`));
  const cancel = d.id ? (
    <Link to="/monitoring" search={{ scenario: d.id }} className="btn">
      Cancel
    </Link>
  ) : (
    <Link to="/monitoring" className="btn">
      Cancel
    </Link>
  );

  return (
    <>
      <PageHead
        crumbs={<CrumbLinks name={d.id ? initial.name : 'New scenario'} scenarioId={d.id} tail={d.id ? 'Edit' : undefined} />}
        title={d.id ? 'Edit scenario' : 'New scenario'}
        actions={
          <>
            {cancel}
            <button type="button" className="btn pri" onClick={() => void onSave()} disabled={save.pending || hidden} aria-describedby={hidden ? 'hidden-why' : undefined}>
              {save.pending ? 'Saving…' : 'Save scenario'}
            </button>
          </>
        }
      />
      {hidden && (
        <div className="note warn" role="note" id="hidden-why">
          Some steps use a credential and their headers and body are hidden from you, so this scenario cannot be saved from here: saving would send those steps back without them. Ask an
          editor to change it.
        </div>
      )}
      <ErrorSummary error={errState.source === 'save' ? save.error : null} fields={fields} steps={d.steps} admin={admin} />
      <div className="editor-cols">
        <div className="editor-main">
          <section className="card pad-lg" aria-labelledby="basics-h">
            <h2 id="basics-h">Basics</h2>
            <div className="grid-2">
              <div>
                <label className="lbl" htmlFor="sn">
                  Name
                </label>
                <input className="in" value={d.name} onChange={(e) => set({ name: e.target.value })} maxLength={200} {...aria('sn', fields.name)} />
                <FieldMsg id="sn" text={fields.name} admin={admin} />
              </div>
              <div>
                <label className="lbl" htmlFor="so">
                  Owner label
                </label>
                <input className="in mono" value={d.owner_selector} placeholder="team=payments" onChange={(e) => set({ owner_selector: e.target.value })} {...aria('so', fields.owner_selector, true)} />
                <FieldMsg id="so" text={fields.owner_selector} admin={admin} />
                {!fields.owner_selector && (
                  <div className="field-hint" id="so-hint">
                    A label to show and filter by; it does not decide who may edit.
                  </div>
                )}
              </div>
            </div>
            <div>
              <div className="lbl" id="type-l">
                Type
              </div>
              <div className="pills" role="group" aria-labelledby="type-l">
                {(Object.keys(TYPE_LABEL) as ScenarioType[]).map((t) => (
                  <button key={t} type="button" className="pill" aria-pressed={d.type === t} onClick={() => setType(t)}>
                    {TYPE_LABEL[t]}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="chk">
                <input type="checkbox" checked={d.store_responses} onChange={(e) => set({ store_responses: e.target.checked })} aria-describedby="sr-hint" /> Store response excerpts
              </label>
              <div className="field-hint" id="sr-hint">
                {d.store_responses
                  ? 'Keeps the first 2 KB of each HTTP response for 7 days, redacted on the probe, so a failed run shows what came back.'
                  : 'Off: no response excerpts or response text are kept for this scenario. A privacy control for responses that may hold personal data; runs still record status, timings and assertions.'}
              </div>
            </div>
          </section>

          <section className="card pad-lg" aria-labelledby="steps-h">
            <div className="spread">
              <h2 id="steps-h">{single ? 'Check' : 'Steps'}</h2>
              {!single && <span className="muted small">Steps run in order; the run stops at the first failed step</span>}
            </div>
            {fields.steps && <div className="field-error" role="alert">{fields.steps}</div>}
            <ol className="plain-list stack-sm" aria-label="Steps">
              {d.steps.map((es, i) => {
                const errs = stepErrors(es.key);
                const isOpen = single || open === es.key;
                if (!isOpen) {
                  const { title, detail } = stepTitle(es.step);
                  return (
                    <li key={es.key} className={`step-card${errs.length ? ' failed' : ''}`}>
                      <div className="spread">
                        <div className="inline-sm">
                          <span className="snum">{i + 1}</span>
                          <b>{es.step.kind === 'http' ? es.step.http?.method : title}</b>
                          <span className="mono muted break">{es.step.kind === 'http' ? es.step.http?.url : detail}</span>
                          {errs.length > 0 && <span className="ico-crit small">· {plural(errs.length, 'problem')}</span>}
                        </div>
                        <button type="button" className="btn sm" onClick={() => setOpen(es.key)} aria-label={`Edit step ${i + 1}`}>
                          Edit
                        </button>
                      </div>
                    </li>
                  );
                }
                return (
                  <li key={es.key} className="step-card open">
                    <StepEditor
                      index={i}
                      es={es}
                      single={single}
                      count={d.steps.length}
                      creds={credsQ.data?.items ?? []}
                      fields={fields}
                      sent={errState.sent[es.key]}
                      credsQ={credsQ}
                      admin={admin}
                      onChange={(f) => setStep(es.key, f)}
                      onMove={(by) => move(i, by)}
                      onRemove={() => set({ steps: d.steps.filter((s) => s.key !== es.key) })}
                      onDone={() => setOpen(null)}
                    />
                  </li>
                );
              })}
            </ol>
            {!single && d.steps.length < 10 && (
              <button
                type="button"
                className="btn self-start"
                onClick={() => {
                  const s = wrap(newStep('http'));
                  set({ steps: [...d.steps, s] });
                  setOpen(s.key);
                }}
              >
                + Add step
              </button>
            )}
          </section>
        </div>

        <aside className="editor-side">
          <section className="card pad-lg" aria-labelledby="sched-h">
            <h2 id="sched-h">Schedule</h2>
            <div>
              <div className="lbl" id="every-l">
                Every
              </div>
              <div className="pills" role="group" aria-labelledby="every-l">
                {[...INTERVALS, ...(INTERVALS.includes(d.interval_seconds) ? [] : [d.interval_seconds])].map((s) => (
                  <button key={s} type="button" className="pill" aria-pressed={d.interval_seconds === s} onClick={() => set({ interval_seconds: s })}>
                    {INTERVAL_LABEL[s] ?? `${s} s`}
                  </button>
                ))}
              </div>
              <FieldMsg id="every" text={fields.interval_seconds} admin={admin} />
            </div>
            <div className="grid-2">
              <div>
                <label className="lbl" htmlFor="to">
                  Timeout (seconds)
                </label>
                <input className="in mono" type="number" min={1} max={60} value={d.timeout_seconds} onChange={(e) => set({ timeout_seconds: Number(e.target.value) })} {...aria('to', fields.timeout_seconds)} />
                <FieldMsg id="to" text={fields.timeout_seconds} admin={admin} />
              </div>
              <div>
                <label className="lbl" htmlFor="rt">
                  Retry a failed step
                </label>
                <select className="in" value={d.step_retries} onChange={(e) => set({ step_retries: Number(e.target.value) })} {...aria('rt', fields.step_retries)}>
                  <option value={0}>No retry</option>
                  <option value={1}>1 time</option>
                  <option value={2}>2 times</option>
                </select>
                <FieldMsg id="rt" text={fields.step_retries} admin={admin} />
              </div>
            </div>
          </section>

          <RunsOn d={d} set={set} fields={fields} admin={admin} globalEditor={globalEditor} />

          <section className="card pad-lg" aria-labelledby="alert-h">
            <h2 id="alert-h">Alerting</h2>
            <div className="grid-2">
              <NumberField id="a1" label="Alert a cluster after" unit="failed runs" value={d.alerts.cluster_fail_after} onChange={(v) => set({ alerts: { ...d.alerts, cluster_fail_after: v } })} error={fields['alerts.cluster_fail_after']} admin={admin} />
              <NumberField id="a2" label="Critical when failing in" unit="clusters" value={d.alerts.fleet_critical_clusters} onChange={(v) => set({ alerts: { ...d.alerts, fleet_critical_clusters: v } })} error={fields['alerts.fleet_critical_clusters']} admin={admin} />
            </div>
            <LoadError what="the channels" q={channelsQ} />
            <ChannelSelect id="ch" label="Channel" value={d.alerts.channel_id} none="The routes of the synthetic events" channels={channelsQ.data?.items ?? []} onChange={(v) => set({ alerts: { ...d.alerts, channel_id: v } })} error={fields['alerts.channel_id']} admin={admin} />
            <ChannelSelect id="ch2" label="Critical channel" value={d.alerts.critical_channel_id} none="Same as the channel" channels={channelsQ.data?.items ?? []} onChange={(v) => set({ alerts: { ...d.alerts, critical_channel_id: v } })} error={fields['alerts.critical_channel_id']} admin={admin} />
            <div className="chk wrap-gap">
              <input id="rec" type="checkbox" checked={d.alerts.send_recovery} onChange={(e) => set({ alerts: { ...d.alerts, send_recovery: e.target.checked } })} />
              <label htmlFor="rec">Send a recovery message after</label>
              <input className="in mono tiny" type="number" min={1} max={1000} aria-label="Passing runs before the recovery message" value={d.alerts.recovery_after} onChange={(e) => set({ alerts: { ...d.alerts, recovery_after: Number(e.target.value) } })} />
              <span>passing runs</span>
            </div>
            <FieldMsg id="rec" text={fields['alerts.recovery_after']} admin={admin} />
          </section>

          <TestRun d={d} admin={admin} initialCluster={testCluster} sending={(fn) => sending('test', fn)} disabled={hidden} fields={errState.source === 'test' ? fields : {}} />
        </aside>
      </div>
    </>
  );
}

function NumberField({ id, label, unit, value, onChange, error, admin }: { id: string; label: string; unit: string; value: number; onChange: (v: number) => void; error?: string; admin: boolean }) {
  return (
    <div>
      <label className="lbl" htmlFor={id}>
        {label}
      </label>
      <div className="inline-sm nowrap">
        <input className="in mono" type="number" min={1} max={1000} value={value} onChange={(e) => onChange(Number(e.target.value))} {...aria(id, error)} />
        <span className="muted small">{unit}</span>
      </div>
      <FieldMsg id={id} text={error} admin={admin} />
    </div>
  );
}

function ChannelSelect({ id, label, value, none, channels, onChange, error, admin }: { id: string; label: string; value: string | null; none: string; channels: Channel[]; onChange: (v: string | null) => void; error?: string; admin: boolean }) {
  return (
    <div>
      <label className="lbl" htmlFor={id}>
        {label}
      </label>
      <select className="in" value={value ?? ''} onChange={(e) => onChange(e.target.value || null)} {...aria(id, error)}>
        <option value="">{none}</option>
        {channels.map((c) => (
          <option key={c.id} value={c.id}>
            {c.name}
          </option>
        ))}
      </select>
      <FieldMsg id={id} text={error} admin={admin} />
    </div>
  );
}

// ------------------------------------------------------------ runs on

function RunsOn({ d, set, fields, admin, globalEditor }: { d: Draft; set: (p: Partial<Draft>) => void; fields: Record<string, string>; admin: boolean; globalEditor: boolean }) {
  const body = previewBody(d);
  const [debounced, setDebounced] = useState(body);
  const json = JSON.stringify(body);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(JSON.parse(json)), 300);
    return () => clearTimeout(t);
  }, [json]);
  const q = useQuery({ queryKey: ['synthetic', 'preview', debounced], queryFn: () => api.post<ScenarioPreview>('/synthetic/scenarios/preview', debounced), retry: false, placeholderData: (prev) => prev });
  const p = q.data;
  const previewErr = q.error instanceof ApiError ? Object.values(q.error.fields)[0] ?? q.error.message : q.isError ? 'Could not count the clusters now.' : '';
  const exclErrors = Object.entries(fields).filter(([k]) => k.startsWith('exclude_selectors'));
  return (
    <section className="card pad-lg" aria-labelledby="runs-h">
      <h2 id="runs-h">Runs on</h2>
      <fieldset className="plain stack-sm">
        <legend className="sr-only">Runs on</legend>
        <label className="opt">
          <input type="radio" name="ro" checked={d.run_on === 'all'} onChange={() => set({ run_on: 'all' })} />
          <span>
            <span className="t1">All clusters</span>
            <span className="t2">{globalEditor ? 'New clusters are included automatically' : 'Needs the synthetic-editor role with scope all; yours covers some clusters only'}</span>
          </span>
        </label>
        <label className="opt">
          <input type="radio" name="ro" checked={d.run_on === 'selector'} onChange={() => set({ run_on: 'selector' })} />
          <span>
            <span className="t1">Clusters matching labels</span>
            <span className="t2">{globalEditor ? 'A label selector over the cluster labels' : 'You need the role on every cluster the selector matches now'}</span>
          </span>
        </label>
      </fieldset>
      {d.run_on === 'selector' && (
        <div>
          <label className="lbl" htmlFor="ros">
            Cluster labels
          </label>
          <input className="in mono" value={d.run_on_selector} placeholder="env=prod" onChange={(e) => set({ run_on_selector: e.target.value })} {...aria('ros', fields.run_on_selector)} />
          <FieldMsg id="ros" text={fields.run_on_selector} admin={admin} />
        </div>
      )}
      <div>
        <label className="lbl" htmlFor="excl">
          Exclude
        </label>
        <TagInput
          id="excl"
          mode="values"
          listLabel="Exclusions"
          placeholder="label or cluster…"
          value={d.exclude_selectors}
          validate={(v) => {
            const sel = v.includes('=') || v.includes('!') ? v : `olympos.io/cluster=${v}`;
            return parseSelector(sel).error;
          }}
          onChange={(v) => set({ exclude_selectors: v.map((x) => (x.includes('=') || x.includes('!') ? x : `olympos.io/cluster=${x}`)) })}
        />
        <div className="field-hint">A label selector (env=dev) or a cluster name; a cluster that matches any of them is left out.</div>
        {exclErrors.map(([k, v]) => (
          <div key={k} className="field-error" role="alert">
            {fieldLabel(k)}: {v}
          </div>
        ))}
      </div>
      <div className="note" aria-live="polite" aria-label="Where the scenario runs">
        {previewErr ? (
          <span className="ico-crit">{previewErr}</span>
        ) : !p ? (
          <span className="inline-sm">
            <Spinner label="Counting clusters" /> Counting clusters…
          </span>
        ) : (
          <>
            Runs on{' '}
            <b>
              {p.runs_on} of {p.of}
            </b>{' '}
            {p.of === 1 ? 'cluster' : 'clusters'}
            {p.clusters.length > 0 && `: ${p.clusters.join(', ')}`}
            {p.excluded.length > 0 && <div>Excluded: {p.excluded.join(', ')}</div>}
          </>
        )}
      </div>
      {p && (p.over_scenario_cap || p.over_limit.length > 0) && (
        <div className="note warn" role="note">
          {p.over_scenario_cap && (
            <div>
              Up to {p.requests_per_minute} requests per minute on each cluster; the cap is {p.scenario_cap}. Run it less often, retry less or follow fewer redirects.
            </div>
          )}
          {p.over_limit.length > 0 && (
            <div>
              Over the cap of {p.cluster_cap} requests per minute per cluster on {p.over_limit.map((o) => `${o.cluster} (${o.requests_per_minute}/min)`).join(', ')}.
            </div>
          )}
        </div>
      )}
    </section>
  );
}

// ------------------------------------------------------------ one step

function StepEditor({
  index,
  es,
  single,
  count,
  creds,
  fields,
  admin,
  onChange,
  onMove,
  onRemove,
  onDone,
  sent,
  credsQ,
}: {
  /** The step as the last save or test run sent it. */
  sent?: ScenarioStep;
  credsQ: { isError: boolean; error: unknown; refetch: () => unknown };
  index: number;
  es: EStep;
  single: boolean;
  count: number;
  creds: SyntheticCredential[];
  fields: Record<string, string>;
  admin: boolean;
  onChange: (f: (s: EStep) => EStep) => void;
  onMove: (by: number) => void;
  onRemove: () => void;
  onDone: () => void;
}) {
  const st = es.step;
  const id = useId().replace(/:/g, '');
  const now = stepInput(es);
  /** The error of a field of this step, until the field is changed (then the live hint takes over). */
  const f = (rest: string) => {
    const msg = fields[`#${es.key}.${rest}`];
    return msg && sent && JSON.stringify(stepValue(now, rest)) !== JSON.stringify(stepValue(sent, rest)) ? undefined : msg;
  };
  const setStep = (p: Partial<ScenarioStep>) => onChange((s) => ({ ...s, step: { ...s.step, ...p } }));
  const n = index + 1;
  const others = Object.entries(fields).filter(([k]) => k.startsWith(`#${es.key}.`) && !shownInline(k, [es]));
  if (st.hidden) {
    const { title, detail } = stepTitle(st);
    return (
      <div className="stack-sm">
        <div className="inline-sm">
          <span className="snum">{n}</span>
          <b>{title}</b>
          <span className="mono muted break">{detail}</span>
        </div>
        <HiddenNote />
        <span className="muted small">This step is read-only here: it is kept exactly as it is saved.</span>
      </div>
    );
  }
  return (
    <div className="stack-sm">
      <div className="spread">
        <div className="inline-sm">
          <span className="snum">{n}</span>
          {single ? (
            <b>{KIND_LABEL[st.kind]}</b>
          ) : (
            <select
              className="in compact"
              aria-label={`Step ${n} type`}
              value={st.kind}
              onChange={(e) => {
                const k = e.target.value as StepKind;
                onChange((s) => ({ ...s, step: newStep(k), headers: [] }));
              }}
            >
              {(Object.keys(KIND_LABEL) as StepKind[]).map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </select>
          )}
        </div>
        {!single && (
          <div className="inline-sm">
            <button type="button" className="btn sm" aria-label={`Move step ${n} up`} disabled={index === 0} onClick={() => onMove(-1)}>
              <IconArrowUp />
            </button>
            <button type="button" className="btn sm" aria-label={`Move step ${n} down`} disabled={index === count - 1} onClick={() => onMove(1)}>
              <IconArrowDown />
            </button>
            <button type="button" className="btn sm" onClick={onRemove} disabled={count === 1} aria-label={`Remove step ${n}`}>
              Remove
            </button>
            <button type="button" className="btn sm" onClick={onDone} aria-label={`Close step ${n}`}>
              Done
            </button>
          </div>
        )}
      </div>

      {st.kind === 'http' && st.http && (
        <>
          <div className="method-url">
            <select className="in" aria-label={`Step ${n} method`} value={st.http.method} onChange={(e) => setStep({ http: { ...st.http!, method: e.target.value as HttpMethod } })}>
              {METHODS.map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <input className="in mono" aria-label={`Step ${n} URL`} value={st.http.url} onChange={(e) => setStep({ http: { ...st.http!, url: e.target.value } })} spellCheck={false} {...aria(`${id}-url`, f('http.url'))} />
          </div>
          <FieldMsg id={`${id}-url`} text={f('http.url')} admin={admin} />
          {!f('http.url') && <HostHint value={st.http.url} admin={admin} />}
          <HeadersEditor n={n} id={id} rows={es.headers} errorOf={(name) => f(`http.headers.${name}`)} admin={admin} onChange={(headers) => onChange((s) => ({ ...s, headers }))} />
          {st.http.method !== 'GET' && st.http.method !== 'HEAD' && (
            <div>
              <div className="spread">
                <label className="lbl" htmlFor={`${id}-body`}>
                  Body
                </label>
                <select className="in compact" aria-label={`Step ${n} body type`} value={st.http.body_type ?? 'text'} onChange={(e) => setStep({ http: { ...st.http!, body_type: e.target.value as 'text' | 'json' } })}>
                  <option value="text">Text</option>
                  <option value="json">JSON</option>
                </select>
              </div>
              <textarea className="in mono" rows={4} value={st.http.body ?? ''} onChange={(e) => setStep({ http: { ...st.http!, body: e.target.value } })} spellCheck={false} {...aria(`${id}-body`, f('http.body'))} />
              <FieldMsg id={`${id}-body`} text={f('http.body')} admin={admin} />
            </div>
          )}
          <label className="chk">
            <input type="checkbox" checked={!!st.http.follow_redirects} onChange={(e) => setStep({ http: { ...st.http!, follow_redirects: e.target.checked } })} /> Follow redirects (at most 5; each hop is checked against the allowlist)
          </label>
          <div>
            <label className="lbl" htmlFor={`${id}-auth`}>
              Auth
            </label>
            <select className="in" value={st.credential_id ?? ''} onChange={(e) => setStep({ credential_id: e.target.value || null })} {...aria(`${id}-auth`, f('credential_id'), true)}>
              <option value="">None</option>
              {creds.map((c) => {
                const host = urlHost(st.http!.url);
                const off = host && !bound(c, host);
                return (
                  <option key={c.id} value={c.id}>
                    {c.name} · {CRED_KIND[c.kind] ?? c.kind}
                    {c.kind === 'header' && c.header_name ? ` ${c.header_name}` : ''} · bound to {c.bound_hosts.map((b) => b.pattern).join(', ')}
                    {off ? ' · not bound to this host' : ''}
                    {c.expired ? ' · expired' : ''}
                  </option>
                );
              })}
            </select>
            <FieldMsg id={`${id}-auth`} text={f('credential_id')} admin={admin} />
            <LoadError what="the credentials" q={credsQ} />
            {!f('credential_id') && (
              <div className="field-hint" id={`${id}-auth-hint`}>
                Stored encrypted in Olympos. Sent to the probe only for this run and attached only to requests whose host matches the credential's hosts.
                {admin ? (
                  <>
                    {' '}
                    Credentials are managed in <Link to="/settings/synthetic">Settings › Synthetic monitoring</Link>.
                  </>
                ) : (
                  ' Only admins add credentials.'
                )}
              </div>
            )}
          </div>
        </>
      )}

      {st.kind === 'dns' && st.dns && (
        <div className="method-url">
          <select className="in" aria-label={`Step ${n} record type`} value={st.dns.record_type} onChange={(e) => setStep({ dns: { ...st.dns!, record_type: e.target.value as 'A' } })}>
            {['A', 'AAAA', 'CNAME', 'TXT'].map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
          <div>
            <input className="in mono" aria-label={`Step ${n} name`} placeholder="api.prod.wrw.com" value={st.dns.name} onChange={(e) => setStep({ dns: { ...st.dns!, name: e.target.value } })} {...aria(`${id}-dns`, f('dns.name'))} />
            <FieldMsg id={`${id}-dns`} text={f('dns.name')} admin={admin} />
            {!f('dns.name') && <HostHint value={st.dns.name} admin={admin} />}
          </div>
        </div>
      )}

      {(st.kind === 'tcp' || st.kind === 'tls') && (
        <HostPort
          n={n}
          id={id}
          host={(st.tcp ?? st.tls)?.host ?? ''}
          port={(st.tcp ?? st.tls)?.port ?? 443}
          hostError={f(`${st.kind}.host`)}
          portError={f(`${st.kind}.port`)}
          admin={admin}
          onChange={(host, port) => setStep(st.kind === 'tcp' ? { tcp: { host, port } } : { tls: { ...st.tls!, host, port } })}
        />
      )}
      {st.kind === 'tls' && st.tls && (
        <div>
          <label className="lbl" htmlFor={`${id}-sni`}>
            SNI (optional)
          </label>
          <input className="in mono" value={st.tls.sni ?? ''} placeholder="the host" onChange={(e) => setStep({ tls: { ...st.tls!, sni: e.target.value } })} {...aria(`${id}-sni`, f('tls.sni'))} />
          <FieldMsg id={`${id}-sni`} text={f('tls.sni')} admin={admin} />
        </div>
      )}

      <AssertionsEditor n={n} kind={st.kind} list={st.assertions} errorOf={(i) => f(`assertions.${i}.value`) ?? f(`assertions.${i}.subject`) ?? f(`assertions.${i}`)} onChange={(assertions) => setStep({ assertions })} />
      {st.kind === 'http' && <ExtractsEditor n={n} list={st.extracts} onChange={(extracts) => setStep({ extracts })} />}
      {others.length > 0 && (
        <ul className="plain-list">
          {others.map(([k, v]) => (
            <li key={k} className="field-error" role="alert">
              {fieldLabel(k, [es.key]).replace(/^Step 1 /, '')}: <ApiMessage text={v} admin={admin} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function HostPort({ n, id, host, port, hostError, portError, admin, onChange }: { n: number; id: string; host: string; port: number; hostError?: string; portError?: string; admin: boolean; onChange: (host: string, port: number) => void }) {
  return (
    <div className="host-port">
      <div>
        <input className="in mono" aria-label={`Step ${n} host`} placeholder="kafka-0.kafka.data.svc.cluster.local" value={host} onChange={(e) => onChange(e.target.value, port)} {...aria(`${id}-host`, hostError)} />
        <FieldMsg id={`${id}-host`} text={hostError} admin={admin} />
        {!hostError && <HostHint value={host} admin={admin} />}
      </div>
      <div>
        <input className="in mono" type="number" min={1} max={65535} aria-label={`Step ${n} port`} value={port} onChange={(e) => onChange(host, Number(e.target.value))} {...aria(`${id}-port`, portError)} />
        <FieldMsg id={`${id}-port`} text={portError} admin={admin} />
      </div>
    </div>
  );
}

function HeadersEditor({
  n,
  id,
  rows,
  errorOf,
  admin,
  onChange,
}: {
  n: number;
  id: string;
  rows: { name: string; value: string }[];
  /** The error of the header with this name (a taint error is keyed by the header name). */
  errorOf: (name: string) => string | undefined;
  admin: boolean;
  onChange: (rows: { name: string; value: string }[]) => void;
}) {
  const set = (i: number, p: Partial<{ name: string; value: string }>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...p } : r)));
  return (
    <div>
      <div className="lbl">Headers</div>
      <div className="stack-xs">
        {rows.map((h, i) => {
          const err = h.name.trim() ? errorOf(h.name.trim()) : undefined;
          return (
            <div key={i}>
              <div className="hrow">
                <input className="in mono" aria-label={`Step ${n} header ${i + 1} name`} value={h.name} onChange={(e) => set(i, { name: e.target.value })} spellCheck={false} aria-invalid={err ? true : undefined} />
                <input className="in mono" aria-label={`Step ${n} header ${i + 1} value`} value={h.value} onChange={(e) => set(i, { value: e.target.value })} spellCheck={false} autoComplete="off" {...aria(`${id}-h${i}`, err)} />
                <button type="button" className="btn sm icon-sq" aria-label={`Remove header ${i + 1} of step ${n}`} onClick={() => onChange(rows.filter((_, j) => j !== i))}>
                  <IconClose />
                </button>
              </div>
              <FieldMsg id={`${id}-h${i}`} text={err} admin={admin} />
            </div>
          );
        })}
        <button type="button" className="btn sm self-start" onClick={() => onChange([...rows, { name: '', value: '' }])}>
          + Add header
        </button>
        <div className="field-hint">Use a credential for tokens: header values are stored as plain text and shown to editors.</div>
      </div>
    </div>
  );
}

function AssertionsEditor({ n, kind, list, errorOf, onChange }: { n: number; kind: StepKind; list: ScenarioAssertion[]; errorOf: (i: number) => string | undefined; onChange: (l: ScenarioAssertion[]) => void }) {
  const set = (i: number, a: ScenarioAssertion) => onChange(list.map((x, j) => (j === i ? a : x)));
  const subjects = SUBJECTS[kind];
  return (
    <div>
      <div className="lbl">Assertions · all must pass</div>
      <div className="stack-xs">
        {list.map((a, i) => {
          const base = baseOf(a.subject);
          const ops = OPERATORS[base] ?? (Object.keys(OPERATOR_LABEL) as AssertionOperator[]);
          const err = errorOf(i);
          return (
            <div key={i}>
              <div className="arow">
                <div className="stack-xs">
                  <select
                    className="in"
                    aria-label={`Step ${n} assertion ${i + 1} check`}
                    value={base}
                    onChange={(e) => {
                      const b = e.target.value;
                      const subject = b === 'header' ? 'header:' : b === 'json' ? 'json:$' : b;
                      const op = (OPERATORS[b] ?? ['equals'])[0];
                      set(i, { subject, operator: op, value: b === 'connects' || b === 'chain_valid' || b === 'hostname_matches' ? 'true' : '' });
                    }}
                  >
                    {[...subjects, ...(subjects.includes(base) ? [] : [base])].map((s) => (
                      <option key={s} value={s}>
                        {BASE_LABEL[s] ?? s}
                      </option>
                    ))}
                  </select>
                  {(base === 'header' || base === 'json') && (
                    <input className="in mono" aria-label={`Step ${n} assertion ${i + 1} ${base === 'header' ? 'header name' : 'JSON path'}`} placeholder={base === 'header' ? 'Content-Type' : '$.items'} value={argOf(a.subject)} onChange={(e) => set(i, { ...a, subject: `${base}:${e.target.value}` })} />
                  )}
                </div>
                <select className="in" aria-label={`Step ${n} assertion ${i + 1} operator`} value={a.operator} onChange={(e) => set(i, { ...a, operator: e.target.value as AssertionOperator })}>
                  {[...ops, ...(ops.includes(a.operator) ? [] : [a.operator])].map((o) => (
                    <option key={o} value={o}>
                      {OPERATOR_LABEL[o] ?? o}
                    </option>
                  ))}
                </select>
                {a.operator === 'exists' ? (
                  <span />
                ) : (
                  <input className="in mono" aria-label={`Step ${n} assertion ${i + 1} value`} placeholder={base === 'latency_ms' ? 'ms' : ''} value={a.value} onChange={(e) => set(i, { ...a, value: e.target.value })} aria-invalid={err ? true : undefined} />
                )}
                <button type="button" className="btn sm icon-sq" aria-label={`Remove assertion ${i + 1} of step ${n}`} onClick={() => onChange(list.filter((_, j) => j !== i))}>
                  <IconClose />
                </button>
              </div>
              {err && (
                <div className="field-error" role="alert">
                  {err}
                </div>
              )}
            </div>
          );
        })}
        <button type="button" className="btn sm self-start" onClick={() => onChange([...list, { subject: subjects[0], operator: (OPERATORS[subjects[0]] ?? ['equals'])[0], value: '' }])}>
          + Add assertion
        </button>
      </div>
    </div>
  );
}

function ExtractsEditor({ n, list, onChange }: { n: number; list: ScenarioExtract[]; onChange: (l: ScenarioExtract[]) => void }) {
  const set = (i: number, p: Partial<ScenarioExtract>) => onChange(list.map((x, j) => (j === i ? { ...x, ...p } : x)));
  return (
    <div>
      <div className="lbl">Extract for later steps</div>
      <div className="stack-xs">
        {list.map((e, i) => (
          <div key={i} className="xrow">
            <input className="in mono" aria-label={`Step ${n} variable ${i + 1} name`} placeholder="item" value={e.name} onChange={(ev) => set(i, { name: ev.target.value })} />
            <select className="in" aria-label={`Step ${n} variable ${i + 1} source`} value={e.source} onChange={(ev) => set(i, { source: ev.target.value as ScenarioExtract['source'] })}>
              <option value="json_path">JSON path</option>
              <option value="header">Header</option>
              <option value="regex">Regex</option>
            </select>
            <input className="in mono" aria-label={`Step ${n} variable ${i + 1} ${e.source === 'json_path' ? 'JSON path' : e.source === 'header' ? 'header name' : 'regex'}`} placeholder={e.source === 'json_path' ? '$.items[0].id' : e.source === 'header' ? 'Location' : 'id=(\\w+)'} value={e.expr} onChange={(ev) => set(i, { expr: ev.target.value })} />
            <button type="button" className="btn sm icon-sq" aria-label={`Remove variable ${i + 1} of step ${n}`} onClick={() => onChange(list.filter((_, j) => j !== i))}>
              <IconClose />
            </button>
          </div>
        ))}
        <button type="button" className="btn sm self-start" onClick={() => onChange([...list, { name: '', source: 'json_path', expr: '' }])}>
          + Add variable
        </button>
        {list.length > 0 && <div className="field-hint">Later steps use it as {'${name}'} in the URL, headers or body. Only the name is stored, never the value.</div>}
      </div>
    </div>
  );
}

// ------------------------------------------------------------ test run

/** "912 ms > 500 ms" for a failed latency check; the check and what came back otherwise. */
export function failedCheck(a: SyntheticStepResult['assertions'][number]): string {
  const x = Number(a.actual);
  const y = Number(a.expected);
  if ((a.operator === 'less_than' || a.operator === 'greater_than') && a.actual !== '' && a.expected !== '' && !Number.isNaN(x) && !Number.isNaN(y)) {
    const unit = a.subject === 'latency_ms' ? ' ms' : '';
    return `${a.actual}${unit} ${x === y ? '=' : x > y ? '>' : '<'} ${a.expected}${unit}`;
  }
  return `${assertionText(a)}: got ${actualText(a) || 'nothing'}`;
}

function TestRun({
  d,
  admin,
  initialCluster,
  sending,
  disabled,
  fields,
}: {
  d: Draft;
  admin: boolean;
  initialCluster?: string;
  sending: <R>(fn: () => Promise<R>) => Promise<R>;
  disabled: boolean;
  /** The form's field errors: after a failed test run, its own (keyed by step, credentials by name). */
  fields: Record<string, string>;
}) {
  const ov = useSyntheticOverview();
  const clusters = ov.data?.clusters ?? [];
  const [cluster, setCluster] = useState('');
  const picked = cluster || clusters.find((c) => c.id === initialCluster || c.name === initialCluster)?.id || clusters.find((c) => c.probe_status === 'online')?.id || '';
  const start = useAction<{ run_id: string }>();
  const [runId, setRunId] = useState<string | null>(null);
  // polling stops at the run's timeout plus a margin; after that the panel says there is no result yet
  const [deadline, setDeadline] = useState<number | undefined>();
  const [details, setDetails] = useState(false);
  const runQ = useSyntheticRun(runId, deadline);
  const r = runQ.data;
  const unfinished = !!runId && (!r || r.status === 'running' || r.status === 'scheduled');
  const now = useNow(unfinished ? 1000 : 60_000);
  const late = unfinished && deadline !== undefined && now >= deadline;
  const running = unfinished && !late;
  const go = async () => {
    setRunId(null);
    const res = await start.run(() => sending(() => api.post<{ run_id: string }>('/synthetic/test-runs', { scenario: toInput(d), cluster_id: picked })));
    if (res) {
      setDeadline(Date.now() + d.timeout_seconds * 1000 + POLL_MARGIN_MS);
      setRunId(res.run_id);
    }
  };
  const name = clusters.find((c) => c.id === picked)?.name ?? '';
  const e = start.error;
  return (
    <section className="card pad-lg" aria-labelledby="test-h">
      <h2 id="test-h">Test run</h2>
      <div className="test-row">
        <select className="in" aria-label="Cluster for test run" value={picked} onChange={(ev) => setCluster(ev.target.value)}>
          {clusters.length === 0 && <option value="">{ov.isError ? 'Clusters not loaded' : 'Loading clusters…'}</option>}
          {clusters.map((c) => (
            <option key={c.id} value={c.id} disabled={c.probe_status !== 'online'}>
              {c.name}
              {c.probe_status !== 'online' ? ` · probe ${c.probe_status.replace('_', ' ')}` : ''}
            </option>
          ))}
        </select>
        <button type="button" className="btn" onClick={() => void go()} disabled={!picked || start.pending || running || disabled}>
          {start.pending || running ? 'Running…' : 'Run once'}
        </button>
      </div>
      <LoadError what="the clusters" q={ov} />
      {e ? (
        <ErrorSummary
          error={e}
          fields={fields}
          steps={d.steps}
          admin={admin}
          all
          title={
            e instanceof ApiError && e.status === 429
              ? `Not run: ${sentence(e.message)}`
              : e instanceof ApiError && e.status === 409
                ? `Not run: ${sentence(e.message)} Pick a cluster whose probe is online.`
                : e instanceof ApiError && e.status === 422
                  ? 'Not run: the draft has errors.'
                  : undefined
          }
        />
      ) : null}
      {runId && (
        <div aria-live="polite" aria-label="Test run result">
          {late ? (
            <div className="stack-xs">
              <div className="chk muted">No result yet: the probe on {name} has not reported back within the timeout. It may still arrive.</div>
              <button type="button" className="link-btn small self-start" onClick={() => setDetails(true)}>
                Open the run details
              </button>
            </div>
          ) : !r || running ? (
            <div className="chk muted">
              <Spinner label="Test run" /> Running on {name}…
            </div>
          ) : (
            <TestResult r={r} onDetails={() => setDetails(true)} />
          )}
        </div>
      )}
      <p className="muted small" style={{ margin: 0 }}>
        Test runs never send alerts.
      </p>
      {details && runId && <RunDialog id={runId} onClose={() => setDetails(false)} />}
    </section>
  );
}

function TestResult({ r, onDetails }: { r: NonNullable<ReturnType<typeof useSyntheticRun>['data']>; onDetails: () => void }) {
  const lines: ReactNode[] = r.steps.map((st, i) => {
    const req = st.request;
    const t = req ? stepTitle(req).title : `Step ${i + 1}`;
    const ms = st.timings ? `${Math.round(st.timings.total_us / 1000)} ms` : '';
    const bad = st.assertions.filter((a) => !a.passed);
    if (st.status === 'skipped' || st.status === '')
      return (
        <div key={i} className="chk muted">
          <span className="ico-sp" aria-hidden="true">–</span> {i + 1} {t} · {st.status === 'skipped' ? 'skipped' : 'no result'}
        </div>
      );
    const ok = st.status === 'passed';
    return (
      <div key={i} className="chk">
        <CheckIcon ok={ok} />
        <span>
          {i + 1} {t}
          {st.status_code !== null && ` · ${st.status_code}`}
          {ok || !bad.length ? (ms ? ` · ${ms}` : '') : ' · '}
          {!ok && bad.length > 0 && <b className="ico-crit">{bad.map(failedCheck).join('; ')}</b>}
          {!ok && !bad.length && st.error && <b className="ico-crit">{reasonText(st.error)}</b>}
        </span>
      </div>
    );
  });
  return (
    <div className="stack-xs">
      {r.status === 'skipped' || r.status === 'error' ? <div className="ico-crit small">{r.status === 'skipped' ? 'Skipped' : 'Error'}: {reasonText(r.failure_reason)}</div> : null}
      {lines}
      <button type="button" className="link-btn small self-start" onClick={onDetails}>
        Open the run details
      </button>
    </div>
  );
}
