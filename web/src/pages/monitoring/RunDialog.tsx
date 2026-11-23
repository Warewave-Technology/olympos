// Run detail (docs/design/monitoring-run.html): the per-step waterfall, the assertions and the redacted response
// excerpt of a step, and "Copy as curl" with the credential replaced by $TOKEN (or $USERNAME:$PASSWORD).
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../../api/client';
import type { Scenario, StepTimings, SyntheticRunDetail, SyntheticStepResult } from '../../api/types';
import { useCan } from '../../auth/me';
import { dateTime, plural } from '../../lib/format';
import { toCurl } from '../../lib/curl';
import { CheckIcon } from '../../ui/icons';
import { CopyButton, ErrorState, Loading, Modal, useToast } from '../../ui/kit';
import { HiddenNote, actualText, assertionText, ordinal, reasonShort, reasonText, stepTitle } from '../../ui/synthetic';
import { scenarioKey } from './ScenarioDetail';

const PHASES: { key: keyof Omit<StepTimings, 'total_us'>; label: string; cls: string }[] = [
  { key: 'dns_us', label: 'DNS', cls: 'ph-dns' },
  { key: 'connect_us', label: 'connect', cls: 'ph-connect' },
  { key: 'tls_us', label: 'TLS', cls: 'ph-tls' },
  { key: 'ttfb_us', label: 'waiting (TTFB)', cls: 'ph-ttfb' },
  { key: 'download_us', label: 'download', cls: 'ph-dl' },
];

const runKey = (id: string) => ['synthetic', 'run', id] as const;
const msOf = (us: number) => (us >= 10_000 ? `${Math.round(us / 1000)} ms` : `${Math.round(us / 100) / 10} ms`);
const done = (r: SyntheticRunDetail | undefined) => !!r && r.status !== 'scheduled' && r.status !== 'running';

export function useSyntheticRun(id: string | null) {
  return useQuery({
    queryKey: runKey(id ?? ''),
    queryFn: () => api.get<SyntheticRunDetail>(`/synthetic/runs/${id}`),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data && !done(q.state.data) ? 1500 : false),
  });
}

/** "Failed at step 3 · latency", "Passed", "Skipped · probe offline". */
export function runTitle(r: SyntheticRunDetail): string {
  switch (r.status) {
    case 'passed':
      return 'Passed';
    case 'failed':
      return r.failed_step !== null ? `Failed at step ${r.failed_step + 1} · ${reasonShort(r.failure_reason)}` : `Failed · ${reasonShort(r.failure_reason)}`;
    case 'error':
      return `Error · ${reasonShort(r.failure_reason)}`;
    case 'skipped':
      return `Skipped · ${reasonShort(r.failure_reason)}`;
    default:
      return 'Running…';
  }
}

function runDescription(r: SyntheticRunDetail, s: Scenario | undefined): string {
  const parts: string[] = [];
  if (r.test) parts.push(`Test run${r.requested_by_name ? ` by ${r.requested_by_name}` : ''} · test runs never send alerts`);
  else if (r.manual) parts.push(`Run now${r.requested_by_name ? ` by ${r.requested_by_name}` : ''} · counts toward alerts`);
  if ((r.status === 'failed' || r.status === 'error') && r.consecutive_failures > 0 && !r.test) parts.push(`${ordinal(r.consecutive_failures)} failed run in a row`);
  if (r.alert) {
    const ch = s?.alerts.channel_name;
    parts.push(r.alert.state === 'firing' ? `alert sent${ch ? ` to ${ch}` : ''}` : 'alert resolved');
  }
  if (r.failure_reason && r.status !== 'failed') parts.push(reasonText(r.failure_reason));
  if (r.probe_ip) parts.push(`probe egress ${r.probe_ip}`);
  return parts.join(' · ');
}

function Waterfall({ r, selected, onSelect }: { r: SyntheticRunDetail; selected: number; onSelect: (i: number) => void }) {
  const steps = r.steps;
  const total = steps.reduce((n, s) => n + (s.timings?.total_us ?? 0), 0) || 1;
  let offset = 0;
  return (
    <div className="stack-sm">
      <div className="legend" aria-hidden="true">
        {PHASES.map((p) => (
          <span key={p.key}>
            <i className={p.cls} />
            {p.label}
          </span>
        ))}
      </div>
      <ul className="plain-list wf-list" aria-label="Steps">
        {steps.map((st, i) => {
          const req = st.request;
          const name = req ? stepTitle(req).title : `Step ${i + 1}`;
          const failed = st.status === 'failed' || st.status === 'error';
          const t = st.timings;
          const start = offset;
          if (t) offset += t.total_us;
          let left = (start / total) * 100;
          const phases = t
            ? PHASES.filter((p) => t[p.key] > 0).map((p) => {
                const w = (t[p.key] / total) * 100;
                const seg = { ...p, left, width: Math.max(w, 0.3), us: t[p.key] };
                left += w;
                return seg;
              })
            : [];
          const right = st.status === 'skipped' ? 'skipped' : st.status === '' ? (done(r) ? 'no result' : 'running') : t ? msOf(t.total_us) : '—';
          const summary = phases.map((p) => `${p.label} ${msOf(p.us)}`).join(', ');
          return (
            <li key={i}>
              <button type="button" className={`wf${selected === i ? ' on' : ''}${failed ? ' failed' : ''}${st.status === 'skipped' ? ' skipped' : ''}`} aria-pressed={selected === i} onClick={() => onSelect(i)}>
                <span className="wf-name">
                  {i + 1} {name}
                  {failed && <span className="sr-only"> (failed)</span>}
                </span>
                <span className="wf-bar" role="img" aria-label={summary || right}>
                  {phases.map((p) => (
                    <span key={p.key} className={p.cls} style={{ left: `${p.left}%`, width: `${p.width}%` }} />
                  ))}
                </span>
                <span className="mono wf-ms">{right}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function StepPanel({ r, st, s }: { r: SyntheticRunDetail; st: SyntheticStepResult; s: Scenario | undefined }) {
  const req = st.request;
  const n = st.position + 1;
  const curl = req && req.kind === 'http' && !req.hidden ? toCurl(req) : '';
  return (
    <div className="run-panels">
      <div className="boxed">
        <b className="strong">Step {n} assertions</b>
        {st.error && <div className="ico-crit small">{reasonText(st.error) || st.error}</div>}
        {st.assertions.length === 0 ? (
          <span className="muted small">{st.status === 'skipped' ? 'Skipped: an earlier step failed.' : st.status === '' ? 'No result for this step.' : 'No assertions were checked.'}</span>
        ) : (
          <ul className="plain-list" aria-label={`Step ${n} assertions`}>
            {st.assertions.map((a, i) => (
              <li key={i} className="chk">
                <CheckIcon ok={a.passed} />
                <span>{assertionText(a)}</span>
                <span className={`mono push-right${a.passed ? ' muted' : ' ico-crit'}`}>{actualText(a)}</span>
              </li>
            ))}
          </ul>
        )}
        {st.extracted_names.length > 0 && <span className="muted small">Extracted (names only): {st.extracted_names.map((x) => '${' + x + '}').join(', ')}</span>}
        {req && req.kind === 'http' && req.http && (
          <div className="stack-xs">
            <span className="mono small break">
              {req.http.method} {req.http.url}
            </span>
            {req.hidden ? <HiddenNote /> : req.credential && <span className="muted small">Auth: <span className="mono">{req.credential.name}</span>, sent as {curlVar(req.credential.kind)}</span>}
          </div>
        )}
      </div>
      <div className="boxed">
        <b className="strong">Response · first 2 KB</b>
        {st.excerpt ? (
          <pre className="code scroll" aria-label="Response excerpt">
            {st.excerpt}
          </pre>
        ) : (
          <span className="muted small">{req?.kind === 'http' ? (s && !s.store_responses ? 'This scenario does not keep responses.' : 'No response kept for this step.') : 'Only HTTP steps keep a response.'}</span>
        )}
        <span className="muted small">Kept 7 days. Cookie, Authorization and token-like headers are redacted on the probe.</span>
        {curl && r.definition === 'saved' && s && Date.parse(s.updated_at) > Date.parse(r.scheduled_for) && <span className="muted small">The scenario changed after this run; the request is the scenario as saved now.</span>}
      </div>
    </div>
  );
}

function curlVar(kind: string): string {
  return kind === 'basic' ? '$USERNAME:$PASSWORD' : '$TOKEN';
}

/** onBack: "Back to scenario" (the scenario's detail page); without it the button is not shown. */
export function RunDialog({ id, onClose, onBack }: { id: string; onClose: () => void; onBack?: (scenarioId: string) => void }) {
  const q = useSyntheticRun(id);
  const r = q.data;
  const canEdit = useCan('synthetic_edit');
  const sq = useQuery({ queryKey: scenarioKey(r?.scenario_id ?? ''), queryFn: () => api.get<Scenario>(`/synthetic/scenarios/${r!.scenario_id}`), enabled: !!r?.scenario_id && r.definition !== 'none', retry: false });
  const s = sq.data;
  const [picked, setPicked] = useState<number | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const again = useMutation({
    mutationFn: () => api.post<{ run_ids: string[] }>(`/synthetic/scenarios/${r!.scenario_id}/run`, { cluster_id: r!.cluster_id }),
    onSuccess: () => {
      toast(`Run queued on ${r!.cluster_name}. It counts toward alerts.`);
      setTimeout(() => void qc.invalidateQueries({ queryKey: ['synthetic'] }), 1500);
    },
    onError: (e) => toast(`Could not run the scenario: ${errorMessage(e)}`, 'crit'),
  });
  const failedIdx = r?.steps.findIndex((x) => x.status === 'failed' || x.status === 'error') ?? -1;
  const selected = picked ?? (failedIdx >= 0 ? failedIdx : Math.max(0, (r?.steps.length ?? 1) - 1));
  const st = r?.steps[selected];
  const curl = st?.request && st.request.kind === 'http' && !st.request.hidden ? toCurl(st.request) : '';
  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      eyebrow={r ? `${r.test ? 'Test run' : 'Run'} · ${r.cluster_name} · ${dateTime(r.started_at ?? r.scheduled_for)}` : 'Run'}
      title={r ? runTitle(r) : 'Run'}
      description={r ? runDescription(r, s) : undefined}
    >
      {q.isPending ? (
        <Loading label="Loading the run…" />
      ) : q.isError ? (
        <ErrorState what="this run" error={q.error} onRetry={() => q.refetch()} />
      ) : (
        r && (
          <>
            <div className="muted small">
              {r.scenario_name} · {plural(r.steps.length, 'step')}
              {r.total_ms !== null && ` · ${r.total_ms} ms in all`}
            </div>
            {r.steps.length === 0 ? <p className="muted small">The run has no step results.</p> : <Waterfall r={r} selected={selected} onSelect={setPicked} />}
            {st && <StepPanel r={r} st={st} s={s} />}
            <div className="spread">
              {onBack && r.scenario_id && !r.test ? (
                <button type="button" className="btn" onClick={() => onBack(r.scenario_id!)}>
                  Back to scenario
                </button>
              ) : (
                <span />
              )}
              <div className="inline">
                {curl && <CopyButton text={curl} label="Copy as curl" />}
                {st?.request?.hidden && <span className="muted small">Copy as curl: hidden (the step uses a credential)</span>}
                {canEdit && s?.can_edit && !r.test && s.enabled && (
                  <button type="button" className="btn pri" onClick={() => again.mutate()} disabled={again.isPending}>
                    Run again on {r.cluster_name}
                  </button>
                )}
              </div>
            </div>
          </>
        )
      )}
    </Modal>
  );
}
