import { useMemo, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { KyvernoPolicyDetail, KyvernoViolation } from '../api/types';
import { plural } from '../lib/format';
import { buildExamples, explainPolicy, isCelKind, policyMode, renderMessage, type Example, type RuleExplanation } from '../lib/kyverno';
import { kyvernoPolicyRoute } from '../router';
import { ScopeCrumbs, findCluster, resolveScope, scopeParam, useClusterList } from '../ui/clusterScope';
import { DataTable } from '../ui/DataTable';
import { Badge, EmptyState, QueryView } from '../ui/kit';
import { PageHead, SeverityBadge } from '../ui/status';
import { YamlView } from '../ui/YamlView';

const TYPE_LABEL: Record<RuleExplanation['type'], string> = { validate: 'Validate', mutate: 'Mutate', generate: 'Generate', verifyImages: 'Verify images', cel: 'CEL validation', other: 'Rule' };

export function KyvernoPolicyPage() {
  const s = kyvernoPolicyRoute.useSearch();
  const { list: clusters } = useClusterList();
  const cluster = findCluster(clusters, s.cluster);
  // where the user came from: one cluster (default) or the all-clusters view
  const backScope = resolveScope(s.from || s.cluster || 'all');
  const q = useQuery({
    queryKey: ['kyverno-policy', s.cluster, s.kind, s.namespace ?? '', s.name],
    queryFn: () => api.get<KyvernoPolicyDetail>('/security/kyverno/policy', { cluster: s.cluster, kind: s.kind, namespace: s.namespace, name: s.name }),
    enabled: !!(s.cluster && s.kind && s.name),
  });
  const crumbs = (
    <ScopeCrumbs area="Security" to="/security" scope={backScope} cluster={backScope.mode === 'cluster' ? findCluster(clusters, backScope.id) : undefined}>
      <span aria-hidden="true"> / </span>
      <Link to="/security" search={{ cluster: scopeParam(backScope), tab: 'kyverno' }}>
        Kyverno policies
      </Link>
      <span aria-hidden="true"> / </span>
      <span className="mono" aria-current="page">
        {s.name}
      </span>
    </ScopeCrumbs>
  );
  if (!s.cluster || !s.kind || !s.name) {
    return (
      <>
        <PageHead crumbs={crumbs} title="Kyverno policy" />
        <section className="card">
          <EmptyState title="No policy selected" action={<Link to="/security" search={{ cluster: 'all', tab: 'kyverno' }} className="btn">Kyverno policies</Link>}>
            Open a policy from Security › Kyverno policies.
          </EmptyState>
        </section>
      </>
    );
  }
  const p = q.data;
  const mode = p ? policyMode(p) : null;
  return (
    <>
      <PageHead
        crumbs={crumbs}
        title={<span className="mono">{s.name}</span>}
        sub={
          <span className="inline-sm">
            <span>{s.kind}</span>
            <span aria-hidden="true">·</span>
            <span className="mono">{cluster?.name ?? p?.cluster_name ?? s.cluster}</span>
            <span aria-hidden="true">·</span>
            <span>{s.namespace ? <span className="mono">namespace {s.namespace}</span> : 'cluster-wide'}</span>
            {mode && (
              <Badge tone={mode.mode === 'Enforce' ? 'ok' : 'info'} title={mode.detail ? `${mode.detail}. ${mode.mode === 'Enforce' ? 'Violating requests are blocked.' : 'Violations are only reported.'}` : undefined}>
                {mode.mode === 'Enforce' ? 'Enforce · blocks violations' : 'Audit · reports only'}
              </Badge>
            )}
            {p && !p.ready && <Badge tone="warn">Not ready</Badge>}
            {p && <Badge tone={p.fail_count ? 'warn' : 'ok'}>{p.fail_count ? `${p.fail_count} failing` : 'No violations'}</Badge>}
          </span>
        }
      />
      <QueryView q={q} what="this Kyverno policy" isEmpty={() => false}>
        {(d) => <PolicyBody d={d} />}
      </QueryView>
    </>
  );
}

function PolicyBody({ d }: { d: KyvernoPolicyDetail }) {
  const rules = useMemo(() => explainPolicy(d), [d]);
  const examples = useMemo(() => buildExamples(d, rules), [d, rules]);
  const [text, setText] = useState('');
  const cel = isCelKind(d.kind);
  return (
    <>
      <div className="cols-2 ky-top">
        <section className="card" aria-labelledby="ky-rules-t">
          <div className="card-head">
            <div>
              <h2 id="ky-rules-t">What it checks</h2>
              <div className="desc">{cel ? 'CEL policy (policies.kyverno.io): match constraints, conditions and each validation.' : `${plural(rules.length, 'rule')} (kyverno.io): what each rule matches and requires.`}</div>
            </div>
          </div>
          <div className="ky-rules">
            {rules.length === 0 && <p className="muted small">This policy has no rules Olympos can read.</p>}
            {rules.map((r) => (
              <RuleCard key={r.name} r={r} cel={cel} violations={d.violations.filter((v) => v.rule === r.name).length} />
            ))}
          </div>
        </section>
        <section className="card" aria-labelledby="ky-ex-t">
          <div className="card-head">
            <div>
              <h2 id="ky-ex-t">At a glance</h2>
              <div className="desc">{d.violations.length ? 'Real failing resources, and the same resource changed so that it passes.' : 'An example resource that fails, and the change that makes it pass.'}</div>
            </div>
          </div>
          <div className="kx-list">
            {examples.length === 0 ? <p className="muted small">No example can be derived from this policy’s rules. The YAML below shows the exact checks.</p> : examples.map((e) => <ExampleRow key={e.key} e={e} />)}
          </div>
          <div className="card-foot">Examples are derived from the violations and the rule patterns; they are illustrations, not a policy evaluation.</div>
        </section>
      </div>

      <section className="card" aria-labelledby="ky-v-t">
        <div className="card-head">
          <div>
            <h2 id="ky-v-t">Current violations</h2>
            <div className="desc">From the latest PolicyReports{d.violations.length ? ` · ${plural(d.violations.length, 'result')}` : ''}.</div>
          </div>
          {d.violations.length > 0 && (
            <span>
              <label className="sr-only" htmlFor="kyv-q">
                Search violations
              </label>
              <input id="kyv-q" type="search" className="in search-sm" placeholder="Search resource, rule or message…" value={text} onChange={(e) => setText(e.target.value)} />
            </span>
          )}
        </div>
        <DataTable<KyvernoViolation>
          label="Violations"
          what="violations"
          rows={d.violations}
          rowKey={(v) => `${v.resource_kind}/${v.resource_namespace}/${v.resource_name}/${v.rule}`}
          filterText={text}
          pageSize={10}
          pageSizes={[10, 25, 50]}
          initialSort={{ id: 'res', dir: 'asc' }}
          empty={<EmptyState title="No violations">Every resource passes this policy in the latest PolicyReports.</EmptyState>}
          columns={[
            {
              id: 'res',
              header: 'Resource',
              sortValue: (v) => `${v.resource_namespace}/${v.resource_name}`,
              searchText: (v) => `${v.resource_kind} ${v.resource_namespace}/${v.resource_name} ${v.rule} ${v.message}`,
              className: 'wrap',
              style: { minWidth: 240 },
              cell: (v) => (
                <>
                  <span className="mono">
                    {v.resource_namespace ? `${v.resource_namespace}/` : ''}
                    {v.resource_name}
                  </span>
                  <div className="muted small">{v.resource_kind}</div>
                </>
              ),
            },
            { id: 'rule', header: 'Rule', sortValue: (v) => v.rule, className: 'mono', cell: (v) => v.rule },
            { id: 'sev', header: 'Severity', sortValue: (v) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(v.severity), cell: (v) => (v.severity ? <SeverityBadge s={v.severity} /> : <span className="muted">—</span>) },
            { id: 'msg', header: 'Message', sortValue: (v) => v.message, className: 'wrap', style: { minWidth: 320 }, cell: (v) => renderMessage(v.message, v) },
          ]}
        />
      </section>

      <section className="card" aria-labelledby="ky-y-t">
        <div className="card-head">
          <div>
            <h2 id="ky-y-t">YAML</h2>
            <div className="desc">As stored in the cluster (metadata trimmed). Read-only: change policies through your GitOps flow.</div>
          </div>
        </div>
        <div className="pad-x">
          <YamlView yaml={d.yaml} label={`${d.kind ?? 'Policy'} ${d.name}`} maxHeight={520} />
        </div>
        <div className="card-spacer" />
      </section>
    </>
  );
}

function RuleCard({ r, cel, violations }: { r: RuleExplanation; cel: boolean; violations: number }) {
  return (
    <article className="ky-rule">
      <header className="ky-rule-head">
        <span className="mono strong">{r.name}</span>
        <Badge tone="mute">{TYPE_LABEL[r.type]}</Badge>
        {!cel && violations > 0 && <Badge tone="warn">{violations} failing</Badge>}
      </header>
      <dl className="ky-dl">
        <dt>Applies to</dt>
        <dd>{r.applies.length ? r.applies.join('; ') : 'every resource the policy receives'}</dd>
        {r.excludes.length > 0 && (
          <>
            <dt>Except</dt>
            <dd>{r.excludes.join('; ')}</dd>
          </>
        )}
        {r.conditions.length > 0 && (
          <>
            <dt>Only when</dt>
            <dd>
              <ul className="plain-list">
                {r.conditions.map((c) => (
                  <li key={c} className="mono small">
                    {c}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
        <dt>Requires</dt>
        <dd>
          <ul className="ky-checks">
            {r.checks.map((c, i) => (
              <li key={i}>
                <span>{c.text}</span>
                {c.code && <code className="ky-code">{c.code}</code>}
                {c.message && <span className="muted small">Message: “{c.message}”</span>}
              </li>
            ))}
            {r.checks.length === 0 && <li className="muted">No validation in this rule.</li>}
          </ul>
        </dd>
        {r.message && !r.checks.some((c) => c.message) && (
          <>
            <dt>Message</dt>
            <dd>“{r.message}”</dd>
          </>
        )}
      </dl>
    </article>
  );
}

function ExampleRow({ e }: { e: Example }) {
  const fail = e.verdict === 'fail';
  return (
    <div className={`kx ${fail ? 'fail' : 'pass'}`}>
      <div className="kx-res">
        <div className="kx-kind">
          <span>{e.kind}</span> <span className="mono">{e.namespace ? `${e.namespace}/` : ''}{e.name}</span>
        </div>
        {!fail && <div className="kx-change">same resource, changed:</div>}
        {e.fields.map(([k, v]) => (
          <code key={k} className="kx-field">
            {k}: <span className={v === '(not set)' || v === '(removed)' ? 'muted' : 'strong'}>{v}</span>
          </code>
        ))}
      </div>
      <div className="kx-arrow" aria-hidden="true">
        →
      </div>
      <div className="kx-verdict">
        {fail ? (
          <>
            <Badge tone="crit">✗ Fails</Badge> <span className="mono small">{e.rule}</span>
            <div className="small kx-msg">“{e.message}”</div>
          </>
        ) : (
          <>
            <Badge tone="ok">✓ Passes</Badge> <span className="mono small">{e.rule}</span>
          </>
        )}
      </div>
    </div>
  );
}
