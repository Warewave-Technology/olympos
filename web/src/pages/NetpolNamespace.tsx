import { useEffect, useMemo, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { NetpolNamespaceDetail, NetpolWorkload } from '../api/types';
import { plural } from '../lib/format';
import {
  NS_NAME_LABEL,
  describePeer,
  describePorts,
  describeSelector,
  directionState,
  isEmptySelector,
  parsePort,
  policyTypes,
  selectsPod,
  simulate,
  type DirectionState,
  type Labels,
  type NetworkPolicy,
  type NetworkPolicyPeer,
  type NetworkPolicyPort,
  type PolicyType,
} from '../lib/netpol';
import { netpolNamespaceRoute } from '../router';
import { ScopeCrumbs, findCluster, resolveScope, scopeParam, useClusterList } from '../ui/clusterScope';
import { Badge, EmptyState, Field, QueryView } from '../ui/kit';
import { Select } from '../ui/Select';
import { PageHead } from '../ui/status';
import { TagInput } from '../ui/TagInput';
import { YamlView } from '../ui/YamlView';

export function NetpolNamespacePage() {
  const s = netpolNamespaceRoute.useSearch();
  const { list: clusters } = useClusterList();
  const cluster = findCluster(clusters, s.cluster);
  const backScope = resolveScope(s.from || s.cluster || 'all');
  const q = useQuery({
    queryKey: ['netpol-namespace', s.cluster, s.namespace],
    queryFn: () => api.get<NetpolNamespaceDetail>('/security/netpol/namespace', { cluster: s.cluster, namespace: s.namespace }),
    enabled: !!(s.cluster && s.namespace),
  });
  const crumbs = (
    <ScopeCrumbs area="Security" to="/security" scope={backScope} cluster={backScope.mode === 'cluster' ? findCluster(clusters, backScope.id) : undefined}>
      <span aria-hidden="true"> / </span>
      <Link to="/security" search={{ cluster: scopeParam(backScope), tab: 'netpol' }}>
        Network policies
      </Link>
      <span aria-hidden="true"> / </span>
      <span className="mono" aria-current="page">
        {s.namespace}
      </span>
    </ScopeCrumbs>
  );
  if (!s.cluster || !s.namespace) {
    return (
      <>
        <PageHead crumbs={crumbs} title="Namespace" />
        <section className="card">
          <EmptyState title="No namespace selected">Open a namespace from Security › Network policies.</EmptyState>
        </section>
      </>
    );
  }
  return (
    <>
      <PageHead
        crumbs={crumbs}
        title={<span className="mono">{s.namespace}</span>}
        sub={
          <span className="inline-sm">
            <span>NetworkPolicies on</span> <span className="mono">{cluster?.name ?? q.data?.cluster_name ?? s.cluster}</span>
            {q.data && <StateBadges d={q.data} />}
          </span>
        }
      />
      <QueryView q={q} what="this namespace" isEmpty={() => false}>
        {(d) => <NamespaceBody d={d} />}
      </QueryView>
    </>
  );
}

const asPolicies = (d: NetpolNamespaceDetail): NetworkPolicy[] => d.policies.map((p) => ({ name: p.name, spec: p.spec as NetworkPolicy['spec'] }));

const STATE_TEXT: Record<DirectionState, [string, 'ok' | 'warn' | 'info']> = {
  'default-deny': ['default-deny', 'ok'],
  partial: ['some pods isolated', 'info'],
  open: ['all allowed', 'warn'],
};

function StateBadges({ d }: { d: NetpolNamespaceDetail }) {
  const pols = asPolicies(d);
  if (d.excluded) return <Badge tone="mute">Excluded · system namespace</Badge>;
  return (
    <>
      {(['Ingress', 'Egress'] as PolicyType[]).map((dir) => {
        const [t, tone] = STATE_TEXT[directionState(pols, dir)];
        return (
          <Badge key={dir} tone={dir === 'Egress' && tone === 'warn' ? 'mute' : tone}>
            {dir}: {t}
          </Badge>
        );
      })}
    </>
  );
}

function NamespaceBody({ d }: { d: NetpolNamespaceDetail }) {
  const pols = useMemo(() => asPolicies(d), [d]);
  const s = netpolNamespaceRoute.useSearch();
  const ing = directionState(pols, 'Ingress');
  return (
    <>
      {pols.length === 0 ? (
        <div className="note warn" role="note">
          <div className="note-title">No NetworkPolicy: all traffic allowed</div>
          Every pod in <span className="mono">{d.namespace}</span> accepts connections from any pod in the cluster (and from outside, where routed), and can reach anything. Add a default-deny policy (<span className="mono">podSelector: {'{}'}</span>, policyTypes Ingress, no rules) and then allow what is needed.
        </div>
      ) : ing === 'default-deny' ? (
        <div className="note ok" role="note">
          <div className="note-title">Default-deny for ingress</div>
          Every pod in <span className="mono">{d.namespace}</span> is isolated: only the connections the rules below allow get in, everything else is denied.
        </div>
      ) : (
        <div className="note warn" role="note">
          <div className="note-title">No default-deny: only some pods are isolated</div>
          Pods selected by a policy below accept only what its rules allow; every other pod in <span className="mono">{d.namespace}</span> still accepts all traffic.
        </div>
      )}
      <Simulator d={d} policies={pols} />
      <section className="card" aria-labelledby="np-pols-t">
        <div className="card-head">
          <div>
            <h2 id="np-pols-t">Policies · {pols.length}</h2>
            <div className="desc">Selected pods in the middle, allowed sources on the left, allowed destinations on the right. Policies add up: a connection is allowed when any rule of any selecting policy allows it.</div>
          </div>
        </div>
        {pols.length === 0 ? (
          <EmptyState title="No policies in this namespace">Nothing is isolated, so the simulator above allows every connection.</EmptyState>
        ) : (
          <div className="np-pols">
            {d.policies.map((p, i) => (
              <PolicyCard key={p.name} name={p.name} policy={pols[i]} yaml={p.yaml} namespace={d.namespace} workloads={d.workloads} open={s.policy === p.name} />
            ))}
          </div>
        )}
      </section>
    </>
  );
}

// ------------------------------------------------------------ diagram

interface Box {
  title: string;
  sub: string;
  tone: 'ok' | 'crit' | 'mute' | 'info';
  tag?: string;
}

function peerBoxes(rules: { peers: NetworkPolicyPeer[] | null | undefined; ports: NetworkPolicyPort[] | null | undefined }[], dir: PolicyType, types: PolicyType[], ns: string): Box[] {
  const word = dir === 'Ingress' ? 'ingress' : 'egress';
  if (!types.includes(dir)) return [{ title: `${dir} not restricted`, sub: 'by this policy', tone: 'mute' }];
  if (rules.length === 0) return [{ title: `✗ All ${word} denied`, sub: 'no rules: default-deny', tone: 'crit' }];
  const out: Box[] = [];
  rules.forEach((r, i) => {
    const ports = describePorts(r.ports);
    if (!r.peers || r.peers.length === 0) out.push({ title: dir === 'Ingress' ? 'Any source' : 'Any destination', sub: ports, tone: 'ok', tag: `rule ${i + 1}` });
    else for (const p of r.peers) out.push({ title: describePeer(p, ns), sub: ports, tone: p.ipBlock ? 'info' : 'ok', tag: `rule ${i + 1}` });
  });
  return out;
}

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

/** SVG: sources → selected pods → destinations, with the default for everything else. */
export function PolicyDiagram({ policy, namespace, workloads }: { policy: NetworkPolicy; namespace: string; workloads: NetpolWorkload[] }) {
  const types = policyTypes(policy.spec);
  const left = peerBoxes((policy.spec.ingress ?? []).map((r) => ({ peers: r.from, ports: r.ports })), 'Ingress', types, namespace);
  const right = peerBoxes((policy.spec.egress ?? []).map((r) => ({ peers: r.to, ports: r.ports })), 'Egress', types, namespace);
  const selected = workloads.filter((w) => selectsPod(policy, w.labels));
  const sel = isEmptySelector(policy.spec.podSelector) ? `all pods in ${namespace}` : describeSelector(policy.spec.podSelector);
  const W = 940;
  const BW = 290;
  const BH = 48;
  const GAP = 12;
  const CX = 330;
  const CW = 280;
  const centerLines = Math.min(selected.length, 4) + (selected.length > 4 ? 1 : 0);
  const CH = Math.max(86, 64 + centerLines * 17);
  const colH = (n: number) => n * BH + (n - 1) * GAP;
  const H = Math.max(colH(left.length), colH(right.length), CH) + 52;
  const cy = (H - 40) / 2;
  const top = (n: number) => (H - 40 - colH(n)) / 2;
  const boxY = (n: number, i: number) => top(n) + i * (BH + GAP);
  const allowedIn = types.includes('Ingress') && (policy.spec.ingress ?? []).length > 0;
  const allowedOut = types.includes('Egress') && (policy.spec.egress ?? []).length > 0;
  const footer = [
    types.includes('Ingress') ? (allowedIn ? 'Ingress: only the sources shown, everything else denied' : 'Ingress: everything denied') : 'Ingress: not restricted by this policy',
    types.includes('Egress') ? (allowedOut ? 'Egress: only the destinations shown, everything else denied' : 'Egress: everything denied') : 'Egress: not restricted by this policy',
  ];
  const renderBox = (b: Box, x: number, y: number, key: string) => (
    <g key={key} className={`np-box ${b.tone}`}>
      <title>{`${b.title} · ${b.sub}`}</title>
      <rect x={x} y={y} width={BW} height={BH} rx={7} />
      <text x={x + 12} y={y + 20} className="np-t1">
        {clip(b.title, 34)}
      </text>
      <text x={x + 12} y={y + 37} className="np-t2">
        {clip(b.sub, b.tag ? 34 : 42)}
      </text>
      {b.tag && (
        <text x={x + BW - 10} y={y + 37} className="np-tag" textAnchor="end">
          {b.tag}
        </text>
      )}
    </g>
  );
  const edge = (x1: number, y1: number, x2: number, y2: number, tone: string, key: string) => {
    const mx = (x1 + x2) / 2;
    return <path key={key} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} className={`np-edge ${tone}`} markerEnd={`url(#np-arrow-${tone})`} />;
  };
  return (
    <svg className="np-svg" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${policy.name}: selects ${sel}. ${footer.join('. ')}.`}>
      <defs>
        {['ok', 'crit', 'mute', 'info'].map((t) => (
          <marker key={t} id={`np-arrow-${t}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" className={`np-arrowhead ${t}`} />
          </marker>
        ))}
      </defs>
      <text x={0} y={12} className="np-col">
        FROM (INGRESS)
      </text>
      <text x={CX + CW / 2} y={12} className="np-col" textAnchor="middle">
        SELECTED PODS
      </text>
      <text x={W} y={12} className="np-col" textAnchor="end">
        TO (EGRESS)
      </text>
      <g transform="translate(0, 22)">
        {left.map((b, i) => (
          <g key={`l${i}`}>
            {renderBox(b, 0, boxY(left.length, i), `lb${i}`)}
            {edge(BW, boxY(left.length, i) + BH / 2, CX - 4, cy, b.tone === 'crit' ? 'crit' : b.tone === 'mute' ? 'mute' : 'ok', `le${i}`)}
          </g>
        ))}
        <g className="np-center">
          <rect x={CX} y={cy - CH / 2} width={CW} height={CH} rx={9} />
          <text x={CX + 14} y={cy - CH / 2 + 22} className="np-t1">
            {clip(sel, 33)}
          </text>
          <text x={CX + 14} y={cy - CH / 2 + 40} className="np-t2">
            {selected.length ? `${plural(selected.length, 'workload')} match` : 'no reported workload matches'}
          </text>
          {selected.slice(0, 4).map((w, i) => (
            <text key={w.name} x={CX + 14} y={cy - CH / 2 + 60 + i * 17} className="np-wl">
              {clip(`${w.kind} ${w.name}`, 36)}
            </text>
          ))}
          {selected.length > 4 && (
            <text x={CX + 14} y={cy - CH / 2 + 60 + 4 * 17} className="np-t2">
              +{selected.length - 4} more
            </text>
          )}
        </g>
        {right.map((b, i) => (
          <g key={`r${i}`}>
            {edge(CX + CW + 4, cy, W - BW - 4, boxY(right.length, i) + BH / 2, b.tone === 'crit' ? 'crit' : b.tone === 'mute' ? 'mute' : 'ok', `re${i}`)}
            {renderBox(b, W - BW, boxY(right.length, i), `rb${i}`)}
          </g>
        ))}
      </g>
      <text x={0} y={H - 6} className={`np-foot ${allowedIn || !types.includes('Ingress') ? '' : 'crit'}`}>
        {footer[0]}
      </text>
      <text x={W} y={H - 6} className={`np-foot ${allowedOut || !types.includes('Egress') ? '' : 'crit'}`} textAnchor="end">
        {footer[1]}
      </text>
    </svg>
  );
}

function PolicyCard({ name, policy, yaml, namespace, workloads, open }: { name: string; policy: NetworkPolicy; yaml: string; namespace: string; workloads: NetpolWorkload[]; open: boolean }) {
  const types = policyTypes(policy.spec);
  return (
    <article className="np-pol" id={`np-${name}`}>
      <header className="inline-sm">
        <span className="mono strong">{name}</span>
        {types.map((t) => (
          <Badge key={t} tone="mute">
            {t}
          </Badge>
        ))}
        {!policy.spec.policyTypes?.length && <span className="muted small">policyTypes defaulted</span>}
      </header>
      <PolicyDiagram policy={policy} namespace={namespace} workloads={workloads} />
      <details className="np-yaml" open={open}>
        <summary>YAML</summary>
        <YamlView yaml={yaml} label={`NetworkPolicy ${name}`} maxHeight={360} />
      </details>
    </article>
  );
}

// ------------------------------------------------------------ simulator

const CUSTOM = '__custom__';
const PROTOCOLS = ['TCP', 'UDP', 'SCTP'];

function Simulator({ d, policies }: { d: NetpolNamespaceDetail; policies: NetworkPolicy[] }) {
  const [dir, setDir] = useState<PolicyType>('Ingress');
  const nsOptions = useMemo(() => [{ name: d.namespace, labels: d.namespace_labels }, ...d.other_namespaces.filter((n) => n.name !== d.namespace)], [d]);
  // start from a typical source: the ingress controller's namespace when there is one
  const others = d.other_namespaces.filter((n) => n.name !== d.namespace);
  const firstOther = (others.find((n) => n.name === 'ingress-nginx') ?? others[0])?.name ?? d.namespace;
  const [peerNs, setPeerNs] = useState<string>(firstOther);
  const [customNs, setCustomNs] = useState('');
  const [peerNsLabels, setPeerNsLabels] = useState<Labels>({});
  const [peerWl, setPeerWl] = useState<string>(CUSTOM);
  const [peerPod, setPeerPod] = useState<Labels>({});
  const [localWl, setLocalWl] = useState<string>(d.workloads[0]?.name ?? CUSTOM);
  const [localPod, setLocalPod] = useState<Labels>(d.workloads[0]?.labels ?? {});
  const [port, setPort] = useState<string>(String(d.workloads[0]?.ports[0] ?? 80));
  const [proto, setProto] = useState('TCP');

  const peerNsName = peerNs === CUSTOM ? customNs.trim() : peerNs;
  const peerInThisNs = peerNsName === d.namespace;
  const local = d.workloads.find((w) => w.name === localWl);
  const peerWorkload = peerInThisNs ? d.workloads.find((w) => w.name === peerWl) : undefined;

  // prefill namespace labels from the chosen namespace
  useEffect(() => {
    if (peerNs === CUSTOM) return;
    const n = nsOptions.find((x) => x.name === peerNs);
    const { [NS_NAME_LABEL]: _auto, ...rest } = n?.labels ?? {}; // eslint-disable-line @typescript-eslint/no-unused-vars
    setPeerNsLabels(rest);
    if (peerNs !== d.namespace) setPeerWl(CUSTOM);
  }, [peerNs, nsOptions, d.namespace]);
  useEffect(() => {
    if (peerWorkload) setPeerPod(peerWorkload.labels);
  }, [peerWorkload]);
  useEffect(() => {
    if (local) setLocalPod(local.labels);
  }, [local]);
  // suggest the destination's first port
  useEffect(() => {
    const dst = dir === 'Ingress' ? local : peerWorkload;
    if (dst?.ports[0]) setPort(String(dst.ports[0]));
  }, [dir, local, peerWorkload]);

  const parsed = parsePort(port, proto);
  const result = parsed && peerNsName ? simulate({ direction: dir, namespace: d.namespace, policies, local: { podLabels: localPod, namedPorts: local?.named_ports }, peer: { namespace: peerNsName, namespaceLabels: peerNsLabels, podLabels: peerPod, namedPorts: peerWorkload?.named_ports }, port: parsed }) : null;
  const dst = dir === 'Ingress' ? local : peerWorkload;
  const portHints = dst ? [...dst.ports.map(String), ...Object.keys(dst.named_ports ?? {})] : [];

  const localField = (
    <Field label={dir === 'Ingress' ? `Destination workload in ${d.namespace}` : `Source workload in ${d.namespace}`} htmlFor="sim-local">
      <Select<string>
        id="sim-local"
        value={localWl}
        onChange={setLocalWl}
        options={[...d.workloads.map((w) => ({ value: w.name, label: `${w.kind} ${w.name}`, text: `${w.kind} ${w.name}`, hint: Object.entries(w.labels).map(([k, v]) => `${k}=${v}`).join(', ') })), { value: CUSTOM, label: 'Custom pod labels…' }]}
      />
      <div className="sim-sub">
        <span className="lbl small" id="sim-local-l">
          Pod labels
        </span>
        <TagInput id="sim-local-labels" value={localPod} onChange={(v) => { setLocalPod(v); setLocalWl(CUSTOM); }} listLabel="Pod labels" placeholder="app=web" aria-describedby="sim-local-l" />
      </div>
    </Field>
  );
  const peerField = (
    <Field label={dir === 'Ingress' ? 'Source' : 'Destination'} htmlFor="sim-peer-ns">
      <Select<string>
        id="sim-peer-ns"
        searchable
        searchLabel="Find a namespace"
        value={peerNs}
        onChange={setPeerNs}
        options={[...nsOptions.map((n) => ({ value: n.name, label: n.name === d.namespace ? `${n.name} (this namespace)` : n.name, text: n.name, hint: Object.entries(n.labels).filter(([k]) => k !== NS_NAME_LABEL).map(([k, v]) => `${k}=${v}`).join(', ') || undefined })), { value: CUSTOM, label: 'Other namespace…', text: 'other custom namespace' }]}
      />
      {peerNs === CUSTOM && (
        <input className="in mono sim-sub" aria-label="Namespace name" placeholder="namespace name" value={customNs} onChange={(e) => setCustomNs(e.target.value)} spellCheck={false} />
      )}
      <div className="sim-sub">
        <span className="lbl small" id="sim-ns-l">
          Namespace labels <span className="muted">(+ {NS_NAME_LABEL}={peerNsName || '…'})</span>
        </span>
        <TagInput id="sim-ns-labels" value={peerNsLabels} onChange={setPeerNsLabels} listLabel="Namespace labels" placeholder="team=web" aria-describedby="sim-ns-l" />
      </div>
      {peerInThisNs && (
        <div className="sim-sub">
          <Select<string>
            aria-label="Workload"
            size="sm"
            value={peerWl}
            onChange={setPeerWl}
            options={[{ value: CUSTOM, label: 'Custom pod labels' }, ...d.workloads.map((w) => ({ value: w.name, label: `${w.kind} ${w.name}` }))]}
          />
        </div>
      )}
      <div className="sim-sub">
        <span className="lbl small" id="sim-pod-l">
          Pod labels
        </span>
        <TagInput id="sim-pod-labels" value={peerPod} onChange={(v) => { setPeerPod(v); setPeerWl(CUSTOM); }} listLabel="Pod labels" placeholder="app=web" aria-describedby="sim-pod-l" />
      </div>
    </Field>
  );

  return (
    <section className="card" aria-labelledby="sim-t">
      <div className="card-head">
        <div>
          <h2 id="sim-t">Simulate a connection</h2>
          <div className="desc">Kubernetes NetworkPolicy semantics, evaluated on the policies of {d.namespace}. Labels are prefilled from what the agent reports; edit them to try other cases.</div>
        </div>
        <div className="pills" role="group" aria-label="Direction">
          <button type="button" className="pill" aria-pressed={dir === 'Ingress'} onClick={() => setDir('Ingress')}>
            Ingress into {d.namespace}
          </button>
          <button type="button" className="pill" aria-pressed={dir === 'Egress'} onClick={() => setDir('Egress')}>
            Egress from {d.namespace}
          </button>
        </div>
      </div>
      <div className="sim">
        <div className="sim-col">{dir === 'Ingress' ? peerField : localField}</div>
        <div className="sim-arrow" aria-hidden="true">
          →
        </div>
        <div className="sim-col">
          {dir === 'Ingress' ? localField : peerField}
          <div className="grid-2 sim-port">
            <Field label="Port" htmlFor="sim-port" hint={portHints.length ? `Container ports: ${portHints.join(', ')}` : 'Number or port name'} error={port && !parsed ? 'Enter 1–65535 or a port name.' : undefined}>
              <input id="sim-port" className="in mono" value={port} onChange={(e) => setPort(e.target.value)} spellCheck={false} />
            </Field>
            <Field label="Protocol" htmlFor="sim-proto">
              <Select<string> id="sim-proto" value={proto} onChange={setProto} options={PROTOCOLS.map((p) => ({ value: p, label: p }))} />
            </Field>
          </div>
        </div>
        <div className={`sim-result ${result ? (result.allowed ? 'ok' : 'crit') : ''}`} aria-live="polite">
          {result ? (
            <>
              <div className="sim-verdict">{result.allowed ? '✓ Allowed' : '✗ Denied'}</div>
              <p className="sim-reason">{result.reason}</p>
              {result.selectedBy.length > 0 && (
                <div className="small">
                  <span className="muted">Selected for {dir} by </span>
                  <span className="mono">{result.selectedBy.join(', ')}</span>
                </div>
              )}
              {result.trace.length > 0 && (
                <details className="sim-trace">
                  <summary>How each rule was checked ({result.trace.length})</summary>
                  <ul className="plain-list">
                    {result.trace.map((t, i) => (
                      <li key={i} className="small">
                        <span className={t.ok ? 'ico-ok' : 'ico-crit'}>{t.ok ? '✓' : '✗'}</span> <span className="mono">{t.policy}</span> {t.rule >= 0 ? `rule ${t.rule + 1}` : ''}: {t.why}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
              <p className="muted small sim-note">
                {dir === 'Ingress' ? `Only ${d.namespace}'s ingress side is simulated: egress policies in the source namespace can still block the connection.` : `Only ${d.namespace}'s egress side is simulated: ingress policies at the destination can still block the connection.`} ipBlock rules are shown, not evaluated.
              </p>
            </>
          ) : (
            <p className="muted small">{!peerNsName ? 'Enter the namespace name.' : 'Enter a port to see the result.'}</p>
          )}
        </div>
      </div>
    </section>
  );
}
