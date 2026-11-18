// Kubernetes NetworkPolicy (networking.k8s.io/v1) semantics for the Security › Network policies
// simulator. Pure functions, no cluster access: the inputs are the policies of one namespace,
// the labels of a pod in it, and the other end of the connection (namespace labels + pod labels).
//
// Rules implemented (https://kubernetes.io/docs/concepts/services-networking/network-policies/):
// - A pod is isolated for a direction when at least one policy selects it (spec.podSelector,
//   `{}` = every pod of the namespace) and that policy's policyTypes include the direction.
//   policyTypes defaults to ["Ingress"] plus "Egress" when the policy has egress rules.
// - A connection to/from an isolated pod is allowed when ANY rule of ANY selecting policy allows
//   it (policies are additive, never deny explicitly). No rule at all = deny everything.
// - A rule matches when one of its peers matches (missing/empty from/to = every peer) AND one of
//   its ports matches (missing/empty ports = every port).
// - Peer: podSelector alone = pods of the policy's namespace; namespaceSelector alone = every pod
//   of the selected namespaces; both = selected pods in the selected namespaces. Namespaces carry
//   the automatic label kubernetes.io/metadata.name. ipBlock is shown as text and never matches a
//   pod here (pod IPs are not part of the simulation).
// - Port: protocol defaults to TCP; no port = every port of that protocol; endPort = range;
//   named ports resolve against the container port names of the pod they refer to (the
//   destination pod) when known.

export type Labels = Record<string, string>;
export interface LabelSelectorRequirement {
  key: string;
  operator: 'In' | 'NotIn' | 'Exists' | 'DoesNotExist' | string;
  values?: string[];
}
export interface LabelSelector {
  matchLabels?: Labels | null;
  matchExpressions?: LabelSelectorRequirement[] | null;
}
export interface IPBlock {
  cidr: string;
  except?: string[] | null;
}
export interface NetworkPolicyPeer {
  podSelector?: LabelSelector | null;
  namespaceSelector?: LabelSelector | null;
  ipBlock?: IPBlock | null;
}
export interface NetworkPolicyPort {
  protocol?: string;
  port?: number | string;
  endPort?: number;
}
export interface NetworkPolicyIngressRule {
  from?: NetworkPolicyPeer[] | null;
  ports?: NetworkPolicyPort[] | null;
}
export interface NetworkPolicyEgressRule {
  to?: NetworkPolicyPeer[] | null;
  ports?: NetworkPolicyPort[] | null;
}
export type PolicyType = 'Ingress' | 'Egress';
export interface NetworkPolicySpec {
  podSelector?: LabelSelector | null;
  policyTypes?: PolicyType[] | null;
  ingress?: NetworkPolicyIngressRule[] | null;
  egress?: NetworkPolicyEgressRule[] | null;
}
export interface NetworkPolicy {
  name: string;
  spec: NetworkPolicySpec;
}

export const NS_NAME_LABEL = 'kubernetes.io/metadata.name';

// ------------------------------------------------------------ selectors

export function isEmptySelector(sel: LabelSelector | null | undefined): boolean {
  return !sel || (Object.keys(sel.matchLabels ?? {}).length === 0 && (sel.matchExpressions ?? []).length === 0);
}

/** metav1.LabelSelector semantics: every matchLabels pair and every expression must hold; `{}` matches everything. */
export function selectorMatches(sel: LabelSelector | null | undefined, labels: Labels): boolean {
  if (!sel) return true;
  for (const [k, v] of Object.entries(sel.matchLabels ?? {})) if (labels[k] !== v) return false;
  for (const e of sel.matchExpressions ?? []) {
    const has = Object.prototype.hasOwnProperty.call(labels, e.key);
    const vals = e.values ?? [];
    switch (e.operator) {
      case 'In':
        if (!has || !vals.includes(labels[e.key])) return false;
        break;
      case 'NotIn':
        if (has && vals.includes(labels[e.key])) return false;
        break;
      case 'Exists':
        if (!has) return false;
        break;
      case 'DoesNotExist':
        if (has) return false;
        break;
      default:
        return false; // unknown operators never match (the API server rejects them)
    }
  }
  return true;
}

export function describeSelector(sel: LabelSelector | null | undefined): string {
  if (isEmptySelector(sel)) return 'all';
  const parts = Object.entries(sel!.matchLabels ?? {}).map(([k, v]) => `${k}=${v}`);
  for (const e of sel!.matchExpressions ?? []) {
    const vals = (e.values ?? []).join(', ');
    if (e.operator === 'In') parts.push(`${e.key} in (${vals})`);
    else if (e.operator === 'NotIn') parts.push(`${e.key} not in (${vals})`);
    else if (e.operator === 'Exists') parts.push(`${e.key} exists`);
    else if (e.operator === 'DoesNotExist') parts.push(`no ${e.key}`);
    else parts.push(`${e.key} ${e.operator} (${vals})`);
  }
  return parts.join(', ');
}

/** Namespace labels including the label Kubernetes sets on every namespace. */
export function namespaceLabels(name: string, labels: Labels = {}): Labels {
  return { [NS_NAME_LABEL]: name, ...labels };
}

// ------------------------------------------------------------ policy types

/** Effective policyTypes (API server defaulting). */
export function policyTypes(spec: NetworkPolicySpec): PolicyType[] {
  if (spec.policyTypes && spec.policyTypes.length) return spec.policyTypes;
  return (spec.egress ?? []).length > 0 ? ['Ingress', 'Egress'] : ['Ingress'];
}

export function selectsPod(p: NetworkPolicy, podLabels: Labels): boolean {
  return selectorMatches(p.spec.podSelector ?? {}, podLabels);
}

function rulesOf(p: NetworkPolicy, dir: PolicyType): { peers: NetworkPolicyPeer[] | null | undefined; ports: NetworkPolicyPort[] | null | undefined }[] {
  return dir === 'Ingress' ? (p.spec.ingress ?? []).map((r) => ({ peers: r.from, ports: r.ports })) : (p.spec.egress ?? []).map((r) => ({ peers: r.to, ports: r.ports }));
}

// ------------------------------------------------------------ peers & ports

export interface Endpoint {
  namespace: string;
  /** Without kubernetes.io/metadata.name (added automatically). */
  namespaceLabels: Labels;
  podLabels: Labels;
  /** Container port name → number, for named ports. */
  namedPorts?: Record<string, number>;
}

/** Does `peer` (in a policy of namespace `policyNs`) select the pod `ep`? */
export function peerMatches(peer: NetworkPolicyPeer, policyNs: string, ep: Endpoint): { match: boolean; why: string } {
  if (peer.ipBlock) return { match: false, why: `ipBlock ${peer.ipBlock.cidr} is an IP range, not evaluated for pods` };
  if (!peer.podSelector && !peer.namespaceSelector) return { match: false, why: 'empty peer' };
  const nsOk = peer.namespaceSelector ? selectorMatches(peer.namespaceSelector, namespaceLabels(ep.namespace, ep.namespaceLabels)) : ep.namespace === policyNs;
  if (!nsOk) {
    return {
      match: false,
      why: peer.namespaceSelector ? `namespace ${ep.namespace} does not match namespaceSelector ${describeSelector(peer.namespaceSelector)}` : `podSelector alone only selects pods in ${policyNs}, not ${ep.namespace}`,
    };
  }
  if (peer.podSelector && !selectorMatches(peer.podSelector, ep.podLabels)) return { match: false, why: `pod labels do not match podSelector ${describeSelector(peer.podSelector)}` };
  return { match: true, why: describePeer(peer, policyNs) };
}

export interface SimPort {
  /** Number, numeric string or a port name. */
  port: number | string;
  protocol?: string;
}

const numeric = (v: unknown): number | null => (typeof v === 'number' ? v : typeof v === 'string' && /^\d+$/.test(v.trim()) ? Number(v) : null);

/**
 * Does the port list allow `target`? Named ports in the policy resolve against `named` (the
 * container ports of the pod the traffic goes to).
 */
export function portsMatch(ports: NetworkPolicyPort[] | null | undefined, target: SimPort, named: Record<string, number> = {}): { match: boolean; why: string } {
  if (!ports || ports.length === 0) return { match: true, why: 'all ports' };
  const proto = (target.protocol || 'TCP').toUpperCase();
  const tNum = numeric(target.port) ?? (typeof target.port === 'string' ? (named[target.port] ?? null) : null);
  const tName = typeof target.port === 'string' && numeric(target.port) === null ? target.port : (Object.entries(named).find(([, n]) => n === tNum)?.[0] ?? null);
  for (const p of ports) {
    if ((p.protocol || 'TCP').toUpperCase() !== proto) continue;
    if (p.port === undefined || p.port === null || p.port === '') return { match: true, why: `all ${proto} ports` };
    const num = numeric(p.port);
    if (num !== null) {
      if (tNum === null) continue;
      if (p.endPort ? tNum >= num && tNum <= p.endPort : tNum === num) return { match: true, why: describePort(p) };
      continue;
    }
    const name = String(p.port);
    if (tName === name || (named[name] !== undefined && named[name] === tNum)) return { match: true, why: describePort(p) };
  }
  return { match: false, why: `${proto} ${target.port} is not in ${describePorts(ports)}` };
}

export function describePort(p: NetworkPolicyPort): string {
  const proto = (p.protocol || 'TCP').toUpperCase();
  if (p.port === undefined || p.port === null || p.port === '') return `${proto} any port`;
  return p.endPort ? `${proto} ${p.port}–${p.endPort}` : `${proto} ${p.port}`;
}
export function describePorts(ports: NetworkPolicyPort[] | null | undefined): string {
  if (!ports || ports.length === 0) return 'all ports';
  return ports.map(describePort).join(', ');
}

export function describePeer(peer: NetworkPolicyPeer, policyNs: string): string {
  if (peer.ipBlock) return `IP ${peer.ipBlock.cidr}${peer.ipBlock.except?.length ? ` except ${peer.ipBlock.except.join(', ')}` : ''}`;
  const pods = peer.podSelector ? (isEmptySelector(peer.podSelector) ? 'all pods' : `pods ${describeSelector(peer.podSelector)}`) : 'all pods';
  if (!peer.namespaceSelector) return `${pods} in ${policyNs}`;
  const nsSel = peer.namespaceSelector;
  const byName = Object.keys(nsSel.matchLabels ?? {}).length === 1 && (nsSel.matchExpressions ?? []).length === 0 ? nsSel.matchLabels?.[NS_NAME_LABEL] : undefined;
  const ns = byName ? `namespace ${byName}` : isEmptySelector(nsSel) ? 'all namespaces' : `namespaces ${describeSelector(nsSel)}`;
  return `${pods} in ${ns}`;
}

// ------------------------------------------------------------ simulation

export interface SimInput {
  direction: PolicyType;
  /** The namespace whose policies are simulated. */
  namespace: string;
  policies: NetworkPolicy[];
  /** The pod in `namespace`: the destination for Ingress, the source for Egress. */
  local: { podLabels: Labels; namedPorts?: Record<string, number> };
  /** The other end: the source for Ingress, the destination for Egress. */
  peer: Endpoint;
  port: SimPort;
}
export interface SimTrace {
  policy: string;
  /** -1 = the policy has no rule for this direction. */
  rule: number;
  ok: boolean;
  why: string;
}
export interface SimResult {
  allowed: boolean;
  code: 'not-isolated' | 'allowed' | 'denied-no-rules' | 'denied-no-match';
  reason: string;
  /** Policies that select the local pod for this direction. */
  selectedBy: string[];
  match?: { policy: string; rule: number };
  trace: SimTrace[];
}

/** Kubernetes decision for one connection, seen from `namespace`'s policies. */
export function simulate(input: SimInput): SimResult {
  const { direction: dir, namespace, policies, local, peer, port } = input;
  const word = dir === 'Ingress' ? 'ingress' : 'egress';
  const podWord = dir === 'Ingress' ? 'destination' : 'source';
  const isolating = policies.filter((p) => policyTypes(p.spec).includes(dir) && selectsPod(p, local.podLabels));
  const selectedBy = isolating.map((p) => p.name);
  if (isolating.length === 0) {
    const anySelects = policies.filter((p) => selectsPod(p, local.podLabels));
    return {
      allowed: true,
      code: 'not-isolated',
      reason:
        policies.length === 0
          ? `No NetworkPolicy in ${namespace}: all ${word} traffic is allowed.`
          : anySelects.length
            ? `${anySelects.map((p) => p.name).join(', ')} select${anySelects.length === 1 ? 's' : ''} the ${podWord} pod but not for ${dir}: ${word} is not restricted, so it is allowed.`
            : `No policy selects the ${podWord} pod: ${word} is not restricted, so it is allowed.`,
      selectedBy,
      trace: [],
    };
  }
  // Ports refer to the destination pod: the local pod for Ingress, the peer for Egress.
  const named = dir === 'Ingress' ? (local.namedPorts ?? {}) : (peer.namedPorts ?? {});
  const trace: SimTrace[] = [];
  for (const p of isolating) {
    const rules = rulesOf(p, dir);
    if (rules.length === 0) {
      trace.push({ policy: p.name, rule: -1, ok: false, why: `no ${word} rules: denies all ${word} to the pods it selects` });
      continue;
    }
    for (let i = 0; i < rules.length; i++) {
      const r = rules[i];
      let peerWhy = 'every peer';
      if (r.peers && r.peers.length) {
        const res = r.peers.map((x) => peerMatches(x, namespace, peer));
        const hit = res.find((x) => x.match);
        if (!hit) {
          trace.push({ policy: p.name, rule: i, ok: false, why: res.map((x) => x.why).join('; ') });
          continue;
        }
        peerWhy = hit.why;
      }
      const pm = portsMatch(r.ports, port, named);
      if (!pm.match) {
        trace.push({ policy: p.name, rule: i, ok: false, why: `peer matches (${peerWhy}) but ${pm.why}` });
        continue;
      }
      trace.push({ policy: p.name, rule: i, ok: true, why: `${peerWhy} · ${pm.why}` });
      return {
        allowed: true,
        code: 'allowed',
        reason: `Allowed by ${p.name}, ${word} rule ${i + 1}: ${dir === 'Ingress' ? 'from' : 'to'} ${peerWhy}, ${pm.why}.`,
        selectedBy,
        match: { policy: p.name, rule: i },
        trace,
      };
    }
  }
  const allNoRules = isolating.every((p) => rulesOf(p, dir).length === 0);
  return {
    allowed: false,
    code: allNoRules ? 'denied-no-rules' : 'denied-no-match',
    reason: allNoRules
      ? `Denied: ${selectedBy.join(', ')} select${selectedBy.length === 1 ? 's' : ''} the ${podWord} pod for ${dir} with no ${word} rules (default-deny), and no other policy allows it.`
      : `Denied: selected by ${selectedBy.join(', ')}, but no ${word} rule matches this ${dir === 'Ingress' ? 'source' : 'destination'} and port.`,
    selectedBy,
    trace,
  };
}

// ------------------------------------------------------------ namespace summary

export type DirectionState = 'open' | 'partial' | 'default-deny';
/**
 * open: no policy restricts the direction (everything allowed); default-deny: a policy selects
 * every pod for the direction, so only what rules allow gets through; partial: only some pods
 * are isolated.
 */
export function directionState(policies: NetworkPolicy[], dir: PolicyType): DirectionState {
  const typed = policies.filter((p) => policyTypes(p.spec).includes(dir));
  if (typed.length === 0) return 'open';
  return typed.some((p) => isEmptySelector(p.spec.podSelector)) ? 'default-deny' : 'partial';
}

/** SPEC §13.2 default-deny: selects all pods, Ingress, no ingress rules. */
export function isDefaultDenyIngress(p: NetworkPolicy): boolean {
  return isEmptySelector(p.spec.podSelector) && policyTypes(p.spec).includes('Ingress') && (p.spec.ingress ?? []).length === 0;
}

/** Parse "80", "http", "8080/UDP" into a SimPort. */
export function parsePort(text: string, protocol = 'TCP'): SimPort | null {
  const t = text.trim();
  if (!t) return null;
  const m = /^([^/\s]+)(?:\s*\/\s*(TCP|UDP|SCTP))?$/i.exec(t);
  if (!m) return null;
  const n = numeric(m[1]);
  if (n !== null && (n < 1 || n > 65535)) return null;
  return { port: n ?? m[1], protocol: (m[2] ?? protocol).toUpperCase() };
}
