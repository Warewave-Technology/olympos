import { describe, expect, it } from 'vitest';
import { describePeer, describeSelector, directionState, isDefaultDenyIngress, parsePort, policyTypes, portsMatch, selectorMatches, simulate, type NetworkPolicy, type SimInput } from '../lib/netpol';

const NS = 'orders';
const denyAll: NetworkPolicy = { name: 'default-deny', spec: { podSelector: {}, policyTypes: ['Ingress'] } };
const fromIngress: NetworkPolicy = {
  name: 'allow-from-ingress',
  spec: {
    podSelector: { matchLabels: { app: 'web' } },
    ingress: [{ from: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'ingress-nginx' } } }], ports: [{ port: 8080 }] }],
  },
};
const webToApi: NetworkPolicy = {
  name: 'api-from-web',
  spec: {
    podSelector: { matchLabels: { app: 'api' } },
    policyTypes: ['Ingress'],
    ingress: [{ from: [{ podSelector: { matchLabels: { app: 'web' } } }], ports: [{ port: 'http', protocol: 'TCP' }] }],
  },
};
const monitoring: NetworkPolicy = {
  name: 'allow-metrics',
  spec: {
    podSelector: { matchExpressions: [{ key: 'app', operator: 'In', values: ['api', 'web'] }] },
    ingress: [{ from: [{ namespaceSelector: { matchLabels: { team: 'obs' } }, podSelector: { matchLabels: { app: 'prometheus' } } }], ports: [{ protocol: 'TCP', port: 9000, endPort: 9100 }] }],
  },
};
const allowAll: NetworkPolicy = { name: 'allow-all', spec: { podSelector: {}, ingress: [{}] } };
const ipOnly: NetworkPolicy = { name: 'from-lb', spec: { podSelector: { matchLabels: { app: 'web' } }, ingress: [{ from: [{ ipBlock: { cidr: '10.0.0.0/8', except: ['10.1.0.0/16'] } }] }] } };
const egressDb: NetworkPolicy = {
  name: 'api-egress',
  spec: {
    podSelector: { matchLabels: { app: 'api' } },
    policyTypes: ['Egress'],
    egress: [
      { to: [{ podSelector: { matchLabels: { app: 'postgres' } } }], ports: [{ port: 5432 }] },
      { to: [{ namespaceSelector: {}, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }], ports: [{ port: 53, protocol: 'UDP' }] },
    ],
  },
};

const web = { app: 'web' };
const api = { app: 'api' };
const sameNs = (podLabels: Record<string, string>) => ({ namespace: NS, namespaceLabels: { team: 'orders' }, podLabels });

type Case = [string, Partial<SimInput> & { policies: NetworkPolicy[] }, boolean, string, string?];
const ingressCases: Case[] = [
  ['no policy at all → allowed', { policies: [], local: { podLabels: api } }, true, 'not-isolated', 'No NetworkPolicy in orders'],
  ['no policy selects the destination → allowed', { policies: [webToApi], local: { podLabels: { app: 'worker' } } }, true, 'not-isolated', 'No policy selects the destination pod'],
  ['egress-only policy does not isolate ingress', { policies: [egressDb], local: { podLabels: api } }, true, 'not-isolated', 'but not for Ingress'],
  ['default-deny with no rules → denied', { policies: [denyAll], local: { podLabels: api } }, false, 'denied-no-rules', 'default-deny'],
  ['default-deny + allowing rule → allowed by the rule (additive)', { policies: [denyAll, webToApi], local: { podLabels: api, namedPorts: { http: 8080 } }, peer: sameNs(web), port: { port: 8080 } }, true, 'allowed', 'api-from-web, ingress rule 1'],
  ['named port matched by name', { policies: [webToApi], local: { podLabels: api }, peer: sameNs(web), port: { port: 'http' } }, true, 'allowed'],
  ['named port matched by number via container port names', { policies: [webToApi], local: { podLabels: api, namedPorts: { http: 8080 } }, peer: sameNs(web), port: { port: 8080 } }, true, 'allowed'],
  ['named port unresolved (port names unknown) → denied', { policies: [webToApi], local: { podLabels: api }, peer: sameNs(web), port: { port: 8080 } }, false, 'denied-no-match'],
  ['wrong protocol → denied', { policies: [webToApi], local: { podLabels: api }, peer: sameNs(web), port: { port: 'http', protocol: 'UDP' } }, false, 'denied-no-match'],
  ['podSelector-only peer does not match another namespace', { policies: [webToApi], local: { podLabels: api }, peer: { namespace: 'shop', namespaceLabels: {}, podLabels: web }, port: { port: 'http' } }, false, 'denied-no-match', 'no ingress rule matches'],
  ['namespaceSelector by the automatic name label', { policies: [fromIngress], local: { podLabels: web }, peer: { namespace: 'ingress-nginx', namespaceLabels: {}, podLabels: { 'app.kubernetes.io/name': 'ingress-nginx' } }, port: { port: 8080 } }, true, 'allowed'],
  ['namespaceSelector: other namespace → denied', { policies: [fromIngress], local: { podLabels: web }, peer: { namespace: 'shop', namespaceLabels: {}, podLabels: {} }, port: { port: 8080 } }, false, 'denied-no-match'],
  ['port not listed → denied', { policies: [fromIngress], local: { podLabels: web }, peer: { namespace: 'ingress-nginx', namespaceLabels: {}, podLabels: {} }, port: { port: 9090 } }, false, 'denied-no-match'],
  ['namespaceSelector AND podSelector both required', { policies: [monitoring], local: { podLabels: api }, peer: { namespace: 'monitoring', namespaceLabels: { team: 'obs' }, podLabels: { app: 'grafana' } }, port: { port: 9090 } }, false, 'denied-no-match'],
  ['matchExpressions In + endPort range', { policies: [monitoring], local: { podLabels: api }, peer: { namespace: 'monitoring', namespaceLabels: { team: 'obs' }, podLabels: { app: 'prometheus' } }, port: { port: 9090 } }, true, 'allowed'],
  ['endPort upper bound is inclusive', { policies: [monitoring], local: { podLabels: web }, peer: { namespace: 'monitoring', namespaceLabels: { team: 'obs' }, podLabels: { app: 'prometheus' } }, port: { port: 9100 } }, true, 'allowed'],
  ['beyond endPort → denied', { policies: [monitoring], local: { podLabels: web }, peer: { namespace: 'monitoring', namespaceLabels: { team: 'obs' }, podLabels: { app: 'prometheus' } }, port: { port: 9101 } }, false, 'denied-no-match'],
  ['empty rule {} allows everything', { policies: [denyAll, allowAll], local: { podLabels: { app: 'x' } }, peer: { namespace: 'anywhere', namespaceLabels: {}, podLabels: {} }, port: { port: 1234, protocol: 'UDP' } }, true, 'allowed'],
  ['ipBlock peers never match a pod', { policies: [ipOnly], local: { podLabels: web }, peer: sameNs({}), port: { port: 80 } }, false, 'denied-no-match'],
];

describe('NetworkPolicy simulator · ingress', () => {
  it.each(ingressCases)('%s', (_name, partial, allowed, code, reason) => {
    const r = simulate({ direction: 'Ingress', namespace: NS, local: { podLabels: {} }, peer: sameNs({}), port: { port: 80 }, ...partial });
    expect(r.allowed).toBe(allowed);
    expect(r.code).toBe(code);
    if (reason) expect(r.reason).toContain(reason);
  });

  it('names the selecting policies and traces each rule', () => {
    const r = simulate({ direction: 'Ingress', namespace: NS, policies: [denyAll, fromIngress], local: { podLabels: web }, peer: sameNs({ app: 'x' }), port: { port: 8080 } });
    expect(r.selectedBy).toEqual(['default-deny', 'allow-from-ingress']);
    expect(r.trace.map((t) => [t.policy, t.rule, t.ok])).toEqual([
      ['default-deny', -1, false],
      ['allow-from-ingress', 0, false],
    ]);
    expect(r.trace[1].why).toContain('does not match namespaceSelector');
  });
});

describe('NetworkPolicy simulator · egress', () => {
  it('allows the listed destination and port, denies the rest', () => {
    const base = { direction: 'Egress' as const, namespace: NS, policies: [egressDb], local: { podLabels: api } };
    expect(simulate({ ...base, peer: sameNs({ app: 'postgres' }), port: { port: 5432 } }).allowed).toBe(true);
    expect(simulate({ ...base, peer: { namespace: 'kube-system', namespaceLabels: {}, podLabels: { 'k8s-app': 'kube-dns' } }, port: { port: 53, protocol: 'UDP' } }).allowed).toBe(true);
    const r = simulate({ ...base, peer: { namespace: 'shop', namespaceLabels: {}, podLabels: { app: 'postgres' } }, port: { port: 5432 } });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('no egress rule matches');
    // a pod the policy does not select is not restricted
    expect(simulate({ ...base, local: { podLabels: web }, peer: sameNs({}), port: { port: 1 } }).code).toBe('not-isolated');
  });
});

describe('NetworkPolicy helpers', () => {
  it('defaults policyTypes like the API server', () => {
    expect(policyTypes({ podSelector: {} })).toEqual(['Ingress']);
    expect(policyTypes({ podSelector: {}, egress: [{}] })).toEqual(['Ingress', 'Egress']);
    expect(policyTypes({ podSelector: {}, egress: [] })).toEqual(['Ingress']);
    expect(policyTypes({ podSelector: {}, policyTypes: ['Egress'] })).toEqual(['Egress']);
  });
  it('evaluates matchExpressions', () => {
    const sel = { matchExpressions: [{ key: 'env', operator: 'NotIn', values: ['dev'] }, { key: 'team', operator: 'Exists' }, { key: 'legacy', operator: 'DoesNotExist' }] };
    expect(selectorMatches(sel, { team: 'a' })).toBe(true); // NotIn holds when the key is absent
    expect(selectorMatches(sel, { team: 'a', env: 'dev' })).toBe(false);
    expect(selectorMatches(sel, { team: 'a', legacy: '1' })).toBe(false);
    expect(selectorMatches({ matchExpressions: [{ key: 'x', operator: 'Bogus' }] }, { x: '1' })).toBe(false);
    expect(describeSelector(sel)).toBe('env not in (dev), team exists, no legacy');
  });
  it('describes peers and ports', () => {
    expect(describePeer({ podSelector: {} }, NS)).toBe('all pods in orders');
    expect(describePeer({ namespaceSelector: {} }, NS)).toBe('all pods in all namespaces');
    expect(describePeer({ namespaceSelector: { matchLabels: { team: 'obs' } }, podSelector: { matchLabels: { app: 'p' } } }, NS)).toBe('pods app=p in namespaces team=obs');
    expect(portsMatch([{ protocol: 'UDP' }], { port: 53, protocol: 'udp' }).match).toBe(true);
  });
  it('summarises the namespace state per direction', () => {
    expect(directionState([], 'Ingress')).toBe('open');
    expect(directionState([webToApi], 'Ingress')).toBe('partial');
    expect(directionState([denyAll, webToApi], 'Ingress')).toBe('default-deny');
    expect(directionState([denyAll], 'Egress')).toBe('open');
    expect(isDefaultDenyIngress(denyAll)).toBe(true);
    expect(isDefaultDenyIngress(allowAll)).toBe(false);
  });
  it('parses port input', () => {
    expect(parsePort('8080')).toEqual({ port: 8080, protocol: 'TCP' });
    expect(parsePort('53/udp')).toEqual({ port: 53, protocol: 'UDP' });
    expect(parsePort('http', 'SCTP')).toEqual({ port: 'http', protocol: 'SCTP' });
    expect(parsePort('70000')).toBeNull();
    expect(parsePort('')).toBeNull();
  });
});
