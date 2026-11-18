// DEV-ONLY fixtures and handlers for the cluster-first views: per-cluster summaries
// (security/audit/backup), Kyverno policy detail, NetworkPolicy namespace detail, per-cluster
// filters on images/policies/runs/findings, and tag-scanned images.
import type { AuditClusterSummary, BackupClusterSummary, Cluster, Image, KyvernoPolicy, KyvernoPolicyDetail, KyvernoViolation, NetpolNamespace, NetpolNamespaceDetail, NetpolWorkload, SecurityClusterSummary } from '../api/types';
import { toYaml } from '../lib/yaml';
import * as db from './db';
import type { MockReq, MockRes } from './handlers';

type Handler = (req: MockReq, params: Record<string, string>) => MockRes | Promise<MockRes>;
const ok = (body: unknown, status = 200): MockRes => ({ status, body });
const items = (list: unknown[]) => ok({ items: list });
const notFound = (): MockRes => ({ status: 404, body: { error: 'not found' } });
const rnd = db.seeded(4711);
const H = 3_600_000;
const D = 24 * H;

const live = () => db.clusters.filter((c) => c.status !== 'pending' && c.status !== 'revoked');
const clusterOf = (idOrName: string | null): Cluster | undefined => (idOrName ? db.clusters.find((c) => c.id === idOrName || c.name === idOrName) : undefined);
const noImages = () => localStorage.getItem('olympos.mock.noImages') === '1';

// ------------------------------------------------------------ images: tag scans + cluster mapping

// kind/kubeadm control-plane images: the running digest is the node's local build, so the server
// scanned the registry image with the same tag (scanned_by: tag).
for (const [repo, tag, crit, high] of [
  ['registry.k8s.io/kube-apiserver', 'v1.30.9', 0, 3],
  ['registry.k8s.io/kube-controller-manager', 'v1.30.9', 0, 2],
  ['registry.k8s.io/kube-scheduler', 'v1.30.9', 0, 1],
  ['registry.k8s.io/etcd', '3.5.15-0', 1, 6],
  ['registry.k8s.io/coredns/coredns', 'v1.11.1', 0, 2],
] as [string, string, number, number][]) {
  db.images.push({
    digest: `sha256:${Array.from({ length: 64 }, () => Math.floor(rnd() * 16).toString(16)).join('')}`,
    repo,
    tags: [tag],
    clusters: 2,
    workloads: 2,
    critical: crit,
    high,
    medium: 4,
    low: 9,
    scan_status: 'scanned',
    scanned_by: 'tag',
    scan_error: `MANIFEST_UNKNOWN: the running digest is not in ${repo.split('/')[0]}; scanned ${repo}:${tag} instead`,
    scan_attempts: 1,
    next_retry_at: null,
    last_scanned_at: new Date(Date.now() - 3 * H).toISOString(),
    fixable: crit + high > 0 ? 1 : 0,
    registry: 'public',
  });
}

/** digest → cluster ids the image runs in (length = image.clusters). */
export const imageClusters = new Map<string, string[]>();
{
  const ids = live().map((c) => c.id);
  const onprem = live().filter((c) => c.provider === 'onprem').map((c) => c.id);
  db.images.forEach((img, n) => {
    const pool = img.scanned_by === 'tag' || img.repo.includes('kindest') || img.repo.startsWith('harbor.') ? onprem : ids;
    const want = Math.min(img.clusters, pool.length);
    const picked: string[] = [];
    const start = (n * 7) % Math.max(1, pool.length);
    for (let k = 0; k < pool.length && picked.length < want; k++) picked.push(pool[(start + k) % pool.length]);
    img.clusters = picked.length;
    imageClusters.set(img.digest, picked);
  });
}
const imagesIn = (clusterId: string) => db.images.filter((i) => imageClusters.get(i.digest)?.includes(clusterId));
const needsAttention = (i: Image) => ['failed', 'unavailable', 'missing_credential'].includes(i.scan_status) && i.scanned_by !== 'tag';

// No Kyverno on the offline lab cluster (shows "not installed" in the overview).
for (let i = db.kyverno.length - 1; i >= 0; i--) if (db.kyverno[i].cluster_name === 'onprem-ist-lab') db.kyverno.splice(i, 1);

// ------------------------------------------------------------ Kyverno specs

interface RuleTpl {
  name: string;
  message: string;
  pattern?: unknown;
  deny?: unknown;
}
interface PolicyTpl {
  title: string;
  category: string;
  severity: 'low' | 'medium' | 'high';
  rules: RuleTpl[];
  cel: { expression: string; message: string }[];
  kinds?: string[];
}
const POD = ['Pod'];
const TPL: Record<string, PolicyTpl> = {
  'require-labels': { title: 'Require labels', category: 'Best Practices', severity: 'medium', rules: [{ name: 'check-team', message: "label 'team' is required", pattern: { metadata: { labels: { team: '?*' } } } }], cel: [{ expression: "has(object.metadata.labels) && 'team' in object.metadata.labels", message: "label 'team' is required" }], kinds: ['Pod', 'Deployment', 'StatefulSet'] },
  'require-probes': { title: 'Require readiness probes', category: 'Best Practices', severity: 'medium', rules: [{ name: 'validate-readiness', message: 'Readiness probes are required for all containers.', pattern: { spec: { containers: [{ readinessProbe: { periodSeconds: '>0' } }] } } }], cel: [{ expression: 'object.spec.containers.all(c, has(c.readinessProbe))', message: 'Readiness probes are required for all containers.' }] },
  'disallow-privileged': { title: 'Disallow privileged containers', category: 'Pod Security Standards (Baseline)', severity: 'high', rules: [{ name: 'privileged-containers', message: 'Privileged mode is disallowed. The field spec.containers[*].securityContext.privileged must be unset or set to `false`.', pattern: { spec: { containers: [{ '=(securityContext)': { '=(privileged)': 'false' } }] } } }], cel: [{ expression: 'object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false)', message: 'Privileged mode is disallowed.' }] },
  'disallow-host-namespaces': { title: 'Disallow host namespaces', category: 'Pod Security Standards (Baseline)', severity: 'high', rules: [{ name: 'host-namespaces', message: 'Sharing the host namespaces is disallowed. The fields spec.hostNetwork, spec.hostIPC, and spec.hostPID must be unset or set to `false`.', pattern: { spec: { '=(hostPID)': 'false', '=(hostIPC)': 'false', '=(hostNetwork)': 'false' } } }], cel: [{ expression: 'object.spec.?hostNetwork.orValue(false) == false && object.spec.?hostPID.orValue(false) == false', message: 'Sharing the host namespaces is disallowed.' }] },
  'require-image-digest': { title: 'Require images by digest', category: 'Supply chain', severity: 'medium', rules: [{ name: 'require-digest', message: 'Images must use a digest (image@sha256:…).', pattern: { spec: { containers: [{ image: '*@sha256:*' }] } } }], cel: [{ expression: "object.spec.containers.all(c, c.image.contains('@sha256:'))", message: 'Images must use a digest (image@sha256:…).' }] },
  'restrict-registries': { title: 'Restrict image registries', category: 'Supply chain', severity: 'high', rules: [{ name: 'validate-registries', message: 'Unknown image registry. Use acr.contoso.io or ghcr.io/contoso.', pattern: { spec: { containers: [{ image: 'acr.contoso.io/* | ghcr.io/contoso/*' }] } } }], cel: [{ expression: "object.spec.containers.all(c, c.image.startsWith('acr.contoso.io/'))", message: 'Unknown image registry. Use acr.contoso.io.' }] },
  'require-pod-requests': { title: 'Require CPU and memory requests', category: 'Best Practices', severity: 'medium', rules: [{ name: 'validate-resources', message: 'CPU and memory resource requests are required.', pattern: { spec: { containers: [{ resources: { requests: { cpu: '?*', memory: '?*' } } }] } } }], cel: [{ expression: 'object.spec.containers.all(c, has(c.resources.requests.cpu))', message: 'CPU requests are required.' }] },
  'disallow-capabilities': { title: 'Disallow added capabilities', category: 'Pod Security Standards (Baseline)', severity: 'medium', rules: [{ name: 'adding-capabilities', message: 'Any capabilities added beyond the allowed list (AUDIT_WRITE, CHOWN, …) are disallowed.', pattern: { spec: { containers: [{ '=(securityContext)': { '=(capabilities)': { 'X(add)': 'null' } } }] } } }], cel: [{ expression: "object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.capabilities) || !has(c.securityContext.capabilities.add) || c.securityContext.capabilities.add.all(cap, cap in ['AUDIT_WRITE','CHOWN']))", message: 'Added capabilities are disallowed.' }] },
  'require-run-as-nonroot': {
    title: 'Require runAsNonRoot',
    category: 'Pod Security Standards (Restricted)',
    severity: 'high',
    rules: [
      { name: 'run-as-non-root', message: 'Running as root is not allowed. spec.containers[*].securityContext.runAsNonRoot must be set to `true`.', pattern: { spec: { containers: [{ securityContext: { runAsNonRoot: true } }] } } },
      { name: 'run-as-non-root-user', message: 'Running as root is not allowed. The field runAsUser must be greater than 0.', pattern: { spec: { containers: [{ '=(securityContext)': { '=(runAsUser)': '>0' } }] } } },
    ],
    cel: [{ expression: 'object.spec.containers.all(c, has(c.securityContext) && c.securityContext.runAsNonRoot == true)', message: 'Running as root is not allowed.' }],
  },
  'disallow-latest-tag': {
    title: 'Disallow latest tag',
    category: 'Best Practices',
    severity: 'medium',
    rules: [
      { name: 'require-image-tag', message: 'An image tag is required.', pattern: { spec: { containers: [{ image: '*:*' }] } } },
      { name: 'validate-image-tag', message: "Using a mutable image tag e.g. 'latest' is not allowed.", pattern: { spec: { containers: [{ image: '!*:latest' }] } } },
    ],
    cel: [{ expression: "object.spec.containers.all(c, !c.image.endsWith(':latest'))", message: "Using a mutable image tag e.g. 'latest' is not allowed." }],
  },
  'require-resource-limits': { title: 'Require memory limits', category: 'Best Practices', severity: 'medium', rules: [{ name: 'validate-resources', message: 'Memory limits are required.', pattern: { spec: { containers: [{ resources: { limits: { memory: '?*' } } }] } } }], cel: [{ expression: 'object.spec.containers.all(c, has(c.resources.limits.memory))', message: 'Memory limits are required.' }] },
  'restrict-host-path': { title: 'Restrict hostPath volumes', category: 'Pod Security Standards (Baseline)', severity: 'high', rules: [{ name: 'host-path', message: 'HostPath volumes are forbidden. The field spec.volumes[*].hostPath must be unset.', pattern: { spec: { '=(volumes)': [{ 'X(hostPath)': 'null' }] } } }], cel: [{ expression: '!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))', message: 'HostPath volumes are forbidden.' }] },
};
const tplOf = (name: string): PolicyTpl => TPL[name] ?? TPL['require-labels'];
const isCel = (p: KyvernoPolicy) => !!p.kind && p.kind !== 'ClusterPolicy' && p.kind !== 'Policy';

// keep the list in line with the specs (rule count and names)
for (const p of db.kyverno) {
  const t = tplOf(p.name);
  p.kind = p.kind ?? (p.namespace ? 'Policy' : 'ClusterPolicy');
  p.rules = isCel(p) ? t.cel.length : t.rules.length;
  p.rule_names = isCel(p) ? [p.name] : t.rules.map((r) => r.name);
}

function policySpec(p: KyvernoPolicy): Record<string, unknown> {
  const t = tplOf(p.name);
  if (isCel(p)) {
    return {
      validationActions: p.mode === 'Enforce' ? ['Deny'] : ['Audit'],
      evaluation: { background: { enabled: true } },
      matchConstraints: { resourceRules: [{ apiGroups: [''], apiVersions: ['v1'], operations: ['CREATE', 'UPDATE'], resources: ['pods'] }] },
      matchConditions: [{ name: 'skip-system-namespaces', expression: "!(request.namespace in ['kube-system', 'olympos-system'])" }],
      validations: t.cel,
    };
  }
  return {
    validationFailureAction: p.mode,
    background: true,
    rules: t.rules.map((r) => ({
      name: r.name,
      match: { any: [{ resources: { kinds: t.kinds ?? POD } }] },
      exclude: { any: [{ resources: { namespaces: ['kube-system', 'olympos-system'] } }] },
      validate: { message: r.message, ...(r.pattern !== undefined ? { pattern: r.pattern } : {}), ...(r.deny ? { deny: r.deny } : {}) },
    })),
  };
}

const WORKLOADS = ['web', 'api', 'worker', 'cache', 'cron-cleanup', 'exporter', 'gateway', 'scheduler'];
function violations(p: KyvernoPolicy): KyvernoViolation[] {
  const t = tplOf(p.name);
  const nss = db.netpol.filter((n) => n.cluster_id === p.cluster_id && !n.excluded).map((n) => n.namespace);
  const out: KyvernoViolation[] = [];
  for (let i = 0; i < p.fail_count; i++) {
    const rule = isCel(p) ? { name: p.name, message: t.cel[i % t.cel.length].message } : t.rules[i % t.rules.length];
    const ns = p.namespace || nss[i % Math.max(1, nss.length)] || 'default';
    const w = WORKLOADS[(i * 3 + p.name.length) % WORKLOADS.length];
    const kind = (t.kinds ?? POD)[i % (t.kinds ?? POD).length];
    const name = kind === 'Pod' ? `${w}-${(7919 * (i + 3)).toString(36).slice(-5)}` : w;
    out.push({ rule: rule.name, result: 'fail', severity: t.severity, message: isCel(p) ? rule.message : `validation error: ${rule.message} rule ${rule.name} failed at path /${kind === 'Pod' ? '' : 'spec/template/'}${p.name === 'require-labels' ? 'metadata/labels/team/' : 'spec/containers/0/'}`, resource_kind: kind, resource_namespace: ns, resource_name: name });
  }
  return out;
}

function kyvernoDetail(p: KyvernoPolicy): KyvernoPolicyDetail {
  const spec = policySpec(p);
  const t = tplOf(p.name);
  const obj = {
    apiVersion: isCel(p) ? 'policies.kyverno.io/v1' : 'kyverno.io/v1',
    kind: p.kind,
    metadata: { name: p.name, ...(p.namespace ? { namespace: p.namespace } : {}), annotations: { 'policies.kyverno.io/title': t.title, 'policies.kyverno.io/category': t.category, 'policies.kyverno.io/severity': t.severity } },
    spec,
  };
  return { ...p, spec, yaml: toYaml(obj), violations: violations(p) };
}

// ------------------------------------------------------------ NetworkPolicy namespaces

const NS_LABELS: Record<string, Record<string, string>> = {
  'ingress-nginx': { 'app.kubernetes.io/name': 'ingress-nginx', tier: 'edge' },
  monitoring: { team: 'observability', 'prometheus-scrape': 'true' },
  observability: { team: 'observability' },
  'kube-system': {},
  'cert-manager': { team: 'platform' },
  default: {},
};
const nsLabels = (name: string, cluster: Cluster) => ({ 'kubernetes.io/metadata.name': name, ...(NS_LABELS[name] ?? { team: name }), ...(cluster.labels.env ? { env: cluster.labels.env } : {}) });

const pol = (name: string, spec: Record<string, unknown>, ns: string) => ({ name, spec, yaml: toYaml({ apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name, namespace: ns }, spec }) });

function ordersDetail(n: NetpolNamespace, c: Cluster): NetpolNamespaceDetail {
  const ns = n.namespace;
  return {
    ...base(n, c),
    policies: [
      pol('default-deny-ingress', { podSelector: {}, policyTypes: ['Ingress'] }, ns),
      pol('allow-web-from-ingress', { podSelector: { matchLabels: { app: 'web' } }, policyTypes: ['Ingress'], ingress: [{ from: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'ingress-nginx' } } }], ports: [{ protocol: 'TCP', port: 8080 }] }] }, ns),
      pol(
        'orders-api',
        {
          podSelector: { matchLabels: { app: 'orders-api' } },
          policyTypes: ['Ingress', 'Egress'],
          ingress: [
            { from: [{ podSelector: { matchLabels: { app: 'web' } } }], ports: [{ protocol: 'TCP', port: 'http' }] },
            { from: [{ namespaceSelector: { matchLabels: { team: 'observability' } }, podSelector: { matchLabels: { 'app.kubernetes.io/name': 'prometheus' } } }], ports: [{ protocol: 'TCP', port: 9090 }] },
          ],
          egress: [
            { to: [{ podSelector: { matchLabels: { app: 'orders-pg' } } }], ports: [{ protocol: 'TCP', port: 5432 }] },
            { to: [{ namespaceSelector: {}, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }], ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }] },
            { to: [{ ipBlock: { cidr: '10.40.0.0/16', except: ['10.40.9.0/24'] } }], ports: [{ protocol: 'TCP', port: 443 }] },
          ],
        },
        ns,
      ),
    ],
    workloads: [
      { kind: 'Deployment', name: 'web', labels: { app: 'web', tier: 'frontend' }, ports: [8080], named_ports: { 'http-web': 8080 } },
      { kind: 'Deployment', name: 'orders-api', labels: { app: 'orders-api', tier: 'backend' }, ports: [8080, 9090], named_ports: { http: 8080, metrics: 9090 } },
      { kind: 'StatefulSet', name: 'orders-pg', labels: { app: 'orders-pg', 'app.kubernetes.io/name': 'postgresql' }, ports: [5432], named_ports: { postgres: 5432 } },
      { kind: 'Deployment', name: 'orders-worker', labels: { app: 'orders-worker' }, ports: [] },
    ],
  };
}

function base(n: NetpolNamespace, c: Cluster): NetpolNamespaceDetail {
  const others = db.netpol.filter((x) => x.cluster_id === c.id && x.namespace !== n.namespace).map((x) => x.namespace);
  for (const extra of ['kube-system', 'ingress-nginx', 'monitoring']) if (!others.includes(extra) && extra !== n.namespace) others.push(extra);
  return {
    cluster_id: c.id,
    cluster_name: c.name,
    namespace: n.namespace,
    namespace_labels: nsLabels(n.namespace, c),
    default_deny: n.default_deny,
    excluded: n.excluded,
    policies: [],
    workloads: [],
    other_namespaces: others.sort().map((name) => ({ name, labels: nsLabels(name, c) })),
  };
}

function genericDetail(n: NetpolNamespace, c: Cluster): NetpolNamespaceDetail {
  const ns = n.namespace;
  const d = base(n, c);
  const app = ns === 'default' ? 'demo' : ns.replace(/-.*/, '');
  d.workloads = [
    { kind: 'Deployment', name: `${app}-api`, labels: { app: `${app}-api`, tier: 'backend' }, ports: [8080, 9090], named_ports: { http: 8080, metrics: 9090 } },
    { kind: 'Deployment', name: `${app}-web`, labels: { app: `${app}-web`, tier: 'frontend' }, ports: [3000], named_ports: { http: 3000 } },
    { kind: 'StatefulSet', name: `${app}-db`, labels: { app: `${app}-db` }, ports: [5432] },
  ] satisfies NetpolWorkload[];
  const pool = [
    pol('allow-same-namespace', { podSelector: {}, ingress: [{ from: [{ podSelector: {} }] }] }, ns),
    pol('allow-from-ingress-nginx', { podSelector: { matchLabels: { tier: 'frontend' } }, ingress: [{ from: [{ namespaceSelector: { matchLabels: { 'app.kubernetes.io/name': 'ingress-nginx' } } }], ports: [{ port: 'http' }] }] }, ns),
    pol('allow-prometheus-scrape', { podSelector: { matchExpressions: [{ key: 'tier', operator: 'In', values: ['backend', 'frontend'] }] }, ingress: [{ from: [{ namespaceSelector: { matchLabels: { team: 'observability' } } }], ports: [{ port: 'metrics' }, { port: 9100, endPort: 9110 }] }] }, ns),
    pol('allow-dns-egress', { podSelector: {}, policyTypes: ['Egress'], egress: [{ to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } } }], ports: [{ protocol: 'UDP', port: 53 }] }, { to: [{ podSelector: {} }] }] }, ns),
  ];
  if (n.default_deny) d.policies.push(pol('default-deny', { podSelector: {}, policyTypes: ['Ingress'] }, ns));
  const need = n.policy_count - d.policies.length;
  // allow-only namespaces never get the select-everything policies (they would be default-deny)
  const candidates = n.default_deny ? pool : pool.filter((p) => p.name !== 'allow-same-namespace' && p.name !== 'allow-dns-egress');
  for (let i = 0; i < need && i < candidates.length; i++) d.policies.push(candidates[i]);
  return d;
}

function netpolDetail(n: NetpolNamespace): NetpolNamespaceDetail {
  const c = clusterOf(n.cluster_id)!;
  if (c.name === 'prod-aks-weu-01' && n.namespace === 'orders') return ordersDetail(n, c);
  return genericDetail(n, c);
}
// policy counts follow the generated specs
for (const n of db.netpol) n.policy_count = netpolDetail(n).policies.length;

// ------------------------------------------------------------ summaries

function securitySummary(c: Cluster): SecurityClusterSummary {
  const imgs = imagesIn(c.id);
  const ky = db.kyverno.filter((p) => p.cluster_id === c.id);
  const np = db.netpol.filter((n) => n.cluster_id === c.id);
  const scanned = imgs.filter((i) => i.scan_status === 'scanned');
  return {
    cluster_id: c.id,
    cluster_name: c.name,
    provider: c.provider,
    status: c.status,
    images: imgs.length,
    workloads: imgs.reduce((s, i) => s + Math.max(1, Math.round(i.workloads / Math.max(1, i.clusters))), 0),
    critical: scanned.reduce((s, i) => s + i.critical, 0),
    high: scanned.reduce((s, i) => s + i.high, 0),
    images_with_critical: scanned.filter((i) => i.critical > 0).length,
    not_scanned: imgs.filter(needsAttention).length,
    kyverno_installed: ky.length > 0,
    kyverno_policies: ky.length,
    kyverno_failures: ky.reduce((s, p) => s + p.fail_count, 0),
    namespaces: np.length,
    namespaces_without_default_deny: np.filter((n) => !n.default_deny && !n.excluded).length,
  };
}

const AUDIT_SOURCES = ['kubescape', 'polaris', 'kube-bench'];
function auditSummary(c: Cluster): AuditClusterSummary {
  const last_runs = ['kubescape', 'polaris', 'kube-bench']
    .map((tool) => db.auditRuns.find((r) => r.tool === tool && r.cluster_id === c.id))
    .filter(Boolean)
    .map((r) => ({ tool: r!.tool, run_id: r!.id, status: r!.status, score: r!.score, finished_at: r!.finished_at, new_findings: r!.new_findings }));
  const open = db.findings.filter((f) => f.cluster_id === c.id && f.status === 'open' && AUDIT_SOURCES.includes(f.source));
  const count = (s: string) => open.filter((f) => f.severity === s).length;
  return { cluster_id: c.id, cluster_name: c.name, provider: c.provider, bench_enabled: c.bench_enabled, last_runs, open_findings: { critical: count('critical'), high: count('high'), medium: count('medium'), low: count('low') } };
}

function backupSummary(c: Cluster): BackupClusterSummary {
  const targets = db.targets.filter((t) => t.cluster_id === c.id && t.status !== 'gone');
  const jobs = db.jobs.filter((j) => j.target.cluster_id === c.id);
  const runs = db.runs.filter((r) => r.cluster_name === c.name && r.trigger !== 'test');
  const since = (ms: number) => runs.filter((r) => Date.now() - new Date(r.started_at ?? r.scheduled_for ?? 0).getTime() < ms);
  const day = since(D);
  const ok = runs.filter((r) => r.status === 'succeeded').sort((a, b) => (b.finished_at ?? '').localeCompare(a.finished_at ?? ''));
  return {
    cluster_id: c.id,
    cluster_name: c.name,
    targets: targets.filter((t) => t.engine !== '').length,
    candidates: targets.filter((t) => t.status === 'candidate' && t.engine !== '').length,
    jobs: jobs.length,
    jobs_enabled: jobs.filter((j) => j.enabled).length,
    last_24h: { succeeded: day.filter((r) => r.status === 'succeeded').length, failed: day.filter((r) => r.status === 'failed').length, missed: day.filter((r) => r.status === 'missed').length },
    last_success_at: ok[0]?.finished_at ?? null,
    bytes_30d: since(30 * D).reduce((s, r) => s + (r.bytes || 0), 0),
  };
}

// ------------------------------------------------------------ handlers

const byCluster = <T extends { cluster_id: string }>(list: T[], q: string | null) => {
  if (!q) return list;
  const c = clusterOf(q);
  return c ? list.filter((x) => x.cluster_id === c.id) : [];
};

export const fleetRoutes: [string, string, Handler][] = [
  ['GET', '/security/clusters', () => items(live().map(securitySummary))],
  ['GET', '/audit/clusters', () => items(live().map(auditSummary))],
  ['GET', '/backup/clusters', () => items(live().map(backupSummary))],
  [
    'GET',
    '/images',
    (r) => {
      const q = (r.query.get('q') ?? '').toLowerCase();
      const sev = r.query.get('severity');
      if (noImages()) return items([]);
      const cq = r.query.get('cluster');
      const c = clusterOf(cq);
      if (cq && !c) return items([]);
      return items(
        db.images
          .filter((i) => !c || imageClusters.get(i.digest)?.includes(c.id))
          .filter((i) => (!q || i.repo.toLowerCase().includes(q) || i.digest.includes(q)) && (!sev || (sev === 'critical' ? i.critical > 0 : i.high > 0)))
          .map((i) => (c ? { ...i, clusters: 1, workloads: Math.max(1, Math.round(i.workloads / Math.max(1, i.clusters))) } : i)),
      );
    },
  ],
  [
    'GET',
    '/images/:digest',
    (_r, p) => {
      const i = db.images.find((x) => x.digest === decodeURIComponent(p.digest));
      if (!i) return notFound();
      const cs = (imageClusters.get(i.digest) ?? []).map((id) => clusterOf(id)!).filter(Boolean);
      const name = i.repo.split('/').pop()!;
      return ok({
        scan_error: '',
        ...i,
        usage: cs.map((c, n) => ({ cluster_id: c.id, cluster_name: c.name, namespace: i.scanned_by === 'tag' ? 'kube-system' : ['apps', 'erp', 'monitoring', 'jobs'][n % 4], workload_kind: i.scanned_by === 'tag' ? 'Pod' : 'Deployment', workload_name: i.scanned_by === 'tag' ? `${name}-${c.name}` : name, container: name, image: `${i.repo}:${i.tags[0] ?? 'latest'}` })),
        vulns: i.critical || i.high ? [...(i.critical ? [{ cve_id: 'CVE-2026-31337', severity: 'critical', package: 'openssl', installed: '3.0.13', fixed_in: '3.0.15', title: 'Buffer overflow in X.509 name checks' }] : []), { cve_id: 'CVE-2026-1021', severity: 'high', package: 'libexpat', installed: '2.5.0', fixed_in: '2.6.3', title: 'Integer overflow in XML parser' }] : [],
      });
    },
  ],
  ['GET', '/security/kyverno', (r) => items(byCluster(db.kyverno, r.query.get('cluster')))],
  ['GET', '/security/netpol', (r) => items(byCluster(db.netpol, r.query.get('cluster')))],
  [
    'GET',
    '/security/kyverno/policy',
    (r) => {
      const c = clusterOf(r.query.get('cluster'));
      const kind = r.query.get('kind') ?? '';
      const ns = r.query.get('namespace') ?? '';
      const name = r.query.get('name') ?? '';
      const p = c && db.kyverno.find((x) => x.cluster_id === c.id && x.name === name && (x.kind ?? '') === kind && x.namespace === ns);
      return p ? ok(kyvernoDetail(p)) : notFound();
    },
  ],
  [
    'GET',
    '/security/netpol/namespace',
    (r) => {
      const c = clusterOf(r.query.get('cluster'));
      const n = c && db.netpol.find((x) => x.cluster_id === c.id && x.namespace === r.query.get('namespace'));
      return n ? ok(netpolDetail(n)) : notFound();
    },
  ],
  [
    'GET',
    '/audit/runs',
    (r) => {
      const tool = r.query.get('tool');
      const sid = r.query.get('schedule_id');
      const cid = r.query.get('cluster_id');
      return items(
        db.auditRuns
          .filter((x) => (!tool || x.tool === tool) && (!sid || x.schedule_id === sid) && (!cid || x.cluster_id === cid))
          .slice(0, Number(r.query.get('limit') ?? 50))
          .map(({ log: _log, ...x }) => x), // eslint-disable-line @typescript-eslint/no-unused-vars
      );
    },
  ],
  [
    'GET',
    '/findings',
    (r) => {
      const src = r.query.get('source');
      const st = r.query.get('status');
      const runId = r.query.get('run_id');
      const cq = r.query.get('cluster');
      const c = clusterOf(cq);
      if (cq && !c) return items([]);
      const run = runId ? db.auditRuns.find((x) => x.id === runId) : undefined;
      return items(db.findings.filter((f) => (!src || f.source === src) && (!st || f.status === st) && (!c || f.cluster_id === c.id) && (!runId || (f.source === (run?.tool ?? 'kubescape') && (!run?.cluster_id || f.cluster_id === run.cluster_id)))));
    },
  ],
];
