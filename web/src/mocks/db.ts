// DEV-ONLY fixtures (VITE_MOCK). Shapes follow docs/openapi.yaml. Never imported by
// production code paths: main.tsx loads this behind `import.meta.env.VITE_MOCK`.
import type {
  ActivityEntry,
  AuditRun,
  AuditSchedule,
  BackupJob,
  BackupRun,
  Channel,
  ChangeRequest,
  Cluster,
  Destination,
  DestinationMount,
  Finding,
  Grant,
  Image,
  KyvernoPolicy,
  Me,
  NetpolNamespace,
  Principal,
  Registry,
  Role,
  Routes,
  SecretDetail,
  SecretSummary,
  Target,
  UnmatchedRegistry,
  Vault,
} from '../api/types';

const NOW = Date.now();
export const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();
export const isoIn = (msAhead: number) => new Date(NOW + msAhead).toISOString();
const MIN = 60_000;
const H = 60 * MIN;
const D = 24 * H;
const GB = 1e9;
const TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';

/** Deterministic pseudo-random numbers so generated fixtures look the same on every load. */
export function seeded(seed: number) {
  let x = seed >>> 0 || 1;
  return () => {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    return x / 2 ** 32;
  };
}
const rnd = seeded(20261118);
const hex = (n: number) => Array.from({ length: n }, () => Math.floor(rnd() * 16).toString(16)).join('');

export const uuid = () =>
  'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });

function principal(oid: string, upn: string, name: string, userType = 'Member', enabled = true): Principal {
  return { id: uuid(), tenant_id: TENANT, object_id: oid, upn, display_name: name, user_type: userType, account_enabled: enabled };
}

export const people = {
  yigit: principal('9a2f0c7e-5b1d-4e8a-9c3f-2d6b8e1a41bd', 'yigit@contoso.com', 'Yiğit B.'),
  selin: principal('4c1e93b2-7d4a-4f10-8e2b-6a9d5c3ba07f', 'selin@contoso.com', 'Selin A.'),
  mert: principal('d71b2e4f-9a3c-4b6d-8e1f-7c5a2b9d0c3e', 'mert@contoso.com', 'Mert K.'),
  deniz: principal('5e09a1c3-2b4d-4e6f-8a1b-3c5d7e9fb8a2', 'deniz@contoso.com', 'Deniz Y.', 'Member', false),
};

const ROLE_PRESETS: Record<string, Role[]> = {
  admin: ['admin', 'vault-maker', 'vault-approver'],
  operator: ['viewer', 'operator'],
  viewer: ['viewer'],
  maker: ['viewer', 'vault-maker'],
  approver: ['viewer', 'vault-approver'],
};

/** Switch with localStorage.setItem('olympos.mock.role', 'viewer'|'operator'|'maker'|'approver'|'admin'). */
export function me(): Me {
  let preset = 'admin';
  try {
    preset = localStorage.getItem('olympos.mock.role') || 'admin';
  } catch {
    /* ignore */
  }
  const roles = ROLE_PRESETS[preset] ?? ROLE_PRESETS.admin;
  const has = (r: Role) => roles.includes(r);
  return {
    principal: people.yigit,
    is_guest: false,
    roles,
    grants: roles.map((role) => ({ role, scope: 'all' })),
    permissions: {
      read: true,
      operate: has('operator') || has('admin'),
      operate_global: has('operator') || has('admin'),
      vault_make: has('vault-maker'),
      vault_approve: has('vault-approver'),
      admin: has('admin'),
      admin_global: has('admin'),
    },
    csrf_token: 'mock-csrf',
    dev_mode: true,
  };
}

/** Stable UUID-shaped id from a name, so ?cluster=<id> deep links survive a reload of the mock. */
export function stableId(name: string): string {
  const r = seeded([...name].reduce((h, c) => Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0, 2166136261));
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const v = Math.floor(r() * 16);
    return (c === 'x' ? v : (v & 0x3) | 0x8).toString(16);
  });
}

function cluster(p: Partial<Cluster> & Pick<Cluster, 'name'>): Cluster {
  return {
    id: stableId(p.name),
    labels: {},
    provider: 'azure',
    provider_label: 'Azure',
    provider_override: '',
    region: 'westeurope',
    api_version: 'v1.32.4',
    status: 'online',
    last_seen_at: iso(8_000),
    agent_version: '0.4.2',
    bench_enabled: true,
    transfer_mode: 'e2e-tls',
    egress_rate_per_gb: null,
    cert_expires_at: isoIn(13 * D),
    nodes: 3,
    nodes_ready: 3,
    cpu_milli: 24_000,
    mem_bytes: 96 * 2 ** 30,
    min_kubelet: p.api_version ?? 'v1.32.4',
    version_skew: false,
    eol: false,
    inventory_at: iso(40_000),
    created_at: iso(48 * D),
    ...p,
  };
}

export const clusters: Cluster[] = [
  cluster({ name: 'prod-aks-weu-01', labels: { env: 'prod', team: 'core' }, nodes: 18, nodes_ready: 18, cpu_milli: 240_000, mem_bytes: 1.4 * 2 ** 40, zones: ['westeurope-1', 'westeurope-2', 'westeurope-3'], instance_types: [{ instance_type: 'D8s_v5', count: 12 }, { instance_type: 'E16s_v5', count: 6 }] }),
  cluster({ name: 'prod-aks-weu-02', labels: { env: 'prod', team: 'billing' }, nodes: 14, nodes_ready: 14, cpu_milli: 112_000, mem_bytes: 448 * 2 ** 30, zones: ['westeurope-1', 'westeurope-2', 'westeurope-3'], instance_types: [{ instance_type: 'D8s_v5', count: 14 }] }),
  cluster({ name: 'aks-neu-dr', labels: { env: 'dr' }, region: 'northeurope', api_version: 'v1.31.4', min_kubelet: 'v1.31.4', nodes: 9, cpu_milli: 72_000, mem_bytes: 288 * 2 ** 30, bench_enabled: false, zones: ['northeurope-1', 'northeurope-2'], instance_types: [{ instance_type: 'D8s_v5', count: 9 }] }),
  cluster({ name: 'oke-fra-erp', labels: { env: 'prod', team: 'erp' }, provider: 'oracle', provider_label: 'Oracle Cloud', region: 'eu-frankfurt-1', api_version: 'v1.31.1', min_kubelet: 'v1.30.6', version_skew: true, nodes: 11, cpu_milli: 176_000, mem_bytes: 704 * 2 ** 30, zones: ['AD-1'], instance_types: [{ instance_type: 'VM.Standard.E5.Flex', count: 11 }], agent_version: '0.4.2' }),
  cluster({ name: 'eks-fra-data', labels: { env: 'prod', team: 'data' }, provider: 'aws', provider_label: 'AWS', region: 'eu-central-1', api_version: 'v1.31.3', min_kubelet: 'v1.31.3', nodes: 12, cpu_milli: 160_000, mem_bytes: 640 * 2 ** 30, transfer_mode: 'compressed', egress_rate_per_gb: 0.09, zones: ['eu-central-1a', 'eu-central-1b'], instance_types: [{ instance_type: 'm6i.2xlarge', count: 8 }, { instance_type: 'r6i.4xlarge', count: 4 }], backup_wire_bytes_30d: 74 * GB, backup_bytes_30d: 520 * GB }),
  cluster({ name: 'onprem-factory-01', labels: { env: 'prod', site: 'factory' }, provider: 'onprem', provider_label: 'On-prem', provider_override: 'onprem', region: '', api_version: 'v1.30.9', min_kubelet: 'v1.30.9', nodes: 5, cpu_milli: 40_000, mem_bytes: 160 * 2 ** 30, agent_version: '0.4.1', instance_types: [{ instance_type: '8 vCPU / 32 GiB', count: 5 }] }),
  cluster({ name: 'gke-euw1-web', labels: { env: 'prod', team: 'web' }, provider: 'gcp', provider_label: 'GCP', region: 'europe-west1', api_version: 'v1.32.2', min_kubelet: 'v1.32.2', nodes: 8, cpu_milli: 64_000, mem_bytes: 256 * 2 ** 30, instance_types: [{ instance_type: 'n2-standard-8', count: 8 }] }),
  cluster({ name: 'aks-weu-staging', labels: { env: 'staging', team: 'core' }, nodes: 6, cpu_milli: 48_000, mem_bytes: 192 * 2 ** 30, bench_enabled: false, instance_types: [{ instance_type: 'D4s_v5', count: 6 }] }),
  cluster({ name: 'eks-use1-ml', labels: { env: 'prod', team: 'ml', region: 'us' }, provider: 'aws', provider_label: 'AWS', region: 'us-east-1', api_version: 'v1.31.3', min_kubelet: 'v1.31.3', nodes: 16, cpu_milli: 256_000, mem_bytes: 1 * 2 ** 40, instance_types: [{ instance_type: 'g5.4xlarge', count: 4 }, { instance_type: 'm6i.4xlarge', count: 12 }] }),
  cluster({ name: 'cce-ist-retail', labels: { env: 'prod', team: 'retail', site: 'istanbul' }, provider: 'huawei', provider_label: 'Huawei Cloud', region: 'tr-west-1', api_version: 'v1.30.6', min_kubelet: 'v1.30.6', nodes: 7, cpu_milli: 56_000, mem_bytes: 224 * 2 ** 30, instance_types: [{ instance_type: 'c7.2xlarge.4', count: 7 }] }),
  cluster({ name: 'aks-sea-apac', labels: { env: 'prod', team: 'core', region: 'apac' }, region: 'southeastasia', nodes: 10, cpu_milli: 80_000, mem_bytes: 320 * 2 ** 30, instance_types: [{ instance_type: 'D8s_v5', count: 10 }] }),
  cluster({ name: 'onprem-ist-lab', labels: { env: 'lab' }, provider: 'onprem', provider_label: 'On-prem', provider_override: 'onprem', region: '', api_version: 'v1.29.12', min_kubelet: 'v1.29.12', eol: true, status: 'offline', last_seen_at: iso(2 * H), nodes: 3, nodes_ready: 0, cpu_milli: 12_000, mem_bytes: 48 * 2 ** 30, agent_version: '0.3.9', bench_enabled: false, instance_types: [{ instance_type: '4 vCPU / 16 GiB', count: 3 }] }),
];
export const byName = (n: string) => clusters.find((c) => c.name === n)!;

/** When a mock cluster was created by POST /clusters (it goes online after a few seconds). */
export const enrolling = new Map<string, number>();

function target(p: Partial<Target> & Pick<Target, 'service' | 'namespace' | 'engine'>, clusterName: string): Target {
  const c = byName(clusterName);
  return {
    id: Array.from({ length: 32 }, () => ((Math.random() * 16) | 0).toString(16)).join(''),
    cluster_id: c.id,
    cluster_name: c.name,
    port: 5432,
    port_name: '',
    vault_provider: '',
    tls_server_name: '',
    detected_version: '',
    tls_ok: true,
    status: 'candidate',
    first_seen_at: iso(2 * H),
    last_seen_at: iso(30_000),
    ...p,
  };
}

export const targets: Target[] = [
  target({ service: 'orders-pg', namespace: 'orders', engine: 'postgresql', detected_version: '16.4', port_name: 'postgres', tls_server_name: 'orders-pg.orders.svc' }, 'prod-aks-weu-01'),
  target({ service: 'events-ch', namespace: 'analytics', engine: 'clickhouse', detected_version: '24.8', port: 9000, port_name: 'native', tls_ok: false }, 'eks-fra-data'),
  target({ service: 'vault', namespace: 'vault', engine: 'vault', vault_provider: 'hashicorp', detected_version: '1.18', port: 8200, tls_server_name: 'vault.vault.svc' }, 'oke-fra-erp'),
  target({ service: 'billing-pg', namespace: 'billing', engine: 'postgresql', detected_version: '15.8', status: 'configured', first_seen_at: iso(40 * D) }, 'prod-aks-weu-02'),
  target({ service: 'openbao', namespace: 'security', engine: 'vault', vault_provider: 'openbao', detected_version: '2.1', port: 8200, status: 'configured', first_seen_at: iso(30 * D) }, 'prod-aks-weu-01'),
  target({ service: 'metrics-ch', namespace: 'observability', engine: 'clickhouse', detected_version: '24.3', port: 9000, tls_ok: false, status: 'configured', first_seen_at: iso(30 * D) }, 'oke-fra-erp'),
  target({ service: 'vault-dev', namespace: 'vault', engine: '', vault_provider: 'hashicorp', detected_version: '1.17', port: 8200, tls_server_name: 'vault-dev.vault.svc' }, 'onprem-factory-01'),
  // backup candidate whose vault is not configured in Olympos yet (wizard step 2 blocks)
  target({ service: 'bao-retail', namespace: 'security', engine: 'vault', vault_provider: 'openbao', detected_version: '2.2', port: 8200, tls_ok: false }, 'cce-ist-retail'),
];
export const tByService = (s: string) => targets.find((t) => t.service === s)!;

export const destinations: Destination[] = [
  {
    id: uuid(),
    name: 'blob-weu-backups',
    kind: 'azure_blob',
    account: 'stolympweu01',
    container: 'backups',
    prefix: 'olympos/',
    auth: 'managed_identity',
    sas_source: '',
    sas_ref: '',
    sas_expires_at: null,
    sas_permissions: '',
    endpoint_override: '',
    last_test_at: iso(3 * H),
    last_test_ok: true,
    last_test: { ok: true, can_delete: false, steps: [{ name: 'write', ok: true, detail: '' }, { name: 'read', ok: true, detail: '' }, { name: 'tag', ok: true, detail: '' }, { name: 'delete_refused', ok: true, detail: 'delete returned 403' }], sas: null },
    jobs: 9,
  },
  {
    id: uuid(),
    name: 'blob-neu-dr',
    kind: 'azure_blob',
    account: 'stolympneu01',
    container: 'dr-copies',
    prefix: 'olympos/',
    auth: 'sas_token',
    sas_source: 'stored',
    sas_ref: '',
    sas_expires_at: isoIn(12 * D),
    sas_permissions: 'rcwt',
    endpoint_override: '',
    last_test_at: iso(2 * H),
    last_test_ok: true,
    last_test: {
      ok: true,
      can_delete: false,
      steps: [{ name: 'write', ok: true, detail: '' }, { name: 'read', ok: true, detail: '' }, { name: 'tag', ok: true, detail: '' }, { name: 'delete_refused', ok: true, detail: 'delete returned 403' }],
      sas: { permissions: 'rcwt', expires_at: isoIn(12 * D), missing: [], extra: [], scope: 'container' },
    },
    jobs: 2,
  },
  {
    id: uuid(),
    name: 'minio-factory',
    kind: 's3',
    account: '',
    container: '',
    prefix: 'olympos/',
    auth: 'access_key',
    sas_source: '',
    sas_ref: '',
    sas_expires_at: null,
    sas_permissions: '',
    endpoint_override: 'https://minio.storage.svc:9000',
    bucket: 'olympos-backups',
    region: 'us-east-1',
    path_style: true,
    access_key_id: 'olympos-backup',
    secret_key_source: 'keyvault_ref',
    secret_key_ref: 'kv://kv-platform-weu/minio-secret-key',
    last_test_at: iso(5 * H),
    last_test_ok: true,
    last_test: {
      ok: true,
      can_delete: false,
      steps: [
        { name: 'endpoint', ok: true, detail: 'minio.storage.svc:9000 · TLS ok' },
        { name: 'write', ok: true, detail: '' },
        { name: 'read', ok: true, detail: '' },
        { name: 'tag', ok: true, detail: '' },
        { name: 'delete_refused', ok: true, detail: 'DeleteObject returned 403 AccessDenied' },
      ],
      sas: null,
    },
    jobs: 1,
  },
  {
    id: uuid(),
    name: 'nas-factory',
    kind: 'nfs',
    account: '',
    container: '',
    prefix: '',
    auth: 'none',
    sas_source: '',
    sas_ref: '',
    sas_expires_at: null,
    sas_permissions: '',
    endpoint_override: '',
    path: '/var/lib/olympos/nfs/backup-nas/olympos',
    last_test_at: iso(26 * H),
    last_test_ok: true,
    last_test: {
      ok: true,
      can_delete: true,
      steps: [
        { name: 'path', ok: true, detail: 'directory exists, writable' },
        { name: 'write', ok: true, detail: '' },
        { name: 'read', ok: true, detail: '' },
        { name: 'delete_refused', ok: false, detail: 'the server can delete files here' },
      ],
      sas: null,
    },
    jobs: 0,
  },
];

/** Volumes mounted into the server for NFS destinations (Helm value nfsMounts). */
export const destinationMounts: DestinationMount[] = [
  { name: 'backup-nas', path: '/var/lib/olympos/nfs/backup-nas', writable: true },
  { name: 'archive', path: '/var/lib/olympos/nfs/archive', writable: false },
];

export const channels: Channel[] = [
  { id: uuid(), kind: 'slack', name: '#infra-backups', slack_channel_id: 'C0123ABCD', routes: ['backup.failed', 'backup.missed'], created_at: iso(60 * D) },
  { id: uuid(), kind: 'slack', name: '#vault-approvals', slack_channel_id: 'C0456EFGH', routes: ['cr.opened', 'cr.expired', 'vault.unmanaged_write'], created_at: iso(60 * D) },
  { id: uuid(), kind: 'slack', name: '#infra-audit', slack_channel_id: 'C0789IJKL', routes: ['audit.new_findings', 'vuln.critical'], created_at: iso(60 * D) },
  { id: uuid(), kind: 'slack', name: '#platform-access', slack_channel_id: 'C0ABCMNOP', routes: ['grant.changed', 'grant.stale', 'agent.offline', 'sas.expiring'], created_at: iso(60 * D) },
];

export const catalog: Routes['catalog'] = [
  { event_type: 'backup.failed', description: 'A backup run failed', opt_in: false },
  { event_type: 'backup.missed', description: 'A scheduled run did not start', opt_in: false },
  { event_type: 'backup.succeeded', description: 'A backup run succeeded (noisy)', opt_in: true },
  { event_type: 'cr.opened', description: 'A change request waits for approval (link only)', opt_in: false },
  { event_type: 'cr.approved', description: 'A change request was approved and applied', opt_in: false },
  { event_type: 'cr.rejected', description: 'A change request was rejected', opt_in: false },
  { event_type: 'cr.expired', description: 'A change request expired without a decision', opt_in: false },
  { event_type: 'cr.failed', description: 'Applying an approved change failed', opt_in: false },
  { event_type: 'vault.unmanaged_write', description: 'A secret changed outside Olympos (drift)', opt_in: false },
  { event_type: 'audit.new_findings', description: 'An audit run found new issues', opt_in: false },
  { event_type: 'vuln.critical', description: 'New critical CVE in a running image', opt_in: false },
  { event_type: 'agent.offline', description: 'An agent stopped reporting', opt_in: false },
  { event_type: 'agent.online', description: 'An agent is back online', opt_in: false },
  { event_type: 'grant.changed', description: 'Access was granted or revoked', opt_in: false },
  { event_type: 'grant.stale', description: 'A grant holder was disabled in Entra ID', opt_in: false },
  { event_type: 'sas.expiring', description: 'A destination SAS token expires in 14 or 3 days', opt_in: false },
];

function run(p: Partial<BackupRun> & Pick<BackupRun, 'job_id' | 'target_service' | 'cluster_name' | 'engine'>): BackupRun {
  return {
    id: uuid(),
    trigger: 'schedule',
    status: 'succeeded',
    scheduled_for: null,
    tier: 'daily',
    started_at: iso(H),
    finished_at: iso(H - 11_000),
    bytes: 42e6,
    wire_bytes: 42e6,
    blob_path: '',
    sha256: '',
    error: '',
    destination_name: 'blob-weu-backups',
    ...p,
  };
}

function job(t: Target, p: Partial<BackupJob>): BackupJob {
  return {
    id: uuid(),
    target: t,
    engine: t.engine,
    credential: { id: uuid(), source: 'keyvault_ref', ref: `kv://kv-platform-weu/${t.service}-backup`, username: 'backup_ro' },
    destination: { id: destinations[0].id, name: destinations[0].name },
    engine_options: {},
    cron: '0 2 * * *',
    timezone: 'Europe/Istanbul',
    retention: { daily: 14, weekly: 8, monthly: 12 },
    enabled: true,
    paused_reason: '',
    notify_channel_id: channels[0].id,
    notify_on_success: false,
    next_run_at: isoIn(9 * H),
    last_run: null,
    estimated_monthly_bytes: 93 * GB,
    estimated_monthly_cost: null,
    created_at: iso(40 * D),
    ...p,
  };
}

export const jobs: BackupJob[] = [
  job(tByService('billing-pg'), { engine_options: { databases: ['billing'], globals: true } }),
  job(tByService('openbao'), { notify_on_success: true, cron: '0 */6 * * *', next_run_at: isoIn(2 * H), estimated_monthly_bytes: 5 * GB, credential: { id: uuid(), source: 'keyvault_ref', ref: 'kv://kv-platform-weu/olympos-approle', username: 'approle' } }),
  job(tByService('metrics-ch'), { cron: '30 3 * * *', destination: { id: destinations[1].id, name: destinations[1].name }, estimated_monthly_bytes: 74 * GB, estimated_monthly_cost: 6.66 }),
];
const [jBilling, jBao, jMetrics] = jobs;

export const runs: BackupRun[] = [
  run({ job_id: jBao.id, target_service: 'openbao', cluster_name: 'prod-aks-weu-01', engine: 'vault', started_at: iso(2 * H), finished_at: iso(2 * H - 11_000), bytes: 42e6, wire_bytes: 42e6 }),
  run({ job_id: jMetrics.id, target_service: 'metrics-ch', cluster_name: 'oke-fra-erp', engine: 'clickhouse', status: 'failed', error: 'SAS expired', started_at: iso(6.5 * H), finished_at: iso(6.5 * H - 252_000), bytes: 0, wire_bytes: 0, destination_name: 'blob-neu-dr' }),
  run({ job_id: jBilling.id, target_service: 'billing-pg', cluster_name: 'prod-aks-weu-02', engine: 'postgresql', started_at: iso(8 * H), finished_at: iso(8 * H - 400_000), bytes: 3.1e9, wire_bytes: 3.1e9 }),
  run({ job_id: jBao.id, target_service: 'openbao', cluster_name: 'prod-aks-weu-01', engine: 'vault', started_at: iso(8 * H), finished_at: iso(8 * H - 10_000), bytes: 41e6, wire_bytes: 41e6 }),
  run({ job_id: jBilling.id, target_service: 'billing-pg', cluster_name: 'prod-aks-weu-02', engine: 'postgresql', started_at: iso(32 * H), finished_at: iso(32 * H - 395_000), bytes: 3.08e9, wire_bytes: 3.08e9, tier: 'weekly' }),
  run({ job_id: jMetrics.id, target_service: 'metrics-ch', cluster_name: 'oke-fra-erp', engine: 'clickhouse', started_at: iso(30.5 * H), finished_at: iso(30.5 * H - 610_000), bytes: 18e9, wire_bytes: 2.4e9, destination_name: 'blob-neu-dr' }),
];
jBilling.last_run = runs[2];
jBao.last_run = runs[0];
jMetrics.last_run = runs[1];
// two weeks of history so the Runs tab pages
for (let i = 0; i < 84; i++) {
  const j = jobs[i % 3];
  const ago = 2 * D + i * 4 * H;
  const failed = i % 17 === 5;
  runs.push(
    run({
      job_id: j.id,
      target_service: j.target.service,
      cluster_name: j.target.cluster_name,
      engine: j.engine,
      status: failed ? 'failed' : i % 29 === 11 ? 'missed' : 'succeeded',
      error: failed ? 'connection reset by agent tunnel' : '',
      started_at: iso(ago),
      finished_at: iso(ago - (j.engine === 'postgresql' ? 400_000 : 12_000)),
      bytes: failed ? 0 : j.engine === 'postgresql' ? 3.05e9 + i * 1e6 : j.engine === 'vault' ? 41e6 : 17.5e9,
      wire_bytes: failed ? 0 : j.engine === 'clickhouse' ? 2.3e9 : j.engine === 'postgresql' ? 3.05e9 : 41e6,
      tier: i % 7 === 0 ? 'weekly' : 'daily',
      destination_name: j.destination.name,
    }),
  );
}

// ------------------------------------------------------------ vaults
export const vaults: Vault[] = [
  {
    id: uuid(),
    target: tByService('vault'),
    provider: 'hashicorp',
    version: '1.18.2',
    status: 'configured',
    kv_mounts: [
      { path: 'kv/', version: 2, managed: true, description: 'application secrets' },
      { path: 'legacy/', version: 1, managed: false, description: 'old integrations' },
    ],
    configured_by_name: 'yigit@contoso.com',
    configured_at: iso(30 * D),
    secret_id_rotated_at: iso(6 * D),
    last_index_at: iso(4 * MIN),
    secrets: 14,
    drift: 0,
    last_error: '',
  },
  {
    id: uuid(),
    target: tByService('openbao'),
    provider: 'openbao',
    version: '2.1.0',
    status: 'configured',
    kv_mounts: [{ path: 'kv/', version: 2, managed: true, description: '' }],
    configured_by_name: 'yigit@contoso.com',
    configured_at: iso(28 * D),
    secret_id_rotated_at: iso(3 * D),
    last_index_at: iso(7 * MIN),
    secrets: 9,
    drift: 1,
    last_error: '',
  },
  {
    id: uuid(),
    target: tByService('vault-dev'),
    provider: 'hashicorp',
    version: '1.17.6',
    status: 'discovered',
    kv_mounts: [],
    configured_by_name: '',
    configured_at: null,
    secret_id_rotated_at: null,
    last_index_at: null,
    secrets: 0,
    drift: 0,
    last_error: '',
  },
];

// 12 clusters × 1–3 vaults: generated, so the Vaults list can be tried at fleet size.
const VAULT_NAMES: [string, 'hashicorp' | 'openbao', string][] = [
  ['vault', 'hashicorp', 'vault'],
  ['openbao', 'openbao', 'security'],
  ['vault-payments', 'hashicorp', 'payments'],
  ['bao-platform', 'openbao', 'platform'],
  ['vault-ci', 'hashicorp', 'ci'],
];
const PATH_POOL = ['apps/orders/db', 'apps/orders/api', 'apps/billing/stripe', 'apps/billing/db', 'apps/checkout/redis', 'platform/ci', 'platform/ingress', 'platform/registry', 'shared/smtp', 'shared/sentry', 'teams/data/warehouse', 'teams/ml/feature-store', 'teams/web/cdn', 'erp/sap'];
const KEY_POOL = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'API_KEY', 'API_SECRET', 'TOKEN', 'TLS_CERT', 'TLS_KEY', 'WEBHOOK_SECRET', 'DSN'];
const generatedSecrets: Record<string, { path: string; keys: string[]; version: number; ago: number; managed: boolean }[]> = {};
clusters.forEach((c, ci) => {
  if (c.status === 'pending') return;
  const want = 1 + (ci % 3);
  const have = vaults.filter((v) => v.target.cluster_id === c.id).length;
  let made = 0;
  for (const [name, provider, ns] of VAULT_NAMES) {
    if (have + made >= want) break;
    if (vaults.some((v) => v.target.cluster_id === c.id && v.target.service === name) || targets.some((t) => t.cluster_id === c.id && t.service === name)) continue;
    const t = target({ service: name, namespace: ns, engine: '', vault_provider: provider, detected_version: provider === 'openbao' ? '2.1' : '1.18', port: 8200, tls_server_name: `${name}.${ns}.svc`, status: 'configured' }, c.name);
    targets.push(t);
    const offline = c.status === 'offline';
    const status: Vault['status'] = offline ? 'error' : (ci + made) % 5 === 3 ? 'discovered' : 'configured';
    const v: Vault = {
      id: uuid(),
      target: t,
      provider,
      version: provider === 'openbao' ? `2.1.${ci % 3}` : `1.18.${ci % 4}`,
      status,
      kv_mounts: status === 'discovered' ? [] : [{ path: ci % 2 ? 'secret/' : 'kv/', version: 2, managed: true, description: '' }],
      configured_by_name: status === 'discovered' ? '' : 'yigit@contoso.com',
      configured_at: status === 'discovered' ? null : iso((20 + ci) * D),
      secret_id_rotated_at: status === 'discovered' ? null : iso((ci % 6) * D),
      last_index_at: status === 'configured' ? iso((3 + ci) * MIN) : status === 'error' ? iso(2 * H) : null,
      secrets: 0,
      drift: ci % 6 === 1 ? 1 : 0,
      last_error: status === 'error' ? 'index refresh failed: agent onprem-ist-lab is offline (no heartbeat for 2 h)' : '',
    };
    vaults.push(v);
    if (status !== 'discovered') {
      const n = 3 + Math.floor(rnd() * 6);
      const paths = [...PATH_POOL].sort(() => rnd() - 0.5).slice(0, n);
      generatedSecrets[v.id] = paths.map((path) => ({ path, keys: [...KEY_POOL].sort(() => rnd() - 0.5).slice(0, 2 + Math.floor(rnd() * 4)), version: 1 + Math.floor(rnd() * 9), ago: Math.floor(1 + rnd() * 60) * D, managed: rnd() > 0.08 }));
      v.secrets = paths.length;
    }
    made++;
  }
});
// the backup candidate bao-retail is a discovered (not yet configured) OpenBao
vaults.push({
  id: uuid(),
  target: tByService('bao-retail'),
  provider: 'openbao',
  version: '2.2.0',
  status: 'discovered',
  kv_mounts: [],
  configured_by_name: '',
  configured_at: null,
  secret_id_rotated_at: null,
  last_index_at: null,
  secrets: 0,
  drift: 0,
  last_error: '',
});
for (const v of vaults) v.cluster_labels = { ...(clusters.find((c) => c.id === v.target.cluster_id)?.labels ?? {}) };

function sec(mount: string, path: string, keys: string[], version: number, updatedAgo: number, managed = true): SecretDetail {
  return {
    mount,
    path,
    keys,
    current_version: version,
    updated_time: iso(updatedAgo),
    managed,
    pending_change_requests: 0,
    updated_by_name: managed ? 'selin@contoso.com' : 'outside Olympos',
    versions: Array.from({ length: version }, (_, i) => ({
      version: i + 1,
      created_time: iso(updatedAgo + (version - i - 1) * 21 * D),
      deletion_time: '',
      destroyed: false,
      by_olympos: managed || i < version - 1,
      keys: Math.max(1, keys.length - (i < 2 ? 1 : 0)),
    })),
    key_info: keys.map((k, i) => ({ key: k, version: Math.max(1, version - (i % 3)), updated_time: iso(updatedAgo + (i % 3) * 14 * D), pending_cr_id: null, last_cr_id: null })),
  };
}

export const secrets: Record<string, SecretDetail[]> = {
  [vaults[0].id]: [
    sec('kv/', 'erp/payments', ['DB_HOST', 'DB_PASSWORD', 'PSP_API_KEY', 'PSP_WEBHOOK_SECRET', 'PSP_LEGACY_TOKEN', 'SFTP_PRIVATE_KEY'], 7, 3 * D),
    sec('kv/', 'erp/integrations', ['SAP_USER', 'SAP_PASSWORD', 'EDI_TOKEN'], 4, 20 * D),
    sec('kv/', 'platform/ci', ['GHCR_TOKEN', 'COSIGN_KEY'], 3, 9 * D),
    sec('kv/', 'shared/smtp', ['SMTP_HOST', 'SMTP_PASSWORD'], 2, 60 * D),
  ],
  [vaults[1].id]: [
    sec('kv/', 'platform/ci', ['RUNNER_TOKEN', 'NPM_TOKEN'], 12, 1 * D, false),
    sec('kv/', 'platform/ingress', ['TLS_KEY', 'TLS_CERT'], 5, 30 * D),
  ],
};
// key metadata to match the mockup
{
  const p = secrets[vaults[0].id][0];
  const ki = p.key_info!;
  ki[0].version = 5;
  ki[0].updated_time = iso(47 * D);
  ki[1].version = 7;
  ki[1].updated_time = iso(3 * D);
  ki[2].version = 6;
  ki[2].updated_time = iso(17 * D);
  ki[3].version = 6;
  ki[3].updated_time = iso(17 * D);
  ki[4].version = 2;
  ki[4].updated_time = iso(220 * D);
  ki[5].version = 3;
  ki[5].updated_time = iso(89 * D);
}

for (const [vid, list] of Object.entries(generatedSecrets)) {
  const v = vaults.find((x) => x.id === vid)!;
  secrets[vid] = list.map((g) => sec(v.kv_mounts[0].path, g.path, g.keys, g.version, g.ago, g.managed));
}

export function summaries(vaultId: string): SecretSummary[] {
  return (secrets[vaultId] ?? []).map((s) => ({ mount: s.mount, path: s.path, keys: s.keys.length, current_version: s.current_version, updated_time: s.updated_time, managed: s.managed }));
}

let crSeq = 142;
export const nextCrNumber = () => `CR-0${++crSeq}`;

function cr(p: Partial<ChangeRequest> & Pick<ChangeRequest, 'maker' | 'items'>, v: Vault): ChangeRequest {
  return {
    id: uuid(),
    vault: { id: v.id, name: v.target.service, cluster_name: v.target.cluster_name, provider: v.provider, version: v.version },
    checker: null,
    justification: '',
    status: 'pending',
    created_at: iso(5 * H),
    expires_at: isoIn(68 * H),
    decided_at: null,
    decision_comment: '',
    applied_at: null,
    failure: '',
    can_approve: true,
    approve_disabled_reason: '',
    can_cancel: false,
    events: [],
    eligible_approvers: 3,
    ...p,
  };
}

export const changeRequests: ChangeRequest[] = [
  cr(
    {
      number: 'CR-0142',
      maker: people.selin,
      justification: 'PSP provider rotated API keys after their incident notice. Old key is revoked on Nov 20 (ticket OPS-2207).',
      created_at: iso(4 * H),
      expires_at: isoIn(68 * H),
      items: [{ id: uuid(), mount: 'kv/', path: 'erp/payments', key: 'PSP_API_KEY', op: 'replace', base_version: 7, versions: [], fingerprint: 'hm:51d0·8a2e·c7f9' }],
      events: [
        { at: iso(4 * H), kind: 'opened', actor_name: 'selin@contoso.com', details: { sealed_with: 'kv-platform-weu/cr-key' } },
        { at: iso(4 * H - 2000), kind: 'notified', actor_name: 'system', details: { channel: '#vault-approvals' } },
      ],
    },
    vaults[0],
  ),
  cr(
    {
      number: 'CR-0141',
      maker: people.mert,
      justification: 'New CI runner registration and npm automation token; old runner token retired (OPS-2199).',
      created_at: iso(21 * H),
      expires_at: isoIn(51 * H),
      items: [
        { id: uuid(), mount: 'kv/', path: 'platform/ci', key: 'RUNNER_TOKEN_V2', op: 'create', base_version: 12, versions: [], fingerprint: 'hm:0b7c·e1d4·992a' },
        { id: uuid(), mount: 'kv/', path: 'platform/ci', key: 'NPM_AUTOMATION', op: 'create', base_version: 12, versions: [], fingerprint: 'hm:c3a9·5f10·4e8b' },
        { id: uuid(), mount: 'kv/', path: 'platform/ci', key: 'RUNNER_TOKEN', op: 'delete', base_version: 12, versions: [], fingerprint: '' },
      ],
      events: [{ at: iso(21 * H), kind: 'opened', actor_name: 'mert@contoso.com', details: {} }],
    },
    vaults[1],
  ),
  cr(
    {
      number: 'CR-0140',
      maker: people.yigit,
      justification: 'Rotate ERP database password after DBA handover.',
      created_at: iso(26 * H),
      expires_at: isoIn(46 * H),
      can_approve: false,
      approve_disabled_reason: 'You opened this request. Another approver must decide.',
      can_cancel: true,
      items: [{ id: uuid(), mount: 'kv/', path: 'erp/payments', key: 'DB_PASSWORD', op: 'replace', base_version: 7, versions: [], fingerprint: 'hm:9f3a·71c2·e04b' }],
      events: [{ at: iso(26 * H), kind: 'opened', actor_name: 'yigit@contoso.com', details: {} }],
    },
    vaults[0],
  ),
  cr(
    {
      number: 'CR-0139',
      maker: people.selin,
      checker: people.yigit,
      status: 'applied',
      can_approve: false,
      justification: 'Quarterly DB password rotation.',
      created_at: iso(3 * D + 2 * H),
      decided_at: iso(3 * D),
      applied_at: iso(3 * D),
      decision_comment: 'Verified fingerprint with Selin on a call.',
      items: [{ id: uuid(), mount: 'kv/', path: 'erp/payments', key: 'DB_PASSWORD', op: 'replace', base_version: 6, versions: [], fingerprint: 'hm:2c4e·aa01·7d93' }],
      events: [
        { at: iso(3 * D + 2 * H), kind: 'opened', actor_name: 'selin@contoso.com', details: {} },
        { at: iso(3 * D), kind: 'approved', actor_name: 'yigit@contoso.com', details: { comment: 'Verified fingerprint with Selin on a call.' } },
        { at: iso(3 * D - 1000), kind: 'applied', actor_name: 'system', details: { version: 7 } },
      ],
    },
    vaults[0],
  ),
];
{
  const ki = secrets[vaults[0].id][0].key_info!;
  ki[2].pending_cr_id = changeRequests[0].id;
  ki[2].pending_cr_label = 'CR-0142';
  ki[1].pending_cr_id = changeRequests[2].id;
  ki[1].pending_cr_label = 'CR-0140';
  ki[1].last_cr_id = changeRequests[3].id;
  ki[1].last_cr_label = 'CR-0139';
  secrets[vaults[0].id][0].pending_change_requests = 2;
}

// ------------------------------------------------------------ audit
const ksSched = uuid();
const polSched = uuid();
const kbSched = uuid();
function arun(p: Partial<AuditRun> & Pick<AuditRun, 'tool'>): AuditRun {
  return { id: uuid(), schedule_id: null, cluster_id: '', cluster_name: 'all clusters', status: 'succeeded', started_at: iso(H), finished_at: iso(H - 300_000), score: null, new_findings: 0, resolved_findings: 0, error: '', ...p };
}

/** Kubescape 4 output of a run whose schedule asked for a CIS framework the binary no longer ships. */
export const KUBESCAPE_FAILED_LOG = [
  `{"level":"info","ts":"${iso(10 * H)}","msg":"Kubescape scanner initializing...","version":"v4.0.2"}`,
  `{"level":"info","ts":"${iso(10 * H - 1000)}","msg":"Loading kubeconfig","server":"https://127.0.0.1:43117","context":"olympos-proxy"}`,
  `{"level":"info","ts":"${iso(10 * H - 2000)}","msg":"Downloading/Loading framework","framework":"nsa"}`,
  `{"level":"info","ts":"${iso(10 * H - 3000)}","msg":"Downloading/Loading framework","framework":"mitre"}`,
  `{"level":"warn","ts":"${iso(10 * H - 4000)}","msg":"failed to load framework from the local cache, trying the API","framework":"cis-v1.23-t1.0.1"}`,
  `{"level":"error","ts":"${iso(10 * H - 6000)}","msg":"failed to download framework","framework":"cis-v1.23-t1.0.1","error":"framework 'cis-v1.23-t1.0.1' not found","attempt":3}`,
  `{"level":"info","ts":"${iso(10 * H - 6100)}","msg":"available CIS frameworks","frameworks":"cis-aks-t1.8.0, cis-eks-t1.8.0, cis-v1.12.0"}`,
  "Error: framework 'cis-v1.23-t1.0.1' not found",
].join('\n');

export const auditRuns: AuditRun[] = [];
{
  const live = clusters.filter((c) => c.status !== 'pending');
  const failedIdx = live.findIndex((c) => c.name === 'onprem-factory-01');
  live.forEach((c, ci) => {
    const order = ci === failedIdx ? 0 : ci + 1;
    for (let k = 0; k < 4; k++) {
      const start = (10 + 24 * k) * H + order * 4 * MIN;
      const failed = ci === failedIdx && k === 0;
      const offline = c.status === 'offline' && k === 0;
      // an older run stored before the server kept a short reason: the whole stderr ended up in `error`
      const legacy = c.name === 'cce-ist-retail' && k === 1;
      const score = 68 + ((ci * 7.3 + k * 1.7) % 26);
      auditRuns.push(
        arun({
          tool: 'kubescape',
          schedule_id: ksSched,
          cluster_id: c.id,
          cluster_name: c.name,
          status: failed || offline || legacy ? 'failed' : 'succeeded',
          started_at: iso(start),
          finished_at: iso(start - (failed ? 7_000 : 400_000)),
          score: failed || offline || legacy ? null : Math.round(score * 10) / 10,
          new_findings: failed || offline || legacy ? 0 : (ci + k) % 4 === 0 ? 2 + (ci % 3) : 0,
          resolved_findings: failed || offline || legacy ? 0 : (ci + k) % 5 === 1 ? 1 : 0,
          error: failed ? "framework 'cis-v1.23-t1.0.1' not found" : offline ? 'agent_offline' : legacy ? `kubescape failed: exit status 1: ${KUBESCAPE_FAILED_LOG.split('\n').join(' ')}` : '',
          log: failed || legacy ? KUBESCAPE_FAILED_LOG : offline ? 'agent onprem-ist-lab is offline (last seen 2 h ago): the read-only API proxy is not reachable, kubescape was not started.' : '',
          details: { trigger: k === 0 && failed ? 'schedule' : 'schedule', frameworks: ['nsa', 'cis', 'mitre'] },
        }),
      );
    }
    if (c.labels.env === 'prod') {
      auditRuns.push(arun({ tool: 'polaris', schedule_id: polSched, cluster_id: c.id, cluster_name: c.name, started_at: iso(2 * D + order * MIN), finished_at: iso(2 * D + order * MIN - 60_000), score: Math.round((84 + ((ci * 3.1) % 14)) * 10) / 10, new_findings: ci % 4 === 1 ? 3 : 0 }));
    }
    if (c.bench_enabled) {
      const managed = c.provider !== 'onprem';
      const bench = c.provider === 'azure' ? 'aks-1.7' : c.provider === 'aws' ? 'eks-1.5' : c.provider === 'gcp' ? 'gke-1.6' : 'cis-1.9';
      const nodes = Array.from({ length: Math.min(3, c.nodes) }, (_, n) => ({
        node_name: c.provider === 'azure' ? `aks-sys-${17402 + ci}-vmss00000${n}` : c.provider === 'aws' ? `ip-10-${20 + ci}-4-${17 + n}` : `${c.name.split('-').slice(-2).join('-')}-${n === 0 && !managed ? 'cp' : 'w'}${n + 1}`,
        cluster_name: c.name,
        benchmark: !managed ? (n === 0 ? `${bench} master` : `${bench} node`) : bench,
        state: 'done',
        pass: 39 + ((ci + n) % 5) * 4,
        fail: (ci + n) % 3,
        warn: 5 + ((ci + n) % 4),
        control_plane_na: managed,
        message: '',
        duration_s: 36 + ((ci * 7 + n * 3) % 20),
      }));
      auditRuns.push(arun({ tool: 'kube-bench', schedule_id: kbSched, cluster_id: c.id, cluster_name: c.name, started_at: iso(3 * D + order * MIN), finished_at: iso(3 * D + order * MIN - 120_000), score: Math.round((nodes.reduce((s, x) => s + x.pass, 0) / nodes.reduce((s, x) => s + x.pass + x.fail, 0)) * 1000) / 10, resolved_findings: ci % 3 === 0 ? 2 : 0, bench_nodes: nodes }));
    }
  });
  auditRuns.sort((x, y) => (y.started_at ?? '').localeCompare(x.started_at ?? ''));
}
const latest = (tool: string) => auditRuns.find((r) => r.tool === tool) ?? null;
export const auditSchedules: AuditSchedule[] = [
  { id: ksSched, tool: 'kubescape', frameworks: ['nsa', 'cis', 'mitre'], scope_selector: 'all', cron: '0 4 * * *', timezone: 'Europe/Istanbul', enabled: true, notify_channel_id: channels[2].id, next_run_at: isoIn(14 * H), clusters: 11, last_run: latest('kubescape') },
  { id: polSched, tool: 'polaris', frameworks: [], scope_selector: 'env=prod', cron: '0 5 * * 1', timezone: 'Europe/Istanbul', enabled: true, notify_channel_id: channels[2].id, next_run_at: isoIn(5 * D), clusters: 9, last_run: latest('polaris') },
  { id: kbSched, tool: 'kube-bench', frameworks: [], scope_selector: 'all', cron: '0 3 * * 0', timezone: 'Europe/Istanbul', enabled: true, notify_channel_id: channels[2].id, next_run_at: isoIn(4 * D), clusters: 9, last_run: latest('kube-bench') },
];

function finding(p: Partial<Finding> & Pick<Finding, 'control_id' | 'title' | 'cluster_name' | 'resource_ref' | 'severity'>): Finding {
  return { id: uuid(), source: 'kubescape', cluster_id: byName(p.cluster_name).id, details: {}, status: 'open', first_seen_at: iso(10 * H), last_seen_at: iso(10 * H), resolved_at: null, ...p };
}
export const findings: Finding[] = [
  finding({ control_id: 'C-0057', title: 'Privileged container', severity: 'high', cluster_name: 'eks-fra-data', resource_ref: 'analytics/deploy/spark-driver' }),
  finding({ control_id: 'C-0017', title: 'Immutable root filesystem', severity: 'medium', cluster_name: 'prod-aks-weu-02', resource_ref: 'billing/deploy/invoice-api' }),
  finding({ control_id: 'C-0034', title: 'Automount SA token', severity: 'medium', cluster_name: 'oke-fra-erp', resource_ref: 'erp/sts/report-gen' }),
  finding({ source: 'transfer', control_id: 'transfer.compressed_mode', title: 'Backups use compressed transfer mode (agent can see backup data)', severity: 'medium', cluster_name: 'eks-fra-data', resource_ref: 'cluster/eks-fra-data', first_seen_at: iso(20 * D) }),
  finding({ source: 'vault-drift', control_id: 'vault.unmanaged_write', title: 'Unmanaged change: kv/platform/ci v12', severity: 'high', cluster_name: 'prod-aks-weu-01', resource_ref: 'openbao/kv/platform/ci', first_seen_at: iso(9 * H) }),
];
{
  const CONTROLS: [string, string, Finding['severity'], string][] = [
    ['C-0016', 'Allow privilege escalation', 'high', 'kubescape'],
    ['C-0013', 'Non-root containers', 'medium', 'kubescape'],
    ['C-0270', 'Ensure CPU limits are set', 'high', 'kubescape'],
    ['C-0030', 'Ingress and Egress blocked', 'medium', 'kubescape'],
    ['C-0041', 'HostNetwork access', 'critical', 'kubescape'],
    ['C-0046', 'Insecure capabilities', 'high', 'kubescape'],
    ['C-0076', 'Label usage for resources', 'low', 'kubescape'],
    ['runAsRootAllowed', 'Should not be allowed to run as root', 'medium', 'polaris'],
    ['livenessProbeMissing', 'Liveness probe should be configured', 'low', 'polaris'],
    ['cis-1.9:4.2.6', 'Ensure that the --protect-kernel-defaults argument is set to true', 'high', 'kube-bench'],
  ];
  const NS = ['apps', 'monitoring', 'jobs', 'default', 'ingress-nginx'];
  const WL = ['deploy/api', 'deploy/web', 'sts/cache', 'ds/node-agent', 'cronjob/cleanup'];
  clusters.forEach((c, ci) => {
    if (c.status === 'pending') return;
    const n = 2 + ((ci * 5) % 7);
    for (let i = 0; i < n; i++) {
      const [id, title, sev, src] = CONTROLS[(ci * 3 + i) % CONTROLS.length];
      if (src === 'kube-bench' && !c.bench_enabled) continue;
      if (src === 'polaris' && c.labels.env !== 'prod') continue;
      findings.push(finding({ source: src, control_id: id, title, severity: sev, cluster_name: c.name, resource_ref: src === 'kube-bench' ? `node/${c.name}-w${i + 1}` : `${NS[(ci + i) % NS.length]}/${WL[(ci * 2 + i) % WL.length]}`, first_seen_at: iso((10 + 24 * (i % 3)) * H) }));
    }
  });
}

// ------------------------------------------------------------ security
export const images: Image[] = [
  { digest: 'sha256:7c1e4b2f9a0d3c5e7f1a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c09ab', repo: 'acr.contoso.io/erp/payments-api', tags: ['2.14.1'], clusters: 2, workloads: 6, critical: 3, high: 11, medium: 20, low: 31, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), fixable: 9, registry: 'acr.contoso.io' },
  { digest: 'sha256:a40f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b771c', repo: 'docker.io/bitnami/redis', tags: ['7.2.4'], clusters: 5, workloads: 9, critical: 2, high: 6, medium: 9, low: 14, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), fixable: 4, registry: '' },
  { digest: 'sha256:1b9d3e5f7a9c1e3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7be2f0', repo: 'quay.io/legacy/report-gen', tags: ['0.9'], clusters: 1, workloads: 1, critical: 1, high: 14, medium: 22, low: 9, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), fixable: 0, registry: 'quay.io/legacy/*' },
  { digest: 'sha256:c33a5d7f9b1d3f5a7c9e1f3b5d7a9c1e3f5b7d9a1c3e5f7b9d1a3c5e7f9b5d12', repo: 'ghcr.io/contoso/ingest-worker', tags: ['1.8.0'], clusters: 3, workloads: 12, critical: 1, high: 4, medium: 8, low: 12, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), fixable: 2, registry: 'ghcr.io/contoso/*' },
  { digest: 'sha256:e81f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f', repo: 'harbor.factory.local/mes/line-agent', tags: ['3.2'], clusters: 1, workloads: 4, critical: 0, high: 0, medium: 0, low: 0, scan_status: 'missing_credential', last_scanned_at: null, registry: '' },
  { digest: 'sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f0f1e2d3c4b5a69788796a5b4c3d2e1f00', repo: 'acr.contoso.io/platform/olympos-agent', tags: ['0.4.2'], clusters: 7, workloads: 7, critical: 0, high: 0, medium: 1, low: 2, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), registry: 'acr.contoso.io' },
];
// ...and a fleet-sized list (>= 120) with every scan state, incl. failed and unavailable.
{
  const REPOS = [
    ['docker.io/library/postgres', ['16-alpine', '15.8', '17.2']],
    ['docker.io/library/redis', ['7.4', '7.2.5']],
    ['docker.io/library/nginx', ['1.27', '1.26-alpine']],
    ['quay.io/prometheus/prometheus', ['v2.54.1', 'v3.0.1']],
    ['quay.io/prometheus/node-exporter', ['v1.8.2']],
    ['registry.k8s.io/ingress-nginx/controller', ['v1.11.3']],
    ['registry.k8s.io/coredns/coredns', ['v1.11.3']],
    ['registry.k8s.io/kube-proxy', ['v1.31.3', 'v1.32.2']],
    ['ghcr.io/contoso/checkout', ['3.1.0', '3.0.9']],
    ['ghcr.io/contoso/catalog', ['1.22.4']],
    ['ghcr.io/contoso/search', ['0.9.12']],
    ['acr.contoso.io/erp/invoice-api', ['4.2.0', '4.1.7']],
    ['acr.contoso.io/erp/report-gen', ['2.0.1']],
    ['acr.contoso.io/platform/olympos-server', ['0.4.2']],
    ['docker.io/grafana/grafana', ['11.3.0']],
    ['docker.io/grafana/loki', ['3.2.1']],
    ['docker.io/bitnami/kafka', ['3.8.0']],
    ['docker.io/clickhouse/clickhouse-server', ['24.8', '24.3']],
    ['docker.io/hashicorp/vault', ['1.18.2', '1.17.6']],
    ['docker.io/openbao/openbao', ['2.1.0']],
    ['mcr.microsoft.com/oss/kubernetes/azure-cni', ['v1.6.13']],
    ['public.ecr.aws/eks/aws-load-balancer-controller', ['v2.9.0']],
    ['harbor.factory.local/mes/plc-gateway', ['1.4']],
    ['harbor.factory.local/mes/scada-ui', ['2.0']],
    ['docker.io/kindest/kindnetd', ['v20241108-5c6d2daf']],
    ['docker.io/kindest/local-path-provisioner', ['v20241108-5c6d2daf']],
    ['localhost/contoso/debug-shell', ['dev']],
  ] as [string, string[]][];
  const ERRORS = [
    'GET https://ghcr.io/v2/contoso/checkout/manifests/sha256:4f1a: TOOMANYREQUESTS: rate limit exceeded (retry after 600 s)',
    'trivy: context deadline exceeded while downloading the vulnerability DB (mirror.gcr.io unreachable from the server)',
    'registry acr.contoso.io answered 503 Service Unavailable\nrequest id 7f2c1d9e, retried automatically',
    'layer sha256:4f1a could not be extracted: unexpected EOF (image is 4.1 GB, scan timed out after 10 min)',
  ];
  let k = 0;
  for (const [repo, tags] of REPOS) {
    for (const tag of tags) {
      const local = repo.includes('kindest') || repo.startsWith('localhost');
      for (let variant = 0; variant < (local ? 1 : 4); variant++) {
        k++;
        const harbor = repo.startsWith('harbor.');
        const r = rnd();
        let st: Image['scan_status'] = local ? 'unavailable' : harbor ? 'missing_credential' : r < 0.06 ? 'failed' : r < 0.09 ? 'pending' : r < 0.1 ? 'scanning' : 'scanned';
        if (k % 23 === 4 && !local && !harbor) st = 'failed';
        const crit = st === 'scanned' ? (rnd() < 0.25 ? Math.floor(rnd() * 5) + 1 : 0) : 0;
        const high = st === 'scanned' ? Math.floor(rnd() * 30) : 0;
        const attempts = st === 'failed' ? 1 + (k % 5) : 0;
        images.push({
          digest: `sha256:${hex(64)}`,
          repo,
          tags: variant === 0 ? [tag] : [],
          clusters: 1 + Math.floor(rnd() * 6),
          workloads: 1 + Math.floor(rnd() * 14),
          critical: crit,
          high,
          medium: st === 'scanned' ? Math.floor(rnd() * 40) : 0,
          low: st === 'scanned' ? Math.floor(rnd() * 50) : 0,
          scan_status: st,
          scan_error:
            st === 'failed'
              ? ERRORS[k % ERRORS.length]
              : st === 'unavailable'
                ? `MANIFEST_UNKNOWN: manifest sha256:${hex(12)} not found in ${repo.split('/')[0]} (the digest exists only on the nodes)`
                : st === 'missing_credential'
                  ? `No registry credential matches ${repo.split('/')[0]}`
                  : '',
          scan_attempts: attempts || (st === 'unavailable' ? 1 : 0),
          next_retry_at: st === 'failed' && attempts < 5 ? isoIn((10 + attempts * 15) * MIN) : null,
          last_scanned_at: st === 'scanned' ? iso((20 + Math.floor(rnd() * 600)) * MIN) : null,
          fixable: crit + high > 0 ? Math.floor((crit + high) * rnd()) : 0,
          registry: st === 'missing_credential' ? '' : repo.startsWith('acr.') ? 'acr.contoso.io' : repo.startsWith('ghcr.io/contoso') ? 'ghcr.io/contoso/*' : 'public',
        });
      }
    }
  }
}
export const kyverno: KyvernoPolicy[] = [
  { cluster_id: byName('prod-aks-weu-01').id, cluster_name: 'prod-aks-weu-01', namespace: '', name: 'require-run-as-nonroot', mode: 'Audit', rules: 2, fail_count: 11, ready: true },
  { cluster_id: byName('eks-fra-data').id, cluster_name: 'eks-fra-data', namespace: '', name: 'disallow-latest-tag', mode: 'Audit', rules: 1, fail_count: 8, ready: true },
  { cluster_id: byName('prod-aks-weu-02').id, cluster_name: 'prod-aks-weu-02', namespace: '', name: 'require-resource-limits', mode: 'Enforce', rules: 1, fail_count: 4, ready: true },
  { cluster_id: byName('oke-fra-erp').id, cluster_name: 'oke-fra-erp', namespace: 'erp', name: 'restrict-host-path', mode: 'Enforce', rules: 1, fail_count: 0, ready: true },
];
export const netpol: NetpolNamespace[] = [
  { cluster_id: byName('eks-fra-data').id, cluster_name: 'eks-fra-data', namespace: 'analytics', policy_count: 0, default_deny: false, excluded: false },
  { cluster_id: byName('oke-fra-erp').id, cluster_name: 'oke-fra-erp', namespace: 'observability', policy_count: 1, default_deny: false, excluded: false },
  { cluster_id: byName('onprem-factory-01').id, cluster_name: 'onprem-factory-01', namespace: 'mes', policy_count: 0, default_deny: false, excluded: false },
  { cluster_id: byName('prod-aks-weu-01').id, cluster_name: 'prod-aks-weu-01', namespace: 'orders', policy_count: 3, default_deny: true, excluded: false },
  { cluster_id: byName('prod-aks-weu-01').id, cluster_name: 'prod-aks-weu-01', namespace: 'kube-system', policy_count: 0, default_deny: false, excluded: true },
];
{
  const POLICIES = ['require-labels', 'require-probes', 'disallow-privileged', 'disallow-host-namespaces', 'require-image-digest', 'restrict-registries', 'require-pod-requests', 'disallow-capabilities'];
  clusters.forEach((c, ci) => {
    if (c.status === 'pending') return;
    for (let i = 0; i < 3 + (ci % 3); i++) {
      const name = POLICIES[(ci + i * 3) % POLICIES.length];
      if (kyverno.some((p) => p.cluster_id === c.id && p.name === name)) continue;
      const fail = rnd() < 0.45 ? Math.floor(rnd() * 14) : 0;
      kyverno.push({ cluster_id: c.id, cluster_name: c.name, kind: i % 4 === 3 ? 'ValidatingPolicy' : undefined, namespace: '', name, mode: rnd() < 0.3 ? 'Enforce' : 'Audit', rules: 1 + Math.floor(rnd() * 3), fail_count: fail, ready: !(ci === 7 && i === 0) });
    }
    for (const ns of ['default', 'monitoring', 'ingress-nginx', 'apps', 'jobs', 'cert-manager']) {
      if (netpol.some((n) => n.cluster_id === c.id && n.namespace === ns)) continue;
      const deny = rnd() < 0.6;
      netpol.push({ cluster_id: c.id, cluster_name: c.name, namespace: ns, policy_count: deny ? 1 + Math.floor(rnd() * 4) : Math.floor(rnd() * 2), default_deny: deny, excluded: false });
    }
  });
}
export const registries: Registry[] = [
  { id: uuid(), host_pattern: 'acr.contoso.io', username: '', credential_source: 'managed_identity', credential_ref: '', images: 118, created_at: iso(50 * D) },
  { id: uuid(), host_pattern: 'ghcr.io/contoso/*', username: 'olympos-scan', credential_source: 'keyvault_ref', credential_ref: 'kv://kv-platform-weu/ghcr-pull-token', images: 41, created_at: iso(50 * D) },
  { id: uuid(), host_pattern: 'quay.io/legacy/*', username: 'robot$legacy', credential_source: 'stored', credential_ref: '', images: 3, created_at: iso(40 * D) },
];
export const unmatched: UnmatchedRegistry[] = [{ host: 'harbor.factory.local', images: 4, example_repo: 'harbor.factory.local/mes/line-agent' }];

// ------------------------------------------------------------ access
function grant(p: Principal, role: Role, scope: string, grantedAgo: number, by: string, stale = false): Grant {
  return { id: uuid(), principal: p, is_guest: p.user_type === 'Guest', role, scope, granted_by: by ? uuid() : null, granted_by_name: by, granted_at: iso(grantedAgo), stale };
}
export const grants: Grant[] = [
  grant(people.yigit, 'admin', 'all', 70 * D, ''),
  grant(people.yigit, 'vault-maker', 'all', 70 * D, ''),
  grant(people.yigit, 'vault-approver', 'all', 70 * D, ''),
  grant(people.selin, 'vault-maker', 'env=prod', 37 * D, 'yigit@contoso.com'),
  grant(people.selin, 'vault-approver', 'env=prod', 37 * D, 'yigit@contoso.com'),
  grant(people.mert, 'vault-maker', 'all', 37 * D, 'yigit@contoso.com'),
  grant(people.deniz, 'viewer', 'all', 76 * D, 'yigit@contoso.com', true),
];
export const directory = [
  { object_id: '7b3e1a2c-4d5e-4f60-8a71-9b8c7d6ec19d', display_name: 'Ayşe Kaya', upn: 'ayse.kaya@contoso.com', mail: 'ayse.kaya@contoso.com', user_type: 'Member', account_enabled: true, is_guest: false },
  { object_id: '2f90b4c1-8e7d-4a6b-9c5d-3e2f1a0ba4b1', display_name: 'Ayşe Demir', upn: 'ayse_partner.com#EXT#@contoso.onmicrosoft.com', mail: 'ayse@partner.com', user_type: 'Guest', account_enabled: true, is_guest: true },
  { object_id: 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', display_name: 'Ahmet Şahin', upn: 'ahmet.sahin@contoso.com', mail: 'ahmet.sahin@contoso.com', user_type: 'Member', account_enabled: true, is_guest: false },
];

// ------------------------------------------------------------ activity
const A: [number, string, string, string, string, string, Record<string, unknown>][] = [
  [41 * MIN, 'yigit@contoso.com', 'destination.tested', 'destination', 'blob-neu-dr', 'user', { summary: 'write, read, tag ok · delete refused' }],
  [3 * H, 'system', 'vault.unmanaged_write', 'vault', 'openbao · kv/platform/ci', 'system', { summary: 'v12 created outside Olympos' }],
  [3 * D, 'yigit@contoso.com', 'cr.applied', 'change_request', 'CR-0139', 'user', { summary: 'kv/erp/payments v6 → v7 · approved by yigit@' }],
  [4 * H, 'selin@contoso.com', 'cr.opened', 'change_request', 'CR-0142', 'user', { summary: 'replace PSP_API_KEY' }],
  [7 * H, 'yigit@contoso.com', 'grant.created', 'grant', 'mert@contoso.com', 'user', { summary: '+ vault-maker · scope all' }],
  [8 * H, 'system', 'backup.succeeded', 'backup_run', 'openbao', 'system', { summary: '42 MB · blob-weu-backups' }],
  [6.5 * H, 'system', 'backup.failed', 'backup_run', 'metrics-ch', 'system', { summary: 'SAS expired' }],
  [13 * H, 'system', 'grant.stale', 'grant', 'deniz@contoso.com', 'system', { summary: 'account disabled in Entra' }],
  [18 * H, 'yigit@contoso.com', 'login.succeeded', 'session', '', 'user', { summary: 'Entra ID · tid verified' }],
  [21 * H, 'yigit@contoso.com', 'cluster.updated', 'cluster', 'eks-fra-data', 'user', { summary: 'transfer mode e2e-tls → compressed' }],
  [2 * H, 'agent', 'agent.offline', 'cluster', 'onprem-ist-lab', 'agent', { summary: 'no heartbeat for 60 s' }],
  [21 * H, 'mert@contoso.com', 'cr.opened', 'change_request', 'CR-0141', 'user', { summary: 'create 2 keys, delete 1' }],
  [26 * H, 'yigit@contoso.com', 'cr.opened', 'change_request', 'CR-0140', 'user', { summary: 'replace DB_PASSWORD' }],
  [10 * H, 'system', 'audit.new_findings', 'audit_run', 'kubescape', 'system', { summary: '+3 new failed controls' }],
];
export const activity: ActivityEntry[] = [];
{
  for (const [ago, actor, action, objectType, objectId, kind, details] of A) {
    activity.push({ id: uuid(), at: iso(ago), actor_id: kind === 'user' ? uuid() : null, actor_name: actor, actor_kind: kind as ActivityEntry['actor_kind'], action, object_type: objectType, object_id: objectId, cluster_id: null, details });
  }
  // older history for cursor paging
  const filler = ['backup.succeeded', 'login.succeeded', 'backup.succeeded', 'audit.run_finished', 'vault.index_refreshed'];
  for (let i = 0; i < 160; i++) {
    const action = filler[i % filler.length];
    activity.push({
      id: uuid(),
      at: iso(2 * D + i * 3 * H),
      actor_id: null,
      actor_name: action === 'login.succeeded' ? 'selin@contoso.com' : 'system',
      actor_kind: action === 'login.succeeded' ? 'user' : 'system',
      action,
      object_type: action.split('.')[0],
      object_id: action === 'backup.succeeded' ? (i % 2 ? 'billing-pg' : 'openbao') : '',
      cluster_id: null,
      details: { summary: action === 'backup.succeeded' ? '3.1 GB · blob-weu-backups' : '' },
    });
  }
  activity.sort((a, b) => b.at.localeCompare(a.at));
}

export function record(action: string, objectType: string, objectId: string, summary: string) {
  activity.unshift({ id: uuid(), at: new Date().toISOString(), actor_id: people.yigit.id, actor_name: people.yigit.upn, actor_kind: 'user', action, object_type: objectType, object_id: objectId, cluster_id: null, details: { summary } });
}
