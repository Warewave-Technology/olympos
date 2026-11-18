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

function cluster(p: Partial<Cluster> & Pick<Cluster, 'name'>): Cluster {
  return {
    id: uuid(),
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
  job(tByService('openbao'), { cron: '0 */6 * * *', next_run_at: isoIn(2 * H), estimated_monthly_bytes: 5 * GB, credential: { id: uuid(), source: 'keyvault_ref', ref: 'kv://kv-platform-weu/olympos-approle', username: 'approle' } }),
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
export const auditRuns: AuditRun[] = [
  arun({ tool: 'kubescape', schedule_id: ksSched, started_at: iso(10 * H), finished_at: iso(10 * H - 420_000), score: 78.4, new_findings: 3, resolved_findings: 1 }),
  arun({ tool: 'kubescape', schedule_id: ksSched, started_at: iso(34 * H), finished_at: iso(34 * H - 400_000), score: 78.9, new_findings: 0, resolved_findings: 4 }),
  arun({ tool: 'kubescape', schedule_id: ksSched, started_at: iso(58 * H), finished_at: iso(58 * H - 410_000), score: 77.2, new_findings: 1, resolved_findings: 0 }),
  arun({ tool: 'kubescape', schedule_id: ksSched, started_at: iso(82 * H), finished_at: iso(82 * H - 405_000), score: 77.4, new_findings: 0, resolved_findings: 2 }),
  arun({ tool: 'polaris', schedule_id: polSched, started_at: iso(2 * D), score: 91.0 }),
  arun({
    tool: 'kube-bench',
    schedule_id: kbSched,
    started_at: iso(3 * D),
    resolved_findings: 2,
    bench_nodes: [
      { node_name: 'aks-sys-17402-vmss000000', cluster_name: 'prod-aks-weu-01', benchmark: 'aks-1.7', state: 'done', pass: 41, fail: 2, warn: 6, control_plane_na: true, message: '', duration_s: 38 },
      { node_name: 'ip-10-20-4-17', cluster_name: 'eks-fra-data', benchmark: 'eks-1.5', state: 'done', pass: 39, fail: 1, warn: 7, control_plane_na: true, message: '', duration_s: 41 },
      { node_name: 'factory-cp-1', cluster_name: 'onprem-factory-01', benchmark: 'cis-1.9 master', state: 'done', pass: 58, fail: 4, warn: 9, control_plane_na: false, message: '', duration_s: 52 },
      { node_name: 'ist-lab-w1', cluster_name: 'onprem-ist-lab', benchmark: 'cis-1.9 node', state: 'skipped', pass: 0, fail: 0, warn: 0, control_plane_na: false, message: 'agent offline' },
    ],
  }),
];
export const auditSchedules: AuditSchedule[] = [
  { id: ksSched, tool: 'kubescape', frameworks: ['nsa', 'cis', 'mitre'], scope_selector: 'all', cron: '0 4 * * *', timezone: 'Europe/Istanbul', enabled: true, notify_channel_id: channels[2].id, next_run_at: isoIn(14 * H), clusters: 7, last_run: auditRuns[0] },
  { id: polSched, tool: 'polaris', frameworks: [], scope_selector: 'env=prod', cron: '0 5 * * 1', timezone: 'Europe/Istanbul', enabled: true, notify_channel_id: channels[2].id, next_run_at: isoIn(5 * D), clusters: 5, last_run: auditRuns[4] },
  { id: kbSched, tool: 'kube-bench', frameworks: [], scope_selector: 'all', cron: '0 3 * * 0', timezone: 'Europe/Istanbul', enabled: true, notify_channel_id: channels[2].id, next_run_at: isoIn(4 * D), clusters: 5, last_run: auditRuns[5] },
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

// ------------------------------------------------------------ security
export const images: Image[] = [
  { digest: 'sha256:7c1e4b2f9a0d3c5e7f1a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c09ab', repo: 'acr.contoso.io/erp/payments-api', tags: ['2.14.1'], clusters: 2, workloads: 6, critical: 3, high: 11, medium: 20, low: 31, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), fixed_in: '2.14.3', registry: 'acr.contoso.io' },
  { digest: 'sha256:a40f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b771c', repo: 'docker.io/bitnami/redis', tags: ['7.2.4'], clusters: 5, workloads: 9, critical: 2, high: 6, medium: 9, low: 14, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), fixed_in: '7.2.6', registry: '' },
  { digest: 'sha256:1b9d3e5f7a9c1e3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7be2f0', repo: 'quay.io/legacy/report-gen', tags: ['0.9'], clusters: 1, workloads: 1, critical: 1, high: 14, medium: 22, low: 9, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), fixed_in: '', registry: 'quay.io/legacy/*' },
  { digest: 'sha256:c33a5d7f9b1d3f5a7c9e1f3b5d7a9c1e3f5b7d9a1c3e5f7b9d1a3c5e7f9b5d12', repo: 'ghcr.io/contoso/ingest-worker', tags: ['1.8.0'], clusters: 3, workloads: 12, critical: 1, high: 4, medium: 8, low: 12, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), fixed_in: 'base image', registry: 'ghcr.io/contoso/*' },
  { digest: 'sha256:e81f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f', repo: 'harbor.factory.local/mes/line-agent', tags: ['3.2'], clusters: 1, workloads: 4, critical: 0, high: 0, medium: 0, low: 0, scan_status: 'missing_credential', last_scanned_at: null, registry: '' },
  { digest: 'sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f0f1e2d3c4b5a69788796a5b4c3d2e1f00', repo: 'acr.contoso.io/platform/olympos-agent', tags: ['0.4.2'], clusters: 7, workloads: 7, critical: 0, high: 0, medium: 1, low: 2, scan_status: 'scanned', last_scanned_at: iso(25 * MIN), registry: 'acr.contoso.io' },
];
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
