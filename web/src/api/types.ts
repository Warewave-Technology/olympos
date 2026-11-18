// Types mirror docs/openapi.yaml (components.schemas). Keep them in sync.

export type Role = 'viewer' | 'operator' | 'vault-maker' | 'vault-approver' | 'admin';
export const ROLES: Role[] = ['viewer', 'operator', 'vault-maker', 'vault-approver', 'admin'];

export interface ItemList<T> {
  items: T[];
}

export interface Principal {
  id: string;
  tenant_id: string;
  object_id: string;
  upn: string;
  display_name: string;
  user_type: string;
  account_enabled: boolean;
}

export interface Permissions {
  read: boolean;
  operate: boolean;
  operate_global: boolean;
  vault_make: boolean;
  vault_approve: boolean;
  admin: boolean;
  admin_global: boolean;
}
export type Permission = keyof Permissions;

export interface Me {
  principal: Principal;
  is_guest: boolean;
  roles: Role[];
  grants: { role: Role; scope: string }[];
  permissions: Permissions;
  csrf_token?: string;
  dev_mode: boolean;
}

export interface Grant {
  id: string;
  principal: Principal;
  is_guest: boolean;
  role: Role;
  scope: string;
  granted_by: string | null;
  granted_by_name: string;
  granted_at: string;
  stale: boolean;
}

export interface DirectoryUser {
  object_id: string;
  display_name: string;
  upn: string;
  mail: string;
  user_type: string;
  account_enabled: boolean;
  is_guest: boolean;
}

export type Provider = '' | 'azure' | 'aws' | 'gcp' | 'oracle' | 'huawei' | 'onprem';
export type ClusterStatus = 'pending' | 'online' | 'offline' | 'revoked';
export type TransferMode = 'e2e-tls' | 'compressed';

export interface Cluster {
  id: string;
  name: string;
  labels: Record<string, string>;
  provider: Provider;
  provider_label: string;
  provider_override: string;
  region: string;
  api_version: string;
  status: ClusterStatus;
  last_seen_at: string | null;
  agent_version: string;
  bench_enabled: boolean;
  transfer_mode: TransferMode;
  egress_rate_per_gb: number | null;
  cert_expires_at: string | null;
  nodes: number;
  nodes_ready: number;
  cpu_milli: number;
  mem_bytes: number;
  min_kubelet: string;
  version_skew: boolean;
  eol: boolean;
  inventory_at: string | null;
  created_at: string;
  /** Optional (openapi extension): distinct node zones. */
  zones?: string[];
  /** Optional (openapi extension): node count per instance type. */
  instance_types?: { instance_type: string; count: number }[];
  /** Optional (openapi extension): wire bytes of backup runs, last 30 days. */
  backup_wire_bytes_30d?: number;
  /** Optional (openapi extension): uncompressed bytes of backup runs, last 30 days. */
  backup_bytes_30d?: number;
}

export interface InstallResponse {
  cluster: Cluster;
  command: string;
  expires_at: string;
}

export interface Node {
  name: string;
  provider_id: string;
  kubelet_version: string;
  region: string;
  zone: string;
  instance_type: string;
  cpu_milli: number;
  mem_bytes: number;
  roles: string[];
  ready: boolean;
  seen_at: string;
}

export type Engine = '' | 'postgresql' | 'clickhouse' | 'vault';

export interface Target {
  id: string;
  cluster_id: string;
  cluster_name: string;
  namespace: string;
  service: string;
  port: number;
  port_name: string;
  engine: Engine;
  vault_provider: '' | 'hashicorp' | 'openbao';
  tls_server_name: string;
  detected_version: string;
  tls_ok: boolean | null;
  status: 'candidate' | 'configured' | 'gone';
  first_seen_at: string;
  last_seen_at: string;
}

export interface AttentionItem {
  kind: 'agent_offline' | 'backup_failed' | 'backup_missed' | 'approvals' | 'eol' | 'critical_cves';
  severity: 'crit' | 'warn';
  label: string;
  detail: string;
  link: string;
}

export interface Dashboard {
  attention: AttentionItem[];
  totals: {
    clusters: number;
    agents_online: number;
    nodes: number;
    cpu_milli: number;
    mem_bytes: number;
    versions: number;
    version_min: string;
    version_max: string;
    skew_clusters: number;
    offline_agents: number;
    offline_detail: string;
  };
  version_matrix: { minor: string; clusters: number; eol: boolean }[];
  providers: { provider: string; label: string; clusters: number; nodes: number }[];
  clusters: Cluster[];
  refreshed_at: string | null;
}

// ---------------------------------------------------- notifications
export interface Channel {
  id: string;
  kind: 'slack';
  name: string;
  slack_channel_id: string;
  routes: string[];
  created_at: string;
}
export interface Route {
  event_type: string;
  channel_ids: string[];
}
export interface Routes {
  catalog: { event_type: string; description: string; opt_in: boolean }[];
  routes: Route[];
}

// ---------------------------------------------------- destinations
export type SecretSource = 'keyvault_ref' | 'stored';
export interface SecretSourceInput {
  source: SecretSource;
  ref?: string;
  value?: string;
}
export type DestinationKind = 'azure_blob' | 's3' | 'nfs';
export type DestinationAuth = 'managed_identity' | 'sas_token' | 'access_key' | 'none';
/**
 * docs/openapi.yaml DestinationInput. Fields by kind:
 * azure_blob: account, container, auth managed_identity|sas_token (+ sas), endpoint_override;
 * s3: bucket, region, endpoint_override, path_style, auth access_key + access_key_id + secret_key;
 * nfs: path (below a GET /destinations/mounts mount). PATCH is partial; kind cannot change.
 */
export interface DestinationInput {
  name?: string;
  kind?: DestinationKind;
  prefix?: string;
  endpoint_override?: string;
  account?: string;
  container?: string;
  auth?: DestinationAuth;
  sas?: SecretSourceInput;
  bucket?: string;
  region?: string;
  path_style?: boolean;
  access_key_id?: string;
  secret_key?: SecretSourceInput;
  path?: string;
}
export interface DestinationMount {
  name: string;
  path: string;
  writable: boolean;
}
export interface DestinationTestStep {
  name: 'write' | 'read' | 'tag' | 'delete_refused' | 'sas_permissions' | 'sas_expiry' | 'endpoint' | 'path';
  ok: boolean;
  detail: string;
}
export interface DestinationTest {
  ok: boolean;
  can_delete: boolean;
  steps: DestinationTestStep[];
  sas: {
    permissions: string;
    expires_at: string | null;
    missing: string[];
    extra: string[];
    scope: 'container' | 'account' | 'service' | 'unknown';
  } | null;
  error?: string;
  probe_path?: string;
}
export interface DestinationTestFailed {
  error: string;
  fields?: Record<string, string>;
  test?: DestinationTest;
}
export interface Destination {
  id: string;
  name: string;
  kind: DestinationKind;
  prefix: string;
  endpoint_override: string;
  auth: DestinationAuth;
  // azure_blob
  account: string;
  container: string;
  sas_source: '' | SecretSource;
  sas_ref: string;
  sas_expires_at: string | null;
  sas_permissions: string;
  // s3
  bucket?: string;
  region?: string;
  path_style?: boolean;
  access_key_id?: string;
  secret_key_source?: '' | SecretSource;
  secret_key_ref?: string;
  // nfs
  path?: string;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test?: DestinationTest | null;
  jobs: number;
  created_at?: string;
  /** Only on create/patch responses. */
  warnings?: string[];
}

// ---------------------------------------------------- backups
export interface CredentialInput {
  source: SecretSource;
  ref?: string;
  username: string;
  password?: string;
}
export interface Retention {
  daily: number;
  weekly: number;
  monthly: number;
}
export interface BackupJobInput {
  target_id?: string;
  credential?: CredentialInput;
  destination_id?: string;
  engine_options?: Record<string, unknown>;
  cron?: string;
  timezone?: string;
  retention?: Retention;
  enabled?: boolean;
  notify_channel_id?: string | null;
}
export type RunStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'missed';
export interface BackupRun {
  id: string;
  job_id: string;
  target_service: string;
  cluster_name: string;
  engine: string;
  trigger: 'schedule' | 'manual' | 'test';
  status: RunStatus;
  scheduled_for: string | null;
  tier: '' | 'daily' | 'weekly' | 'monthly';
  started_at: string | null;
  finished_at: string | null;
  bytes: number;
  wire_bytes: number;
  blob_path: string;
  sha256: string;
  error: string;
  /** Optional (openapi extension): destination name for run lists. */
  destination_name?: string;
  /** Optional (openapi extension): dry-run checklist steps. */
  steps?: { name: string; ok: boolean; detail: string }[];
}
export interface BackupJob {
  id: string;
  target: Target;
  engine: string;
  credential: { id: string; source: string; ref: string; username: string };
  destination: { id: string; name: string };
  engine_options: Record<string, unknown>;
  cron: string;
  timezone: string;
  retention: Retention;
  enabled: boolean;
  paused_reason: string;
  notify_channel_id: string | null;
  next_run_at: string | null;
  last_run: BackupRun | null;
  estimated_monthly_bytes: number;
  estimated_monthly_cost: number | null;
  created_at: string;
}
export interface ConnectionTest {
  ok: boolean;
  server_version: string;
  tls: boolean;
  privileges: { name: string; ok: boolean; detail: string }[];
  databases: string[];
  error: string;
}
export interface SchedulePreview {
  next: string[];
  description: string;
}

// ---------------------------------------------------- vaults
export interface KVMount {
  path: string;
  version: 1 | 2;
  managed: boolean;
  description: string;
}
export interface Vault {
  id: string;
  target: Target;
  provider: 'hashicorp' | 'openbao';
  version: string;
  status: 'discovered' | 'configured' | 'error' | 'gone';
  kv_mounts: KVMount[];
  configured_by_name: string;
  configured_at: string | null;
  secret_id_rotated_at: string | null;
  last_index_at: string | null;
  secrets: number;
  drift: number;
  last_error: string;
}
export interface VaultInspect {
  version: string;
  sealed: boolean;
  mounts: KVMount[];
}
export interface SecretSummary {
  mount: string;
  path: string;
  keys: number;
  current_version: number;
  updated_time: string | null;
  managed: boolean;
}
export interface SecretVersion {
  version: number;
  created_time: string;
  deletion_time: string;
  destroyed: boolean;
  by_olympos: boolean;
  /** Optional (openapi extension): number of keys in that version. */
  keys?: number;
}
export interface SecretDetail {
  mount: string;
  path: string;
  keys: string[];
  current_version: number;
  updated_time: string | null;
  managed: boolean;
  versions: SecretVersion[];
  pending_change_requests: number;
  /** Optional (openapi extension): per-key metadata for the keys table. */
  key_info?: { key: string; version: number; updated_time: string | null; pending_cr_id: string | null; pending_cr_label?: string; last_cr_id?: string | null; last_cr_label?: string }[];
  /** Optional (openapi extension): who wrote the current version. */
  updated_by_name?: string;
}
export type ChangeOp = 'create' | 'replace' | 'delete' | 'destroy_history';
export interface ChangeItemInput {
  mount: string;
  path: string;
  key?: string;
  op: ChangeOp;
  value?: string;
  base_version?: number;
  versions?: number[];
}
export interface ChangeRequestInput {
  vault_id: string;
  justification: string;
  items: ChangeItemInput[];
}
export type CRStatus = 'pending' | 'approved' | 'applied' | 'rejected' | 'expired' | 'failed' | 'cancelled';
export interface ChangeRequest {
  id: string;
  /** Optional (openapi extension): short display number, e.g. CR-0142. */
  number?: string;
  vault: { id: string; name: string; cluster_name: string; provider: string; version?: string };
  maker: Principal;
  checker: Principal | null;
  justification: string;
  status: CRStatus;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  decision_comment: string;
  applied_at: string | null;
  failure: string;
  can_approve: boolean;
  approve_disabled_reason: string;
  can_cancel: boolean;
  items: {
    id: string;
    mount: string;
    path: string;
    key: string | null;
    op: ChangeOp;
    base_version: number;
    versions: number[];
    fingerprint: string;
  }[];
  events: {
    at: string;
    kind: 'opened' | 'approved' | 'rejected' | 'applied' | 'failed' | 'expired' | 'cancelled' | string;
    actor_name: string;
    details: Record<string, unknown>;
  }[];
  /** Optional (openapi extension): eligible approvers excluding the maker. */
  eligible_approvers?: number;
}

// ---------------------------------------------------- audit
export type AuditTool = 'kubescape' | 'polaris' | 'kube-bench';
export interface AuditScheduleInput {
  tool?: AuditTool;
  frameworks?: ('nsa' | 'cis' | 'mitre')[];
  scope_selector?: string;
  cron?: string;
  timezone?: string;
  enabled?: boolean;
  notify_channel_id?: string | null;
}
export interface BenchNode {
  node_name: string;
  benchmark: string;
  state: string;
  pass: number;
  fail: number;
  warn: number;
  control_plane_na: boolean;
  message: string;
  /** Optional: cluster name, when runs are listed across clusters. */
  cluster_name?: string;
  duration_s?: number;
}
export interface AuditRun {
  id: string;
  schedule_id: string | null;
  tool: AuditTool | string;
  cluster_id: string;
  cluster_name: string;
  status: 'queued' | 'running' | 'succeeded' | 'failed';
  started_at: string | null;
  finished_at: string | null;
  score: number | null;
  new_findings: number;
  resolved_findings: number;
  error: string;
  bench_nodes?: BenchNode[];
}
export interface AuditSchedule extends AuditScheduleInput {
  id: string;
  tool: AuditTool;
  next_run_at: string | null;
  clusters: number;
  last_run: AuditRun | null;
}
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface Finding {
  id: string;
  source: string;
  cluster_id: string;
  cluster_name: string;
  control_id: string;
  severity: Severity;
  resource_ref: string;
  title: string;
  details: Record<string, unknown>;
  status: 'open' | 'resolved';
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
}

// ---------------------------------------------------- security
export interface Image {
  digest: string;
  repo: string;
  tags: string[];
  clusters: number;
  workloads: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  scan_status: 'pending' | 'scanning' | 'scanned' | 'missing_credential' | 'failed';
  last_scanned_at: string | null;
  /** Vulnerabilities (any severity) that have a fixed version. */
  fixable?: number;
  /** Optional (openapi extension): matched registry credential host pattern. */
  registry?: string;
}
export interface ImageDetail extends Image {
  usage: { cluster_id: string; cluster_name: string; namespace: string; workload_kind: string; workload_name: string; container: string }[];
  vulns: { cve_id: string; severity: string; package: string; installed: string; fixed_in: string; title: string }[];
  scan_error: string;
}
export interface KyvernoPolicy {
  cluster_id: string;
  cluster_name: string;
  /** ClusterPolicy | Policy (legacy kyverno.io) or a policies.kyverno.io CEL kind. */
  kind?: string;
  namespace: string;
  name: string;
  mode: 'Enforce' | 'Audit';
  rules: number;
  fail_count: number;
  ready: boolean;
}
export interface NetpolNamespace {
  cluster_id: string;
  cluster_name: string;
  namespace: string;
  policy_count: number;
  default_deny: boolean;
  excluded: boolean;
}
export interface RegistryInput {
  host_pattern: string;
  username?: string;
  password?: SecretSourceInput;
}
export interface Registry {
  id: string;
  host_pattern: string;
  username: string;
  /** '' = anonymous; managed_identity is an openapi extension (ACR only). */
  credential_source: '' | SecretSource | 'managed_identity';
  credential_ref: string;
  images: number;
  created_at: string;
}
export interface UnmatchedRegistry {
  host: string;
  images: number;
  example_repo: string;
}

export interface ActivityEntry {
  id: string;
  at: string;
  actor_id: string | null;
  actor_name: string;
  actor_kind: 'user' | 'system' | 'agent';
  action: string;
  object_type: string;
  object_id: string;
  cluster_id: string | null;
  details: Record<string, unknown> | null;
}
