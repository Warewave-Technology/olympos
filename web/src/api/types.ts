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
  /** A changed olympos.io/tls-server-name waiting for an admin; null when none. */
  tls_server_name_pending?: string | null;
  tls_server_name_changed_at?: string | null;
  detected_version: string;
  tls_ok: boolean | null;
  status: 'candidate' | 'configured' | 'gone';
  first_seen_at: string;
  last_seen_at: string;
}

export interface AttentionItem {
  kind: 'agent_offline' | 'backup_failed' | 'backup_missed' | 'approvals' | 'eol' | 'critical_cves' | 'backup_partial' | 'self_backup_unset' | 'self_backup_failed' | 'self_backup_partial' | 'kek_purgeable' | 'kek_recovery_unknown' | 'target_tls_changed';
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
  /** Last delivery attempt (null = not yet). */
  last_delivery_at?: string | null;
  last_delivery_ok?: boolean | null;
  last_delivery_error?: string;
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
  /** Number of destination groups this destination is a member of. */
  groups?: number;
  created_at?: string;
  /** Only on create/patch responses. */
  warnings?: string[];
}
/** docs/openapi.yaml DestinationGroupInput: create needs name and member_ids; PATCH takes any. */
export interface DestinationGroupInput {
  name?: string;
  description?: string;
  /** 2 to 4 distinct destination ids in order; the first is the default restore copy. */
  member_ids?: string[];
}
export interface DestinationGroupMember {
  id: string;
  name: string;
  kind: DestinationKind;
}
/** A set of destinations a backup job writes one dump to (docs/design/destination-groups.md). */
export interface DestinationGroup {
  id: string;
  name: string;
  description: string;
  /** In position order. */
  members: DestinationGroupMember[];
  /** Jobs using the group (a count only, deleted jobs included). */
  jobs: number;
  created_at: string;
  updated_at: string;
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
  /** Exactly one of destination_id and destination_group_id; on PATCH, setting one clears the other. */
  destination_id?: string;
  destination_group_id?: string;
  engine_options?: Record<string, unknown>;
  cron?: string;
  timezone?: string;
  retention?: Retention;
  enabled?: boolean;
  notify_channel_id?: string | null;
  /** Also send backup.succeeded for this job. */
  notify_on_success?: boolean;
}
/** partial = a destination group run that wrote some but not all of its copies. */
export type RunStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'missed' | 'partial';
/** One destination's result of a run. */
export interface BackupRunCopy {
  destination_id: string;
  destination_name: string;
  destination_kind: DestinationKind;
  status: 'succeeded' | 'failed';
  /** May be set on a failed copy; it is not a restore source then. */
  blob_path: string;
  bytes: number;
  sha256: string;
  tier: string;
  error: string;
}
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
  /** Counts every run queued for one activation: 1 = the first, +1 per retry after an agent disconnect and per repair (repair_of set). */
  attempt?: number;
  /** The destination the run wrote to when it wrote to exactly one, else the job's destination or group name. */
  destination_name?: string;
  /** One result per destination in write order; empty for runs from before destination groups. */
  copies?: BackupRunCopy[];
  /** The run whose missing copies this run completes. */
  repair_of?: string | null;
  /** A queued run is not started before then (repairs wait 5 min, 30 min, 2 h); null = as soon as a worker is free. */
  not_before?: string | null;
  created_at?: string;
  /** Optional (openapi extension): dry-run checklist steps. */
  steps?: { name: string; ok: boolean; detail: string }[];
}
/** Ready-to-copy restore commands of one successful run (F19). */
export interface RestoreCopy {
  destination_id: string;
  name: string;
  kind: DestinationKind;
  /** The copy the steps are built from. */
  selected: boolean;
  /** The run that wrote this copy: the guide's run, or a repair of it. */
  run_id: string;
  taken_at: string | null;
}
export interface RestoreGuide {
  doc: string;
  steps: { title: string; commands: string; note?: string }[];
  /** Succeeded copies in member order, then copies repairs completed later. */
  copies?: RestoreCopy[];
}
export interface BackupRunDetail extends BackupRun {
  restore: RestoreGuide | null;
  /** Partial run with a repair queued: when the repair starts (its not_before). */
  next_repair_at?: string | null;
}
/** GET /backup/self: the built-in olympos-self job (Olympos' own database). */
export interface SelfBackup {
  configured: boolean;
  job: {
    id: string;
    /** Set when the job writes to one destination. */
    destination_id: string | null;
    /** Set when the job writes to every destination of a group. */
    destination_group_id?: string | null;
    /** Name of the destination or the group. */
    destination_name: string;
    cron: string;
    timezone: string;
    retention: Retention;
    enabled: boolean;
    notify_channel_id: string | null;
    created_at: string;
  } | null;
  runs: BackupRun[];
  /** Restore commands for the latest succeeded or partial original run. */
  restore?: RestoreGuide | null;
}
/** GET/PUT /audit/settings: where raw audit reports are kept. */
export interface AuditSettings {
  raw_destination: { id: string; name: string; kind: string } | null;
}
export interface AuditSettingsInput {
  raw_destination_id: string | null;
}

export interface SelfBackupInput {
  destination_id?: string;
  destination_group_id?: string;
  cron?: string;
  timezone?: string;
  retention?: Retention;
  enabled?: boolean;
}
export interface BackupJob {
  id: string;
  target: Target;
  engine: string;
  credential: { id: string; source: string; ref: string; username: string };
  /** Set for a job that writes to one destination, else null. */
  destination: { id: string; name: string } | null;
  /** Set for a job that writes to a destination group, else null. */
  destination_group: { id: string; name: string; members: string[] } | null;
  engine_options: Record<string, unknown>;
  cron: string;
  timezone: string;
  retention: Retention;
  enabled: boolean;
  paused_reason: string;
  notify_channel_id: string | null;
  notify_on_success?: boolean;
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
  /** Olympos labels of the vault's cluster (filtering). */
  cluster_labels?: Record<string, string>;
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
/** GET /vaults/search?q= result: a vault, or a secret path inside one. */
export interface VaultSearchHit {
  match: 'vault' | 'path';
  vault_id: string;
  vault_name: string;
  provider: string;
  cluster_id: string;
  cluster_name: string;
  namespace: string;
  /** path matches only */
  mount?: string;
  path?: string;
  keys?: number;
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
export type CRStatus = 'pending' | 'approved' | 'applying' | 'applied' | 'rejected' | 'expired' | 'failed' | 'cancelled';
export interface ChangeRequest {
  id: string;
  /** Optional (openapi extension): short display number, e.g. CR-0142. */
  number?: string;
  /** namespace is an optional extension; the SPA falls back to GET /vaults. */
  vault: { id: string; name: string; cluster_name: string; provider: string; version?: string; namespace?: string };
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
  /** apply_error | apply_unknown | conflict ('' unless failed). */
  failure_code?: string;
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
    kind: 'opened' | 'approved' | 'applying' | 'rejected' | 'applied' | 'failed' | 'expired' | 'cancelled' | string;
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
/** One kube-bench result on a node. */
export interface BenchCheck {
  id: string;
  section: string;
  section_text: string;
  node_type: string;
  description: string;
  status: 'PASS' | 'FAIL' | 'WARN' | 'INFO';
  scored: boolean;
  remediation: string;
  actual_value?: string;
  expected_result?: string;
  reason?: string;
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
  /** Every result (run detail only; empty for runs stored before checks were kept). */
  checks?: BenchCheck[];
}
export interface AuditRun {
  id: string;
  schedule_id: string | null;
  tool: AuditTool | string;
  cluster_id: string;
  cluster_name: string;
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'missed';
  started_at: string | null;
  finished_at: string | null;
  score: number | null;
  new_findings: number;
  resolved_findings: number;
  /** Short reason, e.g. "agent_offline" or "framework 'cis-v1.23-t1.0.1' not found". */
  error: string;
  /** Full tool output (stderr/stdout), run detail only (GET /audit/runs/{id}). */
  log?: string;
  details?: Record<string, unknown>;
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
export type ScanStatus = 'pending' | 'scanning' | 'scanned' | 'missing_credential' | 'unavailable' | 'failed';
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
  /**
   * unavailable = the digest is not in the registry (locally built or retagged, e.g. kind
   * node images); failed = transient error, retried automatically (scan_attempts, next_retry_at).
   */
  scan_status: ScanStatus;
  /** Why the last scan did not succeed (also on list items). */
  scan_error?: string;
  scan_attempts?: number;
  next_retry_at?: string | null;
  /**
   * tag = the running digest is not in the registry; the registry's image with the same tag
   * was scanned instead (results may differ from what runs). '' / digest = scanned by digest.
   */
  scanned_by?: '' | 'digest' | 'tag';
  last_scanned_at: string | null;
  /** Vulnerabilities (any severity) that have a fixed version. */
  fixable?: number;
  /** Optional (openapi extension): matched registry credential host pattern. */
  registry?: string;
}
export interface ImageDetail extends Image {
  usage: { cluster_id: string; cluster_name: string; namespace: string; workload_kind: string; workload_name: string; container: string }[];
  vulns: { cve_id: string; severity: string; package: string; installed: string; fixed_in: string; title: string }[];
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
  rule_names?: string[];
  fail_count: number;
  ready: boolean;
}
export interface KyvernoViolation {
  rule: string;
  result: string;
  severity: string;
  message: string;
  resource_kind: string;
  resource_namespace: string;
  resource_name: string;
}
/** GET /security/kyverno/policy */
export interface KyvernoPolicyDetail extends KyvernoPolicy {
  /** The policy spec as stored in the cluster (metadata trimmed). */
  spec: Record<string, unknown>;
  /** The whole object as YAML (apiVersion, kind, name, spec). */
  yaml: string;
  violations: KyvernoViolation[];
}
export interface NetpolNamespace {
  cluster_id: string;
  cluster_name: string;
  namespace: string;
  policy_count: number;
  default_deny: boolean;
  excluded: boolean;
}
export interface NetpolWorkload {
  kind: string;
  name: string;
  /** Pod template labels. */
  labels: Record<string, string>;
  ports: number[];
  /** Optional extension: container port names → numbers (named ports in policies). */
  named_ports?: Record<string, number>;
}
/** GET /security/netpol/namespace */
export interface NetpolNamespaceDetail {
  cluster_id: string;
  cluster_name: string;
  namespace: string;
  namespace_labels: Record<string, string>;
  default_deny: boolean;
  excluded: boolean;
  /** spec: networking.k8s.io/v1 NetworkPolicySpec as in the cluster. */
  policies: { name: string; spec: Record<string, unknown>; yaml: string }[];
  workloads: NetpolWorkload[];
  other_namespaces: { name: string; labels: Record<string, string> }[];
}

// ---------------------------------------------------- per-cluster summaries (cluster overview level)
/** GET /security/clusters */
export interface SecurityClusterSummary {
  cluster_id: string;
  cluster_name: string;
  provider: string;
  status: string;
  images: number;
  workloads: number;
  critical: number;
  high: number;
  images_with_critical: number;
  not_scanned: number;
  kyverno_installed: boolean;
  kyverno_policies: number;
  kyverno_failures: number;
  namespaces: number;
  namespaces_without_default_deny: number;
  /** Open sensitive-data findings (credential-like values in ConfigMaps). */
  sensitive_data?: number;
  sensitive_data_high?: number;
}
/** GET /security/secrets: opt-in Secret inventory (names and key names only). */
export interface SecretRow {
  cluster_id: string;
  cluster_name: string;
  namespace: string;
  name: string;
  type: string;
  keys: string[];
  keys_unknown: boolean;
  referenced_by: string[];
  managed_by: string;
  created_at: string | null;
  first_seen_at: string;
  last_referenced_at: string | null;
  findings: string[];
}
export interface SecretInventory {
  clusters: { cluster_id: string; cluster_name: string; enabled: boolean }[];
  items: SecretRow[];
  fix: string;
}
export interface AuditClusterRun {
  tool: AuditTool | string;
  run_id: string;
  status: string;
  score: number | null;
  finished_at: string | null;
  new_findings: number;
}
/** GET /audit/clusters */
export interface AuditClusterSummary {
  cluster_id: string;
  cluster_name: string;
  provider: string;
  bench_enabled: boolean;
  last_runs: AuditClusterRun[];
  open_findings: { critical: number; high: number; medium: number; low: number };
}
/** GET /backup/clusters */
export interface BackupClusterSummary {
  cluster_id: string;
  cluster_name: string;
  targets: number;
  candidates: number;
  jobs: number;
  jobs_enabled: number;
  /** Original runs; partial = wrote some copies and its repairs did not complete them. */
  last_24h: { succeeded: number; failed: number; missed: number; partial?: number };
  last_success_at: string | null;
  bytes_30d: number;
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
  /** Last pull through this entry (null = not yet). */
  last_pull_at?: string | null;
  last_pull_ok?: boolean | null;
  last_pull_error?: string;
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
