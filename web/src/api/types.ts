// Types mirror docs/openapi.yaml (components.schemas). Keep them in sync.

export type Role = 'viewer' | 'operator' | 'vault-maker' | 'vault-approver' | 'synthetic-editor' | 'admin';
export const ROLES: Role[] = ['viewer', 'operator', 'vault-maker', 'vault-approver', 'synthetic-editor', 'admin'];

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
  /** synthetic-editor (or admin) on at least one cluster: create and edit scenarios in scope. */
  synthetic_edit: boolean;
  /** synthetic-editor (or admin) with scope all: scenarios that run on all clusters. */
  synthetic_edit_global: boolean;
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
export type ProbeStatus = 'not_installed' | 'pending' | 'online' | 'offline' | 'revoked';

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
  /** The synthetic probe next to the agent (docs/design/synthetic-monitoring.md §2). */
  probe_status: ProbeStatus;
  probe_version: string;
  probe_last_seen_at: string | null;
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
  /** Backup runs with a copy record on this destination; such a destination cannot be deleted. */
  copies?: number;
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
  /** Per current destination (member order): when the self-backup last wrote a successful copy there. */
  destinations_last_success?: DestinationLastSuccess[];
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
  /** Per current destination (member order): when the job last wrote a successful copy there. */
  destinations_last_success?: DestinationLastSuccess[];
  estimated_monthly_bytes: number;
  estimated_monthly_cost: number | null;
  created_at: string;
}
/** docs/openapi.yaml DestinationLastSuccess. */
export interface DestinationLastSuccess {
  destination_id: string;
  name: string;
  /** When the latest successful copy there finished; null when there is none. */
  last_success_at: string | null;
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

// ---------------------------------------------------- restores (docs/design/ui-restore.md)
export type RestoreStatus = 'pending' | 'approved' | 'running' | 'succeeded' | 'failed' | 'rejected' | 'expired' | 'cancelled';
export type RestoreEngine = 'postgresql' | 'clickhouse' | 'vault';
/** POST /restores and /restores/check. credential.password and vault_token are write-only. */
export interface RestoreInput {
  run_id: string;
  /** The copy to read (group runs); null = the copy the run's restore guide selects. */
  copy_destination_id?: string | null;
  target_id: string;
  /** PostgreSQL, ClickHouse: databases in the backup; empty = all. Vault: none. */
  databases?: string[];
  /** PostgreSQL only: restore roles from globals.sql (default on; off without a superuser). */
  globals?: boolean | null;
  tls_ca_pem?: string;
  /** PostgreSQL, ClickHouse: the target's admin login. */
  credential?: CredentialInput;
  /** Vault/OpenBao: a token of the new Vault that may call sys/storage/raft/snapshot-force. */
  vault_token?: string;
  /** 10–2000 characters; not checked by /restores/check. */
  justification: string;
  /** Admins on both clusters start the request without a checker. */
  break_glass?: boolean;
}
export interface RestoreOptions {
  globals?: boolean;
  /** PostgreSQL: the credential is a superuser (owners and privileges are kept). */
  superuser?: boolean;
  tls_ca_pem?: string;
  /** Open-time findings: existing empty databases restored into, no superuser. */
  notes?: string[];
  server_version?: string;
}
export interface RestoreTargetReport {
  /** Selected databases that exist on the target: true when they hold user objects. */
  existing: Record<string, boolean>;
  superuser: boolean;
  /** Vault/OpenBao */
  initialized: boolean;
  sealed: boolean;
  /** The token holds update and sudo (or root) on sys/storage/raft/snapshot-force. */
  can_snapshot_force: boolean;
  /** An HA node that is not the active node. */
  standby: boolean;
  /** sys/capabilities-self refused the token (HTTP 401/403). */
  capabilities_denied: boolean;
  server_version: string;
}
/** POST /restores/check: 200 with ok=false, error and fields when a check failed. */
export interface RestoreCheck {
  ok: boolean;
  error?: string;
  fields?: Record<string, string>;
  engine: RestoreEngine;
  copy_destination_id: string | null;
  /** The run that wrote the copy (the run or one of its repairs). */
  copy_run_id: string | null;
  databases_in_backup: string[] | null;
  /** What would be restored. */
  databases: string[] | null;
  options: RestoreOptions;
  report: RestoreTargetReport | null;
}
/** restore_requests.progress: the latest progress of a running restore ({} before it starts). */
export interface RestoreProgress {
  /** verify (the checksum pass) | check (the target re-check) | globals (PostgreSQL roles) | restore */
  phase?: string;
  database?: string;
  table?: string;
  /** Bytes of the backup read in the current phase, of total. */
  bytes?: number;
  total?: number;
  done?: string[];
  /** Databases created on the target so far: they stay after a failure. */
  created?: string[];
}
/** One database (or the Vault snapshot) of a restore result. */
export interface RestoreItem {
  name: string;
  status: 'succeeded' | 'failed' | 'skipped' | string;
  bytes: number;
  duration_seconds: number;
  tables: number;
  /** Rows written (ClickHouse). */
  rows: number;
  /** What was not restored, with the reason. */
  skipped?: string[];
  error?: string;
}
/** restore_requests.result ({} until the restore ends). */
export interface RestoreResult {
  items?: RestoreItem[];
  notes?: string[];
  created?: string[];
}
/** A restore request. Never carries a password or a token. */
export interface RestoreRequest {
  id: string;
  status: RestoreStatus;
  engine: RestoreEngine;
  source: {
    run_id: string;
    copy_run_id: string;
    target_id: string;
    cluster_id: string;
    cluster_name: string;
    namespace: string;
    service: string;
    destination_id: string;
    destination_name: string;
    destination_kind: DestinationKind | string;
  };
  target: { id: string; cluster_id: string; cluster_name: string; namespace: string; service: string; port: number; vault_provider?: string };
  databases: string[];
  options: RestoreOptions;
  /** The target login's public part; null once the request has ended. */
  credential: { source: SecretSource; ref?: string; username: string } | null;
  has_vault_token: boolean;
  maker: Principal;
  checker: Principal | null;
  justification: string;
  /** Started by the maker without a checker; the maker is the decider. */
  break_glass: boolean;
  created_at: string;
  /** When a pending request expires. */
  expires_at: string;
  decided_at: string | null;
  decision_comment: string;
  /** When an approved request that has not started expires (approval + 24 h). */
  approved_expires_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  progress: RestoreProgress | null;
  result: RestoreResult | null;
  error: string;
  can_approve: boolean;
  approve_disabled_reason: string;
  can_cancel: boolean;
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

// ------------------------------------------------------------ synthetic monitoring (docs/design/synthetic-monitoring.md)

export type ScenarioType = 'http_flow' | 'http' | 'dns' | 'tcp' | 'tls';
export type StepKind = 'dns' | 'http' | 'tcp' | 'tls';
export type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';
export type AssertionOperator = 'equals' | 'not_equals' | 'contains' | 'matches' | 'less_than' | 'greater_than' | 'exists' | 'length_greater_than';
export type SyntheticCellState = 'failing' | 'degraded' | 'passing' | 'probe_offline' | 'not_installed' | 'excluded' | 'paused' | 'no_data';
export type ScenarioStatus = 'failing' | 'degraded' | 'passing' | 'paused' | 'no_data';
export type SyntheticRunStatus = 'scheduled' | 'running' | 'passed' | 'failed' | 'error' | 'skipped';
export type CredentialKind = 'bearer' | 'basic' | 'header' | 'oauth2_client_credentials';
export type AllowKind = 'exact' | 'wildcard' | 'suffix';

export interface ScenarioAssertion {
  /** status_code, latency_ms, header:<Name>, body, json:<path>, tls_days_left, record_count, record, connects, chain_valid, hostname_matches, tls_version */
  subject: string;
  operator: AssertionOperator;
  value: string;
}
export interface ScenarioExtract {
  name: string;
  source: 'json_path' | 'header' | 'regex';
  expr: string;
}
export interface HttpStepSpec {
  method: HttpMethod;
  url: string;
  /** null when hidden (the caller may not see a credentialed step's headers). */
  headers: Record<string, string> | null;
  /** null when hidden. */
  body: string | null;
  body_type?: 'text' | 'json';
  follow_redirects?: boolean;
}
/** The credential of a step: its name and kind, never its value. */
export interface SyntheticCredentialRef {
  id: string;
  name: string;
  kind: CredentialKind | string;
  header_name: string;
}
/** A step (openapi SyntheticStep). Exactly one of dns, http, tcp, tls: the one `kind` names. */
export interface ScenarioStep {
  /** Ignored on input; the server numbers steps in order. */
  position?: number;
  kind: StepKind;
  dns?: { name: string; record_type: 'A' | 'AAAA' | 'CNAME' | 'TXT' } | null;
  http?: HttpStepSpec | null;
  tcp?: { host: string; port: number } | null;
  tls?: { host: string; port: number; sni?: string } | null;
  credential_id?: string | null;
  /** Read-only. */
  credential?: SyntheticCredentialRef | null;
  assertions: ScenarioAssertion[];
  extracts: ScenarioExtract[];
  /** Read-only: headers and body are hidden from the caller (the step uses a credential). */
  hidden?: boolean;
}
export type SyntheticStep = ScenarioStep;

export interface ScenarioAlertRule {
  cluster_fail_after: number;
  fleet_critical_clusters: number;
  recovery_after: number;
  send_recovery: boolean;
  /** null: the routes of the synthetic.* events decide. */
  channel_id: string | null;
  /** null: channel_id. */
  critical_channel_id: string | null;
  channel_name?: string;
  critical_channel_name?: string;
}

export interface ScenarioInput {
  name: string;
  type: ScenarioType;
  owner_selector: string;
  interval_seconds: number;
  timeout_seconds: number;
  step_retries: number;
  enabled?: boolean;
  store_responses?: boolean;
  run_on: 'all' | 'selector';
  run_on_selector: string;
  exclude_selectors: string[];
  steps: ScenarioStep[];
  alerts?: ScenarioAlertRule;
}

export interface ScenarioTargets {
  runs_on: number;
  of: number;
  clusters: string[];
  excluded: string[];
}

export interface Scenario extends ScenarioInput {
  id: string;
  enabled: boolean;
  store_responses: boolean;
  alerts: ScenarioAlertRule;
  targets: ScenarioTargets;
  requests_per_minute: number;
  can_edit: boolean;
  created_by: string | null;
  created_by_name: string;
  created_at: string;
  updated_at: string;
}

export interface ScenarioSummary {
  id: string;
  name: string;
  type: ScenarioType;
  owner_selector: string;
  interval_seconds: number;
  timeout_seconds: number;
  enabled: boolean;
  run_on: 'all' | 'selector';
  run_on_selector: string;
  exclude_selectors: string[];
  steps: number;
  targets: ScenarioTargets;
  can_edit: boolean;
  created_at: string;
  updated_at: string;
}

export interface ScenarioPreview extends ScenarioTargets {
  requests_per_minute: number;
  scenario_cap: number;
  cluster_cap: number;
  over_scenario_cap: boolean;
  over_limit: { cluster: string; requests_per_minute: number }[];
}

export interface SyntheticCell {
  cluster_id: string;
  state: SyntheticCellState;
  last_run_id: string | null;
  last_status: 'passed' | 'failed' | 'error' | null;
  last_finished_at: string | null;
  failed_step: number | null;
  failure_reason: string;
  consecutive_failures: number;
  /** rate_limit: a request cap keeps the scheduler from running it there. */
  blocked_reason: string;
}

export interface SyntheticOverviewCluster {
  id: string;
  name: string;
  probe_status: ProbeStatus;
  probe_version: string;
  probe_last_seen_at: string | null;
}

export interface SyntheticOverviewScenario {
  id: string;
  name: string;
  type: ScenarioType;
  owner_selector: string;
  interval_seconds: number;
  enabled: boolean;
  steps: number;
  status: ScenarioStatus;
  failing_clusters: number;
  degraded_clusters: number;
  /** One per column of `clusters`, same order. */
  cells: SyntheticCell[];
  runs_24h: number;
  availability_24h: number | null;
  p95_ms_24h: number | null;
  can_edit: boolean;
}

export interface SyntheticOverview {
  kpis: {
    scenarios: number;
    active: number;
    paused: number;
    failing_scenarios: number;
    failing_clusters: number;
    degraded_scenarios: number;
    degraded_clusters: number;
    probes_online: number;
    probes_total: number;
    probes_offline: string[];
    probes_not_installed: string[];
  };
  clusters: SyntheticOverviewCluster[];
  scenarios: SyntheticOverviewScenario[];
}

export interface TimelineBucket {
  start: string;
  runs: number;
  passed: number;
  failed: number;
  state: 'passed' | 'failed' | 'no_data';
}

export interface ScenarioClusterRow {
  cluster_id: string;
  cluster_name: string;
  probe_status: ProbeStatus | string;
  state: SyntheticCellState;
  last_run: { id: string; status: string; finished_at: string; failed_step: number | null; failure_reason: string } | null;
  consecutive_failures: number;
  consecutive_passes: number;
  blocked_reason: string;
  runs_24h: number;
  availability_24h: number | null;
  p50_ms: number | null;
  p95_ms: number | null;
  timeline: TimelineBucket[];
}

export interface ScenarioClusters {
  window_start: string;
  bucket_minutes: number;
  buckets: number;
  items: ScenarioClusterRow[];
}

export interface SyntheticAlert {
  id: string;
  fleet: boolean;
  cluster_id: string | null;
  cluster_name: string;
  state: 'firing' | 'resolved';
  /** The failure reason of the run that opened it; no_longer_monitored when it resolved without a run. */
  reason: string;
  opened_at: string;
  resolved_at: string | null;
  duration_seconds: number | null;
  last_run_id: string | null;
  failed_step: number | null;
  clusters: string[];
  clusters_total: number;
  still_failing: number | null;
  notified: boolean;
}

export interface SyntheticRun {
  id: string;
  /** null for a test run of an unsaved draft. */
  scenario_id: string | null;
  scenario_name: string;
  cluster_id: string;
  cluster_name: string;
  scheduled_for: string;
  started_at: string | null;
  finished_at: string | null;
  status: SyntheticRunStatus;
  failed_step: number | null;
  failure_reason: string;
  total_ms: number | null;
  test: boolean;
  manual: boolean;
  probe_version: string;
}

export interface StepTimings {
  dns_us: number;
  connect_us: number;
  tls_us: number;
  ttfb_us: number;
  download_us: number;
  total_us: number;
}

export interface AssertionResult {
  subject: string;
  operator: AssertionOperator | string;
  expected: string;
  actual: string;
  passed: boolean;
}

export interface SyntheticStepResult {
  position: number;
  /** Empty when the probe reported nothing for the step. */
  status: 'passed' | 'failed' | 'error' | 'skipped' | '';
  status_code: number | null;
  timings: StepTimings | null;
  assertions: AssertionResult[];
  /** First 2 KiB of the response, redacted on the probe and the server. */
  excerpt: string | null;
  extracted_names: string[];
  error: string;
  request: ScenarioStep | null;
}

export interface SyntheticRunDetail extends SyntheticRun {
  scenario_type: ScenarioType | string;
  remote_ip: string;
  probe_ip: string;
  allowlist_version: number;
  requested_by_name: string;
  consecutive_failures: number;
  alert: { id: string; state: string; opened_at: string; resolved_at: string | null } | null;
  /** Where the requests come from: the test run's draft, the scenario as saved now, or none (deleted). */
  definition: 'test' | 'saved' | 'none';
  steps: SyntheticStepResult[];
}

export interface AllowRule {
  id: string;
  pattern: string;
  kind: AllowKind;
  note: string;
  scenarios: number;
  created_by: string | null;
  created_by_name: string;
  created_at: string;
}

export interface HostCheck {
  host: string;
  allowed: boolean;
  rule: AllowRule | null;
  also: AllowRule[];
  denied_reason: '' | 'ip_literal' | 'always_denied' | 'invalid_host' | 'no_rule';
  message: string;
}

export interface SyntheticCredential {
  id: string;
  name: string;
  kind: CredentialKind;
  bound_hosts: { pattern: string; kind: AllowKind }[];
  header_name: string;
  oauth_token_url: string;
  oauth_scopes: string;
  source: 'stored' | 'keyvault_ref';
  expires_at: string | null;
  expired: boolean;
  rotated_at: string | null;
  scenarios: { id: string; name: string }[];
  resolve_failures_24h: number;
  last_resolve_failed_at: string | null;
  created_by: string | null;
  created_by_name: string;
  created_at: string;
  updated_at: string;
}

/** A 409 that names what still needs the object. */
export interface InUse {
  error: string;
  scenarios: string[];
  credentials: string[];
}
