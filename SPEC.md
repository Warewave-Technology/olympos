# Olympos — Product & Implementation Spec (v0.1)

> Central, self-hosted management platform for a fleet of Kubernetes clusters.
> Server–agent architecture. One installation per customer (not SaaS).
> UI pilot: https://claude.ai/artifact/3fWjB7fn6vFcEwoqR4XKP7 (Gruvbox dark, 9 screens + logo).

This document is the source of truth for the implementation. Where it says **MUST**, do not deviate without asking. Where it says *suggested*, a better choice is welcome if explained in the PR.

---

## 0. Principles (read first)

1. **Credentials never enter the cluster.** All work that needs a credential (backups, Vault operations, image scans) runs on the **server**. The agent is discovery + a constrained tunnel.
2. **The agent is a narrow, boring component.** Distroless, no shell, read-only RBAC, no Secret access except its own identity Secret and the opt-in Secret inventory (metadata only, F3; off by default; `list` on `secrets` would let a stolen agent token read values), no listening port. It only dials out.
3. **The agent only tunnels to targets it discovered itself.** The server can never ask for an arbitrary `host:port`.
4. **Secret values are never shown in the UI.** Users see keys, never values; values can only be replaced, through maker/checker approval.
5. **Every sensitive action is auditable.** Append-only logs for grants, change requests, backup runs, logins.
6. **The server is the only writer to backup storage.** Nothing in a cluster ever gets a Blob credential; the server cannot delete backups (retention is done by Blob lifecycle rules; on NFS a file system cannot enforce this, so the destination shows a permanent warning, see `docs/spec-changes.md` #13).
7. **Simple to install and operate.** One Helm chart for the server, one for the agent. Sensible defaults; dangerous features opt-in.
8. **Tech terms and UI copy in English.**

---

## 1. Architecture

```
            Azure (customer subscription)
 ┌──────────────────────────────────────────────────────┐
 │  Olympos Server (Go)                                 │
 │   ├─ web (React SPA, served by server)               │
 │   ├─ REST API /api/v1  (BFF session, Entra OIDC)     │
 │   ├─ Agent Gateway (gRPC, mTLS, :8443)               │
 │   ├─ Scheduler + Workers (backups, audits, scans)    │
 │   ├─ Notifier (Slack)                                │
 │   └─ Internal CA (agent client certs)                │
 │  PostgreSQL  · Azure Key Vault · Azure Blob Storage  │
 │  Managed Identity                                    │
 └───────────────▲──────────────────────────────────────┘
                 │ gRPC bidi over mTLS (agent dials out)
   ┌─────────────┴───────────┬─────────────────────────┐
   │ cluster A               │ cluster B (on-prem) ... │
   │  olympos-agent          │  olympos-agent          │
   │   ├─ informers          │                         │
   │   ├─ tunnel (L4)        │                         │
   │   ├─ read-only API proxy│                         │
   │   └─ kube-bench runner  │  (opt-in)               │
   └─────────────────────────┴─────────────────────────┘
```

### 1.1 Stack (suggested unless marked MUST)

| Area | Choice |
|---|---|
| Language | **Go 1.23+ (MUST)** for server and agent |
| HTTP router | `go-chi/chi/v5` |
| DB | PostgreSQL 16 (Azure Database for PostgreSQL Flexible Server or in-cluster), `jackc/pgx/v5`, `sqlc` for queries, `pressly/goose` migrations |
| Agent ↔ server | `grpc-go` + protobuf, mTLS |
| k8s | `client-go` informers (`sigs.k8s.io/controller-runtime` acceptable) |
| Azure | `azidentity` (Managed Identity), `azkeys`, `azsecrets`, `azblob` |
| OIDC | `coreos/go-oidc/v3` + `golang.org/x/oauth2` |
| Vault / OpenBao | `hashicorp/vault/api` (OpenBao is API-compatible) |
| Slack | `slack-go/slack` |
| Cron parsing | `robfig/cron/v3` (parser only; scheduling loop is ours, see §10.5) |
| Web | React 18 + TypeScript + Vite, TanStack Query + TanStack Router, plain CSS with CSS variables (Gruvbox tokens, §15) |
| External tools in server image | `pg_dump`/`pg_dumpall` 13–17, `trivy`, `kubescape`, `polaris` (pinned versions) |
| Packaging | Distroless images, Helm charts, SBOM + cosign signatures in CI |

### 1.2 Repository layout

```
olympos/
  cmd/
    olympos-server/
    olympos-agent/
  internal/
    server/        # http api, bff session, rbac middleware
    gateway/       # grpc agent gateway, enrollment, tunnel broker
    agent/         # discovery, tunnel endpoint, api proxy, bench runner
    inventory/
    backup/        # engines: postgres, clickhouse, vault
    vaults/        # vault/openbao mgmt, change requests
    approvals/     # maker/checker state machine
    audit/         # kubescape, polaris, kube-bench ingest, diff
    security/      # image inventory, trivy, kyverno, netpol
    notify/        # event bus, outbox, slack sink
    secrets/       # envelope encryption, key vault refs, hmac
    authz/         # principals, grants, scopes
    store/         # sqlc generated + migrations
    pki/           # internal CA
  proto/olympos/v1/*.proto
  web/
  deploy/helm/olympos-server/
  deploy/helm/olympos-agent/
  docs/
```

---

## 2. Deployment & configuration

### 2.1 Server
- Two deployment modes (owner decision): **Kubernetes** (Helm chart) and a plain **systemd service** on a Linux VM (`.deb`/`.rpm`/tarball, `docs/install-systemd.md`). v0.1 runs as a **single instance** in both (§17, F5).
- **Olympos' own database** runs next to the server by default: a bundled single-instance PostgreSQL 16 StatefulSet in the same namespace (Helm, `postgresql.bundled: true`), or the local PostgreSQL on the same host over the Unix socket with peer auth (systemd, `database.dsn: postgres:///olympos?host=/var/run/postgresql`). An external PostgreSQL (e.g. Azure Database for PostgreSQL) stays supported (`postgresql.bundled: false` + `database.dsnRef`).
- The built-in, non-deletable backup job **`olympos-self`** dumps that database (`pg_dump -Fc`, daily by default) to a destination the admin chooses at setup (Dashboard *Needs attention* until set); same manifest, tags and retention as every job. Restore: `docs/restore-olympos.md`. The dump is useless without the Key Vault KEK: soft delete + purge protection MUST be on (the server warns otherwise).
- Uses a **User-Assigned Managed Identity** for Key Vault, Blob and (optionally) Graph.
- Needs network reachability to every agent? **No** — agents dial in. The server only needs one inbound endpoint for agents (`:8443`, mTLS) and one for users (`:443`).
- Config via env/Helm values. Key settings:

```yaml
olympos:
  publicURL: https://olympos.contoso.internal
  agentGatewayURL: olympos-gw.contoso.internal:8443
  entra:
    tenantID: <guid>          # MUST be validated on every token (tid + iss)
    clientID: <guid>
    clientSecretRef: kv://kv-platform-weu/olympos-oidc-client-secret
  bootstrapAdmins:            # Entra object IDs; only used when grants table is empty
    - 9a2f...41bd
  keyVault:
    name: kv-platform-weu
    kekName: olympos-kek       # RSA/EC key used to wrap DEKs
    hmacSecretName: olympos-hmac
  database:                   # default: local/bundled PostgreSQL (see above)
    dsnRef: kv://kv-platform-weu/olympos-db-dsn   # external database only
  deadMansSwitch:
    url: https://heartbeat.example/olympos   # optional, see §10.6
```

### 2.2 Agent
- Helm chart `olympos-agent`, namespace `olympos-system`.
- Install command is generated by the UI ("Add cluster") and contains a **one-time bootstrap token** (TTL 1 h).
- Values:

```yaml
server: olympos-gw.contoso.internal:8443
bootstrapToken: <one-time>
clusterName: prod-aks-weu-01
providerOverride: ""        # set for on-prem: "onprem", region text optional
bench:
  enabled: false            # kube-bench exception, see §12.3
  maxParallel: 3
```

---

## 3. Authentication & authorization

### 3.1 Login
- Entra ID OIDC, Authorization Code + PKCE, handled by the server (**BFF pattern**). The SPA never sees tokens; it gets an `HttpOnly; Secure; SameSite=Strict` session cookie.
- Token validation MUST check: signature (JWKS), `iss` = `https://login.microsoftonline.com/<tenantID>/v2.0`, `tid` = configured tenant, `aud` = clientID, `exp`/`nbf`.
- Entra Enterprise App **"Assignment required = Yes"** is a documented install prerequisite (second gate).
- Session: server-side session row in Postgres, 8 h absolute, 30 min idle. CSRF token on state-changing requests.

### 3.2 Principals & grants (by object ID, not groups)
- A principal is `(tenant_id, object_id)`. UPN and display name are **snapshots** refreshed daily via Graph (`User.ReadBasic.All`, delegated or app).
- Grants are stored in Olympos, not in Entra groups. Group claims are ignored.
- Roles:

| Role | Can |
|---|---|
| `viewer` | Read everything except secrets (keys visible, values never) |
| `operator` | viewer + run/configure backups, audits, scans, notification routing |
| `vault-maker` | Open change requests on vaults in scope |
| `vault-approver` | Approve/reject change requests **opened by someone else** |
| `admin` | Everything incl. grants, clusters, destinations, vault configure. Does **not** bypass maker/checker. |

- **Scope**: `all` or a cluster label selector (e.g. `env=prod`). Cluster labels are set in Olympos (Settings › Clusters).
- Rules:
  - `vault-approver` MUST NOT be granted to guest accounts (`userType=Guest` / UPN contains `#EXT#`).
  - Every grant change emits `grant.changed` (Slack) and an audit row.
  - Daily job: principals with `accountEnabled=false` or deleted in Entra → grant marked **stale**, `grant.stale` event. Stale grants do not authorize.
  - Bootstrap admins from config are only applied when the grants table is empty.

---

## 4. Agent

### 4.1 Responsibilities
1. **Inventory**: cluster version, nodes (see §6), namespaces.
2. **Discovery**: annotated Services (§5), Kyverno policies + PolicyReports, NetworkPolicies, workload images (from Pod `status.containerStatuses[].imageID`).
3. **Tunnel endpoint**: L4 byte pipe to **discovered targets only**.
4. **Read-only API proxy**: lets server-side tools (kubescape, polaris) talk to the kube-apiserver with the agent's identity, `GET/LIST/WATCH` only.
5. **kube-bench runner** (opt-in, §12.3).

### 4.2 RBAC (MUST be exactly this, plus bench extras when enabled, plus `secrets: [list, watch]` — never `get` — only with the opt-in Secret inventory, metadata-only, F3)

```yaml
kind: ClusterRole
rules:
- apiGroups: [""]
  resources: [nodes, namespaces, services, endpoints, pods]
  verbs: [get, list, watch]
- apiGroups: ["discovery.k8s.io"]
  resources: [endpointslices]
  verbs: [get, list, watch]
- apiGroups: ["apps"]
  resources: [deployments, statefulsets, daemonsets, replicasets]
  verbs: [get, list, watch]
- apiGroups: ["networking.k8s.io"]
  resources: [networkpolicies]
  verbs: [get, list, watch]
- apiGroups: ["kyverno.io"]
  resources: [clusterpolicies, policies]
  verbs: [get, list, watch]
- apiGroups: ["policies.kyverno.io"]   # Kyverno ≥ 1.17 CEL policies (1.20 runs only these)
  resources: [validatingpolicies, namespacedvalidatingpolicies, imagevalidatingpolicies, namespacedimagevalidatingpolicies]
  verbs: [get, list, watch]
- apiGroups: ["wgpolicyk8s.io"]
  resources: [policyreports, clusterpolicyreports]
  verbs: [get, list, watch]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: [roles, rolebindings, clusterroles, clusterrolebindings]
  verbs: [get, list, watch]      # needed by kubescape
```
- **No `secrets`, no `configmaps` write, no `pods/exec`, no `create` anywhere** (except bench namespace, §12.3).
- Kubescape and Polaris need a few more read-only resources (e.g. `serviceaccounts`, `configmaps` (read), `podsecuritypolicies` legacy, `mutating/validatingwebhookconfigurations`). Add read-only verbs for these; never Secrets.

### 4.3 Runtime
- Distroless static image, `runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities dropped, seccomp `RuntimeDefault`.
- No listening ports except an optional localhost-only health endpoint.

### 4.5 Reconnect semantics (owner decision: reliability and consistency first)
- **State, not event replay.** On every (re)connect the agent sends a full snapshot (inventory, targets, reports) carrying a monotonically increasing `generation`; the server applies it per cluster in one transaction (mark-and-sweep). Diffs and target messages carry the next generation; anything out of order is dropped and the server sends `RequestResync`.
- **No false resolutions.** While a cluster is offline nothing from it is marked resolved or gone; pages show "as of <last seen>". Findings resolve only from a fresh snapshot or a scan after the reconnect.
- **Result-bearing work** (kube-bench status and result chunks) is kept in a bounded agent buffer (16 MiB, oldest dropped with a warning) and re-sent after the reconnect; the server ingests idempotently by `run_id` + node + `seq` and fails a node whose chunks have a gap.
- **Tunnels** close on disconnect. Backup and audit runs that fail because the agent is gone end `agent_disconnected` and are retried after the reconnect while inside the job's window (half the interval to the next activation, at most 3 attempts), else `missed`. A retried attempt does not notify.
- **Alert debounce.** `agent.offline` fires after 5 min offline (`agents.offlineAlertAfter`); `agent.flapping` when an agent disconnects more than 5 times in 30 min; exactly one `agent.online` when it comes back after an alert.

### 4.4 Enrollment & identity
1. UI "Add cluster" → server creates cluster row (`pending`) + one-time bootstrap token (hashed in DB, TTL 1 h).
2. Agent starts, generates an ECDSA P-256 key pair **in memory**, sends CSR + bootstrap token to `Enroll` RPC (server-TLS only).
3. Server validates token, signs a client cert (CN = cluster UUID, 30-day validity), invalidates token.
4. Agent stores key + cert in a Kubernetes Secret **in its own namespace** (this is the one Secret it may read/write — namespaced Role, resourceNames-restricted).
5. Agent renews at 2/3 of lifetime via `RenewCert` over the authenticated channel.
6. Server can **revoke** a cluster: cert serial added to deny list, open streams dropped.

---

## 5. Discovery annotations

Annotations go on the **Service** that fronts the workload.

| Annotation | Values | Meaning |
|---|---|---|
| `olympos.io/backup` | `postgresql` \| `clickhouse` \| `vault` | Backup candidate |
| `olympos.io/vault` | `hashicorp` \| `openbao` | Vault provider (Vaults page) |
| `olympos.io/port` | port name or number | Which Service port to target (default: engine's well-known port) |
| `olympos.io/tls-server-name` | hostname | SNI / cert name the server should verify (pinned at first sight; changes need admin acceptance) |

- A Vault Service can carry both `olympos.io/vault` and `olympos.io/backup: vault`.
- **Target ID** = `sha256(cluster_uuid | namespace | service_name | port)` truncated to 16 bytes, hex. Stable across restarts.
- Agent sends `TargetUpsert` / `TargetDelete` on changes. Server marks new targets as **candidates** (Backups › Candidates, Vaults › Discovered).
- Targets that disappear → status `gone`; jobs referencing them pause and emit an event.

---

## 6. Inventory & dashboard

Per node the agent reports:
- `name`, `providerID`, `kubeletVersion`, labels `topology.kubernetes.io/region`, `topology.kubernetes.io/zone`, `node.kubernetes.io/instance-type`, capacity/allocatable CPU+memory, roles (from `node-role.kubernetes.io/*`), Ready condition.
- Cluster: API server `gitVersion`.

Provider detection from `providerID` prefix: `azure://` → Azure, `aws://` → AWS, `gce://` → GCP, `oci://` → Oracle Cloud, `huaweicloud://` → Huawei Cloud, empty/other → **On-prem** (unless `providerOverride`).

Derived:
- **Version matrix**: count of clusters per API minor version; versions past upstream EOL flagged (maintain a small EOL table in code, updatable).
- **Version skew**: any node `kubeletVersion` minor < API minor.
- **Needs attention strip** (Dashboard top, hidden when empty): agent offline > 5 min, backup failed/missed/incomplete, pending approvals for the current user, EOL versions, new critical CVEs. Each item links to the relevant page.

Snapshots every 60 s (agent pushes diffs; full snapshot every 10 min).

---

## 7. Agent ↔ Server protocol

`proto/olympos/v1/gateway.proto` (sketch — refine as needed):

```proto
service AgentGateway {
  rpc Enroll(EnrollRequest) returns (EnrollResponse);          // bootstrap token, server-TLS only
  rpc Control(stream AgentMessage) returns (stream ServerMessage); // mTLS, one per agent
  rpc Tunnel(stream TunnelFrame) returns (stream TunnelFrame);    // mTLS, one per open tunnel
}

message AgentMessage {
  oneof msg {
    Hello hello = 1;                 // agent version, cluster uuid, capabilities (bench enabled?)
    InventorySnapshot inventory = 2;
    InventoryDiff inventory_diff = 3;
    TargetUpsert target_upsert = 4;
    TargetDelete target_delete = 5;
    ResourceReport report = 6;       // kyverno policies/reports, netpols, images
    TunnelAccepted tunnel_accepted = 7;
    TunnelRejected tunnel_rejected = 8;
    BenchStatus bench_status = 9;
    BenchResultChunk bench_result = 10;
    Pong pong = 11;
  }
}

message ServerMessage {
  oneof msg {
    OpenTunnel open_tunnel = 1;      // { tunnel_id, target_id }  — never host:port
    OpenAPIProxy open_api_proxy = 2; // { tunnel_id }  read-only kube-apiserver proxy
    RunBench run_bench = 3;          // { run_id, node_name, benchmark }
    RequestResync resync = 4;
    Ping ping = 5;
  }
}

message TunnelFrame {
  string tunnel_id = 1;   // first frame only on agent→server
  bytes data = 2;
  bool close = 3;
}
```

Rules:
- Server → `OpenTunnel{target_id}`. Agent looks up `target_id` in **its own** discovered set; unknown → `TunnelRejected`. Agent resolves Service → endpoint, opens TCP, then calls `Tunnel` RPC with `tunnel_id` and pipes bytes.
- The agent never inspects or terminates TLS. The server speaks TLS **end-to-end** with the target. If the target has no TLS, the target gets a `tls.missing` security finding (shown as "TLS: No" badge) and, in `e2e-tls` mode, **no password crosses a non-TLS connection**: PostgreSQL is allowed only when the server asks for SCRAM-SHA-256 (checked before the password is sent; cleartext/MD5 are refused), ClickHouse and Vault/OpenBao are refused. The error names both ways out: enable TLS on the target, or switch the cluster to `compressed`. Target certificates are verified against the configured target CA bundle (and per-target CAs); public CAs only with `targetTLS.systemRoots`. The TLS name (`olympos.io/tls-server-name`) is pinned when the target is first seen; a later change is held until an admin of the cluster accepts it (security review v0.1 #1).
- **Transfer mode** (per cluster, set in Settings › Clusters & agents):
  - `e2e-tls` (**default**): server ↔ target TLS end-to-end, tunnel carries ciphertext. No tunnel compression (ciphertext does not compress).
  - `compressed` (opt-in): server connects to the target **without TLS**; agent ↔ target is plaintext inside the cluster; `TunnelFrame` payloads are zstd-compressed on the mTLS gRPC stream. Intended for clusters where egress is billed (e.g. AWS). Enabling it creates a `transfer.compressed_mode` finding on that cluster (agent can see backup data in this mode). UI shows the trade-off before enabling.
  - ClickHouse native protocol compression (zstd/LZ4) is used in both modes.
- Each backup run records `wire_bytes` (bytes that crossed the tunnel). The UI shows an **estimated monthly transfer** per job (last runs × frequency) and, where a per-GB rate is configured for the cluster's provider, an estimated cost.
- **API proxy**: agent terminates a local HTTP/1.1+2 proxy per tunnel, injects its own ServiceAccount token, forwards to the in-cluster apiserver, and rejects any verb other than `GET` (incl. `watch`). Paths under `/api/v1/namespaces/*/secrets` are rejected even for GET.
- Limits: max concurrent tunnels per agent (default 16), idle timeout 5 min, max tunnel lifetime 6 h (long backups).
- Heartbeat: Ping every 15 s; agent considered **offline** after 60 s without traffic.
- Server side, tunnels are exposed to workers as a `net.Conn` (`gateway.Dial(ctx, clusterID, targetID)`), so engines use normal drivers/clients.

---

## 8. Data model (PostgreSQL)

All tables have `id uuid pk`, `created_at`, `updated_at` unless noted. Append-only tables have no update/delete grants for the app role.

```
clusters(id, name, labels jsonb, provider, provider_override, region, api_version,
         status[pending|online|offline|revoked], last_seen_at, agent_version,
         bench_enabled bool, cert_serial, transfer_mode[e2e-tls|compressed] default 'e2e-tls',
         egress_rate_per_gb numeric null)
enroll_tokens(id, cluster_id, token_hash, expires_at, used_at)
nodes(cluster_id, name, provider_id, kubelet_version, region, zone, instance_type,
      cpu_capacity, mem_capacity, roles text[], ready bool, seen_at)   -- pk(cluster_id,name)

targets(id text pk /*target id*/, cluster_id, namespace, service, port, engine
        [postgresql|clickhouse|vault|openbao], vault_provider, tls_server_name,
        detected_version, tls_ok bool, status[candidate|configured|gone], first_seen_at, last_seen_at)

credentials(id, kind[stored|keyvault_ref], keyvault_name, secret_name,
            ciphertext bytea, wrapped_dek bytea, kek_version, username)   -- stored never returned by API

destinations(id, name, kind[azure_blob], account, container, prefix,
             auth[managed_identity|sas_token], sas_credential_id null, sas_expires_at null)

destination_groups(id, name, description)                          -- §10.3.2
destination_group_members(group_id, destination_id, position)      -- 2 to 4 per group

backup_jobs(id, target_id, credential_id, destination_id null, destination_group_id null, engine_options jsonb,
            cron, timezone, retention jsonb, enabled, notify_channel_id, created_by)  -- exactly one destination target
backup_runs(id, job_id, trigger[schedule|manual|test], status[queued|running|succeeded|partial|failed|missed],
            started_at, finished_at, bytes, wire_bytes, blob_path, sha256, error,
            repair_of null, destination_ids uuid[], not_before null)  -- append-only after finish
backup_run_copies(run_id, destination_id, status[succeeded|failed], blob_path, bytes, sha256, tier, error,
                  started_at, finished_at)  -- one per destination written; append-only

vaults(id, target_id, provider, version, kv_mounts jsonb, auth_method[approle],
       role_id, secret_id_ref /*key vault*/, configured_by, configured_at, status)
vault_secret_index(vault_id, mount, path, keys text[], current_version, updated_time, managed bool)

change_requests(id, vault_id, maker_principal_id, justification, status
                [pending|approved|applied|rejected|expired|failed], expires_at,
                checker_principal_id, decided_at, decision_comment, applied_at, failure)
change_items(id, cr_id, mount, path, key null, op[create|replace|delete|destroy_history], base_version int,
             sealed_value bytea, wrapped_dek bytea, hmac_fingerprint text)   -- sealed_value nulled after apply/expire
change_events(id, cr_id, at, actor_principal_id, kind, details jsonb)       -- append-only

audit_schedules(id, tool[kubescape|polaris|kube-bench], frameworks text[], scope_selector,
                cron, enabled, notify_channel_id)
audit_runs(id, schedule_id, cluster_id, status, started_at, finished_at, score, raw_blob_path)
findings(id, source[kubescape|polaris|kube-bench|kyverno|netpol|tls|vault-drift],
         cluster_id, control_id, severity, resource_ref, title, first_seen_run_id,
         last_seen_run_id, resolved_run_id, status[open|resolved])

images(digest pk, repo, tags text[], last_scanned_at, critical, high, medium, low, scan_status)
image_usage(digest, cluster_id, namespace, workload_kind, workload_name, container, seen_at)
image_vulns(digest, cve_id, severity, package, installed, fixed_in)
registries(id, host_pattern, credential_id)

principals(id, tenant_id, object_id, upn_snapshot, display_name_snapshot, user_type,
           account_enabled, synced_at)                                   -- unique(tenant_id, object_id)
grants(id, principal_id, role, scope_selector, granted_by, granted_at, revoked_at, stale bool)

notification_channels(id, kind[slack], slack_channel_id, name)
notification_routes(id, event_type, channel_id)
outbox(id, event_type, payload jsonb, created_at, attempts, next_attempt_at, delivered_at)

activity_log(id, at, actor_principal_id, action, object_type, object_id, details jsonb)  -- append-only
sessions(id, principal_id, created_at, last_seen_at, expires_at, csrf_token)
```

---

## 9. Secret handling (MUST)

- **Envelope encryption** for anything stored: random 256-bit DEK per record, AES-256-GCM; DEK wrapped with Key Vault key `kekName` (`wrapKey`/`unwrapKey`). Store `wrapped_dek` + `kek_version`.
- **Key Vault references** (`kv://<vault>/<secret>`) are resolved at use time with Managed Identity and never persisted. Because Olympos' identity can read the whole vault, references users enter are limited (security review v0.1 #2): Olympos' own secrets (HMAC key, DSN, OIDC client secret, Slack token, AppRole `secret_id`s) are never resolved for a user; global admins may reference any other secret; everyone else only what a `keyVault.references` rule (glob on `<vault>/<secret>` + cluster label scope) allows for the target's cluster.
- Plaintext secrets live only in memory, for the shortest time; zero byte slices after use where practical.
- **Logging**: a redaction layer; credentials, tokens, SAS, Vault tokens and change values MUST never be logged or returned by the API. Add a test that greps logs in integration tests for known fake secrets.
- **HMAC fingerprints** (for change requests): `HMAC-SHA256(hmac_key, value)` → display first 12 hex chars as `hm:xxxx·xxxx·xxxx`. `hmac_key` from Key Vault. Never a plain hash.
- Vault **root tokens are never stored** (§11.1).

---

## 10. Backups

### 10.1 Flow
Candidates (auto-discovered) → **Configure wizard** (4 steps: Target · Credentials · Destination & schedule · Review & test run) → job enabled.
- Step 1 shows target, detected version, TLS status.
- Step 2: credential source = Key Vault reference (default, recommended) or Stored in Olympos; username; DB list. "Test connection" runs a real check through the tunnel and shows privileges.
- Step 3: destination **or destination group** (§10.3.2), cron + timezone, retention, notification channel; shows next run times.
- Step 4: summary + **dry run** (small test backup, e.g. schema-only for Postgres) before "Enable".

### 10.2 Engines

| Engine | How | Data path |
|---|---|---|
| PostgreSQL | Server worker runs `pg_dump -Fc` (per DB) and `pg_dumpall --globals-only` against `tunnel` (local listener → `gateway.Dial`). pg_dump major version chosen from `SHOW server_version_num` (must be ≥ server major). Note: the PostgreSQL wire protocol is uncompressed; `-Fc` compresses on the server side. Use transfer mode `compressed` to reduce egress. | target → agent → server → Blob (streamed, no temp file) |
| ClickHouse | Server connects over the **native protocol** (9440 TLS / 9000) via tunnel with network compression `zstd`. Backup = schema (`SHOW CREATE` for databases/tables) + data per table/partition (`SELECT * … FORMAT Native`), streamed into a tar-like archive in Blob with a manifest. Large tables are split by partition. ClickHouse **never** gets a Blob credential. | target → agent → server → Blob |
| Vault / OpenBao (raft) | `GET /v1/sys/storage/raft/snapshot` via tunnel with the Olympos AppRole token (policy below). Streamed to Blob. Snapshot data is encrypted by Vault's barrier. | target → agent → server → Blob |

> ClickHouse logical backup is slower than native `BACKUP` for very large datasets. A later option (v2) is an S3-compatible ingest endpoint on the server so ClickHouse `BACKUP TO S3(...)` can target Olympos itself, still keeping the server as the only Blob writer.

Snapshot policy (part of the Olympos Vault policy):
```hcl
path "sys/storage/raft/snapshot" { capabilities = ["read"] }
```

### 10.3 Destination (Azure Blob)
**Exactly two auth options** in the UI (Settings › Destinations), nothing else:

| Option | How | Notes |
|---|---|---|
| **Managed Identity** (recommended, preselected) | Server's user-assigned MI with a custom data-plane role on the container | Allows `allowSharedKeyAccess=false` on the storage account |
| **SAS token** | Customer pastes a container-scoped SAS; stored as a credential (envelope-encrypted or Key Vault ref) | Required permissions: `r` `c` `w` `t` (read, create, write, tag). **No `d` (delete), no `l` needed.** Expiry parsed from `se` and stored; `sas.expiring` event 14 and 3 days before expiry; runs fail fast with a clear error after expiry. Account/service SAS needs shared key enabled on the account; documented. |

Both options are used **only by the server**. No SAS or Blob credential is ever sent to a cluster.

- Layout: `{prefix}/{cluster}/{namespace}/{service}/{engine}/{YYYY}/{MM}/{DD}/{run_id}.{ext}` + `{run_id}.manifest.json` (sha256, size, wire_bytes, engine, versions, started/finished, job id).
- **Retention is done by Blob Lifecycle Management, not by the server.** The server writes blob index tag `olympos-tier=daily|weekly|monthly` on each backup (GFS promotion decided at write time). Lifecycle rules (rendered by the install docs / optional Bicep module) delete by tag + age. The server has **no delete permission**.
- Validation on save: "Test destination" writes and reads a small probe blob, sets a tag, and verifies that **delete is refused** (warns if the credential can delete).

### 10.3.1 Storage account hardening (install guide + optional Bicep module)
1. Public network access **disabled**; access only via **Private Endpoint** in the server's VNet.
2. MI option: `allowSharedKeyAccess = false`.
3. Data-plane RBAC only for the server MI, custom role: `blobs/read`, `blobs/write`, `blobs/add/action`, `blobs/tags/read`, `blobs/tags/write` — **no `blobs/delete`**. No human data-plane roles; break-glass via PIM time-bound assignment.
4. Blob **versioning + soft delete + version-level immutability (time-based retention)** ≥ the longest retention tier.
5. Resource lock `CanNotDelete` on the storage account.
6. Azure Policy: deny public network access and shared key re-enablement (MI option).
7. Diagnostic logs → Log Analytics; alert on any data-plane operation by a principal other than the server MI.

### 10.3.2 Destination groups
A **destination group** is a named, ordered list of **2 to 4 destinations** of any kinds (Azure Blob, S3, NFS mixed freely), managed in Settings › Destinations › Groups with the same permissions as destinations. A backup job, and the built-in `olympos-self` job, writes to exactly one destination **or** one group.

- **One dump per run, written to every member.** The engine runs once; the server streams its output to all members at the same time (still no temp file, §10.2). The sha256 and size are computed once, so every copy of a run has the same bytes, and each copy is verified against them.
- **Same location refused.** Two members that would write to the same place (same kind and endpoint, account and container, bucket, or NFS path, and the same prefix) are refused when a group is saved and when a member destination is edited.
- **Per-copy results.** Each destination's result is stored (`backup_run_copies`: blob path, bytes, sha256, tier, error, times) and shown on the run. Every copy has its own `{run_id}.manifest.json` next to its blob, with `destination` (name, kind) and `group` (name, members in order).
- **Retention is unchanged:** lifecycle rules in each storage, by the `olympos-tier` tag (§10.3). The GFS tier is decided **per destination** (it counts that destination's successful scheduled copies of the job), so copies of one run can carry different tiers and a destination that missed copies still gets its weekly and monthly ones.
- A destination in a group, or a group used by a job, cannot be deleted. A member added later receives only new runs; existing backups are not copied to it.
- The restore guide is built per copy: the reader picks the copy, the commands use that copy's destination (§10.4).

### 10.4 Restore
Out of scope for v1 UI, but manifests MUST contain everything needed to restore. Document manual restore commands per engine in `docs/restore.md`. For a destination group run, every successful copy is a full backup; the restore guide offers each one, including copies completed later by a repair run (§10.5), which come from a later dump and have their own run id and sha256.

### 10.5 Scheduler
- Single active scheduler via Postgres advisory lock (multiple server replicas allowed).
- Loop every 30 s: compute due runs from cron + timezone, insert `backup_runs(queued)` idempotently (unique on job_id + scheduled_for).
- Workers pull queued runs with `SELECT … FOR UPDATE SKIP LOCKED`. Concurrency limits: global and per cluster.
- **Missed runs**: on startup and each loop, any scheduled_for in the past with no run → `missed` + `backup.missed` event.
- Cluster offline at run time → run `failed` with reason `agent_offline`.
- **Run status from copies** (§10.3.2): every copy written → `succeeded`; at least one written and at least one not → `partial`; none written, or the engine failed → `failed`. `partial` is never shown or counted as a success: it has its own badge, its own event (`backup.partial`, warning) and its own count in the 24-hour summaries, which count original runs only (a partial run counts as succeeded once a repair has written its missing copies). It does count as a restorable backup for "last backup".
- **Repair runs.** After a `partial` run, up to three repair runs are queued one after the other, spaced out: the first starts 5 minutes after the partial run, the second 30 minutes after the first, the third 2 hours after the second (`backup_runs.not_before`; workers leave a queued run alone until then). Each must start inside the job's retry window (half the interval to the next activation, as for agent disconnects); a repair that would start later is not queued. A repair dumps again and writes **only** to the destinations without a copy that the job still writes to. It keeps the original run's `trigger` and `scheduled_for` (so each copy gets the tier it would have had) and points at the original run with `repair_of`. A repair that ends `partial`, `failed` or `missed` queues the next one while the delays and the window allow. An agent disconnect during a repair follows the disconnect rule: a repair whose attempt is below 3 is retried after a disconnect (that retry is the same repair); later ones end `missed` without `backup.missed` and continue the repair chain as after a `failed` repair (next repair, or `backup.failed` when none is left). A repair waiting for its start does not block a manual or test run of the job. A repair that comes due while its job is disabled or paused does not run: it ends `failed` (`skipped: the job is disabled` / `skipped: the job is paused`), sends nothing and queues no further repair. The partial run stays `partial` as the record of what happened. A repair that writes every missing copy emits `backup.succeeded` (opt-in) with `repair_of`; one that gives up emits `backup.failed` with `repair_of` and the missing destinations. Test runs are never repaired; a run that fails entirely is not retried (unchanged).
- **Stall detection.** A member that accepts no data for 10 minutes, or does not finish within 10 minutes after the end of the stream, is detached as `stalled` and its copy fails; the other members go on (the slowest live member sets the pace, nothing is buffered without bound). An upload that does not return within 30 seconds of being detached (a write blocked in the kernel on a hard NFS mount) is abandoned: the run finishes without it and the stuck upload stays in the server process until the kernel returns or the server restarts. When every member has failed, the engine is stopped and the run fails.

### 10.6 Dead man's switch
After every scheduler loop, if `deadMansSwitch.url` set, `GET` it. If Olympos itself is down, the external monitor alerts (e.g. Heimdall/UptimeRobot-style). Documented as strongly recommended.

---

## 11. Vaults (HashiCorp Vault & OpenBao)

### 11.1 Configure (root token used once, never stored)
1. Admin opens a discovered vault → "Configure" → pastes root token (or a token with equivalent sys privileges).
2. Server, over the tunnel, creates:
   - policy `olympos` (below),
   - AppRole `olympos` bound to that policy, `secret_id_ttl=720h`, `token_ttl=1h`, `token_max_ttl=24h`,
   - reads `role_id`, generates `secret_id`; stores `secret_id` in **Key Vault** (`secret_id_ref`).
3. Server verifies the AppRole login works, then **discards the root token from memory**. Root token never touches DB, logs or Key Vault.
4. Server rotates `secret_id` monthly (generate new → store → destroy old accessor).
5. UI text: "Root token is used once to set up access and is not stored."

```hcl
# olympos policy — <mount> repeated per managed KV v2 mount
path "<mount>/metadata/*" { capabilities = ["list", "read"] }   # path tree, versions
path "<mount>/subkeys/*"  { capabilities = ["read"] }           # key names, values returned as null
path "<mount>/data/*"     { capabilities = ["create", "patch"] } # NO read, NO update
path "<mount>/destroy/*"  { capabilities = ["update"] }         # destroy_history op only
path "sys/mounts"         { capabilities = ["read"] }
path "sys/storage/raft/snapshot" { capabilities = ["read"] }
```

> **Values are unreadable at the Vault level.** Key names come from the KV v2 `subkeys` endpoint (values are `null`); all changes are JSON merge `PATCH` (no read needed). The Olympos token **cannot read any secret value**, even if the server is compromised. Requires Vault ≥ 1.10; OpenBao support to be verified by an e2e test in M3.
>
> KV v1 mounts: no `subkeys`/`patch`. KV v1 is shown as **read-only, keys not listed** with a notice "Upgrade to KV v2 to manage this mount". (No `read` capability on KV v1 data is ever requested.)

### 11.2 Browsing
- KV v2 mounts: path tree (metadata list), keys per secret (subkeys), version and updated time (metadata). Values rendered as `••••••••`.
- Index refreshed every 10 min and on demand → `vault_secret_index`.

### 11.3 Changes → maker/checker (§11.4)
A KV v2 secret is one JSON map at a path; every write creates a new **version** of the whole map. All operations are applied with `PATCH <mount>/data/<path>`, `Content-Type: application/merge-patch+json`, and `options.cas = base_version` (fails if someone changed the secret after the request was opened).

| Op | Payload `data` | Result |
|---|---|---|
| `create` (key) | `{"KEY": "<value>"}` | New version with the key added |
| `replace` | `{"KEY": "<value>"}` | New version with the key's value replaced |
| `delete` (key) | `{"KEY": null}` | New version **without** the key (merge patch removes nulls) |
| `create` (new secret path) | `POST <mount>/data/<path>` with `options.cas = 0` | Version 1 |
| `destroy_history` | `POST <mount>/destroy/<path>` `{"versions":[…]}` | Permanently destroys the listed **whole versions** (all keys in them). Irreversible. |

- Multiple items per change request allowed (e.g. rotate two keys at once); items on the same path are merged into **one** PATCH → one new version.
- **Deleting a key does not erase its old value:** previous versions still contain it. The UI says so in the delete dialog and offers `destroy_history` as a separate, explicit operation (red warning, lists affected versions and that every key in those versions is destroyed; still maker/checker).

### 11.4 Approvals (maker/checker) — MUST
State machine:
```
pending ──approve──▶ approved ──▶ applying ──apply ok──▶ applied
   │                                  └──apply err──▶ failed (e.g. cas conflict)
   ├──reject──▶ rejected
   └──ttl──▶ expired
```
- Vault write and DB commit are not atomic, so the apply is two transactions around the Vault call: (1) `approved → applying` committed with `change_events`, (2) `applying → applied` with the resulting versions, or `failed`. The vault lock is held across both. A **reconciler** (every minute, leader only) settles requests left in `applying` for more than 2 minutes from the KV metadata: version `base+1` created after `applying` → `applied` (`cr.applied_reconciled`); version still `base` → `failed` (`apply_unknown`, retry with a new request); anything else → `failed` (`conflict`). Drift detection skips paths of requests in `applying`.
- Maker ≠ checker, compared by `(tenant_id, object_id)`. **No role bypasses this, including admin.**
- Checker needs `vault-approver` in scope of the vault's cluster; maker needs `vault-maker`.
- New values sealed with envelope encryption at submit; **sealed_value set to NULL** on applied/rejected/expired/failed (kept while `applying`).
- TTL default 72 h (configurable).
- Checker sees: vault, path, key, op, HMAC fingerprint, base version, justification, maker. Never the value.
- UI: change request form is a **right-side drawer** on the Vaults page with "New value" + "Confirm value".
- Slack `cr.opened` notification contains a **link only** — no approve/reject buttons.
- Every transition → `change_events` + `activity_log`.

### 11.5 Drift detection
- Every 10 min: compare `current_version` per secret in `vault_secret_index` with versions produced by applied change requests. A new version not produced by Olympos → finding `vault-drift` ("Unmanaged change") + event `vault.unmanaged_write`.
- Break-glass is outside Olympos (direct Vault access via `generate-root`), documented in `docs/runbooks/vault-break-glass.md`; drift detection makes it visible.

---

## 12. Audit

### 12.1 Kubescape & Polaris (remote)
- Server runs `kubescape scan framework <nsa,cis,mitre> --format json` / `polaris audit --format json` with a generated kubeconfig whose server URL is a local listener bound to `gateway.OpenAPIProxy(cluster)` (read-only proxy, §7). No cluster token ever reaches the server.
- Raw JSON → Blob (`audit/{cluster}/{tool}/{run_id}.json`, retention 400 days). Normalized → `findings`.

### 12.2 Diff
- A finding key = `(source, cluster, control_id, resource_ref)`. New = not open in previous run; resolved = open previously, absent now.
- Event `audit.new_findings` only when new > 0 (summary + link).

### 12.3 kube-bench (opt-in exception)
kube-bench must read node files, so it runs as a **Job per node**. Constraints (MUST):
1. **Job spec is compiled into the agent.** Server can only send `RunBench{run_id, node_name, benchmark}`. Agent validates `node_name` exists and `benchmark` is in an allowlist.
2. Image `aquasec/kube-bench` **pinned by digest** in the agent build. Upstream images are unsigned: each release copies the pinned index to `ghcr.io/warewave-technology/kube-bench` and signs it with the release identity; `bench.imageRepository` pulls the same digest from that or another mirror (§18; `docs/install.md` › The kube-bench image).
3. Pod: `hostPID: true`, host paths mounted **read-only** (`/etc/kubernetes`, `/var/lib/kubelet`, `/var/lib/etcd` if present, `/etc/systemd`, `/usr/bin` for binaries), no added capabilities, `nodeName` set, tolerations for control-plane taints, `ttlSecondsAfterFinished: 300`, `activeDeadlineSeconds: 600`.
4. Namespace `olympos-bench` with PSA label `pod-security.kubernetes.io/enforce: privileged`; `olympos-system` stays `restricted`. If Kyverno policies would block the bench pods, the chart renders a `PolicyException` limited to that namespace (+ image) — opt-in, see §13.1.
5. RBAC for this (Role in `olympos-bench`: `jobs` create/get/list/delete, `pods` get/list, `pods/log` get) is **rendered only when `bench.enabled=true`**. Agent advertises the capability in `Hello`.
6. Parallelism ≤ `bench.maxParallel`.
7. Result: agent reads pod log (kube-bench `--json`), streams via `BenchResultChunk`, deletes Job.
8. Benchmark auto-selection by provider: AKS → `aks-*`, EKS → `eks-*`, GKE → `gke-*`, on-prem → `cis-*` (master on control-plane nodes, node elsewhere), OKE/others → generic `cis-*` node.
9. Managed clusters: control plane checks are shown as **"Control plane N/A · managed"**, never as missing/failed.

---

## 13. Security

### 13.1 Kyverno
- Agent watches `ClusterPolicy`/`Policy` (legacy `kyverno.io/v1`, Kyverno ≤ 1.19) and the CEL policies of `policies.kyverno.io/v1` — `ValidatingPolicy`, `NamespacedValidatingPolicy`, `ImageValidatingPolicy`, `NamespacedImageValidatingPolicy` (Kyverno ≥ 1.17; 1.20 no longer runs the legacy kinds) — with kind, name, mode `Enforce|Audit` (CEL: `validationActions` containing `Deny` → Enforce) and rules, plus `PolicyReport`/`ClusterPolicyReport` results. Failures → findings (`source=kyverno`). Discovery decides which APIs are watched; either set alone counts as "Kyverno installed".
- The kube-bench Kyverno exception (§12.3.4) is opt-in per API: `kyverno.io/v2` for legacy policies, `policies.kyverno.io/v1` (requires explicit policy refs) for CEL policies.

### 13.2 NetworkPolicy
- Finding `netpol.no_default_deny` for each namespace without a policy that selects all pods (`podSelector: {}`) with `policyTypes` including Ingress and no ingress rules. System namespaces excluded by configurable list.

### 13.3 Images
- Inventory from `status.containerStatuses[].imageID` (digest) + image string; dedupe by digest.
- Scanner: `trivy image --format json` on the server, pulling via **registry credentials stored in Olympos** (`registries`, matched by host pattern). Agent never reads `imagePullSecrets` (the opt-in Secret inventory records their *names* only).
- Digest without matching credential → status "Missing credential" in UI.
- Rescan: new digests immediately; all digests daily after trivy DB update. Trivy DB mirrored by the server (supports restricted networks).
- Event `vuln.critical` for new critical CVEs in running images.

### 13.4 TLS findings
- Target without TLS → `tls.missing` finding.

### 13.6 Kubernetes Secret inventory (opt-in, key names only)
- Helm `secretsInventory.enabled: false` by default. Only when true the ClusterRole gets `secrets: [list, watch]` (no `get`) and the agent advertises `secrets_inventory` in `Hello`. Kubernetes RBAC has no "metadata only" permission: that token could read values with a normal request, hence opt-in (`docs/security-model.md`).
- The agent lists/watches Secrets **only** through the metadata client (PartialObjectMetadata); key names come from `managedFields` (`f:data` / `f:stringData`), else `keys_unknown` — never a full read. Annotations are dropped (kubectl's last-applied-configuration contains the data). A test fails if any other client touches Secrets (the agent's own identity Secret excepted).
- Reported per Secret: namespace, name, inferred type, key names, labels, owners, creation time and the workloads/ServiceAccounts that reference it — by **name** from pod specs (`env[].valueFrom.secretKeyRef.name`, `envFrom[].secretRef.name`, secret and projected volumes, `imagePullSecrets`); extends deviation #16.
- Findings `source=k8s-secrets`: `secret.unused` (low, no reference for 7 days), `secret.unmanaged` (info, configurable: not owned by External Secrets / Vault Secrets Operator / sealed-secrets / cert-manager), `secret.legacy_sa_token` (medium). Security › *Kubernetes secrets*. Olympos does not delete Secrets.

### 13.5 Sensitive data in ConfigMaps
- The **agent** scans ConfigMap values (informer transform on add/update, full re-scan every 6 h) with the gitleaks rules (library, embedded and versioned in the agent build) plus key-name heuristics (`password`, `passwd`, `secret`, `token`, `apikey`, `private_key`, `connection_string`, `dsn`, …). System namespaces (same list as NetworkPolicy, `sensitiveData.excludeNamespaces`) and `kube-root-ca.crt` are skipped. Values never leave the cluster and never enter the informer cache.
- `SensitiveDataReport` carries namespace, ConfigMap, key, rule id/description, confidence (`high` = credential pattern, `medium` = key name only) and value length (rounded up to a power of two) — **never the value, a prefix/suffix or a hash** (proto test).
- Findings `source=sensitive-data`, `control_id=<rule id>`, severity high/medium; resolved when the key disappears or no longer matches. Event `sensitive_data.found` (new findings only, one per cluster per scan). UI: Security › *Sensitive data*. Olympos never edits or deletes ConfigMaps.

---

## 14. Notifications

- Slack app (bot token in Key Vault, `chat:write` scope). Channel objects defined once, reused by any module.
- **Event catalog** (v1): `backup.failed`, `backup.partial`, `backup.missed`, `backup.succeeded` (opt-in), `cr.opened`, `cr.approved`, `cr.rejected`, `cr.expired`, `cr.failed`, `vault.unmanaged_write`, `audit.new_findings`, `vuln.critical`, `agent.offline`, `agent.online`, `grant.changed`, `grant.stale`, `sas.expiring`.
- Routing: `notification_routes(event_type → channel)`; jobs/schedules can override with their own channel.
- **Transactional outbox**: events written in the same DB transaction as the state change; a dispatcher delivers with retries + backoff. At-least-once; messages carry an idempotency key.
- Messages: Block Kit, short, with a link to the object. **No interactive buttons.** Never include secret values, fingerprints are fine.
- Internal `Sink` interface so Teams/email can be added later.

---

## 15. UI

- **Mockups are in `docs/design/`** — open the `.html` files in a browser; they link to each other through the sidebar:

**v1 screen set is complete: build every screen below.** Start from `login.html` or `dashboard.html`; the sidebar and buttons link the screens together.

| File | Screen | Spec |
|---|---|---|
| `login.html` | Sign in with Microsoft | §3.1 |
| `dashboard.html` | Fleet overview, Needs-attention strip, version matrix, providers, clusters | §6 |
| `dialog-add-cluster.html` | Add cluster: name, labels, bench opt-in, Helm command with one-time token, waiting state | §2.2, §4.4 |
| `backups.html` | Candidates, recent runs | §10 |
| `backup-wizard-1-target.html` | Wizard 1: discovered target, TLS, annotation | §5, §10.1 |
| `backup-wizard-2-credentials.html` | Wizard 2: Key Vault ref / stored, connection test | §10.1 |
| `backup-wizard-3-schedule.html` | Wizard 3: destination, cron presets, timezone, GFS retention, notify | §10.1, §10.3 |
| `backup-wizard-4-review.html` | Wizard 4: summary, dry run checklist, enable | §10.1 |
| `vaults.html` | Instances, path tree, keys, change-request **drawer**, Delete action | §11 |
| `dialog-vault-configure.html` | Root token used once, what gets created, KV mounts (v1 read-only) | §11.1 |
| `dialog-vault-delete-destroy.html` | Delete key (history warning) and Destroy history (irreversible, type to confirm) | §11.3 |
| `approvals.html` | Checker view of a change request, trail | §11.4 |
| `audit.html` | Schedules, kube-bench per node (control plane N/A on managed), run history, new findings | §12 |
| `activity-log.html` | Append-only activity log with filters | §17 |
| `security.html` | Images by digest, Kyverno, NetworkPolicy | §13 |
| `settings.html` | Access grants (by object ID), notification channels & routing | §3.2, §14 |
| `dialog-grant-access.html` | Person search (guest flagged), roles, scope by labels | §3.2 |
| `settings-destinations.html` | Managed Identity / SAS token, parsed SAS checks, destination test | §10.3 |
| `settings-registries.html` | Registry credentials for scanning, unmatched images | §13.3 |
| `settings-clusters.html` | Labels, provider override, transfer mode trade-off, egress estimate, bench state, revoke | §6, §7, §12.3 |
| `logo.html` + `logo*.svg`, `app-icon.svg` | Brand sheet and logo files | §15 |

- Mockups are **static visual references**: match layout, hierarchy, copy and tokens; sample data is illustrative. Build real components from the tokens below, not by copying mockup markup.
- States not drawn (empty lists, loading, errors, permission-denied) follow the same style: empty states explain what to do next ("No clusters yet — Add cluster"), errors say what failed and how to fix it, and controls a user's role does not allow are hidden, not disabled (except Approve on one's own request, which is disabled with the reason shown).
- **Theme: Gruvbox dark.** Tokens:

```css
:root {
  --bg-page: #1d2021;   --bg-surface: #282828;  --bg-raised: #3c3836;
  --bg-hover: #32302f;  --border: #3c3836;      --border-strong: #504945;
  --fg: #ebdbb2;        --fg-strong: #fbf1c7;   --fg-muted: #a89984;  --fg-nav: #bdae93;
  --accent: #fabd2f;    --accent-strong: #d79921;  /* primary buttons: bg #d79921, text #1d2021 */
  --link: #83a598;      --link-hover: #8ec07c;
  --ok-fg: #b8bb26;  --ok-bg: #2f3317;
  --warn-fg: #fabd2f; --warn-bg: #3d3014;
  --crit-fg: #fc7f6f; --crit-bg: #3c1f1e; --crit-border: #cc241d; /* #fb4934 only for large numbers */
  --info-fg: #83a598; --info-bg: #273436;
  --orange: #fe8019;
}
```
- Fonts: Inter (UI), JetBrains Mono (technical values: names, versions, digests, paths), Space Grotesk 700 (wordmark only).
- Logo: **container summit** — six isometric containers stacked into a mountain (3-2-1), the top container gold, orange horizon line underneath. Files in `docs/design/`: `logo.svg` (dark UI), `logo-light.svg`, `logo-mono.svg` (uses `currentColor`), `app-icon.svg` (rounded square, favicon/PWA). Copy them to `web/src/assets/`. Wordmark: "olympos" in lowercase, Space Grotesk 700, letter-spacing -0.03em.
- Accessibility: WCAG AA contrast, real `<button>`/`<a>`/`<label>`, keyboard navigable drawer with focus trap, `aria-label` on icon buttons.
- Status is never color-only: badges always have text.
- Secret values: rendered as `••••••••` with `aria-label="Value hidden"`; no reveal control exists.

---

## 16. REST API (v1, JSON, OpenAPI 3.1 in `docs/openapi.yaml`)

```
GET    /api/v1/me
GET    /api/v1/dashboard
GET    /api/v1/clusters                 POST /api/v1/clusters (returns install cmd)
GET    /api/v1/clusters/{id}            PATCH (labels, provider override)   DELETE (revoke)
GET    /api/v1/targets?status=candidate&engine=
GET    /api/v1/backup/jobs              POST   PATCH /{id}   DELETE /{id}
POST   /api/v1/backup/jobs/{id}/run     POST /api/v1/backup/test-connection
GET    /api/v1/backup/runs
GET    /api/v1/destinations             POST   PATCH   DELETE
GET    /api/v1/vaults                   POST /api/v1/vaults/{id}/configure  (root token in body, TLS only)
GET    /api/v1/vaults/{id}/tree         GET  /api/v1/vaults/{id}/secrets/{path}  (keys + versions only)
POST   /api/v1/change-requests          GET  /api/v1/change-requests?mine=&waiting_for_me=
POST   /api/v1/change-requests/{id}/approve   /reject   /cancel
GET    /api/v1/audit/schedules          POST PATCH DELETE   POST /{id}/run
GET    /api/v1/audit/runs               GET /api/v1/findings?source=&status=&cluster=
GET    /api/v1/images                   GET /api/v1/images/{digest}
GET    /api/v1/registries               POST PATCH DELETE
GET    /api/v1/principals/search?q=     (Graph lookup)
GET    /api/v1/grants                   POST   DELETE /{id}
GET    /api/v1/notifications/channels   POST PATCH DELETE
GET    /api/v1/notifications/routes     PUT
GET    /api/v1/activity
```
- Authorization enforced in middleware + per-handler scope checks (cluster labels). 403 responses never leak object existence outside scope.

---

## 17. Olympos's own operability

- `/metrics` (Prometheus): agents online, tunnel count, backup run durations/results, backup copies per destination and result, scheduler lag, outbox backlog, CR counts.
- `/healthz`, `/readyz`. Structured JSON logs (slog) with redaction.
- Every user action → `activity_log`.

---

## 18. Security checklist (CI should enforce where possible)

- [ ] Agent RBAC matches §4.2 exactly (golden-file test on rendered Helm templates).
- [ ] No code path sends a credential to the agent (review + test: agent proto has no credential fields).
- [ ] Tunnel open with unknown target_id is rejected (unit + e2e test).
- [ ] API proxy rejects non-GET and Secret paths (test).
- [ ] Token validation checks `tid`/`iss` (test with foreign-tenant token).
- [ ] Maker cannot approve own CR, admin included (test).
- [ ] Sealed values nulled after terminal state (test).
- [ ] No secret strings in logs (integration test with canaries).
- [ ] Images distroless, non-root, read-only FS; SBOM + cosign signature (signatures and attestations only while the repository is public, see `docs/spec-changes.md` F7).
- [ ] Root token never persisted (code review + grep test).
- [ ] Olympos Vault policy has no `read` on `<mount>/data/*` (e2e: reading a value with the Olympos token returns 403).
- [ ] No Blob credential or SAS appears in any agent message (proto review + test).
- [ ] Destination test refuses to save silently when the credential can delete (warning shown).
- [ ] `compressed` transfer mode always produces a visible finding.

---

## 19. Milestones

1. **M1 — Skeleton:** repo, CI, Helm charts, Entra login (BFF), principals/grants, agent enrollment + mTLS, inventory, Dashboard incl. attention strip.
2. **M2 — Notifications + Backups:** outbox + Slack, destinations, tunnel, Postgres engine, wizard, scheduler, missed-run detection, dead man's switch.
3. **M3 — Vaults + Approvals:** configure (AppRole), browsing, change requests, maker/checker, drift detection, Vault/OpenBao snapshot backups.
4. **M4 — Audit:** API proxy, kubescape, polaris, diff, kube-bench exception.
5. **M5 — Security:** Kyverno, NetworkPolicy, image inventory, trivy, registries.
6. **M6 — ClickHouse backups, hardening, docs** (install, restore, break-glass, security model).

Each milestone ends with an e2e test on kind (agent + server + Postgres + Vault dev + Azurite for Blob/Key Vault fakes where possible).

---

## 20. Open questions — resolved (owner decisions, v0.1)

1. **Hosting:** Kubernetes (Helm) **and** a systemd service on Linux (§2.1, `docs/install-systemd.md`).
2. **Olympos DB:** PostgreSQL on the same server/namespace by default (bundled), external PostgreSQL optional; backed up by the built-in `olympos-self` job (§2.1).
3. **Restore UI:** v0.1 shows ready-to-copy restore commands per successful run; a UI restore to a **new** target only (maker/checker) is planned for v0.2.
4. **Intermittent links:** full resync on reconnect (state snapshots with a generation), no diff buffering; a bounded buffer only for result-bearing work (kube-bench results, report chunks).
5. **Approvers:** one approver in v0.1 (maker ≠ checker); TTL 72 h. Multiple approvers per path: later.
