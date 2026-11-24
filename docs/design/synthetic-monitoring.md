# Synthetic monitoring (spec addendum)

Status: **implemented** (v0.3, 2026-11-24): the owner's spec of 2026-11-23, with the decisions taken in review below and
the [decisions taken during implementation](#decisions-taken-during-implementation). Tracks issue
[#46](https://github.com/Warewave-Technology/olympos/issues/46) (milestone v0.3). User documentation:
[Synthetic monitoring](../synthetic-monitoring.md); security: [Security model](../security-model.md#synthetic-monitoring-credentials-in-the-cluster);
SPEC §4.6; `docs/spec-changes.md` #21–#25.

## Decisions after review

These change or settle parts of the spec below. Where they conflict, they win.

1. **The agent keeps the probe's identity [decided].** The probe has no RBAC and no Kubernetes API access (§2.1), and the bootstrap
   token is single use (§2.2), so the probe cannot store or renew a certificate by itself. The agent enrolls the probe with
   the same token (`probe` role), writes the probe's certificate and key to the Secret `olympos-probe-identity`, and renews it
   the same way it renews its own. The probe mounts that Secret read-only and reloads it when it changes.
   - The agent's Role gains this one Secret name, with the verbs it already has for its own.
   - Cost: the probe's key passes through the agent. The agent's identity is already the more powerful of the two.
   - For existing clusters, "Install probe" creates a probe-only token. The chart puts it into `olympos-probe-identity`,
     and the agent enrolls the probe with it.
2. **Credentials are sealed to a per-connection key, not to the certificate key.** §6.2 asks for encryption to the probe's
   certificate key. That key signs (mTLS), and using one key for both signing and encryption breaks key separation. Instead,
   the probe makes an HPKE key pair (RFC 9180, Go `crypto/hpke`, DHKEM(X25519)) in memory for each `Connect` stream and sends
   the public key in its first message, inside the mTLS stream that proves who it is. The server seals each run's credentials
   to that key, with the run id and cluster id as AAD. A sealed message cannot be opened by another probe, or by the same probe
   after it reconnects. The private key never leaves memory.
3. **Identities in the gateway.** The agent's certificate keeps CN = `<cluster-uuid>`. The probe's certificate has CN =
   `<cluster-uuid>/probe`, and its serial is stored apart from the agent's (`clusters.probe_cert_serial`), so the probe can be
   revoked alone. The gateway maps each identity to its role. A probe identity may only use `ProbeGateway`, and an agent
   identity may never use it.
4. **Settled with the implementation plan [decided].**
   - **Degraded / failing.** A cluster cell is *degraded* when its last run failed but the cluster alert is not firing yet,
     and *failing* while that alert is firing.
   - **Scope.** `owner_selector` is a display label only. To make a scenario run on all clusters, a `synthetic-editor` needs
     a global grant. To make it run on a selector, they need the grant on every cluster that matches it now.
   - **Limits.** At most 120 requests per minute per scenario per cluster, and at most 2 retries for a failed step.
   - **Name resolution.** The probe resolves names as absolute names, without the search list, so short names such as
     `kubernetes` cannot get past the allowlist. In-cluster services are written in full: `svc.ns.svc.cluster.local`.
   - **Deleting what is in use.** An allowlist rule or a credential that a scenario still uses cannot be removed (409);
     the error names the scenarios.
   - **Default route.** `synthetic.allowlist_changed` gets the routes of `grant.changed` when the migration runs.
   - **Runs that count.** *Run now* counts toward alerting; only test runs from the editor never alert. Test runs are
     kept for 7 days.
   - **Upgrading without a probe token.** A `helm upgrade` without a probe token succeeds: the probe waits and the
     cluster shows "Probe: not installed" until *Install probe* is used.

## Decisions taken during implementation

Rulings P1–P26 of the implementation (in the order they were taken). Where they differ from the spec below,
they win. The user-visible ones:

| Ruling | Decision | Cost |
|---|---|---|
| P1 | The migration copies the routes of `grant.changed` to `synthetic.allowlist_changed` (decision 4). | One more route row per access channel. |
| P2 | An OAuth2 credential's token URL is checked against the allowlist and its bound hosts when saved (and must be `https://`). | None. |
| P3 | Every mockup's sidebar has *Monitoring* after *Security*, as the app has. | None. |
| P4 | "Cloud metadata" covers every cloud: Alibaba `100.100.100.200`, Oracle `192.0.0.192` and `255.255.255.255` are always denied too; `100.64.0.0/10` is not (it may hold pod or service CIDRs). | A scenario to one of these addresses is refused. |
| P5 | The request rate counts the **worst case**: a step that follows redirects counts 1 + 5 requests per attempt, every retry counts. | The caps are reached sooner. |
| P6 | Only the **current** probe certificate (serial = `clusters.probe_cert_serial`) may connect; older ones are refused. | After a renewal the probe reconnects within the kubelet sync plus a 30 s poll; this never alerts. |
| P7 | A lost renewal answer must not lock the probe out: the previous serial (`probe_prev_cert_serial`) may call `RenewCert` only, until the new certificate connects. | One more column. |
| P8 | A bootstrap token in `olympos-probe-identity` always means a newer install request: the agent enrolls with it even over a valid certificate (recovers revoked probes). | None. |
| P9 | Bound hosts travel as `<kind>:<pattern>`; one that does not parse fails the run closed (`credential_error`). | None. |
| P10 | A step whose response contains any form of a run's credential refuses all its extracts (`credential_error`). | Such a step cannot extract anything. |
| P11 | **Taint**: variables extracted from a credentialed step (or from a step that used a tainted variable) may only be used toward that credential's bound hosts, checked at save and at run time; `Range` and `If-Range` are reserved; non-text, compressed or NUL bodies give no body extracts. | A flow cannot send data derived from a credentialed step outside its bound hosts. |
| P12 | Extracts from **any** response of a host inside a credential's bound hosts are tainted with it; tainted values shorter than 4 bytes are not scrubbed; templates whose references do not parse are refused by the probe. | Credential-free steps on bound hosts also produce tainted variables. |
| P13 | Runs due after their scenario was disabled are skipped (`scenario_disabled`); runs with an expired credential end `error` (`credential_expired`). *Superseded by [credential-alerts.md](credential-alerts.md) (#54) for the expired credential: it is reported once, for the credential, and its runs no longer count toward scenario alerts.* | None. |
| P14 | A server-side credential resolution failure (Key Vault or envelope outage) ends the run **skipped** (`credential_unavailable`), not error, and is shown on the credential. *Superseded by [credential-alerts.md](credential-alerts.md) (#54): only a transient failure stays skipped, and alerts after 30 minutes; a permanent one ends `error` (`credential_broken`) and alerts at once.* | A broken credential reads skipped until its warning is acted on. |
| P15 | Saving a scenario that a rate cap would itself block is refused (enabled scenarios only). | A new scenario cannot be saved enabled on a full cluster. |
| P16 | A firing alert whose pair is no longer monitored (scenario disabled, cluster excluded, probe not installed or revoked) resolves **silently**; a deleted scenario or cluster takes its alerts with it; an offline probe keeps its alert. | None. |
| P17 | Revoking a probe on a cluster that never had one answers 409 *no probe installed*. | None. |
| P18 | Guests cannot hold `synthetic-editor`, and a guest's existing grant does not authorize editing. | B2B guests cannot edit scenarios. |
| P19 | (Process) a mechanical index fix was verified by the controller instead of a second review. | — |
| P20 | The agent starts enrolling the probe only after its own identity exists. | The probe enrolls one agent loop later. |
| P21 | The *Install probe* command appends the server's `OLYMPOS_AGENT_INSTALL_SETS`, like *Add cluster*. | None. |
| P22 | The editor has **Store response excerpts** (`store_responses`) and the scenario detail **Delete** with a confirm dialog; both are in the mockups. | None. |
| P23 | The probe's state is part of the *Status* cell of *Settings › Clusters & agents* (no extra column; no sideways scroll at 1440 px). | None. |
| P24 | `POST /clusters/{id}/probe-token` answers 409 while the cluster waits for its first agent: its *Add cluster* command already installs the probe. | None. |
| P25 | The allowlist version is a time: every change, and every server start, sets it to `greatest(version + 1, now in milliseconds)`. A database restored from an older dump is then ahead of every version a probe has seen once a server starts on it; the probe's check that versions never go back is unchanged. A probe whose certificate was renewed after the dump needs *Install probe* (P6), and credentials rotated after it must be rotated again (`docs/restore-olympos.md`). | Versions are large numbers; runs after a restore wait for a server start. |
| P26 | Only traffic on a stream of the **current** probe certificate (`clusters.probe_cert_serial`) keeps a probe online. A probe left on a certificate that was renewed (the agent could not write the new one to the Secret) gets no run (runs go only to streams of the current certificate), so it goes offline after `gateway.OfflineAfter` and `probe.offline` fires after `synthetic.probeOfflineAlertAfter`, instead of looking online while every run ends `not_dispatched`. | A normal renewal can show the probe offline for about a minute, until it reconnects; that never alerts. |

Also settled while building, and documented for users: names must be fully qualified (no search list), a
literal `${` cannot be written, `Accept-Encoding`, `Range`, `If-Range` and `Host` are reserved headers, a header
credential cannot name those, `Cookie`, `Content-Type` or the transport's headers (one list,
`spec.ReservedCredentialHeader`, checked at save and on the probe), test runs and *Run now* are each limited to
6 a minute per person, a result the server could not store ends its run skipped (`ingest_failed`), a reissued
add-cluster token enrolls no probe on a cluster that has one, and after a full outage late runs go out
together.

**Model additions** (beyond §3 below; migration `00024_synthetic_monitoring.sql`):

- `synthetic_runs.manual` (*Run now*, counts toward alerts, no slot), `test`, `test_spec`, `requested_by`,
  `allowlist_version`, `remote_ip`, `probe_ip`; unique indexes for one run per slot, **one open** scheduled run
  and **one open manual** run per scenario and cluster; finished runs are append-only (trigger).
- `synthetic_alerts.reason`, `clusters`, **`still_failing`** (cluster alerts still firing when the fleet alert
  resolved), `notified_at`, `resolved_notified_at`; one firing alert per scenario and cluster (or fleet).
- `synthetic_state` (streaks, last run, `blocked_reason`), `synthetic_hourly` (the 400-day roll-up),
  `synthetic_allowlist_version` (moved by trigger and at server start, P25), `scenario_assertions.position`.
- `clusters.probe_*` (status, version, current and previous certificate serial, expiry, last seen, offline
  since, alerted) and `enroll_tokens.roles`, `agent_used_at`, `probe_used_at`.
- Retention indexes: runs by `finished_at`, step results with an excerpt, `synthetic_hourly.hour`, and the
  `last_run_id` references; the notifier's index of unnotified alerts.

---

> New feature, independent of v0.2. Adds a **Monitoring** area (inner tabs; only **Synthetic** for now).
> A scenario is defined once in Olympos, runs from inside every cluster (minus an exclude list), and alerts a notification channel when its conditions fail.
> Mockups: `docs/design/monitoring-*.html`, `docs/design/settings-synthetic.html`, updated `dialog-add-cluster.html`. Same rules as SPEC §15 (static references, build real components from the tokens).
> Owner decisions are marked **[decided]**. Everything else is a proposal Claude Code may improve if it explains why in the PR.

---

## 1. Principles for this feature

1. **The agent does not change.** Scenarios run in a separate component, `olympos-probe`. The agent keeps its narrow, read-only role and its RBAC is unchanged.
2. **[decided] The probe is installed together with the agent** when a cluster is added (same Helm chart, `probe.enabled: true` by default).
3. **[decided] Probes may only call hosts on a global allowlist.** Admins manage it in Settings › Synthetic monitoring.
4. **[decided] Credentials for scenarios are stored encrypted in Olympos** (envelope encryption, or a Key Vault reference, same as backup credentials) and sent to the probe for a run.
   This is a **documented exception** to SPEC §0 principle 1 ("credentials never enter the cluster"), like the `compressed` transfer mode. Record it in `docs/spec-changes.md` and `docs/security-model.md`, with the mitigations in §6.
5. Monitoring results are operational data, not secrets: response bodies are optional, truncated and redacted.

---

## 2. Components

```
olympos-server ──mTLS gRPC──▶ olympos-agent   (unchanged)
      ▲
      └──────mTLS gRPC─────── olympos-probe   (new, dials out, one per cluster)
                                   │
                                   └──HTTP/DNS/TCP/TLS──▶ allowlisted hosts only
```

### 2.1 olympos-probe
- Separate Deployment in `olympos-system`, 1 replica (configurable; runs are idempotent by run id).
- Distroless, non-root, read-only root FS, all capabilities dropped, no volumes except a projected client cert Secret of its own.
- ServiceAccount with **no RBAC bindings** and `automountServiceAccountToken: false`. The probe never talks to the Kubernetes API.
- Optional NetworkPolicy (chart value `probe.networkPolicy.egressCIDRs`) to restrict egress at the network level as well.
- Dials the server's agent gateway with **its own mTLS identity**: CN = `<cluster-uuid>/probe`. The gateway gives probe identities only the synthetic RPCs (no tunnel, no inventory, no API proxy). Revoking a cluster revokes both identities; the probe can also be revoked alone.

### 2.2 Enrollment
- The Add cluster bootstrap token enrolls both identities: the agent enrolls first; the probe uses the same token within its TTL, but only for the `probe` role (token tracks `agent_used_at`, `probe_used_at`). A token cannot enroll two agents or two probes.
- Install command is unchanged; the chart contains the probe. `probe.enabled: false` opts out (cluster then shows "Probe: not installed" and is skipped by scenarios).
- Existing clusters: `helm upgrade` adds the probe; it enrolls with a fresh one-time token generated from Settings › Clusters & agents › "Install probe".

### 2.3 Protocol (new service, same gateway)
```proto
service ProbeGateway {
  rpc Connect(stream ProbeMessage) returns (stream ServerProbeMessage); // mTLS, probe identity only
}
// Server → probe: RunScenario { run_id, scenario (steps, timeouts), allowlist snapshot + version,
//                               credentials[] (only those this scenario uses, sealed per run, see §6) }
// Probe → server: RunResult { run_id, steps[] { timings, status, assertion results, extracted var names,
//                               response excerpt (optional, redacted) }, probe_version }
// Heartbeat both ways (15 s), same offline rules as the agent.
```
- Scheduling is done by the **server** (single leader, like backups): it sends `RunScenario` to every target cluster's probe at the scenario interval with jitter (±10 % of interval) so all clusters don't fire at the same second.
- If a probe is offline, no new run is created for that cluster, and runs already planned there end `skipped` (`probe_offline`); the cell shows **agent/probe offline**, never "failed" (same consistency rule as SPEC F18).

---

## 3. Scenario model

```
scenarios(id, name, type[http_flow|http|dns|tcp|tls], owner_selector, interval_seconds, timeout_seconds,
          step_retries, enabled, run_on[all|selector], run_on_selector, exclude_selectors text[],
          store_responses bool default true, created_by, updated_at)
scenario_steps(id, scenario_id, position, kind[dns|http|tcp|tls], spec jsonb)   -- method, url, headers, body, host, port…
scenario_assertions(id, step_id, subject, operator, value)                     -- see table below
scenario_extracts(id, step_id, name, source[json_path|header|regex], expr)
scenario_alerts(scenario_id, cluster_fail_after int default 3, fleet_critical_clusters int default 3,
                channel_id, critical_channel_id null, recovery_after int default 2, send_recovery bool)
synthetic_runs(id, scenario_id, cluster_id, scheduled_for, started_at, finished_at, status[passed|failed|error|skipped],
               failed_step int null, failure_reason text, total_ms, probe_version)              -- append-only
synthetic_step_results(run_id, position, status, timings jsonb, assertions jsonb, response_excerpt bytea null)
synthetic_alerts(id, scenario_id, cluster_id null /*null = fleet*/, state[firing|resolved], opened_at, resolved_at, last_run_id)
synthetic_allowlist(id, pattern, kind[exact|wildcard|suffix], note, created_by, created_at)
synthetic_credentials(id, name, kind[bearer|basic|header|oauth2_client_credentials], bound_hosts text[],
                      ciphertext, wrapped_dek, kek_version /*or*/ keyvault_ref, header_name null,
                      oauth_token_url null, expires_at null, rotated_at, created_by)
```

**Step types**

| Type | Spec | Assertions |
|---|---|---|
| `dns` | name, record type (A/AAAA/CNAME/TXT), optional resolver = cluster DNS (default) | record count, contains value, latency |
| `http` | method, URL, headers, body (text/JSON), follow redirects (max 5), auth credential (optional) | status code, latency, header equals/contains, body contains/regex, JSON path (equals, exists, length, number compare), TLS days left |
| `tcp` | host, port | connects, latency |
| `tls` | host, port, SNI | days until expiry, chain valid, hostname matches, min TLS version |

- `http_flow` = ordered steps of any kind; the run stops at the first failed step; remaining steps are `skipped`.
- Variables: extracts produce `${name}`, usable in later steps' URL, headers, body. **Extracted values are never stored**, only their names (they may be tokens).
- Assertion operators: `equals`, `not_equals`, `contains`, `matches` (RE2), `less_than`, `greater_than`, `exists`, `length_greater_than`.
- Limits: ≤ 10 steps, timeout ≤ 60 s, interval ≥ 30 s, request body ≤ 64 KiB, response read ≤ 1 MiB (excerpt stored ≤ 2 KiB).

---

## 4. Targeting (runs on + exclude)

- `run_on = all` (default): every cluster with an online probe, **including clusters added later**.
- `run_on = selector`: clusters matching the label selector.
- `exclude_selectors`: list of label selectors; a cluster matching any is excluded. The reserved `olympos.io/cluster=<name>` label (v0.1 round 4) excludes a single cluster.
- Editor shows the live result: "Runs on 9 of 10 clusters" with the names.
- Overview matrix shows excluded cells hatched with "excluded"; offline probes as "probe offline".

---

## 5. Alerting

- **Cluster alert:** a cluster fails `cluster_fail_after` consecutive runs → alert to `channel_id`.
- **Fleet alert (critical):** `fleet_critical_clusters` or more clusters failing at the same time → one critical alert to `critical_channel_id` (or `channel_id`).
- **Recovery:** after `recovery_after` consecutive passing runs → one recovery message (if `send_recovery`).
- **Deduplication:** one message when an alert opens, one when it resolves. No repeats while firing (activity log keeps every run). Grouping per SPEC F9.
- Probe offline is **not** a scenario failure; it is the existing `agent.offline`-style event `probe.offline` (5 min debounce).
- Test runs (editor "Run once") never alert.
- Events: `synthetic.failing`, `synthetic.critical`, `synthetic.recovered`, `probe.offline`, `probe.online`, `synthetic.credential_expiring` (14 and 3 days).
- Slack message: scenario, cluster(s), failed step, reason (e.g. "latency 912 ms > 500 ms"), link to the run. Never credential values, never response bodies.

---

## 6. Security rules (MUST)

### 6.1 Host allowlist [decided]
Global list, admin-only, every change → `activity_log` + `grant.changed`-style event `synthetic.allowlist_changed` to the access channel.

| Kind | Example | Matches | Does not match |
|---|---|---|---|
| `exact` | `partner-sftp.acme.net` | that host only | anything else |
| `wildcard` | `*.dev.wrw.com` | any host under `dev.wrw.com`, **any depth** (`a.dev.wrw.com`, `x.y.dev.wrw.com`) | `dev.wrw.com` itself |
| `suffix` | `wrw.com` | `wrw.com` **and** every host under it | `notwrw.com`, `wrw.com.evil.io` |

- Matching is on the lower-cased, IDNA-normalized hostname with any trailing dot removed, by whole DNS labels (never substring).
- **Always denied**, regardless of rules: IP literals in URLs, `localhost`, and any resolved address in loopback, link-local (`169.254.0.0/16`, `fe80::/10`), cloud metadata (`169.254.169.254`, `fd00:ec2::254`), unspecified, multicast; the Kubernetes API service IP and `kubernetes.default.svc*`.
- Enforced **on the probe** (the server also validates when saving a scenario):
  1. hostname must match the allowlist;
  2. DNS is resolved by the probe and the connection is made to the resolved IP after checking it against the always-denied ranges (no second resolution: prevents DNS rebinding);
  3. every redirect hop is re-checked (1 and 2); a redirect to a non-allowed host fails the step with `redirect_blocked`;
  4. the probe carries the allowlist snapshot version from the `RunScenario`; a stale or missing snapshot means the run is refused.
- Saving a scenario with a non-allowed host fails with a clear message and a link to Settings › Synthetic monitoring (admins) or "ask an admin" (others).

### 6.2 Credentials [decided: stored encrypted in Olympos]
- Stored like backup credentials (envelope or `kv://`), never returned by the API, never shown again.
- Each credential has **bound hosts** (allowlist-style patterns, must each be within the global allowlist). It is attached **only** to requests whose host matches its bound hosts. On a redirect to a host outside the bound hosts, the credential is removed from the request.
- Delivery: in `RunScenario`, credentials are encrypted to the probe's current certificate public key (HPKE or ECIES with the probe's ECDSA key) per run, so a captured message cannot be replayed to another probe. The probe decrypts in memory, uses, zeroes buffers after the run; never logs, never writes to disk, never puts it into extracted variables or stored excerpts.
- OAuth2 client credentials: the probe fetches the token for the run from `oauth_token_url` (which must also be allowlisted) and discards it after the run.
- Redaction on the probe before anything leaves it: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, the credential's own header name, and any header or JSON field whose name matches the sensitive-key heuristics from F2; plus the gitleaks rules over the excerpt. Excerpts can be disabled per scenario (`store_responses=false`).
- Roles: new `synthetic-editor` (create/edit scenarios in scope, use existing credentials). Creating/rotating credentials and editing the allowlist: admin only. `viewer` sees results but not request headers/bodies of steps that use a credential.
- Expiry tracking and `synthetic.credential_expiring` event.

### 6.3 Abuse limits
- Global cap on probe requests per minute per cluster (default 600) and per scenario; the server refuses to schedule beyond it and shows why.
- Probe has a hard concurrency limit (default 20 runs) and per-run memory cap.

---

## 7. UI (mockups in `docs/design/`)

| File | Screen |
|---|---|
| `monitoring-overview.html` | Monitoring › Synthetic: KPIs (scenarios, failing, degraded, probes), filter pills, **scenario × cluster matrix** (passing / failing / degraded / probe offline / excluded, text + symbol, not colour only), 24 h availability, p95 |
| `monitoring-scenario.html` | Scenario detail: steps as cards (failed step marked), per-cluster table with last result, failed step, p50/p95, availability and a 48 × 30 min timeline; alert rule; alert history; Delete (editors in scope) with a confirm dialog that names the scenario, says its runs and alert history go with it, and asks for its name |
| `monitoring-editor.html` | Editor: basics, type, **Store response excerpts** (`store_responses`; off keeps no excerpts or response text, a privacy control), steps (method, URL, headers, **auth**, assertions, extracts, reorder), allowlist hint per URL, schedule, **Runs on + exclude chips** with live count, alerting, test run on one cluster |
| `monitoring-run.html` | Run detail modal: per-step waterfall (DNS, connect, TLS, TTFB, download), assertion results, redacted response excerpt, "Copy as curl" (credentials replaced by `$TOKEN`) |
| `settings-synthetic.html` | Settings › Synthetic monitoring: **host allowlist** (exact / wildcard / suffix, "check a host"), always-denied note, **credentials** (type, bound hosts, expiry) with the exception notice |
| `dialog-add-cluster.html` | Add cluster now says the probe is installed with the agent |

- Sidebar: **Monitoring** after Security. Monitoring has its own tab bar; only "Synthetic" exists now. Build the tab bar so new tabs are added by config.
- Cluster pages (Security/Audit/Backups pattern): add Monitoring › Synthetic per-cluster view later; not required now.
- Settings › Clusters & agents: show probe state per cluster (installed / not installed / offline, version) and the "Install probe" action.

---

## 8. Data retention
- `synthetic_runs` + step results: 30 days (configurable), then rolled up to hourly aggregates kept 400 days (availability, p50/p95 per scenario × cluster).
- Response excerpts: 7 days.
- Alerts: forever (small).

---

## 9. Acceptance and tests

- **Allowlist:** table-driven tests for exact/wildcard/suffix incl. `wrw.com.evil.io`, `xwrw.com`, uppercase, trailing dot, IDNA; always-denied IPs; DNS rebinding test (resolver returns allowed IP then 169.254.169.254: connection must use the first and only resolution); redirect to non-allowed host blocked.
- **Credentials:** credential never attached to a host outside bound hosts (incl. after redirect); canary credential value never appears in server DB, server logs, probe logs, Slack payloads, stored excerpts, extracted variables; per-run encryption cannot be decrypted by another probe identity.
- **Probe isolation:** golden-file test: probe ServiceAccount has no RoleBindings and token automount is off; probe identity is rejected by tunnel/inventory/API-proxy RPCs.
- **Enrollment:** one token enrolls exactly one agent and one probe; replay fails.
- **Scheduling:** runs spread with jitter; offline probe yields no failed runs; new cluster automatically included for `run_on=all`; exclude selectors respected.
- **Alerting:** 3 consecutive failures → one message; flapping does not spam; 3 clusters failing → one critical message; recovery after 2 passes; test runs never alert.
- **e2e (kind):** both lab clusters with probes; a lab HTTP service (allowlisted lab domain via CoreDNS) with a toggle to return 500/slow; scenario with a bearer credential; assert matrix states, alert, recovery, redaction, and that a scenario pointing at `kubernetes.default.svc` or `169.254.169.254` is refused.
- Update SPEC: §0 principle 1 exception, §2 install (probe), §4 (new component), §7 (probe protocol), §8 (tables), §14 (events), §15 (screens), §18 (checklist lines for the tests above).
