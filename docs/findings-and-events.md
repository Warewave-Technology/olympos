# Findings, Needs attention and events

You see a finding, a *Needs attention* item on the Dashboard or a Slack message, and you want to know
what it means and how to make it go away. This page lists each one, what triggers it, what to do and
how it closes.

- [Three kinds of signal](#three-kinds-of-signal)
- [Needs attention](#needs-attention)
- [Findings by source](#findings-by-source)
- [Events and notifications](#events-and-notifications)
- [Fixing at the source](#fixing-at-the-source)

## Three kinds of signal

| | What it is | Where you see it | How it goes away |
|---|---|---|---|
| **Finding** | A stored record of one problem on one resource in one cluster: source, control ID, severity, resource, title. It is `open` or `resolved`. | *Security* tabs, *Audit*, the *Vaults* list, and `GET /api/v1/findings`. | Olympos resolves it by itself once the problem is gone. |
| **Needs attention** | A strip of links at the top of the Dashboard (*Fleet overview*). It is computed each time the Dashboard loads; nothing is stored. | Dashboard only. Each item links to the page where you fix it. | It disappears when its condition is no longer true. |
| **Event** | A message written to the outbox when something happens (a backup failed, a CR was opened, new findings). | Slack channels you route it to under *Settings › Notifications*. Many events also leave a row in the activity log (*Audit › Platform activity*). | Events are not closed. Each is delivered once per channel. |

### How findings open and resolve

A finding is keyed by source, cluster, control ID and resource. Only one open finding exists per key.
Seeing the same problem again updates its *last seen* time; it does not create a second finding.

Most sources are **diffed run over run**: each run or agent report is the full current set, new keys
open, and keys that are missing are resolved. This applies to Kubescape, Polaris, kube-bench, Kyverno,
NetworkPolicies, sensitive data and the Secret inventory. Three sources open and resolve one finding at
a time when a state changes: `tls`, `transfer` and `vault-drift`. The details are in each section below.

Some rules hold across sources:

- **Audit runs (Kubescape, Polaris, kube-bench) only diff on success.** A failed run resolves nothing.
  In a kube-bench run, nodes whose Job failed or timed out keep their open findings.
- **Agent reports (Kyverno, NetworkPolicies, sensitive data, Secret inventory) are diffed on every
  report.** If an agent resends a report identical to the last one within an hour, the server skips
  it.
- **Resolved findings are kept**, with when they were first seen, last seen and resolved.

### Acknowledge, suppress, ignore

There is no way to acknowledge, snooze, suppress or accept a finding in Olympos. Its status is either
`open` or `resolved`, and only the checks above change it. To make a finding go away, fix the cause, or
change what is scanned:

- Namespaces in `security.systemNamespaces` (server) are skipped by the NetworkPolicy, sensitive-data
  and Secret-inventory checks. The default list is `kube-system`, `kube-public`, `kube-node-lease`,
  `olympos-system` and `olympos-bench`.
- The agent's `sensitiveData.excludeNamespaces` Helm value limits where it scans ConfigMaps.
- `security.secretsInventory.reportUnmanaged: false` (server) turns off `secret.unmanaged`.
- Kubescape, Polaris and Kyverno have their own exception mechanisms. Olympos records what the tool
  reports.

See [configuration](configuration.md) for these settings.

### Severities

Findings use `critical`, `high`, `medium`, `low` and `info`. The UI shows them as *Critical*, *High*,
*Medium*, *Low* and *Info*. Lists sort the most severe first, then the newest. Needs attention items
are either `crit` (red) or `warn` (amber), and the `crit` ones come first.

## Needs attention

The Dashboard shows only what you are allowed to see. Cluster items cover the clusters in your scope.
The Olympos and Key Vault items need global read access. The synthetic credential item needs global read
access or the `synthetic-editor` role. The approvals item needs approve rights on the vault's cluster.

| Item as shown | Severity | Why it appears | What to do | Links to |
|---|---|---|---|---|
| **Agent offline** · `<cluster> · <time>` | crit | The cluster is marked offline and was last seen longer ago than `agents.offlineAlertAfter` (default 5 minutes), the delay of the `agent.offline` message. | Check the agent pod and its outbound connection to the gateway. See [troubleshooting](troubleshooting.md). | *Settings › Clusters & agents* (that cluster) |
| **Backup failed** · `<service> · <error>` | crit | In the last 48 hours, the latest finished run of a backup job failed. Test runs and failures marked `agent_disconnected: retrying` are left out. | Open the run, read the error and its steps, fix the cause, then run it again or wait for the next schedule. | *Backups* (that job) |
| **Backup missed** · `<service>` | crit | In the last 48 hours, the latest run of a job was `missed`: the scheduler did not start it, or the agent stayed away past the window. | Check that the server was up and the agent connected at the scheduled time. | *Backups* (that job) |
| **Backup incomplete** · `<service> · missing <destinations>` | warn | In the last 48 hours, the latest run of a job that writes to a [destination group](#partial-backups-and-repairs) was `partial`: some copies were written, the named ones were not, and no repair run has written them since. While a repair is running, or after one failed, the item stays. Only destinations the job still writes to are named: a destination removed from the group (or a job moved elsewhere) is no longer missing, and the item goes away when none is left. | Open the run: the *Copies* table shows each destination's error. Fix that destination and run its test under *Settings › Destinations*. Repairs run on their own inside the retry window; after that, run the job again or wait for the next schedule. See [troubleshooting](troubleshooting.md#a-backup-is-incomplete-partial). | *Backups* (that job) |
| **TLS name changed** · `<ns>/<svc> asks for <name>; still verifying <pinned>` | crit | A target's `olympos.io/tls-server-name` annotation no longer matches the name Olympos pinned when it first saw the target. Backups and Vault calls keep verifying the pinned name. | If you expected the change, an admin of that cluster clicks *Accept new name* under *Backups*. If not, revert the annotation and find out who edited the Service. | *Backups* (*TLS name changed* card) |
| **Olympos backup failed** · `<error>` | crit | The latest finished run of the built-in `olympos-self` job in the last 48 hours failed. | Open the *Olympos database* card under *Backups* and check the run and its destination. | *Backups* (*Olympos database* card) |
| **Key Vault** · `purge protection is off (<level>): enable soft delete and purge protection` | crit | At the last check, the KEK's recovery level was not recoverable with purge protection. A dump of the Olympos database is useless without that key. | Turn on soft delete and purge protection on the vault ([below](#key-vault-purge-protection)). | *Backups* (*Olympos database* card) |
| **Olympos backup incomplete** · `missing <destinations>` | warn | The same for the built-in `olympos-self` job, when it writes to a group. | As above, from the *Olympos database* card. | *Backups* (*Olympos database* card) |
| **Critical CVEs** · `N new in M images` | crit | A critical CVE was first seen in the last 24 hours in an image running in your clusters. | Open *Security › Images*, sort by *Critical*, and use *Fix* (fixed-in version) to plan an image update. | *Security* |
| **Olympos backup** · `choose where the Olympos database is backed up` | warn | The built-in `olympos-self` job has no destination yet. | An admin picks a destination on the *Olympos database* card. It runs daily at 02:30 UTC by default. | *Backups* (*Olympos database* card) |
| **Key Vault** · `could not check purge protection of the KEK (needs keys/get)` | warn | The last check failed, usually because the server's identity cannot read the key's properties. | Grant the server identity `keys/get` on the key (the *Key Vault Crypto User* role includes it). | *Backups* (*Olympos database* card) |
| **Synthetic credential** · `Credential <name> cannot be resolved — N scenarios affected` | crit | A [synthetic credential](synthetic-monitoring.md#credentials-that-cannot-be-resolved) that an enabled scenario uses cannot be resolved for good (secret not found, access denied, does not decrypt, empty, expired). When Key Vault only does not answer, the item is amber (*has been unavailable since HH:MM UTC*) and appears after 30 minutes. One item per credential, however many scenarios and clusters use it. Shown to whoever may read *Settings › Synthetic monitoring*. | Put the secret back, grant the server `get` on it, or rotate the credential. The item goes away at the next run that resolves it. | *Settings › Synthetic monitoring* (that credential) |
| **N approvals** · `waiting for you · oldest <time> left` | warn | Pending change requests you may approve and that you did not open yourself. *Time left* is the earliest expiry. | Review them under *Approvals* before they expire. | *Approvals* |
| **End of life** · `N clusters on v1.x, …` | warn | At least one cluster runs a Kubernetes minor version past its upstream end of life. | Plan an upgrade. The *Version matrix* marks those versions *EOL*. | Dashboard, filtered to EOL clusters |

The API names these kinds `agent_offline`, `backup_failed`, `backup_missed`, `backup_partial`,
`target_tls_changed`, `self_backup_failed`, `self_backup_partial`, `kek_purgeable`, `critical_cves`,
`self_backup_unset`, `kek_recovery_unknown`, `synthetic_credential_broken`, `approvals` and `eol` (`GET /api/v1/dashboard`, field
`attention`).

The server checks the two Key Vault items at start and then **every hour**. After you fix the vault, the
item goes away at the next check, within an hour; restarting the server checks at once. The server log
has a line each time the result changes.

**Not in Needs attention.** Version skew (kubelet older than the API server) is a Dashboard tile,
*Version skew*, not an item. So is the *Agent offline* count. Open findings from Security or Audit are
not Needs attention items either; only new critical CVEs are.

## Findings by source

The source is the `source` field of a finding. The control ID is `control_id`. The resource is
`resource_ref`.

### `tls`: target without TLS

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| `tls.missing` | medium | The last connection test or backup run of this target did not use TLS. Resource: `<namespace>/<service>:<port>`. Title: *Target ns/svc does not speak TLS*. | Enable TLS on the database and make the server trust its CA ([below](#enabling-tls-on-a-target)). | Resolved by the next connection test or backup run that connects with TLS. |

Where you see it: the *TLS* column under *Backups* shows *No* for these targets (*Yes* with TLS, *Not
probed* before the first contact). The backup wizard warns about it. There is no list of `tls`
findings in the UI; use `GET /api/v1/findings?source=tls`.

### `transfer`: compressed transfer mode

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| `transfer.compressed_mode` | medium | The cluster's transfer mode is `compressed`. Backup traffic is plaintext inside the cluster and the agent can see it. Resource: `cluster`. | Switch the cluster back to `e2e-tls` under *Settings › Clusters & agents*. | Resolved when you save a mode other than `compressed`. |

Where you see it: the *Transfer* column under *Settings › Clusters & agents* shows *compressed*. There is
no list of `transfer` findings in the UI.

### `vault-drift`: unmanaged Vault change

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| `unmanaged-change:<vault-id>` | high | A secret has one or more versions newer than the baseline that Olympos did not write, for example after break-glass. Title: *Unmanaged change*. Resource: `<mount><path>`. Details list the versions. | Review the change. Bring the secret back under management with a reviewed change request that writes the intended value ([runbook](runbooks/vault-break-glass.md)). | Resolved when the latest version of the secret was written by Olympos, or when the secret no longer exists in the index. |

Drift is checked on every index refresh of the vault. Paths with a change request still applying are
skipped until its outcome is known. Where you see it: the *Vaults* list shows *N unmanaged changes*,
and the secret view shows an *Unmanaged change* note.

### `kubescape`

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| Kubescape control ID, e.g. `C-0017` | From the control's score factor: ≥ 9 critical · ≥ 7 high · ≥ 4 medium · > 0 low · else info | A Kubescape control failed on a resource. Resource: `<ns>/<Kind>/<name>`, or `<Kind>/<name>` for cluster-scoped objects. Title: the control name. | Follow the control's remediation in the Kubescape documentation for that ID. | Resolved by the next **successful** Kubescape run on that cluster that no longer fails it. |

Where you see it: *Audit*. On a cluster's page, *New since last run*; across all clusters, *Open
Kubescape findings*. The cluster summary counts open audit findings by severity.

### `polaris`

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| Polaris check ID, e.g. `runAsRootAllowed` | Polaris `danger` → high · `warning` → medium (`ignore` is not a finding) | A Polaris check failed. Resource: `<ns>/<Kind>/<name>`, plus `/container:<name>` for container checks. Title: the Polaris message. Details carry the category. | Fix the workload spec as the Polaris check describes. | Resolved by the next successful Polaris run that no longer fails it. |

Where you see it: *Audit* (run results and the per-cluster severity counts). There is no list of Polaris
findings in the UI; use `GET /api/v1/findings?source=polaris`.

### `kube-bench`

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| `<benchmark>:<test number>`, e.g. `<benchmark>:4.2.1` | FAIL and scored → high · FAIL, not scored → medium (WARN, INFO and PASS are not findings) | A CIS check failed on a node. Resource: `node/<name>`. Title: the check description. Details carry the section and kube-bench's remediation. | Apply the remediation shown for the check. Open the node under *Audit* to see it, with actual and expected values. | Resolved by the next successful kube-bench run where the check passes on that node. A node whose Job failed keeps its findings. |

On managed clusters, control plane sections are skipped (*control plane N/A · managed*). kube-bench is
opt-in per cluster (agent Helm value `bench.enabled=true`).

### `kyverno`

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| `<policy>/<rule>` (or `<policy>`) | From the PolicyReport result; medium when missing or unknown | A resource fails a Kyverno validation rule in the latest PolicyReports. Resource: `<Kind>/<namespace>/<name>`. Title: Kyverno's message. | Fix the resource so the rule passes, or change the policy. Open the policy under *Security › Kyverno policies* to see its rules and failing resources. | Resolved on the next agent report without that failure. If Kyverno is not installed, every Kyverno finding resolves. |

Only `fail` results become findings. `warn` and `error` results show on the policy page but are not
findings.

### `netpol`

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| `netpol.no_default_deny` | medium | The namespace has no ingress default-deny NetworkPolicy: no policy selects all pods with `Ingress` in `policyTypes` and no ingress rules. Resource: the namespace. Title: *Namespace ns has no default-deny ingress NetworkPolicy*. | Add a default-deny ingress policy to the namespace, then allow what is needed ([below](#adding-a-default-deny-networkpolicy)). | Resolved on the next agent report where the namespace has one, is gone, or is a system namespace. |

Where you see it: *Security › Network policies* (*N without default-deny*) and the *No default-deny*
tile.

### `sensitive-data`: credentials in ConfigMaps

| Control ID | Severity | Meaning | How to fix | How it closes |
|---|---|---|---|---|
| A gitleaks rule ID, e.g. `generic-api-key` | high (*High · pattern*) | A ConfigMap value matches a credential pattern. | Move the value to a Secret or Vault and remove it from the ConfigMap. | Resolved on the next agent report once the key is gone or no longer matches. |
| `key-name:<word>`, e.g. `key-name:password` | medium (*Medium · key name*) | The key name suggests a credential and the value is not a placeholder. Words: `privatekey`, `connectionstring`, `password`, `passwd`, `pwd`, `secret`, `token`, `apikey`, `accesskey`, `credential`, `dsn`. | Same as above. | Same as above. |

Resource: `<namespace>/<configmap>:<key>`. The value never leaves the cluster. Olympos knows only where
a match is, which rule matched and a rounded length. Olympos never edits or deletes ConfigMaps. The
agent scans a ConfigMap when it changes and rescans all of them every 6 hours. Where you see it:
*Security › Sensitive data*. Agent Helm values: `sensitiveData.enabled` (default `true`) and
`sensitiveData.excludeNamespaces`.

### `k8s-secrets`: Secret inventory

Only on clusters where the opt-in inventory is on (agent Helm value `secretsInventory.enabled=true`).

| Control ID | Severity | UI label | Meaning | How it closes |
|---|---|---|---|---|
| `secret.legacy_sa_token` | medium | *Legacy SA token* | A Secret of type `kubernetes.io/service-account-token`: a long-lived token. | Resolved once the Secret is gone. |
| `secret.unused` | low | *Unused 7+ days* | No workload or service account has referenced the Secret for more than 7 days. Helm release Secrets are skipped. | Resolved once something references it again, or it is gone. |
| `secret.unmanaged` | info | *Only in cluster* | No secrets operator owns the Secret (External Secrets Operator, Vault Secrets Operator, Sealed Secrets, cert-manager or Helm). Off with `security.secretsInventory.reportUnmanaged: false`. | Resolved once an operator owns it, or it is gone. |

Resource: `<namespace>/<name>`. To fix, remove unused Secrets and legacy tokens through your usual change
process. Olympos does not delete Secrets. Where you see it: *Security › Kubernetes secrets*. The tab
badge (*N to review*) leaves out *Only in cluster*.

### Image CVEs (not findings)

Image vulnerabilities are stored per image digest, not as findings. *Security › Images* shows *Critical*
and *High* counts per image and the *Fix* column; the image view lists each CVE with *Fixed in*. A CVE
disappears from an image when a rescan no longer reports it. To fix one, update the image to a version
with the fix and redeploy. New critical CVEs drive the *Critical CVEs* item in Needs attention and the
`vuln.critical` event.

## Events and notifications

Every event carries a title, a link into Olympos and a few fields. Slack messages show the title, the
fields and an *Open in Olympos* link, never secret values.

**Grouped** below means one message per cluster and scan or run, with counts and the top 5 items. The
activity log still gets one row per item.

| Event type | When it fires | Message (title · fields) | Grouped? |
|---|---|---|---|
| `backup.failed` | A backup run failed (attempts that are retried stay quiet). Also fires for a failed `olympos-self` run, when a job is paused because its target is gone, and when the repairs of a [partial run](#partial-backups-and-repairs) give up. | *Backup failed: ns/svc* · cluster, target, trigger, error (and *missing* when repairs gave up). *Backup failed: Olympos database (olympos-self)*. *Backup paused: target ns/svc is gone* · reason. | No |
| `backup.partial` | A run of a job that writes to a destination group wrote some copies but not all. Also fires for `olympos-self`. Not opt-in: route it like `backup.failed` (on an upgrade to v0.2, every channel that gets `backup.failed` is routed `backup.partial` too). | *Backup incomplete: ns/svc* · cluster, target, trigger, missing, error, next_attempt (when a repair is queued). *Backup incomplete: Olympos database (olympos-self)*. | No |
| `backup.missed` | A scheduled run did not start (scheduler down, or overlap), or a run was marked missed after the agent stayed away (a repair that ends missed sends `backup.failed` when it gives up instead). | *Backup missed: ns/svc*, with *(N runs)* when several slots were missed · cluster, target, scheduled_for, count. | One message per job for a batch of missed slots |
| `backup.succeeded` | A backup run succeeded, or a repair run wrote every missing copy of a partial run. **Opt-in** (see below). | *Backup succeeded: ns/svc* · cluster, target, trigger, size, tier. | No |
| `cr.opened` | A Vault change request was opened and waits for approval. | *Change request waiting for approval* (link only). | No |
| `cr.approved` | A change request was approved. | *Change request approved* · Vault. | No |
| `cr.rejected` | A change request was rejected. | *Change request rejected* · Vault. | No |
| `cr.expired` | A pending change request passed its TTL. | *Change request expired* · Vault. | No |
| `cr.failed` | An approved change request failed to apply. | *Change request failed to apply* · Vault. | No |
| `restore.requested` | A [restore request](restore.md#restore-from-the-ui) was opened and waits for a checker. | *Restore request waiting for approval* · Backup, Target, Databases, Maker. | No |
| `restore.approved` | A checker approved a restore request; it starts when the target's agent is connected. | *Restore request approved* · Backup, Target, Databases, Checker. | No |
| `restore.rejected` | A checker rejected a restore request (the credential is deleted). | *Restore request rejected* · Backup, Target, Databases, Checker. | No |
| `restore.started` | An approved restore started: the server verifies the backup, checks the target again, then writes to it. | *Restore started: ns/svc* · Backup, Target, Databases. | No |
| `restore.succeeded` | A restore finished. | *Restore succeeded: ns/svc* · Backup, Target, Databases, Created. | No |
| `restore.failed` | A restore failed. The databases it created stay on the target and are listed. Route it: a failed restore in a disaster must not go unnoticed (on an upgrade to v0.2, every channel that gets `backup.failed` is routed `restore.failed` too). | *Restore failed: ns/svc* · Backup, Target, Databases, Error, Created. | No |
| `restore.break_glass` | An admin started a restore without a checker (break-glass), with a justification. Critical: route it to a channel someone watches (on an upgrade to v0.2, every channel that gets `backup.failed` is routed `restore.break_glass` too). | *Break-glass restore started without approval* · Backup, Target, Databases, Maker, Justification. | No |
| `vault.unmanaged_write` | The drift check found a Vault secret version that Olympos did not write. | *Unmanaged change to a vault secret* · Vault, Cluster, Secret, Version. | No: one per unmanaged version |
| `audit.new_findings` | A successful Kubescape, Polaris or kube-bench run opened new findings. | *N new \<tool\> findings on \<cluster\>* · cluster, tool, new, resolved, score, top (5 most severe). | Yes: per cluster and run |
| `vuln.critical` | At the end of an image scan run, for critical CVEs new to an image that is running (digest scans only). | *N new critical CVEs in M running images on \<cluster\>* · cluster, new, images, top (5, fixable first). | Yes: per cluster and scan run |
| `sensitive_data.found` | An agent report opened new sensitive-data findings. | *N new credential-like values in ConfigMaps on \<cluster\>* · cluster, new, open, high, top (5, high first). | Yes: per cluster and scan |
| `secret.new_findings` | A Secret inventory report opened new findings. | *N new Secret inventory findings on \<cluster\>* · cluster, new, unused, legacy SA tokens, unmanaged. | Yes: per cluster and scan (counts only, no top 5) |
| `agent.offline` | An agent has been offline for `agents.offlineAlertAfter` (default 5 minutes). | *Agent offline: \<cluster\>* · cluster, offline for. | Once per outage |
| `agent.online` | An agent is back, **only** after an `agent.offline` message for the same outage. | *Agent back online: \<cluster\>* · cluster. | Once per outage |
| `agent.flapping` | An agent disconnected more than 5 times in 30 minutes (`agents.flappingDisconnects`, `agents.flappingWindow`). | *Agent flapping: \<cluster\>* · cluster, disconnects. | At most once per window |
| `grant.changed` | A role grant was added or revoked. | *Access granted: name → role (scope)* or *Access revoked: name (role)* · principal, role, scope, by. | No |
| `grant.stale` | The daily directory sync found a grant whose Entra account is disabled or deleted. Stale grants do not authorize. | *Grant marked stale: name (role) — reason* · principal, role, reason. | No |
| `sas.expiring` | A destination's SAS token expires within 14 days, within 3 days, or has expired. | *SAS token of destination X expires in N days*, *… expires within a day* or *… has expired: backups to it fail* · destination, expires. | One per destination, threshold and expiry |
| `synthetic.failing` | A [synthetic scenario](synthetic-monitoring.md#alerts) failed (or errored) on a cluster the set number of runs in a row (default 3). Skipped runs, an offline probe and test runs never count. | *Synthetic check failing: \<scenario\> on \<clusters\>* · scenario, clusters (first 5), failed step, reason. | Yes: per scenario, the cluster alerts that opened in one 15-second pass |
| `synthetic.critical` | The scenario fails on at least *Critical when failing in* clusters at once (default 3). Goes to the scenario's critical channel when it has one. | *Synthetic check critical: \<scenario\> fails on N clusters* · scenario, clusters, failed step, reason. | Yes: replaces the `synthetic.failing` of the cluster alerts that opened with it |
| `synthetic.recovered` | A firing alert passed the set number of runs in a row (default 2), if the scenario sends recoveries. For the fleet alert: *no longer critical*, with how many clusters still fail. An alert that resolves because its pair is no longer monitored (scenario disabled, cluster excluded, probe removed or revoked) sends nothing; deleting a scenario or a cluster deletes its alerts. | *Synthetic check recovered: \<scenario\> on \<clusters\>* or *Synthetic check no longer critical: \<scenario\>* · scenario, clusters, still failing. | Yes, like the opens |
| `probe.offline` | A cluster's probe has been offline for `synthetic.probeOfflineAlertAfter` (default 5 minutes). Its scenarios read *probe offline*, never failed, and keep any alert that fires. | *Probe offline: \<cluster\>* · cluster, offline for. | Once per outage |
| `probe.online` | The probe is back, **only** after a `probe.offline` for the same outage. A reconnect after a certificate renewal sends nothing. | *Probe back online: \<cluster\>* · cluster. | Once per outage |
| `synthetic.credential_expiring` | A synthetic credential with an expiry date expires within 14 days, or within 3 days. | *Synthetic credential X expires in N days* (*… within a day*) · credential, expires, used by (scenarios). | One per credential and threshold |
| `synthetic.credential_broken` | A [synthetic credential cannot be resolved](synthetic-monitoring.md#credentials-that-cannot-be-resolved): the Key Vault secret is gone or forbidden, the stored value does not decrypt, the secret is empty or the credential expired (at once); or Key Vault or the key encryption key has not answered for 30 minutes. | *Synthetic credential X cannot be resolved* (*… has been unavailable for 30 minutes*) · credential, cause, since, used by (scenarios), impact (N scenarios affected). | One per credential and episode (per channel) |
| `synthetic.credential_restored` | The credential resolves again, **only** after a `synthetic.credential_broken` for the same episode. Saving a new secret or expiry sends nothing. | *Synthetic credential X resolves again* · credential, failing since. | One per credential and episode (per channel) |
| `synthetic.allowlist_changed` | An admin added or removed a rule of the synthetic host allowlist: what probes may reach changed. On the upgrade that adds it, every channel that gets `grant.changed` is routed this event too. | *Synthetic allowlist: added \<kind\> rule \<pattern\>* (or *removed*) · change, rule, kind, by. | No |

Short agent blips send nothing. A cluster counts as offline after 60 seconds of silence, but
`agent.offline` and the Dashboard's *Agent offline* item wait for the alert delay. The item counts it
from when the agent was last seen. The message counts it from the later of that and the server's start,
so a server that was down does not send one for every cluster.

### Partial backups and repairs

A job can write to a **destination group** instead of one destination: one dump per run, one copy in each
member (*Settings › Destinations › Groups*). Each copy has its own result.

| Copies written | Run status | Event |
|---|---|---|
| All | `succeeded` (green) | `backup.succeeded`, if the job opted in |
| Some | `partial` (amber, never green) | `backup.partial` |
| None, or the dump itself failed | `failed` | `backup.failed` |

After a `partial` run, Olympos queues a **repair run**: a new dump, written only to the destinations that
are missing. Repairs are spaced out so that an outage has time to end:

| Repair | Starts |
|---|---|
| 1st | 5 minutes after the partial run |
| 2nd | 30 minutes after the 1st repair |
| 3rd | 2 hours after the 2nd repair |

Every repair must start inside the job's retry window (half the time to its next scheduled run); one that
would start later is not queued. A daily job has a window of about 12 hours, so all three fit; a job that
runs every hour has 30 minutes, so only the first repair does. A repair keeps the original run's trigger
and scheduled time, and its `repair_of` field names the original run. While it waits, it is `queued` with
`not_before` set to its start, and the partial run's details carry `next_repair_at`. It does not block
*Run now* or a dry run. The partial run stays `partial`: it is the record of what happened.

- A repair that writes every missing copy sends `backup.succeeded` (opt-in, as for every run) and clears
  *Backup incomplete*.
- A repair that fails while another repair is left sends nothing; the next repair is queued.
- When no repair is left (three used, or the next one would start after the window), the last repair
  sends `backup.failed` with the destinations that are still missing. The next scheduled run writes to
  every member again.
- If the agent disconnects during a repair, the disconnect rule for every run applies: a repair whose
  attempt is below 3 is retried once the agent is back, and that retry is the same repair, not another
  one. Later ones (and one whose window is over) end `missed`, without `backup.missed`, and continue the
  repair chain as after a failed repair: the next repair is queued with its delay, or, when none is
  left, the repair sends `backup.failed` with the missing destinations.
- A repair that comes due while its job is disabled (*Pause* on the job) or paused (target gone) does
  not run: it ends `failed` with `skipped: the job is disabled` or `skipped: the job is paused`, sends
  nothing and no further repair is queued. *Backup incomplete* stays until a later run writes every copy.
- Test runs (the wizard's dry run) are never repaired. A run that fails entirely is not retried, as before.

Besides the message fields, the stored event (`outbox.payload`) carries `job_id` and `run_id`.
`backup.partial` adds `missing_destinations` (destination names, in member order), `repair_queued`
(`true` when a repair was queued) and, when one was, `next_attempt_at` (RFC 3339, when it starts; the
message shows it as *next_attempt*). Events of a repair run add `repair_of`, the original run's ID; the
`backup.failed` of a repair that gave up also has `missing_destinations`.

**Metrics.** `olympos_backup_runs_total{engine,status}` counts `status="partial"` runs.
`olympos_backup_copies_total{destination,status}` counts finished copies per destination name, with
`status` `succeeded` or `failed`, for every run including single-destination jobs and `olympos-self`. To
be told when a destination keeps failing, alert on
`increase(olympos_backup_copies_total{status="failed"}[1d]) > 0`.

### Routing

Nothing is routed by default. An event with no route and no channel override is dropped (outcome
`no_route`). The one exception is an upgrade that adds an event type that must not go unnoticed: the
upgrade to v0.2 routes the new `backup.partial`, `restore.failed` and `restore.break_glass` to every
channel that already gets `backup.failed`. The upgrade to v0.3 routes the new `synthetic.allowlist_changed` to
every channel that already gets `grant.changed`. The upgrade that adds `synthetic.credential_broken` and
`synthetic.credential_restored` routes both to every channel that already gets `synthetic.credential_expiring`.
To receive events:

1. *Settings › Notifications › Slack channels*: *Add channel* with a name and the Slack channel ID
   (*Channel details › About*, e.g. `C0123ABCD`). Invite the Olympos Slack app to the channel first.
2. *Settings › Notifications › Routing*: tick the events per channel and click *Save routing*. Each row
   shows the event type and its description.

Overrides and opt-in:

- **Per-job and per-schedule channel.** A backup job (*Notify* in the backup wizard; *Default routing*
  uses the routing table) and an audit schedule can name their own channel. That channel then replaces
  the routing for the job's or schedule's events. If the channel was deleted, the routing table is
  used.
- **`backup.succeeded` is opt-in twice.** The job needs *Also notify on success*, **and** the event type
  needs at least one route. A job's own channel does not turn it on by itself.
- **Per-scenario channel.** A synthetic scenario can name a channel and a critical channel for its
  `synthetic.failing`, `synthetic.critical` and `synthetic.recovered` (*Alerting* in the editor). Without
  them, the routing table decides. Besides the message fields, the stored event carries `scenario_id`,
  `alert_ids`, `cluster_count` and, for an open, `run_id` and `failed_step`; a fleet recovery adds
  `still_failing`. Messages never carry a credential or a response body.
- **Restore events are not opt-in.** Like every event they need a route. On upgrade, `restore.failed` and
  `restore.break_glass` are routed wherever `backup.failed` goes (a break-glass restore is critical like a
  failed backup, and `cr.opened` is an approval queue that an install without Vault change requests does
  not route); on a new install, route at least these two. Restore events carry the
  **backup's** cluster (`cluster_id`), like the restore's audit rows, because they name its run and
  databases. A request that expires sends no event.

Delivery is at least once, with retries and backoff. *Last delivery* on each channel shows the time and
result of its most recent send. If the Slack sink is not configured, events wait instead of using up
retries.

## Fixing at the source

### Enabling TLS on a target

1. Turn on TLS on the database or Vault and serve a certificate for the name Olympos verifies:
   `olympos.io/tls-server-name` on the Service, or `<service>.<namespace>.svc` without it.
2. Make the server trust the issuing CA with `targetTLS.caBundleFile` or a per-target CA. Use
   `targetTLS.systemRoots: true` only for publicly issued certificates
   ([install](install.md#target-certificates)).
3. Test the connection in the backup wizard, or wait for the next backup. `tls.missing` resolves on the
   first connection that uses TLS.

In the default `e2e-tls` mode, PostgreSQL without TLS is backed up only over SCRAM-SHA-256. ClickHouse
and Vault/OpenBao without TLS are refused
([troubleshooting](troubleshooting.md#a-target-without-tls-is-refused)).

### Accepting a changed TLS name

When *TLS name changed* appears, open *Backups*. The *TLS name changed* card lists each target with its
*Verified name* and *Requested name*.

- **Expected change:** an admin of that cluster clicks *Accept new name*. If the annotation changed
  again since the page loaded, the server answers *the TLS name changed again; reload and review it*.
- **Unexpected change:** set the annotation back to the verified name. The item clears on the next
  target report from the agent. Then find out who edited the Service: anyone who can edit it can change
  the annotation.

### Key Vault purge protection

```bash
az keyvault update --name <vault> --enable-purge-protection true
```

Purge protection cannot be turned off again. The Dashboard item goes away at the next hourly check;
restart the Olympos server to check at once. See [Restoring Olympos](restore-olympos.md) for why the KEK
must survive.

### Choosing the Olympos backup destination

Under *Backups › Olympos database*, an admin picks a destination or a destination group (two copies of
Olympos' own database are worth having). The job is built in and cannot be deleted. Once it has a
destination, *Olympos backup* leaves Needs attention. A failed run shows *Olympos backup failed* until a
later run succeeds or 48 hours pass; a partial run shows *Olympos backup incomplete* until a repair or a
later run writes every copy.

### Leaving compressed mode

Under *Settings › Clusters & agents*, edit the cluster, choose `e2e-tls` and save.
`transfer.compressed_mode` resolves on save. Targets without TLS may then be refused (see above).

### Bringing a Vault secret back under management

Follow the [break-glass runbook](runbooks/vault-break-glass.md): review the unmanaged version, then open
a change request that writes the intended value. Once it is applied, the latest version is Olympos' own
and the `vault-drift` finding resolves on the next index refresh (*Refresh index* on the vault runs one
now).

### Adding a default-deny NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: <namespace>
spec:
  podSelector: {}
  policyTypes: [Ingress]
```

Then add policies that allow the traffic the namespace needs. Open the namespace from *Security ›
Network policies* to see its workloads and policies.

### Rotating a SAS token

Issue a new SAS with the same permissions (read, create, write, tag; no delete) and paste it under
*Settings › Destinations*, or update the Key Vault secret it references. A new expiry starts a new
series of `sas.expiring` messages.

## See also

- [Security model](security-model.md): what each component can see and do.
- [Security review v0.1](security-review-v0.1.md): the review behind TLS name pinning and other checks.
- [Getting started](getting-started.md), [install](install.md), [restore](restore.md),
  [configuration](configuration.md), [troubleshooting](troubleshooting.md).
