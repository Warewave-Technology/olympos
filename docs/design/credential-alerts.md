# Synthetic credentials that cannot be resolved (#54)

Status: approved by the owner on 2026-11-24. Supersedes rulings P13 (expired credential) and P14 (server-side
resolution failure) of [synthetic-monitoring.md](synthetic-monitoring.md) where they conflict.

## Why

A synthetic credential that can never resolve (deleted Key Vault secret, revoked access, a stored value that does
not decrypt) makes every run of every scenario that uses it `skipped` (`credential_unavailable`), with no alert.
The only trace is a counter on *Settings › Synthetic monitoring › Credentials*. For a monitoring feature, "not
monitoring and not telling you" is the worst failure. An expired credential does alert, but once per scenario
(its runs end in error and feed each scenario's streak): one cause, several messages.

## Goals

- One alert per credential, whatever the number of scenarios and clusters that use it; one *Needs attention* item;
  one recovery message.
- A permanent failure is reported at once; a transient one only when it lasts.
- The matrix, the scenario page and the Credentials page say "credential error", distinct from failing and offline.

Non-goals: retrying inside a run (the next run retries; the Azure SDK already retries 5xx and throttling); a setting
for when the alert fires.

Anti-goal: a broken credential must not also open one `synthetic.failing` per scenario (the noise this removes).

## Approaches

1. **State on the credential row, updated at dispatch** (chosen). Dispatch is the only place a credential is
   resolved; it records the outcome on `synthetic_credentials` and emits the events. Exactly once is an atomic
   `UPDATE … WHERE alerted_at IS NULL` plus the outbox idempotency key.
2. Derive the state from run history in a maintenance job. Rejected: a run does not record which credential failed
   (a scenario can use several), and the alert would lag by the job interval.
3. Keep skipping and alert from the 24-hour counter. Rejected: the counter is an upper bound per scenario, not per
   credential, and cannot tell permanent from transient.

## Design

### Classification

`internal/secrets` and `backup.Credentials.Resolve` return errors that `errors.Is` can classify:

| Cause (`resolve_cause`) | Source | Kind |
|---|---|---|
| `not_found` | Key Vault 404, local vault file missing (`secrets.ErrSecretNotFound`) | permanent |
| `forbidden` | Key Vault 401/403 (new `secrets.ErrSecretForbidden`), reference reserved or not allowed (`ErrRefReserved`, `ErrRefNotAllowed`) | permanent |
| `decrypt` | stored value: the DEK unwraps but AES-GCM does not open (new `secrets.ErrDecrypt`) | permanent |
| `empty` | the resolved secret is empty | permanent |
| `expired` | `expires_at` has passed (checked before resolving) | permanent |
| `unavailable` | anything else: network, 5xx, throttling, the KEK cannot unwrap the DEK | transient |

A KEK unwrap failure is transient: it does not alert at once. If it lasts 30 minutes, every stored credential
alerts once (Key Vault references are not affected). The KEK watch only checks purge protection, so it does not
report this. Unchanged: a missing `synthetic_credentials` row or a bound host
that does not parse stays `error` / `credential_error`.

### Run outcome

- Permanent: the run ends `error` with reason `credential_broken` (`credential_expired` for `expired`, kept for
  existing filters). These two reasons **do not move streaks** (`counts`) and are left out of availability,
  percentiles, the timeline and the hourly rollups (one SQL predicate shared by those queries).
- Transient: the run ends `skipped` / `credential_unavailable`, as today.

### Credential state (migration 00025)

`synthetic_credentials` gets:

| Column | Meaning |
|---|---|
| `resolve_state text NOT NULL DEFAULT 'ok'` | `ok`, `broken` (permanent), `unavailable` (transient) |
| `resolve_cause text` | the cause above; NULL when `ok` |
| `resolve_failing_since timestamptz` | first failure of the current episode; NULL when `ok` |
| `resolve_alerted_at timestamptz` | when `synthetic.credential_broken` went out for this episode |

At every dispatch that resolves a credential:

- **Success:** if the state was not `ok`, set it back to `ok` and clear the other columns; if `resolve_alerted_at`
  was set, emit `synthetic.credential_restored` once.
- **Permanent failure:** set `broken` and the cause (`failing_since` kept if the episode already started), then
  emit `synthetic.credential_broken` if `resolve_alerted_at IS NULL` (setting it in the same statement).
- **Transient failure:** set `unavailable` (a permanent state is not downgraded within an episode), and emit the
  event with `transient=true` once `now - resolve_failing_since >= 30 min` and nothing was sent yet.

Saving a new secret (*Rotate the secret*) or a new expiry resets the state to `ok` without a recovery message (the
next run decides). A credential used by no enabled scenario is never resolved, so its state stays as it was.

### Events

- `synthetic.credential_broken`: *Synthetic credential X cannot be resolved* (*… has been unavailable for 30
  minutes* when transient) · credential, cause, since, used by (scenarios), `N scenarios affected`. Key
  `synthetic.credential_broken:<credential>:<failing_since unix>`.
- `synthetic.credential_restored`: *Synthetic credential X resolves again* · credential, failing since. Key
  `synthetic.credential_restored:<credential>:<failing_since unix>`.
- Routing: one message per distinct channel of the scenarios using the credential (`ChannelID`), plus one through
  the event type's routes when any of them has no channel, like scenario alerts. The migration copies the routes of
  `synthetic.credential_expiring` to both new types (and the down migration removes them).
- No raw error text in messages: the cause code and a fixed sentence per cause.

### Needs attention

Kind `synthetic_credential_broken`: `crit` for `broken`, `warn` for `unavailable` older than 30 minutes. Label
*Synthetic credential*, detail *Credential X cannot be resolved — N scenarios affected*, link
`/settings/synthetic?credential=<id>`. Shown to whoever can see synthetic monitoring.

### UI (mockups first: `settings-synthetic.html`, `monitoring-overview.html`, `monitoring-scenario.html`)

- Matrix and the per-cluster table: new cell state `credential_error` ("Credential error"), after excluded, paused,
  not installed and probe offline, before failing: a scenario with a `broken` credential shows it on every cluster
  it would run on.
  A scenario with an `unavailable` credential shows `credential_unavailable` ("Credential unavailable", warn) in
  the same place, from the first transient failure (#69): its runs are skipped, so the last counted run is old
  news. The alert still waits 30 minutes; the matrix is a status view, not an alert.
- Scenario page: the credentials it uses, each with its state.
- Credentials page: a state badge replaces "could not be read N times in 24 h", e.g.
  `Cannot be resolved · not found in Key Vault · since 10:42`, or `Unavailable since 10:42` (warn).
- API: `resolve_state`, `resolve_cause`, `resolve_failing_since` on the credential view; the 24-hour counter stays.

### Decisions taken while implementing

- Channels come from `scenario_alerts.channel_id` of the enabled scenarios that use the credential.
- A credential that no enabled scenario uses still gets one message, through the routes of the event type.
- The *unavailable* Needs-attention detail reads *since HH:MM UTC*, the same time as the message's `since`.
- A scenario with a broken credential gets the cell state *Credential error* in the matrix. There is no new
  scenario status.
- The `consecutive_failures` count of the run detail also leaves out the two reasons, like the streaks.
- Logs (#69): the dispatch logs a credential that cannot be resolved at WARN only when its state changes (a new
  episode, another cause, transient to permanent) and at INFO once when it resolves again; each run's line is
  DEBUG. Errors that are not a resolution failure (sealing, the database) stay WARN on every run.
- The Needs-attention item counts only enabled scenarios, and is shown to users who may read the synthetic
  settings (global read, or the `synthetic-editor` role).

## Tests

- Unit: classification table (each cause above, wrapped errors); `counts` and the stats predicate.
- Dispatch with the test environment: permanent → one event and the state; repeated runs → no second event;
  transient → no event before 30 minutes, one after; recovery → one `credential_restored`; rotation resets.
- Dedup: 3 scenarios on 9 clusters with one deleted local Key Vault secret → exactly one
  `synthetic.credential_broken` (per channel), one attention item, no `synthetic.failing`; putting the secret back →
  one `synthetic.credential_restored`.
- Web: cell state, badge, attention item.
- e2e M9: delete the credential's local Key Vault secret, see the attention item and the cell; restore it.

## Docs

`synthetic-monitoring.md` (credentials, statuses), `findings-and-events.md` (two events, the attention kind),
`openapi.yaml`, this design's rulings noted in `synthetic-monitoring.md` (design) next to P13/P14, a
`docs/spec-changes.md` row, CHANGELOG *Unreleased*.
