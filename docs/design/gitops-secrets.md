# GitOps-safe Secrets in the charts (#59)

Status: approved by the owner on 2026-11-25 (approach A: the identity Secrets are created once on the cluster,
not rendered).

## Why

Argo CD, Flux and other tools render the charts with `helm template`, where `lookup` finds nothing. Measured in
the lab (`helm template` applied, the agent's write simulated with a plain Update, applied again):

- **The server chart's bundled PostgreSQL password changes on every render.** Every sync writes a new
  password to the Secret; PostgreSQL keeps the old one, and the server loses its database.
- **The bootstrap token is written again on every sync.** The agent ignores it while its certificate is valid.
  The probe takes a token as a new install request: it enrolls with a spent token, is refused, drops the token,
  and the next sync writes it again. Argo CD shows the application out of sync for good.
- The enrolled certificates survive client-side and server-side apply. A sync that replaces the Secret
  (Argo CD `Replace=true`, Flux `force`) wipes them.

## Goals

- Plain Helm keeps working as today, with the same defaults.
- With a GitOps tool, everything that lasts (chart, values, the database password Secret) comes from Git; the
  one-time bootstrap token does not, because it is valid for one hour and used once.
- No change to the agent, its RBAC or the probe: not a security-model change.

## Approaches

A. **The identity Secrets are created once on the cluster (chosen).** With `identity.manageSecrets: false`
   the agent chart renders neither identity Secret. Olympos's install dialog shows a GitOps variant: a
   `kubectl` command that creates them with the token, and the chart values for Git. The agent works as today.
B. The token comes from a user Secret mounted into the agent, so that it can live in Git (SealedSecrets,
   External Secrets). Rejected: a one-hour, single-use token in Git is expired by the time it syncs, and stays
   in Git as a spent secret afterwards; it also changes the agent.

## Design

### Agent chart

- `identity.manageSecrets` (default `true`). With `false`, `templates/identity.yaml` renders no
  `olympos-agent-identity` Secret and `templates/probe-identity.yaml` renders nothing. The Role, its binding,
  the CA ConfigMap and every Deployment stay as they are; `bootstrapToken` is no longer required.
- The agent's Secret must exist before the agent starts (it logs the missing Secret and retries until then).
  The probe's Secret volume is already optional, so the probe waits.

### Server chart

- `postgresql.existingSecret` (default empty): the name of a Secret with the key `password`. When set, the chart
  renders no password Secret and the bundled PostgreSQL and the server read that one. With a GitOps tool it is
  required; the docs say so. Without it, plain Helm generates and keeps the password as today.

### Install commands (API, UI)

- `InstallResponse` gains `gitops`: `{secrets: <kubectl commands>, values: <YAML>}`. The probe's install
  response gains `gitops: {secrets, values}` too.
- `secrets` creates or updates the Secrets in place, so that it also works when they exist (a revoked probe):
  `kubectl create secret generic … --from-literal=bootstrap-token=<token> --dry-run=client -o yaml | kubectl apply -f -`.
  A new cluster's command writes the token to both Secrets (one token enrolls the agent and the probe, as
  today); *Install probe* writes the probe's only.
- `values` holds what the `helm` command sets, without the token: `server`, `clusterName`, `serverCA`,
  `bench.enabled`, the server's agent settings, and `identity.manageSecrets: false` (and `probe.enabled: true`
  for *Install probe*).
- The add cluster dialog and *Install probe* get two pills over the command: **Helm** (today's command) and
  **GitOps (Argo CD, Flux)**. GitOps shows *Run once on the cluster* (the `kubectl` commands) and *Chart
  values for your Git repository* (the YAML), each with its own copy button, and a link to the docs.
  Mockup: `docs/design/dialog-add-cluster-gitops.html`.

### Docs

`docs/install.md` › *Install with Argo CD or Flux*: the two values, the order (Secrets first, then the
application), why the token stays out of Git, an Argo CD `Application` and a Flux `HelmRelease` example, and
a warning against `Replace=true` / `force` on these Secrets. The CHANGELOG under *Unreleased*.

## Tests

- Chart unit tests (`deploy/helm/*_test.go`): `manageSecrets: false` renders no identity Secret and needs no
  `bootstrapToken`; `existingSecret` renders no password Secret and points both pods at it.
- API and web tests for the GitOps variant.
- e2e: a GitOps-installed agent and probe (a cluster of their own in the lab, like M9's `lab-b`): create the
  Secrets with the dialog's command, render the agent chart with `helm template`, apply twice (client-side, then
  server-side); the agent and the probe stay connected with the same certificate serials and no new enroll
  attempt is logged.
- The server chart's part is proven by its unit test: with `existingSecret` the render holds no password at
  all, so no sync can change it. The lab server is not reinstalled for the test.

## Left to the builder

The exact YAML layout of `values`; where the e2e lives (a new `TestGitOpsSync` next to the M1 test is fine).
