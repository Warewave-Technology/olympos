# e2e lab

`./test/e2e/run.sh` creates (or reuses) a 2-node kind cluster **`olympos-lab`** on the local Docker
(OrbStack works), with its own kubeconfig at `test/e2e/.work/kubeconfig`. Your current kube context
is never used or changed.

It builds `olympos-server:e2e` / `olympos-agent:e2e` / `olympos-probe:e2e`, deploys:

| Namespace | Workload | Purpose |
|---|---|---|
| `olympos` | `olympos` (Helm chart, dev mode, local key vault on a PVC) | the server, UI at http://127.0.0.1:28080 |
| `olympos` | `olympos-postgresql`, `azurite`, `minio` | Olympos's database (the chart's bundled PostgreSQL), Blob and S3 fakes |
| `olympos-system` | `olympos-agent`, `olympos-probe` (installed by the tests from the local chart) | the agent and the synthetic monitoring probe |
| `lab` | `orders-pg` (TLS, lab CA), `vault` and `openbao` (TLS, raft), `metrics-ch` | annotated targets |
| `lab` | `restore-pg` (PostgreSQL 16, TLS), `restore-ch`, `restore-vault` (TLS, raft, not configured in Olympos) | new, empty servers that `TestM8Restores` and the docs tour restore backups into (emptied by every reset) |

and runs `go test -tags e2e ./test/e2e/...`. Some tests run a gateway **in-process** on the host and
point a second real agent at it through `host.docker.internal`, so they can ask the agent for arbitrary
target IDs (it must refuse anything it did not discover).

Dev sign-in: http://127.0.0.1:28080/auth/dev-login?oid=00000000-0000-0000-0000-00000000ad01&name=Lab%20Admin

Kyverno 1.20 is installed by default (CEL `ValidatingPolicy` only). `KYVERNO_CHART=3.9.2` installs 1.19,
where the legacy `ClusterPolicy` runs as well, so both agent code paths are exercised.

```bash
SKIP_BUILD=1 ./test/e2e/run.sh   # reuse images
# one milestone with the tests it builds on (M8 needs the enrolled agent, the M2 destination and M3's Vault job)
E2E_RUN='^(TestM1EnrollInventoryDiscovery|TestM2BackupsPostgresAndClickHouse|TestM3VaultMakerChecker|TestM8Restores)$' ./test/e2e/run.sh
E2E_CPUS=4 ./test/e2e/run.sh     # nodes limited to 4 CPUs, like a GitHub runner
./test/e2e/run.sh down           # delete the cluster
```

Go sizes some things by the CPU count it sees (pgxpool's default pool is max(4, CPUs)), so a workstation
with many cores can hide bugs that CI shows. `E2E_CPUS` pins the kind node containers to that many CPUs;
running without it resets them to all CPUs.

## Browsable lab and screenshots

`./test/e2e/env.sh` builds the same lab plus a second cluster, `olympos-edge`, enrolls no agent and resets
Olympos to empty, for trying Olympos by hand: [docs/getting-started.md](../../docs/getting-started.md) walks
through it. `cd web && pnpm docs-tour` then replays that guide in Chrome and writes its screenshots to
`docs/images/` (needs a freshly reset lab).

