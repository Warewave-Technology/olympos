# e2e lab

`./test/e2e/run.sh` creates (or reuses) a 2-node kind cluster **`olympos-lab`** on the local Docker
(OrbStack works), with its own kubeconfig at `test/e2e/.work/kubeconfig`. Your current kube context
is never used or changed.

It builds `olympos-server:e2e` / `olympos-agent:e2e`, deploys:

| Namespace | Workload | Purpose |
|---|---|---|
| `olympos` | `olympos` (Helm chart, dev mode, local key vault on a PVC) | the server, UI at http://127.0.0.1:28080 |
| `olympos` | `olympos-db`, `azurite` | Olympos's database, Blob fake |
| `olympos-system` | `olympos-agent` (installed from the UI-generated command) | the agent |
| `lab` | `orders-pg` (TLS, lab CA), `vault` (raft), `openbao` (dev), `metrics-ch` | annotated targets |

and runs `go test -tags e2e ./test/e2e/...`. Some tests run a gateway **in-process** on the host and
point a second real agent at it through `host.docker.internal`, so they can ask the agent for arbitrary
target IDs (it must refuse anything it did not discover).

Dev sign-in: http://127.0.0.1:28080/auth/dev-login?oid=00000000-0000-0000-0000-00000000ad01&name=Lab%20Admin

Kyverno 1.20 is installed by default (CEL `ValidatingPolicy` only). `KYVERNO_CHART=3.9.2` installs 1.19,
where the legacy `ClusterPolicy` runs as well, so both agent code paths are exercised.

```bash
SKIP_BUILD=1 ./test/e2e/run.sh   # reuse images
E2E_CPUS=4 ./test/e2e/run.sh     # nodes limited to 4 CPUs, like a GitHub runner
./test/e2e/run.sh down           # delete the cluster
```

Go sizes some things by the CPU count it sees (pgxpool's default pool is max(4, CPUs)), so a workstation
with many cores can hide bugs that CI shows. `E2E_CPUS` pins the kind node containers to that many CPUs;
running without it resets them to all CPUs.
