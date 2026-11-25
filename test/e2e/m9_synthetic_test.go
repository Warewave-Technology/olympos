//go:build e2e

package e2e

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/inventory"
)

// Synthetic monitoring in the lab (docs/synthetic-monitoring.md): synth-web
// (test/e2e/cmd/synth-web) answers every *.olympos-lab.test name, and
// metadata.olympos-lab.test resolves to 169.254.169.254 (lib.sh
// patch_coredns).
const (
	labSuffix   = "olympos-lab.test"
	labBName    = "lab-b"
	labBNS      = "olympos-b"
	labBRelease = "olympos-agent-b"
)

// m9Cell and m9Row are the parts of GET /synthetic/overview the test reads.
type m9Cell struct {
	ClusterID     string `json:"cluster_id"`
	State         string `json:"state"`
	LastStatus    string `json:"last_status"`
	FailureReason string `json:"failure_reason"`
}

type m9Row struct {
	ID    string   `json:"id"`
	Cells []m9Cell `json:"cells"`
}

type m9Run struct {
	ID            string `json:"id"`
	ClusterName   string `json:"cluster_name"`
	Status        string `json:"status"`
	FailureReason string `json:"failure_reason"`
	Test          bool   `json:"test"`
	Steps         []struct {
		Position int     `json:"position"`
		Status   string  `json:"status"`
		Excerpt  *string `json:"excerpt"`
		Error    string  `json:"error"`
	} `json:"steps"`
}

// TestM9SyntheticMonitoring registers a second Olympos cluster, lab-b (an
// agent and probe release in olympos-b of the same kind cluster), runs a
// scenario with a bearer credential on both probes and checks the matrix,
// one critical message when synth-web fails, the recovery, redaction
// (no canary in the database, logs or outbox), the always-denied
// addresses, and that a stopped probe shows "probe offline" without failed
// runs (spec §9).
func TestM9SyntheticMonitoring(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")
	labB := ensureLabB(t, admin)
	waitProbesOnline(t, admin, labClusterID, labB)
	checkProbeIsolation(t, "olympos-system")
	checkProbeIsolation(t, labBNS)

	toggle := func(mode string) {
		t.Helper()
		run(t, "kubectl", "-n", "lab", "exec", "deploy/synth-web", "--", "/synth-web", "toggle", mode)
	}
	toggle("ok")
	t.Cleanup(func() {
		_, _ = runOK(t, "kubectl", "-n", "lab", "exec", "deploy/synth-web", "--", "/synth-web", "toggle", "ok")
	})

	// Settings › Synthetic monitoring: the allowlist rule and a bearer
	// credential bound to the lab domain. The canary must never come back.
	ensureRule(t, admin, labSuffix, "suffix")
	canary := "CANARY-synthetic-bearer-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	var cred struct {
		ID string `json:"id"`
	}
	admin.must("POST", "/synthetic/credentials", map[string]any{
		"name": "m9-shop-api-" + uuid.NewString()[:6], "kind": "bearer",
		"bound_hosts": []map[string]string{{"kind": "suffix", "pattern": labSuffix}},
		"secret":      map[string]any{"source": "stored", "password": canary},
	}, &cred, 201)
	t.Cleanup(func() { admin.do("DELETE", "/synthetic/credentials/"+cred.ID, nil, nil) })

	// The always-denied addresses are refused when saving, whatever the
	// allowlist says.
	for _, pattern := range []string{"kubernetes.default.svc", "169.254.169.254"} {
		if code, raw := admin.do("POST", "/synthetic/allowlist", map[string]any{"pattern": pattern, "kind": "exact"}, nil); code != 422 {
			t.Errorf("allowlist rule %s: %d %s (want 422)", pattern, code, raw)
		}
	}
	for _, u := range []string{"http://kubernetes.default.svc/api", "https://kubernetes.default.svc.cluster.local/version", "http://169.254.169.254/latest/meta-data/"} {
		body := m9Scenario("m9-denied", 0, map[string]any{"kind": "http", "http": map[string]any{"method": "GET", "url": u},
			"assertions": []map[string]string{{"subject": "status_code", "operator": "equals", "value": "200"}}})
		code, raw := admin.do("POST", "/synthetic/scenarios", body, nil)
		if code != 422 || !strings.Contains(raw, "steps.0.http.url") {
			t.Errorf("scenario to %s: %d %s (want 422 on steps.0.http.url)", u, code, raw)
		}
	}

	// A test run to a name inside the allowlist that resolves to the cloud
	// metadata address: the probe refuses the connection (ip_denied).
	var tr struct {
		RunID string `json:"run_id"`
	}
	admin.must("POST", "/synthetic/test-runs", map[string]any{
		"cluster_id": labClusterID,
		"scenario": m9Scenario("m9-metadata", 0, map[string]any{"kind": "http",
			"http":       map[string]any{"method": "GET", "url": "http://metadata." + labSuffix + "/latest/meta-data/"},
			"assertions": []map[string]string{{"subject": "status_code", "operator": "equals", "value": "200"}}}),
	}, &tr, 202)
	meta := waitRunDone(t, admin, tr.RunID)
	if meta.Status == "passed" || !strings.HasPrefix(meta.FailureReason, "ip_denied") {
		t.Errorf("test run to metadata.%s: %s %q (want ip_denied)", labSuffix, meta.Status, meta.FailureReason)
	}

	// The scenario: synth-web's health, then its items with the bearer.
	// Two failing clusters make the fleet alert critical.
	sc := m9Scenario("m9-shop-"+uuid.NewString()[:6], 2,
		map[string]any{"kind": "http", "http": map[string]any{"method": "GET", "url": "http://shop." + labSuffix + "/health"},
			"assertions": []map[string]string{{"subject": "status_code", "operator": "equals", "value": "200"}}},
		map[string]any{"kind": "http", "http": map[string]any{"method": "GET", "url": "http://shop." + labSuffix + "/api/items"},
			"credential_id": cred.ID,
			"assertions": []map[string]string{
				{"subject": "status_code", "operator": "equals", "value": "200"},
				{"subject": "json:$.count", "operator": "equals", "value": "2"},
			}})
	var created struct {
		ID string `json:"id"`
	}
	admin.must("POST", "/synthetic/scenarios", sc, &created, 201)
	scenarioID := created.ID
	t.Cleanup(func() { admin.do("DELETE", "/synthetic/scenarios/"+scenarioID, nil, nil) })
	pair := []string{labClusterID, labB}

	waitCells(t, admin, scenarioID, pair, 4*time.Minute, "passing")

	// The excerpt of the credentialed step: the echoed token and the cookie
	// are redacted on the probe.
	var runs struct {
		Items []m9Run `json:"items"`
	}
	admin.must("GET", "/synthetic/runs?status=passed&limit=5&scenario_id="+scenarioID, nil, &runs, 200)
	if len(runs.Items) == 0 {
		t.Fatal("no passed run")
	}
	var detail m9Run
	admin.must("GET", "/synthetic/runs/"+runs.Items[0].ID, nil, &detail, 200)
	if len(detail.Steps) != 2 || detail.Steps[1].Excerpt == nil {
		t.Fatalf("run detail steps: %+v", detail.Steps)
	}
	ex := *detail.Steps[1].Excerpt
	t.Logf("excerpt of /api/items:\n%s", ex)
	if !strings.Contains(ex, `"echo":"[redacted]"`) || !strings.Contains(ex, "Set-Cookie: [redacted]") || !strings.Contains(ex, `"count":2`) {
		t.Errorf("excerpt not redacted as expected:\n%s", ex)
	}

	// synth-web answers 500: after three failed runs on each cluster both
	// cluster alerts fire, and the fleet alert sends one critical message.
	toggle("500")
	waitCells(t, admin, scenarioID, pair, 5*time.Minute, "failing")
	if s := cellStates(t, admin, scenarioID); !strings.Contains(s[labClusterID], "assertion_failed") {
		t.Errorf("failing cell on lab: %q (want the 500 as assertion_failed)", s[labClusterID])
	}
	eventually(t, time.Minute, "synthetic.critical in the outbox", func() (bool, string) {
		n := olymposSQL(t, fmt.Sprintf(`SELECT count(*) FROM outbox WHERE event_type = 'synthetic.critical' AND payload->>'scenario_id' = '%s'`, scenarioID))
		return n == "1", n
	})
	checkAlertMessages(t, scenarioID, false)

	// Back to ok: two passing runs resolve the alerts, with recovery
	// messages that name each alert once.
	toggle("ok")
	waitCells(t, admin, scenarioID, pair, 4*time.Minute, "passing")
	eventually(t, 2*time.Minute, "alerts resolved and notified", func() (bool, string) {
		out := olymposSQL(t, fmt.Sprintf(`SELECT count(*) FILTER (WHERE state <> 'resolved' OR resolved_notified_at IS NULL) || '/' || count(*)
			FROM synthetic_alerts WHERE scenario_id = '%s'`, scenarioID))
		return strings.HasPrefix(out, "0/"), out
	})
	checkAlertMessages(t, scenarioID, true)
	if n := olymposSQL(t, fmt.Sprintf(`SELECT count(*) FROM outbox WHERE event_type = 'synthetic.critical' AND payload->>'scenario_id' = '%s'`, scenarioID)); n != "1" {
		t.Errorf("synthetic.critical messages: %s (want 1)", n)
	}

	checkNoCanary(t, canary, scenarioID)

	// A credential that cannot be resolved: one alert, one attention item,
	// one recovery, and no failing scenario (#54).
	checkCredentialAlerts(t, admin, pair)

	// lab-b's probe stops: its cells read "probe offline", and no run on
	// lab-b fails or errors meanwhile (an offline probe is not a failure).
	// A run the probe was running when it stopped ends skipped
	// (probe_disconnected); waiting for none to be running makes that rare.
	eventually(t, time.Minute, "no lab-b run in flight", func() (bool, string) {
		n := olymposSQL(t, fmt.Sprintf(`SELECT count(*) FROM synthetic_runs WHERE cluster_id = '%s' AND status = 'running'`, labB))
		return n == "0", n
	})
	since := olymposSQL(t, "SELECT now()")
	t.Cleanup(func() { _, _ = runOK(t, "kubectl", "-n", labBNS, "scale", "deploy/olympos-probe", "--replicas=1") })
	run(t, "kubectl", "-n", labBNS, "scale", "deploy/olympos-probe", "--replicas=0")
	waitCells(t, admin, scenarioID, []string{labB}, 3*time.Minute, "probe_offline")
	time.Sleep(70 * time.Second) // two more intervals with the probe offline
	if s := cellStates(t, admin, scenarioID); s[labB] != "probe_offline" || s[labClusterID] != "passing" {
		t.Errorf("cells after the probe stopped: %v", s)
	}
	// Every lab-b run that ended since is skipped (probe_offline,
	// probe_disconnected, not_dispatched), never failed or error.
	out := olymposSQL(t, fmt.Sprintf(`SELECT count(*) FILTER (WHERE status <> 'skipped') || ' ' ||
		coalesce(string_agg(DISTINCT status || ':' || failure_reason, ','), '')
		FROM synthetic_runs WHERE cluster_id = '%s' AND scenario_id = '%s' AND finished_at > '%s'`, labB, scenarioID, since))
	t.Logf("lab-b runs after the probe stopped: %s", out)
	if !strings.HasPrefix(out, "0 ") && out != "0" {
		t.Errorf("lab-b runs that were not skipped while its probe was offline: %s", out)
	}
	if n := olymposSQL(t, fmt.Sprintf(`SELECT count(*) FROM synthetic_alerts WHERE scenario_id = '%s' AND state = 'firing'`, scenarioID)); n != "0" {
		t.Errorf("firing alerts with the probe offline: %s", n)
	}
	run(t, "kubectl", "-n", labBNS, "scale", "deploy/olympos-probe", "--replicas=1")
	waitProbesOnline(t, admin, labB)
}

// kvWriterPod mounts the server's local Key Vault (the PVC of the lab's
// "local" key vault provider), which the server image cannot write to from
// outside: it has no shell. It runs as the server's user, so the files it
// writes are readable by the server.
const kvWriterPod = `apiVersion: v1
kind: Pod
metadata: {name: m9-kv-writer, namespace: olympos}
spec:
  securityContext: {runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532}
  containers:
  - name: c
    image: busybox:1.36
    command: [sleep, "3600"]
    volumeMounts: [{name: kv, mountPath: /kv}]
  volumes:
  - name: kv
    persistentVolumeClaim: {claimName: olympos-localkv}
`

// checkCredentialAlerts points a credential at a local Key Vault secret that
// does not exist and checks that, however many runs and clusters it takes:
// the cells read "credential_error", the Dashboard has one Needs attention
// item and the outbox one synthetic.credential_broken, no run counts as a
// failure and no scenario alert opens. Then it writes the secret and checks
// that the cells pass, the item goes and one synthetic.credential_restored
// goes out (docs/design/credential-alerts.md). Last, a short temporary
// failure: credential_unavailable cells and no message (#69).
func checkCredentialAlerts(t *testing.T, admin *client, clusters []string) {
	t.Helper()
	applyStdin(t, kvWriterPod)
	t.Cleanup(func() {
		_, _ = runOK(t, "kubectl", "-n", "olympos", "delete", "pod/m9-kv-writer", "--ignore-not-found", "--wait=false")
	})
	run(t, "kubectl", "-n", "olympos", "wait", "--for=condition=Ready", "pod/m9-kv-writer", "--timeout=180s")
	secretName := "m9-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	t.Cleanup(func() {
		_, _ = runOK(t, "kubectl", "-n", "olympos", "exec", "m9-kv-writer", "--", "rm", "-f", "/kv/secrets/lab/"+secretName)
	})

	// A Key Vault reference to a secret that is not in the vault yet.
	name := "m9-kv-" + uuid.NewString()[:6]
	var cred struct {
		ID string `json:"id"`
	}
	admin.must("POST", "/synthetic/credentials", map[string]any{
		"name": name, "kind": "bearer",
		"bound_hosts": []map[string]string{{"kind": "suffix", "pattern": labSuffix}},
		"secret":      map[string]any{"source": "keyvault_ref", "ref": "kv://lab/" + secretName},
	}, &cred, 201)
	t.Cleanup(func() { admin.do("DELETE", "/synthetic/credentials/"+cred.ID, nil, nil) })
	sc := m9Scenario("m9-kv-"+uuid.NewString()[:6], 2,
		map[string]any{"kind": "http", "http": map[string]any{"method": "GET", "url": "http://shop." + labSuffix + "/api/items"},
			"credential_id": cred.ID,
			"assertions":    []map[string]string{{"subject": "status_code", "operator": "equals", "value": "200"}}})
	var created struct {
		ID string `json:"id"`
	}
	admin.must("POST", "/synthetic/scenarios", sc, &created, 201)
	scenarioID := created.ID
	t.Cleanup(func() { admin.do("DELETE", "/synthetic/scenarios/"+scenarioID, nil, nil) })

	// Broken: the cell, the credential and the attention item.
	waitCells(t, admin, scenarioID, clusters, 4*time.Minute, "credential_error")
	credState := func() (state, cause string) {
		var list struct {
			Items []struct {
				ID           string `json:"id"`
				ResolveState string `json:"resolve_state"`
				ResolveCause string `json:"resolve_cause"`
			} `json:"items"`
		}
		admin.must("GET", "/synthetic/credentials", nil, &list, 200)
		for _, c := range list.Items {
			if c.ID == cred.ID {
				return c.ResolveState, c.ResolveCause
			}
		}
		return "", ""
	}
	if state, cause := credState(); state != "broken" || cause != "not_found" {
		t.Errorf("credential state %q cause %q (want broken, not_found)", state, cause)
	}
	attention := func() int {
		var dash struct {
			Attention []struct{ Kind, Severity, Detail string } `json:"attention"`
		}
		admin.must("GET", "/dashboard", nil, &dash, 200)
		n := 0
		for _, a := range dash.Attention {
			if a.Kind == "synthetic_credential_broken" && strings.Contains(a.Detail, "Credential "+name+" ") {
				n++
				if a.Severity != "crit" || !strings.Contains(a.Detail, "1 scenario affected") {
					t.Errorf("attention item: %+v (want crit, 1 scenario affected)", a)
				}
			}
		}
		return n
	}
	if n := attention(); n != 1 {
		t.Errorf("Needs attention items for the credential: %d (want 1)", n)
	}

	// Let a few more runs end on both clusters: still one message, and the
	// runs are errors that count for nothing.
	time.Sleep(70 * time.Second)
	count := func(typ string) string {
		return olymposSQL(t, fmt.Sprintf(`SELECT count(*) FROM outbox WHERE event_type = '%s' AND payload->>'credential_id' = '%s'`, typ, cred.ID))
	}
	if n := count("synthetic.credential_broken"); n != "1" {
		t.Errorf("synthetic.credential_broken messages: %s (want 1)", n)
	}
	if n := count("synthetic.credential_restored"); n != "0" {
		t.Errorf("synthetic.credential_restored messages while broken: %s (want 0)", n)
	}
	runs := olymposSQL(t, fmt.Sprintf(`SELECT count(*) FILTER (WHERE failure_reason = 'credential_broken' AND status = 'error') || ' ' ||
		count(*) FILTER (WHERE status IN ('passed','failed','error') AND failure_reason IS DISTINCT FROM 'credential_broken')
		FROM synthetic_runs WHERE scenario_id = '%s' AND NOT test`, scenarioID))
	broken, other, _ := strings.Cut(runs, " ")
	if b, _ := strconv.Atoi(broken); b < 2 || other != "0" {
		t.Errorf("runs of the scenario: %s (want at least 2 credential_broken errors and no other counted run)", runs)
	}
	if n := olymposSQL(t, fmt.Sprintf(`SELECT (SELECT count(*) FROM synthetic_alerts WHERE scenario_id = '%s') || '/' ||
		(SELECT count(*) FROM outbox WHERE event_type IN ('synthetic.failing','synthetic.critical') AND payload->>'scenario_id' = '%s')`, scenarioID, scenarioID)); n != "0/0" {
		t.Errorf("scenario alerts and messages for a broken credential: %s (want 0/0)", n)
	}

	// Put the secret back (as the server's user, so that it can read it).
	run(t, "kubectl", "-n", "olympos", "exec", "m9-kv-writer", "--", "sh", "-c",
		"mkdir -p /kv/secrets/lab && printf %s m9-token > /kv/secrets/lab/"+secretName)
	waitCells(t, admin, scenarioID, clusters, 4*time.Minute, "passing")
	if state, cause := credState(); state != "ok" || cause != "" {
		t.Errorf("credential state after the secret came back: %q %q (want ok)", state, cause)
	}
	eventually(t, time.Minute, "Needs attention item gone", func() (bool, string) {
		n := attention()
		return n == 0, fmt.Sprint(n)
	})
	if n := count("synthetic.credential_restored"); n != "1" {
		t.Errorf("synthetic.credential_restored messages: %s (want 1)", n)
	}
	if n := count("synthetic.credential_broken"); n != "1" {
		t.Errorf("synthetic.credential_broken messages after recovery: %s (want 1)", n)
	}

	// Temporary (#69): a directory where the secret was is neither missing
	// nor forbidden, so the local Key Vault cannot read it for now. The
	// cells say so at once; no message before 30 minutes.
	run(t, "kubectl", "-n", "olympos", "exec", "m9-kv-writer", "--", "sh", "-c",
		"rm /kv/secrets/lab/"+secretName+" && mkdir /kv/secrets/lab/"+secretName)
	waitCells(t, admin, scenarioID, clusters, 4*time.Minute, "credential_unavailable")
	if state, cause := credState(); state != "unavailable" || cause != "unavailable" {
		t.Errorf("credential state with an unreadable secret: %q %q (want unavailable, unavailable)", state, cause)
	}
	run(t, "kubectl", "-n", "olympos", "exec", "m9-kv-writer", "--", "sh", "-c",
		"rmdir /kv/secrets/lab/"+secretName+" && printf %s m9-token > /kv/secrets/lab/"+secretName)
	waitCells(t, admin, scenarioID, clusters, 4*time.Minute, "passing")
	if b, r := count("synthetic.credential_broken"), count("synthetic.credential_restored"); b != "1" || r != "1" {
		t.Errorf("messages after a short unavailable episode: %s broken, %s restored (want 1 and 1)", b, r)
	}
}

// ensureLabB registers lab-b and installs its agent and probe in
// olympos-b of the lab cluster, from the generated command.
func ensureLabB(t *testing.T, admin *client) string {
	t.Helper()
	var clusters struct {
		Items []inventory.Cluster `json:"items"`
	}
	admin.must("GET", "/clusters", nil, &clusters, 200)
	for _, c := range clusters.Items {
		if c.Name == labBName && c.Status != "revoked" {
			return c.ID.String()
		}
	}
	var created inventory.InstallResponse
	admin.must("POST", "/clusters", map[string]any{"name": labBName, "labels": map[string]string{"env": "lab", "team": "platform-b"}}, &created, 201)
	sets := helmSets(created.Command)
	sets["providerOverride"] = "onprem"
	installAgent(t, labBRelease, labBNS, sets)
	return created.Cluster.ID.String()
}

// waitProbesOnline waits until the agent and the probe of each cluster are
// online.
func waitProbesOnline(t *testing.T, admin *client, ids ...string) {
	t.Helper()
	for _, id := range ids {
		eventually(t, 3*time.Minute, "agent and probe online on "+id, func() (bool, string) {
			var c inventory.Cluster
			admin.must("GET", "/clusters/"+id, nil, &c, 200)
			return c.Status == "online" && c.ProbeStatus == "online" && c.ProbeVersion != "", c.Status + "/" + c.ProbeStatus
		})
	}
}

// checkProbeIsolation: the probe's ServiceAccount may do nothing and the
// pod gets no token, runs read-only and non-root (spec §2.1).
func checkProbeIsolation(t *testing.T, ns string) {
	t.Helper()
	sa := "system:serviceaccount:" + ns + ":olympos-probe"
	for _, args := range [][]string{
		{"get", "secrets", "-n", ns}, {"get", "secret/olympos-probe-identity", "-n", ns},
		{"list", "pods", "-A"}, {"get", "services", "-n", "lab"}, {"create", "pods", "-n", ns},
	} {
		if out, _ := runOK(t, "kubectl", append([]string{"auth", "can-i", "--as", sa}, args...)...); strings.TrimSpace(out) != "no" {
			t.Errorf("probe in %s: can-i %v = %q, want no", ns, args, strings.TrimSpace(out))
		}
	}
	if out := run(t, "kubectl", "get", "rolebindings,clusterrolebindings", "-A", "-o",
		`jsonpath={range .items[*]}{range .subjects[*]}{.namespace}/{.name}{"\n"}{end}{end}`); slices.Contains(strings.Fields(out), ns+"/olympos-probe") {
		t.Errorf("a binding names the probe's ServiceAccount in %s", ns)
	}
	spec := run(t, "kubectl", "-n", ns, "get", "deploy", "olympos-probe", "-o", "jsonpath={.spec.template.spec}")
	for _, want := range []string{`"automountServiceAccountToken":false`, `"readOnlyRootFilesystem":true`, `"runAsNonRoot":true`} {
		if !strings.Contains(spec, want) {
			t.Errorf("probe pod spec in %s lacks %s: %s", ns, want, spec)
		}
	}
	if strings.Contains(spec, "containerPort") {
		t.Errorf("probe pod in %s exposes a port", ns)
	}
}

// ensureRule returns the id of an allowlist rule, adding it (and its
// removal at the end of the test) if needed.
func ensureRule(t *testing.T, admin *client, pattern, kind string) string {
	t.Helper()
	var list struct {
		Items []struct {
			ID      string `json:"id"`
			Pattern string `json:"pattern"`
			Kind    string `json:"kind"`
		} `json:"items"`
	}
	admin.must("GET", "/synthetic/allowlist", nil, &list, 200)
	for _, r := range list.Items {
		if r.Pattern == pattern && r.Kind == kind {
			return r.ID
		}
	}
	var r struct {
		ID string `json:"id"`
	}
	admin.must("POST", "/synthetic/allowlist", map[string]any{"pattern": pattern, "kind": kind, "note": "e2e lab (synth-web)"}, &r, 201)
	t.Cleanup(func() { admin.do("DELETE", "/synthetic/allowlist/"+r.ID, nil, nil) })
	return r.ID
}

// m9Scenario is a scenario body that runs every 30 s on all clusters; fleet
// > 0 sets the alert rule.
func m9Scenario(name string, fleet int, steps ...map[string]any) map[string]any {
	typ := "http"
	if len(steps) > 1 {
		typ = "http_flow"
	}
	sc := map[string]any{"name": name, "type": typ, "interval_seconds": 30, "timeout_seconds": 10, "store_responses": true,
		"run_on": "all", "steps": steps}
	if fleet > 0 {
		sc["alerts"] = map[string]any{"cluster_fail_after": 3, "fleet_critical_clusters": fleet, "recovery_after": 2, "send_recovery": true}
	}
	return sc
}

func cellStates(t *testing.T, admin *client, scenarioID string) map[string]string {
	t.Helper()
	var ov struct {
		Scenarios []m9Row `json:"scenarios"`
	}
	admin.must("GET", "/synthetic/overview", nil, &ov, 200)
	out := map[string]string{}
	for _, r := range ov.Scenarios {
		if r.ID == scenarioID {
			for _, c := range r.Cells {
				out[c.ClusterID] = c.State
				if c.FailureReason != "" {
					out[c.ClusterID] += " (" + c.FailureReason + ")"
				}
			}
		}
	}
	return out
}

// waitCells waits until the scenario's cells on these clusters are in state.
func waitCells(t *testing.T, admin *client, scenarioID string, clusters []string, timeout time.Duration, state string) {
	t.Helper()
	eventually(t, timeout, "cells "+state, func() (bool, string) {
		s := cellStates(t, admin, scenarioID)
		for _, id := range clusters {
			if st, _, _ := strings.Cut(s[id], " ("); st != state {
				return false, fmt.Sprint(s)
			}
		}
		return true, ""
	})
}

func waitRunDone(t *testing.T, admin *client, id string) m9Run {
	t.Helper()
	var r m9Run
	eventually(t, 2*time.Minute, "run "+id+" finished", func() (bool, string) {
		admin.must("GET", "/synthetic/runs/"+id, nil, &r, 200)
		return r.Status != "scheduled" && r.Status != "running", r.Status
	})
	return r
}

// checkAlertMessages checks that each of the scenario's alerts is named by
// exactly one open message (synthetic.failing or synthetic.critical) and,
// when resolved, by exactly one synthetic.recovered: no repeats (spec §5).
func checkAlertMessages(t *testing.T, scenarioID string, resolved bool) {
	t.Helper()
	alerts := strings.Fields(olymposSQL(t, fmt.Sprintf(`SELECT id FROM synthetic_alerts WHERE scenario_id = '%s'`, scenarioID)))
	if len(alerts) != 3 {
		t.Errorf("alerts of the scenario: %d (want 2 cluster alerts and 1 fleet alert)", len(alerts))
	}
	types := [][]string{{"synthetic.failing", "synthetic.critical"}}
	if resolved {
		types = append(types, []string{"synthetic.recovered"})
	}
	for _, ts := range types {
		rows := olymposSQL(t, fmt.Sprintf(`SELECT event_type || ' ' || (payload->'alert_ids')::text FROM outbox
			WHERE event_type IN ('%s') AND payload->>'scenario_id' = '%s' ORDER BY created_at`, strings.Join(ts, "','"), scenarioID))
		t.Logf("%v messages:\n%s", ts, rows)
		seen := map[string]int{}
		for _, line := range strings.Split(rows, "\n") {
			_, ids, ok := strings.Cut(line, " ")
			if !ok {
				continue
			}
			var list []string
			if err := json.Unmarshal([]byte(ids), &list); err != nil {
				t.Fatalf("alert_ids %q: %v", ids, err)
			}
			for _, id := range list {
				seen[id]++
			}
		}
		for _, id := range alerts {
			if seen[id] != 1 {
				t.Errorf("%v: alert %s named %d times (want once)", ts, id, seen[id])
			}
		}
		if len(seen) != len(alerts) {
			t.Errorf("%v name %d alerts, the scenario has %d", ts, len(seen), len(alerts))
		}
	}
}

// checkNoCanary looks for the credential everywhere it could leak to: the
// database (a full dump, where pg_dump writes the bytea excerpts as hex,
// and SQL over the step results, the run reasons and the outbox), and the
// logs of every server, probe and agent pod. Matches ignore case.
func checkNoCanary(t *testing.T, canary, scenarioID string) {
	t.Helper()
	low := strings.ToLower(canary)
	dump := strings.ToLower(run(t, "kubectl", "-n", "olympos", "exec", "statefulset/olympos-postgresql", "--",
		"pg_dump", "-U", "olympos", "--data-only", "olympos"))
	if !strings.Contains(dump, scenarioID) {
		t.Fatal("database dump does not hold the scenario: the canary check would look at the wrong database")
	}
	if strings.Contains(dump, low) {
		t.Error("canary credential found in the database dump")
	}
	// Control: the redacted excerpts are in the dump, as hex.
	if !strings.Contains(dump, hex.EncodeToString([]byte(`"echo":"[redacted]"`))) {
		t.Error("no excerpt found in the dump as hex: the hex search would prove nothing")
	}
	for _, form := range []string{canary, low} {
		if strings.Contains(dump, hex.EncodeToString([]byte(form))) {
			t.Error("canary credential found in the database dump as hex (a bytea column)")
		}
	}

	// The canary is ours (letters, digits, dashes): safe as an SQL literal.
	if n := olymposSQL(t, `SELECT count(*) FROM synthetic_step_results WHERE excerpt IS NOT NULL`); n == "0" {
		t.Error("no stored excerpt: the excerpt check would prove nothing")
	}
	raw, lit := "'"+canary+"'", "'"+low+"'"
	for what, sql := range map[string]string{
		"excerpts":   `SELECT count(*) FROM synthetic_step_results WHERE position(convert_to(` + raw + `, 'UTF8') in excerpt) > 0 OR position(convert_to(` + lit + `, 'UTF8') in excerpt) > 0`,
		"errors":     `SELECT count(*) FROM synthetic_step_results WHERE position(` + lit + ` in lower(error)) > 0`,
		"assertions": `SELECT count(*) FROM synthetic_step_results WHERE position(` + lit + ` in lower(assertions::text)) > 0`,
		"reasons":    `SELECT count(*) FROM synthetic_runs WHERE position(` + lit + ` in lower(failure_reason)) > 0`,
		"outbox":     `SELECT count(*) FROM outbox WHERE position(` + lit + ` in lower(payload::text)) > 0`,
	} {
		if n := olymposSQL(t, sql); n != "0" {
			t.Errorf("canary credential found in %s: %s rows", what, n)
		}
	}

	for _, p := range []struct{ ns, app string }{
		{"olympos", "olympos-server"}, {"olympos-system", "olympos-probe"}, {"olympos-system", "olympos-agent"},
		{labBNS, "olympos-probe"}, {labBNS, "olympos-agent"},
	} {
		pods := strings.Fields(run(t, "kubectl", "-n", p.ns, "get", "pods", "-l", "app.kubernetes.io/name="+p.app,
			"-o", "jsonpath={.items[*].metadata.name}"))
		if len(pods) == 0 {
			t.Errorf("no %s pod in %s to check", p.app, p.ns)
		}
		for _, pod := range pods {
			logs := run(t, "kubectl", "-n", p.ns, "logs", pod, "--all-containers", "--tail=-1")
			if strings.Contains(strings.ToLower(logs), low) {
				t.Errorf("canary credential found in the logs of %s/%s", p.ns, pod)
			}
		}
	}
}
