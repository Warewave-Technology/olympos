package security

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/Warewave-Technology/olympos/internal/findings"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Finding control IDs.
const (
	ControlNoDefaultDeny = "netpol.no_default_deny"
)

// Limits on agent input (an agent is trusted only for its own cluster).
const (
	maxImageUses   = 100000
	maxPolicies    = 20000
	maxResults     = 20000
	maxNamespaces  = 20000
	unchangedSkipT = time.Hour
)

// Ingester stores ResourceReports (gateway Hooks.Report).
type Ingester struct {
	DB  *store.DB
	Log *slog.Logger
	// SystemNamespaces are excluded from the default-deny check (globs).
	SystemNamespaces []string
	// OnNewImages is called after a report added digests never seen before.
	OnNewImages func()

	mu   sync.Mutex
	last map[string]lastReport // cluster|kind → hash of the last stored report
}

type lastReport struct {
	sum [32]byte
	at  time.Time
}

// unchanged reports whether an identical report was stored recently, so the
// periodic resend from agents does not rewrite thousands of rows.
func (in *Ingester) unchanged(clusterID uuid.UUID, kind string, m proto.Message) (bool, func()) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return false, func() {}
	}
	sum := sha256.Sum256(b)
	key := clusterID.String() + "|" + kind
	in.mu.Lock()
	defer in.mu.Unlock()
	if l, ok := in.last[key]; ok && l.sum == sum && time.Since(l.at) < unchangedSkipT {
		return true, func() {}
	}
	return false, func() {
		in.mu.Lock()
		defer in.mu.Unlock()
		if in.last == nil {
			in.last = map[string]lastReport{}
		}
		in.last[key] = lastReport{sum: sum, at: time.Now()}
	}
}

// Report dispatches one report.
func (in *Ingester) Report(ctx context.Context, clusterID uuid.UUID, r *pb.ResourceReport) error {
	switch v := r.GetReport().(type) {
	case *pb.ResourceReport_Kyverno:
		return in.ingest(ctx, clusterID, "kyverno", v.Kyverno, func(tx pgx.Tx) (bool, error) {
			return false, in.kyverno(ctx, tx, clusterID, v.Kyverno)
		})
	case *pb.ResourceReport_NetworkPolicies:
		return in.ingest(ctx, clusterID, "netpol", v.NetworkPolicies, func(tx pgx.Tx) (bool, error) {
			return false, in.netpol(ctx, tx, clusterID, v.NetworkPolicies)
		})
	case *pb.ResourceReport_Images:
		return in.ingest(ctx, clusterID, "images", v.Images, func(tx pgx.Tx) (bool, error) {
			return in.images(ctx, tx, clusterID, v.Images)
		})
	case *pb.ResourceReport_SensitiveData:
		return in.ingest(ctx, clusterID, "sensitive-data", v.SensitiveData, func(tx pgx.Tx) (bool, error) {
			return false, in.sensitiveData(ctx, tx, clusterID, v.SensitiveData)
		})
	}
	return nil
}

// SensitiveFix is shown with every sensitive-data finding.
const SensitiveFix = "Move this value to a Secret or Vault and remove it from the ConfigMap."

// sensitiveData reconciles the sensitive-data findings of a cluster with a
// full agent report (F2). The report has no values: only where and which
// rule. Findings resolve when the key is gone or no longer matches.
// Olympos never edits or deletes ConfigMaps.
func (in *Ingester) sensitiveData(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, rep *pb.SensitiveDataReport) error {
	var current []findings.Finding
	for _, it := range rep.Items {
		ns, name, key := clean(it.Namespace, 253), clean(it.ConfigMap, 253), clean(it.Key, 253)
		if MatchesAny(in.SystemNamespaces, ns) {
			continue
		}
		sev := "medium"
		if it.Confidence == "high" {
			sev = "high"
		}
		current = append(current, findings.Finding{
			ControlID: clean(it.RuleId, 120), Severity: sev, ResourceRef: ns + "/" + name + ":" + key,
			Title: fmt.Sprintf("%s in ConfigMap %s/%s (key %s)", clean(it.RuleDescription, 200), ns, name, key),
			Details: map[string]any{"namespace": ns, "config_map": name, "key": key, "rule_id": clean(it.RuleId, 120),
				"rule_description": clean(it.RuleDescription, 300), "confidence": it.Confidence, "value_length": it.ValueLength,
				"rules_version": clean(rep.RulesVersion, 80), "fix": SensitiveFix},
		})
	}
	newCount, _, err := findings.Reconcile(ctx, tx, findings.SourceSensitiveData, clusterID, current, nil)
	if err != nil || newCount == 0 {
		return err
	}
	return in.emitSensitiveFound(ctx, tx, clusterID, current, newCount)
}

// emitSensitiveFound sends one sensitive_data.found per cluster and scan
// with counts and the top 5 (high first): grouped like F9.
func (in *Ingester) emitSensitiveFound(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, current []findings.Finding, newCount int) error {
	var name string
	if err := tx.QueryRow(ctx, `SELECT name FROM clusters WHERE id = $1`, clusterID).Scan(&name); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT resource_ref, control_id, severity FROM findings WHERE source = $1 AND cluster_id = $2 AND status = 'open'
		AND first_seen_at > now() - interval '1 minute' ORDER BY severity = 'high' DESC, resource_ref LIMIT 5`, findings.SourceSensitiveData, clusterID)
	if err != nil {
		return err
	}
	var top []string
	for rows.Next() {
		var ref, rule, sev string
		if err := rows.Scan(&ref, &rule, &sev); err != nil {
			rows.Close()
			return err
		}
		top = append(top, fmt.Sprintf("%s (%s, %s)", ref, rule, sev))
	}
	rows.Close()
	high := 0
	for _, f := range current {
		if f.Severity == "high" {
			high++
		}
	}
	return notify.Emit(ctx, tx, notify.Event{Type: notify.SensitiveDataFound,
		Title: fmt.Sprintf("%d new credential-like values in ConfigMaps on %s", newCount, name),
		Link:  "/security?cluster=" + clusterID.String() + "&tab=sensitive",
		Fields: map[string]string{"cluster": name, "new": fmt.Sprint(newCount), "open": fmt.Sprint(len(current)),
			"high": fmt.Sprint(high), "top": strings.Join(top, "; ")},
		Payload: map[string]any{"cluster_id": clusterID.String(), "new": newCount}})
}

func (in *Ingester) ingest(ctx context.Context, clusterID uuid.UUID, kind string, m proto.Message, fn func(tx pgx.Tx) (bool, error)) error {
	if m == nil {
		return nil
	}
	skip, remember := in.unchanged(clusterID, kind, m)
	if skip {
		return nil
	}
	var newImages bool
	err := store.Tx(ctx, in.DB, func(tx pgx.Tx) error {
		var n bool
		var err error
		n, err = fn(tx)
		newImages = n
		return err
	})
	if err != nil {
		return fmt.Errorf("ingest %s report: %w", kind, err)
	}
	remember()
	if newImages && in.OnNewImages != nil {
		in.OnNewImages()
	}
	return nil
}

// clean strips NUL bytes (not storable in Postgres text) and bounds length.
func clean(s string, max int) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	return truncateStr(s, max)
}

// ---------------------------------------------------------------- kyverno

var findingSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

func kyvernoResourceRef(x *pb.KyvernoResult) string {
	parts := []string{}
	for _, p := range []string{x.ResourceKind, x.ResourceNamespace, x.ResourceName} {
		if p != "" {
			parts = append(parts, clean(p, 253))
		}
	}
	return strings.Join(parts, "/")
}

// kyvernoKinds are the policy kinds the agent reports.
var kyvernoKinds = map[string]bool{
	"ClusterPolicy": true, "Policy": true, "ValidatingPolicy": true, "NamespacedValidatingPolicy": true,
	"ImageValidatingPolicy": true, "NamespacedImageValidatingPolicy": true,
}

// policyKind validates the reported kind; older agents send none, so it is
// inferred from the namespace (legacy kinds). Unknown kinds are dropped.
func policyKind(p *pb.KyvernoPolicy) string {
	if p.Kind == "" {
		if p.Namespace == "" {
			return "ClusterPolicy"
		}
		return "Policy"
	}
	if kyvernoKinds[p.Kind] {
		return p.Kind
	}
	return ""
}

// policyResults returns the results (indexed by policy string) that belong
// to a policy. Kyverno writes the bare name for cluster-scoped policies and
// either "ns/name" or the bare name (in the resource's namespace) for
// namespaced ones.
func policyResults(p *pb.KyvernoPolicy, byPolicy map[string][]*pb.KyvernoResult) []*pb.KyvernoResult {
	if p.Namespace == "" {
		return byPolicy[p.Name]
	}
	out := append([]*pb.KyvernoResult{}, byPolicy[p.Namespace+"/"+p.Name]...)
	for _, x := range byPolicy[p.Name] {
		if x.ResourceNamespace == p.Namespace {
			out = append(out, x)
		}
	}
	return out
}

// Server-side caps on stored specs (the agent caps first; it is trusted only
// for its own cluster).
const (
	maxPolicyObjectBytes = 128 << 10
	maxNetpolSpecBytes   = 64 << 10
)

type policyObject struct {
	apiVersion  string
	annotations map[string]string
	spec        []byte // JSON, nil when absent
	invalid     bool   // sent but unusable (too large, not JSON)
}

// parsePolicyObject extracts apiVersion, the policies.kyverno.io/*
// annotations and spec from the agent's trimmed policy object.
func parsePolicyObject(b []byte) policyObject {
	out := policyObject{annotations: map[string]string{}}
	if len(b) == 0 {
		return out
	}
	obj, ok := cleanJSON(b, maxPolicyObjectBytes)
	m, isObj := obj.(map[string]any)
	if !ok || !isObj {
		out.invalid = true
		return out
	}
	out.apiVersion, _ = m["apiVersion"].(string)
	out.apiVersion = clean(out.apiVersion, 128)
	if meta, ok := m["metadata"].(map[string]any); ok {
		if ann, ok := meta["annotations"].(map[string]any); ok {
			for k, v := range ann {
				if s, ok := v.(string); ok && strings.HasPrefix(k, "policies.kyverno.io/") && len(out.annotations) < 32 {
					out.annotations[clean(k, 253)] = clean(s, 4096)
				}
			}
		}
	}
	if spec, ok := m["spec"]; ok && spec != nil {
		out.spec, _ = json.Marshal(spec)
	}
	return out
}

// cleanJSON decodes JSON of at most max bytes and strips NUL characters from
// keys and strings (jsonb rejects \u0000). Numbers keep their precision.
func cleanJSON(b []byte, max int) (any, bool) {
	if len(b) == 0 || len(b) > max {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil, false
	}
	return stripNUL(v), true
}

func stripNUL(v any) any {
	switch x := v.(type) {
	case string:
		return strings.ReplaceAll(x, "\x00", "")
	case []any:
		for i := range x {
			x[i] = stripNUL(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[strings.ReplaceAll(k, "\x00", "")] = stripNUL(e)
		}
		return out
	}
	return v
}

func (in *Ingester) kyverno(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, rep *pb.KyvernoReport) error {
	policies, results := rep.Policies, rep.Results
	if len(policies) > maxPolicies {
		policies = policies[:maxPolicies]
	}
	if len(results) > maxResults {
		results = results[:maxResults]
	}
	if !rep.Installed {
		policies, results = nil, nil
	}
	// Distinct failures (policy, rule, resource).
	type fkey struct{ policy, rule, ref string }
	fails := map[fkey]*pb.KyvernoResult{}
	for _, x := range results {
		if strings.ToLower(x.Result) != "fail" || x.Policy == "" {
			continue
		}
		k := fkey{x.Policy, x.Rule, kyvernoResourceRef(x)}
		if _, dup := fails[k]; !dup {
			fails[k] = x
		}
	}
	// Non-passing results by the policy string Kyverno wrote.
	byPolicy := map[string][]*pb.KyvernoResult{}
	for _, x := range results {
		switch strings.ToLower(x.Result) {
		case "fail", "warn", "error":
			if x.Policy != "" {
				byPolicy[x.Policy] = append(byPolicy[x.Policy], x)
			}
		}
	}
	for _, q := range []string{`DELETE FROM kyverno_policies WHERE cluster_id = $1`, `DELETE FROM kyverno_violations WHERE cluster_id = $1`} {
		if _, err := tx.Exec(ctx, q, clusterID); err != nil {
			return err
		}
	}
	seen := map[[3]string]bool{}
	b := &pgx.Batch{}
	total := 0
	var violations [][]any
	for _, p := range policies {
		kind := policyKind(p)
		if p.Name == "" || kind == "" || seen[[3]string{kind, p.Namespace, p.Name}] {
			continue
		}
		seen[[3]string{kind, p.Namespace, p.Name}] = true
		mode := p.Mode
		if mode != "Enforce" {
			mode = "Audit"
		}
		ns, name := clean(p.Namespace, 253), clean(p.Name, 253)
		type vkey struct{ rule, result, ref, msg string }
		vseen := map[vkey]bool{}
		failed := map[fkey]bool{} // distinct failures (rule, resource) of this policy
		for _, x := range policyResults(p, byPolicy) {
			ref := kyvernoResourceRef(x)
			if strings.ToLower(x.Result) == "fail" {
				failed[fkey{x.Policy, x.Rule, ref}] = true
			}
			k := vkey{x.Rule, strings.ToLower(x.Result), ref, x.Message}
			if vseen[k] || len(violations) >= maxResults {
				continue
			}
			vseen[k] = true
			violations = append(violations, []any{clusterID, kind, ns, name, clean(x.Rule, 253), clean(strings.ToLower(x.Result), 16),
				clean(strings.ToLower(x.Severity), 16), clean(x.Message, 1024), clean(x.ResourceKind, 63),
				clean(x.ResourceNamespace, 253), clean(x.ResourceName, 253)})
		}
		n := len(failed)
		total += n
		rules := make([]string, 0, len(p.Rules))
		for _, r := range p.Rules {
			rules = append(rules, clean(r, 253))
		}
		obj := parsePolicyObject(p.ObjectJson)
		b.Queue(`INSERT INTO kyverno_policies (cluster_id, kind, namespace, name, mode, rules, ready, fail_count, seen_at,
				api_version, annotations, spec, spec_omitted)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9, $10, $11, $12)`, clusterID, kind, ns, name, mode, rules, p.Ready, n,
			obj.apiVersion, obj.annotations, obj.spec, p.SpecOmitted || obj.invalid)
	}
	if b.Len() > 0 {
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
	}
	if len(violations) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"kyverno_violations"},
			[]string{"cluster_id", "kind", "namespace", "name", "rule", "result", "severity", "message",
				"resource_kind", "resource_namespace", "resource_name"}, pgx.CopyFromRows(violations)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO kyverno_status (cluster_id, installed, policy_count, fail_count, reported_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (cluster_id) DO UPDATE SET installed = EXCLUDED.installed, policy_count = EXCLUDED.policy_count,
		  fail_count = EXCLUDED.fail_count, reported_at = now()`, clusterID, rep.Installed, len(seen), total); err != nil {
		return err
	}
	cur := make([]findings.Finding, 0, len(fails))
	for k, x := range fails {
		sev := strings.ToLower(x.Severity)
		if !findingSeverities[sev] {
			sev = "medium"
		}
		title := clean(x.Message, 300)
		if title == "" {
			title = "Kyverno policy " + k.policy + " failed"
		}
		control := clean(k.policy, 253)
		if k.rule != "" {
			control += "/" + clean(k.rule, 253)
		}
		cur = append(cur, findings.Finding{
			ControlID: control, ResourceRef: k.ref, Severity: sev, Title: title,
			Details: map[string]any{"policy": k.policy, "rule": k.rule, "message": clean(x.Message, 1024), "result": "fail"},
		})
	}
	sort.Slice(cur, func(i, j int) bool {
		return cur[i].ControlID+cur[i].ResourceRef < cur[j].ControlID+cur[j].ResourceRef
	})
	_, _, err := findings.Reconcile(ctx, tx, findings.SourceKyverno, clusterID, cur, nil)
	return err
}

// ---------------------------------------------------------------- netpol

// IsDefaultDeny reports whether a policy is an ingress default-deny: it
// selects all pods, its policyTypes include Ingress and it has no ingress
// rules (SPEC §13.2).
func IsDefaultDeny(p *pb.NetworkPolicy) bool {
	if !p.SelectsAllPods || p.IngressRules != 0 {
		return false
	}
	for _, t := range p.PolicyTypes {
		if t == "Ingress" {
			return true
		}
	}
	return false
}

type nsState struct {
	count int
	deny  bool
}

func (in *Ingester) netpol(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, rep *pb.NetworkPolicyReport) error {
	nss := map[string]*nsState{}
	for i, ns := range rep.Namespaces {
		if i >= maxNamespaces {
			break
		}
		if ns != "" {
			nss[clean(ns, 253)] = &nsState{}
		}
	}
	for _, p := range rep.Policies {
		ns := clean(p.Namespace, 253)
		if ns == "" {
			continue
		}
		st := nss[ns]
		if st == nil {
			if len(nss) >= maxNamespaces {
				continue
			}
			st = &nsState{}
			nss[ns] = st
		}
		st.count++
		if IsDefaultDeny(p) {
			st.deny = true
		}
	}
	nsLabels := map[string]map[string]string{}
	for _, nl := range rep.NamespaceLabels {
		if ns := clean(nl.Name, 253); nss[ns] != nil {
			nsLabels[ns] = cleanLabels(nl.Labels)
		}
	}
	for _, q := range []string{`DELETE FROM network_policy_status WHERE cluster_id = $1`,
		`DELETE FROM network_policies WHERE cluster_id = $1`, `DELETE FROM namespace_workloads WHERE cluster_id = $1`} {
		if _, err := tx.Exec(ctx, q, clusterID); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(nss))
	for ns := range nss {
		names = append(names, ns)
	}
	sort.Strings(names)
	b := &pgx.Batch{}
	var cur []findings.Finding
	for _, ns := range names {
		st := nss[ns]
		excluded := MatchesAny(in.SystemNamespaces, ns)
		labels := nsLabels[ns]
		if labels == nil {
			labels = map[string]string{}
		}
		b.Queue(`INSERT INTO network_policy_status (cluster_id, namespace, policy_count, default_deny, excluded, labels, seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, now())`, clusterID, ns, st.count, st.deny, excluded, labels)
		if !excluded && !st.deny {
			title := "Namespace " + ns + " has no default-deny ingress NetworkPolicy"
			cur = append(cur, findings.Finding{ControlID: ControlNoDefaultDeny, ResourceRef: ns, Severity: "medium", Title: title,
				Details: map[string]any{"namespace": ns, "policy_count": st.count}})
		}
	}
	if b.Len() > 0 {
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
	}
	if err := in.netpolDetails(ctx, tx, clusterID, rep, nss); err != nil {
		return err
	}
	_, _, err := findings.Reconcile(ctx, tx, findings.SourceNetpol, clusterID, cur, nil)
	return err
}

// Limits on the simulator data stored per report.
const (
	maxWorkloadsPerNS = 50
	maxWorkloads      = 50000
	maxLabels         = 64
	maxPorts          = 32
)

// netpolDetails stores the policies with their specs and the workloads of
// known namespaces (replaced per report).
func (in *Ingester) netpolDetails(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, rep *pb.NetworkPolicyReport, nss map[string]*nsState) error {
	b := &pgx.Batch{}
	seen := map[[2]string]bool{}
	for _, p := range rep.Policies {
		ns, name := clean(p.Namespace, 253), clean(p.Name, 253)
		if ns == "" || name == "" || nss[ns] == nil || seen[[2]string{ns, name}] {
			continue
		}
		seen[[2]string{ns, name}] = true
		var spec []byte
		if v, ok := cleanJSON(p.SpecJson, maxNetpolSpecBytes); ok {
			if _, isObj := v.(map[string]any); isObj {
				spec, _ = json.Marshal(v)
			}
		}
		b.Queue(`INSERT INTO network_policies (cluster_id, namespace, name, spec) VALUES ($1, $2, $3, $4)`, clusterID, ns, name, spec)
	}
	perNS := map[string]int{}
	wseen := map[[3]string]bool{}
	n := 0
	for _, w := range rep.Workloads {
		ns, name := clean(w.Namespace, 253), clean(w.Name, 253)
		kind := w.Kind
		if kind != "Deployment" && kind != "StatefulSet" && kind != "DaemonSet" {
			continue
		}
		k := [3]string{ns, kind, name}
		if name == "" || nss[ns] == nil || wseen[k] || perNS[ns] >= maxWorkloadsPerNS || n >= maxWorkloads {
			continue
		}
		wseen[k] = true
		perNS[ns]++
		n++
		ports := []int32{}
		for _, p := range w.Ports {
			if p > 0 && p <= 65535 && len(ports) < maxPorts {
				ports = append(ports, p)
			}
		}
		b.Queue(`INSERT INTO namespace_workloads (cluster_id, namespace, kind, name, labels, ports) VALUES ($1, $2, $3, $4, $5, $6)`,
			clusterID, ns, kind, name, cleanLabels(w.Labels), ports)
	}
	if b.Len() == 0 {
		return nil
	}
	return tx.SendBatch(ctx, b).Close()
}

// cleanLabels bounds a label map (count, key and value length).
func cleanLabels(l map[string]string) map[string]string {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]string{}
	for _, k := range keys {
		if len(out) >= maxLabels {
			break
		}
		if ck := clean(k, 317); ck != "" {
			out[ck] = clean(l[k], 256)
		}
	}
	return out
}

// ---------------------------------------------------------------- images

func (in *Ingester) images(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, rep *pb.ImageReport) (bool, error) {
	type img struct {
		repo string
		tags map[string]bool
	}
	imgs := map[string]*img{}
	type ukey struct{ digest, ns, kind, name, container string }
	uses := map[ukey]string{}
	for i, u := range rep.Uses {
		if i >= maxImageUses {
			in.Log.Warn("image report truncated", "cluster", clusterID, "uses", len(rep.Uses))
			break
		}
		digest := strings.ToLower(u.Digest)
		if !DigestRe.MatchString(digest) || u.Namespace == "" || u.Container == "" {
			continue
		}
		_, repo, tag := ParseReference(u.Image)
		if !ValidRepo(repo) {
			continue
		}
		im := imgs[digest]
		if im == nil {
			im = &img{repo: repo, tags: map[string]bool{}}
			imgs[digest] = im
		}
		if tag != "" && repo == im.repo {
			im.tags[clean(tag, 128)] = true
		}
		kind, name := clean(u.WorkloadKind, 63), clean(u.WorkloadName, 253)
		if kind == "" {
			kind, name = "Pod", "unknown"
		}
		uses[ukey{digest, clean(u.Namespace, 253), kind, name, clean(u.Container, 253)}] = clean(u.Image, 512)
	}

	digests := make([]string, 0, len(imgs))
	for d := range imgs {
		digests = append(digests, d)
	}
	sort.Strings(digests)
	b := &pgx.Batch{}
	for _, d := range digests {
		im := imgs[d]
		tags := make([]string, 0, len(im.tags))
		for t := range im.tags {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		b.Queue(`INSERT INTO images (digest, repo, tags) VALUES ($1, $2, $3)
			ON CONFLICT (digest) DO UPDATE
			  SET tags = (SELECT COALESCE(array_agg(DISTINCT t ORDER BY t), '{}') FROM unnest(images.tags || EXCLUDED.tags) AS t)
			  WHERE NOT images.tags @> EXCLUDED.tags
			RETURNING (xmax = 0)`, d, im.repo, tags)
	}
	newImages := false
	if b.Len() > 0 {
		br := tx.SendBatch(ctx, b)
		for range digests {
			var inserted bool
			err := br.QueryRow().Scan(&inserted)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				br.Close()
				return false, err
			}
			if inserted {
				newImages = true
			}
		}
		if err := br.Close(); err != nil {
			return false, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM image_usage WHERE cluster_id = $1`, clusterID); err != nil {
		return false, err
	}
	rows := make([][]any, 0, len(uses))
	for k, image := range uses {
		rows = append(rows, []any{k.digest, clusterID, k.ns, k.kind, k.name, k.container, image})
	}
	if len(rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"image_usage"},
			[]string{"digest", "cluster_id", "namespace", "workload_kind", "workload_name", "container", "image"},
			pgx.CopyFromRows(rows)); err != nil {
			return false, err
		}
	}
	return newImages, nil
}
