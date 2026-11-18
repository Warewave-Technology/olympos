package security

import (
	"context"
	"crypto/sha256"
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
	}
	return nil
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

// policyMatches reports whether a report result belongs to a policy. Kyverno
// writes the bare name for ClusterPolicies and either "ns/name" or the bare
// name (in the resource's namespace) for namespaced Policies.
func policyMatches(p *pb.KyvernoPolicy, x *pb.KyvernoResult) bool {
	if p.Namespace == "" {
		return x.Policy == p.Name
	}
	return x.Policy == p.Namespace+"/"+p.Name || (x.Policy == p.Name && x.ResourceNamespace == p.Namespace)
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
	if _, err := tx.Exec(ctx, `DELETE FROM kyverno_policies WHERE cluster_id = $1`, clusterID); err != nil {
		return err
	}
	seen := map[[3]string]bool{}
	b := &pgx.Batch{}
	total := 0
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
		n := 0
		for _, x := range fails {
			if policyMatches(p, x) {
				n++
			}
		}
		total += n
		rules := make([]string, 0, len(p.Rules))
		for _, r := range p.Rules {
			rules = append(rules, clean(r, 253))
		}
		b.Queue(`INSERT INTO kyverno_policies (cluster_id, kind, namespace, name, mode, rules, ready, fail_count, seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())`, clusterID, kind, clean(p.Namespace, 253), clean(p.Name, 253), mode, rules, p.Ready, n)
	}
	if b.Len() > 0 {
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
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

func (in *Ingester) netpol(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, rep *pb.NetworkPolicyReport) error {
	type nsState struct {
		count int
		deny  bool
	}
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
	if _, err := tx.Exec(ctx, `DELETE FROM network_policy_status WHERE cluster_id = $1`, clusterID); err != nil {
		return err
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
		b.Queue(`INSERT INTO network_policy_status (cluster_id, namespace, policy_count, default_deny, excluded, seen_at)
			VALUES ($1, $2, $3, $4, $5, now())`, clusterID, ns, st.count, st.deny, excluded)
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
	_, _, err := findings.Reconcile(ctx, tx, findings.SourceNetpol, clusterID, cur, nil)
	return err
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
