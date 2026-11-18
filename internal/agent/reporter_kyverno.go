package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kdiscovery "k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// Kyverno resources (SPEC §4.2 RBAC, read-only): legacy kyverno.io/v1
// policies, the CEL-based policies.kyverno.io/v1 validation policies
// (Kyverno ≥ 1.17; 1.20 no longer runs the legacy kinds) and the
// wgpolicyk8s.io reports both write to.
var (
	gvrClusterPolicy       = schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "clusterpolicies"}
	gvrPolicy              = schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "policies"}
	gvrValidatingPolicy    = schema.GroupVersionResource{Group: "policies.kyverno.io", Version: "v1", Resource: "validatingpolicies"}
	gvrNSValidatingPolicy  = schema.GroupVersionResource{Group: "policies.kyverno.io", Version: "v1", Resource: "namespacedvalidatingpolicies"}
	gvrImageVPolicy        = schema.GroupVersionResource{Group: "policies.kyverno.io", Version: "v1", Resource: "imagevalidatingpolicies"}
	gvrNSImageVPolicy      = schema.GroupVersionResource{Group: "policies.kyverno.io", Version: "v1", Resource: "namespacedimagevalidatingpolicies"}
	gvrPolicyReport        = schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports"}
	gvrClusterPolicyReport = schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports"}

	// policyKinds maps each policy resource to the kind reported upstream.
	policyKinds = map[schema.GroupVersionResource]string{
		gvrClusterPolicy: "ClusterPolicy", gvrPolicy: "Policy",
		gvrValidatingPolicy: "ValidatingPolicy", gvrNSValidatingPolicy: "NamespacedValidatingPolicy",
		gvrImageVPolicy: "ImageValidatingPolicy", gvrNSImageVPolicy: "NamespacedImageValidatingPolicy",
	}
	policyGVRs  = []schema.GroupVersionResource{gvrClusterPolicy, gvrPolicy, gvrValidatingPolicy, gvrNSValidatingPolicy, gvrImageVPolicy, gvrNSImageVPolicy}
	kyvernoGVRs = append(append([]schema.GroupVersionResource{}, policyGVRs...), gvrPolicyReport, gvrClusterPolicyReport)
)

// anyPolicy reports whether any Kyverno policy resource is served.
func anyPolicy(present map[schema.GroupVersionResource]bool) bool {
	for _, g := range policyGVRs {
		if present[g] {
			return true
		}
	}
	return false
}

const kyvernoRecheck = 5 * time.Minute

// kyvernoReporter watches Kyverno policies and policy reports. Kyverno is
// optional: when its CRDs are absent the reporter sends installed=false and
// re-checks discovery periodically, starting informers once they appear.
type kyvernoReporter struct {
	disc    kdiscovery.DiscoveryInterface
	dyn     dynamic.Interface
	log     *slog.Logger
	base    context.Context
	recheck time.Duration
	changed signal

	mu      sync.Mutex
	present map[schema.GroupVersionResource]bool
	cancel  context.CancelFunc
	listers map[schema.GroupVersionResource]cache.GenericLister
}

func newKyvernoReporter(disc kdiscovery.DiscoveryInterface, dyn dynamic.Interface, log *slog.Logger) *kyvernoReporter {
	return &kyvernoReporter{disc: disc, dyn: dyn, log: log, base: context.Background(), recheck: kyvernoRecheck, changed: newSignal()}
}

func (r *kyvernoReporter) Name() string { return "kyverno" }

func (r *kyvernoReporter) Run(ctx context.Context, send func(*pb.ResourceReport)) error {
	if err := r.ensure(ctx); err != nil {
		r.log.Warn("kyverno discovery", "err", err)
	}
	t := time.NewTicker(r.recheck)
	defer t.Stop()
	extra := make(chan time.Time)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if err := r.ensure(ctx); err != nil {
					r.log.Warn("kyverno discovery", "err", err)
					continue
				}
				select {
				case extra <- now:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	l := &reportLoop{name: r.Name(), log: r.log, changed: r.changed, debounce: 5 * time.Second, extra: extra, build: r.build}
	return l.run(ctx, send)
}

// discover returns which Kyverno resources the API server serves.
func (r *kyvernoReporter) discover() (map[schema.GroupVersionResource]bool, error) {
	out := map[schema.GroupVersionResource]bool{}
	byGV := map[string][]schema.GroupVersionResource{}
	for _, g := range kyvernoGVRs {
		gv := g.GroupVersion().String()
		byGV[gv] = append(byGV[gv], g)
	}
	for gv, gvrs := range byGV {
		list, err := r.disc.ServerResourcesForGroupVersion(gv)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("discover %s: %w", gv, err)
		}
		served := map[string]bool{}
		for _, res := range list.APIResources {
			served[res.Name] = true
		}
		for _, g := range gvrs {
			out[g] = served[g.Resource]
		}
	}
	return out, nil
}

// ensure (re)starts informers when the set of served Kyverno resources
// changes (CRDs installed or removed).
func (r *kyvernoReporter) ensure(ctx context.Context) error {
	present, err := r.discover()
	if err != nil {
		return err
	}
	r.mu.Lock()
	same := r.present != nil && len(present) == len(r.present)
	if same {
		for g, ok := range present {
			if r.present[g] != ok {
				same = false
			}
		}
	}
	if same {
		r.mu.Unlock()
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.present, r.cancel, r.listers = present, nil, map[schema.GroupVersionResource]cache.GenericLister{}
	if !anyPolicy(present) {
		r.mu.Unlock()
		r.log.Info("kyverno not installed")
		r.changed.poke()
		return nil
	}
	ictx, cancel := context.WithCancel(r.base)
	r.cancel = cancel
	f := dynamicinformer.NewDynamicSharedInformerFactory(r.dyn, informerResync)
	var syncs []cache.InformerSynced
	for _, g := range kyvernoGVRs {
		if !present[g] {
			continue
		}
		gi := f.ForResource(g)
		inf := gi.Informer()
		_ = inf.SetTransform(stripUnstructured)
		_, _ = inf.AddEventHandler(r.changed.handler())
		r.listers[g] = gi.Lister()
		syncs = append(syncs, inf.HasSynced)
	}
	r.mu.Unlock()
	f.Start(ictx.Done())
	wctx, wcancel := context.WithTimeout(ctx, cacheSyncTimeout)
	defer wcancel()
	if !cache.WaitForCacheSync(wctx.Done(), syncs...) {
		return errors.New("kyverno informer cache sync timed out")
	}
	r.log.Info("kyverno informers synced", "resources", len(syncs))
	r.changed.poke()
	return nil
}

func stripUnstructured(obj any) (any, error) {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		u.SetManagedFields(nil)
		// Keep only Kyverno's own policy annotations (title, category,
		// severity, description); drop the rest (last-applied-configuration
		// can be large and is not ours to forward).
		var keep map[string]string
		for k, v := range u.GetAnnotations() {
			if strings.HasPrefix(k, kyvernoAnnotationPrefix) {
				if keep == nil {
					keep = map[string]string{}
				}
				keep[k] = v
			}
		}
		u.SetAnnotations(keep)
	}
	return obj, nil
}

const kyvernoAnnotationPrefix = "policies.kyverno.io/"

// Caps on policy objects sent upstream: one policy, and all policies of a
// report together (the gRPC message limit is 32 MiB; results need room too).
var (
	maxPolicyObjectBytes = 64 << 10
	maxPolicyObjectTotal = 8 << 20
)

// PolicyObjectJSON returns the trimmed policy object sent to the server:
// apiVersion, kind, metadata.name/namespace, the policies.kyverno.io/*
// annotations and spec. status, managedFields, labels, other annotations
// and everything else in metadata are dropped.
func PolicyObjectJSON(u *unstructured.Unstructured) ([]byte, error) {
	meta := map[string]any{"name": u.GetName()}
	if ns := u.GetNamespace(); ns != "" {
		meta["namespace"] = ns
	}
	ann := map[string]any{}
	for k, v := range u.GetAnnotations() {
		if strings.HasPrefix(k, kyvernoAnnotationPrefix) {
			ann[k] = v
		}
	}
	if len(ann) > 0 {
		meta["annotations"] = ann
	}
	obj := map[string]any{"apiVersion": u.GetAPIVersion(), "kind": u.GetKind(), "metadata": meta}
	if spec, ok := u.Object["spec"]; ok {
		obj["spec"] = spec
	}
	return json.Marshal(obj)
}

func policyAPIVersion(kind string) string {
	if kind == "ClusterPolicy" || kind == "Policy" {
		return "kyverno.io/v1"
	}
	return "policies.kyverno.io/v1"
}

func (r *kyvernoReporter) build(context.Context) (*pb.ResourceReport, error) {
	r.mu.Lock()
	listers, known := r.listers, r.present != nil
	installed := anyPolicy(r.present)
	r.mu.Unlock()
	if !known {
		// Discovery has not succeeded yet: do not claim "not installed",
		// which would clear the server's view. Retried on the next recheck.
		return nil, errors.New("kyverno discovery pending")
	}
	rep := &pb.KyvernoReport{Installed: installed}
	if !installed {
		return &pb.ResourceReport{Report: &pb.ResourceReport_Kyverno{Kyverno: rep}}, nil
	}
	list := func(g schema.GroupVersionResource) []*unstructured.Unstructured {
		l := listers[g]
		if l == nil {
			return nil
		}
		objs, err := l.List(everything)
		if err != nil {
			return nil
		}
		out := make([]*unstructured.Unstructured, 0, len(objs))
		for _, o := range objs {
			if u, ok := o.(*unstructured.Unstructured); ok {
				out = append(out, u)
			}
		}
		return out
	}
	objs := map[*pb.KyvernoPolicy]*unstructured.Unstructured{}
	for _, g := range policyGVRs {
		for _, u := range list(g) {
			var p *pb.KyvernoPolicy
			if g.Group == "kyverno.io" {
				p = KyvernoPolicyToPB(u)
			} else {
				p = CELPolicyToPB(u)
			}
			p.Kind = policyKinds[g]
			rep.Policies = append(rep.Policies, p)
			objs[p] = u
		}
	}
	for _, g := range []schema.GroupVersionResource{gvrClusterPolicyReport, gvrPolicyReport} {
		for _, u := range list(g) {
			rep.Results = append(rep.Results, KyvernoResultsFromReport(u)...)
		}
	}
	sort.Slice(rep.Policies, func(i, j int) bool {
		a, b := rep.Policies[i], rep.Policies[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	// Objects in sorted order, so the total budget cuts deterministically.
	// The informer cache is shared: copy before defaulting apiVersion/kind.
	budget, omitted := maxPolicyObjectTotal, 0
	for _, p := range rep.Policies {
		u := objs[p]
		if u.GetAPIVersion() == "" || u.GetKind() == "" {
			u = u.DeepCopy()
			if u.GetAPIVersion() == "" {
				u.SetAPIVersion(policyAPIVersion(p.Kind))
			}
			if u.GetKind() == "" {
				u.SetKind(p.Kind)
			}
		}
		b, err := PolicyObjectJSON(u)
		if err != nil || len(b) > maxPolicyObjectBytes || len(b) > budget {
			p.SpecOmitted = true
			omitted++
			continue
		}
		budget -= len(b)
		p.ObjectJson = b
	}
	if omitted > 0 {
		r.log.Warn("kyverno policy specs omitted (too large)", "omitted", omitted,
			"per_policy_cap", maxPolicyObjectBytes, "total_cap", maxPolicyObjectTotal)
	}
	sort.Slice(rep.Results, func(i, j int) bool { return resultKey(rep.Results[i]) < resultKey(rep.Results[j]) })
	if len(rep.Results) > maxKyvernoResults {
		r.log.Warn("kyverno results truncated", "total", len(rep.Results), "sent", maxKyvernoResults)
		rep.Results = rep.Results[:maxKyvernoResults]
	}
	return &pb.ResourceReport{Report: &pb.ResourceReport_Kyverno{Kyverno: rep}}, nil
}

func resultKey(x *pb.KyvernoResult) string {
	return strings.Join([]string{x.Policy, x.Rule, x.ResourceKind, x.ResourceNamespace, x.ResourceName, x.Result, x.Message}, "\x00")
}

// normalizeAction maps validationFailureAction / failureAction values
// (Enforce, enforce, Audit, audit) to Enforce or Audit ("" if unset).
func normalizeAction(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "enforce":
		return "Enforce"
	case "audit":
		return "Audit"
	}
	return ""
}

// KyvernoPolicyToPB summarizes a ClusterPolicy or Policy.
//
// Mode: each validate rule's effective action is its own
// validate.failureAction (Kyverno ≥ 1.13) or else spec.validationFailureAction
// (default Audit). The policy is reported as Enforce when any rule — or any
// validationFailureActionOverrides entry — enforces, since it can then block
// admission somewhere; otherwise Audit.
func KyvernoPolicyToPB(u *unstructured.Unstructured) *pb.KyvernoPolicy {
	out := &pb.KyvernoPolicy{Namespace: u.GetNamespace(), Name: u.GetName(), Ready: true}
	base, _, _ := unstructured.NestedString(u.Object, "spec", "validationFailureAction")
	base = normalizeAction(base)
	if base == "" {
		base = "Audit"
	}
	mode := base
	enforce := false
	rules, _, _ := unstructured.NestedSlice(u.Object, "spec", "rules")
	validateRules := 0
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := rule["name"].(string); name != "" {
			out.Rules = append(out.Rules, name)
		}
		v, ok := rule["validate"].(map[string]any)
		if !ok {
			continue
		}
		validateRules++
		action := base
		if fa, _ := v["failureAction"].(string); normalizeAction(fa) != "" {
			action = normalizeAction(fa)
		}
		if action == "Enforce" {
			enforce = true
		}
	}
	if validateRules > 0 {
		mode = "Audit"
		if enforce {
			mode = "Enforce"
		}
	}
	overrides, _, _ := unstructured.NestedSlice(u.Object, "spec", "validationFailureActionOverrides")
	for _, raw := range overrides {
		if o, ok := raw.(map[string]any); ok {
			if a, _ := o["action"].(string); normalizeAction(a) == "Enforce" {
				mode = "Enforce"
			}
		}
	}
	out.Mode = mode

	// Readiness: status.conditions[type=Ready] (Kyverno ≥ 1.9), else the
	// legacy status.ready boolean; unknown counts as ready.
	if conds, found, _ := unstructured.NestedSlice(u.Object, "status", "conditions"); found {
		for _, raw := range conds {
			if c, ok := raw.(map[string]any); ok && c["type"] == "Ready" {
				out.Ready = c["status"] == "True"
			}
		}
	} else if ready, found, _ := unstructured.NestedBool(u.Object, "status", "ready"); found {
		out.Ready = ready
	}
	return out
}

// CELPolicyToPB summarizes a policies.kyverno.io/v1 (Image)ValidatingPolicy
// or its namespaced variant. spec.validationActions lists Deny, Audit and/or
// Warn; Deny can block admission, so it maps to Enforce, anything else to
// Audit. Validations have no names: the reported rules are their messages
// (or "validation-N").
func CELPolicyToPB(u *unstructured.Unstructured) *pb.KyvernoPolicy {
	out := &pb.KyvernoPolicy{Namespace: u.GetNamespace(), Name: u.GetName(), Mode: "Audit", Ready: true}
	actions, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "validationActions")
	for _, a := range actions {
		if strings.EqualFold(a, "Deny") {
			out.Mode = "Enforce"
		}
	}
	vals, _, _ := unstructured.NestedSlice(u.Object, "spec", "validations")
	for i, raw := range vals {
		name := fmt.Sprintf("validation-%d", i+1)
		if v, ok := raw.(map[string]any); ok {
			if m := strings.TrimSpace(str(v["message"])); m != "" {
				name = truncate(m, 120)
			}
		}
		out.Rules = append(out.Rules, name)
	}
	// Readiness: status.conditionStatus.ready, else conditions[type=Ready].
	if ready, found, _ := unstructured.NestedBool(u.Object, "status", "conditionStatus", "ready"); found {
		out.Ready = ready
	} else if conds, found, _ := unstructured.NestedSlice(u.Object, "status", "conditions"); found {
		for _, raw := range conds {
			if c, ok := raw.(map[string]any); ok && c["type"] == "Ready" {
				out.Ready = c["status"] == "True"
			}
		}
	}
	return out
}

// KyvernoResultsFromReport extracts non-passing results (fail, warn, error)
// from a PolicyReport or ClusterPolicyReport. Passing and skipped results are
// not sent: the server only needs failures and fail counts.
func KyvernoResultsFromReport(u *unstructured.Unstructured) []*pb.KyvernoResult {
	results, _, _ := unstructured.NestedSlice(u.Object, "results")
	// Kyverno ≥ 1.10 writes one report per resource with the subject in
	// .scope and no per-result resources.
	scopeKind, _, _ := unstructured.NestedString(u.Object, "scope", "kind")
	scopeNS, _, _ := unstructured.NestedString(u.Object, "scope", "namespace")
	scopeName, _, _ := unstructured.NestedString(u.Object, "scope", "name")
	if scopeNS == "" && scopeName != "" {
		scopeNS = u.GetNamespace()
	}
	var out []*pb.KyvernoResult
	for _, raw := range results {
		res, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		result := strings.ToLower(str(res["result"]))
		switch result {
		case "fail", "warn", "error":
		default:
			continue
		}
		policy, rule := str(res["policy"]), str(res["rule"])
		severity := strings.ToLower(str(res["severity"]))
		msg := truncate(str(res["message"]), 1024)
		mk := func(kind, ns, name string) *pb.KyvernoResult {
			return &pb.KyvernoResult{Policy: policy, Rule: rule, Result: result, Severity: severity, Message: msg,
				ResourceKind: kind, ResourceNamespace: ns, ResourceName: name}
		}
		resources, _ := res["resources"].([]any)
		if len(resources) == 0 {
			ns := scopeNS
			if ns == "" {
				ns = u.GetNamespace()
			}
			out = append(out, mk(scopeKind, ns, scopeName))
			continue
		}
		for _, rr := range resources {
			if obj, ok := rr.(map[string]any); ok {
				out = append(out, mk(str(obj["kind"]), str(obj["namespace"]), str(obj["name"])))
			}
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// truncate cuts s to at most n bytes on a rune boundary (proto strings must
// be valid UTF-8).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

var everything = labels.Everything()
