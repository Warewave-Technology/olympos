package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// Caps for the NetworkPolicy report (gRPC messages are limited to 32 MiB).
var (
	maxNetpolSpecBytes  = 32 << 10 // one policy spec
	maxNetpolSpecTotal  = 8 << 20  // all specs of a report
	maxWorkloadsPerNS   = 50
	maxWorkloadsTotal   = 20000
	maxLabelsPerObject  = 64
	maxPortsPerWorkload = 32
	workloadKindOrder   = map[string]int{"Deployment": 0, "StatefulSet": 1, "DaemonSet": 2}
)

// netpolReporter reports every namespace with its labels, every
// NetworkPolicy with its spec, and per namespace up to maxWorkloadsPerNS
// workloads with their pod template labels and container ports (SPEC §13.2;
// the labels feed the policy simulator). The server decides what counts as
// default-deny.
type netpolReporter struct {
	inf     *kubeInformers
	log     *slog.Logger
	changed signal
}

func newNetpolReporter(inf *kubeInformers, log *slog.Logger) *netpolReporter {
	r := &netpolReporter{inf: inf, log: log, changed: newSignal()}
	_, _ = inf.netpols.AddEventHandler(r.changed.handler())
	_, _ = inf.nss.AddEventHandler(r.changed.handler())
	// Workloads update constantly (status, rollouts); only label or port
	// changes matter here.
	wl := cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { r.changed.poke() },
		UpdateFunc: func(o, n any) {
			a, b := WorkloadToPB(o), WorkloadToPB(n)
			if a == nil || b == nil || !proto.Equal(a, b) {
				r.changed.poke()
			}
		},
		DeleteFunc: func(any) { r.changed.poke() },
	}
	for _, i := range []cache.SharedIndexInformer{inf.deploys, inf.sts, inf.ds} {
		_, _ = i.AddEventHandler(wl)
	}
	return r
}

func (r *netpolReporter) Name() string { return "networkpolicies" }

func (r *netpolReporter) Run(ctx context.Context, send func(*pb.ResourceReport)) error {
	if err := r.inf.start(ctx); err != nil {
		return err
	}
	l := &reportLoop{name: r.Name(), log: r.log, changed: r.changed, debounce: 2 * time.Second, build: r.build}
	return l.run(ctx, send)
}

func (r *netpolReporter) build(context.Context) (*pb.ResourceReport, error) {
	rep := &pb.NetworkPolicyReport{}
	for _, o := range r.inf.nss.GetStore().List() {
		if ns, ok := o.(*corev1.Namespace); ok {
			rep.Namespaces = append(rep.Namespaces, ns.Name)
			rep.NamespaceLabels = append(rep.NamespaceLabels, &pb.NamespaceLabels{Name: ns.Name, Labels: capLabels(ns.Labels)})
		}
	}
	sort.Strings(rep.Namespaces)
	sort.Slice(rep.NamespaceLabels, func(i, j int) bool { return rep.NamespaceLabels[i].Name < rep.NamespaceLabels[j].Name })
	for _, o := range r.inf.netpols.GetStore().List() {
		if np, ok := o.(*networkingv1.NetworkPolicy); ok {
			rep.Policies = append(rep.Policies, NetworkPolicyToPB(np))
		}
	}
	sort.Slice(rep.Policies, func(i, j int) bool {
		a, b := rep.Policies[i], rep.Policies[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	budget, omitted := maxNetpolSpecTotal, 0
	for _, p := range rep.Policies {
		if len(p.SpecJson) > budget {
			p.SpecJson = nil
		}
		if len(p.SpecJson) == 0 {
			omitted++
			continue
		}
		budget -= len(p.SpecJson)
	}
	if omitted > 0 {
		r.log.Warn("networkpolicy specs omitted (too large)", "omitted", omitted,
			"per_policy_cap", maxNetpolSpecBytes, "total_cap", maxNetpolSpecTotal)
	}

	var wls []*pb.Workload
	for _, inf := range []cache.SharedIndexInformer{r.inf.deploys, r.inf.sts, r.inf.ds} {
		for _, o := range inf.GetStore().List() {
			if w := WorkloadToPB(o); w != nil {
				wls = append(wls, w)
			}
		}
	}
	rep.Workloads = SelectWorkloads(wls, maxWorkloadsPerNS, maxWorkloadsTotal)
	if len(rep.Workloads) < len(wls) {
		r.log.Debug("workloads capped for the netpol report", "total", len(wls), "sent", len(rep.Workloads))
	}
	return &pb.ResourceReport{Report: &pb.ResourceReport_NetworkPolicies{NetworkPolicies: rep}}, nil
}

// SelectWorkloads sorts workloads (namespace, kind, name) and keeps at most
// perNS per namespace and total overall.
func SelectWorkloads(wls []*pb.Workload, perNS, total int) []*pb.Workload {
	sort.Slice(wls, func(i, j int) bool {
		a, b := wls[i], wls[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return workloadKindOrder[a.Kind] < workloadKindOrder[b.Kind]
		}
		return a.Name < b.Name
	})
	out := make([]*pb.Workload, 0, min(len(wls), total))
	n, ns := 0, ""
	for _, w := range wls {
		if len(out) >= total {
			break
		}
		if w.Namespace != ns {
			ns, n = w.Namespace, 0
		}
		if n >= perNS {
			continue
		}
		n++
		out = append(out, w)
	}
	return out
}

// WorkloadToPB returns a Deployment, StatefulSet or DaemonSet's pod template
// labels and container ports (nil for other objects).
func WorkloadToPB(obj any) *pb.Workload {
	var kind string
	var meta struct{ ns, name string }
	var tmpl corev1.PodTemplateSpec
	switch w := obj.(type) {
	case *appsv1.Deployment:
		kind, meta.ns, meta.name, tmpl = "Deployment", w.Namespace, w.Name, w.Spec.Template
	case *appsv1.StatefulSet:
		kind, meta.ns, meta.name, tmpl = "StatefulSet", w.Namespace, w.Name, w.Spec.Template
	case *appsv1.DaemonSet:
		kind, meta.ns, meta.name, tmpl = "DaemonSet", w.Namespace, w.Name, w.Spec.Template
	default:
		return nil
	}
	out := &pb.Workload{Namespace: meta.ns, Kind: kind, Name: meta.name, Labels: capLabels(tmpl.Labels)}
	seen := map[int32]bool{}
	for _, c := range tmpl.Spec.Containers {
		for _, p := range c.Ports {
			if p.ContainerPort > 0 && !seen[p.ContainerPort] && len(out.Ports) < maxPortsPerWorkload {
				seen[p.ContainerPort] = true
				out.Ports = append(out.Ports, p.ContainerPort)
			}
		}
	}
	sort.Slice(out.Ports, func(i, j int) bool { return out.Ports[i] < out.Ports[j] })
	return out
}

// capLabels keeps at most maxLabelsPerObject labels (smallest keys first).
func capLabels(l map[string]string) map[string]string {
	if len(l) <= maxLabelsPerObject {
		return l
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, maxLabelsPerObject)
	for _, k := range keys[:maxLabelsPerObject] {
		out[k] = l[k]
	}
	return out
}

// NetworkPolicyToPB summarizes a NetworkPolicy and carries its spec as JSON
// (omitted above maxNetpolSpecBytes). policyTypes is defaulted the way the
// API server does when it is empty: Ingress always, Egress when the policy
// has egress rules.
func NetworkPolicyToPB(np *networkingv1.NetworkPolicy) *pb.NetworkPolicy {
	sel := np.Spec.PodSelector
	out := &pb.NetworkPolicy{
		Namespace:      np.Namespace,
		Name:           np.Name,
		SelectsAllPods: len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0,
		IngressRules:   int32(len(np.Spec.Ingress)),
		EgressRules:    int32(len(np.Spec.Egress)),
	}
	for _, t := range np.Spec.PolicyTypes {
		out.PolicyTypes = append(out.PolicyTypes, string(t))
	}
	if len(out.PolicyTypes) == 0 {
		out.PolicyTypes = []string{string(networkingv1.PolicyTypeIngress)}
		if len(np.Spec.Egress) > 0 {
			out.PolicyTypes = append(out.PolicyTypes, string(networkingv1.PolicyTypeEgress))
		}
	}
	sort.Strings(out.PolicyTypes)
	if b, err := json.Marshal(np.Spec); err == nil && len(b) <= maxNetpolSpecBytes {
		out.SpecJson = b
	}
	return out
}
