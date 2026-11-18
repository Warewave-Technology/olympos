package agent

import (
	"context"
	"log/slog"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// netpolReporter reports every namespace plus every NetworkPolicy (SPEC
// §13.2). The server decides what counts as default-deny.
type netpolReporter struct {
	inf     *kubeInformers
	log     *slog.Logger
	changed signal
}

func newNetpolReporter(inf *kubeInformers, log *slog.Logger) *netpolReporter {
	r := &netpolReporter{inf: inf, log: log, changed: newSignal()}
	_, _ = inf.netpols.AddEventHandler(r.changed.handler())
	_, _ = inf.nss.AddEventHandler(r.changed.handler())
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
		}
	}
	sort.Strings(rep.Namespaces)
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
	return &pb.ResourceReport{Report: &pb.ResourceReport_NetworkPolicies{NetworkPolicies: rep}}, nil
}

// NetworkPolicyToPB summarizes a NetworkPolicy. policyTypes is defaulted the
// way the API server does when it is empty: Ingress always, Egress when the
// policy has egress rules.
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
	return out
}
