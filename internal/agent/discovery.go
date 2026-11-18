package agent

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/targetid"
)

// Discovery annotations (SPEC §5).
const (
	AnnBackup        = "olympos.io/backup"
	AnnVault         = "olympos.io/vault"
	AnnPort          = "olympos.io/port"
	AnnTLSServerName = "olympos.io/tls-server-name"
)

const (
	diffInterval     = 60 * time.Second
	snapshotInterval = 10 * time.Minute
)

type discovery struct {
	a       *Agent
	factory informers.SharedInformerFactory
	nodes   listersv1.NodeLister
	nss     listersv1.NamespaceLister
	svcs    listersv1.ServiceLister
	eps     cache.Indexer // EndpointSlices by service

	changed chan struct{}
	resync  chan struct{}

	mu          sync.RWMutex
	targets     map[string]*pb.Target // current discovered set (by target id)
	sentNodes   map[string]*pb.Node
	sentNS      map[string]bool
	sentTargets map[string]*pb.Target
	apiVersion  string
}

func newDiscovery(a *Agent) *discovery {
	return &discovery{a: a, changed: make(chan struct{}, 1), resync: make(chan struct{}, 1), targets: map[string]*pb.Target{}}
}

func (d *discovery) start(ctx context.Context) error {
	d.factory = informers.NewSharedInformerFactory(d.a.kube, 10*time.Minute)
	ni := d.factory.Core().V1().Nodes()
	nsi := d.factory.Core().V1().Namespaces()
	si := d.factory.Core().V1().Services()
	esi := d.factory.Discovery().V1().EndpointSlices()
	d.nodes, d.nss, d.svcs = ni.Lister(), nsi.Lister(), si.Lister()
	d.eps = esi.Informer().GetIndexer()
	poke := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { d.poke() },
		UpdateFunc: func(any, any) { d.poke() },
		DeleteFunc: func(any) { d.poke() },
	}
	if _, err := si.Informer().AddEventHandler(poke); err != nil {
		return err
	}
	d.factory.Start(ctx.Done())
	for typ, ok := range d.factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("informer cache sync failed for %v", typ)
		}
	}
	d.a.log.Info("discovery caches synced")
	return nil
}

func (d *discovery) poke() {
	select {
	case d.changed <- struct{}{}:
	default:
	}
}

func (d *discovery) requestResync() {
	select {
	case d.resync <- struct{}{}:
	default:
	}
}

// publish runs for one control session: a full snapshot first, then diffs.
func (d *discovery) publish(ctx context.Context) {
	if err := d.sendSnapshot(ctx); err != nil {
		d.a.log.Error("send snapshot", "err", err)
	}
	diffT := time.NewTicker(diffInterval)
	snapT := time.NewTicker(snapshotInterval)
	defer diffT.Stop()
	defer snapT.Stop()
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.changed:
			if debounce == nil {
				debounce = time.After(2 * time.Second)
			}
		case <-debounce:
			debounce = nil
			d.sendTargetChanges()
		case <-diffT.C:
			d.sendDiff(ctx)
			d.sendTargetChanges()
		case <-snapT.C:
			_ = d.sendSnapshot(ctx)
		case <-d.resync:
			_ = d.sendSnapshot(ctx)
		}
	}
}

func (d *discovery) clusterID() string {
	_, leaf := d.a.id.get()
	return leaf.Subject.CommonName
}

func (d *discovery) serverVersion() string {
	v, err := d.a.kube.Discovery().ServerVersion()
	if err != nil {
		d.a.log.Warn("server version", "err", err)
		d.mu.RLock()
		defer d.mu.RUnlock()
		return d.apiVersion
	}
	return v.GitVersion
}

func (d *discovery) currentNodes() map[string]*pb.Node {
	out := map[string]*pb.Node{}
	list, _ := d.nodes.List(labels.Everything())
	for _, n := range list {
		out[n.Name] = nodeToPB(n)
	}
	return out
}

func (d *discovery) currentNamespaces() map[string]bool {
	out := map[string]bool{}
	list, _ := d.nss.List(labels.Everything())
	for _, n := range list {
		out[n.Name] = true
	}
	return out
}

func (d *discovery) sendSnapshot(ctx context.Context) error {
	ver := d.serverVersion()
	nodes := d.currentNodes()
	nss := d.currentNamespaces()
	targets := d.computeTargets()
	snap := &pb.InventorySnapshot{ApiVersion: ver}
	for _, n := range sortedNodes(nodes) {
		snap.Nodes = append(snap.Nodes, n)
	}
	for ns := range nss {
		snap.Namespaces = append(snap.Namespaces, ns)
	}
	sort.Strings(snap.Namespaces)
	for _, t := range targets {
		snap.Targets = append(snap.Targets, t)
	}
	sort.Slice(snap.Targets, func(i, j int) bool { return snap.Targets[i].TargetId < snap.Targets[j].TargetId })
	if err := d.a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_Inventory{Inventory: snap}}); err != nil {
		return err
	}
	d.mu.Lock()
	d.apiVersion, d.sentNodes, d.sentNS, d.sentTargets, d.targets = ver, nodes, nss, targets, targets
	d.mu.Unlock()
	return nil
}

func (d *discovery) sendDiff(ctx context.Context) {
	ver := d.serverVersion()
	nodes := d.currentNodes()
	nss := d.currentNamespaces()
	d.mu.RLock()
	diff := &pb.InventoryDiff{ApiVersion: ver}
	for name, n := range nodes {
		if old, ok := d.sentNodes[name]; !ok || !proto.Equal(old, n) {
			diff.UpsertedNodes = append(diff.UpsertedNodes, n)
		}
	}
	for name := range d.sentNodes {
		if _, ok := nodes[name]; !ok {
			diff.DeletedNodes = append(diff.DeletedNodes, name)
		}
	}
	for ns := range nss {
		if !d.sentNS[ns] {
			diff.AddedNamespaces = append(diff.AddedNamespaces, ns)
		}
	}
	for ns := range d.sentNS {
		if !nss[ns] {
			diff.DeletedNamespaces = append(diff.DeletedNamespaces, ns)
		}
	}
	changed := ver != d.apiVersion || len(diff.UpsertedNodes)+len(diff.DeletedNodes)+len(diff.AddedNamespaces)+len(diff.DeletedNamespaces) > 0
	d.mu.RUnlock()
	if !changed {
		return
	}
	if err := d.a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_InventoryDiff{InventoryDiff: diff}}); err != nil {
		return
	}
	d.mu.Lock()
	d.apiVersion, d.sentNodes, d.sentNS = ver, nodes, nss
	d.mu.Unlock()
}

func (d *discovery) sendTargetChanges() {
	cur := d.computeTargets()
	d.mu.Lock()
	d.targets = cur
	prev := d.sentTargets
	d.mu.Unlock()
	sent := map[string]*pb.Target{}
	for id, t := range prev {
		sent[id] = t
	}
	for id, t := range cur {
		if old, ok := prev[id]; !ok || !proto.Equal(old, t) {
			if d.a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_TargetUpsert{TargetUpsert: &pb.TargetUpsert{Target: t}}}) == nil {
				sent[id] = t
			}
		}
	}
	for id := range prev {
		if _, ok := cur[id]; !ok {
			if d.a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_TargetDelete{TargetDelete: &pb.TargetDelete{TargetId: id}}}) == nil {
				delete(sent, id)
			}
		}
	}
	d.mu.Lock()
	d.sentTargets = sent
	d.mu.Unlock()
}

// lookupTarget returns a target from the agent's OWN discovered set.
func (d *discovery) lookupTarget(id string) (*pb.Target, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	t, ok := d.targets[id]
	return t, ok
}

func (d *discovery) computeTargets() map[string]*pb.Target {
	out := map[string]*pb.Target{}
	cid := d.clusterID()
	svcs, _ := d.svcs.List(labels.Everything())
	for _, s := range svcs {
		t, ok := TargetFromService(cid, s)
		if ok {
			out[t.TargetId] = t
		}
	}
	return out
}

// Default ports per engine when olympos.io/port is not set.
var defaultPorts = map[string][]int32{
	"postgresql": {5432},
	"clickhouse": {9440, 9000},
	"vault":      {8200},
}

// TargetFromService derives a target from an annotated Service.
func TargetFromService(clusterID string, s *corev1.Service) (*pb.Target, bool) {
	backup := strings.TrimSpace(s.Annotations[AnnBackup])
	vault := strings.TrimSpace(s.Annotations[AnnVault])
	switch backup {
	case "", "postgresql", "clickhouse", "vault":
	default:
		return nil, false
	}
	switch vault {
	case "", "hashicorp", "openbao":
	default:
		vault = ""
	}
	if backup == "" && vault == "" {
		return nil, false
	}
	engine := backup
	if engine == "" {
		engine = "vault"
	}
	port, ok := pickPort(s, engine)
	if !ok {
		return nil, false
	}
	return &pb.Target{
		TargetId:      targetid.Compute(clusterID, s.Namespace, s.Name, port.Port),
		Namespace:     s.Namespace,
		Service:       s.Name,
		Port:          port.Port,
		PortName:      port.Name,
		Engine:        backup,
		VaultProvider: vault,
		TlsServerName: s.Annotations[AnnTLSServerName],
	}, true
}

func pickPort(s *corev1.Service, engine string) (corev1.ServicePort, bool) {
	if want := strings.TrimSpace(s.Annotations[AnnPort]); want != "" {
		n, numErr := strconv.Atoi(want)
		for _, p := range s.Spec.Ports {
			if p.Name == want || (numErr == nil && p.Port == int32(n)) {
				return p, true
			}
		}
		return corev1.ServicePort{}, false
	}
	for _, def := range defaultPorts[engine] {
		for _, p := range s.Spec.Ports {
			if p.Port == def {
				return p, true
			}
		}
	}
	if len(s.Spec.Ports) == 1 {
		return s.Spec.Ports[0], true
	}
	return corev1.ServicePort{}, false
}

func nodeToPB(n *corev1.Node) *pb.Node {
	out := &pb.Node{
		Name:                n.Name,
		ProviderId:          n.Spec.ProviderID,
		KubeletVersion:      n.Status.NodeInfo.KubeletVersion,
		Region:              n.Labels["topology.kubernetes.io/region"],
		Zone:                n.Labels["topology.kubernetes.io/zone"],
		InstanceType:        n.Labels["node.kubernetes.io/instance-type"],
		CpuCapacityMilli:    n.Status.Capacity.Cpu().MilliValue(),
		MemCapacityBytes:    n.Status.Capacity.Memory().Value(),
		CpuAllocatableMilli: n.Status.Allocatable.Cpu().MilliValue(),
		MemAllocatableBytes: n.Status.Allocatable.Memory().Value(),
	}
	for k := range n.Labels {
		if r, ok := strings.CutPrefix(k, "node-role.kubernetes.io/"); ok && r != "" {
			out.Roles = append(out.Roles, r)
		}
	}
	sort.Strings(out.Roles)
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			out.Ready = c.Status == corev1.ConditionTrue
		}
	}
	return out
}

func sortedNodes(m map[string]*pb.Node) []*pb.Node {
	out := make([]*pb.Node, 0, len(m))
	for _, n := range m {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
