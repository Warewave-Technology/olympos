package agent

import (
	"context"
	"log/slog"
	pathpkg "path"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

const (
	// sensitiveRescan: full re-list and re-scan of every ConfigMap.
	sensitiveRescan = 6 * time.Hour
	// rootCAConfigMap exists in every namespace and holds a public CA.
	rootCAConfigMap = "kube-root-ca.crt"
)

// DefaultSensitiveExclude are namespaces not scanned (same defaults as the
// server's security.systemNamespaces; Helm sensitiveData.excludeNamespaces).
var DefaultSensitiveExclude = []string{"kube-system", "kube-public", "kube-node-lease", "olympos-system", "olympos-bench"}

// sensitiveReporter reports sensitive data in ConfigMaps (F2). Its own
// ConfigMap informer scans every object in a transform and caches only
// metadata, so values are never kept in memory beyond one scan.
type sensitiveReporter struct {
	kube    kubernetes.Interface
	log     *slog.Logger
	scanner *sensitiveScanner
	exclude []string
	changed signal

	inf  cache.SharedIndexInformer
	once sync.Once

	mu      sync.Mutex
	results map[types.UID]cmScan
}

type cmScan struct {
	ns, name string
	items    []*pb.SensitiveDataItem
}

func newSensitiveReporter(kube kubernetes.Interface, exclude []string, log *slog.Logger) (*sensitiveReporter, error) {
	sc, err := newSensitiveScanner()
	if err != nil {
		return nil, err
	}
	if exclude == nil {
		exclude = DefaultSensitiveExclude
	}
	r := &sensitiveReporter{kube: kube, log: log, scanner: sc, exclude: exclude, changed: newSignal(), results: map[types.UID]cmScan{}}
	f := informers.NewSharedInformerFactory(kube, 0)
	r.inf = f.Core().V1().ConfigMaps().Informer()
	_ = r.inf.SetTransform(r.transform)
	_, _ = r.inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj any) {
			if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = d.Obj
			}
			if m, ok := obj.(metav1.Object); ok {
				r.mu.Lock()
				delete(r.results, m.GetUID())
				r.mu.Unlock()
				r.changed.poke()
			}
		},
	})
	return r, nil
}

func (r *sensitiveReporter) Name() string { return "sensitive-data" }

func (r *sensitiveReporter) skipped(cm *corev1.ConfigMap) bool {
	if cm.Name == rootCAConfigMap {
		return true
	}
	for _, p := range r.exclude {
		if ok, _ := pathpkg.Match(p, cm.Namespace); ok {
			return true
		}
	}
	return false
}

// transform scans a full ConfigMap and hands the cache a copy without data.
func (r *sensitiveReporter) transform(obj any) (any, error) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return obj, nil
	}
	if cm.Data != nil || cm.BinaryData != nil {
		var items []*pb.SensitiveDataItem
		if !r.skipped(cm) {
			items = r.scanner.scan(cm)
		}
		r.mu.Lock()
		if len(items) > 0 {
			r.results[cm.UID] = cmScan{ns: cm.Namespace, name: cm.Name, items: items}
		} else {
			delete(r.results, cm.UID)
		}
		r.mu.Unlock()
		r.changed.poke()
	}
	return &corev1.ConfigMap{TypeMeta: cm.TypeMeta, ObjectMeta: metav1.ObjectMeta{Name: cm.Name, Namespace: cm.Namespace,
		UID: cm.UID, ResourceVersion: cm.ResourceVersion}}, nil
}

// rescan lists every ConfigMap (paged) and replaces the results.
func (r *sensitiveReporter) rescan(ctx context.Context) error {
	fresh := map[types.UID]cmScan{}
	opts := metav1.ListOptions{Limit: 200}
	for {
		list, err := r.kube.CoreV1().ConfigMaps("").List(ctx, opts)
		if err != nil {
			return err
		}
		for i := range list.Items {
			cm := &list.Items[i]
			if r.skipped(cm) {
				continue
			}
			if items := r.scanner.scan(cm); len(items) > 0 {
				fresh[cm.UID] = cmScan{ns: cm.Namespace, name: cm.Name, items: items}
			}
		}
		list.Items = nil
		if list.Continue == "" {
			break
		}
		opts.Continue = list.Continue
	}
	r.mu.Lock()
	r.results = fresh
	r.mu.Unlock()
	r.changed.poke()
	return nil
}

func (r *sensitiveReporter) start(ctx context.Context) error {
	var err error
	r.once.Do(func() {
		go r.inf.Run(context.Background().Done())
		go func() {
			t := time.NewTicker(sensitiveRescan)
			defer t.Stop()
			for range t.C {
				rctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
				if err := r.rescan(rctx); err != nil {
					r.log.Warn("sensitive data rescan", "err", err)
				}
				cancel()
			}
		}()
	})
	wctx, cancel := context.WithTimeout(ctx, cacheSyncTimeout)
	defer cancel()
	if !cache.WaitForCacheSync(wctx.Done(), r.inf.HasSynced) {
		err = context.DeadlineExceeded
	}
	return err
}

func (r *sensitiveReporter) build(context.Context) (*pb.ResourceReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rep := &pb.SensitiveDataReport{RulesVersion: SensitiveRulesVersion, ConfigMapsScanned: int32(len(r.inf.GetStore().ListKeys()))}
	for _, s := range r.results {
		rep.Items = append(rep.Items, s.items...)
	}
	sort.Slice(rep.Items, func(i, j int) bool {
		a, b := rep.Items[i], rep.Items[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.ConfigMap != b.ConfigMap {
			return a.ConfigMap < b.ConfigMap
		}
		return a.Key < b.Key
	})
	return &pb.ResourceReport{Report: &pb.ResourceReport_SensitiveData{SensitiveData: rep}}, nil
}

// Run sends the report once the informer has synced (never a partial
// report: that would resolve findings that still exist), then on change.
func (r *sensitiveReporter) Run(ctx context.Context, send func(*pb.ResourceReport)) error {
	if err := r.start(ctx); err != nil {
		return err
	}
	l := &reportLoop{name: r.Name(), log: r.log, changed: r.changed, debounce: 2 * time.Second, build: r.build}
	return l.run(ctx, send)
}
