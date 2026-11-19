package agent

import (
	"sync"
	"testing"
	"testing/quick"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/targetid"
)

// F11: a tunnel opens only to a target in the agent's OWN discovered set:
// any other id is rejected (property), and a deleted target is rejected as
// soon as the discovered set no longer has it, also under concurrent
// updates and opens (run with -race).
func TestTunnelAllowlist(t *testing.T) {
	d := newDiscovery(&Agent{})
	known := targetid.Compute("c1", "shop", "orders-pg", 5432)
	d.mu.Lock()
	d.targets = map[string]*pb.Target{known: {TargetId: known, Namespace: "shop", Service: "orders-pg", Port: 5432}}
	d.mu.Unlock()
	if _, ok := d.lookupTarget(known); !ok {
		t.Fatal("known target rejected")
	}
	prop := func(id string) bool {
		_, ok := d.lookupTarget(id)
		return id == known || !ok
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 20000}); err != nil {
		t.Fatal(err)
	}
	// Ids of other clusters, namespaces or ports are different targets.
	for _, id := range []string{targetid.Compute("c2", "shop", "orders-pg", 5432), targetid.Compute("c1", "kube-system", "orders-pg", 5432),
		targetid.Compute("c1", "shop", "orders-pg", 5433), "", known + " ", "../" + known} {
		if _, ok := d.lookupTarget(id); ok {
			t.Fatalf("%q accepted", id)
		}
	}

	// Race: discovery removes and re-adds the target while opens look it up.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = d.lookupTarget(known)
				}
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		next := map[string]*pb.Target{}
		if i%2 == 0 {
			next[known] = &pb.Target{TargetId: known}
		}
		d.mu.Lock()
		d.targets = next
		d.mu.Unlock()
	}
	d.mu.Lock()
	d.targets = map[string]*pb.Target{} // the target is gone
	d.mu.Unlock()
	close(stop)
	wg.Wait()
	if _, ok := d.lookupTarget(known); ok {
		t.Fatal("deleted target still accepted")
	}
}
