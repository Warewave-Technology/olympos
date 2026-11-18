package audit

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/inventory"
)

// Benchmark auto-selection (SPEC §12.3.8). Profile IDs match the agent's
// compiled-in allowlist ("<kube-bench benchmark>/<role>").
//
//	AKS (azure)      → aks-1.8/node
//	EKS (aws)        → eks-1.8.0/node
//	GKE (gcp)        → gke-1.9.0/node
//	on-prem          → cis-<v>/master on control-plane nodes, cis-<v>/node elsewhere
//	OKE/Huawei/other → cis-<v>/node (generic)
//
// cis-<v> follows the cluster's API minor version: ≤1.29 → cis-1.9,
// 1.30–1.31 → cis-1.10, 1.32 → cis-1.11, ≥1.33 (or unknown) → cis-1.12.
var managedBenchmarks = map[string]string{
	inventory.ProviderAzure: "aks-1.8/node",
	inventory.ProviderAWS:   "eks-1.8.0/node",
	inventory.ProviderGCP:   "gke-1.9.0/node",
}

func cisVersion(apiVersion string) string {
	m := inventory.Minor(apiVersion)
	switch {
	case m == 0:
		return "cis-1.12"
	case m <= 29:
		return "cis-1.9"
	case m <= 31:
		return "cis-1.10"
	case m == 32:
		return "cis-1.11"
	}
	return "cis-1.12"
}

// SelectBenchmark picks the profile for one node.
func SelectBenchmark(provider, apiVersion string, nodeRoles []string) string {
	if b, ok := managedBenchmarks[provider]; ok {
		return b
	}
	cis := cisVersion(apiVersion)
	if provider == inventory.ProviderOnPrem || provider == "" {
		for _, r := range nodeRoles {
			if r == "control-plane" || r == "master" {
				return cis + "/master"
			}
		}
	}
	return cis + "/node"
}

// benchmarkName strips the role from a profile ID ("cis-1.12/node" → "cis-1.12").
func benchmarkName(profile string) string {
	if i := strings.IndexByte(profile, '/'); i > 0 {
		return profile[:i]
	}
	return profile
}

// ---------------------------------------------------------------- collector

// benchNodeState is what the agent reported for one node.
type benchNodeState struct {
	State   string
	Message string
	Data    bytes.Buffer
	Last    bool
}

func (n *benchNodeState) done() bool {
	switch n.State {
	case "rejected", "failed":
		return true
	case "succeeded":
		return n.Last
	}
	return false
}

// benchCollector gathers BenchStatus/BenchResultChunk for one run.
type benchCollector struct {
	mu      sync.Mutex
	cluster uuid.UUID
	nodes   map[string]*benchNodeState
	changed chan struct{}
}

func newBenchCollector(cluster uuid.UUID, nodes []string) *benchCollector {
	c := &benchCollector{cluster: cluster, nodes: map[string]*benchNodeState{}, changed: make(chan struct{}, 1)}
	for _, n := range nodes {
		c.nodes[n] = &benchNodeState{State: "pending"}
	}
	return c
}

func (c *benchCollector) signal() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

// maxBenchBytes caps one node's result on the server.
const maxBenchBytes = 16 << 20

func (c *benchCollector) status(s *pb.BenchStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[s.NodeName]
	if !ok || n.done() {
		return
	}
	n.State, n.Message = s.State, truncate(s.Message, 500)
	c.signal()
}

func (c *benchCollector) chunk(ch *pb.BenchResultChunk) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[ch.NodeName]
	if !ok || n.Last || n.State == "rejected" || n.State == "failed" {
		return
	}
	if n.Data.Len()+len(ch.Data) > maxBenchBytes {
		n.State, n.Message = "failed", "kube-bench result too large"
		n.Data.Reset()
		c.signal()
		return
	}
	n.Data.Write(ch.Data)
	if ch.Last {
		n.Last = true
		c.signal()
	}
}

// fail marks a node failed locally (e.g. send error).
func (c *benchCollector) fail(node, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n, ok := c.nodes[node]; ok && !n.done() {
		n.State, n.Message = "failed", msg
		c.signal()
	}
}

func (c *benchCollector) allDone() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.nodes {
		if !n.done() {
			return false
		}
	}
	return true
}

// snapshot returns node states (copy) for persistence.
func (c *benchCollector) snapshot() map[string]*benchNodeState {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]*benchNodeState{}
	for k, n := range c.nodes {
		cp := &benchNodeState{}
		cp.State, cp.Message, cp.Last = n.State, n.Message, n.Last
		cp.Data.Write(n.Data.Bytes())
		out[k] = cp
	}
	return out
}

// wait blocks until every node is done, the deadline passes or ctx ends.
// onChange is called after each update (to persist progress).
func (c *benchCollector) wait(ctx context.Context, deadline time.Duration, onChange func()) bool {
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	for {
		if c.allDone() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case <-c.changed:
			if onChange != nil {
				onChange()
			}
		}
	}
}

// benchDeadline: each wave of maxParallel nodes may take the Job's
// activeDeadlineSeconds (600 s) plus scheduling/log slack.
func benchDeadline(nodes, maxParallel int) time.Duration {
	if maxParallel < 1 {
		maxParallel = 1
	}
	waves := (nodes + maxParallel - 1) / maxParallel
	return time.Duration(waves)*12*time.Minute + 2*time.Minute
}
