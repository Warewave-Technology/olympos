package audit

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/agent"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

func TestSelectBenchmark(t *testing.T) {
	cases := []struct {
		provider, version string
		roles             []string
		want              string
	}{
		{"azure", "v1.32.4", []string{"agent"}, "aks-1.8/node"},
		{"azure", "v1.32.4", []string{"control-plane"}, "aks-1.8/node"}, // managed: never master
		{"aws", "v1.31.2-eks-1", nil, "eks-1.8.0/node"},
		{"gcp", "v1.33.1-gke.100", nil, "gke-1.9.0/node"},
		{"onprem", "v1.33.2", []string{"control-plane"}, "cis-1.12/master"},
		{"onprem", "v1.33.2", []string{"master"}, "cis-1.12/master"},
		{"onprem", "v1.33.2", []string{"worker"}, "cis-1.12/node"},
		{"onprem", "v1.32.0", nil, "cis-1.11/node"},
		{"onprem", "v1.31.0", []string{"control-plane"}, "cis-1.10/master"},
		{"onprem", "v1.30.5", nil, "cis-1.10/node"},
		{"onprem", "v1.28.5", nil, "cis-1.9/node"},
		{"", "", []string{"control-plane"}, "cis-1.12/master"},
		{"oracle", "v1.33.0", []string{"control-plane"}, "cis-1.12/node"}, // OKE → generic node
		{"huawei", "v1.30.0", nil, "cis-1.10/node"},
	}
	allow := agent.BenchProfiles()
	for _, c := range cases {
		got := SelectBenchmark(c.provider, c.version, c.roles)
		if got != c.want {
			t.Errorf("%s %s %v: got %s want %s", c.provider, c.version, c.roles, got, c.want)
		}
		if !slices.Contains(allow, got) {
			t.Errorf("%s is not in the agent allowlist %v", got, allow)
		}
	}
}

func TestBenchCollector(t *testing.T) {
	cluster := uuid.New()
	run := uuid.New().String()
	c := newBenchCollector(cluster, []string{"a", "b"})
	c.status(&pb.BenchStatus{RunId: run, NodeName: "a", State: "accepted"})
	c.status(&pb.BenchStatus{RunId: run, NodeName: "zzz", State: "succeeded"}) // unknown node ignored
	c.chunk(&pb.BenchResultChunk{RunId: run, NodeName: "a", Data: []byte(`{"Con`)})
	c.chunk(&pb.BenchResultChunk{RunId: run, NodeName: "a", Data: []byte(`trols":[]}`), Last: true})
	if c.allDone() {
		t.Fatal("done too early")
	}
	c.status(&pb.BenchStatus{RunId: run, NodeName: "a", State: "succeeded"})
	c.status(&pb.BenchStatus{RunId: run, NodeName: "b", State: "rejected", Message: "unknown node"})
	if !c.allDone() {
		t.Fatal("not done")
	}
	s := c.snapshot()
	if s["a"].Data.String() != `{"Controls":[]}` || s["b"].Message != "unknown node" {
		t.Fatalf("snapshot %+v", s)
	}
	// A terminal state is not overwritten.
	c.status(&pb.BenchStatus{RunId: run, NodeName: "b", State: "succeeded"})
	if c.snapshot()["b"].State != "rejected" {
		t.Fatal("terminal state overwritten")
	}
}

func TestBenchDeadline(t *testing.T) {
	if d := benchDeadline(7, 3); d != 3*12*time.Minute+2*time.Minute {
		t.Fatalf("got %v", d)
	}
	if d := benchDeadline(1, 0); d != 14*time.Minute {
		t.Fatalf("got %v", d)
	}
}

// F18: chunks re-sent after a reconnect are not applied twice; a gap fails
// the node.
func TestBenchCollectorSeq(t *testing.T) {
	c := newBenchCollector(uuid.New(), []string{"a", "b"})
	c.status(&pb.BenchStatus{NodeName: "a", State: "succeeded"})
	for _, seq := range []uint32{1, 2, 1, 2, 3} {
		c.chunk(&pb.BenchResultChunk{NodeName: "a", Seq: seq, Data: []byte{byte('0' + seq)}, Last: seq == 3})
	}
	c.chunk(&pb.BenchResultChunk{NodeName: "a", Seq: 3, Data: []byte("x"), Last: true}) // after last: ignored
	st := c.snapshot()["a"]
	if got := st.Data.String(); got != "123" || !st.Last {
		t.Fatalf("node a: %q last=%v", got, st.Last)
	}
	c.status(&pb.BenchStatus{NodeName: "b", State: "succeeded"})
	c.chunk(&pb.BenchResultChunk{NodeName: "b", Seq: 1, Data: []byte("1")})
	c.chunk(&pb.BenchResultChunk{NodeName: "b", Seq: 3, Data: []byte("3"), Last: true})
	if st := c.snapshot()["b"]; st.State != "failed" || st.Data.Len() != 0 {
		t.Fatalf("gap must fail the node: %+v", st)
	}
}
