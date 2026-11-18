package security

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// F2: a report opens one finding per key (high for patterns, medium for key
// names), sends one grouped sensitive_data.found, skips system namespaces
// and resolves findings whose key is gone.
func TestIngestSensitiveData(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	in := &Ingester{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), SystemNamespaces: []string{"kube-*"}}
	var cid uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, status) VALUES ('c1', 'online') RETURNING id`).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	item := func(key, rule, conf string) *pb.SensitiveDataItem {
		return &pb.SensitiveDataItem{Namespace: "shop", ConfigMap: "app-config", Key: key, RuleId: rule, RuleDescription: "d", Confidence: conf, ValueLength: 20}
	}
	report := func(items ...*pb.SensitiveDataItem) {
		t.Helper()
		if err := in.Report(ctx, cid, &pb.ResourceReport{Report: &pb.ResourceReport_SensitiveData{SensitiveData: &pb.SensitiveDataReport{
			RulesVersion: "v", Items: items}}}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string) int {
		var n int
		if err := db.QueryRow(ctx, q, cid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	sys := &pb.SensitiveDataItem{Namespace: "kube-system", ConfigMap: "x", Key: "PASSWORD", RuleId: "key-name:password", Confidence: "medium"}
	report(item("AWS_ACCESS_KEY_ID", "aws-access-token", "high"), item("tls.key", "private-key", "high"), item("DB_PASSWORD", "key-name:password", "medium"), sys)
	if n := count(`SELECT count(*) FROM findings WHERE cluster_id = $1 AND source = 'sensitive-data' AND status = 'open'`); n != 3 {
		t.Fatalf("open findings: %d", n)
	}
	if n := count(`SELECT count(*) FROM findings WHERE cluster_id = $1 AND source = 'sensitive-data' AND severity = 'high'`); n != 2 {
		t.Fatalf("high: %d", n)
	}
	if n := count(`SELECT count(*) FROM outbox WHERE event_type = 'sensitive_data.found' AND payload->>'cluster_id' = $1::text`); n != 1 {
		t.Fatalf("events: %d", n)
	}
	// The keys go away: resolved, no new event.
	report(item("tls.key", "private-key", "high"))
	if n := count(`SELECT count(*) FROM findings WHERE cluster_id = $1 AND source = 'sensitive-data' AND status = 'resolved'`); n != 2 {
		t.Fatalf("resolved: %d", n)
	}
	if n := count(`SELECT count(*) FROM outbox WHERE event_type = 'sensitive_data.found' AND payload->>'cluster_id' = $1::text`); n != 1 {
		t.Fatalf("events after resolve: %d", n)
	}
}
