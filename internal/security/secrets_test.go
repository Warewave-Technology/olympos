package security

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// F3: the inventory is stored without values; SA tokens, unused (after 7
// days) and unmanaged Secrets become k8s-secrets findings; operator-owned
// and referenced Secrets do not; vanished Secrets are swept.
func TestIngestSecretInventory(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	in := &Ingester{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), SystemNamespaces: []string{"kube-*"}, ReportUnmanaged: true}
	var cid uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, status) VALUES ('c1', 'online') RETURNING id`).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour).Unix()
	report := func(ss ...*pb.K8SSecret) {
		t.Helper()
		if err := in.Report(ctx, cid, &pb.ResourceReport{Report: &pb.ResourceReport_SecretInventory{SecretInventory: &pb.SecretInventoryReport{Secrets: ss}}}); err != nil {
			t.Fatal(err)
		}
	}
	used := &pb.K8SSecret{Namespace: "shop", Name: "db-creds", Keys: []string{"password"}, CreatedUnix: old, ReferencedBy: []string{"Deployment/api"}}
	unused := &pb.K8SSecret{Namespace: "shop", Name: "leftover", Keys: []string{"token"}, CreatedUnix: old}
	eso := &pb.K8SSecret{Namespace: "shop", Name: "from-vault", CreatedUnix: old, ReferencedBy: []string{"Deployment/api"},
		Owners: []*pb.ObjectOwner{{ApiVersion: "external-secrets.io/v1", Kind: "ExternalSecret", Name: "from-vault"}}}
	sa := &pb.K8SSecret{Namespace: "shop", Name: "deployer-token", Type: "kubernetes.io/service-account-token", CreatedUnix: old}
	fresh := &pb.K8SSecret{Namespace: "shop", Name: "new-one", CreatedUnix: time.Now().Unix()}
	sys := &pb.K8SSecret{Namespace: "kube-system", Name: "x", CreatedUnix: old}
	report(used, unused, eso, sa, fresh, sys)

	got := map[string][]string{}
	rows, err := db.Query(ctx, `SELECT resource_ref, control_id FROM findings WHERE cluster_id = $1 AND source = 'k8s-secrets' AND status = 'open'`, cid)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ref, c string
		_ = rows.Scan(&ref, &c)
		got[ref] = append(got[ref], c)
	}
	rows.Close()
	want := map[string]string{
		"shop/db-creds": "secret.unmanaged", "shop/leftover": "secret.unmanaged,secret.unused",
		"shop/deployer-token": "secret.legacy_sa_token", "shop/new-one": "secret.unmanaged",
	}
	for ref, w := range want {
		g := append([]string(nil), got[ref]...)
		sort.Strings(g)
		if strings.Join(g, ",") != w {
			t.Errorf("%s: %v, want %s", ref, g, w)
		}
	}
	if got["shop/from-vault"] != nil || len(got) != len(want) {
		t.Fatalf("findings: %v", got)
	}
	var n, events int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM k8s_secrets WHERE cluster_id = $1`, cid).Scan(&n)
	_ = db.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type = 'secret.new_findings'`).Scan(&events)
	if n != 5 || events != 1 {
		t.Fatalf("rows %d events %d", n, events)
	}
	// leftover deleted in the cluster: row swept, its findings resolved.
	report(used, eso, sa, fresh)
	_ = db.QueryRow(ctx, `SELECT count(*) FROM k8s_secrets WHERE cluster_id = $1`, cid).Scan(&n)
	var open int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM findings WHERE cluster_id = $1 AND resource_ref = 'shop/leftover' AND status = 'open'`, cid).Scan(&open)
	if n != 4 || open != 0 {
		t.Fatalf("after delete: rows %d, open findings for leftover %d", n, open)
	}
}
