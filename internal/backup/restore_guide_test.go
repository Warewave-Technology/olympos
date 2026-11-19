package backup

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// F19: per-run restore commands name the exact blob, checksum and tool.
func TestRestoreGuide(t *testing.T) {
	run := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	base := guideInput{blobPath: "olympos/c1/shop/orders/postgresql/2026/11/19/" + run.String() + ".zip", sha256: "abc123", runID: run,
		engine: "postgresql", ns: "shop", svc: "orders"}
	all := func(g *RestoreGuide) string {
		var b strings.Builder
		for _, s := range g.Steps {
			b.WriteString(s.Commands + "\n")
		}
		return b.String()
	}
	for _, tc := range []struct {
		name string
		in   func(guideInput) guideInput
		want []string
	}{
		{"azure+pg", func(i guideInput) guideInput {
			i.kind, i.account, i.container, i.options = "azure_blob", "acct", "backups", map[string]any{"databases": []any{"shop"}, "globals": false}
			return i
		}, []string{"az storage blob download", "--account-name 'acct'", "'" + base.blobPath + "'", run.String() + ".manifest.json",
			"abc123  backup.zip", "pg_restore -h <new-host> -U postgres -d 'shop'", "'restore/shop.dump'"}},
		{"s3 compatible", func(i guideInput) guideInput {
			i.kind, i.bucket, i.region, i.endpoint = "s3", "bk", "eu-west-1", "https://minio.local:9000"
			return i
		}, []string{"aws s3 cp 's3://bk/" + base.blobPath + "'", "--region 'eu-west-1'", "--endpoint-url 'https://minio.local:9000'", "for f in restore/*.dump", "globals.sql"}},
		{"nfs+vault", func(i guideInput) guideInput {
			i.kind, i.nfsPath, i.engine, i.vaultProvider, i.svc = "nfs", "/var/lib/olympos/nfs/lab/olympos", "vault", "openbao", "openbao"
			i.blobPath = strings.TrimSuffix(i.blobPath, ".zip") + ".snap"
			return i
		}, []string{"cp '/var/lib/olympos/nfs/lab/olympos/olympos/c1", "bao operator raft snapshot restore -force backup.snap"}},
		{"clickhouse", func(i guideInput) guideInput { i.kind, i.engine = "azure_blob", "clickhouse"; return i }, []string{"restore-clickhouse.sh backup.zip"}},
	} {
		g := buildRestoreGuide(tc.in(base))
		got := all(g)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", tc.name, w, got)
			}
		}
		if g.Doc == "" {
			t.Errorf("%s: no doc link", tc.name)
		}
	}
	self := base
	self.kind, self.ns, self.svc = "azure_blob", selfNamespace, selfService
	if g := buildRestoreGuide(self); g.Doc != "docs/restore-olympos.md" {
		t.Errorf("olympos-self doc: %s", g.Doc)
	}
}

// F10: a dry run's checklist lists each stage that ran with its result.
func TestDryRunSteps(t *testing.T) {
	yes := true
	job := &Job{DestinationName: "lab-azurite"}
	job.Target.Namespace, job.Target.Service = "shop", "orders-pg"
	names := func(s []Step) string {
		var b strings.Builder
		for _, x := range s {
			if x.OK {
				b.WriteString("+" + x.Name + " ")
			} else {
				b.WriteString("-" + x.Name + " ")
			}
		}
		return strings.TrimSpace(b.String())
	}
	ok := dryRunSteps(outcome{status: "succeeded", bytes: 2048, wire: 900}, &RunResult{ServerVersion: "16.4", TLS: &yes}, job)
	if names(ok) != "+agent +credential +engine +upload +manifest" || !strings.Contains(ok[2].Detail, "TLS verified") || !strings.Contains(ok[3].Detail, "lab-azurite") {
		t.Fatalf("success: %+v", ok)
	}
	for _, tc := range []struct{ err, want string }{
		{errAgentOffline, "-agent"},
		{"credential: kv://x not found", "+agent -credential"},
		{"open destination: 403", "+agent +credential -destination"},
		{"connect: password authentication failed", "+agent +credential -engine"},
		{"upload: 503", "+agent +credential +engine -upload"},
		{"upload manifest: 409", "+agent +credential +engine +upload -manifest"},
	} {
		if got := names(dryRunSteps(outcome{status: "failed", err: tc.err}, nil, job)); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.err, got, tc.want)
		}
	}
}
