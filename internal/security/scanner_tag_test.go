package security

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const dg6 = "sha256:6666666666666666666666666666666666666666666666666666666666666666"

func TestFallbackTag(t *testing.T) {
	cases := map[string][]string{
		"":        nil,
		"latest":  {"latest"},
		"v1.37.0": {"latest", "v1.37.0"},
		"1.25":    {"bad tag!", "1.25", "1.26"},
	}
	for want, tags := range cases {
		if got := fallbackTag(tags); got != want {
			t.Errorf("fallbackTag(%v) = %q, want %q", tags, got, want)
		}
	}
}

// A digest missing from its registry is scanned by tag (scanned_by=tag,
// scan_note); only when the tag fails too is it unavailable (or
// missing_credential on auth errors). Tag scans emit no vuln.critical.
func TestScannerTagFallback(t *testing.T) {
	ctx := context.Background()
	e := newScanEnv(t)
	e.report(t,
		use("kindest/node:v1.31.0", dg1, "kube-system", "DaemonSet", "kindnet", "node"),
		use("ghcr.io/org/private:2.0", dg2, "app", "Deployment", "p", "p"),
		use("quay.io/x/y:1.0", dg3, "app", "Deployment", "y", "y"),
		use("redis:7", dg4, "app", "StatefulSet", "redis", "redis"),
		use("registry.local/app@"+dg5, dg5, "app", "Deployment", "untagged", "app"),
		use("nginx:1.27", dg6, "web", "Deployment", "front", "nginx"),
	)
	e.runner.out = func(ref string) ([]byte, error) {
		switch {
		case strings.HasPrefix(ref, "docker.io/library/nginx@"):
			return fixture(nil) // normal digest scan
		case strings.Contains(ref, "@sha256:"):
			return nil, &ScanError{NotFound: true, Msg: "MANIFEST_UNKNOWN: manifest unknown"}
		case ref == "docker.io/kindest/node:v1.31.0":
			return fixture(nil)
		case ref == "ghcr.io/org/private:2.0":
			return nil, &ScanError{Auth: true, Msg: "UNAUTHORIZED"}
		case ref == "quay.io/x/y:1.0":
			return nil, &ScanError{NotFound: true, Msg: "MANIFEST_UNKNOWN"}
		case ref == "docker.io/library/redis:7":
			return nil, errors.New("connection reset by peer")
		}
		t.Errorf("unexpected scan of %s", ref)
		return nil, errors.New("unexpected")
	}
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	type row struct{ status, msg, by, note string }
	get := func(d string) row {
		var r row
		if err := e.db.QueryRow(ctx, `SELECT scan_status, scan_error, scanned_by, scan_note FROM images WHERE digest = $1`, d).Scan(&r.status, &r.msg, &r.by, &r.note); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// kind node image: scanned by tag, with results.
	r := get(dg1)
	if r.status != "scanned" || r.by != "tag" || r.note != TagScanNote("v1.31.0") || r.msg != "" {
		t.Errorf("tag scan = %+v", r)
	}
	if !strings.Contains(r.note, "Scanned by tag v1.31.0 — the running digest is not in the registry") {
		t.Errorf("note = %q", r.note)
	}
	var crit int
	_ = e.db.QueryRow(ctx, `SELECT critical FROM images WHERE digest = $1`, dg1).Scan(&crit)
	if crit == 0 {
		t.Error("tag scan stored no results")
	}
	calls := func(prefix string) []string {
		e.runner.mu.Lock()
		defer e.runner.mu.Unlock()
		var out []string
		for _, c := range e.runner.calls {
			if strings.HasPrefix(c.ref, prefix) {
				out = append(out, c.ref)
			}
		}
		return out
	}
	if c := calls("docker.io/kindest/node"); len(c) != 2 || c[0] != "docker.io/kindest/node@"+dg1 || c[1] != "docker.io/kindest/node:v1.31.0" {
		t.Errorf("kind calls = %v", c)
	}
	// Tag needs a credential → missing_credential.
	if r := get(dg2); r.status != "missing_credential" || !strings.Contains(r.msg, "ghcr.io") || r.by != "" {
		t.Errorf("private = %+v", r)
	}
	// Tag not there either → unavailable.
	if r := get(dg3); r.status != "unavailable" || !strings.Contains(r.msg, "not in quay.io") || !strings.Contains(r.msg, "tag 1.0") {
		t.Errorf("quay = %+v", r)
	}
	// Transient error on the tag scan → failed (retried).
	if r := get(dg4); r.status != "failed" || !strings.Contains(r.msg, "tag 7") || !strings.Contains(r.msg, "connection reset") {
		t.Errorf("redis = %+v", r)
	}
	// No tag to fall back to → unavailable.
	if r := get(dg5); r.status != "unavailable" || !strings.Contains(r.msg, "no tag") {
		t.Errorf("untagged = %+v", r)
	}
	if c := calls("registry.local/app"); len(c) != 1 {
		t.Errorf("untagged calls = %v", c)
	}
	// Digest scans are marked as such.
	if r := get(dg6); r.status != "scanned" || r.by != "digest" || r.note != "" {
		t.Errorf("digest scan = %+v", r)
	}
	// vuln.critical only for the digest scan.
	for _, k := range e.criticalKeys(t) {
		if strings.Contains(k, dg1) {
			t.Errorf("vuln.critical emitted for a tag scan: %s", k)
		}
	}
	if keys := e.criticalKeys(t); len(keys) == 0 || !strings.Contains(strings.Join(keys, " "), dg6) {
		t.Errorf("digest scan critical events = %v", keys)
	}

	// The image API returns scanned_by and scan_note.
	a := &API{DB: e.db, Log: quiet}
	regs, _ := registryRefs(ctx, e.db)
	rows, err := e.db.Query(ctx, imageSelect+` AND i.digest = $2 GROUP BY i.digest`, []any{e.cluster}, dg1)
	if err != nil {
		t.Fatal(err)
	}
	items, err := a.scanImages(rows, regs)
	if err != nil || len(items) != 1 || items[0].ScannedBy != "tag" || items[0].ScanNote == "" {
		t.Fatalf("api image = %+v %v", items, err)
	}
}
