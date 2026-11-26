//go:build dev

package backup_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/backup/engines/clickhouse"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// The restore check of a native copy (task 16) on chains the worker took:
// the chain is resolved from the copy's run, read from the copy's
// destination, verified and bound for reads.

// CheckNativeRestore is the real engine's.
func (fakeEngine) CheckNativeRestore(ctx context.Context, in backup.NativeRestoreInput) (*backup.NativeRestoreCheck, error) {
	return clickhouse.Engine{}.CheckNativeRestore(ctx, in)
}

func restoreCfg(e nativeEnv) backup.NativeRestoreConfig {
	return backup.NativeRestoreConfig{KV: e.kv, ManifestKeyName: nativeKey, URL: e.srv.URL}
}

// TestNativeRestoreCheck: an incremental's copy restores from its chain,
// the full first, read from the copy's destination; the decisions are for
// the objects of the selected databases, and the source serves the chain's
// objects only.
func TestNativeRestoreCheck(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedIncremental(t, db)
	full := scheduled(t, e, db, time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC))
	inc := scheduled(t, e, db, time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC))

	for i, b := range []*fakeBlobs{e.B1, e.B2} {
		dest := []uuid.UUID{e.DestID, e.Dest2}[i]
		src, err := backup.FindRestoreSource(ctx, db, inc, &dest)
		if err != nil {
			t.Fatal(err)
		}
		got, err := backup.CheckNativeRestore(ctx, db, b, fakeEngine{}, restoreCfg(e), src, nil, quietLog())
		if err != nil {
			t.Fatalf("copy %d: %v", i, err)
		}
		if !reflect.DeepEqual(got.Runs, []uuid.UUID{full, inc}) || !reflect.DeepEqual(got.Databases, []string{"shop"}) ||
			len(got.Manifests) != 2 {
			t.Fatalf("copy %d: %+v", i, got)
		}
		if want := []backup.NativeDecision{{Database: "shop", Name: "orders", Kind: "table", Allowed: true}}; !reflect.DeepEqual(got.Objects, want) {
			t.Fatalf("copy %d decisions: %+v", i, got.Objects)
		}
		// The source serves the chain: the full's metadata, under its run.
		rc, rec, err := got.Source().Open(ctx, full.String()+"/metadata/shop/orders.sql")
		if err != nil || rec.Size == 0 {
			t.Fatalf("copy %d: the full's metadata: %v", i, err)
		}
		_ = rc.Close()
		if _, _, err := got.Source().Open(ctx, uuid.NewString()+"/.backup"); err == nil {
			t.Fatalf("copy %d: the source serves an object outside the chain", i)
		}
	}

	// Another selection: only its databases are decided.
	src, err := backup.FindRestoreSource(ctx, db, inc, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := backup.CheckNativeRestore(ctx, db, e.B1, fakeEngine{}, restoreCfg(e), src, []string{"other"}, quietLog())
	if err != nil || len(got.Objects) != 0 || !reflect.DeepEqual(got.Databases, []string{"shop"}) {
		t.Fatalf("another selection: %+v, %v", got, err)
	}

	// Through another ingest.url, the chain is refused with the reason.
	cfg := restoreCfg(e)
	cfg.URL = "https://ingest.elsewhere.test:9444"
	if _, err := backup.CheckNativeRestore(ctx, db, e.B1, fakeEngine{}, cfg, src, nil, quietLog()); !errors.Is(err, backup.ErrNativeChain) ||
		!strings.Contains(err.Error(), e.srv.URL+"/olympos/"+full.String()+"/") {
		t.Fatalf("another ingest.url: %v", err)
	}
}

// TestNativeRestoreBaseDoesNotVerify: a chain whose base manifest does not
// verify is refused with "the backup's manifest does not verify"; the
// decisions are listed, from the copy's own signed manifest, every object
// left out, and the chain is not served.
func TestNativeRestoreBaseDoesNotVerify(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedIncremental(t, db)
	full := scheduled(t, e, db, time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC))
	inc := scheduled(t, e, db, time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC))
	side := backup.ManifestPath(runDir(t, db, "a", full), full)
	e.B1.blobs[side] = bytes.Replace(e.B1.blobs[side], []byte(`"rows":42`), []byte(`"rows":43`), 1)

	src, err := backup.FindRestoreSource(ctx, db, inc, &e.DestID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := backup.CheckNativeRestore(ctx, db, e.B1, fakeEngine{}, restoreCfg(e), src, nil, quietLog())
	if !errors.Is(err, backup.ErrNativeNotVerified) || err.Error() == backup.ErrNativeNotVerified.Error() || got == nil {
		t.Fatalf("a base that does not verify: %+v, %v", got, err)
	}
	if want := []backup.NativeDecision{{Database: "shop", Name: "orders", Kind: "table", Reason: "the backup's manifest does not verify"}}; !reflect.DeepEqual(got.Objects, want) {
		t.Fatalf("decisions: %+v", got.Objects)
	}
	if got.Manifests != nil || got.Source() != nil {
		t.Fatal("a chain that does not verify is bound for reads")
	}
	// The other destination's copies are intact: that copy restores.
	src2, err := backup.FindRestoreSource(ctx, db, inc, &e.Dest2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.CheckNativeRestore(ctx, db, e.B2, fakeEngine{}, restoreCfg(e), src2, nil, quietLog()); err != nil {
		t.Fatalf("the intact copy: %v", err)
	}
	// A sidecar that is gone does not verify either.
	delete(e.B2.blobs, backup.ManifestPath(runDir(t, db, "b", full), full))
	if _, err := backup.CheckNativeRestore(ctx, db, e.B2, fakeEngine{}, restoreCfg(e), src2, nil, quietLog()); !errors.Is(err, backup.ErrNativeNotVerified) {
		t.Fatalf("a missing sidecar: %v", err)
	}
}

// TestNativeRestoreChainCopies: every run of the chain needs a succeeded
// copy on the copy's destination; the chain is read there and nowhere else.
func TestNativeRestoreChainCopies(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedIncremental(t, db)
	full := scheduled(t, e, db, time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC))
	inc := scheduled(t, e, db, time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC))
	// A chain member that has no copy on the destination (here, one that
	// never ran: copy rows are append-only).
	other := uuid.New()
	if _, err := db.Exec(ctx, `UPDATE ingest_credentials SET scope = jsonb_set(scope, '{read}', jsonb_build_array($2::text, $3::text))
		WHERE run_id = $1 AND kind = 'backup'`, inc, other.String()+"/", full.String()+"/"); err != nil {
		t.Fatal(err)
	}
	src, err := backup.FindRestoreSource(ctx, db, inc, &e.Dest2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.CheckNativeRestore(ctx, db, e.B2, fakeEngine{}, restoreCfg(e), src, nil, quietLog()); !errors.Is(err, backup.ErrNativeChain) ||
		!strings.Contains(err.Error(), "run "+other.String()+" of its chain has no succeeded copy on dest-b") {
		t.Fatalf("a chain member without a copy here: %v", err)
	}
	// A read scope that is not a chain of run prefixes.
	if _, err := db.Exec(ctx, `UPDATE ingest_credentials SET scope = jsonb_set(scope, '{read}', '["../x/"]') WHERE run_id = $1 AND kind = 'backup'`, inc); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.CheckNativeRestore(ctx, db, e.B2, fakeEngine{}, restoreCfg(e), src, nil, quietLog()); !errors.Is(err, backup.ErrNativeChain) {
		t.Fatalf("a read scope that is not a chain: %v", err)
	}
	// Longer than a restore reads (32 runs, the cap of Task 13).
	long := make([]string, 32)
	for i := range long {
		long[i] = uuid.NewString() + "/"
	}
	if _, err := db.Exec(ctx, `UPDATE ingest_credentials SET scope = jsonb_set(scope, '{read}', to_jsonb($2::text[])) WHERE run_id = $1 AND kind = 'backup'`, inc, long); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.CheckNativeRestore(ctx, db, e.B2, fakeEngine{}, restoreCfg(e), src, nil, quietLog()); !errors.Is(err, backup.ErrNativeChain) ||
		!strings.Contains(err.Error(), "33 runs, more than the 32") {
		t.Fatalf("a chain over the cap: %v", err)
	}
}

// TestNativeRestoreSource: a native run offers only its succeeded copies, and
// its restore guide has no commands to restore by hand (its copy is a
// directory).
func TestNativeRestoreSource(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedNative(t, db)
	e.B2.fail, e.B2.failAfter, e.B2.failOn = errors.New("503 ServerBusy"), 100_000, "all_1_1_0/data.bin"
	partial := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, partial)
	if r := loadRun(t, db, partial); r.Status != "partial" {
		t.Fatalf("run: %+v", r)
	}
	if _, err := backup.FindRestoreSource(ctx, db, partial, &e.Dest2); !errors.Is(err, backup.ErrNoSuccessfulCopy) {
		t.Fatalf("the failed copy is a source: %v", err)
	}
	src, err := backup.FindRestoreSource(ctx, db, partial, nil)
	if err != nil || src.DestinationID != e.DestID {
		t.Fatalf("default source: %+v, %v", src, err)
	}
	g, err := backup.LoadRestoreGuide(ctx, db, partial, nil)
	if err != nil || g == nil || len(g.Steps) != 0 || len(g.Copies) != 1 || !g.Copies[0].Selected {
		t.Fatalf("guide of a native run: %+v, %v", g, err)
	}
}

// TestNativeRunKeptAs: a daily member of a chain is kept as weekly once an
// incremental on it succeeded (R45), and the run says so; a monthly one is
// kept as it was written.
func TestNativeRunKeptAs(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedIncremental(t, db)
	full := scheduled(t, e, db, time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC))
	r, err := backup.LoadRun(ctx, db, full)
	if err != nil || r.KeptAs != "" {
		t.Fatalf("a full no incremental is based on: %+v, %v", r, err)
	}
	inc := scheduled(t, e, db, time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC))
	for run, want := range map[uuid.UUID]string{full: "", inc: ""} {
		if r, err := backup.LoadRun(ctx, db, run); err != nil || r.KeptAs != want {
			t.Fatalf("run %s kept as %q, want %q (%v)", run, r.KeptAs, want, err)
		}
	}
	// The monthly full stays monthly; the daily incremental, once an
	// incremental is based on it, is kept weekly.
	inc2 := scheduled(t, e, db, time.Date(2026, 11, 25, 2, 0, 0, 0, time.UTC))
	for run, want := range map[uuid.UUID]string{full: "", inc: "weekly", inc2: ""} {
		if r, err := backup.LoadRun(ctx, db, run); err != nil || r.KeptAs != want {
			t.Fatalf("run %s kept as %q, want %q (%v)", run, r.KeptAs, want, err)
		}
	}
}
