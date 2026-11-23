//go:build dev

package backup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// FindRestoreSource picks the same copy as the restore guide: the run's own
// copy, a repair's copy for a destination the run missed, never a failed
// copy, and nothing for a run that cannot be restored.
func TestFindRestoreSource(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	g := seedGroup(t, db, jobOpts{cron: yearly})
	orig, _ := partialRun(t, db, g)

	// Default: the run's own (first) succeeded copy.
	s, err := backup.FindRestoreSource(ctx, db, orig, nil)
	if err != nil || s.DestinationID != g.DestID || s.CopyRunID != orig || s.RunID != orig || s.BlobPath == "" || s.SHA256 == "" ||
		s.DestinationName != "dest" {
		t.Fatalf("default source: %+v, %v", s, err)
	}
	// dest-b failed in the run: no copy there (yet).
	if _, err := backup.FindRestoreSource(ctx, db, orig, &g.Dest2); !errors.Is(err, backup.ErrNoSuccessfulCopy) {
		t.Fatalf("failed copy is not a source: %v", err)
	}
	// After the repair wrote dest-b, it is restorable from the repair's copy.
	rep := onlyRepair(t, db, g.Job, orig, 2, g.Dest2)
	g.B2.fail, g.B2.failAfter = nil, 0
	claimRepair(t, g.W, db, rep.ID)
	s, err = backup.FindRestoreSource(ctx, db, orig, &g.Dest2)
	if err != nil || s.DestinationID != g.Dest2 || s.CopyRunID != rep.ID || s.RunID != orig {
		t.Fatalf("repair copy: %+v, %v", s, err)
	}
	guide, err := backup.LoadRestoreGuide(ctx, db, orig, &g.Dest2)
	if err != nil || len(guide.Copies) != 2 || !guide.Copies[1].Selected || guide.Copies[1].RunID != s.CopyRunID {
		t.Fatalf("guide and source disagree: %+v, %v", guide, err)
	}

	// A test run is never a source; an unknown run is not found.
	tr := queue(t, db, g.Job, "test", nil)
	g.B2.fail, g.B2.failAfter = nil, 0
	claimAndRun(t, g.W, tr)
	if _, err := backup.FindRestoreSource(ctx, db, tr, nil); !errors.Is(err, backup.ErrNotRestorable) {
		t.Fatalf("test run: %v", err)
	}
	if _, err := backup.FindRestoreSource(ctx, db, uuid.New(), nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown run: %v", err)
	}
}
