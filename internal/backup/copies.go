package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// errNothingToRepair fails a repair run whose missing destinations the job
// no longer writes to.
const errNothingToRepair = "nothing left to repair: the missing destinations are no longer used by this job"

// destRef is one destination a run writes to.
type destRef struct {
	ID   uuid.UUID
	Name string
	Kind string
}

// copyResult is how the copy on one destination ended; it becomes a
// backup_run_copies row. Failed copies carry only the error and times.
type copyResult struct {
	DestinationID uuid.UUID
	Name          string
	Status        string // succeeded | failed
	BlobPath      string
	Bytes         int64
	SHA256        string
	Tier          string
	Err           string // already scrubbed
	StartedAt     time.Time
	FinishedAt    time.Time
}

// runDestinations resolves the destinations a run writes to and fixes them
// in backup_runs.destination_ids: the ones already set on the run, else the
// job's destination or its group's members in position order. A repair run
// keeps only those the job still writes to (it may end up with none).
func runDestinations(ctx context.Context, q store.Querier, runID uuid.UUID) ([]destRef, error) {
	var jobID uuid.UUID
	var ids []uuid.UUID
	var repairOf *uuid.UUID
	if err := q.QueryRow(ctx, `SELECT job_id, destination_ids, repair_of FROM backup_runs WHERE id = $1`, runID).
		Scan(&jobID, &ids, &repairOf); err != nil {
		return nil, err
	}
	var out []destRef
	var err error
	switch {
	case repairOf != nil:
		var current []destRef
		current, err = scanDestRefs(q.Query(ctx, `SELECT d.id, d.name, d.kind FROM backup_jobs j
			LEFT JOIN destination_group_members m ON m.group_id = j.destination_group_id
			JOIN destinations d ON d.id = COALESCE(j.destination_id, m.destination_id) WHERE j.id = $1`, jobID))
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			for _, d := range current {
				if d.ID == id {
					out = append(out, d)
				}
			}
		}
	case len(ids) > 0:
		out, err = scanDestRefs(q.Query(ctx, `SELECT d.id, d.name, d.kind FROM unnest($1::uuid[]) WITH ORDINALITY u(id, ord)
			JOIN destinations d ON d.id = u.id ORDER BY u.ord`, ids))
	default:
		out, err = scanDestRefs(q.Query(ctx, `SELECT d.id, d.name, d.kind FROM backup_jobs j
			LEFT JOIN destination_group_members m ON m.group_id = j.destination_group_id
			JOIN destinations d ON d.id = COALESCE(j.destination_id, m.destination_id) WHERE j.id = $1 ORDER BY m.position`, jobID))
	}
	if err != nil {
		return nil, err
	}
	fixed := make([]uuid.UUID, len(out))
	for i, d := range out {
		fixed[i] = d.ID
	}
	if _, err := q.Exec(ctx, `UPDATE backup_runs SET destination_ids = $2 WHERE id = $1 AND finished_at IS NULL`, runID, fixed); err != nil {
		return nil, err
	}
	return out, nil
}

func scanDestRefs(rows pgx.Rows, err error) ([]destRef, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []destRef
	for rows.Next() {
		var d destRef
		if err := rows.Scan(&d.ID, &d.Name, &d.Kind); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// groupMembers returns the names of a group's members in position order.
func groupMembers(ctx context.Context, q store.Querier, groupID uuid.UUID) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT d.name FROM destination_group_members m JOIN destinations d ON d.id = m.destination_id
		WHERE m.group_id = $1 ORDER BY m.position`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// TierForDestination is TierFor for the copy on one destination: it counts
// this job's scheduled runs (other than runID) with a succeeded copy on
// destID, plus succeeded scheduled runs without copy rows (from before
// destination groups), which count for every destination.
func TierForDestination(ctx context.Context, q store.Querier, jobID, runID, destID uuid.UUID, ref time.Time, loc *time.Location) (string, error) {
	return gfsTier(ref, loc, func(from, to time.Time) (int, error) {
		var n int
		err := q.QueryRow(ctx, `SELECT count(*) FROM backup_runs r WHERE r.job_id = $1 AND r.id <> $2 AND r.trigger = 'schedule'
			AND COALESCE(r.scheduled_for, r.started_at) >= $4 AND COALESCE(r.scheduled_for, r.started_at) < $5
			AND (EXISTS (SELECT 1 FROM backup_run_copies c WHERE c.run_id = r.id AND c.destination_id = $3 AND c.status = 'succeeded')
				OR r.status = 'succeeded' AND NOT EXISTS (SELECT 1 FROM backup_run_copies c WHERE c.run_id = r.id))`,
			jobID, runID, destID, from, to).Scan(&n)
		return n, err
	})
}

// runStatus derives a run's status from the engine and its copies.
func runStatus(engineErr error, copies []copyResult) string {
	if engineErr != nil || len(copies) == 0 {
		return "failed"
	}
	ok := 0
	for _, c := range copies {
		if c.Status == "succeeded" {
			ok++
		}
	}
	switch ok {
	case len(copies):
		return "succeeded"
	case 0:
		return "failed"
	}
	return "partial"
}

// copiesError is the run error for a partial run: each failed copy as
// "<destination>: <error>".
func copiesError(copies []copyResult) string {
	var parts []string
	for _, c := range copies {
		if c.Status != "succeeded" {
			parts = append(parts, c.Name+": "+c.Err)
		}
	}
	return strings.Join(parts, "; ")
}

// lockedWriter hashes and counts what the fan-out accepted. It serialises
// writes, since FanOut.Write must not be called concurrently.
type lockedWriter struct {
	mu        sync.Mutex
	fo        *FanOut
	ch        *countingHash
	allFailed bool
	cancel    context.CancelFunc
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.fo.Write(p)
	_, _ = l.ch.Write(p[:n])
	if err != nil {
		// No destination is left: stop the engine.
		l.allFailed = true
		l.cancel()
	}
	return n, err
}

// streamCopies runs the engine once and streams its output to every
// destination in dests, then writes each successful copy's manifest next to
// its blob. A destination that cannot be opened, or whose upload or
// manifest fails, is a failed copy; the others carry on. path builds the
// blob path from a destination's prefix, tiers holds each destination's tier
// (its tag), manifest builds a copy's manifest (streamCopies fills in what
// the engine reported) and scrub cleans error messages.
//
// streamed is how many bytes the fan-out accepted (the run's size when no
// copy succeeded). engErr is the engine's own error; it is nil when the engine failed only
// because every upload had failed (the copies then hold the root cause).
// When the engine failed before any data reached the uploads there are no
// copies.
func streamCopies(ctx context.Context, eng Engine, ec EngineContext, dests []destRef,
	open func(context.Context, uuid.UUID) (blob.Writer, error), path func(prefix string) string,
	tiers map[uuid.UUID]string, manifest func(destRef, ManifestBlob, string) Manifest,
	scrub func(string) string) (rr *RunResult, copies []copyResult, streamed int64, engErr error) {
	started := time.Now().UTC()
	type opened struct {
		i    int
		w    blob.Writer
		path string
		tags map[string]string
	}
	var live []opened
	var branches []Branch
	copies = make([]copyResult, len(dests))
	for i, d := range dests {
		copies[i] = copyResult{DestinationID: d.ID, Name: d.Name, Status: "failed", StartedAt: started}
		w, err := open(ctx, d.ID)
		if err != nil {
			copies[i].Err, copies[i].FinishedAt = scrub("open destination: "+err.Error()), time.Now().UTC()
			continue
		}
		o := opened{i: i, w: w, path: path(w.Prefix()), tags: map[string]string{TierTag: tiers[d.ID]}}
		live = append(live, o)
		branches = append(branches, Branch{Name: d.Name, Upload: func(ctx context.Context, r io.Reader) error {
			_, err := o.w.Upload(ctx, o.path, r, eng.ContentType(), o.tags)
			return err
		}})
	}
	if len(live) == 0 {
		return nil, copies, 0, nil
	}

	ectx, cancel := context.WithCancel(ctx)
	defer cancel()
	lw := &lockedWriter{fo: NewFanOut(ctx, branches, 0), ch: &countingHash{h: sha256.New()}, cancel: cancel}
	rr, runErr := eng.Run(ectx, ec, lw)
	results := lw.fo.Close(runErr)
	lw.mu.Lock()
	allFailed, total, sum := lw.allFailed, lw.ch.n, hex.EncodeToString(lw.ch.h.Sum(nil))
	lw.mu.Unlock()
	if runErr != nil && !allFailed {
		engErr = runErr
		if total == 0 {
			return rr, nil, total, engErr
		}
	}
	if rr == nil {
		rr = &RunResult{}
	}
	for j, res := range results {
		o := live[j]
		c := &copies[o.i]
		if res.Err != nil {
			if engErr != nil && errors.Is(res.Err, engErr) {
				c.Err = scrub(engErr.Error())
			} else {
				c.Err = scrub("upload: " + res.Err.Error())
			}
			c.FinishedAt = time.Now().UTC()
			continue
		}
		tier := tiers[dests[o.i].ID]
		m := manifest(dests[o.i], ManifestBlob{Path: o.path, ContentType: eng.ContentType(), Ext: eng.Ext(), Size: total, SHA256: sum}, tier)
		m.TLS, m.ServerVersion, m.ToolVersion = rr.TLS, rr.ServerVersion, rr.ToolVersion
		if m.Details == nil {
			m.Details = rr.Details
		} else {
			for k, v := range rr.Details {
				m.Details[k] = v
			}
		}
		mb, err := json.MarshalIndent(m, "", "  ")
		if err == nil {
			_, err = o.w.Upload(ctx, ManifestPath(o.path, m.RunID), bytes.NewReader(mb), "application/json", o.tags)
			if err != nil {
				err = errors.New(scrub("upload manifest: " + err.Error()))
			}
		} else {
			err = errors.New("encode manifest: " + err.Error())
		}
		c.FinishedAt = time.Now().UTC()
		if err != nil {
			c.Err = err.Error()
			continue
		}
		c.Status, c.BlobPath, c.Bytes, c.SHA256, c.Tier = "succeeded", o.path, total, sum, tier
	}
	return rr, copies, total, engErr
}
