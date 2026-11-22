package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Warewave-Technology/olympos/internal/testutil"
)

func requireSQLState(t *testing.T, err error, want string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != want {
		t.Fatalf("want SQLSTATE %s, got %v", want, err)
	}
}

// Migration 00022: destination groups, the one-destination-or-group rule on
// jobs, the partial run status and the append-only per-copy results.
func TestDestinationGroupsMigration(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()

	var destA, destB, group string
	if err := db.QueryRow(ctx, `INSERT INTO destinations (name, account, container, auth) VALUES ('a', 'acct', 'c', 'managed_identity') RETURNING id::text`).Scan(&destA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO destinations (name, account, container, auth) VALUES ('b', 'acct', 'c', 'managed_identity') RETURNING id::text`).Scan(&destB); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO destination_groups (name) VALUES ('g') RETURNING id::text`).Scan(&group); err != nil {
		t.Fatal(err)
	}
	for i, d := range []string{destA, destB} {
		if _, err := db.Exec(ctx, `INSERT INTO destination_group_members (group_id, destination_id, position) VALUES ($1, $2, $3)`, group, d, i); err != nil {
			t.Fatal(err)
		}
	}

	// (d) a member must reference an existing destination.
	_, err := db.Exec(ctx, `INSERT INTO destination_group_members (group_id, destination_id, position) VALUES ($1, gen_random_uuid(), 2)`, group)
	requireSQLState(t, err, "23503")

	// (a) a job targets exactly one of destination and group.
	const insJob = `INSERT INTO backup_jobs (system, cron, destination_id, destination_group_id) VALUES ('olympos-self', '0 3 * * *', $1, $2)`
	_, err = db.Exec(ctx, insJob, destA, group)
	requireSQLState(t, err, "23514")
	_, err = db.Exec(ctx, insJob, nil, nil)
	requireSQLState(t, err, "23514")
	var job string
	if err := db.QueryRow(ctx, `INSERT INTO backup_jobs (system, cron, destination_group_id) VALUES ('olympos-self', '0 3 * * *', $1) RETURNING id::text`, group).Scan(&job); err != nil {
		t.Fatalf("group job: %v", err)
	}

	// (b) a partial run, with the destinations it set out to write.
	var run string
	if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, destination_ids) VALUES ($1, 'manual', 'partial', ARRAY[$2, $3]::uuid[]) RETURNING id::text`, job, destA, destB).Scan(&run); err != nil {
		t.Fatalf("partial run: %v", err)
	}
	var repair string
	if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, repair_of) VALUES ($1, 'manual', 'queued', $2) RETURNING id::text`, job, run).Scan(&repair); err != nil {
		t.Fatalf("repair run: %v", err)
	}
	_, err = db.Exec(ctx, `INSERT INTO backup_runs (job_id, trigger, status) VALUES ($1, 'manual', 'bogus')`, job)
	requireSQLState(t, err, "23514")

	// (c) copies are written once.
	if _, err := db.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status, bytes) VALUES ($1, $2, 'succeeded', 10)`, run, destA); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status, error) VALUES ($1, $2, 'failed', 'boom')`, run, destB); err != nil {
		t.Fatalf("copy: %v", err)
	}
	_, err = db.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status) VALUES ($1, $2, 'queued')`, run, destA)
	requireSQLState(t, err, "23514")
	_, err = db.Exec(ctx, `UPDATE backup_run_copies SET bytes = 11 WHERE run_id = $1 AND destination_id = $2`, run, destA)
	requireSQLState(t, err, "42501")
	_, err = db.Exec(ctx, `DELETE FROM backup_run_copies WHERE run_id = $1 AND destination_id = $2`, run, destA)
	requireSQLState(t, err, "42501")

	// Groups follow the updated_at convention.
	var before, after string
	if err := db.QueryRow(ctx, `SELECT updated_at::text FROM destination_groups WHERE id = $1`, group).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE destination_groups SET description = 'x' WHERE id = $1`, group); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT updated_at::text FROM destination_groups WHERE id = $1`, group).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("updated_at not touched")
	}
}
