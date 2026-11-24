//go:build dev

package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/inventory"
)

// A partial run is a warning until a repair of it succeeds; a repair that
// failed is shown as its original run (the backup exists, incomplete).
func TestAttentionBackupPartial(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	ctx := context.Background()
	db := e.DB
	admin := e.Login(e.Principal("admin", "Member", "admin"))
	q := func(dst any, sql string, args ...any) {
		t.Helper()
		var err error
		if dst == nil {
			_, err = db.Exec(ctx, sql, args...)
		} else {
			err = db.QueryRow(ctx, sql, args...).Scan(dst)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	var cluster, d1, d2, group uuid.UUID
	q(&cluster, `INSERT INTO clusters (name, status, last_seen_at) VALUES ('prod', 'online', now()) RETURNING id`)
	q(&d1, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('primary', 'a', 'c', 'p', 'managed_identity') RETURNING id`)
	q(&d2, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('offsite', 'a', 'c2', 'p', 'managed_identity') RETURNING id`)
	q(&group, `INSERT INTO destination_groups (name) VALUES ('pair') RETURNING id`)
	q(nil, `INSERT INTO destination_group_members (group_id, destination_id, position) VALUES ($1, $2, 0), ($1, $3, 1)`, group, d1, d2)
	job := func(svc string) uuid.UUID {
		t.Helper()
		tid := "t-" + svc
		q(nil, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine) VALUES ($1, $2, 'db', $3, 5432, 'postgresql')`, tid, cluster, svc)
		var id uuid.UUID
		q(&id, `INSERT INTO backup_jobs (target_id, destination_group_id, cron) VALUES ($1, $2, '0 2 * * *') RETURNING id`, tid, group)
		return id
	}
	run := func(job uuid.UUID, status string, ago time.Duration, repairOf *uuid.UUID, ok ...uuid.UUID) uuid.UUID {
		t.Helper()
		at := time.Now().Add(-ago)
		dests := []uuid.UUID{d1, d2}
		if repairOf != nil {
			dests = []uuid.UUID{d2}
		}
		var id uuid.UUID
		q(&id, `INSERT INTO backup_runs (job_id, trigger, status, created_at, started_at, finished_at, repair_of, destination_ids, error)
			VALUES ($1, 'schedule', $2, $3, $3, $3, $4, $5, CASE WHEN $2 = 'failed' THEN 'offsite: upload: 503' ELSE '' END) RETURNING id`,
			job, status, at, repairOf, dests)
		for _, d := range dests {
			st := "failed"
			for _, o := range ok {
				if o == d {
					st = "succeeded"
				}
			}
			q(nil, `INSERT INTO backup_run_copies (run_id, destination_id, status) VALUES ($1, $2, $3)`, id, d, st)
		}
		return id
	}
	plain := job("plain")
	run(plain, "partial", time.Hour, nil, d1)
	repaired := job("repaired")
	r := run(repaired, "partial", time.Hour, nil, d1)
	run(repaired, "succeeded", 30*time.Minute, &r, d2)
	gaveUp := job("gaveup")
	r = run(gaveUp, "partial", time.Hour, nil, d1)
	run(gaveUp, "failed", 40*time.Minute, &r)
	run(gaveUp, "failed", 20*time.Minute, &r)
	newer := job("newer") // a later plain run replaces the partial one
	run(newer, "partial", 3*time.Hour, nil, d1)
	run(newer, "succeeded", time.Hour, nil, d1, d2)

	var self uuid.UUID
	q(&self, `INSERT INTO backup_jobs (system, destination_group_id, cron) VALUES ('olympos-self', $1, '30 2 * * *') RETURNING id`, group)
	run(self, "partial", time.Hour, nil, d1)

	var d inventory.Dashboard
	if code := admin.Do("GET", "/api/v1/dashboard", nil, &d); code != 200 {
		t.Fatal(code)
	}
	got := map[string]inventory.AttentionItem{}
	for _, a := range d.Attention {
		switch a.Kind {
		case "backup_partial", "backup_failed", "self_backup_partial", "self_backup_failed":
			got[a.Kind+":"+a.Detail] = a
		}
	}
	want := map[string]inventory.AttentionItem{
		"backup_partial:plain · missing offsite":  {Kind: "backup_partial", Severity: "warn", Label: "Backup incomplete", Detail: "plain · missing offsite", Link: "/backups?job=" + plain.String()},
		"backup_partial:gaveup · missing offsite": {Kind: "backup_partial", Severity: "warn", Label: "Backup incomplete", Detail: "gaveup · missing offsite", Link: "/backups?job=" + gaveUp.String()},
		"self_backup_partial:missing offsite": {Kind: "self_backup_partial", Severity: "warn", Label: "Olympos backup incomplete", Detail: "missing offsite",
			Link: "/backups?self=1"},
	}
	if len(got) != len(want) {
		t.Fatalf("attention: %+v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v, want %+v", k, got[k], w)
		}
	}
}

// A missing copy on a destination the job no longer writes to is not
// "missing" any more (no repair will write it): the item names only the
// current destinations without a copy, and goes away when none is left.
func TestAttentionBackupPartialRemovedMember(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	ctx := context.Background()
	db := e.DB
	admin := e.Login(e.Principal("admin", "Member", "admin"))
	q := func(dst any, sql string, args ...any) {
		t.Helper()
		var err error
		if dst == nil {
			_, err = db.Exec(ctx, sql, args...)
		} else {
			err = db.QueryRow(ctx, sql, args...).Scan(dst)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	var cluster, d1, d2, d3, trio uuid.UUID
	q(&cluster, `INSERT INTO clusters (name, status, last_seen_at) VALUES ('prod', 'online', now()) RETURNING id`)
	q(&d1, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('primary', 'a', 'c', 'p', 'managed_identity') RETURNING id`)
	q(&d2, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('offsite', 'a', 'c2', 'p', 'managed_identity') RETURNING id`)
	q(&d3, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('nas', 'a', 'c3', 'p', 'managed_identity') RETURNING id`)
	q(&trio, `INSERT INTO destination_groups (name) VALUES ('trio') RETURNING id`)
	q(nil, `INSERT INTO destination_group_members (group_id, destination_id, position) VALUES ($1, $2, 0), ($1, $3, 1), ($1, $4, 2)`, trio, d1, d2, d3)
	job := func(svc string) uuid.UUID {
		t.Helper()
		tid := "t-" + svc
		q(nil, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine) VALUES ($1, $2, 'db', $3, 5432, 'postgresql')`, tid, cluster, svc)
		var id uuid.UUID
		q(&id, `INSERT INTO backup_jobs (target_id, destination_group_id, cron) VALUES ($1, $2, '0 2 * * *') RETURNING id`, tid, trio)
		return id
	}
	partial := func(job uuid.UUID) {
		t.Helper()
		var id uuid.UUID
		q(&id, `INSERT INTO backup_runs (job_id, trigger, status, created_at, started_at, finished_at, destination_ids)
			VALUES ($1, 'schedule', 'partial', now() - interval '1 hour', now() - interval '1 hour', now() - interval '1 hour', $2) RETURNING id`,
			job, []uuid.UUID{d1, d2, d3})
		q(nil, `INSERT INTO backup_run_copies (run_id, destination_id, status) VALUES ($1, $2, 'succeeded'), ($1, $3, 'failed'), ($1, $4, 'failed')`, id, d1, d2, d3)
	}
	shrunk := job("shrunk") // nas left the group: only offsite is missing
	partial(shrunk)
	moved := job("moved") // the job now writes to primary only: nothing is missing
	partial(moved)
	q(nil, `DELETE FROM destination_group_members WHERE group_id = $1 AND destination_id = $2`, trio, d3)
	q(nil, `UPDATE backup_jobs SET destination_group_id = NULL, destination_id = $2 WHERE id = $1`, moved, d1)

	var d inventory.Dashboard
	if code := admin.Do("GET", "/api/v1/dashboard", nil, &d); code != 200 {
		t.Fatal(code)
	}
	var got []string
	for _, a := range d.Attention {
		if a.Kind == "backup_partial" {
			got = append(got, a.Detail)
		}
	}
	if len(got) != 1 || got[0] != "shrunk · missing offsite" {
		t.Fatalf("backup_partial items: %q", got)
	}
}

// Another module adds items through the hook; a failing hook fails the
// dashboard, as every other source of items does.
func TestAttentionMoreHook(t *testing.T) {
	var hookErr error
	var seen []string
	e := apitest.New(t, apitest.Options{Inventory: func(a *inventory.API) {
		a.MoreAttention = func(_ context.Context, s *authz.Subject) ([]inventory.AttentionItem, error) {
			seen = append(seen, s.Principal.DisplayName)
			if hookErr != nil {
				return nil, hookErr
			}
			return []inventory.AttentionItem{{Kind: "more", Severity: "warn", Label: "More", Detail: "from the hook", Link: "/more"}}, nil
		}
	}})
	admin := e.Login(e.Principal("admin", "Member", "admin"))
	var d inventory.Dashboard
	if code := admin.Do("GET", "/api/v1/dashboard", nil, &d); code != 200 {
		t.Fatal(code)
	}
	var more []inventory.AttentionItem
	for _, a := range d.Attention {
		if a.Kind == "more" {
			more = append(more, a)
		}
	}
	if len(more) != 1 || more[0] != (inventory.AttentionItem{Kind: "more", Severity: "warn", Label: "More", Detail: "from the hook", Link: "/more"}) ||
		len(seen) != 1 || seen[0] != "admin" {
		t.Fatalf("attention %+v, hook called for %v", d.Attention, seen)
	}
	hookErr = errors.New("hook failed")
	if code := admin.Do("GET", "/api/v1/dashboard", nil, nil); code != 500 {
		t.Fatalf("a failing hook: %d", code)
	}
}
