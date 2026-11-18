package backup_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type runRow struct {
	Status       string
	Trigger      string
	ScheduledFor time.Time
	Error        string
}

func runs(t *testing.T, db *store.DB, job uuid.UUID) []runRow {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT status, trigger, scheduled_for, error FROM backup_runs WHERE job_id = $1 ORDER BY scheduled_for`, job)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []runRow
	for rows.Next() {
		var r runRow
		if err := rows.Scan(&r.Status, &r.Trigger, &r.ScheduledFor, &r.Error); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func lastScheduled(t *testing.T, db *store.DB, job uuid.UUID) *time.Time {
	var ts *time.Time
	if err := db.QueryRow(context.Background(), `SELECT last_scheduled_for FROM backup_jobs WHERE id = $1`, job).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestSchedulerQueuesDueRunsIdempotently(t *testing.T) {
	db := testutil.DB(t)
	f := seed(t, db, "prod", nil, "online")
	now := time.Date(2026, 11, 18, 10, 2, 0, 0, time.UTC)
	ch := addChannel(t, db)
	job := addJob(t, db, f, jobOpts{cron: "*/5 * * * *", enabled: true, last: ptr(now.Add(-6 * time.Minute)), channel: &ch})
	disabled := addJob(t, db, f, jobOpts{cron: "*/5 * * * *", enabled: false, last: ptr(now.Add(-6 * time.Minute))})
	paused := addJob(t, db, f, jobOpts{cron: "*/5 * * * *", enabled: true, last: ptr(now.Add(-6 * time.Minute))})
	if _, err := db.Exec(context.Background(), `UPDATE backup_jobs SET paused_reason = 'target_gone' WHERE id = $1`, paused); err != nil {
		t.Fatal(err)
	}
	s := &backup.Scheduler{DB: db, Log: quietLog(), Now: func() time.Time { return now }}
	ctx := context.Background()
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	rs := runs(t, db, job)
	if len(rs) != 1 || rs[0].Status != "queued" || rs[0].Trigger != "schedule" || !rs[0].ScheduledFor.Equal(time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("runs: %+v", rs)
	}
	if !lastScheduled(t, db, job).Equal(rs[0].ScheduledFor) {
		t.Fatal("last_scheduled_for not advanced")
	}
	if len(runs(t, db, disabled)) != 0 || len(runs(t, db, paused)) != 0 {
		t.Fatal("disabled/paused jobs scheduled")
	}
	// Second tick: nothing new. Rewinding last_scheduled_for (e.g. two
	// replicas racing) must not duplicate the run either.
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE backup_jobs SET last_scheduled_for = $2 WHERE id = $1`, job, now.Add(-6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if rs := runs(t, db, job); len(rs) != 1 {
		t.Fatalf("duplicate runs: %+v", rs)
	}
	if len(events(t, db, "backup.missed")) != 0 {
		t.Fatal("unexpected missed event")
	}

	// A job without last_scheduled_for starts from now (no backfill).
	fresh := addJob(t, db, f, jobOpts{cron: "* * * * *", enabled: true})
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(runs(t, db, fresh)) != 0 || !lastScheduled(t, db, fresh).Equal(now) {
		t.Fatal("fresh job backfilled")
	}
}

func TestSchedulerMissedAfterDowntime(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	f := seed(t, db, "prod", nil, "online")
	ch := addChannel(t, db)
	// Server was down from 06:30 to 10:02; hourly job.
	now := time.Date(2026, 11, 18, 10, 2, 0, 0, time.UTC)
	job := addJob(t, db, f, jobOpts{cron: "0 * * * *", enabled: true, last: ptr(time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)), channel: &ch})
	s := &backup.Scheduler{DB: db, Log: quietLog(), Now: func() time.Time { return now }}
	if err := s.Tick(ctx); err != nil { // first loop after startup
		t.Fatal(err)
	}
	rs := runs(t, db, job)
	if len(rs) != 4 {
		t.Fatalf("runs: %+v", rs)
	}
	for i, r := range rs[:3] {
		if r.Status != "missed" || r.ScheduledFor.UTC().Hour() != 7+i || r.Error == "" {
			t.Fatalf("run %d: %+v", i, r)
		}
	}
	if rs[3].Status != "queued" || rs[3].ScheduledFor.UTC().Hour() != 10 {
		t.Fatalf("latest run (within grace) should be queued: %+v", rs[3])
	}
	ev := events(t, db, "backup.missed")
	if len(ev) != 1 || ev[0].Channel == nil || *ev[0].Channel != ch || ev[0].Payload["missed"].(float64) != 3 {
		t.Fatalf("missed events: %+v", ev)
	}
	// Missed rows are finished, i.e. frozen.
	if _, err := db.Exec(ctx, `UPDATE backup_runs SET error = 'x' WHERE job_id = $1 AND status = 'missed'`, job); err == nil {
		t.Fatal("missed run is mutable")
	}

	// The queued 10:00 run is still waiting at 11:00 (agent never connected):
	// it is superseded and recorded as missed.
	now = time.Date(2026, 11, 18, 11, 0, 30, 0, time.UTC)
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	rs = runs(t, db, job)
	if len(rs) != 5 || rs[3].Status != "missed" || rs[4].Status != "queued" {
		t.Fatalf("superseded: %+v", rs)
	}
	if len(events(t, db, "backup.missed")) != 2 {
		t.Fatal("expected a second missed event")
	}

	// Long downtime past the grace window: even the latest activation is missed.
	now = time.Date(2026, 11, 18, 14, 30, 0, 0, time.UTC)
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	rs = runs(t, db, job)
	for _, r := range rs[5:] {
		if r.Status != "missed" {
			t.Fatalf("late activation queued: %+v", rs)
		}
	}
	if len(rs) != 8 {
		t.Fatalf("runs after long downtime: %d", len(rs))
	}
}

func TestSchedulerTimezone(t *testing.T) {
	db := testutil.DB(t)
	f := seed(t, db, "prod", nil, "online")
	// 02:00 Europe/Istanbul (UTC+3) = 23:00 UTC the day before.
	now := time.Date(2026, 11, 17, 23, 1, 0, 0, time.UTC)
	job := addJob(t, db, f, jobOpts{cron: "0 2 * * *", tz: "Europe/Istanbul", enabled: true, last: ptr(time.Date(2026, 11, 17, 20, 0, 0, 0, time.UTC))})
	s := &backup.Scheduler{DB: db, Log: quietLog(), Now: func() time.Time { return now }}
	if err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	rs := runs(t, db, job)
	if len(rs) != 1 || rs[0].Status != "queued" || !rs[0].ScheduledFor.Equal(time.Date(2026, 11, 17, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("runs: %+v", rs)
	}
}

func TestDeadMansSwitch(t *testing.T) {
	db := testutil.DB(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Get("token") == "dms-secret-token" {
			hits.Add(1)
		}
	}))
	defer srv.Close()
	s := &backup.Scheduler{DB: db, Log: quietLog(), Interval: 50 * time.Millisecond, DeadMansSwitchURL: srv.URL + "/ping?token=dms-secret-token"}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	if hits.Load() < 2 {
		t.Fatalf("dead man's switch hits: %d", hits.Load())
	}

	// Failures are logged without the URL (token).
	var buf bytes.Buffer
	dead := httptest.NewServer(http.NotFoundHandler())
	u := dead.URL
	dead.Close()
	s2 := &backup.Scheduler{DB: db, Log: slog.New(slog.NewTextHandler(&buf, nil)), DeadMansSwitchURL: u + "/ping?token=dms-secret-token"}
	s2.Ping(context.Background())
	if !strings.Contains(buf.String(), "dead man's switch ping failed") || strings.Contains(buf.String(), "dms-secret-token") {
		t.Fatalf("log: %s", buf.String())
	}
}

func TestSchedulerSingleLeader(t *testing.T) {
	db := testutil.DB(t)
	var a, b atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			a.Add(1)
		case "/b":
			b.Add(1)
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	done := make(chan struct{}, 2)
	for _, p := range []string{"/a", "/b"} {
		s := &backup.Scheduler{DB: db, Log: quietLog(), Interval: 50 * time.Millisecond, DeadMansSwitchURL: srv.URL + p}
		go func() { s.Run(ctx); done <- struct{}{} }()
	}
	<-done
	<-done
	if (a.Load() > 0) == (b.Load() > 0) {
		t.Fatalf("expected exactly one leader: a=%d b=%d", a.Load(), b.Load())
	}
}
