package synthetic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// runTimeoutSQL is a run's timeout in seconds: the test spec's for a test
// run, else the scenario's, from 1 to spec.MaxRunTimeout. r is
// synthetic_runs, s the scenario (LEFT JOIN).
// The clamp is done in numeric, so that no value of the JSON can overflow
// the cast, and matches the Go side (send): from 1 to MaxRunTimeout.
var runTimeoutSQL = fmt.Sprintf(`GREATEST(LEAST(COALESCE(
	CASE WHEN jsonb_typeof(r.test_spec->'timeout_seconds') = 'number' THEN (r.test_spec->>'timeout_seconds')::numeric END,
	s.timeout_seconds::numeric, %[1]d), %[1]d), 1)::int`, int(spec.MaxRunTimeout/time.Second))

// Dispatch is one pass of this replica's dispatcher:
//
//  1. due runs of clusters whose probe is not online end skipped
//     (probe_offline): no failure for an offline probe;
//  2. scheduled runs that no replica sent within the scenario's interval
//     end skipped (not_dispatched), so that the scheduler plans the next;
//     due runs of disabled scenarios end skipped (scenario_disabled);
//  3. runs this replica sent end skipped (probe_disconnected) when their
//     stream is gone, skipped (ingest_failed) when their result came but
//     could not be stored, or error (no_result) when the stream is open but
//     the result is ResultGrace past the run's timeout; running runs that no
//     live replica tracks end skipped (probe_disconnected) OrphanGrace
//     later;
//  4. due runs of the probes connected here are claimed (FOR UPDATE SKIP
//     LOCKED, up to the stream's free room), marked running, and sent once
//     each, with the allowlist and the scenario's credentials sealed to the
//     stream's key. Only streams of the cluster's current probe
//     certificate count: one that connected before a renewal gets nothing. An expired or invalid credential ends the run as an
//     error; one that cannot be resolved ends it as an error
//     (credential_broken) when retrying cannot help, and skips it
//     (credential_unavailable) when it can. Either way the credential's
//     state is recorded and alerts once (recordCredentialFailure).
//
// It returns how many runs it sent.
func (s *Service) Dispatch(ctx context.Context) (int, error) {
	now := s.now()
	var errs []error
	if err := s.finishWhere(ctx, StatusSkipped, ReasonProbeOffline, `SELECT r.id, r.cluster_id FROM synthetic_runs r
		JOIN clusters c ON c.id = r.cluster_id
		WHERE r.status = 'scheduled' AND r.scheduled_for <= $1 AND c.probe_status <> 'online'
		FOR UPDATE OF r SKIP LOCKED`, now); err != nil {
		errs = append(errs, fmt.Errorf("skip runs of offline probes: %w", err))
	}
	if err := s.finishWhere(ctx, StatusSkipped, ReasonNotDispatched, `SELECT r.id, r.cluster_id FROM synthetic_runs r
		LEFT JOIN scenarios s ON s.id = r.scenario_id
		WHERE r.status = 'scheduled'
		  AND r.scheduled_for + make_interval(secs => CASE WHEN r.test THEN $2 ELSE COALESCE(s.interval_seconds, $2) END) < $1
		FOR UPDATE OF r SKIP LOCKED`, now, int(defaultTestInterval.Seconds())); err != nil {
		errs = append(errs, fmt.Errorf("skip undispatched runs: %w", err))
	}
	if err := s.finishWhere(ctx, StatusSkipped, ReasonScenarioDisabled, `SELECT r.id, r.cluster_id FROM synthetic_runs r
		JOIN scenarios s ON s.id = r.scenario_id
		WHERE r.status = 'scheduled' AND r.scheduled_for <= $1 AND NOT r.test AND NOT s.enabled
		FOR UPDATE OF r SKIP LOCKED`, now); err != nil {
		errs = append(errs, fmt.Errorf("skip runs of disabled scenarios: %w", err))
	}
	if err := s.reap(ctx, now); err != nil {
		errs = append(errs, err)
	}

	clusters, err := s.dueClusters(ctx, now)
	if err != nil {
		return 0, errors.Join(append(errs, err)...)
	}
	sent := 0
	var snap *pb.AllowlistSnapshot
	for _, due := range clusters {
		cl := due.id
		info, ok := s.Probes.ProbeStream(cl, due.serial)
		if !ok {
			continue
		}
		room := min(info.MaxConcurrency, MaxClaim) - info.InFlight
		if room <= 0 {
			continue
		}
		if snap == nil {
			var dropped int
			if snap, dropped, err = loadAllowlist(ctx, s.DB); err != nil {
				return sent, errors.Join(append(errs, fmt.Errorf("load allowlist: %w", err))...)
			}
			if dropped > 0 {
				s.Log.Warn("allowlist rules that do not validate are not sent to probes", "rules", dropped)
			}
		}
		ids, err := s.claim(ctx, cl, room, now, snap.Version)
		if err != nil {
			errs = append(errs, fmt.Errorf("claim runs of cluster %s: %w", cl, err))
			continue
		}
		for _, id := range ids {
			ok, err := s.send(ctx, cl, due.serial, id, snap)
			if err != nil {
				errs = append(errs, fmt.Errorf("send run %s: %w", id, err))
			}
			if ok {
				sent++
			}
		}
	}
	return sent, errors.Join(errs...)
}

// dueCluster is a cluster with an online probe and a due run, with the
// serial of its current probe certificate.
type dueCluster struct {
	id     uuid.UUID
	serial string
}

// dueClusters lists the clusters with an online probe and a due run.
func (s *Service) dueClusters(ctx context.Context, now time.Time) ([]dueCluster, error) {
	rows, err := s.DB.Query(ctx, `SELECT c.id, c.probe_cert_serial FROM clusters c
		WHERE c.probe_status = 'online' AND c.probe_cert_serial <> ''
		  AND EXISTS (SELECT 1 FROM synthetic_runs r WHERE r.cluster_id = c.id AND r.status = 'scheduled' AND r.scheduled_for <= $1)`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (dueCluster, error) {
		var d dueCluster
		return d, r.Scan(&d.id, &d.serial)
	})
}

// claim marks up to n due runs of clusterID running, oldest first. A run
// another replica holds is skipped, not waited for.
func (s *Service) claim(ctx context.Context, clusterID uuid.UUID, n int, now time.Time, allowVersion int64) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.id FROM synthetic_runs r JOIN clusters c ON c.id = r.cluster_id
			LEFT JOIN scenarios s ON s.id = r.scenario_id
			WHERE r.cluster_id = $1 AND r.status = 'scheduled' AND r.scheduled_for <= $2 AND c.probe_status = 'online'
			  AND (r.test OR s.enabled IS NOT false)
			ORDER BY r.scheduled_for, r.id LIMIT $3 FOR UPDATE OF r SKIP LOCKED`, clusterID, now, n)
		if err != nil {
			return err
		}
		if ids, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil || len(ids) == 0 {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE synthetic_runs SET status = 'running', started_at = $2, allowlist_version = $3
			WHERE id = ANY($1)`, ids, now, allowVersion)
		return err
	})
	return ids, err
}

// send sends one claimed run. It reports whether the run went out. A run
// that never left goes back to scheduled; one that may have left is never
// sent again (the probe ignores a run id it has seen): it ends skipped.
func (s *Service) send(ctx context.Context, clusterID uuid.UUID, certSerial string, runID uuid.UUID, snap *pb.AllowlistSnapshot) (bool, error) {
	var scenarioID *uuid.UUID
	var testSpec []byte
	var test bool
	if err := s.DB.QueryRow(ctx, `SELECT scenario_id, test_spec, test FROM synthetic_runs WHERE id = $1`, runID).
		Scan(&scenarioID, &testSpec, &test); err != nil {
		// The run was claimed: end it now rather than leave it to the
		// orphan rule.
		return false, errors.Join(err, s.finishOne(ctx, runID, clusterID, StatusError, ReasonDispatchError))
	}
	sc, err := runScenario(ctx, s.DB, scenarioID, testSpec)
	if err != nil {
		s.Log.Warn("synthetic run has no usable scenario", "run_id", runID, "err", err)
		return false, s.finishOne(ctx, runID, clusterID, StatusError, ReasonInvalidScenario)
	}
	body, err := json.Marshal(sc)
	if err != nil {
		return false, s.finishOne(ctx, runID, clusterID, StatusError, ReasonInvalidScenario)
	}
	credIDs := CredentialIDs(sc)
	timeout := time.Duration(min(max(sc.TimeoutSeconds, 1), int(spec.MaxRunTimeout/time.Second))) * time.Second

	built := false
	var credErr error
	var resolved []resolvedCred
	info, err := s.Probes.SendRun(clusterID, certSerial, func(info gateway.ProbeInfo) (*pb.RunScenario, error) {
		built = true
		msg := &pb.RunScenario{RunId: runID.String(), ScenarioJson: body, Allowlist: snap, Test: test}
		if len(credIDs) > 0 {
			var sealed *pb.SealedCredentials
			var err error
			sealed, resolved, err = s.seal(ctx, info.PublicKey, runID, clusterID, credIDs)
			if err != nil {
				credErr = err
				return nil, err
			}
			msg.Credentials = sealed
		}
		// Tracked before the run goes out: its result may come before
		// SendRun returns.
		s.track(runID, &sentRun{cluster: clusterID, session: info.SessionID, deadline: s.now().Add(timeout + ResultGrace)})
		return msg, nil
	})
	// An editor test run only tells the person testing (credential_broken in
	// the result): it never records state, so it never alerts.
	if !test {
		s.recordCredentials(ctx, runID, resolved, credErr)
	}
	switch {
	case err == nil:
		s.Log.Debug("synthetic run sent", "run_id", runID, "cluster_id", clusterID, "session", info.SessionID)
		return true, nil
	case credErr != nil:
		status, reason := credentialReason(credErr)
		// A resolution failure is logged by its cause: Key Vault's own
		// text may carry its response. Per run at DEBUG: the credential's
		// state changes are the WARN lines (recordCredentialFailure).
		var f *credentialFailure
		if errors.As(credErr, &f) {
			cause, _ := resolveCause(f.Err)
			s.Log.Debug("synthetic run credentials", "run_id", runID, "cluster_id", clusterID, "reason", reason,
				"synthetic_cred", f.ID, "cause", cause)
		} else {
			s.Log.Warn("synthetic run credentials", "run_id", runID, "cluster_id", clusterID, "reason", reason, "err", credErr)
		}
		return false, s.finishOne(ctx, runID, clusterID, status, reason)
	case !built:
		// No stream of the current certificate was free (ErrProbeBusy,
		// or the stream went away or was renewed): the run never left.
		_, uerr := s.DB.Exec(ctx, `UPDATE synthetic_runs SET status = 'scheduled', started_at = NULL WHERE id = $1 AND status = 'running'`, runID)
		return false, uerr
	default:
		// Sending failed: the stream is gone, and the run may have reached
		// it all the same.
		s.untrack(runID)
		return false, s.finishOne(ctx, runID, clusterID, StatusSkipped, ReasonProbeDisconnected)
	}
}

// seal resolves the credentials and seals them to the stream's key for this
// run on this cluster, and returns the credentials that resolved (see
// runCredentials). Every plaintext copy is zeroed before it returns.
func (s *Service) seal(ctx context.Context, pub []byte, runID, clusterID uuid.UUID, ids []uuid.UUID) (*pb.SealedCredentials, []resolvedCred, error) {
	creds, resolved, err := runCredentials(ctx, s.DB, s.Creds, ids, s.now())
	defer spec.ZeroCredentials(creds)
	if err != nil {
		return nil, resolved, err
	}
	enc, ct, err := spec.SealCredentials(pub, runID.String(), clusterID.String(), creds)
	if err != nil {
		return nil, resolved, err
	}
	return &pb.SealedCredentials{Enc: enc, Ciphertext: ct}, resolved, nil
}

// recordCredentials records on each credential what resolving a run's
// credentials found: those in resolved are ok, the one err names is not.
// A failure to record is logged and does not change how the run ends.
func (s *Service) recordCredentials(ctx context.Context, runID uuid.UUID, resolved []resolvedCred, err error) {
	if rerr := s.recordCredentialOK(ctx, resolved); rerr != nil {
		s.Log.Warn("record synthetic credential state", "run_id", runID, "err", rerr)
	}
	var f *credentialFailure
	if !errors.As(err, &f) {
		return
	}
	cause, permanent := resolveCause(f.Err)
	if rerr := s.recordCredentialFailure(ctx, f.ID, f.Backing, cause, permanent); rerr != nil {
		s.Log.Warn("record synthetic credential state", "run_id", runID, "synthetic_cred", f.ID, "cause", cause, "err", rerr)
	}
}

func (s *Service) track(runID uuid.UUID, r *sentRun) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sent == nil {
		s.sent = map[uuid.UUID]*sentRun{}
	}
	s.sent[runID] = r
}

func (s *Service) untrack(runID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sent, runID)
}

// release frees the stream slot of a run whose answer came from clusterID,
// once. A run of another cluster is left alone.
func (s *Service) release(runID, clusterID uuid.UUID) {
	s.mu.Lock()
	r := s.sent[runID]
	if r == nil || r.cluster != clusterID || r.released {
		s.mu.Unlock()
		return
	}
	r.released = true
	s.mu.Unlock()
	s.Probes.RunDone(r.cluster, r.session)
}

// lose records that the result of a run of clusterID came but could not be
// stored. A run this replica did not send is left alone: its own replica
// ends it.
func (s *Service) lose(runID, clusterID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.sent[runID]; r != nil && r.cluster == clusterID {
		r.lost = true
	}
}

// forget drops a finished run: its slot is freed if it was not yet.
func (s *Service) forget(runID uuid.UUID) {
	s.mu.Lock()
	r := s.sent[runID]
	delete(s.sent, runID)
	s.mu.Unlock()
	if r != nil && !r.released {
		s.Probes.RunDone(r.cluster, r.session)
	}
}

// reap ends the running runs whose result will not come (step 3 of
// Dispatch).
func (s *Service) reap(ctx context.Context, now time.Time) error {
	type item struct {
		id uuid.UUID
		r  sentRun
	}
	s.mu.Lock()
	mine := make([]uuid.UUID, 0, len(s.sent))
	var due []item
	for id, r := range s.sent {
		mine = append(mine, id)
		due = append(due, item{id, *r})
	}
	s.mu.Unlock()

	var errs []error
	for _, it := range due {
		status, reason := "", ""
		switch {
		// Its result came and was lost: the probe will not send another.
		case it.r.lost:
			status, reason = StatusSkipped, ReasonIngestFailed
		// A run whose result already came is not skipped because its
		// stream ended: the result is being stored. Only the deadline
		// applies to it.
		case !it.r.released && !s.Probes.ProbeSessionAlive(it.r.cluster, it.r.session):
			// The probe sends a result only on the stream the run came
			// on: none will come.
			status, reason = StatusSkipped, ReasonProbeDisconnected
		case now.After(it.r.deadline):
			status, reason = StatusError, ReasonNoResult
		default:
			continue
		}
		if err := s.finishOne(ctx, it.id, it.r.cluster, status, reason); err != nil {
			errs = append(errs, fmt.Errorf("end run %s: %w", it.id, err))
			continue
		}
		s.forget(it.id)
	}

	if err := s.finishWhere(ctx, StatusSkipped, ReasonProbeDisconnected, `SELECT r.id, r.cluster_id FROM synthetic_runs r
		LEFT JOIN scenarios s ON s.id = r.scenario_id
		WHERE r.status = 'running' AND NOT (r.id = ANY($2))
		  AND COALESCE(r.started_at, r.created_at) + make_interval(secs => `+runTimeoutSQL+` + $3) < $1
		FOR UPDATE OF r SKIP LOCKED`, now, mine, int((ResultGrace+OrphanGrace)/time.Second)); err != nil {
		errs = append(errs, fmt.Errorf("end orphaned runs: %w", err))
	}
	return errors.Join(errs...)
}

// finishOne ends one open run of clusterID, unless it finished already.
func (s *Service) finishOne(ctx context.Context, runID, clusterID uuid.UUID, status, reason string) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		_, err := s.finish(ctx, tx, runID, clusterID, status, reason)
		return err
	})
}

// finishWhere ends, in one transaction, every open run the query selects.
// The query returns the runs' id and cluster_id and takes them FOR UPDATE
// SKIP LOCKED, so that a run another replica is sending is left alone.
func (s *Service) finishWhere(ctx context.Context, status, reason, query string, args ...any) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		type run struct{ id, cluster uuid.UUID }
		runs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (run, error) {
			var x run
			return x, r.Scan(&x.id, &x.cluster)
		})
		if err != nil {
			return err
		}
		for _, x := range runs {
			if _, err := s.finish(ctx, tx, x.id, x.cluster, status, reason); err != nil {
				return err
			}
			s.forget(x.id)
		}
		if len(runs) > 0 {
			s.Log.Info("synthetic runs ended", "status", status, "reason", reason, "runs", len(runs))
		}
		return nil
	})
}

// finish ends an open run (scheduled or running) of clusterID without a
// result, and calls OnResult. It reports whether the run was open.
func (s *Service) finish(ctx context.Context, tx pgx.Tx, runID, clusterID uuid.UUID, status, reason string) (bool, error) {
	now := s.now()
	var scenarioID *uuid.UUID
	var test bool
	err := tx.QueryRow(ctx, `UPDATE synthetic_runs SET status = $3, finished_at = $4, failure_reason = $5, failed_step = NULL
		WHERE id = $1 AND cluster_id = $2 AND status IN ('scheduled','running') RETURNING scenario_id, test`,
		runID, clusterID, status, now, reason).Scan(&scenarioID, &test)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, s.outcome(ctx, tx, RunOutcome{RunID: runID, ScenarioID: deref(scenarioID), ClusterID: clusterID,
		Status: status, Reason: reason, Test: test, FinishedAt: now})
}

func (s *Service) outcome(ctx context.Context, tx pgx.Tx, o RunOutcome) error {
	if s.OnResult == nil {
		return nil
	}
	return s.OnResult(ctx, tx, o)
}

func deref(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}

// rejection maps a probe's RunRejected reason to how the run ends.
func rejection(reason string) (status, failure string) {
	switch reason {
	case "busy":
		return StatusSkipped, ReasonProbeBusy
	case "allowlist_stale":
		return StatusSkipped, ReasonAllowlistStale
	case "credentials_unreadable":
		return StatusError, ReasonCredentialsUnreadable
	case "invalid_scenario":
		return StatusError, ReasonInvalidScenario
	}
	return StatusError, ReasonRejected
}

// Reject records that the probe of clusterID did not start a run. Only a
// running run of that cluster changes; the stream slot is freed.
func (s *Service) Reject(ctx context.Context, clusterID uuid.UUID, r *pb.RunRejected) error {
	runID, err := uuid.Parse(r.GetRunId())
	if err != nil {
		return nil
	}
	ctx, cancel := detached(ctx)
	defer cancel()
	s.release(runID, clusterID)
	status, reason := rejection(r.GetReason())
	var open bool
	err = store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		// Only a running run: a scheduled one was never sent.
		var st string
		err := tx.QueryRow(ctx, `SELECT status FROM synthetic_runs WHERE id = $1 AND cluster_id = $2 FOR UPDATE`, runID, clusterID).Scan(&st)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && st != StatusRunning {
			return nil
		}
		if err != nil {
			return err
		}
		open, err = s.finish(ctx, tx, runID, clusterID, status, reason)
		return err
	})
	if err == nil && open {
		s.forget(runID)
	}
	return err
}

// detached keeps the work of a message that arrived alive when its stream
// ends meanwhile, for a bounded time.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
}
