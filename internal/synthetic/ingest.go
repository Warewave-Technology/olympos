package synthetic

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Bounds on what a result may store. The probe keeps to smaller ones; these
// hold whatever it sends.
const (
	maxReason       = 1024
	maxAssertText   = 256
	maxAssertions   = 50
	maxExtractNames = 20
	maxNameLen      = 64
	maxVersion      = 64
)

// Ingest stores a probe's result. Only a running run of clusterID changes:
// a result for another cluster's run, for a run that finished already (a
// duplicate, or a run the server ended), or for an unknown run is ignored.
// Every text is passed through secrets.RedactString and bounded, and the
// excerpts are dropped when the scenario does not store responses. OnResult
// runs in the same transaction.
func (s *Service) Ingest(ctx context.Context, clusterID uuid.UUID, r *pb.RunResult) error {
	runID, err := uuid.Parse(r.GetRunId())
	if err != nil {
		// Debug: a probe sends as many messages as it likes.
		s.Log.Debug("run result with an invalid run id ignored", "cluster_id", clusterID)
		return nil
	}
	// The stream's slot is free whatever happens to the result.
	s.release(runID, clusterID)
	ctx, cancel := detached(ctx)
	defer cancel()
	var stored bool
	err = store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		stored, err = s.ingest(ctx, tx, runID, clusterID, r)
		return err
	})
	if err != nil {
		return err
	}
	if stored {
		s.forget(runID)
	}
	return nil
}

func (s *Service) ingest(ctx context.Context, tx pgx.Tx, runID, clusterID uuid.UUID, r *pb.RunResult) (bool, error) {
	var scenarioID *uuid.UUID
	var test, keep bool
	err := tx.QueryRow(ctx, `SELECT r.scenario_id, r.test,
			COALESCE(CASE WHEN jsonb_typeof(r.test_spec->'store_responses') = 'boolean' THEN (r.test_spec->>'store_responses')::boolean END,
				s.store_responses, false)
		FROM synthetic_runs r LEFT JOIN scenarios s ON s.id = r.scenario_id
		WHERE r.id = $1 AND r.cluster_id = $2 AND r.status = 'running' FOR UPDATE OF r`, runID, clusterID).Scan(&scenarioID, &test, &keep)
	if errors.Is(err, pgx.ErrNoRows) {
		s.Log.Debug("run result ignored: no such running run of this cluster", "cluster_id", clusterID, "run_id", runID)
		return false, nil
	}
	if err != nil {
		return false, err
	}

	now := s.now()
	status, reason := r.GetStatus(), ""
	switch status {
	case StatusPassed:
	case StatusFailed, StatusError:
		reason = clean(r.GetFailureReason(), maxReason)
	default:
		status, reason = StatusError, ReasonInvalidResult
	}
	failed := failedStep(r, status)
	var totalMS *int
	if a, b := r.GetStartedUnixMs(), r.GetFinishedUnixMs(); a > 0 && b >= a && b-a <= int64(spec.MaxRunTimeout.Milliseconds())*2 {
		v := int(b - a)
		totalMS = &v
	}
	remote := ""
	for _, st := range r.GetSteps() {
		if ip := cleanIP(st.GetRemoteIp()); ip != "" {
			remote = ip
			if failed != nil && int(st.GetPosition()) == *failed {
				break
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE synthetic_runs SET status = $2, finished_at = $3, failed_step = $4, failure_reason = $5,
		total_ms = $6, probe_version = $7, remote_ip = $8, probe_ip = $9 WHERE id = $1`,
		runID, status, now, failed, reason, totalMS, clean(r.GetProbeVersion(), maxVersion), remote, cleanIP(r.GetProbeIp())); err != nil {
		return false, err
	}

	seen := map[int32]bool{}
	for _, st := range r.GetSteps() {
		pos := st.GetPosition()
		if pos < 0 || pos >= spec.MaxSteps || seen[pos] {
			continue
		}
		seen[pos] = true
		if err := insertStep(ctx, tx, runID, st, keep); err != nil {
			return false, err
		}
	}
	return true, s.outcome(ctx, tx, RunOutcome{RunID: runID, ScenarioID: deref(scenarioID), ClusterID: clusterID,
		Status: status, FailedStep: failed, Reason: reason, Test: test, FinishedAt: now})
}

// failedStep is the position of the step that failed: only for a failed or
// errored run, and only when that step is in the result and did not pass.
// failed_step 0 is a real step (proto3 has no unset int), so the status
// decides; a runner panic names no step.
func failedStep(r *pb.RunResult, status string) *int {
	if status != StatusFailed && status != StatusError || strings.HasPrefix(r.GetFailureReason(), ReasonRunnerPanic) {
		return nil
	}
	for _, st := range r.GetSteps() {
		if st.GetPosition() == r.GetFailedStep() && st.GetStatus() != StatusPassed && st.GetStatus() != StatusSkipped {
			v := int(st.GetPosition())
			return &v
		}
	}
	return nil
}

func insertStep(ctx context.Context, tx pgx.Tx, runID uuid.UUID, st *pb.StepResult, keep bool) error {
	status := st.GetStatus()
	switch status {
	case StatusPassed, StatusFailed, StatusError, StatusSkipped:
	default:
		status = StatusError
	}
	t := st.GetTimings()
	timings, err := json.Marshal(map[string]int64{
		"dns_us": nonNeg(t.GetDnsUs()), "connect_us": nonNeg(t.GetConnectUs()), "tls_us": nonNeg(t.GetTlsUs()),
		"ttfb_us": nonNeg(t.GetTtfbUs()), "download_us": nonNeg(t.GetDownloadUs()), "total_us": nonNeg(t.GetTotalUs()),
	})
	if err != nil {
		return err
	}
	type assertion struct {
		Subject  string `json:"subject"`
		Operator string `json:"operator"`
		Expected string `json:"expected"`
		Actual   string `json:"actual"`
		Passed   bool   `json:"passed"`
	}
	as := []assertion{}
	for i, a := range st.GetAssertions() {
		if i == maxAssertions {
			break
		}
		as = append(as, assertion{Subject: clean(a.GetSubject(), maxAssertText), Operator: clean(a.GetOperator(), maxAssertText),
			Expected: clean(a.GetExpected(), maxAssertText), Actual: clean(a.GetActual(), maxAssertText), Passed: a.GetPassed()})
	}
	assertions, err := json.Marshal(as)
	if err != nil {
		return err
	}
	names := []string{}
	for i, n := range st.GetExtractedNames() {
		if i == maxExtractNames {
			break
		}
		names = append(names, clean(n, maxNameLen))
	}
	var code *int32
	if c := st.GetStatusCode(); c > 0 && c < 1000 {
		code = &c
	}
	var excerpt []byte
	if keep {
		excerpt = cleanExcerpt(st.GetResponseExcerpt())
	}
	_, err = tx.Exec(ctx, `INSERT INTO synthetic_step_results (run_id, position, status, status_code, timings, assertions, excerpt, extracted_names, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (run_id, position) DO NOTHING`,
		runID, st.GetPosition(), status, code, timings, assertions, excerpt, names, clean(st.GetError(), maxReason))
	return err
}

func nonNeg(v int64) int64 { return max(v, 0) }

// clean redacts known secret shapes, makes the text valid UTF-8 without NUL
// (Postgres text) and cuts it to at most n bytes on a rune boundary.
func clean(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "")
	s = secrets.RedactString(s)
	return cut(s, n)
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cleanExcerpt redacts an excerpt and bounds it to spec.MaxExcerpt. The
// probe sends text only; anything else is dropped rather than stored
// unread.
func cleanExcerpt(b []byte) []byte {
	if len(b) == 0 || !utf8.Valid(b) {
		return nil
	}
	return []byte(cut(secrets.RedactString(string(b)), spec.MaxExcerpt))
}

// cleanIP returns the IP address in s in canonical form, or "".
func cleanIP(s string) string {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return ip.String()
}
