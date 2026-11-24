// Package synthetic is the server side of synthetic monitoring
// (docs/design/synthetic-monitoring.md): the probes' online state, the
// dispatch of runs to the probe streams on this replica with their
// credentials sealed to the stream's key, and the ingestion of results.
//
// A run moves scheduled → running → passed | failed | error | skipped, and
// a finished run never changes again (a trigger enforces it). A run is sent
// at most once: a new attempt is a new run (the probe ignores a run id it has
// seen). A run the probe could not finish for reasons of its own connection
// (offline, disconnected) ends skipped, never failed (Review Focus 4).
package synthetic

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/config"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Run statuses (synthetic_runs.status).
const (
	StatusScheduled = "scheduled"
	StatusRunning   = "running"
	StatusPassed    = "passed"
	StatusFailed    = "failed"
	StatusError     = "error"
	StatusSkipped   = "skipped"
)

// Failure reasons the server sets (synthetic_runs.failure_reason). The probe
// sets its own (internal/probe: host_not_allowed, ip_denied, timeout, ...).
const (
	// ReasonProbeOffline: the cluster's probe was not online when the run
	// was due (skipped).
	ReasonProbeOffline = "probe_offline"
	// ReasonProbeDisconnected: the stream the run was sent on ended before
	// its result came (skipped): the probe sends a result only on that
	// stream.
	ReasonProbeDisconnected = "probe_disconnected"
	// ReasonNoResult: the stream stayed open but no result came within the
	// run's timeout and ResultGrace (error).
	ReasonNoResult = "no_result"
	// ReasonIngestFailed: the probe's result came but the server could not
	// store it (skipped): the probe sends a result once, and the fault is
	// not the scenario's.
	ReasonIngestFailed = "ingest_failed"
	// ReasonNotDispatched: the probe was online but no replica could send
	// the run within the scenario's interval (skipped).
	ReasonNotDispatched = "not_dispatched"
	// ReasonProbeBusy: the probe refused the run, it had no room (skipped).
	ReasonProbeBusy = "probe_busy"
	// ReasonAllowlistStale: the probe holds a newer allowlist than the run
	// carried (skipped; the next run carries the new one).
	ReasonAllowlistStale = "allowlist_stale"
	// ReasonCredentialsUnreadable: the probe could not open the sealed
	// credentials (error).
	ReasonCredentialsUnreadable = "credentials_unreadable"
	// ReasonInvalidScenario: the scenario could not be loaded, or the probe
	// refused it (error).
	ReasonInvalidScenario = "invalid_scenario"
	// ReasonCredentialError: a credential of the scenario is missing or its
	// bound hosts do not parse (error). The probe uses the same code.
	ReasonCredentialError = "credential_error"
	// ReasonCredentialExpired: a credential of the scenario is past its
	// expires_at (error, ruling P13). Like credential_broken, it moves no
	// streak and counts in no stat: the credential alerts, once (#54).
	ReasonCredentialExpired = "credential_expired"
	// ReasonCredentialBroken: a credential of the scenario cannot be
	// resolved and will not be until someone changes it or the vault (error;
	// not found, forbidden, does not decrypt, empty). It moves no streak and
	// counts in no stat: the credential alerts, once (#54).
	ReasonCredentialBroken = "credential_broken"
	// ReasonCredentialUnavailable: the server could not resolve a
	// credential for now (Key Vault did not answer, the KEK, the database):
	// skipped, the fault is not the scenario's (ruling P14).
	ReasonCredentialUnavailable = "credential_unavailable"
	// ReasonScenarioDisabled: the run was due after its scenario was
	// disabled (skipped, ruling P13).
	ReasonScenarioDisabled = "scenario_disabled"
	// ReasonDispatchError: the server could not read the run to send it
	// (error).
	ReasonDispatchError = "dispatch_error"
	// ReasonRejected: the probe refused the run for a reason this server
	// does not know (error).
	ReasonRejected = "rejected"
	// ReasonInvalidResult: the probe reported a status that is not a run
	// status (error).
	ReasonInvalidResult = "invalid_result"
	// ReasonRunnerPanic is the probe's failure reason of a run whose runner
	// panicked (internal/probe.RunnerPanic): no step is known to have
	// failed.
	ReasonRunnerPanic = "runner_panic"
)

// Timing.
const (
	// DispatchInterval is how often each replica sends due runs.
	DispatchInterval = time.Second
	// AlertsInterval is how often the leader checks probe state.
	AlertsInterval = 15 * time.Second
	// ResultGrace is how long after a run's timeout the server waits for
	// its result. The probe's deadline starts when it receives the run, a
	// little after the server sent it, and the result takes a moment to
	// come back.
	ResultGrace = 30 * time.Second
	// OrphanGrace is the further wait before any replica ends a running run
	// that no live replica tracks (its replica restarted or died, and with
	// it the stream). The replica that sent a run ends it ResultGrace after
	// its timeout; another replica waits OrphanGrace longer.
	OrphanGrace = 60 * time.Second
	// defaultTestInterval stands in for the interval of a test run (it has
	// no schedule) when deciding that it was never dispatched.
	defaultTestInterval = 60 * time.Second
	// MaxClaim is the most runs one pass claims for one stream, whatever
	// concurrency the probe advertises.
	MaxClaim = 20
)

// ProbeSender is the part of the gateway that reaches probe streams on this
// replica (*gateway.Gateway).
type ProbeSender interface {
	// ProbeStream and SendRun use only the streams of certificate
	// certSerial, the cluster's current one (clusters.probe_cert_serial).
	ProbeStream(clusterID uuid.UUID, certSerial string) (gateway.ProbeInfo, bool)
	SendRun(clusterID uuid.UUID, certSerial string, build func(gateway.ProbeInfo) (*pb.RunScenario, error)) (gateway.ProbeInfo, error)
	RunDone(clusterID uuid.UUID, sessionID uint64)
	// ProbeSessionAlive reports whether stream sessionID is still open.
	ProbeSessionAlive(clusterID uuid.UUID, sessionID uint64) bool
}

// RunOutcome is a run that just finished, whatever ended it: a result, a
// rejection, or the server (skipped, error). FailedStep is the failed step's
// position, nil when no step is known to have failed. ScenarioID is
// uuid.Nil for a test run of an unsaved scenario.
type RunOutcome struct {
	RunID, ScenarioID, ClusterID uuid.UUID
	Status                       string
	FailedStep                   *int
	Reason                       string
	Test                         bool
	FinishedAt                   time.Time
}

// Service is the synthetic monitoring module on one replica.
type Service struct {
	DB     *store.DB
	Log    *slog.Logger
	Probes ProbeSender
	Creds  *backup.Credentials
	Cfg    config.Synthetic
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// OnResult is called in the transaction that finishes a run, for every
	// run that finishes (skipped ones included). An error rolls the
	// transaction back. In production it is ApplyOutcome.
	OnResult func(ctx context.Context, tx pgx.Tx, r RunOutcome) error
	// Started is when this server came up. Probes need up to
	// gateway.OfflineAfter to reconnect after a restart, so the probe
	// offline check waits that long and counts an outage from Started at the
	// earliest (as inventory does for agents). Zero: no wait.
	Started time.Time

	mu sync.Mutex
	// sent holds the runs this replica sent and that have not finished.
	sent map[uuid.UUID]*sentRun
	// badTargeting holds the scenarios whose stored targeting does not
	// parse, with that targeting, so that each change is logged once.
	badTargeting map[uuid.UUID]string
}

// sentRun is a run in flight on a stream of this replica.
type sentRun struct {
	cluster  uuid.UUID
	session  uint64
	deadline time.Time
	// released: RunDone was called (the result came), but the run is not
	// finished in the database yet.
	released bool
	// lost: the result came but storing it failed. No other result will
	// come: the run ends skipped (ingest_failed), not error (no_result).
	lost bool
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) probeOfflineAlertAfter() time.Duration {
	if s.Cfg.ProbeOfflineAlertAfter > 0 {
		return s.Cfg.ProbeOfflineAlertAfter
	}
	return 5 * time.Minute
}

// AdvanceAllowlistVersion moves the allowlist version to the current time
// in milliseconds, or by one when it is ahead of that (ruling P25), and
// returns it. Every replica calls it at start-up, before it dispatches: a
// probe refuses a snapshot older than the newest it has seen, so after a
// restore from an older dump every run would be refused (allowlist_stale)
// until the list changed. Calling it more than once does no harm.
func (s *Service) AdvanceAllowlistVersion(ctx context.Context) (int64, error) {
	var v int64
	err := s.DB.QueryRow(ctx, `SELECT olympos_synthetic_allowlist_advance()`).Scan(&v)
	return v, err
}

// InstallHooks connects the gateway's probe streams to the service.
//
// Disconnected is left alone on purpose: when the last stream of a cluster
// ends on this replica, a stream of the same probe may be attaching here or
// on another replica. Whether a probe is offline is decided from its last
// traffic instead (Seen, CheckProbesOffline), with the debounce of §5.
func (s *Service) InstallHooks(h *gateway.ProbeHooks) {
	h.Connected = s.probeConnected
	h.Seen = s.probeSeen
	h.Result = func(ctx context.Context, clusterID uuid.UUID, r *pb.RunResult) {
		if err := s.Ingest(ctx, clusterID, r); err != nil {
			s.Log.Error("ingest run result", "cluster_id", clusterID, "run_id", r.GetRunId(), "err", err)
		}
	}
	h.Rejected = func(ctx context.Context, clusterID uuid.UUID, r *pb.RunRejected) {
		if err := s.Reject(ctx, clusterID, r); err != nil {
			s.Log.Error("record run rejection", "cluster_id", clusterID, "run_id", r.GetRunId(), "err", err)
		}
	}
}

// RunDispatcher sends due runs every DispatchInterval. Every replica runs
// it: each sends the runs of the probes connected to it.
func (s *Service) RunDispatcher(ctx context.Context) {
	t := time.NewTicker(DispatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := s.Dispatch(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("dispatch synthetic runs", "err", err)
		}
	}
}

// RunAlerts is the leader loop of LockSyntheticAlerts, every
// AlertsInterval: probe state, unmonitored alerts, then the alert messages
// (one loop per lock: two loops on one key would exclude each other).
func (s *Service) RunAlerts(ctx context.Context) {
	schedule.RunLeader(ctx, s.DB, schedule.LockSyntheticAlerts, AlertsInterval, s.Log.With("loop", "alerts"), s.alertsTick)
}

// alertsTick runs every check, one failing does not hold the others back:
// probe state, the alerts of pairs no longer monitored (ruling P16), then
// the messages.
func (s *Service) alertsTick(ctx context.Context) error {
	return errors.Join(s.CheckProbesOffline(ctx), s.ResolveUnmonitored(ctx), s.Notify(ctx))
}
