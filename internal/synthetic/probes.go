package synthetic

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Probe states (clusters.probe_status).
const (
	ProbeNotInstalled = "not_installed"
	ProbePending      = "pending"
	ProbeOnlineState  = "online"
	ProbeOfflineState = "offline"
	ProbeRevoked      = "revoked"
)

// errProbeRevoked refuses a stream whose probe was revoked after the
// gateway checked its identity.
var errProbeRevoked = errors.New("probe revoked")

// probeConnected is the gateway's Connected hook: the probe is online and
// its version is recorded. A revoked probe stays revoked, and its stream is
// refused.
func (s *Service) probeConnected(ctx context.Context, clusterID uuid.UUID, h *pb.ProbeHello) error {
	now := s.now()
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var prev, name string
		var alerted bool
		var since *time.Time
		err := tx.QueryRow(ctx, `SELECT probe_status, name, probe_offline_alerted, probe_offline_since FROM clusters
			WHERE id = $1 AND status <> 'revoked' FOR UPDATE`, clusterID).Scan(&prev, &name, &alerted, &since)
		if errors.Is(err, pgx.ErrNoRows) {
			return errProbeRevoked
		}
		if err != nil {
			return err
		}
		if prev == ProbeRevoked {
			return errProbeRevoked
		}
		version := clean(h.GetProbeVersion(), maxVersion)
		if _, err := tx.Exec(ctx, `UPDATE clusters SET probe_version = $2, probe_last_seen_at = $3 WHERE id = $1`,
			clusterID, version, now); err != nil {
			return err
		}
		if prev == ProbePending || prev == ProbeNotInstalled {
			if _, err := tx.Exec(ctx, `UPDATE clusters SET probe_status = 'online', probe_offline_since = NULL, probe_offline_alerted = false
				WHERE id = $1`, clusterID); err != nil {
				return err
			}
			// A probe re-enrolled while it was alerted offline: its
			// outage ends here, and the alert gets its probe.online.
			if alerted {
				if err := emitProbeOnline(ctx, tx, clusterID, name, since); err != nil {
					return err
				}
			}
			return activity.Record(ctx, tx, activity.Entry{ActorKind: "agent", Action: "probe.connected", ObjectType: "cluster",
				ObjectID: clusterID.String(), ClusterID: &clusterID, Details: map[string]any{"probe_version": version}})
		}
		return s.markProbeOnline(ctx, tx, clusterID, now)
	})
}

// markProbeOnline moves an offline probe back online (the caller holds the
// row). probe.online is emitted only when probe.offline was: one message
// pair per outage, none for a short blip.
func (s *Service) markProbeOnline(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, now time.Time) error {
	var name, prev string
	var alerted bool
	var since *time.Time
	err := tx.QueryRow(ctx, `UPDATE clusters c SET probe_status = 'online', probe_offline_since = NULL, probe_offline_alerted = false
		FROM (SELECT id, probe_status, probe_offline_alerted, probe_offline_since FROM clusters WHERE id = $1) o
		WHERE c.id = o.id AND c.probe_status IN ('online','offline')
		RETURNING c.name, o.probe_status, o.probe_offline_alerted, o.probe_offline_since`, clusterID).Scan(&name, &prev, &alerted, &since)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && prev != ProbeOfflineState {
		return nil
	}
	if err != nil {
		return err
	}
	details := map[string]any{}
	if since != nil {
		details["offline_for_s"] = int(now.Sub(*since).Seconds())
	}
	if alerted {
		if err := emitProbeOnline(ctx, tx, clusterID, name, since); err != nil {
			return err
		}
	}
	return activity.Record(ctx, tx, activity.Entry{ActorKind: "agent", Action: "probe.online", ObjectType: "cluster",
		ObjectID: clusterID.String(), ClusterID: &clusterID, Details: details})
}

// emitProbeOnline sends the probe.online that follows a probe.offline.
func emitProbeOnline(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, name string, since *time.Time) error {
	key := "probe.online:" + clusterID.String()
	if since != nil {
		key += fmt.Sprintf(":%d", since.Unix())
	}
	return notify.Emit(ctx, tx, notify.Event{
		Type: notify.ProbeOnline, Key: key, Title: "Probe back online: " + name, Link: "/settings/clusters",
		Fields: map[string]string{"cluster": name},
	})
}

// probeSeen is the gateway's Seen hook (throttled by the gateway): it
// records the probe's traffic, and a probe marked offline while its stream
// stayed open comes back online. Only the traffic of a stream of the
// current certificate counts (ruling P26): a probe left on a certificate
// that was renewed (the agent could not write the new one) gets no run, so
// it must go offline and alert rather than look online.
func (s *Service) probeSeen(ctx context.Context, clusterID uuid.UUID, certSerial string) {
	now := s.now()
	var st string
	err := s.DB.QueryRow(ctx, `UPDATE clusters SET probe_last_seen_at = $2
		WHERE id = $1 AND probe_status IN ('online','offline') AND probe_cert_serial <> '' AND probe_cert_serial = $3
		RETURNING probe_status`, clusterID, now, certSerial).Scan(&st)
	if err == nil && st == ProbeOfflineState {
		err = store.Tx(ctx, s.DB, func(tx pgx.Tx) error { return s.markProbeOnline(ctx, tx, clusterID, now) })
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
		s.Log.Warn("update probe last seen", "cluster_id", clusterID, "err", err)
	}
}

// CheckProbesOffline is one pass of the probe offline check (leader,
// LockSyntheticAlerts), the same rules as the agent's (F18): a probe with no
// traffic for gateway.OfflineAfter is offline, without a message (short
// blips are common); once an outage lasts ProbeOfflineAlertAfter, one
// probe.offline. markProbeOnline sends the one probe.online that follows.
func (s *Service) CheckProbesOffline(ctx context.Context) error {
	now := s.now()
	if !s.Started.IsZero() && now.Sub(s.Started) < gateway.OfflineAfter {
		return nil
	}
	alertAfter := s.probeOfflineAlertAfter()
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		type row struct {
			id    uuid.UUID
			name  string
			since *time.Time
		}
		scan := func(rows pgx.Rows) ([]row, error) {
			defer rows.Close()
			var out []row
			for rows.Next() {
				var x row
				if err := rows.Scan(&x.id, &x.name, &x.since); err != nil {
					return nil, err
				}
				out = append(out, x)
			}
			return out, rows.Err()
		}
		var started *time.Time
		if !s.Started.IsZero() {
			started = &s.Started
		}
		rows, err := tx.Query(ctx, `UPDATE clusters SET probe_status = 'offline',
				probe_offline_since = GREATEST(probe_last_seen_at, $2::timestamptz), probe_offline_alerted = false
			WHERE probe_status = 'online' AND (probe_last_seen_at IS NULL OR probe_last_seen_at < $1)
			RETURNING id, name, probe_offline_since`, now.Add(-gateway.OfflineAfter), started)
		if err != nil {
			return err
		}
		gone, err := scan(rows)
		if err != nil {
			return err
		}
		for _, x := range gone {
			id := x.id
			if err := activity.Record(ctx, tx, activity.Entry{Action: "probe.offline", ObjectType: "cluster", ObjectID: id.String(), ClusterID: &id}); err != nil {
				return err
			}
			s.Log.Warn("probe offline", "cluster", x.name)
		}
		rows, err = tx.Query(ctx, `UPDATE clusters SET probe_offline_alerted = true
			WHERE probe_status = 'offline' AND NOT probe_offline_alerted
			  AND COALESCE(probe_offline_since, probe_last_seen_at) < $1
			RETURNING id, name, probe_offline_since`, now.Add(-alertAfter))
		if err != nil {
			return err
		}
		alert, err := scan(rows)
		if err != nil {
			return err
		}
		for _, x := range alert {
			key := "probe.offline:" + x.id.String()
			if x.since != nil {
				key += fmt.Sprintf(":%d", x.since.Unix())
			}
			if err := notify.Emit(ctx, tx, notify.Event{Type: notify.ProbeOffline, Key: key, Title: "Probe offline: " + x.name,
				Link: "/settings/clusters", Fields: map[string]string{"cluster": x.name, "offline for": "more than " + alertAfter.String()}}); err != nil {
				return err
			}
		}
		return nil
	})
}
