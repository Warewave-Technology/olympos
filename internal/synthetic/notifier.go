package synthetic

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Message limits: how many clusters a message names, and how long a reason
// may be in it.
const (
	topClusters      = 5
	maxMessageReason = 200
)

// pendingAlert is an alert with a message to send.
type pendingAlert struct {
	id          uuid.UUID
	clusterID   *uuid.UUID
	clusterName string
	state       string
	reason      string
	clusters    []string
	lastRunID   *uuid.UUID
	failedStep  *int
	stepKind    string
	// stillFailing: for a resolved fleet alert, the cluster alerts that
	// still fired when it resolved.
	stillFailing int
	opened       bool // notified_at is set
	resolved     bool // state resolved and resolved_notified_at is set
}

func (a *pendingAlert) fleet() bool { return a.clusterID == nil }

// Notify sends the messages of the alerts that opened or resolved since its
// last pass (leader of LockSyntheticAlerts, every AlertsInterval), grouped
// per scenario (SPEC F9): one synthetic.failing for the cluster alerts that
// opened, with their count, the first five clusters, the failed step and
// the reason; when the fleet alert opened, one synthetic.critical that
// includes them instead. Resolutions alike: one synthetic.recovered (the
// fleet's includes the clusters'), only when the scenario sends recoveries.
// An alert is marked notified in the transaction that writes its message to
// the outbox, so each one opens and resolves with one message at most; the
// idempotency key (synthetic.<kind>:<alert id>) is the outbox's own guard.
// The messages of one scenario in one pass are delivered in the order they
// are written (notify.Event.Seq): earlier alerts' resolutions, then the
// opens, then the resolutions of alerts that opened in the same pass.
func (s *Service) Notify(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT scenario_id FROM synthetic_alerts
		WHERE notified_at IS NULL OR (state = 'resolved' AND resolved_notified_at IS NULL)`)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error { return s.notifyScenario(ctx, tx, id) }); err != nil {
			errs = append(errs, fmt.Errorf("notify alerts of scenario %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) notifyScenario(ctx context.Context, tx pgx.Tx, scenarioID uuid.UUID) error {
	// The same lock as ApplyOutcome: the alerts do not move under us.
	var name string
	err := tx.QueryRow(ctx, `SELECT name FROM scenarios WHERE id = $1 FOR NO KEY UPDATE`, scenarioID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rule, err := loadAlertRule(ctx, tx, scenarioID)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT a.id, a.cluster_id, COALESCE(c.name, ''), a.state, a.reason, a.clusters, COALESCE(a.still_failing, 0), a.last_run_id,
			r.failed_step, COALESCE(st.kind, ''), a.notified_at IS NOT NULL, a.resolved_notified_at IS NOT NULL
		FROM synthetic_alerts a
		LEFT JOIN clusters c ON c.id = a.cluster_id
		LEFT JOIN synthetic_runs r ON r.id = a.last_run_id
		LEFT JOIN scenario_steps st ON st.scenario_id = a.scenario_id AND st.position = r.failed_step
		WHERE a.scenario_id = $1 AND (a.notified_at IS NULL OR (a.state = 'resolved' AND a.resolved_notified_at IS NULL))
		ORDER BY a.opened_at, a.id
		FOR UPDATE OF a`, scenarioID)
	if err != nil {
		return err
	}
	alerts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (*pendingAlert, error) {
		a := &pendingAlert{}
		return a, r.Scan(&a.id, &a.clusterID, &a.clusterName, &a.state, &a.reason, &a.clusters, &a.stillFailing, &a.lastRunID,
			&a.failedStep, &a.stepKind, &a.opened, &a.resolved)
	})
	if err != nil {
		return err
	}
	// Order (fix round 1): resolutions of alerts whose open went out in
	// an earlier pass come first, then this pass's opens, then the
	// resolutions of alerts that opened in this pass too. A fleet alert
	// that resolved and a new one that opened thus read "no longer
	// critical", then "critical".
	var earlier, opened, blips []*pendingAlert
	for _, a := range alerts {
		if !a.opened {
			opened = append(opened, a)
		}
		if a.state == "resolved" && !a.resolved {
			if a.opened {
				earlier = append(earlier, a)
			} else {
				blips = append(blips, a)
			}
		}
	}
	now := s.now()
	seq := 0
	emit := func(e notify.Event) error {
		e.Seq = seq
		seq++
		return notify.Emit(ctx, tx, e)
	}
	resolve := func(group []*pendingAlert) error {
		if len(group) == 0 {
			return nil
		}
		if rule.SendRecovery {
			if err := emitResolved(scenarioID, name, rule, group, emit); err != nil {
				return err
			}
		}
		// Marked when recoveries are off too: turning them on later does
		// not send old ones.
		_, err := tx.Exec(ctx, `UPDATE synthetic_alerts SET resolved_notified_at = $2 WHERE id = ANY($1)`, alertIDs(group), now)
		return err
	}

	if err := resolve(earlier); err != nil {
		return err
	}
	if len(opened) > 0 {
		if err := emitOpened(ctx, tx, scenarioID, name, rule, opened, emit); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE synthetic_alerts SET notified_at = $2 WHERE id = ANY($1)`, alertIDs(opened), now); err != nil {
			return err
		}
	}
	return resolve(blips)
}

// emitOpened writes the one message of the alerts that opened: critical
// when the fleet alert is among them, else failing. The critical message
// names the fleet's clusters and every cluster alert it is sent for.
func emitOpened(ctx context.Context, tx pgx.Tx, scenarioID uuid.UUID, name string, rule AlertRule, opened []*pendingAlert,
	emit func(notify.Event) error) error {
	fleet, clusters := split(opened)
	if fleet != nil {
		ids := append([]string(nil), fleet.clusters...)
		for _, a := range clusters {
			if id := a.clusterID.String(); !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		names, err := clusterNames(ctx, tx, ids)
		if err != nil {
			return err
		}
		ch := rule.CriticalChannelID
		if ch == nil {
			ch = rule.ChannelID
		}
		return emit(alertEvent(notify.SyntheticCritical, ch, fleet, scenarioID,
			fmt.Sprintf("Synthetic check critical: %s fails on %d clusters", name, len(names)), name, names, true, opened))
	}
	names := make([]string, len(clusters))
	for i, a := range clusters {
		names[i] = a.clusterName
	}
	return emit(alertEvent(notify.SyntheticFailing, rule.ChannelID, clusters[0], scenarioID,
		"Synthetic check failing: "+name+" on "+onClusters(names), name, names, true, opened))
}

// emitResolved writes the one message of the alerts that resolved, to the
// critical channel when the fleet alert is among them, with the number of
// cluster alerts that still fired when the fleet alert resolved.
func emitResolved(scenarioID uuid.UUID, name string, rule AlertRule, resolved []*pendingAlert, emit func(notify.Event) error) error {
	fleet, clusters := split(resolved)
	names := make([]string, len(clusters))
	for i, a := range clusters {
		names[i] = a.clusterName
	}
	if fleet != nil {
		ch := rule.CriticalChannelID
		if ch == nil {
			ch = rule.ChannelID
		}
		e := alertEvent(notify.SyntheticRecovered, ch, fleet, scenarioID, "Synthetic check no longer critical: "+name, name, names, false, resolved)
		e.Fields["still failing"] = fmt.Sprintf("%d clusters", fleet.stillFailing)
		e.Payload["still_failing"] = fleet.stillFailing
		return emit(e)
	}
	return emit(alertEvent(notify.SyntheticRecovered, rule.ChannelID, clusters[0], scenarioID,
		"Synthetic check recovered: "+name+" on "+onClusters(names), name, names, false, resolved))
}

// alertEvent builds a message about the alerts in group; lead names the
// key, the link's run and, for an open, the failed step and reason. Only
// names, counts, a step position and kind, and a redacted, shortened reason
// go into it: never a credential or a response.
func alertEvent(kind string, ch *uuid.UUID, lead *pendingAlert, scenarioID uuid.UUID, title, scenario string, clusters []string,
	open bool, group []*pendingAlert) notify.Event {
	link := "/monitoring?scenario=" + scenarioID.String()
	payload := map[string]any{"scenario_id": scenarioID.String(), "alert_ids": idStrings(group), "cluster_count": len(clusters)}
	if lead.lastRunID != nil {
		link += "&run=" + lead.lastRunID.String()
		payload["run_id"] = lead.lastRunID.String()
	}
	fields := map[string]string{"scenario": scenario}
	if len(clusters) > 0 {
		fields["clusters"] = topList(clusters)
	}
	if open {
		if lead.failedStep != nil {
			step := fmt.Sprintf("%d", *lead.failedStep+1)
			if lead.stepKind != "" {
				step += " (" + lead.stepKind + ")"
			}
			fields["failed step"] = step
			payload["failed_step"] = *lead.failedStep
		}
		if r := clean(lead.reason, maxMessageReason); r != "" {
			fields["reason"] = r
		}
	}
	return notify.Event{Type: kind, Key: kind + ":" + lead.id.String(), ChannelID: ch, Title: title, Link: link, Fields: fields, Payload: payload}
}

// split separates the fleet alert from the cluster alerts.
func split(as []*pendingAlert) (fleet *pendingAlert, clusters []*pendingAlert) {
	for _, a := range as {
		if a.fleet() {
			fleet = a
		} else {
			clusters = append(clusters, a)
		}
	}
	return fleet, clusters
}

// clusterNames returns the names of the clusters with these ids, in their
// order; a cluster deleted since keeps its id.
func clusterNames(ctx context.Context, tx pgx.Tx, ids []string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, name FROM clusters WHERE id::text = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	byID := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, err
		}
		byID[id] = name
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id
		if n, ok := byID[id]; ok {
			out[i] = n
		}
	}
	return out, nil
}

// onClusters is "<name>" for one cluster, "N clusters" for more.
func onClusters(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return fmt.Sprintf("%d clusters", len(names))
}

// topList names the first topClusters clusters and counts the rest.
func topList(names []string) string {
	if len(names) <= topClusters {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:topClusters], ", "), len(names)-topClusters)
}

func alertIDs(as []*pendingAlert) []uuid.UUID {
	out := make([]uuid.UUID, len(as))
	for i, a := range as {
		out[i] = a.id
	}
	return out
}

func idStrings(as []*pendingAlert) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.id.String()
	}
	return out
}
