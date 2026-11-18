package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/targetid"
)

// Service ingests agent messages.
type Service struct {
	DB  *store.DB
	Log *slog.Logger
	// OnTargetGone is called (inside the transaction) when a target
	// disappears, so modules can pause jobs and emit events.
	OnTargetGone []func(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, targetID string) error
	// OnTargetUpsert is called (inside the transaction) when a target is
	// first seen or changes.
	OnTargetUpsert []func(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, t *pb.Target) error

	// Alert debounce (F18). Zero values use the defaults below.
	OfflineAlertAfter   time.Duration
	FlappingDisconnects int
	FlappingWindow      time.Duration
}

// Alert debounce defaults (F18).
const (
	DefaultOfflineAlertAfter   = 5 * time.Minute
	DefaultFlappingDisconnects = 5
	DefaultFlappingWindow      = 30 * time.Minute
)

func (s *Service) alertAfter() time.Duration {
	if s.OfflineAlertAfter > 0 {
		return s.OfflineAlertAfter
	}
	return DefaultOfflineAlertAfter
}

func (s *Service) flapping() (int, time.Duration) {
	n, w := s.FlappingDisconnects, s.FlappingWindow
	if n <= 0 {
		n = DefaultFlappingDisconnects
	}
	if w <= 0 {
		w = DefaultFlappingWindow
	}
	return n, w
}

func interval(d time.Duration) string { return fmt.Sprintf("%d seconds", int(d.Seconds())) }

// Hooks returns the gateway hooks implemented by inventory.
func (s *Service) Hooks(h *gateway.Hooks) {
	h.Connected = s.connected
	h.Seen = s.seen
	h.Disconnected = s.disconnected
	h.Inventory = s.snapshot
	h.InventoryDiff = s.diff
	h.TargetUpsert = s.targetUpsert
	h.TargetDelete = s.targetDelete
}

func (s *Service) connected(ctx context.Context, clusterID uuid.UUID, h *pb.Hello) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var prev string
		err := tx.QueryRow(ctx, `SELECT status FROM clusters WHERE id = $1 FOR UPDATE`, clusterID).Scan(&prev)
		if err != nil {
			return err
		}
		caps := h.GetCapabilities()
		_, err = tx.Exec(ctx, `UPDATE clusters SET last_seen_at = now(), agent_version = $2,
			bench_enabled = $3, bench_max_parallel = $4, secrets_inventory = $6,
			provider_override = CASE WHEN provider_override = '' THEN $5 ELSE provider_override END
			WHERE id = $1`, clusterID, h.AgentVersion, caps.GetBenchEnabled(), caps.GetBenchMaxParallel(), normalizeOverride(h.ProviderOverride),
			caps.GetSecretsInventory())
		if err != nil {
			return err
		}
		if prev == "pending" {
			if _, err := tx.Exec(ctx, `UPDATE clusters SET status = 'online' WHERE id = $1`, clusterID); err != nil {
				return err
			}
			return activity.Record(ctx, tx, activity.Entry{ActorKind: "agent", Action: "agent.connected", ObjectType: "cluster", ObjectID: clusterID.String(), ClusterID: &clusterID,
				Details: map[string]any{"agent_version": h.AgentVersion}})
		}
		return markOnline(ctx, tx, clusterID)
	})
}

// markOnline moves an offline cluster back online (caller holds the row).
// agent.online is emitted only when agent.offline was (F18: one message
// pair per outage, none for a short blip).
func markOnline(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID) error {
	var name, prev string
	var alerted bool
	var since *time.Time
	err := tx.QueryRow(ctx, `UPDATE clusters c SET status = 'online', offline_since = NULL, offline_alerted = false
		FROM (SELECT id, status, offline_alerted, offline_since FROM clusters WHERE id = $1) o
		WHERE c.id = o.id AND c.status IN ('online','offline')
		RETURNING c.name, o.status, o.offline_alerted, o.offline_since`, clusterID).Scan(&name, &prev, &alerted, &since)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && prev != "offline" {
		return nil
	}
	if err != nil {
		return err
	}
	details := map[string]any{}
	if since != nil {
		details["offline_for_s"] = int(time.Since(*since).Seconds())
	}
	if alerted {
		if err := notify.Emit(ctx, tx, notify.Event{
			Type: notify.AgentOnline, Title: fmt.Sprintf("Agent back online: %s", name), Link: "/settings/clusters",
			Fields: map[string]string{"cluster": name},
		}); err != nil {
			return err
		}
	}
	return activity.Record(ctx, tx, activity.Entry{ActorKind: "agent", Action: "agent.online", ObjectType: "cluster", ObjectID: clusterID.String(),
		ClusterID: &clusterID, Details: details})
}

func normalizeOverride(s string) string {
	switch s {
	case "", ProviderAzure, ProviderAWS, ProviderGCP, ProviderOracle, ProviderHuawei, ProviderOnPrem:
		return s
	case "on-prem":
		return ProviderOnPrem
	}
	return ""
}

func (s *Service) seen(ctx context.Context, clusterID uuid.UUID) {
	var st string
	err := s.DB.QueryRow(ctx, `UPDATE clusters SET last_seen_at = now() WHERE id = $1 AND status <> 'revoked' RETURNING status`, clusterID).Scan(&st)
	if err == nil && st == "offline" {
		// Marked offline while the stream stayed open (silence > OfflineAfter).
		err = store.Tx(ctx, s.DB, func(tx pgx.Tx) error { return markOnline(ctx, tx, clusterID) })
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.Log.Warn("update last_seen", "cluster_id", clusterID, "err", err)
	}
}

// disconnected records the end of a control session and raises
// agent.flapping once per window when an agent keeps disconnecting.
func (s *Service) disconnected(clusterID uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	max, window := s.flapping()
	err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO agent_disconnects (cluster_id) VALUES ($1)`, clusterID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agent_disconnects WHERE cluster_id = $1 AND at < now() - interval '1 day'`, clusterID); err != nil {
			return err
		}
		var name string
		var n int
		err := tx.QueryRow(ctx, `UPDATE clusters SET flapping_alerted_at = now()
			WHERE id = $1 AND (flapping_alerted_at IS NULL OR flapping_alerted_at < now() - $2::interval)
			  AND (SELECT count(*) FROM agent_disconnects WHERE cluster_id = $1 AND at > now() - $2::interval) > $3
			RETURNING name, (SELECT count(*) FROM agent_disconnects WHERE cluster_id = $1 AND at > now() - $2::interval)`,
			clusterID, interval(window), max).Scan(&name, &n)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		s.Log.Warn("agent flapping", "cluster", name, "disconnects", n, "window", window.String())
		if err := notify.Emit(ctx, tx, notify.Event{Type: notify.AgentFlapping, Title: "Agent flapping: " + name,
			Link: "/settings/clusters", Fields: map[string]string{"cluster": name, "disconnects": fmt.Sprintf("%d in %s", n, window)}}); err != nil {
			return err
		}
		return activity.Record(ctx, tx, activity.Entry{ActorKind: "agent", Action: "agent.flapping", ObjectType: "cluster", ObjectID: clusterID.String(),
			ClusterID: &clusterID, Details: map[string]any{"disconnects": n, "window_s": int(window.Seconds())}})
	})
	if err != nil {
		s.Log.Warn("record agent disconnect", "cluster_id", clusterID, "err", err)
	}
}

// RunOfflineMonitor marks clusters offline after gateway.OfflineAfter
// without traffic (no message: short blips are common) and raises
// agent.offline once an outage lasts OfflineAlertAfter (F18).
func (s *Service) RunOfflineMonitor(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.CheckOffline(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("offline monitor", "err", err)
		}
	}
}

// CheckOffline is one pass of the offline monitor.
func (s *Service) CheckOffline(ctx context.Context) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		type c struct {
			id   uuid.UUID
			name string
		}
		scan := func(rows pgx.Rows) ([]c, error) {
			defer rows.Close()
			var out []c
			for rows.Next() {
				var x c
				if err := rows.Scan(&x.id, &x.name); err != nil {
					return nil, err
				}
				out = append(out, x)
			}
			return out, rows.Err()
		}
		rows, err := tx.Query(ctx, `UPDATE clusters SET status = 'offline', offline_since = last_seen_at, offline_alerted = false
			WHERE status = 'online' AND last_seen_at < now() - $1::interval RETURNING id, name`, interval(gateway.OfflineAfter))
		if err != nil {
			return err
		}
		gone, err := scan(rows)
		if err != nil {
			return err
		}
		for _, x := range gone {
			id := x.id
			if err := activity.Record(ctx, tx, activity.Entry{Action: "agent.offline", ObjectType: "cluster", ObjectID: id.String(), ClusterID: &id}); err != nil {
				return err
			}
			s.Log.Warn("agent offline", "cluster", x.name)
		}
		rows, err = tx.Query(ctx, `UPDATE clusters SET offline_alerted = true
			WHERE status = 'offline' AND NOT offline_alerted AND COALESCE(offline_since, last_seen_at) < now() - $1::interval
			RETURNING id, name`, interval(s.alertAfter()))
		if err != nil {
			return err
		}
		alert, err := scan(rows)
		if err != nil {
			return err
		}
		for _, x := range alert {
			if err := notify.Emit(ctx, tx, notify.Event{Type: notify.AgentOffline, Title: "Agent offline: " + x.name,
				Link: "/settings/clusters", Fields: map[string]string{"cluster": x.name, "offline for": "more than " + s.alertAfter().String()}}); err != nil {
				return err
			}
		}
		return nil
	})
}

func upsertNode(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, n *pb.Node) error {
	_, err := tx.Exec(ctx, `INSERT INTO nodes (cluster_id, name, provider_id, kubelet_version, region, zone, instance_type,
		cpu_capacity, mem_capacity, cpu_allocatable, mem_allocatable, roles, ready, seen_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
		ON CONFLICT (cluster_id, name) DO UPDATE SET provider_id=EXCLUDED.provider_id, kubelet_version=EXCLUDED.kubelet_version,
		region=EXCLUDED.region, zone=EXCLUDED.zone, instance_type=EXCLUDED.instance_type, cpu_capacity=EXCLUDED.cpu_capacity,
		mem_capacity=EXCLUDED.mem_capacity, cpu_allocatable=EXCLUDED.cpu_allocatable, mem_allocatable=EXCLUDED.mem_allocatable,
		roles=EXCLUDED.roles, ready=EXCLUDED.ready, seen_at=now()`,
		clusterID, n.Name, n.ProviderId, n.KubeletVersion, n.Region, n.Zone, n.InstanceType,
		n.CpuCapacityMilli, n.MemCapacityBytes, n.CpuAllocatableMilli, n.MemAllocatableBytes, nonNil(n.Roles), n.Ready)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// refreshDerived recomputes provider and region from the stored nodes.
func refreshDerived(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, apiVersion string) error {
	rows, err := tx.Query(ctx, `SELECT provider_id, region FROM nodes WHERE cluster_id = $1`, clusterID)
	if err != nil {
		return err
	}
	provs, regions := map[string]int{}, map[string]int{}
	for rows.Next() {
		var pid, region string
		if err := rows.Scan(&pid, &region); err != nil {
			rows.Close()
			return err
		}
		provs[DetectProvider(pid)]++
		if region != "" {
			regions[region]++
		}
	}
	rows.Close()
	_, err = tx.Exec(ctx, `UPDATE clusters SET provider = $2, region = $3, inventory_at = now(),
		api_version = CASE WHEN $4 <> '' THEN $4 ELSE api_version END WHERE id = $1`,
		clusterID, top(provs, ProviderOnPrem), top(regions, ""), apiVersion)
	return err
}

func top(m map[string]int, def string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) == 0 {
		return def
	}
	return keys[0]
}

func (s *Service) snapshot(ctx context.Context, clusterID uuid.UUID, snap *pb.InventorySnapshot) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		names := make([]string, 0, len(snap.Nodes))
		for _, n := range snap.Nodes {
			if err := upsertNode(ctx, tx, clusterID, n); err != nil {
				return err
			}
			names = append(names, n.Name)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM nodes WHERE cluster_id = $1 AND NOT (name = ANY($2))`, clusterID, names); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO namespaces (cluster_id, name) SELECT $1, unnest($2::text[])
			ON CONFLICT (cluster_id, name) DO UPDATE SET seen_at = now()`, clusterID, nonNil(snap.Namespaces)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM namespaces WHERE cluster_id = $1 AND NOT (name = ANY($2))`, clusterID, nonNil(snap.Namespaces)); err != nil {
			return err
		}
		ids := []string{}
		for _, t := range snap.Targets {
			if err := s.upsertTarget(ctx, tx, clusterID, t); err != nil {
				return err
			}
			ids = append(ids, t.TargetId)
		}
		rows, err := tx.Query(ctx, `SELECT id FROM targets WHERE cluster_id = $1 AND status <> 'gone' AND NOT (id = ANY($2))`, clusterID, ids)
		if err != nil {
			return err
		}
		var gone []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			gone = append(gone, id)
		}
		rows.Close()
		for _, id := range gone {
			if err := s.markGone(ctx, tx, clusterID, id); err != nil {
				return err
			}
		}
		return refreshDerived(ctx, tx, clusterID, snap.ApiVersion)
	})
}

func (s *Service) diff(ctx context.Context, clusterID uuid.UUID, d *pb.InventoryDiff) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		for _, n := range d.UpsertedNodes {
			if err := upsertNode(ctx, tx, clusterID, n); err != nil {
				return err
			}
		}
		if len(d.DeletedNodes) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM nodes WHERE cluster_id = $1 AND name = ANY($2)`, clusterID, d.DeletedNodes); err != nil {
				return err
			}
		}
		if len(d.AddedNamespaces) > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO namespaces (cluster_id, name) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING`, clusterID, d.AddedNamespaces); err != nil {
				return err
			}
		}
		if len(d.DeletedNamespaces) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM namespaces WHERE cluster_id = $1 AND name = ANY($2)`, clusterID, d.DeletedNamespaces); err != nil {
				return err
			}
		}
		return refreshDerived(ctx, tx, clusterID, d.ApiVersion)
	})
}

func (s *Service) targetUpsert(ctx context.Context, clusterID uuid.UUID, t *pb.Target) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error { return s.upsertTarget(ctx, tx, clusterID, t) })
}

func (s *Service) targetDelete(ctx context.Context, clusterID uuid.UUID, id string) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error { return s.markGone(ctx, tx, clusterID, id) })
}

func (s *Service) upsertTarget(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, t *pb.Target) error {
	// The server recomputes the ID: an agent cannot alias another target.
	if want := targetid.Compute(clusterID.String(), t.Namespace, t.Service, t.Port); want != t.TargetId {
		s.Log.Warn("target id mismatch; ignoring", "cluster_id", clusterID, "got", t.TargetId, "want", want)
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, port_name, engine, vault_provider, tls_server_name)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET port_name = EXCLUDED.port_name, engine = EXCLUDED.engine,
		  vault_provider = EXCLUDED.vault_provider, tls_server_name = EXCLUDED.tls_server_name, last_seen_at = now(),
		  status = CASE WHEN targets.status = 'gone' THEN
		    -- target status is about backups only (a configured Vault is still a backup candidate)
		    CASE WHEN EXISTS (SELECT 1 FROM backup_jobs j WHERE j.target_id = targets.id AND j.deleted_at IS NULL)
		         THEN 'configured' ELSE 'candidate' END
		    ELSE targets.status END`,
		t.TargetId, clusterID, t.Namespace, t.Service, t.Port, t.PortName, t.Engine, t.VaultProvider, t.TlsServerName)
	if err != nil {
		return err
	}
	if t.VaultProvider != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO vaults (target_id, provider) VALUES ($1, $2)
			ON CONFLICT (target_id) DO UPDATE SET provider = EXCLUDED.provider,
			  status = CASE WHEN vaults.status = 'gone' THEN CASE WHEN vaults.configured_at IS NULL THEN 'discovered' ELSE 'configured' END ELSE vaults.status END`,
			t.TargetId, t.VaultProvider); err != nil {
			return err
		}
	}
	for _, h := range s.OnTargetUpsert {
		if err := h(ctx, tx, clusterID, t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) markGone(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, id string) error {
	tag, err := tx.Exec(ctx, `UPDATE targets SET status = 'gone' WHERE id = $1 AND cluster_id = $2 AND status <> 'gone'`, id, clusterID)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE vaults SET status = 'gone' WHERE target_id = $1`, id); err != nil {
		return err
	}
	for _, h := range s.OnTargetGone {
		if err := h(ctx, tx, clusterID, id); err != nil {
			return err
		}
	}
	return nil
}
