package inventory

import (
	"context"
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
}

// Hooks returns the gateway hooks implemented by inventory.
func (s *Service) Hooks(h *gateway.Hooks) {
	h.Connected = s.connected
	h.Seen = s.seen
	h.Inventory = s.snapshot
	h.InventoryDiff = s.diff
	h.TargetUpsert = s.targetUpsert
	h.TargetDelete = s.targetDelete
}

func (s *Service) connected(ctx context.Context, clusterID uuid.UUID, h *pb.Hello) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var prev, name string
		err := tx.QueryRow(ctx, `SELECT status, name FROM clusters WHERE id = $1 FOR UPDATE`, clusterID).Scan(&prev, &name)
		if err != nil {
			return err
		}
		caps := h.GetCapabilities()
		_, err = tx.Exec(ctx, `UPDATE clusters SET status = 'online', last_seen_at = now(), agent_version = $2,
			bench_enabled = $3, bench_max_parallel = $4,
			provider_override = CASE WHEN provider_override = '' THEN $5 ELSE provider_override END
			WHERE id = $1`, clusterID, h.AgentVersion, caps.GetBenchEnabled(), caps.GetBenchMaxParallel(), normalizeOverride(h.ProviderOverride))
		if err != nil {
			return err
		}
		switch prev {
		case "offline":
			if err := notify.Emit(ctx, tx, notify.Event{
				Type: notify.AgentOnline, Title: fmt.Sprintf("Agent back online: %s", name), Link: "/settings/clusters",
				Fields: map[string]string{"cluster": name},
			}); err != nil {
				return err
			}
			return activity.Record(ctx, tx, activity.Entry{ActorKind: "agent", Action: "agent.online", ObjectType: "cluster", ObjectID: clusterID.String(), ClusterID: &clusterID})
		case "pending":
			return activity.Record(ctx, tx, activity.Entry{ActorKind: "agent", Action: "agent.connected", ObjectType: "cluster", ObjectID: clusterID.String(), ClusterID: &clusterID,
				Details: map[string]any{"agent_version": h.AgentVersion}})
		}
		return nil
	})
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
	if _, err := s.DB.Exec(ctx, `UPDATE clusters SET last_seen_at = now(),
		status = CASE WHEN status = 'offline' THEN 'online' ELSE status END WHERE id = $1 AND status <> 'revoked'`, clusterID); err != nil {
		s.Log.Warn("update last_seen", "cluster_id", clusterID, "err", err)
	}
}

// RunOfflineMonitor marks clusters offline after gateway.OfflineAfter
// without traffic and emits agent.offline once per transition.
func (s *Service) RunOfflineMonitor(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `UPDATE clusters SET status = 'offline'
				WHERE status = 'online' AND last_seen_at < now() - $1::interval RETURNING id, name`,
				fmt.Sprintf("%d seconds", int(gateway.OfflineAfter.Seconds())))
			if err != nil {
				return err
			}
			type c struct {
				id   uuid.UUID
				name string
			}
			var gone []c
			for rows.Next() {
				var x c
				if err := rows.Scan(&x.id, &x.name); err != nil {
					rows.Close()
					return err
				}
				gone = append(gone, x)
			}
			rows.Close()
			for _, x := range gone {
				if err := notify.Emit(ctx, tx, notify.Event{Type: notify.AgentOffline, Title: "Agent offline: " + x.name,
					Link: "/settings/clusters", Fields: map[string]string{"cluster": x.name}}); err != nil {
					return err
				}
				id := x.id
				if err := activity.Record(ctx, tx, activity.Entry{Action: "agent.offline", ObjectType: "cluster", ObjectID: id.String(), ClusterID: &id}); err != nil {
					return err
				}
				s.Log.Warn("agent offline", "cluster", x.name)
			}
			return nil
		})
		if err != nil && ctx.Err() == nil {
			s.Log.Error("offline monitor", "err", err)
		}
	}
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
