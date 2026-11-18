package vaults

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/findings"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/vaults/vclient"
)

// Index limits.
const (
	maxDepth   = 32
	maxSecrets = 20000
)

// VersionInfo is one KV v2 version (metadata only).
type VersionInfo struct {
	Version      int    `json:"version"`
	CreatedTime  string `json:"created_time"`
	DeletionTime string `json:"deletion_time"`
	Destroyed    bool   `json:"destroyed"`
}

type indexEntry struct {
	Path     string
	Keys     []string
	Current  int
	Updated  *time.Time
	Versions []VersionInfo
}

func intOf(v any) int {
	switch x := v.(type) {
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

// walk lists <mount>metadata/ recursively (LIST), then reads metadata and
// subkeys of each secret. subkeys returns key names with null values: the
// Olympos token never reads a value.
func walk(ctx context.Context, c *vclient.Client, mount string) ([]indexEntry, error) {
	var out []indexEntry
	var rec func(prefix string, depth int) error
	rec = func(prefix string, depth int) error {
		if depth > maxDepth {
			return nil
		}
		sec, err := c.Logical().ListWithContext(ctx, mount+"metadata/"+prefix)
		if err != nil {
			return fmt.Errorf("list %smetadata/%s: %w", mount, prefix, vclient.Sanitize(err))
		}
		if sec == nil || sec.Data == nil {
			return nil
		}
		keys, _ := sec.Data["keys"].([]any)
		names := make([]string, 0, len(keys))
		for _, k := range keys {
			if s, ok := k.(string); ok && s != "" {
				names = append(names, s)
			}
		}
		sort.Strings(names)
		for _, k := range names {
			if strings.HasSuffix(k, "/") {
				if err := rec(prefix+k, depth+1); err != nil {
					return err
				}
				continue
			}
			if len(out) >= maxSecrets {
				return nil
			}
			e, err := readSecret(ctx, c, mount, prefix+k)
			if err != nil {
				return err
			}
			if e != nil {
				out = append(out, *e)
			}
		}
		return nil
	}
	return out, rec("", 0)
}

func readSecret(ctx context.Context, c *vclient.Client, mount, path string) (*indexEntry, error) {
	md, err := c.Logical().ReadWithContext(ctx, mount+"metadata/"+path)
	if err != nil {
		return nil, fmt.Errorf("read metadata of %s%s: %w", mount, path, vclient.Sanitize(err))
	}
	if md == nil || md.Data == nil {
		return nil, nil // removed meanwhile
	}
	e := &indexEntry{Path: path, Current: intOf(md.Data["current_version"]), Keys: []string{}}
	if s, ok := md.Data["updated_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			e.Updated = &t
		}
	}
	if vs, ok := md.Data["versions"].(map[string]any); ok {
		for k, v := range vs {
			n, _ := strconv.Atoi(k)
			m, _ := v.(map[string]any)
			vi := VersionInfo{Version: n}
			vi.CreatedTime, _ = m["created_time"].(string)
			vi.DeletionTime, _ = m["deletion_time"].(string)
			vi.Destroyed, _ = m["destroyed"].(bool)
			e.Versions = append(e.Versions, vi)
		}
		sort.Slice(e.Versions, func(i, j int) bool { return e.Versions[i].Version < e.Versions[j].Version })
	}
	// Key names of the current version. A deleted/destroyed current version
	// has no subkeys (404): keys stay empty.
	sk, err := c.Logical().ReadWithDataWithContext(ctx, mount+"subkeys/"+path, map[string][]string{"depth": {"1"}})
	if err != nil {
		if code := vclient.StatusCode(err); code == 404 {
			return e, nil
		}
		return nil, fmt.Errorf("read subkeys of %s%s: %w", mount, path, vclient.Sanitize(err))
	}
	if sk != nil && sk.Data != nil {
		if m, ok := sk.Data["subkeys"].(map[string]any); ok {
			for k := range m {
				e.Keys = append(e.Keys, k)
			}
			sort.Strings(e.Keys)
		}
	}
	return e, nil
}

// Refresh rebuilds the index of one vault and evaluates drift. Refreshes of
// the same vault are serialized (a refresh requested after a write always
// sees it).
func (s *Service) Refresh(ctx context.Context, vaultID uuid.UUID) error {
	s.mu.Lock()
	if s.refreshing == nil {
		s.refreshing = map[uuid.UUID]*sync.Mutex{}
	}
	m := s.refreshing[vaultID]
	if m == nil {
		m = &sync.Mutex{}
		s.refreshing[vaultID] = m
	}
	s.mu.Unlock()
	m.Lock()
	defer m.Unlock()
	err := s.refresh(ctx, vaultID)
	if err != nil && !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
		s.setError(ctx, vaultID, "index refresh failed: "+err.Error())
	}
	return err
}

func (s *Service) refresh(ctx context.Context, vaultID uuid.UUID) error {
	r, err := loadRow(ctx, s.DB, vaultID)
	if err != nil {
		return err
	}
	if r.Status != "configured" {
		return nil
	}
	c, done, err := s.approle(ctx, r, requestTimout)
	if err != nil {
		return err
	}
	defer done()
	mounts := r.managedMounts()
	byMount := map[string][]indexEntry{}
	for _, m := range mounts {
		es, err := walk(ctx, c, m)
		if err != nil {
			return err
		}
		byMount[m] = es
	}
	done()
	indexed := map[string]bool{}
	for _, m := range r.IndexedMounts {
		indexed[m] = true
	}
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := approvals.LockVault(ctx, tx, r.ID); err != nil {
			return err
		}
		for _, m := range mounts {
			// The first index of a mount records a baseline: versions that
			// existed before Olympos managed the mount are not drift.
			baseline := !indexed[m]
			paths := []string{}
			for _, e := range byMount[m] {
				paths = append(paths, e.Path)
				vb, _ := json.Marshal(e.Versions)
				if _, err := tx.Exec(ctx, `INSERT INTO vault_secret_index (vault_id, mount, path, keys, current_version, versions, updated_time,
						managed, baseline_version, drift_checked_version)
					VALUES ($1,$2,$3,$4,$5,$6,$7, true, CASE WHEN $8 THEN $5 ELSE 0 END, CASE WHEN $8 THEN $5 ELSE 0 END)
					ON CONFLICT (vault_id, mount, path) DO UPDATE SET keys = EXCLUDED.keys, current_version = EXCLUDED.current_version,
					  versions = EXCLUDED.versions, updated_time = EXCLUDED.updated_time`,
					r.ID, m, e.Path, e.Keys, e.Current, vb, e.Updated, baseline); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `DELETE FROM vault_secret_index WHERE vault_id = $1 AND mount = $2 AND NOT (path = ANY($3))`,
				r.ID, m, paths); err != nil {
				return err
			}
			indexed[m] = true
		}
		if _, err := tx.Exec(ctx, `DELETE FROM vault_secret_index WHERE vault_id = $1 AND NOT (mount = ANY($2))`, r.ID, mounts); err != nil {
			return err
		}
		im := []string{}
		for _, m := range mounts {
			if indexed[m] {
				im = append(im, m)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE vaults SET last_index_at = $2, indexed_mounts = $3, last_error = '' WHERE id = $1`,
			r.ID, s.now(), im); err != nil {
			return err
		}
		return s.checkDrift(ctx, tx, r)
	})
}

// DriftControlID identifies drift findings of one vault.
func DriftControlID(vaultID uuid.UUID) string { return "unmanaged-change:" + vaultID.String() }

// checkDrift compares the index with versions produced by applied change
// requests (§11.5). Every version newer than the baseline that Olympos did
// not write is reported once: finding vault-drift + vault.unmanaged_write.
// The caller holds approvals.LockVault.
func (s *Service) checkDrift(ctx context.Context, tx pgx.Tx, r *row) error {
	managed := map[string]map[int]bool{}
	rows, err := tx.Query(ctx, `SELECT mount, path, version FROM vault_managed_versions WHERE vault_id = $1`, r.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var m, p string
		var v int
		if err := rows.Scan(&m, &p, &v); err != nil {
			rows.Close()
			return err
		}
		if managed[m+p] == nil {
			managed[m+p] = map[int]bool{}
		}
		managed[m+p][v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	type idx struct {
		mount, path                string
		current, baseline, checked int
	}
	var all []idx
	rows, err = tx.Query(ctx, `SELECT mount, path, current_version, baseline_version, drift_checked_version FROM vault_secret_index
		WHERE vault_id = $1 ORDER BY mount, path`, r.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var x idx
		if err := rows.Scan(&x.mount, &x.path, &x.current, &x.baseline, &x.checked); err != nil {
			rows.Close()
			return err
		}
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// Paths of requests still 'applying' are skipped (not advanced): their
	// new version is Olympos' own until the outcome is recorded or
	// reconciled (F4), then the next pass evaluates it.
	applying := map[string]bool{}
	rows, err = tx.Query(ctx, `SELECT DISTINCT i.mount || i.path FROM change_items i JOIN change_requests cr ON cr.id = i.cr_id
		WHERE cr.vault_id = $1 AND cr.status = 'applying'`, r.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			rows.Close()
			return err
		}
		applying[ref] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	vaultName := r.Namespace + "/" + r.Service
	for _, x := range all {
		ref := x.mount + x.path
		if applying[ref] {
			continue
		}
		m := managed[ref]
		if x.current < x.checked { // metadata deleted and recreated
			x.checked = 0
		}
		from := x.baseline
		if x.checked > from {
			from = x.checked
		}
		var unmanaged []int
		for v := from + 1; v <= x.current; v++ {
			if !m[v] {
				unmanaged = append(unmanaged, v)
			}
		}
		latestManaged := x.current <= x.baseline || m[x.current]
		if len(unmanaged) > 0 {
			if _, err := findings.Open(ctx, tx, findings.Finding{Source: findings.SourceVaultDrift, ClusterID: r.ClusterID,
				ControlID: DriftControlID(r.ID), Severity: "high", ResourceRef: ref, Title: "Unmanaged change",
				Details: map[string]any{"vault_id": r.ID, "vault": vaultName, "mount": x.mount, "path": x.path,
					"versions": unmanaged, "current_version": x.current}}, nil); err != nil {
				return err
			}
			for _, v := range unmanaged {
				if err := notify.Emit(ctx, tx, notify.Event{Type: notify.VaultUnmanagedWrite,
					Key:   fmt.Sprintf("%s:%s:%s:%d", notify.VaultUnmanagedWrite, r.ID, ref, v),
					Title: "Unmanaged change to a vault secret", Link: "/vaults/" + r.ID.String(),
					Fields: map[string]string{"Vault": vaultName, "Cluster": r.ClusterName, "Secret": ref, "Version": strconv.Itoa(v)},
				}); err != nil {
					return err
				}
				if err := activity.Record(ctx, tx, activity.Entry{Action: "vault.unmanaged_write", ObjectType: "vault", ObjectID: r.ID.String(),
					ClusterID: &r.ClusterID, Details: map[string]any{"secret": ref, "version": v}}); err != nil {
					return err
				}
			}
			s.Log.Warn("vault drift: unmanaged write", "vault_id", r.ID, "secret", ref, "versions", unmanaged)
		} else if latestManaged {
			// Olympos wrote over the unmanaged version: back under management.
			if _, err := findings.Resolve(ctx, tx, findings.SourceVaultDrift, r.ClusterID, DriftControlID(r.ID), ref, nil); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE vault_secret_index SET managed = $4, drift_checked_version = $5
			WHERE vault_id = $1 AND mount = $2 AND path = $3`, r.ID, x.mount, x.path, latestManaged, x.current); err != nil {
			return err
		}
	}
	// Findings for secrets that no longer exist are resolved.
	_, err = tx.Exec(ctx, `UPDATE findings f SET status = 'resolved', resolved_at = now()
		WHERE f.source = 'vault-drift' AND f.status = 'open' AND f.control_id = $2
		  AND NOT EXISTS (SELECT 1 FROM vault_secret_index i WHERE i.vault_id = $1 AND i.mount || i.path = f.resource_ref)`,
		r.ID, DriftControlID(r.ID))
	return err
}

// RefreshAll refreshes every configured vault (leader job).
func (s *Service) RefreshAll(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT v.id FROM vaults v JOIN targets t ON t.id = v.target_id JOIN clusters c ON c.id = t.cluster_id
		WHERE v.status = 'configured' AND c.status <> 'revoked' ORDER BY v.last_index_at NULLS FIRST`)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		if err := s.Refresh(cctx, id); err != nil && ctx.Err() == nil {
			s.Log.Error("vault index refresh", "vault_id", id, "err", err)
		}
		cancel()
	}
	return rows.Err()
}
