package approvals

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// KVMeta is the KV v2 metadata of one secret path.
type KVMeta struct {
	Current  int
	Versions map[int]KVVersion
}

// KVVersion is one version of a secret.
type KVVersion struct {
	Created   time.Time
	Destroyed bool
}

// Inspector reads KV metadata with the Olympos AppRole (implemented by
// internal/vaults). It returns nil, nil when the path does not exist.
type Inspector interface {
	KVMetadata(ctx context.Context, vaultID uuid.UUID, mount, path string) (*KVMeta, error)
}

const (
	// reconcileAfter: a request still 'applying' this long after transaction
	// 1 lost its outcome (the Vault call is bounded by applyTimeout).
	reconcileAfter = 2 * time.Minute
	// clockSkew tolerated between the database clock (applying_at) and the
	// vault's created_time.
	clockSkew = time.Minute
)

// ReconcileApplying settles requests left in 'applying' (the outcome of the
// Vault call was never recorded) from the KV metadata. Run by the vaults
// maintenance leader every minute:
//   - every write is visible (version base+1 created after 'applying',
//     destroyed versions destroyed): applied, cr.applied_reconciled;
//   - no write is visible (version still base): failed, apply_unknown;
//     nothing changed and a new request can retry;
//   - anything else: failed, conflict.
//
// A vault that cannot be read leaves the request in 'applying'.
func (a *API) ReconcileApplying(ctx context.Context) (int, error) {
	if a.Inspector == nil {
		return 0, nil
	}
	type due struct {
		id, vaultID uuid.UUID
		at          time.Time
	}
	rows, err := a.DB.Query(ctx, `SELECT id, vault_id, applying_at FROM change_requests
		WHERE status = 'applying' AND applying_at < now() - $1::interval ORDER BY applying_at LIMIT 50`,
		fmt.Sprintf("%d seconds", int(reconcileAfter.Seconds())))
	if err != nil {
		return 0, err
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.vaultID, &d.at); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, d := range list {
		if err := a.reconcileOne(ctx, d.id, d.vaultID, d.at); err != nil {
			a.Log.Warn("change request still applying: vault state unknown", "cr_id", d.id, "vault_id", d.vaultID, "err", err)
			continue
		}
		n++
	}
	return n, nil
}

func (a *API) reconcileOne(ctx context.Context, crID, vaultID uuid.UUID, applyingAt time.Time) error {
	v, err := LoadVault(ctx, a.DB, vaultID)
	if err != nil {
		return err
	}
	plan, err := planShape(ctx, a.DB, crID)
	if err != nil {
		return err
	}
	since := applyingAt.Add(-clockSkew)
	var done []Applied
	conflict := false
	for _, w := range plan {
		meta, err := a.Inspector.KVMetadata(ctx, vaultID, w.Mount, w.Path)
		if err != nil {
			return err
		}
		switch st, ver := writeState(w, meta, since); st {
		case writeDone:
			done = append(done, Applied{Mount: w.Mount, Path: w.Path, Kind: w.Kind, Version: ver})
		case writeConflict:
			conflict = true
		}
	}
	var applyErr error
	code := ""
	switch {
	case len(done) == len(plan):
	case len(done) == 0 && !conflict:
		code = FailApplyUnknown
		applyErr = &SafeError{Msg: "Olympos could not record the outcome of the write, and the vault shows no new version: " +
			"nothing was changed. Open a new request to try again."}
	default:
		code = FailConflict
		applyErr = &SafeError{Msg: "Olympos could not record the outcome of the write, and the vault shows changes Olympos " +
			"cannot attribute to this request. Review the secret versions in the vault."}
	}
	return store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		if err := LockVault(ctx, tx, vaultID); err != nil {
			return err
		}
		return a.finishApply(ctx, tx, crID, v, done, applyErr, code, len(plan), true)
	})
}

type writeOutcome int

const (
	writeNotDone writeOutcome = iota
	writeDone
	writeConflict
)

// writeState tells whether w is visible in meta. Data writes produce
// exactly version base+1 (cas); destroys mark every listed version.
func writeState(w Write, meta *KVMeta, since time.Time) (writeOutcome, int) {
	if w.Kind == WriteDestroy {
		if meta == nil {
			return writeConflict, 0
		}
		n := 0
		for _, v := range w.Versions {
			if meta.Versions[v].Destroyed {
				n++
			}
		}
		switch n {
		case 0:
			return writeNotDone, 0
		case len(w.Versions):
			return writeDone, 0
		}
		return writeConflict, 0
	}
	if meta == nil || meta.Current == w.BaseVersion {
		return writeNotDone, 0
	}
	want := w.BaseVersion + 1
	if v, ok := meta.Versions[want]; ok && meta.Current == want && !v.Created.Before(since) {
		return writeDone, want
	}
	return writeConflict, 0
}

// planShape is the write plan of a request without values (the reconciler
// only needs paths, kinds, base versions and destroyed versions).
func planShape(ctx context.Context, q store.Querier, crID uuid.UUID) ([]Write, error) {
	rows, err := q.Query(ctx, `SELECT mount, path, COALESCE(key, ''), op, base_version, versions
		FROM change_items WHERE cr_id = $1 ORDER BY created_at, id`, crID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Item
	for rows.Next() {
		var it Item
		var op string
		if err := rows.Scan(&it.Mount, &it.Path, &it.Key, &op, &it.BaseVersion, &it.Versions); err != nil {
			return nil, err
		}
		it.Op = Op(op)
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return Plan(items)
}
