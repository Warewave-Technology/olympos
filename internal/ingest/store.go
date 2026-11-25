package ingest

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// The audit rows of ingest credentials (migration 00026). The secret is never
// passed to any of these.

func insertCredential(ctx context.Context, db *store.DB, accessKey string, runID uuid.UUID, kind string, scope Scope,
	fingerprint string, created, expires time.Time) error {
	b, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `INSERT INTO ingest_credentials (access_key, run_id, kind, scope, fingerprint, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, accessKey, runID, kind, b, fingerprint, created, expires)
	return err
}

// revokeCredential sets revoked_at and reason once: a credential that is
// already revoked keeps its first reason.
func revokeCredential(ctx context.Context, db *store.DB, accessKey, reason string, at time.Time) error {
	_, err := db.Exec(ctx, `UPDATE ingest_credentials SET revoked_at = $2, reason = $3
		WHERE access_key = $1 AND revoked_at IS NULL`, accessKey, at, reason)
	return err
}

func revokeAllCredentials(ctx context.Context, db *store.DB, reason string, at time.Time) error {
	_, err := db.Exec(ctx, `UPDATE ingest_credentials SET revoked_at = $1, reason = $2 WHERE revoked_at IS NULL`, at, reason)
	return err
}
