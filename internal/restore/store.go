package restore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// requestSelect never selects sealed_token, wrapped_dek or a credential's
// secret: only whether a token is held and the credential's public part.
// The backup's cluster may be revoked (the source of a disaster recovery);
// its labels still decide who sees the request.
const requestSelect = `SELECT rr.id, rr.status, rr.engine, rr.source_run_id, rr.source_copy_run_id, rr.source_destination_id, d.name, d.kind,
	st.id, sc.id, sc.name, sc.labels, st.namespace, st.service,
	t.id, tc.id, tc.name, tc.labels, t.namespace, t.service, t.port, t.vault_provider,
	rr.databases, rr.options, cr.kind, cr.keyvault_name, cr.secret_name, cr.username, rr.sealed_token IS NOT NULL,
	rr.maker_principal_id, rr.checker_principal_id, rr.justification, rr.break_glass, rr.created_at, rr.expires_at,
	rr.decided_at, rr.decision_comment, rr.approved_expires_at, rr.started_at, rr.finished_at, rr.progress, rr.result, rr.error
	FROM restore_requests rr
	JOIN backup_runs r ON r.id = rr.source_run_id JOIN backup_jobs j ON j.id = r.job_id
	JOIN targets st ON st.id = j.target_id JOIN clusters sc ON sc.id = st.cluster_id
	JOIN targets t ON t.id = rr.target_id JOIN clusters tc ON tc.id = t.cluster_id
	JOIN destinations d ON d.id = rr.source_destination_id
	LEFT JOIN credentials cr ON cr.id = rr.credential_id`

func scanRequest(row pgx.Row) (*Request, error) {
	rq := &Request{}
	var st string
	var opts []byte
	var credKind, kvName, secName, user *string
	err := row.Scan(&rq.ID, &st, &rq.Engine, &rq.Source.RunID, &rq.Source.CopyRunID, &rq.Source.DestinationID,
		&rq.Source.DestinationName, &rq.Source.DestinationKind,
		&rq.Source.TargetID, &rq.Source.ClusterID, &rq.Source.ClusterName, &rq.clusters.Run, &rq.Source.Namespace, &rq.Source.Service,
		&rq.Target.ID, &rq.Target.ClusterID, &rq.Target.ClusterName, &rq.clusters.Target, &rq.Target.Namespace, &rq.Target.Service,
		&rq.Target.Port, &rq.Target.VaultProvider,
		&rq.Databases, &opts, &credKind, &kvName, &secName, &user, &rq.HasVaultToken,
		&rq.makerID, &rq.checkerID, &rq.Justification, &rq.BreakGlass, &rq.CreatedAt, &rq.ExpiresAt,
		&rq.DecidedAt, &rq.DecisionComment, &rq.ApprovedExpiresAt, &rq.StartedAt, &rq.FinishedAt, &rq.Progress, &rq.Result, &rq.Error)
	if err != nil {
		return nil, err
	}
	rq.Status = Status(st)
	_ = json.Unmarshal(opts, &rq.Options)
	if rq.Databases == nil {
		rq.Databases = []string{}
	}
	if credKind != nil {
		c := &CredentialRef{Source: *credKind, Username: *user}
		if *credKind == backup.SourceKeyVault {
			c.Ref = secrets.Ref{Vault: *kvName, Secret: *secName}.String()
		}
		rq.Credential = c
	}
	return rq, nil
}

// visible: read on the backup's cluster, where the data comes from. A
// reader of the target's cluster only does not see the source's names, run
// or databases. The maker (read there) and every valid checker (operate on
// both clusters) do.
func visible(sub *authz.Subject, c Clusters) bool {
	return sub.Can(authz.PermRead, c.Run)
}

// loadRequest loads a request without any scope check.
func loadRequest(ctx context.Context, q store.Querier, id uuid.UUID) (*Request, error) {
	rq, err := scanRequest(q.QueryRow(ctx, requestSelect+` WHERE rr.id = $1`, id))
	if err != nil {
		return nil, store.NotFound(err)
	}
	return rq, nil
}

// GetRequest loads one request as sub sees it; store.ErrNotFound when it
// does not exist or is outside sub's scope.
func GetRequest(ctx context.Context, q store.Querier, sub *authz.Subject, id uuid.UUID, now time.Time) (*Request, error) {
	rq, err := loadRequest(ctx, q, id)
	if err != nil {
		return nil, err
	}
	if !visible(sub, rq.clusters) {
		return nil, store.ErrNotFound
	}
	return rq, fill(ctx, q, rq, sub, now)
}

// Filter narrows ListRequests.
type Filter struct {
	Status       string
	MakerID      *uuid.UUID
	RunID        *uuid.UUID
	WaitingForMe bool
	Limit        int
}

// ListRequests returns the requests visible to sub, newest first. Scope is
// applied in SQL (the backup's cluster among those sub may read), and
// waiting_for_me pages on until Limit matching requests are found, so no
// visible request is dropped by the limit.
func ListRequests(ctx context.Context, q store.Querier, sub *authz.Subject, f Filter, now time.Time) ([]*Request, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 200
	}
	if f.WaitingForMe {
		f.Status = string(StatusPending)
	}
	readable, err := httpx.ScopedClusters(ctx, q, sub, authz.PermRead)
	if err != nil {
		return nil, err
	}
	out := []*Request{}
	for offset := 0; ; offset += f.Limit {
		rows, err := q.Query(ctx, requestSelect+`
			WHERE sc.id = ANY($1) AND ($2 = '' OR rr.status = $2) AND ($3::uuid IS NULL OR rr.maker_principal_id = $3)
			  AND ($4::uuid IS NULL OR rr.source_run_id = $4)
			ORDER BY rr.created_at DESC, rr.id LIMIT $5 OFFSET $6`, readable, f.Status, f.MakerID, f.RunID, f.Limit, offset)
		if err != nil {
			return nil, err
		}
		var page []*Request
		for rows.Next() {
			rq, err := scanRequest(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			page = append(page, rq)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, rq := range page {
			if !visible(sub, rq.clusters) {
				continue // labels changed since ScopedClusters; never show
			}
			if err := fill(ctx, q, rq, sub, now); err != nil {
				return nil, err
			}
			if f.WaitingForMe && !rq.CanApprove {
				continue
			}
			out = append(out, rq)
			if len(out) >= f.Limit {
				return out, nil
			}
		}
		if len(page) < f.Limit {
			return out, nil
		}
	}
}

// fill adds the principals and what sub may do with the request.
func fill(ctx context.Context, q store.Querier, rq *Request, sub *authz.Subject, now time.Time) error {
	var err error
	if rq.Maker, err = authz.GetPrincipal(ctx, q, rq.makerID); err != nil {
		return err
	}
	if rq.checkerID != nil {
		p, err := authz.GetPrincipal(ctx, q, *rq.checkerID)
		if err != nil {
			return err
		}
		rq.Checker = &p
	}
	if err := CheckDecide(sub, rq.Maker, rq.clusters, rq.Status, rq.ExpiresAt, now); err != nil {
		rq.ApproveDisabledReason = err.Error()
	} else {
		rq.CanApprove = true
	}
	rq.CanCancel = CheckCancel(sub, rq.Maker, rq.Status) == nil
	return nil
}

// lockedRequest is the state of a request read under FOR UPDATE.
type lockedRequest struct {
	ID                uuid.UUID
	Status            Status
	MakerID           uuid.UUID
	ExpiresAt         time.Time
	ApprovedExpiresAt *time.Time
	TargetID          string
	TargetClusterID   uuid.UUID
	Clusters          Clusters
}

var errNotFound = errors.New("not found")

func lockRequest(ctx context.Context, tx pgx.Tx, id uuid.UUID) (lockedRequest, error) {
	var l lockedRequest
	var st string
	err := tx.QueryRow(ctx, `SELECT rr.id, rr.status, rr.maker_principal_id, rr.expires_at, rr.approved_expires_at, rr.target_id,
		tc.id, tc.labels, sc.labels
		FROM restore_requests rr JOIN targets t ON t.id = rr.target_id JOIN clusters tc ON tc.id = t.cluster_id
		JOIN backup_runs r ON r.id = rr.source_run_id JOIN backup_jobs j ON j.id = r.job_id
		JOIN targets st ON st.id = j.target_id JOIN clusters sc ON sc.id = st.cluster_id
		WHERE rr.id = $1 FOR UPDATE OF rr`, id).
		Scan(&l.ID, &st, &l.MakerID, &l.ExpiresAt, &l.ApprovedExpiresAt, &l.TargetID, &l.TargetClusterID, &l.Clusters.Target, &l.Clusters.Run)
	l.Status = Status(st)
	if errors.Is(err, pgx.ErrNoRows) {
		return l, errNotFound
	}
	return l, err
}

// Wipe removes a request's secrets: the sealed Vault token and the target
// credential (the credentials row is deleted, whether stored or a Key Vault
// reference). Call it with every move to a terminal state, in the same
// transaction; the restore_requests_scrub trigger clears the token as well.
func Wipe(ctx context.Context, q store.Querier, id uuid.UUID) error {
	var cred *uuid.UUID
	if err := q.QueryRow(ctx, `SELECT credential_id FROM restore_requests WHERE id = $1`, id).Scan(&cred); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE restore_requests SET sealed_token = NULL, wrapped_dek = NULL, kek_version = '', credential_id = NULL
		WHERE id = $1`, id); err != nil {
		return err
	}
	if cred != nil {
		if _, err := q.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, *cred); err != nil {
			return err
		}
	}
	return nil
}

// summary is the one-line description of a request in notifications.
func summary(rq *Request) map[string]string {
	f := map[string]string{
		"Backup": rq.Source.ClusterName + " / " + rq.Source.Namespace + "/" + rq.Source.Service,
		"Target": rq.Target.ClusterName + " / " + rq.Target.Namespace + "/" + rq.Target.Service,
	}
	if len(rq.Databases) > 0 {
		f["Databases"] = strings.Join(rq.Databases, ", ")
	}
	return f
}
