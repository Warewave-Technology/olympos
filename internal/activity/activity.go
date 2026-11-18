// Package activity writes and reads the append-only activity log (SPEC §17).
package activity

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// Entry is one activity log row.
type Entry struct {
	ID         uuid.UUID      `json:"id"`
	At         time.Time      `json:"at"`
	ActorID    *uuid.UUID     `json:"actor_id"`
	ActorName  string         `json:"actor_name"`
	ActorKind  string         `json:"actor_kind"` // user | system | agent
	Action     string         `json:"action"`
	ObjectType string         `json:"object_type"`
	ObjectID   string         `json:"object_id"`
	ClusterID  *uuid.UUID     `json:"cluster_id"`
	Details    map[string]any `json:"details"`
}

// Record appends an entry. Pass the transaction that performs the change so
// the log and the change commit together. Details MUST NOT contain secrets.
func Record(ctx context.Context, q store.Querier, e Entry) error {
	if e.ActorKind == "" {
		if e.ActorID != nil {
			e.ActorKind = "user"
		} else {
			e.ActorKind = "system"
		}
	}
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	d, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO activity_log (actor_principal_id, actor_kind, action, object_type, object_id, cluster_id, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, e.ActorID, e.ActorKind, e.Action, e.ObjectType, e.ObjectID, e.ClusterID, d)
	return err
}

// Filter narrows List.
type Filter struct {
	Action     string // prefix match, e.g. "backup."
	ObjectType string
	ActorID    *uuid.UUID
	ClusterIDs []uuid.UUID // nil = no restriction; scope enforcement by caller
	Since      *time.Time
	Before     *time.Time // cursor
	Limit      int
	Query      string
}

// List returns entries newest first.
func List(ctx context.Context, q store.Querier, f Filter) ([]Entry, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	sql := `SELECT a.id, a.at, a.actor_principal_id, COALESCE(NULLIF(p.display_name_snapshot,''), p.upn_snapshot, ''),
		a.actor_kind, a.action, a.object_type, a.object_id, a.cluster_id, a.details
		FROM activity_log a LEFT JOIN principals p ON p.id = a.actor_principal_id WHERE true`
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		sql += " AND " + replaceArg(cond, len(args))
	}
	if f.Action != "" {
		add("a.action LIKE $? || '%'", f.Action)
	}
	if f.ObjectType != "" {
		add("a.object_type = $?", f.ObjectType)
	}
	if f.ActorID != nil {
		add("a.actor_principal_id = $?", *f.ActorID)
	}
	if f.ClusterIDs != nil {
		add("(a.cluster_id IS NULL OR a.cluster_id = ANY($?))", f.ClusterIDs)
	}
	if f.Since != nil {
		add("a.at >= $?", *f.Since)
	}
	if f.Before != nil {
		add("a.at < $?", *f.Before)
	}
	if f.Query != "" {
		add("(a.action ILIKE '%' || $? || '%' OR a.object_id ILIKE '%' || $? || '%' OR a.details::text ILIKE '%' || $? || '%')", f.Query)
	}
	args = append(args, f.Limit)
	sql += " ORDER BY a.at DESC LIMIT $" + strconv.Itoa(len(args))
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var d []byte
		if err := rows.Scan(&e.ID, &e.At, &e.ActorID, &e.ActorName, &e.ActorKind, &e.Action, &e.ObjectType, &e.ObjectID, &e.ClusterID, &d); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(d, &e.Details)
		out = append(out, e)
	}
	return out, rows.Err()
}

// replaceArg substitutes every "$?" in cond with $n.
func replaceArg(cond string, n int) string {
	out := []byte{}
	ns := strconv.Itoa(n)
	for i := 0; i < len(cond); i++ {
		if cond[i] == '$' && i+1 < len(cond) && cond[i+1] == '?' {
			out = append(out, '$')
			out = append(out, ns...)
			i++
			continue
		}
		out = append(out, cond[i])
	}
	return string(out)
}
