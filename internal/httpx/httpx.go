// Package httpx holds HTTP helpers shared by API modules: the authenticated
// subject in context, JSON encoding, error shapes and scope helpers.
//
// Scope rule (SPEC §16): an object outside the caller's scope is reported as
// 404, never 403, so existence does not leak.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/store"
)

type ctxKey int

const subjectKey ctxKey = iota

// WithSubject stores the authenticated subject.
func WithSubject(ctx context.Context, s *authz.Subject) context.Context {
	return context.WithValue(ctx, subjectKey, s)
}

// Subject returns the authenticated subject (never nil behind auth middleware).
func Subject(r *http.Request) *authz.Subject {
	s, _ := r.Context().Value(subjectKey).(*authz.Subject)
	return s
}

// ActorID returns the subject's principal ID for audit rows.
func ActorID(r *http.Request) *uuid.UUID {
	if s := Subject(r); s != nil {
		id := s.Principal.ID
		return &id
	}
	return nil
}

// JSON writes v as JSON.
func JSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// ErrorBody is the shape of every error response.
type ErrorBody struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
}

// Error writes {"error": msg}.
func Error(w http.ResponseWriter, code int, msg string) {
	JSON(w, code, ErrorBody{Error: msg})
}

// FieldErrors writes a 422 with per-field messages.
func FieldErrors(w http.ResponseWriter, msg string, fields map[string]string) {
	JSON(w, http.StatusUnprocessableEntity, ErrorBody{Error: msg, Fields: fields})
}

// NotFound writes a 404.
func NotFound(w http.ResponseWriter) { Error(w, http.StatusNotFound, "not found") }

// Forbidden writes a 403 (only for objects the caller can see).
func Forbidden(w http.ResponseWriter, msg string) {
	if msg == "" {
		msg = "your role does not allow this action"
	}
	Error(w, http.StatusForbidden, msg)
}

// Internal logs err and writes a generic 500 (no internals leak).
func Internal(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	Error(w, http.StatusInternalServerError, "internal error")
}

// Decode reads a JSON body (max 1 MiB) and rejects unknown fields.
func Decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body: " + err.Error())
	}
	return nil
}

// UUIDParam parses a chi URL parameter; writes 404 on failure.
func UUIDParam(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		NotFound(w)
		return uuid.Nil, false
	}
	return id, true
}

// IntQuery parses an integer query parameter with a default.
func IntQuery(r *http.Request, name string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(name)); err == nil {
		return v
	}
	return def
}

// RequireAny is middleware that hides a whole route group from subjects
// without the permission on any scope.
func RequireAny(p authz.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !Subject(r).CanAny(p) {
				Forbidden(w, "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClusterLabels loads a cluster's Olympos labels.
func ClusterLabels(ctx context.Context, q store.Querier, clusterID uuid.UUID) (map[string]string, error) {
	var labels map[string]string
	err := q.QueryRow(ctx, `SELECT labels FROM clusters WHERE id = $1`, clusterID).Scan(&labels)
	return labels, store.NotFound(err)
}

// CanCluster checks p on a cluster. Returns (allowed, visible): visible is
// false when the caller cannot even read the cluster (answer 404).
func CanCluster(ctx context.Context, q store.Querier, s *authz.Subject, clusterID uuid.UUID, p authz.Permission) (allowed, visible bool, err error) {
	labels, err := ClusterLabels(ctx, q, clusterID)
	if errors.Is(err, store.ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return s.Can(p, labels), s.Can(authz.PermRead, labels), nil
}

// ScopedClusters returns IDs of clusters on which the subject has p.
func ScopedClusters(ctx context.Context, q store.Querier, s *authz.Subject, p authz.Permission) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx, `SELECT id, labels FROM clusters`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var labels map[string]string
		if err := rows.Scan(&id, &labels); err != nil {
			return nil, err
		}
		if s.Can(p, labels) {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// Record writes an activity row for the current user.
func Record(r *http.Request, q store.Querier, action, objectType, objectID string, clusterID *uuid.UUID, details map[string]any) error {
	return activity.Record(r.Context(), q, activity.Entry{
		ActorID: ActorID(r), Action: action, ObjectType: objectType, ObjectID: objectID, ClusterID: clusterID, Details: details,
	})
}
