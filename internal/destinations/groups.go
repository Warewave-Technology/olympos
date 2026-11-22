package destinations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Destination groups: a backup job can write one dump to every member of a
// group (docs/design/destination-groups.md). Reads follow destinations (any
// role that may read them), writes are admin with scope "all". Olympos never
// deletes anything in a destination, so removing a member or a group only
// changes what future runs write to.

const (
	minGroupMembers = 2
	maxGroupMembers = 4
	maxGroupName    = 80
	maxGroupDesc    = 500
)

// routesGroups mounts /destination-groups next to /destinations.
func (a *API) routesGroups(r chi.Router) {
	r.Route("/destination-groups", func(r chi.Router) {
		r.Use(httpx.RequireAny(authz.PermRead))
		r.Get("/", a.listGroups)
		r.Post("/", a.createGroup)
		r.Get("/{id}", a.getGroup)
		r.Patch("/{id}", a.patchGroup)
		r.Delete("/{id}", a.deleteGroup)
	})
}

// GroupInput is the create/patch body (patch: absent fields keep their value;
// member_ids replaces the whole member list and its order).
type GroupInput struct {
	Name        *string      `json:"name"`
	Description *string      `json:"description"`
	MemberIDs   *[]uuid.UUID `json:"member_ids"`
}

// GroupMember is a member destination, in position order.
type GroupMember struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Kind string    `json:"kind"`
}

// GroupView is the API shape of a group. It carries only the number of jobs
// that use it: cluster-scoped operators may read groups but not the jobs of
// other clusters.
type GroupView struct {
	ID          uuid.UUID     `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Members     []GroupMember `json:"members"`
	Jobs        int           `json:"jobs"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// groupSelect counts every job row that points at the group, soft-deleted
// ones included: the foreign key keeps them there.
const groupSelect = `SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
	(SELECT count(*) FROM backup_jobs j WHERE j.destination_group_id = g.id)
	FROM destination_groups g`

func scanGroups(ctx context.Context, q store.Querier, where string, args ...any) ([]GroupView, error) {
	rows, err := q.Query(ctx, groupSelect+where+` ORDER BY g.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupView{}
	idx := map[uuid.UUID]int{}
	for rows.Next() {
		g := GroupView{Members: []GroupMember{}}
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.Jobs); err != nil {
			return nil, err
		}
		idx[g.ID] = len(out)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if len(out) == 0 {
		return out, nil
	}
	mrows, err := q.Query(ctx, `SELECT m.group_id, d.id, d.name, d.kind
		FROM destination_group_members m JOIN destinations d ON d.id = m.destination_id
		ORDER BY m.group_id, m.position`)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var gid uuid.UUID
		var m GroupMember
		if err := mrows.Scan(&gid, &m.ID, &m.Name, &m.Kind); err != nil {
			return nil, err
		}
		if i, ok := idx[gid]; ok {
			out[i].Members = append(out[i].Members, m)
		}
	}
	return out, mrows.Err()
}

func loadGroup(ctx context.Context, q store.Querier, id uuid.UUID) (GroupView, error) {
	gs, err := scanGroups(ctx, q, ` WHERE g.id = $1`, id)
	if err != nil {
		return GroupView{}, err
	}
	if len(gs) == 0 {
		return GroupView{}, store.ErrNotFound
	}
	return gs[0], nil
}

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := scanGroups(r.Context(), a.DB, ``)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": gs})
}

func (a *API) getGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	g, err := loadGroup(r.Context(), a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, g)
}

// ---------------------------------------------------------------- validation

func validGroupName(name string, f map[string]string) {
	switch {
	case name == "":
		f["name"] = "required"
	case len(name) > maxGroupName:
		f["name"] = fmt.Sprintf("at most %d characters", maxGroupName)
	}
}

// location is where a destination writes: two members with the same kind and
// location (prefix included) would hold the same object twice in one place,
// which is a copy in name only.
func (d groupDest) location() string {
	switch d.kind {
	case "s3":
		return strings.Join([]string{d.kind, d.endpoint, d.bucket, d.prefix}, "\x00")
	case "nfs":
		return strings.Join([]string{d.kind, d.path, d.prefix}, "\x00")
	default:
		return strings.Join([]string{d.kind, d.endpoint, d.account, d.container, d.prefix}, "\x00")
	}
}

type groupDest struct {
	id                                               uuid.UUID
	name, kind, prefix, endpoint, account, container string
	bucket, path                                     string
}

// checkMembers validates a member list and returns the field error for
// "member_ids" ("" when valid).
func checkMembers(ctx context.Context, q store.Querier, ids []uuid.UUID) (string, error) {
	if len(ids) < minGroupMembers || len(ids) > maxGroupMembers {
		return fmt.Sprintf("a group needs %d to %d destinations", minGroupMembers, maxGroupMembers), nil
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		if seen[id] {
			return "a destination can be in a group only once", nil
		}
		seen[id] = true
	}
	rows, err := q.Query(ctx, `SELECT id, name, kind, prefix, endpoint_override, account, container, bucket, path
		FROM destinations WHERE id = ANY($1)`, ids)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	byID := map[uuid.UUID]groupDest{}
	for rows.Next() {
		var d groupDest
		if err := rows.Scan(&d.id, &d.name, &d.kind, &d.prefix, &d.endpoint, &d.account, &d.container, &d.bucket, &d.path); err != nil {
			return "", err
		}
		byID[d.id] = d
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	locs := map[string]groupDest{}
	for _, id := range ids {
		d, ok := byID[id]
		if !ok {
			return "unknown destination", nil
		}
		if prev, dup := locs[d.location()]; dup {
			return fmt.Sprintf("%s and %s write to the same location", prev.name, d.name), nil
		}
		locs[d.location()] = d
	}
	return "", nil
}

// saveMembers rewrites the member rows: positions are 0..n-1 in the order of ids.
func saveMembers(ctx context.Context, tx pgx.Tx, group uuid.UUID, ids []uuid.UUID) error {
	if _, err := tx.Exec(ctx, `DELETE FROM destination_group_members WHERE group_id = $1`, group); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO destination_group_members (group_id, destination_id, position)
		SELECT $1, t.id, t.ord - 1 FROM unnest($2::uuid[]) WITH ORDINALITY AS t(id, ord)`, group, ids)
	return err
}

func memberIDs(ms []GroupMember) []uuid.UUID {
	out := make([]uuid.UUID, len(ms))
	for i, m := range ms {
		out[i] = m.ID
	}
	return out
}

// errFields carries field errors out of a transaction.
type errFields map[string]string

func (errFields) Error() string { return "invalid destination group" }

func groupNameTaken(w http.ResponseWriter) {
	httpx.FieldErrors(w, "a destination group with this name already exists", map[string]string{"name": "already exists"})
}

func (a *API) writeGroupErr(w http.ResponseWriter, r *http.Request, err error) {
	var fe errFields
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	case errors.As(err, &fe):
		httpx.FieldErrors(w, fe.Error(), fe)
	case store.IsUniqueViolation(err):
		groupNameTaken(w)
	default:
		httpx.Internal(w, r, a.Log, err)
	}
}

// ---------------------------------------------------------------- create

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	if !canAdmin(r) {
		httpx.Forbidden(w, "")
		return
	}
	var in GroupInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(deref(in.Name))
	desc := strings.TrimSpace(deref(in.Description))
	f := map[string]string{}
	validGroupName(name, f)
	if len(desc) > maxGroupDesc {
		f["description"] = fmt.Sprintf("at most %d characters", maxGroupDesc)
	}
	var members []uuid.UUID
	if in.MemberIDs != nil {
		members = *in.MemberIDs
	}
	var out GroupView
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		if msg, err := checkMembers(r.Context(), tx, members); err != nil {
			return err
		} else if msg != "" {
			f["member_ids"] = msg
		}
		if f["name"] == "" {
			var taken bool
			if err := tx.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM destination_groups WHERE name = $1)`, name).Scan(&taken); err != nil {
				return err
			}
			if taken {
				f["name"] = "already exists"
			}
		}
		if len(f) > 0 {
			return errFields(f)
		}
		var id uuid.UUID
		if err := tx.QueryRow(r.Context(), `INSERT INTO destination_groups (name, description) VALUES ($1, $2) RETURNING id`, name, desc).Scan(&id); err != nil {
			return err
		}
		if err := saveMembers(r.Context(), tx, id, members); err != nil {
			return err
		}
		var err error
		if out, err = loadGroup(r.Context(), tx, id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "destination_group.created", "destination_group", id.String(), nil, map[string]any{
			"name": name, "description": desc, "members": idStrings(members)})
	})
	if err != nil {
		a.writeGroupErr(w, r, memberFK(err))
		return
	}
	httpx.JSON(w, http.StatusCreated, out)
}

// memberFK maps the foreign key error of a member that vanished between the
// check and the insert to the same field error as an unknown destination.
func memberFK(err error) error {
	if isForeignKey(err) {
		return errFields{"member_ids": "unknown destination"}
	}
	return err
}

func idStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// ---------------------------------------------------------------- patch

func (a *API) patchGroup(w http.ResponseWriter, r *http.Request) {
	if !canAdmin(r) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in GroupInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var out GroupView
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		var cur GroupView
		if err := tx.QueryRow(r.Context(), `SELECT id, name, description FROM destination_groups WHERE id = $1 FOR UPDATE`, id).
			Scan(&cur.ID, &cur.Name, &cur.Description); err != nil {
			return store.NotFound(err)
		}
		before, err := loadGroup(r.Context(), tx, id)
		if err != nil {
			return err
		}
		name, desc := cur.Name, cur.Description
		if in.Name != nil {
			name = strings.TrimSpace(*in.Name)
		}
		if in.Description != nil {
			desc = strings.TrimSpace(*in.Description)
		}
		f := map[string]string{}
		validGroupName(name, f)
		if len(desc) > maxGroupDesc {
			f["description"] = fmt.Sprintf("at most %d characters", maxGroupDesc)
		}
		if in.MemberIDs != nil {
			if msg, err := checkMembers(r.Context(), tx, *in.MemberIDs); err != nil {
				return err
			} else if msg != "" {
				f["member_ids"] = msg
			}
		}
		if f["name"] == "" && name != cur.Name {
			var taken bool
			if err := tx.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM destination_groups WHERE name = $1 AND id <> $2)`, name, id).Scan(&taken); err != nil {
				return err
			}
			if taken {
				f["name"] = "already exists"
			}
		}
		if len(f) > 0 {
			return errFields(f)
		}

		changes := map[string]any{}
		if name != cur.Name || desc != cur.Description {
			if _, err := tx.Exec(r.Context(), `UPDATE destination_groups SET name = $2, description = $3 WHERE id = $1`, id, name, desc); err != nil {
				return err
			}
			if name != cur.Name {
				changes["name"] = map[string]string{"from": cur.Name, "to": name}
			}
			if desc != cur.Description {
				changes["description"] = map[string]string{"from": cur.Description, "to": desc}
			}
		}
		if in.MemberIDs != nil {
			old, now := memberIDs(before.Members), *in.MemberIDs
			added, removed := idDiff(now, old), idDiff(old, now)
			reordered := len(added) == 0 && len(removed) == 0 && !sameOrder(old, now)
			if len(added) > 0 || len(removed) > 0 || reordered {
				if err := saveMembers(r.Context(), tx, id, now); err != nil {
					return err
				}
				changes["added"] = idStrings(added)
				changes["removed"] = idStrings(removed)
				if reordered {
					changes["reordered"] = true
				}
			}
		}
		if len(changes) > 0 {
			if err := httpx.Record(r, tx, "destination_group.updated", "destination_group", id.String(), nil, changes); err != nil {
				return err
			}
		}
		out, err = loadGroup(r.Context(), tx, id)
		return err
	})
	if err != nil {
		a.writeGroupErr(w, r, memberFK(err))
		return
	}
	httpx.JSON(w, http.StatusOK, out)
}

// idDiff returns the ids of a that are not in b, in a's order.
func idDiff(a, b []uuid.UUID) []uuid.UUID {
	in := map[uuid.UUID]bool{}
	for _, id := range b {
		in[id] = true
	}
	out := []uuid.UUID{}
	for _, id := range a {
		if !in[id] {
			out = append(out, id)
		}
	}
	return out
}

func sameOrder(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- delete

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if !canAdmin(r) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	errInUse := errors.New("in use")
	var jobs int
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(r.Context(), `SELECT name FROM destination_groups WHERE id = $1 FOR UPDATE`, id).Scan(&name); err != nil {
			return store.NotFound(err)
		}
		gv, err := loadGroup(r.Context(), tx, id)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM backup_jobs WHERE destination_group_id = $1`, id).Scan(&jobs); err != nil {
			return err
		}
		if jobs > 0 {
			return errInUse
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM destination_groups WHERE id = $1`, id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "destination_group.deleted", "destination_group", id.String(), nil, map[string]any{
			"name": name, "members": idStrings(memberIDs(gv.Members))})
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	case errors.Is(err, errInUse):
		httpx.Error(w, http.StatusConflict, fmt.Sprintf("destination group is used by %d backup job(s); move them first", jobs))
	case isForeignKey(err):
		httpx.Error(w, http.StatusConflict, "destination group is used by backup jobs; move them first")
	case err != nil:
		httpx.Internal(w, r, a.Log, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func isForeignKey(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23503"
}
