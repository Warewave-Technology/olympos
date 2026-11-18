package notify

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
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

// API serves /notifications/channels and /notifications/routes. Reads are
// open to every role; writes need operator with scope "all" (channels and
// routes are global objects).
type API struct {
	DB    *store.DB
	Log   *slog.Logger
	Sinks map[string]Sink
	// Link builds absolute links for test messages (Deps.PublicLink).
	Link func(path string) string
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Route("/notifications", func(r chi.Router) {
		r.Use(httpx.RequireAny(authz.PermRead))
		r.Get("/channels", a.listChannels)
		r.Post("/channels", a.createChannel)
		r.Get("/channels/{id}", a.getChannel)
		r.Patch("/channels/{id}", a.patchChannel)
		r.Delete("/channels/{id}", a.deleteChannel)
		r.Post("/channels/{id}/test", a.testChannel)
		r.Get("/routes", a.getRoutes)
		r.Put("/routes", a.putRoutes)
	})
}

// ChannelView is the API shape of a channel.
type ChannelView struct {
	ID             uuid.UUID `json:"id"`
	Kind           string    `json:"kind"`
	Name           string    `json:"name"`
	SlackChannelID string    `json:"slack_channel_id"`
	Routes         []string  `json:"routes"`
	CreatedAt      time.Time `json:"created_at"`
}

// ChannelInput is the create/patch body.
type ChannelInput struct {
	Name           *string `json:"name"`
	SlackChannelID *string `json:"slack_channel_id"`
}

// RouteView is one event type with its channels.
type RouteView struct {
	EventType  string      `json:"event_type"`
	ChannelIDs []uuid.UUID `json:"channel_ids"`
}

// RoutesView is the GET/PUT /notifications/routes response.
type RoutesView struct {
	Catalog []CatalogEntry `json:"catalog"`
	Routes  []RouteView    `json:"routes"`
}

var slackChannelRe = regexp.MustCompile(`^[CGD][A-Z0-9]{6,20}$`)

func canWrite(r *http.Request) bool { return httpx.Subject(r).CanGlobal(authz.PermOperate) }

const channelSelect = `SELECT c.id, c.kind, c.name, c.slack_channel_id, c.created_at,
	COALESCE(array_agg(r.event_type ORDER BY r.event_type) FILTER (WHERE r.event_type IS NOT NULL), '{}')
	FROM notification_channels c LEFT JOIN notification_routes r ON r.channel_id = c.id`

func scanChannels(rows pgx.Rows) ([]ChannelView, error) {
	defer rows.Close()
	out := []ChannelView{}
	for rows.Next() {
		var c ChannelView
		if err := rows.Scan(&c.ID, &c.Kind, &c.Name, &c.SlackChannelID, &c.CreatedAt, &c.Routes); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (a *API) loadChannel(ctx context.Context, q store.Querier, id uuid.UUID) (ChannelView, error) {
	rows, err := q.Query(ctx, channelSelect+` WHERE c.id = $1 GROUP BY c.id`, id)
	if err != nil {
		return ChannelView{}, err
	}
	cs, err := scanChannels(rows)
	if err != nil {
		return ChannelView{}, err
	}
	if len(cs) == 0 {
		return ChannelView{}, store.ErrNotFound
	}
	return cs[0], nil
}

func (a *API) listChannels(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(r.Context(), channelSelect+` GROUP BY c.id ORDER BY c.name, c.id`)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	cs, err := scanChannels(rows)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": cs})
}

func (a *API) getChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	c, err := a.loadChannel(r.Context(), a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

func validateChannel(name, slackID string) map[string]string {
	f := map[string]string{}
	if name == "" {
		f["name"] = "required"
	} else if len(name) > 80 {
		f["name"] = "at most 80 characters"
	}
	if !slackChannelRe.MatchString(slackID) {
		f["slack_channel_id"] = "must be a Slack channel ID such as C0123ABCD (not the #name)"
	}
	return f
}

func (a *API) createChannel(w http.ResponseWriter, r *http.Request) {
	if !canWrite(r) {
		httpx.Forbidden(w, "")
		return
	}
	var in ChannelInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	name, sid := strings.TrimSpace(deref(in.Name)), strings.TrimSpace(deref(in.SlackChannelID))
	if f := validateChannel(name, sid); len(f) > 0 {
		httpx.FieldErrors(w, "invalid channel", f)
		return
	}
	var out ChannelView
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		var id uuid.UUID
		if err := tx.QueryRow(r.Context(), `INSERT INTO notification_channels (kind, slack_channel_id, name) VALUES ('slack', $1, $2) RETURNING id`,
			sid, name).Scan(&id); err != nil {
			return err
		}
		if err := httpx.Record(r, tx, "notification.channel.created", "notification_channel", id.String(), nil,
			map[string]any{"name": name, "slack_channel_id": sid}); err != nil {
			return err
		}
		var err error
		out, err = a.loadChannel(r.Context(), tx, id)
		return err
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, out)
}

func (a *API) patchChannel(w http.ResponseWriter, r *http.Request) {
	if !canWrite(r) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in ChannelInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var out ChannelView
	var fields map[string]string
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		cur, err := a.loadChannel(r.Context(), tx, id)
		if err != nil {
			return err
		}
		name, sid := cur.Name, cur.SlackChannelID
		if in.Name != nil {
			name = strings.TrimSpace(*in.Name)
		}
		if in.SlackChannelID != nil {
			sid = strings.TrimSpace(*in.SlackChannelID)
		}
		if fields = validateChannel(name, sid); len(fields) > 0 {
			return errInvalid
		}
		if _, err := tx.Exec(r.Context(), `UPDATE notification_channels SET name = $2, slack_channel_id = $3 WHERE id = $1`, id, name, sid); err != nil {
			return err
		}
		details := map[string]any{}
		if name != cur.Name {
			details["name"] = map[string]string{"from": cur.Name, "to": name}
		}
		if sid != cur.SlackChannelID {
			details["slack_channel_id"] = map[string]string{"from": cur.SlackChannelID, "to": sid}
		}
		if err := httpx.Record(r, tx, "notification.channel.updated", "notification_channel", id.String(), nil, details); err != nil {
			return err
		}
		out, err = a.loadChannel(r.Context(), tx, id)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	case errors.Is(err, errInvalid):
		httpx.FieldErrors(w, "invalid channel", fields)
	case err != nil:
		httpx.Internal(w, r, a.Log, err)
	default:
		httpx.JSON(w, http.StatusOK, out)
	}
}

var errInvalid = errors.New("invalid input")

func (a *API) deleteChannel(w http.ResponseWriter, r *http.Request) {
	if !canWrite(r) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		cur, err := a.loadChannel(r.Context(), tx, id)
		if err != nil {
			return err
		}
		// Routes cascade; jobs/schedules that override with this channel
		// keep the FK and block the delete (409).
		if _, err := tx.Exec(r.Context(), `DELETE FROM notification_channels WHERE id = $1`, id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "notification.channel.deleted", "notification_channel", id.String(), nil,
			map[string]any{"name": cur.Name, "slack_channel_id": cur.SlackChannelID, "routes": cur.Routes})
	})
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	case errors.As(err, &pg) && pg.Code == "23503":
		httpx.Error(w, http.StatusConflict, "channel is used by backup jobs or audit schedules; change them first")
	case err != nil:
		httpx.Internal(w, r, a.Log, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// TestResult is the /channels/{id}/test response.
type TestResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (a *API) testChannel(w http.ResponseWriter, r *http.Request) {
	if !canWrite(r) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	cur, err := a.loadChannel(r.Context(), a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	link := "/settings/notifications"
	if a.Link != nil {
		link = a.Link(link)
	}
	msg := Message{Key: "test:" + uuid.NewString(), EventType: "test", Title: "Olympos test message for " + cur.Name,
		Link: link, Fields: map[string]string{"sent by": httpx.Subject(r).Principal.DisplayName}, CreatedAt: time.Now(), Test: true}
	res := TestResult{OK: true}
	sink := a.Sinks[cur.Kind]
	if sink == nil {
		res = TestResult{Error: "no sink for channel kind " + cur.Kind}
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		err := sink.Send(ctx, Channel{ID: cur.ID, Kind: cur.Kind, Name: cur.Name, SlackChannelID: cur.SlackChannelID}, msg)
		cancel()
		if err != nil {
			res = TestResult{Error: sanitizeError(err.Error())}
		}
	}
	if err := httpx.Record(r, a.DB, "notification.channel.tested", "notification_channel", id.String(), nil,
		map[string]any{"ok": res.OK, "error": res.Error}); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

func (a *API) loadRoutes(ctx context.Context, q store.Querier) (RoutesView, error) {
	rows, err := q.Query(ctx, `SELECT event_type, array_agg(channel_id ORDER BY channel_id) FROM notification_routes GROUP BY event_type`)
	if err != nil {
		return RoutesView{}, err
	}
	defer rows.Close()
	byType := map[string][]uuid.UUID{}
	for rows.Next() {
		var t string
		var ids []uuid.UUID
		if err := rows.Scan(&t, &ids); err != nil {
			return RoutesView{}, err
		}
		byType[t] = ids
	}
	if err := rows.Err(); err != nil {
		return RoutesView{}, err
	}
	v := RoutesView{Catalog: CatalogEntries(), Routes: []RouteView{}}
	for _, t := range Catalog {
		ids := byType[t]
		if ids == nil {
			ids = []uuid.UUID{}
		}
		v.Routes = append(v.Routes, RouteView{EventType: t, ChannelIDs: ids})
	}
	return v, nil
}

func (a *API) getRoutes(w http.ResponseWriter, r *http.Request) {
	v, err := a.loadRoutes(r.Context(), a.DB)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

func (a *API) putRoutes(w http.ResponseWriter, r *http.Request) {
	if !canWrite(r) {
		httpx.Forbidden(w, "")
		return
	}
	var in struct {
		Routes []RouteView `json:"routes"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	fields := map[string]string{}
	want := map[string]map[uuid.UUID]bool{}
	for i, rt := range in.Routes {
		if !Known(rt.EventType) {
			fields["routes["+strconv.Itoa(i)+"].event_type"] = "unknown event type " + rt.EventType
			continue
		}
		if want[rt.EventType] == nil {
			want[rt.EventType] = map[uuid.UUID]bool{}
		}
		for _, id := range rt.ChannelIDs {
			want[rt.EventType][id] = true
		}
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid routes", fields)
		return
	}
	var out RoutesView
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		existing := map[uuid.UUID]bool{}
		rows, err := tx.Query(r.Context(), `SELECT id FROM notification_channels`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			existing[id] = true
		}
		rows.Close()
		for t, ids := range want {
			for id := range ids {
				if !existing[id] {
					fields["routes."+t] = "unknown channel " + id.String()
				}
			}
		}
		if len(fields) > 0 {
			return errInvalid
		}
		before, err := a.loadRoutes(r.Context(), tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM notification_routes`); err != nil {
			return err
		}
		n := 0
		for t, ids := range want {
			for id := range ids {
				if _, err := tx.Exec(r.Context(), `INSERT INTO notification_routes (event_type, channel_id) VALUES ($1, $2)`, t, id); err != nil {
					return err
				}
				n++
			}
		}
		if out, err = a.loadRoutes(r.Context(), tx); err != nil {
			return err
		}
		return httpx.Record(r, tx, "notification.routes.updated", "notification_routes", "", nil,
			map[string]any{"before": compactRoutes(before.Routes), "after": compactRoutes(out.Routes), "count": n})
	})
	switch {
	case errors.Is(err, errInvalid):
		httpx.FieldErrors(w, "invalid routes", fields)
	case err != nil:
		httpx.Internal(w, r, a.Log, err)
	default:
		httpx.JSON(w, http.StatusOK, out)
	}
}

func compactRoutes(rs []RouteView) map[string][]uuid.UUID {
	m := map[string][]uuid.UUID{}
	for _, r := range rs {
		if len(r.ChannelIDs) > 0 {
			m[r.EventType] = r.ChannelIDs
		}
	}
	return m
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
