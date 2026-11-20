package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Settings are the audit module's global settings: where raw Kubescape,
// Polaris and kube-bench reports are kept (RawDestinationSetting).
type Settings struct {
	RawDestination *DestinationRef `json:"raw_destination"`
}

// DestinationRef names a backup destination.
type DestinationRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Kind string    `json:"kind"`
}

type settingsInput struct {
	RawDestinationID *uuid.UUID `json:"raw_destination_id"` // null: stop storing raw reports
}

func loadSettings(ctx context.Context, q store.Querier) (Settings, error) {
	var out Settings
	var ref DestinationRef
	err := q.QueryRow(ctx, `SELECT d.id, d.name, d.kind FROM settings s JOIN destinations d ON d.id::text = s.value #>> '{}'
		WHERE s.key = $1`, RawDestinationSetting).Scan(&ref.ID, &ref.Name, &ref.Kind)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return out, err
	default:
		out.RawDestination = &ref
	}
	return out, nil
}

// getSettings is readable by every signed-in reader, like destinations.
func (a *API) getSettings(w http.ResponseWriter, r *http.Request) {
	s, err := loadSettings(r.Context(), a.DB)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, s)
}

// putSettings sets or clears the raw report destination. Raw reports hold
// (redacted) cluster objects of every cluster, so only a global admin
// chooses where they go.
func (a *API) putSettings(w http.ResponseWriter, r *http.Request) {
	if !httpx.Subject(r).CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "audit settings need the admin role with scope all")
		return
	}
	var in settingsInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		before, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		details := map[string]any{"raw_destination_from": nil, "raw_destination_to": nil}
		if before.RawDestination != nil {
			details["raw_destination_from"] = before.RawDestination.Name
		}
		if in.RawDestinationID == nil {
			_, err = tx.Exec(ctx, `DELETE FROM settings WHERE key = $1`, RawDestinationSetting)
		} else {
			var name string
			if err := tx.QueryRow(ctx, `SELECT name FROM destinations WHERE id = $1`, *in.RawDestinationID).Scan(&name); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return errUnknownDestination
				}
				return err
			}
			details["raw_destination_to"] = name
			v, _ := json.Marshal(in.RawDestinationID.String())
			_, err = tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
				ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, RawDestinationSetting, v)
		}
		if err != nil {
			return err
		}
		return httpx.Record(r, tx, "audit.settings_changed", "settings", RawDestinationSetting, nil, details)
	})
	if errors.Is(err, errUnknownDestination) {
		httpx.FieldErrors(w, "unknown destination", map[string]string{"raw_destination_id": "no destination with this id"})
		return
	} else if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	s, err := loadSettings(ctx, a.DB)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, s)
}

var errUnknownDestination = errors.New("unknown destination")
