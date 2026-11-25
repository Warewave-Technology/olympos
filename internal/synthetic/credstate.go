package synthetic

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// The state of a synthetic credential (synthetic_credentials.resolve_*,
// docs/design/credential-alerts.md): dispatch, the only place a credential
// is resolved, records what each run found. An episode starts at the first
// failure (resolve_failing_since) and ends at the next success; it sends
// synthetic.credential_broken once (resolve_alerted_at), and
// synthetic.credential_restored when it ends if that went out.

// UnavailableAlertAfter is how long a credential stays unavailable
// (transient) before synthetic.credential_broken goes out: Key Vault
// throttling or a short outage is not worth a message.
const UnavailableAlertAfter = 30 * time.Minute

// Why a credential cannot be resolved (resolve_cause). All but unavailable
// are permanent: retrying will not help until someone changes the credential
// or the vault.
const (
	CauseNotFound    = "not_found"
	CauseForbidden   = "forbidden"
	CauseDecrypt     = "decrypt"
	CauseEmpty       = "empty"
	CauseExpired     = "expired"
	CauseUnavailable = "unavailable"
)

// resolveCause classifies an error from runCredentials. Anything not known
// to be permanent is transient, the KEK failing to unwrap included. Like any
// transient failure it alerts only after UnavailableAlertAfter; if a KEK
// outage lasts that long, every stored credential alerts once.
func resolveCause(err error) (cause string, permanent bool) {
	switch {
	case errors.Is(err, secrets.ErrSecretNotFound):
		return CauseNotFound, true
	case errors.Is(err, secrets.ErrSecretForbidden),
		errors.Is(err, secrets.ErrRefReserved),
		errors.Is(err, secrets.ErrRefNotAllowed):
		return CauseForbidden, true
	case errors.Is(err, secrets.ErrDecrypt):
		return CauseDecrypt, true
	case errors.Is(err, errCredentialEmpty):
		return CauseEmpty, true
	case errors.Is(err, errCredentialExpired):
		return CauseExpired, true
	}
	return CauseUnavailable, false
}

// credentialFailure names the synthetic credential a run could not
// resolve, so that dispatch records it on that credential.
type credentialFailure struct {
	ID      uuid.UUID
	Backing uuid.UUID // the credentials row its secret was loaded from
	Err     error
}

func (f *credentialFailure) Error() string {
	return "credential " + f.ID.String() + ": " + f.Err.Error()
}
func (f *credentialFailure) Unwrap() error { return f.Err }

// causeText is the sentence a message gives for each cause: never the
// error itself, which may carry Key Vault's response.
var causeText = map[string]string{
	CauseNotFound:    "the secret was not found",
	CauseForbidden:   "Olympos is not allowed to read the secret",
	CauseDecrypt:     "the stored value does not decrypt",
	CauseEmpty:       "the secret is empty",
	CauseExpired:     "the credential has expired",
	CauseUnavailable: "Key Vault or the key encryption key did not answer",
}

// recordCredentialOK records that the credentials of ids resolved. A
// credential that was failing is ok again, and synthetic.credential_restored
// goes out when its episode was alerted. The usual case, every credential
// ok already, changes nothing.
//
// A result is recorded only if the credential still has the secret row the
// run loaded (credential_id): a run that loaded the secret before a rotation
// must not undo the reset the rotation made.
func (s *Service) recordCredentialOK(ctx context.Context, resolved []resolvedCred) error {
	if len(resolved) == 0 {
		return nil
	}
	ids, backing := make([]uuid.UUID, len(resolved)), make([]uuid.UUID, len(resolved))
	for i, r := range resolved {
		ids[i], backing[i] = r.ID, r.Backing
	}
	type restored struct {
		id      uuid.UUID
		name    string
		since   *time.Time
		alerted bool
	}
	var list []restored
	err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		// FOR UPDATE: of two passes that find a credential ok again, the
		// second finds it ok already and sends nothing.
		rows, err := tx.Query(ctx, `UPDATE synthetic_credentials c SET resolve_state = 'ok', resolve_cause = NULL,
				resolve_failing_since = NULL, resolve_alerted_at = NULL
			FROM (SELECT id, resolve_failing_since, resolve_alerted_at FROM synthetic_credentials
				WHERE (id, credential_id) IN (SELECT * FROM unnest($1::uuid[], $2::uuid[])) AND resolve_state <> 'ok'
				ORDER BY id FOR UPDATE) old
			WHERE c.id = old.id
			RETURNING c.id, c.name, old.resolve_failing_since, old.resolve_alerted_at IS NOT NULL`, ids, backing)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (restored, error) {
			var x restored
			return x, r.Scan(&x.id, &x.name, &x.since, &x.alerted)
		})
		if err != nil {
			return err
		}
		for _, x := range list {
			if !x.alerted || x.since == nil {
				continue
			}
			_, channels, err := credentialScenarios(ctx, tx, x.id)
			if err != nil {
				return err
			}
			since := x.since.UTC().Format(time.RFC3339)
			if err := emitCredential(ctx, tx, channels, notify.Event{
				Type:    notify.SyntheticCredentialRestored,
				Key:     fmt.Sprintf("%s:%s:%d", notify.SyntheticCredentialRestored, x.id, x.since.Unix()),
				Title:   fmt.Sprintf("Synthetic credential %s resolves again", x.name),
				Link:    credentialLink(x.id),
				Fields:  map[string]string{"credential": x.name, "failing since": since},
				Payload: map[string]any{"credential_id": x.id.String(), "failing_since": since},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, x := range list {
		args := []any{"synthetic_cred", x.id, "name", x.name}
		if x.since != nil {
			args = append(args, "failing_since", x.since.UTC().Format(time.RFC3339))
		}
		s.Log.Info("synthetic credential resolves again", args...)
	}
	return nil
}

// recordCredentialFailure records that credential id could not be resolved,
// for cause; permanent says whether retrying can help. The episode keeps
// its start, and a transient failure never downgrades a permanent one
// within it. synthetic.credential_broken goes out once per episode: at
// once when permanent, after UnavailableAlertAfter when transient. backing
// is the credentials row the failed run loaded: when the credential has a
// new secret since (a rotation), the failure is stale and is ignored.
func (s *Service) recordCredentialFailure(ctx context.Context, id, backing uuid.UUID, cause string, permanent bool) error {
	now := s.now()
	// What the update changed, logged once it commits (#69): a WARN per
	// state change, not per run.
	var changed bool
	var logName, logState, logCause string
	var logSince time.Time
	err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var oldState, newState string
		var oldCause, newCause *string
		err := tx.QueryRow(ctx, `UPDATE synthetic_credentials c SET
				resolve_cause = CASE WHEN $3 OR old.resolve_state <> 'broken' THEN $2 ELSE old.resolve_cause END,
				resolve_state = CASE WHEN $3 OR old.resolve_state = 'broken' THEN 'broken' ELSE 'unavailable' END,
				resolve_failing_since = COALESCE(old.resolve_failing_since, $4)
			FROM (SELECT id, resolve_state, resolve_cause, resolve_failing_since FROM synthetic_credentials
				WHERE id = $1 AND credential_id = $5 FOR UPDATE) old
			WHERE c.id = old.id
			RETURNING c.name, old.resolve_state, old.resolve_cause, c.resolve_state, c.resolve_cause, c.resolve_failing_since`,
			id, cause, permanent, now, backing).Scan(&logName, &oldState, &oldCause, &newState, &newCause, &logSince)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // a stale failure: the credential has a new secret since
		}
		if err != nil {
			return err
		}
		changed = oldState != newState || (oldCause == nil) != (newCause == nil) || oldCause != nil && *oldCause != *newCause
		logState = newState
		if newCause != nil {
			logCause = *newCause
		}
		// The one-message mark, set where the message is written: of the
		// runs that fail at once, here or on other replicas, one passes
		// (the row lock of the update above orders them).
		var name, state string
		var current *string
		var since time.Time
		err = tx.QueryRow(ctx, `UPDATE synthetic_credentials SET resolve_alerted_at = $2
			WHERE id = $1 AND credential_id = $4 AND resolve_alerted_at IS NULL AND (resolve_state = 'broken' OR resolve_failing_since <= $3)
			RETURNING name, resolve_state, resolve_cause, resolve_failing_since`, id, now, now.Add(-UnavailableAlertAfter), backing).
			Scan(&name, &state, &current, &since)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if current != nil {
			cause = *current
		}
		scenarios, channels, err := credentialScenarios(ctx, tx, id)
		if err != nil {
			return err
		}
		transient := state != "broken"
		title := fmt.Sprintf("Synthetic credential %s cannot be resolved", name)
		if transient {
			title = fmt.Sprintf("Synthetic credential %s has been unavailable for %d minutes", name, int(UnavailableAlertAfter/time.Minute))
		}
		used := "none"
		if len(scenarios) > 0 {
			used = topList(scenarios)
		}
		affected := fmt.Sprintf("%d scenarios affected", len(scenarios))
		if len(scenarios) == 1 {
			affected = "1 scenario affected"
		}
		at := since.UTC().Format(time.RFC3339)
		return emitCredential(ctx, tx, channels, notify.Event{
			Type:  notify.SyntheticCredentialBroken,
			Key:   fmt.Sprintf("%s:%s:%d", notify.SyntheticCredentialBroken, id, since.Unix()),
			Title: title,
			Link:  credentialLink(id),
			Fields: map[string]string{"credential": name, "cause": causeText[cause], "since": at, "used by": used,
				"impact": affected},
			Payload: map[string]any{"credential_id": id.String(), "cause": cause, "transient": transient, "failing_since": at,
				"scenario_count": len(scenarios)},
		})
	})
	if err == nil && changed {
		s.Log.Warn("synthetic credential cannot be resolved", "synthetic_cred", id, "name", logName, "state", logState,
			"cause", logCause, "failing_since", logSince.UTC().Format(time.RFC3339))
	}
	return err
}

func credentialLink(id uuid.UUID) string { return "/settings/synthetic?credential=" + id.String() }

// credentialScenarios returns the names of the enabled scenarios whose
// steps use credential id, by name, and their alert channels (nil: the
// event's routes), one each.
func credentialScenarios(ctx context.Context, tx pgx.Tx, id uuid.UUID) (names []string, channels []*uuid.UUID, err error) {
	rows, err := tx.Query(ctx, `SELECT sc.name, a.channel_id FROM scenarios sc
		LEFT JOIN scenario_alerts a ON a.scenario_id = sc.id
		WHERE sc.enabled AND EXISTS (SELECT 1 FROM scenario_steps st WHERE st.scenario_id = sc.id AND st.credential_id = $1)
		ORDER BY sc.name, sc.id`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var ch *uuid.UUID
		if err := rows.Scan(&name, &ch); err != nil {
			return nil, nil, err
		}
		names = append(names, name)
		channels = append(channels, ch)
	}
	return names, channels, rows.Err()
}

// emitCredential writes e, an event about a credential, once per distinct
// channel of the scenarios that use it (channels, from
// credentialScenarios), and once through the event type's routes when one
// of them has no channel or none uses it any more, as scenario alerts are
// routed. Each copy's key ends with its channel, or "default".
func emitCredential(ctx context.Context, tx pgx.Tx, channels []*uuid.UUID, e notify.Event) error {
	seen := map[uuid.UUID]bool{}
	routes := len(channels) == 0
	base := e.Key
	for _, ch := range channels {
		if ch == nil {
			routes = true
			continue
		}
		if seen[*ch] {
			continue
		}
		seen[*ch] = true
		c := e
		c.ChannelID, c.Key = ch, base+":"+ch.String()
		if err := notify.Emit(ctx, tx, c); err != nil {
			return err
		}
	}
	if !routes {
		return nil
	}
	e.Key = base + ":default"
	return notify.Emit(ctx, tx, e)
}

// AttentionItems are the credentials that cannot be resolved, for the
// Needs-attention strip of whoever may read the settings: crit when broken,
// warn when unavailable for longer than UnavailableAlertAfter (as the
// message). Only credentials an enabled scenario uses count: nothing else
// resolves them, so their state is old news.
func (s *Service) AttentionItems(ctx context.Context, sub *authz.Subject) ([]inventory.AttentionItem, error) {
	if !mayReadSettings(sub) {
		return nil, nil
	}
	rows, err := s.DB.Query(ctx, `SELECT c.id, c.name, c.resolve_state, c.resolve_failing_since,
			(SELECT count(*) FROM scenarios sc WHERE sc.enabled
				AND EXISTS (SELECT 1 FROM scenario_steps st WHERE st.scenario_id = sc.id AND st.credential_id = c.id))
		FROM synthetic_credentials c
		WHERE (c.resolve_state = 'broken' OR c.resolve_state = 'unavailable' AND c.resolve_failing_since <= $1)
		  AND EXISTS (SELECT 1 FROM scenarios sc JOIN scenario_steps st ON st.scenario_id = sc.id
			WHERE sc.enabled AND st.credential_id = c.id)
		ORDER BY c.resolve_state, c.name, c.id`, s.now().Add(-UnavailableAlertAfter))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (inventory.AttentionItem, error) {
		var id uuid.UUID
		var name, state string
		var since *time.Time
		var n int
		if err := r.Scan(&id, &name, &state, &since, &n); err != nil {
			return inventory.AttentionItem{}, err
		}
		affected := fmt.Sprintf("%d scenarios affected", n)
		if n == 1 {
			affected = "1 scenario affected"
		}
		item := inventory.AttentionItem{Kind: "synthetic_credential_broken", Severity: "crit", Label: "Synthetic credential",
			Detail: fmt.Sprintf("Credential %s cannot be resolved \u2014 %s", name, affected), Link: credentialLink(id)}
		if state != "broken" {
			item.Severity = "warn"
			item.Detail = fmt.Sprintf("Credential %s has been unavailable since %s UTC \u2014 %s", name, since.UTC().Format("15:04"), affected)
		}
		return item, nil
	})
}
