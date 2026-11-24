package synthetic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/backup"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// How a scenario is stored (migration 00024):
//
//   - scenarios holds the scenario's own fields;
//   - scenario_steps.spec holds the JSON of the step kind's spec alone
//     (spec.DNSSpec, HTTPSpec, TCPSpec or TLSSpec), and credential_id the
//     step's credential;
//   - scenario_assertions and scenario_extracts hold the step's
//     assertions (in position order) and extracts (by name).
//
// synthetic_credentials.bound_hosts holds each bound host rule in the form
// hostallow.FormatRule writes ("suffix:wrw.com"), the same form a
// RunCredential carries to the probe.

// LoadScenario reads a saved scenario as RunScenario carries it.
func LoadScenario(ctx context.Context, q store.Querier, id uuid.UUID) (*spec.Scenario, error) {
	sc := &spec.Scenario{ID: id.String()}
	err := q.QueryRow(ctx, `SELECT name, type, interval_seconds, timeout_seconds, step_retries, store_responses
		FROM scenarios WHERE id = $1`, id).Scan(&sc.Name, &sc.Type, &sc.IntervalSeconds, &sc.TimeoutSeconds, &sc.StepRetries, &sc.StoreResponses)
	if err != nil {
		return nil, store.NotFound(err)
	}
	rows, err := q.Query(ctx, `SELECT id, position, kind, spec, credential_id FROM scenario_steps WHERE scenario_id = $1 ORDER BY position`, id)
	if err != nil {
		return nil, err
	}
	var stepIDs []uuid.UUID
	for rows.Next() {
		var sid uuid.UUID
		var st spec.Step
		var raw []byte
		if err := rows.Scan(&sid, &st.Position, &st.Kind, &raw, &st.CredentialID); err != nil {
			rows.Close()
			return nil, err
		}
		if err := decodeStepSpec(&st, raw); err != nil {
			rows.Close()
			return nil, fmt.Errorf("step %d: %w", st.Position, err)
		}
		st.Assertions, st.Extracts = []spec.Assertion{}, []spec.Extract{}
		stepIDs = append(stepIDs, sid)
		sc.Steps = append(sc.Steps, st)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	index := make(map[uuid.UUID]int, len(stepIDs))
	for i, sid := range stepIDs {
		index[sid] = i
	}
	rows, err = q.Query(ctx, `SELECT step_id, subject, operator, value FROM scenario_assertions
		WHERE step_id = ANY($1) ORDER BY step_id, position`, stepIDs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sid uuid.UUID
		var a spec.Assertion
		if err := rows.Scan(&sid, &a.Subject, &a.Operator, &a.Value); err != nil {
			rows.Close()
			return nil, err
		}
		i := index[sid]
		sc.Steps[i].Assertions = append(sc.Steps[i].Assertions, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT step_id, name, source, expr FROM scenario_extracts WHERE step_id = ANY($1) ORDER BY step_id, name`, stepIDs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sid uuid.UUID
		var e spec.Extract
		if err := rows.Scan(&sid, &e.Name, &e.Source, &e.Expr); err != nil {
			rows.Close()
			return nil, err
		}
		i := index[sid]
		sc.Steps[i].Extracts = append(sc.Steps[i].Extracts, e)
	}
	rows.Close()
	return sc, rows.Err()
}

func decodeStepSpec(st *spec.Step, raw []byte) error {
	var dst any
	switch st.Kind {
	case spec.KindDNS:
		st.DNS = &spec.DNSSpec{}
		dst = st.DNS
	case spec.KindHTTP:
		st.HTTP = &spec.HTTPSpec{}
		dst = st.HTTP
	case spec.KindTCP:
		st.TCP = &spec.TCPSpec{}
		dst = st.TCP
	case spec.KindTLS:
		st.TLS = &spec.TLSSpec{}
		dst = st.TLS
	default:
		return fmt.Errorf("unknown step kind %q", st.Kind)
	}
	return json.Unmarshal(raw, dst)
}

// stepSpec returns the stored form of the step kind's spec.
func stepSpec(st *spec.Step) ([]byte, error) {
	var v any
	switch st.Kind {
	case spec.KindDNS:
		v = st.DNS
	case spec.KindHTTP:
		v = st.HTTP
	case spec.KindTCP:
		v = st.TCP
	case spec.KindTLS:
		v = st.TLS
	}
	if v == nil {
		return nil, fmt.Errorf("step %d: no %s spec", st.Position, st.Kind)
	}
	return json.Marshal(v)
}

// WriteSteps replaces the steps of a saved scenario, with their assertions
// and extracts. Step i is stored at position i. The caller validates the
// steps first (spec.Validate).
func WriteSteps(ctx context.Context, q store.Querier, scenarioID uuid.UUID, steps []spec.Step) error {
	if _, err := q.Exec(ctx, `DELETE FROM scenario_steps WHERE scenario_id = $1`, scenarioID); err != nil {
		return err
	}
	for i := range steps {
		st := &steps[i]
		raw, err := stepSpec(st)
		if err != nil {
			return err
		}
		var sid uuid.UUID
		if err := q.QueryRow(ctx, `INSERT INTO scenario_steps (scenario_id, position, kind, spec, credential_id)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, scenarioID, i, st.Kind, raw, st.CredentialID).Scan(&sid); err != nil {
			return err
		}
		for j, a := range st.Assertions {
			if _, err := q.Exec(ctx, `INSERT INTO scenario_assertions (step_id, position, subject, operator, value)
				VALUES ($1, $2, $3, $4, $5)`, sid, j, a.Subject, a.Operator, a.Value); err != nil {
				return err
			}
		}
		for _, e := range st.Extracts {
			if _, err := q.Exec(ctx, `INSERT INTO scenario_extracts (step_id, name, source, expr) VALUES ($1, $2, $3, $4)`,
				sid, e.Name, e.Source, e.Expr); err != nil {
				return err
			}
		}
	}
	return nil
}

// CredentialIDs returns the credentials the scenario's steps name, once
// each, in step order. It is the set a run is given (sealed) and the set
// spec.ValidateTaint must be given when the scenario is saved: the probe
// taints by exactly the credentials it holds.
func CredentialIDs(sc *spec.Scenario) []uuid.UUID {
	if sc == nil {
		return nil
	}
	var ids []uuid.UUID
	seen := map[uuid.UUID]bool{}
	for _, st := range sc.Steps {
		if st.CredentialID != nil && !seen[*st.CredentialID] {
			seen[*st.CredentialID] = true
			ids = append(ids, *st.CredentialID)
		}
	}
	return ids
}

// credentialRow is a synthetic_credentials row, its bound hosts parsed.
type credentialRow struct {
	expiresAt                  *time.Time
	id, credentialID           uuid.UUID
	kind, headerName, tokenURL string
	scopes                     string
	bound                      []hostallow.Rule
}

// How a credential can fail a run (#54, superseding rulings P13 and P14
// where they conflict). A credential that cannot be resolved for good, or
// has expired, ends the run as an error that moves no streak: the
// credential alerts, once. One the server cannot resolve for now (Key
// Vault, the KEK, the database) skips the run. A missing row or bound host
// that does not parse is the scenario's and ends the run as an error.
var (
	// errCredential means a credential is missing or its row is unusable.
	errCredential = errors.New("synthetic credential unusable")
	// errCredentialExpired means a credential's expires_at has passed.
	errCredentialExpired = errors.New("synthetic credential expired")
	// errCredentialEmpty means the resolved secret has no content.
	errCredentialEmpty = errors.New("synthetic credential empty")
)

// credentialReason maps a credential error to how the run ends.
func credentialReason(err error) (status, reason string) {
	var f *credentialFailure
	switch {
	case errors.Is(err, errCredential):
		return StatusError, ReasonCredentialError
	case !errors.As(err, &f):
		return StatusSkipped, ReasonCredentialUnavailable
	}
	switch cause, permanent := resolveCause(f.Err); {
	case cause == CauseExpired:
		return StatusError, ReasonCredentialExpired
	case permanent:
		return StatusError, ReasonCredentialBroken
	}
	return StatusSkipped, ReasonCredentialUnavailable
}

// loadCredentials reads the rows of ids, in the order of ids. A missing row
// or a bound host that does not parse fails: a credential is never sent
// with fewer bounds than stored, or to no bounds at all.
func loadCredentials(ctx context.Context, q store.Querier, ids []uuid.UUID) ([]credentialRow, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `SELECT id, credential_id, kind, bound_hosts, COALESCE(header_name, ''), COALESCE(oauth_token_url, ''), oauth_scopes, expires_at
		FROM synthetic_credentials WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	byID := map[uuid.UUID]credentialRow{}
	for rows.Next() {
		var c credentialRow
		var hosts []string
		if err := rows.Scan(&c.id, &c.credentialID, &c.kind, &hosts, &c.headerName, &c.tokenURL, &c.scopes, &c.expiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		for _, h := range hosts {
			r, err := hostallow.ParseRule(h)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("%w: credential %s: bound host does not parse", errCredential, c.id)
			}
			c.bound = append(c.bound, r)
		}
		if len(c.bound) == 0 {
			rows.Close()
			return nil, fmt.Errorf("%w: credential %s has no bound hosts", errCredential, c.id)
		}
		byID[c.id] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]credentialRow, 0, len(ids))
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("%w: credential %s not found", errCredential, id)
		}
		out = append(out, c)
	}
	return out, nil
}

// CredentialBounds returns the bound hosts of each credential of ids, as
// spec.ValidateTaint takes them. Give it CredentialIDs of the scenario.
func CredentialBounds(ctx context.Context, q store.Querier, ids []uuid.UUID) (map[uuid.UUID][]hostallow.Rule, error) {
	rows, err := loadCredentials(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID][]hostallow.Rule, len(rows))
	for _, c := range rows {
		out[c.id] = c.bound
	}
	return out, nil
}

// resolvedCred is a synthetic credential and the credentials row that backs
// its secret when it was loaded. Recording a result checks the backing row
// is still the same, so that a run that loaded a secret before a rotation
// does not mark the rotated credential (credstate.go).
type resolvedCred struct{ ID, Backing uuid.UUID }

// runCredentials resolves the credentials of ids for one run at now. A
// credential whose expires_at has passed is refused. The caller
// zeroes the result with spec.ZeroCredentials, whatever happens; on an
// error, nothing is left to zero.
//
// A credential that is expired or does not resolve fails with a
// *credentialFailure that names it; resolved lists the credentials that
// resolved before it (all of ids on success), so that dispatch records the
// state of each credential it actually tried (#54).
//
// Only basic and OAuth2 credentials carry a user name (the client id for
// OAuth2): for the other kinds the stored user name is a label, and the
// probe would scrub it from every result as if it were secret.
func runCredentials(ctx context.Context, q store.Querier, creds *backup.Credentials, ids []uuid.UUID, now time.Time) (out []spec.RunCredential, resolved []resolvedCred, err error) {
	rows, err := loadCredentials(ctx, q, ids)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range rows {
		if c.expiresAt != nil && !now.Before(*c.expiresAt) {
			return nil, nil, &credentialFailure{c.id, c.credentialID, fmt.Errorf("%w at %s", errCredentialExpired, c.expiresAt.UTC().Format(time.RFC3339))}
		}
	}
	if len(rows) > 0 && creds == nil {
		return nil, nil, errors.New("no credential store")
	}
	defer func() {
		if err != nil {
			spec.ZeroCredentials(out)
			out = nil
		}
	}()
	for _, c := range rows {
		rc := spec.RunCredential{ID: c.id, Kind: c.kind, HeaderName: c.headerName, TokenURL: c.tokenURL, Scopes: c.scopes}
		for _, r := range c.bound {
			rc.BoundHosts = append(rc.BoundHosts, hostallow.FormatRule(r))
		}
		login, err := creds.Resolve(ctx, q, c.credentialID)
		if err != nil {
			return out, resolved, &credentialFailure{c.id, c.credentialID, err}
		}
		// NewSecret takes the resolved buffer: ZeroCredentials reaches it.
		rc.Secret = spec.NewSecret(login.Secret)
		if c.kind == spec.CredBasic || c.kind == spec.CredOAuth2 {
			rc.Username = spec.NewSecret([]byte(login.Username))
		}
		out = append(out, rc)
		if rc.Secret == nil {
			return out, resolved, &credentialFailure{c.id, c.credentialID, errCredentialEmpty}
		}
		resolved = append(resolved, resolvedCred{c.id, c.credentialID})
	}
	return out, resolved, nil
}

// loadAllowlist reads the allowlist and its version in one statement, so
// the two match. A stored rule that does not validate is left out (fail
// closed: fewer hosts are allowed); the probe would refuse the whole run.
func loadAllowlist(ctx context.Context, q store.Querier) (*pb.AllowlistSnapshot, int, error) {
	rows, err := q.Query(ctx, `SELECT v.version, a.pattern, a.kind FROM synthetic_allowlist_version v
		LEFT JOIN synthetic_allowlist a ON true WHERE v.id = 1 ORDER BY a.kind, a.pattern`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	snap := &pb.AllowlistSnapshot{}
	dropped := 0
	found := false
	for rows.Next() {
		var pattern, kind *string
		if err := rows.Scan(&snap.Version, &pattern, &kind); err != nil {
			return nil, 0, err
		}
		found = true
		if pattern == nil || kind == nil {
			continue
		}
		r, err := hostallow.ValidateRule(hostallow.Rule{Pattern: *pattern, Kind: hostallow.Kind(*kind)})
		if err != nil {
			dropped++
			continue
		}
		snap.Rules = append(snap.Rules, &pb.AllowRule{Pattern: r.Pattern, Kind: string(r.Kind)})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if !found {
		return nil, 0, errors.New("synthetic_allowlist_version has no row")
	}
	return snap, dropped, nil
}

// runScenario reads what a run runs: the test_spec of a test run, else the
// saved scenario.
func runScenario(ctx context.Context, q store.Querier, scenarioID *uuid.UUID, testSpec []byte) (*spec.Scenario, error) {
	if testSpec != nil {
		var sc spec.Scenario
		if err := json.Unmarshal(testSpec, &sc); err != nil {
			return nil, err
		}
		return &sc, nil
	}
	if scenarioID == nil {
		return nil, pgx.ErrNoRows
	}
	return LoadScenario(ctx, q, *scenarioID)
}
