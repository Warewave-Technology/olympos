package synthetic

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/net/http/httpguts"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Limits of the settings input.
const (
	maxNote       = 500
	maxCredName   = 200
	maxBoundHosts = 20
	maxScopes     = 1024
)

// The settings link of the messages.
const settingsLink = "/settings/synthetic"

// mayReadSettings: editors pick hosts and credentials from these lists;
// readers with scope all see them as they see every global setting.
func mayReadSettings(sub *authz.Subject) bool {
	return sub.CanAny(authz.PermSyntheticEdit) || sub.CanGlobal(authz.PermRead)
}

// ---------------------------------------------------------------- allowlist rows

// ruleRow is a synthetic_allowlist row.
type ruleRow struct {
	ID            uuid.UUID      `json:"id"`
	Pattern       string         `json:"pattern"`
	Kind          hostallow.Kind `json:"kind"`
	Note          string         `json:"note"`
	CreatedBy     *uuid.UUID     `json:"created_by"`
	CreatedByName string         `json:"created_by_name"`
	CreatedAt     time.Time      `json:"created_at"`
}

type ruleSet []ruleRow

func (rs ruleSet) list() hostallow.List {
	l := hostallow.List{Rules: make([]hostallow.Rule, len(rs))}
	for i, r := range rs {
		l.Rules[i] = hostallow.Rule{Pattern: r.Pattern, Kind: r.Kind}
	}
	return l
}

// find returns the row of a rule Match returned.
func (rs ruleSet) find(r hostallow.Rule) *ruleRow {
	for i := range rs {
		if rs[i].Pattern == r.Pattern && rs[i].Kind == r.Kind {
			return &rs[i]
		}
	}
	return nil
}

func (rs ruleSet) without(id uuid.UUID) ruleSet {
	out := ruleSet{}
	for _, r := range rs {
		if r.ID != id {
			out = append(out, r)
		}
	}
	return out
}

// loadRules reads the allowlist, in the order of the probe's snapshot.
func loadRules(ctx context.Context, q store.Querier) (ruleSet, error) {
	rows, err := q.Query(ctx, `SELECT a.id, a.pattern, a.kind, a.note, a.created_by, COALESCE(p.display_name_snapshot, ''), a.created_at
		FROM synthetic_allowlist a LEFT JOIN principals p ON p.id = a.created_by ORDER BY a.kind, a.pattern`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ruleRow, error) {
		var x ruleRow
		return x, r.Scan(&x.ID, &x.Pattern, &x.Kind, &x.Note, &x.CreatedBy, &x.CreatedByName, &x.CreatedAt)
	})
}

// scenarioHosts is a scenario with the normalized hosts its steps reach.
type scenarioHosts struct {
	id    uuid.UUID
	name  string
	hosts []string
}

// loadScenarioHosts reads the hosts of every scenario: only the fields of
// the step specs that hold a host, not the bodies.
func loadScenarioHosts(ctx context.Context, q store.Querier) ([]scenarioHosts, error) {
	rows, err := q.Query(ctx, `SELECT s.id, s.name, st.kind, st.spec->>'url', st.spec->>'name', st.spec->>'host', st.spec->>'sni'
		FROM scenarios s JOIN scenario_steps st ON st.scenario_id = s.id ORDER BY s.name, s.id, st.position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scenarioHosts
	var cur *spec.Scenario
	flush := func() {
		if cur != nil {
			out[len(out)-1].hosts = spec.Hosts(cur)
		}
	}
	for rows.Next() {
		var id uuid.UUID
		var name, kind string
		var u, n, h, sni *string
		if err := rows.Scan(&id, &name, &kind, &u, &n, &h, &sni); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].id != id {
			flush()
			out = append(out, scenarioHosts{id: id, name: name})
			cur = &spec.Scenario{}
		}
		st := spec.Step{Kind: kind}
		switch kind {
		case spec.KindHTTP:
			st.HTTP = &spec.HTTPSpec{URL: str(u)}
		case spec.KindDNS:
			st.DNS = &spec.DNSSpec{Name: str(n)}
		case spec.KindTCP:
			st.TCP = &spec.TCPSpec{Host: str(h)}
		case spec.KindTLS:
			st.TLS = &spec.TLSSpec{Host: str(h), SNI: str(sni)}
		}
		cur.Steps = append(cur.Steps, st)
	}
	flush()
	return out, rows.Err()
}

// credentialBounds is a credential with what the allowlist must cover.
type credentialBounds struct {
	id        uuid.UUID
	name      string
	bound     []hostallow.Rule
	tokenHost string
}

func loadCredentialBounds(ctx context.Context, q store.Querier) ([]credentialBounds, error) {
	rows, err := q.Query(ctx, `SELECT id, name, bound_hosts, COALESCE(oauth_token_url, '') FROM synthetic_credentials ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (credentialBounds, error) {
		var c credentialBounds
		var hosts []string
		var token string
		if err := r.Scan(&c.id, &c.name, &hosts, &token); err != nil {
			return c, err
		}
		for _, h := range hosts {
			if b, err := hostallow.ParseRule(h); err == nil {
				c.bound = append(c.bound, b)
			}
		}
		if token != "" {
			c.tokenHost = normalized(urlHost(token))
		}
		return c, nil
	})
}

// ---------------------------------------------------------------- allowlist handlers

// ruleView is an allowlist rule with the scenarios that reach a host it
// matches (another rule may match the same host).
type ruleView struct {
	ruleRow
	Scenarios int `json:"scenarios"`
}

func (a *API) listAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !mayReadSettings(sub) {
		httpx.Forbidden(w, "")
		return
	}
	var version int64
	if err := a.db().QueryRow(ctx, `SELECT version FROM synthetic_allowlist_version WHERE id = 1`).Scan(&version); err != nil {
		a.fail(w, r, err)
		return
	}
	rules, err := loadRules(ctx, a.db())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	uses, err := loadScenarioHosts(ctx, a.db())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]ruleView, 0, len(rules))
	for _, rule := range rules {
		one := hostallow.List{Rules: []hostallow.Rule{{Pattern: rule.Pattern, Kind: rule.Kind}}}
		n := 0
		for _, u := range uses {
			for _, h := range u.hosts {
				if _, ok := one.Match(h); ok {
					n++
					break
				}
			}
		}
		out = append(out, ruleView{ruleRow: rule, Scenarios: n})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out, "version": version})
}

type ruleInput struct {
	Pattern string `json:"pattern"`
	Kind    string `json:"kind"`
	Note    string `json:"note"`
}

func (a *API) addRule(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	var in ruleInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	fields := map[string]string{}
	rule, err := hostallow.ValidateRule(hostallow.Rule{Pattern: strings.TrimSpace(in.Pattern), Kind: hostallow.Kind(in.Kind)})
	if err != nil {
		key := "pattern"
		if in.Kind != string(hostallow.Exact) && in.Kind != string(hostallow.Wildcard) && in.Kind != string(hostallow.Suffix) {
			key = "kind"
		}
		fields[key] = ruleMessage(err)
	}
	note := strings.TrimSpace(in.Note)
	if utf8.RuneCountInString(note) > maxNote || !utf8.ValidString(note) {
		fields["note"] = fmt.Sprintf("at most %d characters", maxNote)
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid rule", fields)
		return
	}
	var row ruleRow
	err = store.Tx(ctx, a.db(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM synthetic_allowlist_version WHERE id = 1 FOR UPDATE`); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO synthetic_allowlist (pattern, kind, note, created_by) VALUES ($1, $2, $3, $4)
			RETURNING id, created_at`, rule.Pattern, rule.Kind, note, httpx.ActorID(r)).Scan(&row.ID, &row.CreatedAt); err != nil {
			return err
		}
		row.Pattern, row.Kind, row.Note, row.CreatedBy, row.CreatedByName = rule.Pattern, rule.Kind, note, httpx.ActorID(r), sub.Principal.DisplayName
		if err := httpx.Record(r, tx, "synthetic.allowlist_rule_added", "synthetic_allowlist", row.ID.String(), nil,
			map[string]any{"pattern": rule.Pattern, "kind": rule.Kind, "note": note}); err != nil {
			return err
		}
		return emitAllowlistChanged(ctx, tx, "added", row.ID, rule, sub.Principal.DisplayName)
	})
	if store.IsUniqueViolation(err) {
		httpx.FieldErrors(w, "invalid rule", map[string]string{"pattern": "This rule exists already."})
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, ruleView{ruleRow: row})
}

// ruleMessage is the field message of a rule that does not validate.
func ruleMessage(err error) string {
	switch {
	case errors.Is(err, hostallow.ErrIPLiteral):
		return "IP addresses are never allowed; use a host name"
	case errors.Is(err, hostallow.ErrDeniedName):
		return "localhost and the Kubernetes API are always denied"
	}
	// ValidateRule's text names the pattern and what is wrong with it.
	return strings.TrimPrefix(err.Error(), hostallow.ErrInvalidHost.Error()+" ")
}

// emitAllowlistChanged sends synthetic.allowlist_changed: what the probes
// may reach changed (routed like grant.changed, migration 00024).
func emitAllowlistChanged(ctx context.Context, tx pgx.Tx, change string, id uuid.UUID, rule hostallow.Rule, by string) error {
	return notify.Emit(ctx, tx, notify.Event{
		Type:   notify.SyntheticAllowlistChanged,
		Key:    notify.SyntheticAllowlistChanged + ":" + change + ":" + id.String(),
		Title:  fmt.Sprintf("Synthetic allowlist: %s %s rule %s", change, rule.Kind, rule.Pattern),
		Link:   settingsLink,
		Fields: map[string]string{"change": change, "rule": rule.Pattern, "kind": string(rule.Kind), "by": by},
	})
}

// removeRule deletes an allowlist rule, unless a scenario reaches a host
// that only this rule allows, or a credential's bound hosts or token URL
// would leave the allowlist (409, naming them).
func (a *API) removeRule(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	err := store.Tx(ctx, a.db(), func(tx pgx.Tx) error {
		// Saves of scenarios and credentials hold this row FOR SHARE while
		// they check their hosts.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM synthetic_allowlist_version WHERE id = 1 FOR UPDATE`); err != nil {
			return err
		}
		rules, err := loadRules(ctx, tx)
		if err != nil {
			return err
		}
		var gone *ruleRow
		for i := range rules {
			if rules[i].ID == id {
				gone = &rules[i]
			}
		}
		if gone == nil {
			return store.ErrNotFound
		}
		before, after := rules.list(), rules.without(id).list()
		scenarios, creds, err := neededBy(ctx, tx, before, after)
		if err != nil {
			return err
		}
		if len(scenarios) > 0 || len(creds) > 0 {
			return inUse("This rule is still needed", scenarios, creds)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM synthetic_allowlist WHERE id = $1`, id); err != nil {
			return err
		}
		if err := httpx.Record(r, tx, "synthetic.allowlist_rule_removed", "synthetic_allowlist", id.String(), nil,
			map[string]any{"pattern": gone.Pattern, "kind": gone.Kind, "note": gone.Note}); err != nil {
			return err
		}
		return emitAllowlistChanged(ctx, tx, "removed", id, hostallow.Rule{Pattern: gone.Pattern, Kind: gone.Kind}, sub.Principal.DisplayName)
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// neededBy names the scenarios with a host that before allows and after
// does not, and the credentials whose bounds or token URL before covers
// and after does not.
func neededBy(ctx context.Context, q store.Querier, before, after hostallow.List) (scenarios, creds []string, err error) {
	uses, err := loadScenarioHosts(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	for _, u := range uses {
		for _, h := range u.hosts {
			_, was := before.Match(h)
			_, is := after.Match(h)
			if was && !is {
				scenarios = append(scenarios, u.name)
				break
			}
		}
	}
	cs, err := loadCredentialBounds(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range cs {
		broken := false
		for _, b := range c.bound {
			if before.Covers(b) && !after.Covers(b) {
				broken = true
			}
		}
		if c.tokenHost != "" {
			_, was := before.Match(c.tokenHost)
			_, is := after.Match(c.tokenHost)
			broken = broken || was && !is
		}
		if broken {
			creds = append(creds, c.name)
		}
	}
	return scenarios, creds, nil
}

// inUse is the 409 of a rule or credential still in use.
func inUse(what string, scenarios, creds []string) *apiError {
	msg := what
	switch {
	case len(scenarios) > 0 && len(creds) > 0:
		msg += " by scenarios " + strings.Join(scenarios, ", ") + " and by credentials " + strings.Join(creds, ", ")
	case len(scenarios) > 0:
		msg += " by scenarios " + strings.Join(scenarios, ", ")
	default:
		msg += " by credentials " + strings.Join(creds, ", ")
	}
	msg += ". Change them first."
	if scenarios == nil {
		scenarios = []string{}
	}
	if creds == nil {
		creds = []string{}
	}
	return &apiError{code: http.StatusConflict, msg: msg, extra: map[string]any{"scenarios": scenarios, "credentials": creds}}
}

// hostCheck is POST /allowlist/check: whether a host may be reached, by
// which rule (and which others match it too), or why not.
type hostCheck struct {
	Host         string     `json:"host"`
	Allowed      bool       `json:"allowed"`
	Rule         *ruleRow   `json:"rule"`
	Also         []*ruleRow `json:"also"`
	DeniedReason string     `json:"denied_reason"`
	Message      string     `json:"message"`
}

// Why a checked host is denied.
const (
	DeniedIPLiteral    = "ip_literal"
	DeniedAlwaysDenied = "always_denied"
	DeniedInvalid      = "invalid_host"
	DeniedNoRule       = "no_rule"
)

func (a *API) checkHost(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanAny(authz.PermSyntheticEdit) {
		httpx.Forbidden(w, "")
		return
	}
	var in struct {
		Host string `json:"host"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	host := strings.TrimSpace(in.Host)
	if strings.Contains(host, "://") {
		host = urlHost(host)
	}
	if host == "" {
		httpx.FieldErrors(w, "invalid check", map[string]string{"host": "required"})
		return
	}
	out := hostCheck{Host: host, Also: []*ruleRow{}}
	n, err := hostallow.Normalize(host)
	switch {
	case errors.Is(err, hostallow.ErrIPLiteral):
		out.DeniedReason, out.Message = DeniedIPLiteral, "IP addresses are always denied; use a host name."
	case errors.Is(err, hostallow.ErrDeniedName):
		out.DeniedReason, out.Message = DeniedAlwaysDenied, "localhost and the Kubernetes API are always denied, whatever the rules say."
	case err != nil:
		out.DeniedReason, out.Message = DeniedInvalid, "Not a valid host name."
	}
	if err != nil {
		httpx.JSON(w, http.StatusOK, out)
		return
	}
	out.Host = n
	rules, err := loadRules(ctx, a.db())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	for i, m := range rules.list().MatchAll(n) {
		row := rules.find(m)
		if row == nil {
			continue
		}
		if i == 0 {
			out.Rule = row
		} else {
			out.Also = append(out.Also, row)
		}
	}
	out.Allowed = out.Rule != nil
	if !out.Allowed {
		out.DeniedReason, out.Message = DeniedNoRule, "No rule matches "+n+"."
	}
	httpx.JSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- credentials

// credentialInput is the body of POST and PUT /credentials. Secret is
// write-only: required on create, optional on update (given: the secret is
// rotated). Bearer and header credentials have no user name; for basic it
// is the login and for OAuth2 the client id.
type credentialInput struct {
	Name          string                  `json:"name"`
	Kind          string                  `json:"kind"`
	BoundHosts    []ruleInput             `json:"bound_hosts"`
	Secret        *backup.CredentialInput `json:"secret"`
	HeaderName    string                  `json:"header_name"`
	OAuthTokenURL string                  `json:"oauth_token_url"`
	OAuthScopes   string                  `json:"oauth_scopes"`
	ExpiresAt     *time.Time              `json:"expires_at"`
}

// validCredential is a checked credential input.
type validCredential struct {
	name, kind, header, tokenURL, scopes string
	bound                                []hostallow.Rule
	expiresAt                            *time.Time
}

func (v *validCredential) boundStrings() []string {
	out := make([]string, len(v.bound))
	for i, b := range v.bound {
		out[i] = hostallow.FormatRule(b)
	}
	return out
}

// Headers a header credential may not set.
var reservedCredentialHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true, "Cookie": true,
}

// validateCredential checks the metadata of a credential (not its secret)
// against the allowlist l: each bound host within the allowlist; an OAuth2
// token URL https, allowlisted and inside the bound hosts (ruling P2).
func validateCredential(in *credentialInput, l hostallow.List, fields map[string]string) *validCredential {
	v := &validCredential{name: strings.TrimSpace(in.Name), kind: in.Kind, header: strings.TrimSpace(in.HeaderName),
		tokenURL: strings.TrimSpace(in.OAuthTokenURL), scopes: strings.TrimSpace(in.OAuthScopes), expiresAt: in.ExpiresAt}
	switch {
	case v.name == "":
		fields["name"] = "required"
	case utf8.RuneCountInString(v.name) > maxCredName || !utf8.ValidString(v.name):
		fields["name"] = fmt.Sprintf("at most %d characters", maxCredName)
	}
	switch v.kind {
	case spec.CredBearer, spec.CredBasic, spec.CredHeader, spec.CredOAuth2:
	default:
		fields["kind"] = "must be bearer, basic, header or oauth2_client_credentials"
	}
	switch {
	case len(in.BoundHosts) == 0:
		fields["bound_hosts"] = "at least one host the credential may be sent to"
	case len(in.BoundHosts) > maxBoundHosts:
		fields["bound_hosts"] = fmt.Sprintf("at most %d", maxBoundHosts)
	}
	seen := map[string]bool{}
	for i, b := range in.BoundHosts {
		key := fmt.Sprintf("bound_hosts.%d", i)
		rule, err := hostallow.ValidateRule(hostallow.Rule{Pattern: strings.TrimSpace(b.Pattern), Kind: hostallow.Kind(b.Kind)})
		switch {
		case err != nil:
			fields[key] = ruleMessage(err)
		case !l.Covers(rule):
			fields[key] = fmt.Sprintf("%s is not inside the allowlist: every host it matches must be allowed. Add a rule first.", rule.Pattern)
		case seen[hostallow.FormatRule(rule)]:
			fields[key] = "listed twice"
		default:
			seen[hostallow.FormatRule(rule)] = true
			v.bound = append(v.bound, rule)
		}
	}
	if v.kind == spec.CredHeader {
		canon := textproto.CanonicalMIMEHeaderKey(v.header)
		switch {
		case v.header == "":
			fields["header_name"] = "required for a header credential"
		case !httpguts.ValidHeaderFieldName(v.header):
			fields["header_name"] = "not a valid header name"
		case reservedCredentialHeaders[canon]:
			fields["header_name"] = canon + " cannot carry a credential"
		}
	} else if v.header != "" {
		fields["header_name"] = "only a header credential names its header"
	}
	if v.kind == spec.CredOAuth2 {
		if msg := validateTokenURL(v.tokenURL, l, v.bound); msg != "" {
			fields["oauth_token_url"] = msg
		}
		if len(v.scopes) > maxScopes {
			fields["oauth_scopes"] = fmt.Sprintf("at most %d characters", maxScopes)
		}
	} else {
		if v.tokenURL != "" {
			fields["oauth_token_url"] = "only an OAuth2 credential has a token URL"
		}
		if v.scopes != "" {
			fields["oauth_scopes"] = "only an OAuth2 credential has scopes"
		}
	}
	return v
}

func validateTokenURL(raw string, l hostallow.List, bound []hostallow.Rule) string {
	if raw == "" {
		return "required for an OAuth2 credential"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return "must be an https:// URL"
	}
	if u.User != nil {
		return "must not contain a user name or password"
	}
	if strings.Contains(raw, "${") {
		return "variables are not allowed in the token URL"
	}
	host, err := hostallow.Normalize(u.Hostname())
	if err != nil {
		return "the host is not allowed: IP addresses, localhost and the Kubernetes API are always denied"
	}
	if _, ok := l.Match(host); !ok {
		return hostNotAllowed(host, true)
	}
	if _, ok := (hostallow.List{Rules: bound}).Match(host); !ok {
		return fmt.Sprintf("%s must be inside the credential's bound hosts: the client secret is sent to it", host)
	}
	return ""
}

// validateSecret checks a secret input. Bearer and header credentials carry
// no user name: the credential's name stands in for the label the
// credentials row requires (the probe is not given it, Task 8).
func validateSecret(kind, name string, in *backup.CredentialInput, fields map[string]string) {
	if kind == spec.CredBearer || kind == spec.CredHeader {
		if strings.TrimSpace(in.Username) != "" {
			fields["secret.username"] = "a " + kind + " credential has no user name"
			return
		}
		in.Username = name
	}
	for k, v := range in.Validate("secret.", secrets.RefUse{GlobalAdmin: true}) {
		if k == "secret.username" && kind == spec.CredOAuth2 {
			v = "the client id is required"
		}
		fields[k] = v
	}
}

// credentialView is a credential as the API shows it: never its secret.
type credentialView struct {
	ID            uuid.UUID      `json:"id"`
	Name          string         `json:"name"`
	Kind          string         `json:"kind"`
	BoundHosts    []ruleInput    `json:"bound_hosts"`
	HeaderName    string         `json:"header_name"`
	OAuthTokenURL string         `json:"oauth_token_url"`
	OAuthScopes   string         `json:"oauth_scopes"`
	Source        string         `json:"source"`
	ExpiresAt     *time.Time     `json:"expires_at"`
	Expired       bool           `json:"expired"`
	RotatedAt     *time.Time     `json:"rotated_at"`
	Scenarios     []scenarioName `json:"scenarios"`
	// ResolveFailures24h counts the runs of the scenarios that use the
	// credential skipped in the last 24 hours because the server could not
	// resolve a credential (credential_unavailable: Key Vault, the
	// envelope). A run names no credential, so with several credentials
	// in one scenario this is an upper bound.
	ResolveFailures24h  int        `json:"resolve_failures_24h"`
	LastResolveFailedAt *time.Time `json:"last_resolve_failed_at"`
	CreatedBy           *uuid.UUID `json:"created_by"`
	CreatedByName       string     `json:"created_by_name"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type scenarioName struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// loadCredentialViews reads the credentials (only, when given). seen says
// which scenarios the caller sees; the others are left out of Scenarios.
func loadCredentialViews(ctx context.Context, q store.Querier, only *uuid.UUID, now time.Time, seen func(uuid.UUID) bool) ([]credentialView, error) {
	rows, err := q.Query(ctx, `SELECT c.id, c.name, c.kind, c.bound_hosts, COALESCE(c.header_name, ''), COALESCE(c.oauth_token_url, ''),
			c.oauth_scopes, k.kind, c.expires_at, c.rotated_at, c.created_by, COALESCE(p.display_name_snapshot, ''), c.created_at, c.updated_at,
			COALESCE(f.n, 0), f.last
		FROM synthetic_credentials c JOIN credentials k ON k.id = c.credential_id
		LEFT JOIN principals p ON p.id = c.created_by
		LEFT JOIN LATERAL (SELECT count(*) AS n, max(r.finished_at) AS last FROM synthetic_runs r
			WHERE r.failure_reason = $3 AND r.finished_at > $2::timestamptz - interval '24 hours'
			  AND r.scenario_id IN (SELECT st.scenario_id FROM scenario_steps st WHERE st.credential_id = c.id)) f ON true
		WHERE $1::uuid IS NULL OR c.id = $1 ORDER BY c.name`, only, now, ReasonCredentialUnavailable)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (credentialView, error) {
		var c credentialView
		var hosts []string
		if err := r.Scan(&c.ID, &c.Name, &c.Kind, &hosts, &c.HeaderName, &c.OAuthTokenURL, &c.OAuthScopes, &c.Source,
			&c.ExpiresAt, &c.RotatedAt, &c.CreatedBy, &c.CreatedByName, &c.CreatedAt, &c.UpdatedAt,
			&c.ResolveFailures24h, &c.LastResolveFailedAt); err != nil {
			return c, err
		}
		c.BoundHosts = []ruleInput{}
		for _, h := range hosts {
			kind, pattern, _ := strings.Cut(h, ":")
			c.BoundHosts = append(c.BoundHosts, ruleInput{Pattern: pattern, Kind: kind})
		}
		c.Expired = c.ExpiresAt != nil && !now.Before(*c.ExpiresAt)
		c.Scenarios = []scenarioName{}
		return c, nil
	})
	if err != nil || len(out) == 0 {
		return out, err
	}
	byID := map[uuid.UUID]*credentialView{}
	ids := make([]uuid.UUID, len(out))
	for i := range out {
		byID[out[i].ID] = &out[i]
		ids[i] = out[i].ID
	}
	rows, err = q.Query(ctx, `SELECT DISTINCT st.credential_id, s.id, s.name FROM scenario_steps st JOIN scenarios s ON s.id = st.scenario_id
		WHERE st.credential_id = ANY($1) ORDER BY s.name, s.id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid uuid.UUID
		var s scenarioName
		if err := rows.Scan(&cid, &s.ID, &s.Name); err != nil {
			return nil, err
		}
		if seen(s.ID) {
			byID[cid].Scenarios = append(byID[cid].Scenarios, s)
		}
	}
	return out, rows.Err()
}

// seenScenarios returns the test of which scenarios sub sees.
func (a *API) seenScenarios(ctx context.Context, sub *authz.Subject) (func(uuid.UUID) bool, error) {
	if sub.CanGlobal(authz.PermRead) {
		return func(uuid.UUID) bool { return true }, nil
	}
	f, err := loadFleet(ctx, a.db(), sub)
	if err != nil {
		return nil, err
	}
	ss, err := visibleScenarios(ctx, a.db(), sub, f)
	if err != nil {
		return nil, err
	}
	ok := map[uuid.UUID]bool{}
	for _, s := range ss {
		ok[s.ID] = true
	}
	return func(id uuid.UUID) bool { return ok[id] }, nil
}

func (a *API) listCredentials(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !mayReadSettings(sub) {
		httpx.Forbidden(w, "")
		return
	}
	seen, err := a.seenScenarios(ctx, sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cs, err := loadCredentialViews(ctx, a.db(), nil, a.now(), seen)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": cs})
}

// respondCredential writes the stored credential id (to an admin).
func (a *API) respondCredential(w http.ResponseWriter, r *http.Request, code int, id uuid.UUID) {
	cs, err := loadCredentialViews(r.Context(), a.db(), &id, a.now(), func(uuid.UUID) bool { return true })
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if len(cs) == 0 {
		httpx.NotFound(w)
		return
	}
	httpx.JSON(w, code, cs[0])
}

// credentialAudit is what the activity log keeps of a credential: never
// its secret or its user name.
func credentialAudit(v *validCredential, source string) map[string]any {
	d := map[string]any{"name": v.name, "kind": v.kind, "bound_hosts": v.boundStrings()}
	if v.header != "" {
		d["header_name"] = v.header
	}
	if v.tokenURL != "" {
		d["oauth_token_url"] = v.tokenURL
	}
	if v.expiresAt != nil {
		d["expires_at"] = v.expiresAt.UTC().Format(time.RFC3339)
	}
	if source != "" {
		d["source"] = source
	}
	return d
}

// lockAllowlistShared holds the allowlist version row FOR SHARE (removing a
// rule waits) and returns the allowlist.
func lockAllowlistShared(ctx context.Context, tx pgx.Tx) (hostallow.List, error) {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM synthetic_allowlist_version WHERE id = 1 FOR SHARE`); err != nil {
		return hostallow.List{}, err
	}
	rules, err := loadRules(ctx, tx)
	return rules.list(), err
}

func (a *API) createCredential(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	var in credentialInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	defer zeroInput(&in)
	var id uuid.UUID
	err := store.Tx(ctx, a.db(), func(tx pgx.Tx) error {
		l, err := lockAllowlistShared(ctx, tx)
		if err != nil {
			return err
		}
		fields := map[string]string{}
		v := validateCredential(&in, l, fields)
		if in.Secret == nil {
			fields["secret"] = "required"
		} else {
			validateSecret(v.kind, v.name, in.Secret, fields)
		}
		if v.expiresAt != nil && !v.expiresAt.After(a.now()) {
			fields["expires_at"] = "must be in the future"
		}
		if len(fields) > 0 {
			return invalid("invalid credential", fields)
		}
		credID, err := a.Svc.Creds.Insert(ctx, tx, *in.Secret)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO synthetic_credentials (name, kind, bound_hosts, credential_id, header_name,
				oauth_token_url, oauth_scopes, expires_at, created_by) VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9)
			RETURNING id`, v.name, v.kind, v.boundStrings(), credID, v.header, v.tokenURL, v.scopes, v.expiresAt, httpx.ActorID(r)).Scan(&id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "synthetic.credential_created", "synthetic_credential", id.String(), nil, credentialAudit(v, in.Secret.Source))
	})
	if store.IsUniqueViolation(err) {
		httpx.FieldErrors(w, "invalid credential", map[string]string{"name": "A credential with this name exists already."})
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondCredential(w, r, http.StatusCreated, id)
}

// updateCredential replaces a credential's metadata, and rotates its secret
// when one is given. The kind cannot change. Narrowing the bound hosts (or
// moving the token URL) is refused while a scenario that uses the
// credential would no longer save: a step's host outside the bounds, or a
// variable carrying the credential sent outside them (409).
func (a *API) updateCredential(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in credentialInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	defer zeroInput(&in)
	err := store.Tx(ctx, a.db(), func(tx pgx.Tx) error {
		var kind string
		var oldCred uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT kind, credential_id FROM synthetic_credentials WHERE id = $1 FOR UPDATE`, id).Scan(&kind, &oldCred); err != nil {
			return store.NotFound(err)
		}
		l, err := lockAllowlistShared(ctx, tx)
		if err != nil {
			return err
		}
		fields := map[string]string{}
		if in.Kind == "" {
			in.Kind = kind
		}
		v := validateCredential(&in, l, fields)
		if v.kind != kind && fields["kind"] == "" {
			fields["kind"] = "the kind cannot change; create a new credential"
		}
		if in.Secret != nil {
			validateSecret(v.kind, v.name, in.Secret, fields)
		}
		if len(fields) > 0 {
			return invalid("invalid credential", fields)
		}
		broken, err := scenariosBrokenBy(ctx, tx, id, v.bound)
		if err != nil {
			return err
		}
		if len(broken) > 0 {
			return &apiError{code: http.StatusConflict, extra: map[string]any{"scenarios": broken, "credentials": []string{}},
				msg: "These bound hosts would break scenarios that use this credential: " + strings.Join(broken, ", ") + ". Change them first."}
		}
		if _, err := tx.Exec(ctx, `UPDATE synthetic_credentials SET name = $2, bound_hosts = $3, header_name = NULLIF($4, ''),
				oauth_token_url = NULLIF($5, ''), oauth_scopes = $6, expires_at = $7 WHERE id = $1`,
			id, v.name, v.boundStrings(), v.header, v.tokenURL, v.scopes, v.expiresAt); err != nil {
			return err
		}
		action, source := "synthetic.credential_updated", ""
		if in.Secret != nil {
			newCred, err := a.Svc.Creds.Insert(ctx, tx, *in.Secret)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE synthetic_credentials SET credential_id = $2, rotated_at = $3 WHERE id = $1`, id, newCred, a.now()); err != nil {
				return err
			}
			if err := a.Svc.Creds.Delete(ctx, tx, oldCred); err != nil {
				return err
			}
			action, source = "synthetic.credential_rotated", in.Secret.Source
		}
		return httpx.Record(r, tx, action, "synthetic_credential", id.String(), nil, credentialAudit(v, source))
	})
	if store.IsUniqueViolation(err) {
		httpx.FieldErrors(w, "invalid credential", map[string]string{"name": "A credential with this name exists already."})
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondCredential(w, r, http.StatusOK, id)
}

// scenariosBrokenBy names the scenarios that use credential id and would
// not save with bound as its bound hosts: a step of theirs with the
// credential on a host outside them, or a ValidateTaint error.
func scenariosBrokenBy(ctx context.Context, tx pgx.Tx, id uuid.UUID, bound []hostallow.Rule) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT s.id, s.name FROM scenario_steps st JOIN scenarios s ON s.id = st.scenario_id
		WHERE st.credential_id = $1 ORDER BY s.name, s.id`, id)
	if err != nil {
		return nil, err
	}
	users, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (scenarioName, error) {
		var s scenarioName
		return s, r.Scan(&s.ID, &s.Name)
	})
	if err != nil {
		return nil, err
	}
	var broken []string
	for _, u := range users {
		sc, err := LoadScenario(ctx, tx, u.ID)
		if err != nil {
			return nil, err
		}
		bounds, err := CredentialBounds(ctx, tx, CredentialIDs(sc))
		if err != nil && !errors.Is(err, errCredential) {
			return nil, err
		}
		if bounds == nil {
			bounds = map[uuid.UUID][]hostallow.Rule{}
		}
		bounds[id] = bound
		bad := len(spec.ValidateTaint(sc, bounds)) > 0
		for _, st := range sc.Steps {
			if bad || st.CredentialID == nil || *st.CredentialID != id || st.HTTP == nil {
				continue
			}
			if host := normalized(urlHost(st.HTTP.URL)); host != "" {
				if _, ok := (hostallow.List{Rules: bound}).Match(host); !ok {
					bad = true
				}
			}
		}
		if bad {
			broken = append(broken, u.Name)
		}
	}
	return broken, nil
}

// deleteCredential removes a credential that no scenario uses (409 names
// the scenarios that do), with its secret.
func (a *API) deleteCredential(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	err := store.Tx(ctx, a.db(), func(tx pgx.Tx) error {
		var name string
		var credID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT name, credential_id FROM synthetic_credentials WHERE id = $1 FOR UPDATE`, id).Scan(&name, &credID); err != nil {
			return store.NotFound(err)
		}
		users, err := credentialUsers(ctx, tx, id)
		if err != nil {
			return err
		}
		if len(users) > 0 {
			return inUse("This credential is still used", users, nil)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM synthetic_credentials WHERE id = $1`, id); err != nil {
			return err
		}
		if err := a.Svc.Creds.Delete(ctx, tx, credID); err != nil {
			return err
		}
		return httpx.Record(r, tx, "synthetic.credential_deleted", "synthetic_credential", id.String(), nil, map[string]any{"name": name})
	})
	if isFKViolation(err) {
		// A scenario took the credential between the check and the delete.
		users, qerr := credentialUsers(ctx, a.db(), id)
		if qerr != nil {
			a.fail(w, r, qerr)
			return
		}
		a.fail(w, r, inUse("This credential is still used", users, nil))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// credentialUsers names the scenarios that use credential id, by name.
func credentialUsers(ctx context.Context, q store.Querier, id uuid.UUID) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT s.name FROM scenario_steps st JOIN scenarios s ON s.id = st.scenario_id
		WHERE st.credential_id = $1 ORDER BY s.name`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// zeroInput clears the secret of an input once it is stored. Go strings
// cannot be overwritten; dropping the reference is all that can be done.
func zeroInput(in *credentialInput) {
	if in.Secret != nil {
		in.Secret.Password = ""
	}
}

// str is *s, "" for nil.
func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
