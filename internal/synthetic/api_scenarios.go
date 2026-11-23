package synthetic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Bounds of the alert rule's thresholds.
const maxAlertThreshold = 1000

// ---------------------------------------------------------------- input

// scenarioInput is the body of POST and PUT /scenarios. Step positions are
// numbered by the server, in the order given.
type scenarioInput struct {
	Name             string      `json:"name"`
	Type             string      `json:"type"`
	OwnerSelector    string      `json:"owner_selector"`
	IntervalSeconds  int         `json:"interval_seconds"`
	TimeoutSeconds   int         `json:"timeout_seconds"`
	StepRetries      int         `json:"step_retries"`
	Enabled          *bool       `json:"enabled"`
	StoreResponses   *bool       `json:"store_responses"`
	RunOn            string      `json:"run_on"`
	RunOnSelector    string      `json:"run_on_selector"`
	ExcludeSelectors []string    `json:"exclude_selectors"`
	Steps            []stepInput `json:"steps"`
	// Alerts nil: the defaults on create, the stored rule on update.
	Alerts *alertInput `json:"alerts"`
	viewOnly
}

// viewOnly holds the read-only fields of a scenario's view (scenarioView):
// accepted and ignored, so that a scenario read with GET can be sent back
// as it is.
type viewOnly struct {
	ID                json.RawMessage `json:"id,omitempty"`
	Targets           json.RawMessage `json:"targets,omitempty"`
	RequestsPerMinute json.RawMessage `json:"requests_per_minute,omitempty"`
	CanEdit           json.RawMessage `json:"can_edit,omitempty"`
	CreatedBy         json.RawMessage `json:"created_by,omitempty"`
	CreatedByName     json.RawMessage `json:"created_by_name,omitempty"`
	CreatedAt         json.RawMessage `json:"created_at,omitempty"`
	UpdatedAt         json.RawMessage `json:"updated_at,omitempty"`
}

// stepInput is a step as spec.Step takes it. Credential and Hidden belong
// to the view (stepView): they are accepted and ignored, so that a scenario
// that was read can be sent back as it is.
type stepInput struct {
	spec.Step
	Credential json.RawMessage `json:"credential,omitempty"`
	Hidden     bool            `json:"hidden,omitempty"`
}

type alertInput struct {
	ClusterFailAfter      int        `json:"cluster_fail_after"`
	FleetCriticalClusters int        `json:"fleet_critical_clusters"`
	RecoveryAfter         int        `json:"recovery_after"`
	SendRecovery          bool       `json:"send_recovery"`
	ChannelID             *uuid.UUID `json:"channel_id"`
	CriticalChannelID     *uuid.UUID `json:"critical_channel_id"`
	// The channels' names belong to the view: accepted and ignored.
	ChannelName         json.RawMessage `json:"channel_name,omitempty"`
	CriticalChannelName json.RawMessage `json:"critical_channel_name,omitempty"`
}

func (in *scenarioInput) targeting() Targeting {
	t := Targeting{RunOn: in.RunOn, RunOnSelector: strings.TrimSpace(in.RunOnSelector), Exclude: []string{}}
	if t.RunOn == "" {
		t.RunOn = RunOnAll
	}
	if t.RunOn == RunOnAll {
		t.RunOnSelector = ""
	}
	for _, e := range in.ExcludeSelectors {
		if e = strings.TrimSpace(e); e != "" {
			t.Exclude = append(t.Exclude, e)
		}
	}
	return t
}

func (in *scenarioInput) enabled() bool { return in.Enabled == nil || *in.Enabled }

// scenario builds the spec.Scenario of the input: positions numbered from
// 0 in the order given (spec.Validate requires it).
func (in *scenarioInput) scenario(id *uuid.UUID) spec.Scenario {
	sc := spec.Scenario{
		Name: strings.TrimSpace(in.Name), Type: in.Type, IntervalSeconds: in.IntervalSeconds,
		TimeoutSeconds: in.TimeoutSeconds, StepRetries: in.StepRetries,
		StoreResponses: in.StoreResponses == nil || *in.StoreResponses,
		Steps:          make([]spec.Step, len(in.Steps)),
	}
	if id != nil {
		sc.ID = id.String()
	}
	for i, st := range in.Steps {
		s := st.Step
		s.Position = i
		if s.Assertions == nil {
			s.Assertions = []spec.Assertion{}
		}
		if s.Extracts == nil {
			s.Extracts = []spec.Extract{}
		}
		sc.Steps[i] = s
	}
	return sc
}

// decodeOptional reads an optional JSON body: an empty one leaves v as it
// is.
func decodeOptional(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON body: " + err.Error())
	}
	return nil
}

// ---------------------------------------------------------------- validation

type validateMode int

const (
	// forSave checks everything a stored scenario must keep to.
	forSave validateMode = iota
	// forTest checks what a test run sends to a probe: the steps, their
	// hosts and credentials. Targeting, alerting and the caps do not apply.
	forTest
)

// prepared is a scenario input that passed validation.
type prepared struct {
	sc        spec.Scenario
	target    Targeting
	owner     string
	enabled   bool
	rule      AlertRule
	ruleGiven bool
}

// validate checks a scenario input (the carries of Tasks 6, 8, 9 and 10):
// spec.Validate on server-numbered steps; the targeting, owner label and
// alert rule; every host against the allowlist; each step's credential
// bound to the step's host; spec.ValidateTaint with the bounds of exactly
// the credentials a run is given (CredentialIDs); for a save, the caller's
// right to the scenario's clusters and the request caps (CheckRate). self
// is the scenario being updated. The allowlist version row and the
// credentials are locked FOR SHARE, so that a rule or a credential cannot
// be removed or narrowed under a save.
func (a *API) validate(ctx context.Context, tx pgx.Tx, sub *authz.Subject, in *scenarioInput, f *fleet, self *uuid.UUID, mode validateMode) (*prepared, error) {
	p := &prepared{sc: in.scenario(self), target: in.targeting(), enabled: in.enabled(), rule: DefaultAlertRule}
	fields := spec.Validate(&p.sc)

	if mode == forSave {
		owner, msg := validateOwner(in.OwnerSelector)
		if msg != "" {
			fields["owner_selector"] = msg
		}
		p.owner = owner
		if err := p.target.Validate(); err != nil {
			key, msg, ok := strings.Cut(err.Error(), ": ")
			if !ok {
				key, msg = "run_on", err.Error()
			}
			fields[key] = msg
		}
		if in.Alerts != nil {
			p.ruleGiven = true
			rule, err := validateAlerts(ctx, tx, in.Alerts, fields)
			if err != nil {
				return nil, err
			}
			p.rule = rule
		}
	}

	if _, err := tx.Exec(ctx, `SELECT 1 FROM synthetic_allowlist_version WHERE id = 1 FOR SHARE`); err != nil {
		return nil, err
	}
	list, err := loadRules(ctx, tx)
	if err != nil {
		return nil, err
	}
	checkHosts(&p.sc, list.list(), sub.CanGlobal(authz.PermAdmin), fields)
	if err := checkCredentials(ctx, tx, &p.sc, fields); err != nil {
		return nil, err
	}
	if len(fields) > 0 {
		return nil, invalid("invalid scenario", fields)
	}
	if mode != forSave {
		return p, nil
	}

	if msg := editRefusal(sub, p.target, f); msg != "" {
		return nil, refused(http.StatusForbidden, msg)
	}
	if p.enabled {
		if err := a.checkRate(ctx, tx, &p.sc, p.target, f, self); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// checkRate refuses a scenario over a cap of §6.3 (ruling P15): over the
// per-scenario cap by itself, or blocked by the per-cluster cap on one of
// the clusters it runs on, among the scenarios there before it.
func (a *API) checkRate(ctx context.Context, q store.Querier, sc *spec.Scenario, t Targeting, f *fleet, self *uuid.UUID) error {
	var ids []uuid.UUID
	for _, tc := range f.targets(t) {
		if tc.State != TargetExcluded {
			ids = append(ids, tc.ID)
		}
	}
	over, err := a.Svc.CheckRate(ctx, q, sc, ids, self)
	if errors.Is(err, ErrRateLimit) {
		return invalid("invalid scenario", map[string]string{"interval_seconds": fmt.Sprintf(
			"The scenario makes up to %.1f requests per minute on each cluster; the cap is %.0f. Run it less often, retry less or follow fewer redirects.",
			spec.RequestsPerMinute(sc), a.Svc.scenarioCap())})
	}
	if err != nil {
		return err
	}
	if len(over) == 0 {
		return nil
	}
	names := make([]string, 0, len(over))
	for n := range over {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s (%.0f/min)", n, over[n])
	}
	return invalid("invalid scenario", map[string]string{"interval_seconds": fmt.Sprintf(
		"Over the cap of %.0f requests per minute per cluster on %s. Run it less often, retry less, or pause other scenarios there.",
		a.Svc.clusterCap(), strings.Join(parts, ", "))})
}

// validateOwner checks the owner label (key=value, a display label and a
// filter, not a scope) and returns it trimmed.
func validateOwner(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	k, v, ok := strings.Cut(s, "=")
	k, v = strings.TrimSpace(k), strings.TrimSpace(v)
	if !ok || k == "" {
		return s, "a label such as team=payments"
	}
	if errs := validation.IsQualifiedName(k); len(errs) > 0 {
		return s, "label key: " + strings.Join(errs, "; ")
	}
	if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
		return s, "label value: " + strings.Join(errs, "; ")
	}
	return k + "=" + v, ""
}

func validateAlerts(ctx context.Context, q store.Querier, in *alertInput, fields map[string]string) (AlertRule, error) {
	r := AlertRule{ClusterFailAfter: in.ClusterFailAfter, FleetCriticalClusters: in.FleetCriticalClusters,
		RecoveryAfter: in.RecoveryAfter, SendRecovery: in.SendRecovery, ChannelID: in.ChannelID, CriticalChannelID: in.CriticalChannelID}
	for key, v := range map[string]int{"alerts.cluster_fail_after": r.ClusterFailAfter,
		"alerts.fleet_critical_clusters": r.FleetCriticalClusters, "alerts.recovery_after": r.RecoveryAfter} {
		if v < 1 || v > maxAlertThreshold {
			fields[key] = fmt.Sprintf("between 1 and %d", maxAlertThreshold)
		}
	}
	for key, id := range map[string]*uuid.UUID{"alerts.channel_id": r.ChannelID, "alerts.critical_channel_id": r.CriticalChannelID} {
		if id == nil {
			continue
		}
		var ok bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notification_channels WHERE id = $1)`, *id).Scan(&ok); err != nil {
			return r, err
		}
		if !ok {
			fields[key] = "unknown channel"
		}
	}
	return r, nil
}

// hostRef is a host a step names, with the field it comes from.
type hostRef struct {
	key, host string
}

// stepHosts lists the hosts of each step's own spec, with their fields: the
// same hosts spec.Hosts returns, not normalized.
func stepHosts(sc *spec.Scenario) []hostRef {
	var out []hostRef
	for i, st := range sc.Steps {
		p := fmt.Sprintf("steps.%d.", i)
		switch {
		case st.Kind == spec.KindHTTP && st.HTTP != nil:
			if h := urlHost(st.HTTP.URL); h != "" {
				out = append(out, hostRef{p + "http.url", h})
			}
		case st.Kind == spec.KindDNS && st.DNS != nil:
			out = append(out, hostRef{p + "dns.name", st.DNS.Name})
		case st.Kind == spec.KindTCP && st.TCP != nil:
			out = append(out, hostRef{p + "tcp.host", st.TCP.Host})
		case st.Kind == spec.KindTLS && st.TLS != nil:
			out = append(out, hostRef{p + "tls.host", st.TLS.Host})
			if st.TLS.SNI != "" {
				out = append(out, hostRef{p + "tls.sni", st.TLS.SNI})
			}
		}
	}
	return out
}

// urlHost is the literal host of an HTTP step's URL, or "" when it has
// none or a variable in its authority (spec.Validate refuses both).
func urlHost(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	auth := raw[i+3:]
	if j := strings.IndexAny(auth, "/?#"); j >= 0 {
		auth = auth[:j]
	}
	if strings.Contains(auth, "${") {
		return ""
	}
	u, err := url.Parse(raw[:i+3] + auth)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// normalized returns the normalized host, or "" when it does not
// normalize (spec.Validate reports it).
func normalized(h string) string {
	n, err := hostallow.Normalize(h)
	if err != nil {
		return ""
	}
	return n
}

// hostNotAllowed is the message of a host no rule matches: an admin can
// add the rule, anyone else asks for it.
func hostNotAllowed(host string, admin bool) string {
	if admin {
		return fmt.Sprintf("Host %s is not allowed. Add a rule in Settings › Synthetic monitoring.", host)
	}
	return fmt.Sprintf("Host %s is not allowed. Ask an admin to add it to the synthetic allowlist.", host)
}

// checkHosts adds a field error for each host no allowlist rule matches.
// Every host spec.Hosts returns is covered: one that no field names (it
// cannot happen today) is reported on "steps".
func checkHosts(sc *spec.Scenario, list hostallow.List, admin bool, fields map[string]string) {
	checked := map[string]bool{}
	for _, h := range stepHosts(sc) {
		n := normalized(h.host)
		if n == "" {
			continue
		}
		checked[n] = true
		if _, ok := list.Match(n); !ok && fields[h.key] == "" {
			fields[h.key] = hostNotAllowed(n, admin)
		}
	}
	for _, n := range spec.Hosts(sc) {
		if _, ok := list.Match(n); !ok && !checked[n] && fields["steps"] == "" {
			fields["steps"] = hostNotAllowed(n, admin)
		}
	}
}

// checkCredentials checks the steps' credentials: each one exists and is
// bound to its step's host; then spec.ValidateTaint with the bounds of
// CredentialIDs(sc), the set the probe holds for a run (Task 8). The rows
// are locked FOR SHARE until the caller's transaction ends.
func checkCredentials(ctx context.Context, tx pgx.Tx, sc *spec.Scenario, fields map[string]string) error {
	ids := CredentialIDs(sc)
	if len(ids) == 0 {
		return nil
	}
	type cred struct {
		name  string
		bound []hostallow.Rule
		raw   []string
	}
	rows, err := tx.Query(ctx, `SELECT id, name, bound_hosts FROM synthetic_credentials WHERE id = ANY($1) FOR SHARE`, ids)
	if err != nil {
		return err
	}
	known := map[uuid.UUID]cred{}
	for rows.Next() {
		var id uuid.UUID
		var c cred
		if err := rows.Scan(&id, &c.name, &c.raw); err != nil {
			rows.Close()
			return err
		}
		for _, h := range c.raw {
			if r, err := hostallow.ParseRule(h); err == nil {
				c.bound = append(c.bound, r)
			}
		}
		known[id] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	missing := false
	for i, st := range sc.Steps {
		if st.CredentialID == nil {
			continue
		}
		key := fmt.Sprintf("steps.%d.credential_id", i)
		c, ok := known[*st.CredentialID]
		if !ok {
			missing = true
			fields[key] = "unknown credential"
			continue
		}
		if st.HTTP == nil {
			continue
		}
		host := normalized(urlHost(st.HTTP.URL))
		if host == "" {
			continue
		}
		if _, ok := (hostallow.List{Rules: c.bound}).Match(host); !ok && fields[key] == "" {
			fields[key] = fmt.Sprintf("Credential %s is not bound to host %s (bound hosts: %s).", c.name, host, strings.Join(rulePatterns(c.bound), ", "))
		}
	}
	if missing {
		return nil
	}
	bounds, err := CredentialBounds(ctx, tx, ids)
	if errors.Is(err, errCredential) {
		fields["steps"] = "a credential of the scenario is unusable; an admin must fix its bound hosts"
		return nil
	}
	if err != nil {
		return err
	}
	for k, v := range spec.ValidateTaint(sc, bounds) {
		if fields[k] != "" {
			continue
		}
		for id, c := range known {
			v = strings.ReplaceAll(v, id.String(), c.name)
		}
		fields[k] = v
	}
	return nil
}

func rulePatterns(rs []hostallow.Rule) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Pattern
	}
	return out
}

// ---------------------------------------------------------------- stored rows

// scenarioRow is a scenarios row.
type scenarioRow struct {
	ID                                           uuid.UUID
	Name, Type, OwnerSelector                    string
	IntervalSeconds, TimeoutSeconds, StepRetries int
	Enabled, StoreResponses                      bool
	Target                                       Targeting
	CreatedBy                                    *uuid.UUID
	CreatedByName                                string
	CreatedAt, UpdatedAt                         time.Time
}

const scenarioSelect = `SELECT s.id, s.name, s.type, s.owner_selector, s.interval_seconds, s.timeout_seconds, s.step_retries,
	s.enabled, s.store_responses, s.run_on, s.run_on_selector, s.exclude_selectors, s.created_by,
	COALESCE(p.display_name_snapshot, ''), s.created_at, s.updated_at
	FROM scenarios s LEFT JOIN principals p ON p.id = s.created_by`

func scanScenario(r pgx.CollectableRow) (scenarioRow, error) {
	var s scenarioRow
	err := r.Scan(&s.ID, &s.Name, &s.Type, &s.OwnerSelector, &s.IntervalSeconds, &s.TimeoutSeconds, &s.StepRetries,
		&s.Enabled, &s.StoreResponses, &s.Target.RunOn, &s.Target.RunOnSelector, &s.Target.Exclude, &s.CreatedBy,
		&s.CreatedByName, &s.CreatedAt, &s.UpdatedAt)
	if s.Target.Exclude == nil {
		s.Target.Exclude = []string{}
	}
	return s, err
}

// loadScenarios reads every scenario, by name.
func loadScenarios(ctx context.Context, q store.Querier) ([]scenarioRow, error) {
	rows, err := q.Query(ctx, scenarioSelect+` ORDER BY s.name, s.id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanScenario)
}

// loadScenarioRow reads one scenario; lock takes its row FOR NO KEY UPDATE
// (the lock ApplyOutcome takes: runs can still be added under it).
func loadScenarioRow(ctx context.Context, q store.Querier, id uuid.UUID, lock bool) (*scenarioRow, error) {
	sql := scenarioSelect + ` WHERE s.id = $1`
	if lock {
		sql += ` FOR NO KEY UPDATE OF s`
	}
	rows, err := q.Query(ctx, sql, id)
	if err != nil {
		return nil, err
	}
	s, err := pgx.CollectExactlyOneRow(rows, scanScenario)
	if err != nil {
		return nil, store.NotFound(err)
	}
	return &s, nil
}

// visibleScenarios returns the scenarios sub sees, by name.
func visibleScenarios(ctx context.Context, q store.Querier, sub *authz.Subject, f *fleet) ([]scenarioRow, error) {
	all, err := loadScenarios(ctx, q)
	if err != nil {
		return nil, err
	}
	out := []scenarioRow{}
	for _, s := range all {
		if canSee(sub, s.Target, f) {
			out = append(out, s)
		}
	}
	return out, nil
}

// seeScenario reads a scenario sub sees; one it does not see is not found.
func seeScenario(ctx context.Context, q store.Querier, sub *authz.Subject, f *fleet, id uuid.UUID, lock bool) (*scenarioRow, error) {
	s, err := loadScenarioRow(ctx, q, id, lock)
	if err != nil {
		return nil, err
	}
	if !canSee(sub, s.Target, f) {
		return nil, store.ErrNotFound
	}
	return s, nil
}

// mayChange refuses a change of a stored scenario that sub may not edit.
func mayChange(sub *authz.Subject, s *scenarioRow, f *fleet) error {
	if !sub.CanAny(authz.PermSyntheticEdit) {
		return refused(http.StatusForbidden, "")
	}
	if editRefusal(sub, s.Target, f) != "" {
		return refused(http.StatusForbidden, "This scenario runs on clusters outside your synthetic-editor scope; you cannot change it.")
	}
	return nil
}

func writeAlertRule(ctx context.Context, q store.Querier, id uuid.UUID, r AlertRule) error {
	_, err := q.Exec(ctx, `INSERT INTO scenario_alerts (scenario_id, cluster_fail_after, fleet_critical_clusters, channel_id,
			critical_channel_id, recovery_after, send_recovery) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (scenario_id) DO UPDATE SET cluster_fail_after = EXCLUDED.cluster_fail_after,
			fleet_critical_clusters = EXCLUDED.fleet_critical_clusters, channel_id = EXCLUDED.channel_id,
			critical_channel_id = EXCLUDED.critical_channel_id, recovery_after = EXCLUDED.recovery_after,
			send_recovery = EXCLUDED.send_recovery`,
		id, r.ClusterFailAfter, r.FleetCriticalClusters, r.ChannelID, r.CriticalChannelID, r.RecoveryAfter, r.SendRecovery)
	return err
}

// auditDetails is what the activity log keeps of a saved scenario: its
// shape and hosts, never header values or bodies.
func auditDetails(p *prepared) map[string]any {
	creds := []string{}
	for _, id := range CredentialIDs(&p.sc) {
		creds = append(creds, id.String())
	}
	return map[string]any{"name": p.sc.Name, "type": p.sc.Type, "enabled": p.enabled, "interval_seconds": p.sc.IntervalSeconds,
		"run_on": p.target.RunOn, "run_on_selector": p.target.RunOnSelector, "exclude_selectors": p.target.Exclude,
		"steps": len(p.sc.Steps), "hosts": spec.Hosts(&p.sc), "credential_ids": creds}
}

// ---------------------------------------------------------------- views

// stepView is a step as the API shows it. A viewer without
// PermSyntheticEdit sees a step that uses a credential with its headers and
// body null and hidden true (§6.2).
type stepView struct {
	Position     int              `json:"position"`
	Kind         string           `json:"kind"`
	DNS          *spec.DNSSpec    `json:"dns,omitempty"`
	HTTP         *httpView        `json:"http,omitempty"`
	TCP          *spec.TCPSpec    `json:"tcp,omitempty"`
	TLS          *spec.TLSSpec    `json:"tls,omitempty"`
	CredentialID *uuid.UUID       `json:"credential_id,omitempty"`
	Credential   *credentialRef   `json:"credential,omitempty"`
	Assertions   []spec.Assertion `json:"assertions"`
	Extracts     []spec.Extract   `json:"extracts"`
	Hidden       bool             `json:"hidden"`
}

type httpView struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers"`
	Body            *string           `json:"body"`
	BodyType        string            `json:"body_type,omitempty"`
	FollowRedirects bool              `json:"follow_redirects"`
}

// credentialRef names a step's credential (never its value): enough for
// "Copy as curl" to put $TOKEN where it goes.
type credentialRef struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	HeaderName string    `json:"header_name,omitempty"`
}

// credentialRefs reads the names of the credentials ids.
func credentialRefs(ctx context.Context, q store.Querier, ids []uuid.UUID) (map[uuid.UUID]credentialRef, error) {
	out := map[uuid.UUID]credentialRef{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT id, name, kind, COALESCE(header_name, '') FROM synthetic_credentials WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	refs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (credentialRef, error) {
		var c credentialRef
		return c, r.Scan(&c.ID, &c.Name, &c.Kind, &c.HeaderName)
	})
	for _, c := range refs {
		out[c.ID] = c
	}
	return out, err
}

// viewSteps turns steps into their views. reveal: the caller may see the
// headers and bodies of steps that use a credential.
func viewSteps(steps []spec.Step, creds map[uuid.UUID]credentialRef, reveal bool) []stepView {
	out := make([]stepView, 0, len(steps))
	for _, st := range steps {
		v := stepView{Position: st.Position, Kind: st.Kind, DNS: st.DNS, TCP: st.TCP, TLS: st.TLS, CredentialID: st.CredentialID,
			Assertions: st.Assertions, Extracts: st.Extracts}
		if v.Assertions == nil {
			v.Assertions = []spec.Assertion{}
		}
		if v.Extracts == nil {
			v.Extracts = []spec.Extract{}
		}
		if st.CredentialID != nil {
			if c, ok := creds[*st.CredentialID]; ok {
				v.Credential = &c
			}
		}
		if h := st.HTTP; h != nil {
			hv := &httpView{Method: h.Method, URL: h.URL, BodyType: h.BodyType, FollowRedirects: h.FollowRedirects}
			if st.CredentialID != nil && !reveal {
				v.Hidden = true
			} else {
				hv.Headers = h.Headers
				if hv.Headers == nil {
					hv.Headers = map[string]string{}
				}
				body := h.Body
				hv.Body = &body
			}
			v.HTTP = hv
		}
		out = append(out, v)
	}
	return out
}

// targetSummary is where a scenario runs, among the clusters the caller
// sees: "Runs on 9 of 10 clusters".
type targetSummary struct {
	RunsOn   int      `json:"runs_on"`
	Of       int      `json:"of"`
	Clusters []string `json:"clusters"`
	Excluded []string `json:"excluded"`
}

func summarize(t Targeting, f *fleet) targetSummary {
	s := targetSummary{Clusters: []string{}, Excluded: []string{}}
	for _, tc := range f.targets(t) {
		if !f.readable[tc.ID] {
			continue
		}
		s.Of++
		if tc.State == TargetExcluded {
			s.Excluded = append(s.Excluded, tc.Name)
			continue
		}
		s.RunsOn++
		s.Clusters = append(s.Clusters, tc.Name)
	}
	return s
}

// alertView is a scenario's alert rule, with its channels' names.
type alertView struct {
	ClusterFailAfter      int        `json:"cluster_fail_after"`
	FleetCriticalClusters int        `json:"fleet_critical_clusters"`
	RecoveryAfter         int        `json:"recovery_after"`
	SendRecovery          bool       `json:"send_recovery"`
	ChannelID             *uuid.UUID `json:"channel_id"`
	ChannelName           string     `json:"channel_name"`
	CriticalChannelID     *uuid.UUID `json:"critical_channel_id"`
	CriticalChannelName   string     `json:"critical_channel_name"`
}

func loadAlertView(ctx context.Context, q store.Querier, id uuid.UUID) (alertView, error) {
	d := DefaultAlertRule
	v := alertView{ClusterFailAfter: d.ClusterFailAfter, FleetCriticalClusters: d.FleetCriticalClusters,
		RecoveryAfter: d.RecoveryAfter, SendRecovery: d.SendRecovery}
	err := q.QueryRow(ctx, `SELECT a.cluster_fail_after, a.fleet_critical_clusters, a.recovery_after, a.send_recovery,
			a.channel_id, COALESCE(c.name, ''), a.critical_channel_id, COALESCE(cc.name, '')
		FROM scenario_alerts a LEFT JOIN notification_channels c ON c.id = a.channel_id
		LEFT JOIN notification_channels cc ON cc.id = a.critical_channel_id WHERE a.scenario_id = $1`, id).
		Scan(&v.ClusterFailAfter, &v.FleetCriticalClusters, &v.RecoveryAfter, &v.SendRecovery,
			&v.ChannelID, &v.ChannelName, &v.CriticalChannelID, &v.CriticalChannelName)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, nil
	}
	return v, err
}

// scenarioView is GET /scenarios/{id}.
type scenarioView struct {
	ID                uuid.UUID     `json:"id"`
	Name              string        `json:"name"`
	Type              string        `json:"type"`
	OwnerSelector     string        `json:"owner_selector"`
	IntervalSeconds   int           `json:"interval_seconds"`
	TimeoutSeconds    int           `json:"timeout_seconds"`
	StepRetries       int           `json:"step_retries"`
	Enabled           bool          `json:"enabled"`
	StoreResponses    bool          `json:"store_responses"`
	RunOn             string        `json:"run_on"`
	RunOnSelector     string        `json:"run_on_selector"`
	ExcludeSelectors  []string      `json:"exclude_selectors"`
	Steps             []stepView    `json:"steps"`
	Alerts            alertView     `json:"alerts"`
	Targets           targetSummary `json:"targets"`
	RequestsPerMinute float64       `json:"requests_per_minute"`
	CanEdit           bool          `json:"can_edit"`
	CreatedBy         *uuid.UUID    `json:"created_by"`
	CreatedByName     string        `json:"created_by_name"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
}

func (a *API) scenarioView(ctx context.Context, q store.Querier, sub *authz.Subject, f *fleet, s *scenarioRow) (*scenarioView, error) {
	sc, err := LoadScenario(ctx, q, s.ID)
	if err != nil {
		return nil, err
	}
	creds, err := credentialRefs(ctx, q, CredentialIDs(sc))
	if err != nil {
		return nil, err
	}
	alerts, err := loadAlertView(ctx, q, s.ID)
	if err != nil {
		return nil, err
	}
	return &scenarioView{
		ID: s.ID, Name: s.Name, Type: s.Type, OwnerSelector: s.OwnerSelector, IntervalSeconds: s.IntervalSeconds,
		TimeoutSeconds: s.TimeoutSeconds, StepRetries: s.StepRetries, Enabled: s.Enabled, StoreResponses: s.StoreResponses,
		RunOn: s.Target.RunOn, RunOnSelector: s.Target.RunOnSelector, ExcludeSelectors: s.Target.Exclude,
		Steps:   viewSteps(sc.Steps, creds, sub.CanAny(authz.PermSyntheticEdit)),
		Alerts:  alerts,
		Targets: summarize(s.Target, f), RequestsPerMinute: spec.RequestsPerMinute(sc),
		CanEdit:   sub.CanAny(authz.PermSyntheticEdit) && editRefusal(sub, s.Target, f) == "",
		CreatedBy: s.CreatedBy, CreatedByName: s.CreatedByName, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}, nil
}

// scenarioSummary is an item of GET /scenarios.
type scenarioSummary struct {
	ID               uuid.UUID     `json:"id"`
	Name             string        `json:"name"`
	Type             string        `json:"type"`
	OwnerSelector    string        `json:"owner_selector"`
	IntervalSeconds  int           `json:"interval_seconds"`
	TimeoutSeconds   int           `json:"timeout_seconds"`
	Enabled          bool          `json:"enabled"`
	RunOn            string        `json:"run_on"`
	RunOnSelector    string        `json:"run_on_selector"`
	ExcludeSelectors []string      `json:"exclude_selectors"`
	Steps            int           `json:"steps"`
	Targets          targetSummary `json:"targets"`
	CanEdit          bool          `json:"can_edit"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
}

// stepCounts reads the number of steps of each scenario.
func stepCounts(ctx context.Context, q store.Querier) (map[uuid.UUID]int, error) {
	rows, err := q.Query(ctx, `SELECT scenario_id, count(*) FROM scenario_steps GROUP BY scenario_id`)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]int{}
	_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) {
		var id uuid.UUID
		var n int
		err := r.Scan(&id, &n)
		out[id] = n
		return struct{}{}, err
	})
	return out, err
}

// ---------------------------------------------------------------- handlers

func (a *API) listScenarios(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	f, err := loadFleet(ctx, a.db(), sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ss, err := visibleScenarios(ctx, a.db(), sub, f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	counts, err := stepCounts(ctx, a.db())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	edit := sub.CanAny(authz.PermSyntheticEdit)
	out := make([]scenarioSummary, 0, len(ss))
	for _, s := range ss {
		out = append(out, scenarioSummary{ID: s.ID, Name: s.Name, Type: s.Type, OwnerSelector: s.OwnerSelector,
			IntervalSeconds: s.IntervalSeconds, TimeoutSeconds: s.TimeoutSeconds, Enabled: s.Enabled, RunOn: s.Target.RunOn,
			RunOnSelector: s.Target.RunOnSelector, ExcludeSelectors: s.Target.Exclude, Steps: counts[s.ID],
			Targets: summarize(s.Target, f), CanEdit: edit && editRefusal(sub, s.Target, f) == "",
			CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (a *API) getScenario(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, sub := r.Context(), httpx.Subject(r)
	f, err := loadFleet(ctx, a.db(), sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	s, err := seeScenario(ctx, a.db(), sub, f, id, false)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	v, err := a.scenarioView(ctx, a.db(), sub, f, s)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

// respondScenario writes the stored scenario id as sub sees it now.
func (a *API) respondScenario(w http.ResponseWriter, r *http.Request, code int, id uuid.UUID) {
	ctx, sub := r.Context(), httpx.Subject(r)
	f, err := loadFleet(ctx, a.db(), sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	s, err := loadScenarioRow(ctx, a.db(), id, false)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	v, err := a.scenarioView(ctx, a.db(), sub, f, s)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.JSON(w, code, v)
}

func (a *API) createScenario(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanAny(authz.PermSyntheticEdit) {
		httpx.Forbidden(w, "")
		return
	}
	var in scenarioInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var id uuid.UUID
	err := txRetry(ctx, a.db(), func(tx pgx.Tx) error {
		f, err := loadFleet(ctx, tx, sub)
		if err != nil {
			return err
		}
		p, err := a.validate(ctx, tx, sub, &in, f, nil, forSave)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO scenarios (name, type, owner_selector, interval_seconds, timeout_seconds, step_retries,
				enabled, run_on, run_on_selector, exclude_selectors, store_responses, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`,
			p.sc.Name, p.sc.Type, p.owner, p.sc.IntervalSeconds, p.sc.TimeoutSeconds, p.sc.StepRetries, p.enabled,
			p.target.RunOn, p.target.RunOnSelector, p.target.Exclude, p.sc.StoreResponses, httpx.ActorID(r)).Scan(&id); err != nil {
			return err
		}
		if err := WriteSteps(ctx, tx, id, p.sc.Steps); err != nil {
			return err
		}
		if err := writeAlertRule(ctx, tx, id, p.rule); err != nil {
			return err
		}
		return httpx.Record(r, tx, "synthetic.scenario_created", "scenario", id.String(), nil, auditDetails(p))
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondScenario(w, r, http.StatusCreated, id)
}

func (a *API) updateScenario(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, sub := r.Context(), httpx.Subject(r)
	var in scenarioInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	err := txRetry(ctx, a.db(), func(tx pgx.Tx) error {
		f, err := loadFleet(ctx, tx, sub)
		if err != nil {
			return err
		}
		cur, err := seeScenario(ctx, tx, sub, f, id, true)
		if err != nil {
			return err
		}
		if err := mayChange(sub, cur, f); err != nil {
			return err
		}
		// Omitted, the switches keep their stored values (as alerts does).
		if in.Enabled == nil {
			in.Enabled = &cur.Enabled
		}
		if in.StoreResponses == nil {
			in.StoreResponses = &cur.StoreResponses
		}
		p, err := a.validate(ctx, tx, sub, &in, f, &id, forSave)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scenarios SET name = $2, type = $3, owner_selector = $4, interval_seconds = $5,
				timeout_seconds = $6, step_retries = $7, enabled = $8, run_on = $9, run_on_selector = $10,
				exclude_selectors = $11, store_responses = $12 WHERE id = $1`,
			id, p.sc.Name, p.sc.Type, p.owner, p.sc.IntervalSeconds, p.sc.TimeoutSeconds, p.sc.StepRetries, p.enabled,
			p.target.RunOn, p.target.RunOnSelector, p.target.Exclude, p.sc.StoreResponses); err != nil {
			return err
		}
		if err := WriteSteps(ctx, tx, id, p.sc.Steps); err != nil {
			return err
		}
		if p.ruleGiven {
			if err := writeAlertRule(ctx, tx, id, p.rule); err != nil {
				return err
			}
		}
		// The fleet threshold may have moved (Task 10).
		if err := a.Svc.ReevaluateFleet(ctx, tx, id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "synthetic.scenario_updated", "scenario", id.String(), nil, auditDetails(p))
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondScenario(w, r, http.StatusOK, id)
}

// patchScenario pauses or resumes a scenario ({"enabled": bool}). Resuming
// checks the caps again: the scenarios on its clusters may have changed.
func (a *API) patchScenario(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, sub := r.Context(), httpx.Subject(r)
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	err := txRetry(ctx, a.db(), func(tx pgx.Tx) error {
		f, err := loadFleet(ctx, tx, sub)
		if err != nil {
			return err
		}
		cur, err := seeScenario(ctx, tx, sub, f, id, true)
		if err != nil {
			return err
		}
		if err := mayChange(sub, cur, f); err != nil {
			return err
		}
		if in.Enabled == nil {
			return invalid("invalid change", map[string]string{"enabled": "required"})
		}
		if *in.Enabled == cur.Enabled {
			return nil
		}
		if *in.Enabled {
			sc, err := LoadScenario(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := a.checkRate(ctx, tx, sc, cur.Target, f, &id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE scenarios SET enabled = $2 WHERE id = $1`, id, *in.Enabled); err != nil {
			return err
		}
		action := "synthetic.scenario_paused"
		if *in.Enabled {
			action = "synthetic.scenario_resumed"
		}
		return httpx.Record(r, tx, action, "scenario", id.String(), nil, map[string]any{"name": cur.Name})
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondScenario(w, r, http.StatusOK, id)
}

// deleteScenario removes a scenario with its runs and alerts. The open runs
// are locked before the scenario, the order in which ingestion locks them.
func (a *API) deleteScenario(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, sub := r.Context(), httpx.Subject(r)
	err := txRetry(ctx, a.db(), func(tx pgx.Tx) error {
		f, err := loadFleet(ctx, tx, sub)
		if err != nil {
			return err
		}
		cur, err := seeScenario(ctx, tx, sub, f, id, false)
		if err != nil {
			return err
		}
		if err := mayChange(sub, cur, f); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT id FROM synthetic_runs WHERE scenario_id = $1 AND status IN ('scheduled','running')
			ORDER BY id FOR UPDATE`, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM scenarios WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrNotFound
		}
		return httpx.Record(r, tx, "synthetic.scenario_deleted", "scenario", id.String(), nil, map[string]any{"name": cur.Name})
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// previewInput is the body of POST /scenarios/preview: a scenario input
// as the editor holds it, and the id of the scenario being edited.
type previewInput struct {
	ID *uuid.UUID `json:"id"`
	scenarioInput
}

// overLimit is a cluster where the per-cluster cap blocks the scenario,
// with what all the scenarios there ask for.
type overLimit struct {
	Cluster           string  `json:"cluster"`
	RequestsPerMinute float64 `json:"requests_per_minute"`
}

// previewView is the editor's live targeting line and rate check.
type previewView struct {
	targetSummary
	RequestsPerMinute float64     `json:"requests_per_minute"`
	ScenarioCap       float64     `json:"scenario_cap"`
	ClusterCap        float64     `json:"cluster_cap"`
	OverScenarioCap   bool        `json:"over_scenario_cap"`
	OverLimit         []overLimit `json:"over_limit"`
}

// preview answers where a draft would run and whether a cap would block
// it, without saving anything. Only the targeting must be valid.
func (a *API) preview(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanAny(authz.PermSyntheticEdit) {
		httpx.Forbidden(w, "")
		return
	}
	var in previewInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	t := in.targeting()
	if err := t.Validate(); err != nil {
		key, msg, ok := strings.Cut(err.Error(), ": ")
		if !ok {
			key, msg = "run_on", err.Error()
		}
		httpx.FieldErrors(w, "invalid targeting", map[string]string{key: msg})
		return
	}
	f, err := loadFleet(ctx, a.db(), sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sc := in.scenario(in.ID)
	out := previewView{targetSummary: summarize(t, f), RequestsPerMinute: spec.RequestsPerMinute(&sc),
		ScenarioCap: a.Svc.scenarioCap(), ClusterCap: a.Svc.clusterCap(), OverLimit: []overLimit{}}
	if in.enabled() {
		var ids []uuid.UUID
		for _, tc := range f.targets(t) {
			if tc.State != TargetExcluded {
				ids = append(ids, tc.ID)
			}
		}
		over, err := a.Svc.CheckRate(ctx, a.db(), &sc, ids, in.ID)
		switch {
		case errors.Is(err, ErrRateLimit):
			out.OverScenarioCap = true
		case err != nil:
			a.fail(w, r, err)
			return
		}
		visibleNames := map[string]bool{}
		for _, c := range f.visible() {
			visibleNames[c.Name] = true
		}
		for name, rpm := range over {
			if visibleNames[name] {
				out.OverLimit = append(out.OverLimit, overLimit{Cluster: name, RequestsPerMinute: rpm})
			}
		}
		slices.SortFunc(out.OverLimit, func(x, y overLimit) int { return strings.Compare(x.Cluster, y.Cluster) })
	}
	httpx.JSON(w, http.StatusOK, out)
}

// runScenario is "Run now": a manual run on one cluster, or on every
// cluster the scenario runs on now. It counts toward alerting. Each user
// makes at most RunNowPerMinute such requests a minute.
func (a *API) runScenario(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, sub := r.Context(), httpx.Subject(r)
	var in struct {
		ClusterID *uuid.UUID `json:"cluster_id"`
	}
	if err := decodeOptional(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	f, err := loadFleet(ctx, a.db(), sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cur, err := seeScenario(ctx, a.db(), sub, f, id, false)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := mayChange(sub, cur, f); err != nil {
		a.fail(w, r, err)
		return
	}
	var clusters []uuid.UUID
	if in.ClusterID != nil {
		if !f.readable[*in.ClusterID] {
			httpx.FieldErrors(w, "invalid run", map[string]string{"cluster_id": "unknown cluster"})
			return
		}
		clusters = []uuid.UUID{*in.ClusterID}
	}
	slot, ok := a.manualRuns.allow(sub.Principal.ID, a.now(), a.runNowPerMinute())
	if !ok {
		httpx.Error(w, http.StatusTooManyRequests, fmt.Sprintf("At most %d Run now requests a minute; wait a moment.", a.runNowPerMinute()))
		return
	}
	ids, err := a.Svc.RunNow(ctx, id, clusters, sub.Principal.ID)
	if err != nil {
		// No run was made: the slot goes back.
		a.manualRuns.undo(sub.Principal.ID, slot)
	}
	switch {
	case errors.Is(err, ErrScenarioDisabled):
		httpx.Error(w, http.StatusConflict, "The scenario is paused; resume it first.")
		return
	case errors.Is(err, ErrNotTarget):
		httpx.FieldErrors(w, "invalid run", map[string]string{"cluster_id": "The scenario does not run on this cluster."})
		return
	case errors.Is(err, ErrProbeNotOnline):
		httpx.Error(w, http.StatusConflict, "The cluster's probe is not online: "+strings.TrimPrefix(err.Error(), ErrProbeNotOnline.Error()+": "))
		return
	case errors.Is(err, ErrNoClusters):
		httpx.Error(w, http.StatusConflict, "The scenario runs on no cluster now: none of its clusters has an online probe that the request caps leave room on.")
		return
	case errors.Is(err, ErrRateLimit):
		httpx.Error(w, http.StatusTooManyRequests, "A request cap blocks this run: "+strings.TrimPrefix(err.Error(), ErrRateLimit.Error()+": "))
		return
	case err != nil:
		a.fail(w, r, err)
		return
	}
	details := map[string]any{"name": cur.Name, "run_ids": ids}
	if in.ClusterID != nil {
		details["cluster_id"] = in.ClusterID.String()
	}
	if err := store.Tx(ctx, a.db(), func(tx pgx.Tx) error {
		return httpx.Record(r, tx, "synthetic.scenario_run", "scenario", id.String(), in.ClusterID, details)
	}); err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{"run_ids": ids})
}

// testRunInput is the body of POST /test-runs: the editor's draft (with
// the id of the scenario it edits, if any) and the cluster to run it on.
type testRunInput struct {
	Scenario  testScenarioInput `json:"scenario"`
	ClusterID uuid.UUID         `json:"cluster_id"`
}

type testScenarioInput struct {
	ID *uuid.UUID `json:"id"`
	scenarioInput
}

// testRun runs a draft once on one cluster ("Run once" in the editor): it
// never alerts. The draft is checked as a save checks its steps, hosts and
// credentials; the caller needs PermSyntheticEdit on that cluster, and at
// most TestRunsPerMinute test runs a minute.
func (a *API) testRun(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	if !sub.CanAny(authz.PermSyntheticEdit) {
		httpx.Forbidden(w, "")
		return
	}
	var in testRunInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var p *prepared
	err := store.Tx(ctx, a.db(), func(tx pgx.Tx) error {
		f, err := loadFleet(ctx, tx, sub)
		if err != nil {
			return err
		}
		c, ok := f.byID[in.ClusterID]
		if !ok || !f.readable[c.ID] {
			return invalid("invalid test run", map[string]string{"cluster_id": "unknown cluster"})
		}
		if !sub.Can(authz.PermSyntheticEdit, c.Labels) {
			return refused(http.StatusForbidden, "You may only test on clusters in your synthetic-editor scope.")
		}
		if in.Scenario.ID != nil {
			cur, err := seeScenario(ctx, tx, sub, f, *in.Scenario.ID, false)
			if err != nil {
				return err
			}
			if err := mayChange(sub, cur, f); err != nil {
				return err
			}
		}
		p, err = a.validate(ctx, tx, sub, &in.Scenario.scenarioInput, f, in.Scenario.ID, forTest)
		return err
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	slot, ok := a.testRuns.allow(sub.Principal.ID, a.now(), a.testRunsPerMinute())
	if !ok {
		httpx.Error(w, http.StatusTooManyRequests, fmt.Sprintf("At most %d test runs a minute; wait a moment.", a.testRunsPerMinute()))
		return
	}
	runID, err := a.Svc.TestRun(ctx, p.sc, in.ClusterID, sub.Principal.ID)
	if err != nil {
		// No run was made: the slot goes back.
		a.testRuns.undo(sub.Principal.ID, slot)
	}
	switch {
	case errors.Is(err, ErrProbeNotOnline):
		httpx.Error(w, http.StatusConflict, "The cluster's probe is not online: "+strings.TrimPrefix(err.Error(), ErrProbeNotOnline.Error()+": "))
		return
	case errors.Is(err, ErrInvalidScenario):
		httpx.FieldErrors(w, "invalid scenario", map[string]string{"scenario": err.Error()})
		return
	case errors.Is(err, store.ErrNotFound):
		httpx.FieldErrors(w, "invalid test run", map[string]string{"cluster_id": "unknown cluster"})
		return
	case err != nil:
		a.fail(w, r, err)
		return
	}
	details := map[string]any{"name": p.sc.Name, "hosts": spec.Hosts(&p.sc)}
	if in.Scenario.ID != nil {
		details["scenario_id"] = in.Scenario.ID.String()
	}
	if err := store.Tx(ctx, a.db(), func(tx pgx.Tx) error {
		return httpx.Record(r, tx, "synthetic.test_run", "synthetic_run", runID.String(), &in.ClusterID, details)
	}); err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{"run_id": runID})
}
