// Package spec is the scenario model of synthetic monitoring
// (docs/design/synthetic-monitoring.md §3): the types the API stores and
// the server sends to olympos-probe in RunScenario, their limits and
// validation, ${var} substitution, the request-rate estimate, and the
// per-run sealing of credentials (decision 2 of the design).
//
// The package is pure: it does no I/O and matches no allowlist. Validate
// refuses hosts that can never be allowed (IP literals, localhost, the
// Kubernetes API names) through hostallow.Normalize; matching the hosts
// against the allowlist is the caller's job (use Hosts).
package spec

import (
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
)

// Limits (§3, decision 4).
const (
	// MaxSteps is the most steps a scenario has.
	MaxSteps = 10
	// MaxRunTimeout is the longest deadline of a whole run.
	MaxRunTimeout = 60 * time.Second
	// MinInterval is the shortest time between two runs of a scenario on
	// one cluster.
	MinInterval = 30 * time.Second
	// MaxBody is the largest HTTP request body, in bytes.
	MaxBody = 64 << 10
	// MaxResponseRead is how much of a response the probe reads, in bytes.
	MaxResponseRead = 1 << 20
	// MaxExcerpt is the largest response excerpt that is stored, in bytes.
	MaxExcerpt = 2 << 10
	// MaxRedirects is how many redirects an HTTP step follows at most.
	MaxRedirects = 5
	// MaxStepRetries is how many times a failed step is tried again at most.
	MaxStepRetries = 2
	// Jitter is the share of the interval by which the scheduler moves a
	// run, either way, so that clusters do not all run at the same second.
	Jitter = 0.10
)

// Scenario types.
const (
	TypeHTTPFlow = "http_flow"
	TypeHTTP     = "http"
	TypeDNS      = "dns"
	TypeTCP      = "tcp"
	TypeTLS      = "tls"
)

// Step kinds.
const (
	KindDNS  = "dns"
	KindHTTP = "http"
	KindTCP  = "tcp"
	KindTLS  = "tls"
)

// Assertion subjects. SubjectHeaderPrefix and SubjectJSONPrefix are
// followed by a header name or a JSON path (see ParseJSONPath).
const (
	SubjectStatusCode      = "status_code"
	SubjectLatencyMS       = "latency_ms"
	SubjectHeaderPrefix    = "header:"
	SubjectBody            = "body"
	SubjectJSONPrefix      = "json:"
	SubjectTLSDaysLeft     = "tls_days_left"
	SubjectRecordCount     = "record_count"
	SubjectRecord          = "record"
	SubjectConnects        = "connects"
	SubjectChainValid      = "chain_valid"
	SubjectHostnameMatches = "hostname_matches"
	SubjectTLSVersion      = "tls_version"
)

// Assertion operators. Matches uses RE2 (Go's regexp).
const (
	OpEquals            = "equals"
	OpNotEquals         = "not_equals"
	OpContains          = "contains"
	OpMatches           = "matches"
	OpLessThan          = "less_than"
	OpGreaterThan       = "greater_than"
	OpExists            = "exists"
	OpLengthGreaterThan = "length_greater_than"
)

// Extract sources.
const (
	SourceJSONPath = "json_path"
	SourceHeader   = "header"
	SourceRegex    = "regex"
)

// HTTP body types. An empty BodyType means BodyText.
const (
	BodyText = "text"
	BodyJSON = "json"
)

// Credential kinds (synthetic_credentials.kind).
const (
	CredBearer = "bearer"
	CredBasic  = "basic"
	CredHeader = "header"
	CredOAuth2 = "oauth2_client_credentials"
)

// Scenario is a scenario as the API takes it and as RunScenario carries it
// (scenario_json).
//
// TimeoutSeconds is the deadline of the whole run, not of one step, and is
// at most IntervalSeconds. Step i has Position i.
type Scenario struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	StepRetries     int    `json:"step_retries"`
	StoreResponses  bool   `json:"store_responses"`
	Steps           []Step `json:"steps"`
}

// Step is one step. Exactly one of DNS, HTTP, TCP and TLS is set, the one
// that Kind names. CredentialID names a synthetic_credentials row and is
// only valid on an HTTP step.
type Step struct {
	Position     int         `json:"position"`
	Kind         string      `json:"kind"`
	DNS          *DNSSpec    `json:"dns,omitempty"`
	HTTP         *HTTPSpec   `json:"http,omitempty"`
	TCP          *TCPSpec    `json:"tcp,omitempty"`
	TLS          *TLSSpec    `json:"tls,omitempty"`
	CredentialID *uuid.UUID  `json:"credential_id,omitempty"`
	Assertions   []Assertion `json:"assertions"`
	Extracts     []Extract   `json:"extracts"`
}

// HTTPSpec is an HTTP request. URL, header values and Body may use
// ${name} variables extracted by earlier steps, but not in the URL's
// scheme, host or port.
type HTTPSpec struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	BodyType        string            `json:"body_type,omitempty"`
	FollowRedirects bool              `json:"follow_redirects"`
}

// DNSSpec is a lookup through the cluster's resolver. RecordType is A,
// AAAA, CNAME or TXT.
type DNSSpec struct {
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
}

// TCPSpec is a TCP connect.
type TCPSpec struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// TLSSpec is a TLS handshake. An empty SNI means Host.
type TLSSpec struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	SNI  string `json:"sni,omitempty"`
}

// Assertion is one check on a step's result. Value is literal: variables
// are not substituted in it.
type Assertion struct {
	Subject  string `json:"subject"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// Extract takes a value from an HTTP step's response and makes it
// available to later steps as ${Name}. Expr is a JSON path (see
// ParseJSONPath), a header name or an RE2 expression, as Source says.
// Extracted values are never stored, only their names.
type Extract struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Expr   string `json:"expr"`
}

// Hosts returns the normalized host names the scenario reaches, once each,
// in step order: the host of each HTTP URL, each DNS name, each TCP host,
// and each TLS host and SNI. Names that do not normalize are left out
// (Validate reports them), as are URLs that do not parse.
//
// DNS names and SNI are included although the probe does not connect to
// them: a lookup reveals the name to resolvers, and the SNI picks the
// virtual host behind the address. Both are kept within the allowlist.
func Hosts(s *Scenario) []string {
	if s == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(h string) {
		if h == "" {
			return
		}
		n, err := hostallow.Normalize(h)
		if err != nil || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, st := range s.Steps {
		if st.HTTP != nil {
			if u, ok := parseURL(st.HTTP.URL); ok {
				add(u.Hostname())
			}
		}
		if st.DNS != nil {
			add(st.DNS.Name)
		}
		if st.TCP != nil {
			add(st.TCP.Host)
		}
		if st.TLS != nil {
			add(st.TLS.Host)
			add(st.TLS.SNI)
		}
	}
	return out
}

// RequestsPerMinute is the worst-case number of requests one cluster's
// probe makes for the scenario, per minute (the cap of §6.3 bounds real
// traffic): each step is tried 1 + retries times; an attempt of an HTTP
// step that follows redirects counts 1 + MaxRedirects requests, every
// other attempt counts 1; each distinct credential the steps use adds one
// token request per run. The sum per run is scaled by 60 / interval.
//
// Only OAuth2 credentials request a token, but a step names its credential
// by id alone, so every credential is counted: an upper bound at most
// 60/interval above the true figure per non-OAuth2 credential. It returns 0
// for an interval below 1.
func RequestsPerMinute(s *Scenario) float64 {
	if s == nil || s.IntervalSeconds < 1 {
		return 0
	}
	attempts := 1 + max(s.StepRetries, 0)
	perRun := 0
	creds := map[uuid.UUID]bool{}
	for _, st := range s.Steps {
		perAttempt := 1
		if st.HTTP != nil && st.HTTP.FollowRedirects {
			perAttempt += MaxRedirects
		}
		perRun += attempts * perAttempt
		if st.CredentialID != nil {
			creds[*st.CredentialID] = true
		}
	}
	perRun += len(creds)
	return float64(perRun) * 60 / float64(s.IntervalSeconds)
}
