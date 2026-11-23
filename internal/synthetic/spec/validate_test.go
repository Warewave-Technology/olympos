package spec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// flow is a valid http_flow scenario: a login that extracts a token, then
// an API call that uses it.
func flow() *Scenario {
	return &Scenario{
		Name: "checkout", Type: TypeHTTPFlow,
		IntervalSeconds: 60, TimeoutSeconds: 30, StepRetries: 1, StoreResponses: true,
		Steps: []Step{
			{
				Position: 0, Kind: KindHTTP,
				HTTP: &HTTPSpec{
					Method: "POST", URL: "https://api.wrw.com/login",
					Headers: map[string]string{"Accept": "application/json"},
					Body:    `{"user":"probe"}`, BodyType: BodyJSON,
				},
				Assertions: []Assertion{
					{SubjectStatusCode, OpEquals, "200"},
					{SubjectJSONPrefix + "data.token", OpExists, ""},
				},
				Extracts: []Extract{{"token", SourceJSONPath, "data.token"}, {"sid", SourceHeader, "X-Session"}},
			},
			{
				Position: 1, Kind: KindHTTP,
				HTTP: &HTTPSpec{
					Method: "GET", URL: "https://api.wrw.com:8443/orders/${sid}?t=${token}",
					Headers: map[string]string{"Authorization": "Bearer ${token}"},
				},
				Assertions: []Assertion{
					{SubjectLatencyMS, OpLessThan, "500"},
					{SubjectHeaderPrefix + "Content-Type", OpContains, "json"},
					{SubjectBody, OpMatches, `"id":\s*\d+`},
					{SubjectTLSDaysLeft, OpGreaterThan, "14"},
				},
			},
			{Position: 2, Kind: KindDNS, DNS: &DNSSpec{"api.wrw.com", "A"},
				Assertions: []Assertion{{SubjectRecordCount, OpGreaterThan, "0"}}},
			{Position: 3, Kind: KindTCP, TCP: &TCPSpec{"db.wrw.com", 5432},
				Assertions: []Assertion{{SubjectConnects, OpEquals, "true"}}},
			{Position: 4, Kind: KindTLS, TLS: &TLSSpec{"api.wrw.com", 443, "edge.wrw.com"},
				Assertions: []Assertion{{SubjectTLSVersion, OpGreaterThan, "1.1"}, {SubjectChainValid, OpEquals, "true"}}},
		},
	}
}

func single(kind string) *Scenario {
	s := &Scenario{Name: kind, Type: kind, IntervalSeconds: 30, TimeoutSeconds: 10}
	st := Step{Kind: kind}
	switch kind {
	case KindHTTP:
		st.HTTP = &HTTPSpec{Method: "GET", URL: "https://www.wrw.com/"}
	case KindDNS:
		st.DNS = &DNSSpec{"wrw.com", "TXT"}
	case KindTCP:
		st.TCP = &TCPSpec{"wrw.com", 22}
	case KindTLS:
		st.TLS = &TLSSpec{Host: "wrw.com", Port: 443}
	}
	s.Steps = []Step{st}
	return s
}

func wantValid(t *testing.T, s *Scenario) {
	t.Helper()
	if f := Validate(s); len(f) != 0 {
		t.Fatalf("Validate = %v, want valid", f)
	}
}

// wantField checks that Validate reports an error for key.
func wantField(t *testing.T, s *Scenario, key string) {
	t.Helper()
	f := Validate(s)
	if _, ok := f[key]; !ok {
		t.Fatalf("Validate = %v, want an error for %q", f, key)
	}
}

func TestValidateValid(t *testing.T) {
	wantValid(t, flow())
	for _, k := range []string{KindHTTP, KindDNS, KindTCP, KindTLS} {
		t.Run(k, func(t *testing.T) { wantValid(t, single(k)) })
	}
}

func TestValidateNil(t *testing.T) {
	if f := Validate(nil); f["scenario"] == "" {
		t.Fatalf("Validate(nil) = %v", f)
	}
}

func TestValidateLimits(t *testing.T) {
	steps := func(n int) *Scenario {
		s := single(KindTCP)
		s.Type = TypeHTTPFlow
		s.Steps = nil
		for i := range n {
			s.Steps = append(s.Steps, Step{Position: i, Kind: KindTCP, TCP: &TCPSpec{"wrw.com", 22}})
		}
		return s
	}
	wantValid(t, steps(MaxSteps))
	wantField(t, steps(MaxSteps+1), "steps")
	wantField(t, steps(0), "steps")

	cases := []struct {
		name  string
		edit  func(*Scenario)
		field string // "" means valid
	}{
		{"interval at minimum", func(s *Scenario) { s.IntervalSeconds = 30 }, ""},
		{"interval below minimum", func(s *Scenario) { s.IntervalSeconds = 29 }, "interval_seconds"},
		{"timeout at maximum", func(s *Scenario) { s.IntervalSeconds, s.TimeoutSeconds = 60, 60 }, ""},
		{"timeout over maximum", func(s *Scenario) { s.IntervalSeconds, s.TimeoutSeconds = 120, 61 }, "timeout_seconds"},
		{"timeout zero", func(s *Scenario) { s.TimeoutSeconds = 0 }, "timeout_seconds"},
		{"timeout equals interval", func(s *Scenario) { s.IntervalSeconds, s.TimeoutSeconds = 45, 45 }, ""},
		{"timeout over interval", func(s *Scenario) { s.IntervalSeconds, s.TimeoutSeconds = 30, 31 }, "timeout_seconds"},
		{"retries at maximum", func(s *Scenario) { s.StepRetries = MaxStepRetries }, ""},
		{"retries over maximum", func(s *Scenario) { s.StepRetries = MaxStepRetries + 1 }, "step_retries"},
		{"retries negative", func(s *Scenario) { s.StepRetries = -1 }, "step_retries"},
		{"body at maximum", func(s *Scenario) {
			s.Steps[0].HTTP.Method, s.Steps[0].HTTP.Body = "POST", strings.Repeat("a", MaxBody)
		}, ""},
		{"body over maximum", func(s *Scenario) {
			s.Steps[0].HTTP.Method, s.Steps[0].HTTP.Body = "POST", strings.Repeat("a", MaxBody+1)
		}, "steps.0.http.body"},
		{"name missing", func(s *Scenario) { s.Name = "  " }, "name"},
		{"name too long", func(s *Scenario) { s.Name = strings.Repeat("é", maxName+1) }, "name"},
		{"name at maximum", func(s *Scenario) { s.Name = strings.Repeat("é", maxName) }, ""},
		{"name with newline", func(s *Scenario) { s.Name = "check\nout" }, "name"},
		{"name with escape", func(s *Scenario) { s.Name = "check\x1b[31mout" }, "name"},
		{"name with C1 control", func(s *Scenario) { s.Name = "check\u0085out" }, "name"},
		{"unknown type", func(s *Scenario) { s.Type = "grpc" }, "type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := single(KindHTTP)
			c.edit(s)
			if c.field == "" {
				wantValid(t, s)
			} else {
				wantField(t, s, c.field)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	if MaxResponseRead != 1<<20 || MaxExcerpt != 2048 || MaxRedirects != 5 || Jitter != 0.10 ||
		MaxBody != 65536 || MaxRunTimeout.Seconds() != 60 || MinInterval.Seconds() != 30 {
		t.Fatal("limits changed")
	}
}

func TestValidateStepShape(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*Scenario)
		field string
	}{
		{"single type with two steps", func(s *Scenario) {
			s.Steps = append(s.Steps, Step{Position: 1, Kind: KindHTTP, HTTP: s.Steps[0].HTTP})
		}, "steps"},
		{"single type with another kind", func(s *Scenario) {
			s.Steps[0] = Step{Kind: KindTCP, TCP: &TCPSpec{"wrw.com", 22}}
		}, "steps.0.kind"},
		{"unknown kind", func(s *Scenario) { s.Type = TypeHTTPFlow; s.Steps[0].Kind = "icmp" }, "steps.0.kind"},
		{"kind without its settings", func(s *Scenario) { s.Steps[0].HTTP = nil }, "steps.0.http"},
		{"two settings", func(s *Scenario) { s.Steps[0].TCP = &TCPSpec{"wrw.com", 22} }, "steps.0"},
		{"wrong position", func(s *Scenario) { s.Steps[0].Position = 1 }, "steps.0.position"},
		{"credential on a tcp step", func(s *Scenario) {
			id := uuid.New()
			s.Type = TypeHTTPFlow
			s.Steps[0] = Step{Kind: KindTCP, TCP: &TCPSpec{"wrw.com", 22}, CredentialID: &id}
		}, "steps.0.credential_id"},
		{"extract on a dns step", func(s *Scenario) {
			s.Type = TypeHTTPFlow
			s.Steps[0] = Step{Kind: KindDNS, DNS: &DNSSpec{"wrw.com", "A"}, Extracts: []Extract{{"x", SourceRegex, "."}}}
		}, "steps.0.extracts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := single(KindHTTP)
			c.edit(s)
			wantField(t, s, c.field)
		})
	}
	// A credential on an HTTP step is fine.
	s := single(KindHTTP)
	id := uuid.New()
	s.Steps[0].CredentialID = &id
	wantValid(t, s)
}

func TestValidateHTTP(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*HTTPSpec)
		field string // "" means valid
	}{
		{"http scheme", func(h *HTTPSpec) { h.URL = "http://www.wrw.com/" }, ""},
		{"idn host", func(h *HTTPSpec) { h.URL = "https://bücher.wrw.com/" }, ""},
		{"explicit port", func(h *HTTPSpec) { h.URL = "https://www.wrw.com:8443/x" }, ""},
		{"ftp scheme", func(h *HTTPSpec) { h.URL = "ftp://www.wrw.com/" }, "url"},
		{"relative", func(h *HTTPSpec) { h.URL = "/path" }, "url"},
		{"no host", func(h *HTTPSpec) { h.URL = "https:///path" }, "url"},
		{"empty", func(h *HTTPSpec) { h.URL = "" }, "url"},
		{"ip literal", func(h *HTTPSpec) { h.URL = "http://169.254.169.254/latest/meta-data" }, "url"},
		{"ipv6 literal", func(h *HTTPSpec) { h.URL = "http://[::1]:8080/" }, "url"},
		{"short ipv4", func(h *HTTPSpec) { h.URL = "http://127.1/" }, "url"},
		{"localhost", func(h *HTTPSpec) { h.URL = "http://localhost:8080/" }, "url"},
		{"kubernetes api", func(h *HTTPSpec) { h.URL = "https://kubernetes.default.svc/api" }, "url"},
		{"kubernetes api fqdn", func(h *HTTPSpec) { h.URL = "https://kubernetes.default.svc.cluster.local/" }, "url"},
		{"userinfo", func(h *HTTPSpec) { h.URL = "https://user:pw@www.wrw.com/" }, "url"},
		{"port zero", func(h *HTTPSpec) { h.URL = "https://www.wrw.com:0/" }, "url"},
		{"port too big", func(h *HTTPSpec) { h.URL = "https://www.wrw.com:65536/" }, "url"},
		{"empty port", func(h *HTTPSpec) { h.URL = "https://www.wrw.com:/" }, "url"},
		{"space", func(h *HTTPSpec) { h.URL = "https://www.wrw.com/a b" }, "url"},
		{"too long", func(h *HTTPSpec) { h.URL = "https://www.wrw.com/" + strings.Repeat("a", maxURL) }, "url"},
		{"method", func(h *HTTPSpec) { h.Method = "TRACE" }, "method"},
		{"lower-case method", func(h *HTTPSpec) { h.Method = "get" }, "method"},
		{"get with body", func(h *HTTPSpec) { h.Body = "x" }, "body"},
		{"body type", func(h *HTTPSpec) { h.Method, h.Body, h.BodyType = "POST", "x", "xml" }, "body_type"},
		{"invalid json body", func(h *HTTPSpec) { h.Method, h.Body, h.BodyType = "POST", "{", BodyJSON }, "body"},
		{"text body", func(h *HTTPSpec) { h.Method, h.Body, h.BodyType = "PUT", "{", BodyText }, ""},
		{"header ok", func(h *HTTPSpec) { h.Headers = map[string]string{"X-Api-Version": "2"} }, ""},
		{"host header", func(h *HTTPSpec) { h.Headers = map[string]string{"host": "internal.wrw.com"} }, "headers.host"},
		{"transfer-encoding", func(h *HTTPSpec) { h.Headers = map[string]string{"Transfer-Encoding": "chunked"} }, "headers.Transfer-Encoding"},
		{"bad header name", func(h *HTTPSpec) { h.Headers = map[string]string{"X Bad": "1"} }, "headers.X Bad"},
		{"header injection", func(h *HTTPSpec) { h.Headers = map[string]string{"X-A": "1\r\nHost: evil"} }, "headers.X-A"},
		{"duplicate header", func(h *HTTPSpec) { h.Headers = map[string]string{"X-A": "1", "x-a": "2"} }, "headers.x-a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := single(KindHTTP)
			c.edit(s.Steps[0].HTTP)
			if c.field == "" {
				wantValid(t, s)
			} else {
				wantField(t, s, "steps.0.http."+c.field)
			}
		})
	}
}

func TestValidateHostFields(t *testing.T) {
	bad := []string{"", "10.0.0.1", "localhost", "kubernetes.default.svc", "a..b", "wrw.com:22", "${host}"}
	for _, h := range bad {
		s := single(KindTCP)
		s.Steps[0].TCP.Host = h
		wantField(t, s, "steps.0.tcp.host")

		s = single(KindDNS)
		s.Steps[0].DNS.Name = h
		wantField(t, s, "steps.0.dns.name")

		s = single(KindTLS)
		s.Steps[0].TLS.Host = h
		wantField(t, s, "steps.0.tls.host")

		if h != "" {
			s = single(KindTLS)
			s.Steps[0].TLS.SNI = h
			wantField(t, s, "steps.0.tls.sni")
		}
	}
	for _, p := range []int{0, -1, 65536} {
		s := single(KindTCP)
		s.Steps[0].TCP.Port = p
		wantField(t, s, "steps.0.tcp.port")
		s = single(KindTLS)
		s.Steps[0].TLS.Port = p
		wantField(t, s, "steps.0.tls.port")
	}
	s := single(KindDNS)
	s.Steps[0].DNS.RecordType = "MX"
	wantField(t, s, "steps.0.dns.record_type")
}

func TestValidateVariables(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*Scenario)
		field string // "" means valid
	}{
		{"var in scheme", func(s *Scenario) { s.Steps[1].HTTP.URL = "${token}://api.wrw.com/" }, "steps.1.http.url"},
		{"var as host", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://${token}/" }, "steps.1.http.url"},
		{"var in host", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://api.${token}.wrw.com/" }, "steps.1.http.url"},
		{"var after host", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://api.wrw.com${token}" }, "steps.1.http.url"},
		{"var in port", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://api.wrw.com:${token}/" }, "steps.1.http.url"},
		{"var in userinfo", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://${token}@api.wrw.com/" }, "steps.1.http.url"},
		{"var in query", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://api.wrw.com?q=${token}" }, ""},
		{"var in fragment", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://api.wrw.com#${token}" }, ""},
		{"undefined var", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://api.wrw.com/${nope}" }, "steps.1.http.url"},
		{"var in own step", func(s *Scenario) { s.Steps[0].HTTP.URL = "https://api.wrw.com/${token}" }, "steps.0.http.url"},
		{"var from later step", func(s *Scenario) {
			s.Steps[1].Extracts = []Extract{{"later", SourceRegex, "id=(\\d+)"}}
			s.Steps[0].HTTP.Headers = map[string]string{"X-Later": "${later}"}
		}, "steps.0.http.headers.X-Later"},
		{"var in body", func(s *Scenario) {
			s.Steps[1].HTTP.Method, s.Steps[1].HTTP.Body, s.Steps[1].HTTP.BodyType = "POST", `{"t":"${token}"}`, BodyJSON
		}, ""},
		{"var as json number", func(s *Scenario) {
			s.Steps[1].HTTP.Method, s.Steps[1].HTTP.Body, s.Steps[1].HTTP.BodyType = "POST", `{"n":${sid},"${token}":true}`, BodyJSON
		}, ""},
		{"invalid json body with var", func(s *Scenario) {
			s.Steps[1].HTTP.Method, s.Steps[1].HTTP.Body, s.Steps[1].HTTP.BodyType = "POST", `{"a":"${token}"`, BodyJSON
		}, "steps.1.http.body"},
		{"json body broken around var", func(s *Scenario) {
			s.Steps[1].HTTP.Method, s.Steps[1].HTTP.Body, s.Steps[1].HTTP.BodyType = "POST", `{"a" ${token}}`, BodyJSON
		}, "steps.1.http.body"},
		{"text body with var is not checked as json", func(s *Scenario) {
			s.Steps[1].HTTP.Method, s.Steps[1].HTTP.Body, s.Steps[1].HTTP.BodyType = "POST", `{"a":"${token}"`, BodyText
		}, ""},
		{"undefined var in body", func(s *Scenario) {
			s.Steps[1].HTTP.Method, s.Steps[1].HTTP.Body = "POST", "${other}"
		}, "steps.1.http.body"},
		{"unterminated reference", func(s *Scenario) { s.Steps[1].HTTP.Headers = map[string]string{"X-T": "${token"} }, "steps.1.http.headers.X-T"},
		{"invalid name reference", func(s *Scenario) { s.Steps[1].HTTP.URL = "https://api.wrw.com/${a-b}" }, "steps.1.http.url"},
		{"var in tcp host", func(s *Scenario) { s.Steps[3].TCP.Host = "${token}" }, "steps.3.tcp.host"},
		{"var in tls host", func(s *Scenario) { s.Steps[4].TLS.Host = "${token}.wrw.com" }, "steps.4.tls.host"},
		{"var in sni", func(s *Scenario) { s.Steps[4].TLS.SNI = "${token}" }, "steps.4.tls.sni"},
		{"var in dns name", func(s *Scenario) { s.Steps[2].DNS.Name = "${token}" }, "steps.2.dns.name"},
		{"duplicate extract across steps", func(s *Scenario) {
			s.Steps[1].Extracts = []Extract{{"token", SourceHeader, "X-New"}}
		}, "steps.1.extracts.0.name"},
		{"duplicate extract in step", func(s *Scenario) {
			s.Steps[0].Extracts = append(s.Steps[0].Extracts, Extract{"sid", SourceHeader, "X-Other"})
		}, "steps.0.extracts.2.name"},
		{"bad extract name", func(s *Scenario) { s.Steps[0].Extracts[0].Name = "1abc" }, "steps.0.extracts.0.name"},
		{"bad extract source", func(s *Scenario) { s.Steps[0].Extracts[0].Source = "xpath" }, "steps.0.extracts.0.source"},
		{"bad json path", func(s *Scenario) { s.Steps[0].Extracts[0].Expr = "data..token" }, "steps.0.extracts.0.expr"},
		{"bad header expr", func(s *Scenario) { s.Steps[0].Extracts[1].Expr = "" }, "steps.0.extracts.1.expr"},
		{"bad regex expr", func(s *Scenario) {
			s.Steps[0].Extracts[1] = Extract{"sid", SourceRegex, "(a"}
		}, "steps.0.extracts.1.expr"},
		{"backreference is not RE2", func(s *Scenario) {
			s.Steps[0].Extracts[1] = Extract{"sid", SourceRegex, `(a)\1`}
		}, "steps.0.extracts.1.expr"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := flow()
			c.edit(s)
			if c.field == "" {
				wantValid(t, s)
			} else {
				wantField(t, s, c.field)
			}
		})
	}
}

func TestValidateAssertions(t *testing.T) {
	cases := []struct {
		kind  string
		a     Assertion
		field string // "" means valid; else subject, operator or value
	}{
		{KindHTTP, Assertion{"status_code", "equals", "200"}, ""},
		{KindHTTP, Assertion{"status_code", "less_than", "400"}, ""},
		{KindHTTP, Assertion{"status_code", "contains", "2"}, "operator"},
		{KindHTTP, Assertion{"status_code", "equals", "ok"}, "value"},
		{KindHTTP, Assertion{"status_code", "equals", "NaN"}, "value"},
		{KindHTTP, Assertion{"latency_ms", "less_than", "250"}, ""},
		{KindHTTP, Assertion{"latency_ms", "less_than", "250.5"}, "value"},
		{KindHTTP, Assertion{"status_code", "equals", "2e2"}, "value"},
		{KindHTTP, Assertion{"tls_days_left", "greater_than", "-1"}, ""},
		{KindHTTP, Assertion{"tls_days_left", "greater_than", "14.5"}, "value"},
		{KindDNS, Assertion{"record_count", "equals", "1.0"}, "value"},
		{KindTLS, Assertion{"tls_days_left", "less_than", " 7"}, "value"},
		{KindHTTP, Assertion{"json:data.ratio", "less_than", "0.5"}, ""},
		{KindHTTP, Assertion{"header:Content-Type", "contains", "json"}, ""},
		{KindHTTP, Assertion{"header:X-Id", "exists", ""}, ""},
		{KindHTTP, Assertion{"header:X-Id", "exists", "yes"}, "value"},
		{KindHTTP, Assertion{"header:Bad Name", "exists", ""}, "subject"},
		{KindHTTP, Assertion{"header:", "exists", ""}, "subject"},
		{KindHTTP, Assertion{"header:X-Id", "less_than", "3"}, "operator"},
		{KindHTTP, Assertion{"body", "contains", "ok"}, ""},
		{KindHTTP, Assertion{"body", "contains", ""}, "value"},
		{KindHTTP, Assertion{"body", "matches", "^ok$"}, ""},
		{KindHTTP, Assertion{"body", "matches", "(?<=a)b"}, "value"},
		{KindHTTP, Assertion{"body", "length_greater_than", "10"}, ""},
		{KindHTTP, Assertion{"body", "length_greater_than", "-1"}, "value"},
		{KindHTTP, Assertion{"body", "exists", ""}, "operator"},
		{KindHTTP, Assertion{"json:data.items", "length_greater_than", "0"}, ""},
		{KindHTTP, Assertion{"json:$.data.items[0]['id']", "greater_than", "7"}, ""},
		{KindHTTP, Assertion{"json:data.count", "greater_than", "many"}, "value"},
		{KindHTTP, Assertion{"json:data.state", "equals", "ready"}, ""},
		{KindHTTP, Assertion{"json:data[", "exists", ""}, "subject"},
		{KindHTTP, Assertion{"json:", "exists", ""}, "subject"},
		{KindHTTP, Assertion{"tls_days_left", "greater_than", "14"}, ""},
		{KindHTTP, Assertion{"record_count", "equals", "1"}, "subject"},
		{KindHTTP, Assertion{"status", "equals", "200"}, "subject"},
		{KindHTTP, Assertion{"status_code", "eq", "200"}, "operator"},
		{KindHTTP, Assertion{"status_code", "", "200"}, "operator"},
		{KindHTTP, Assertion{"body", "equals", strings.Repeat("a", maxValue+1)}, "value"},
		{KindDNS, Assertion{"record_count", "greater_than", "0"}, ""},
		{KindDNS, Assertion{"record", "contains", "v=spf1"}, ""},
		{KindDNS, Assertion{"record", "exists", ""}, "operator"},
		{KindDNS, Assertion{"latency_ms", "less_than", "50"}, ""},
		{KindDNS, Assertion{"status_code", "equals", "200"}, "subject"},
		{KindDNS, Assertion{"header:X", "exists", ""}, "subject"},
		{KindTCP, Assertion{"connects", "equals", "true"}, ""},
		{KindTCP, Assertion{"connects", "equals", "yes"}, "value"},
		{KindTCP, Assertion{"connects", "less_than", "1"}, "operator"},
		{KindTCP, Assertion{"json:a", "exists", ""}, "subject"},
		{KindTLS, Assertion{"tls_days_left", "greater_than", "14"}, ""},
		{KindTLS, Assertion{"chain_valid", "equals", "true"}, ""},
		{KindTLS, Assertion{"hostname_matches", "not_equals", "false"}, ""},
		{KindTLS, Assertion{"tls_version", "greater_than", "1.1"}, ""},
		{KindTLS, Assertion{"tls_version", "equals", "TLS1.3"}, "value"},
		{KindTLS, Assertion{"tls_version", "contains", "1"}, "operator"},
		{KindTLS, Assertion{"body", "contains", "x"}, "subject"},
	}
	for _, c := range cases {
		s := single(c.kind)
		s.Steps[0].Assertions = []Assertion{c.a}
		f := Validate(s)
		if c.field == "" {
			if len(f) != 0 {
				t.Errorf("%s %+v: %v, want valid", c.kind, c.a, f)
			}
			continue
		}
		if _, ok := f["steps.0.assertions.0."+c.field]; !ok {
			t.Errorf("%s %+v: %v, want an error for %s", c.kind, c.a, f, c.field)
		}
	}

	// tls_days_left needs an https URL on an HTTP step.
	s := single(KindHTTP)
	s.Steps[0].HTTP.URL = "http://www.wrw.com/"
	s.Steps[0].Assertions = []Assertion{{SubjectTLSDaysLeft, OpGreaterThan, "14"}}
	wantField(t, s, "steps.0.assertions.0.subject")

	// Too many assertions.
	s = single(KindTCP)
	for range maxAssertions + 1 {
		s.Steps[0].Assertions = append(s.Steps[0].Assertions, Assertion{SubjectConnects, OpEquals, "true"})
	}
	wantField(t, s, "steps.0.assertions")
}

func TestScenarioJSON(t *testing.T) {
	id := uuid.MustParse("6f0c2b3e-8a41-4d4e-9a57-2f6a3f1d9b10")
	s := flow()
	s.ID = "s1"
	s.Steps[1].CredentialID = &id
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"interval_seconds":60`, `"timeout_seconds":30`, `"step_retries":1`,
		`"store_responses":true`, `"credential_id":"6f0c2b3e-8a41-4d4e-9a57-2f6a3f1d9b10"`,
		`"follow_redirects":false`, `"body_type":"json"`, `"record_type":"A"`, `"sni":"edge.wrw.com"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("JSON lacks %s: %s", key, b)
		}
	}
	var back Scenario
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	wantValid(t, &back)
	if *back.Steps[1].CredentialID != id || back.Steps[4].TLS.SNI != "edge.wrw.com" {
		t.Fatalf("round trip lost fields: %+v", back)
	}
}
