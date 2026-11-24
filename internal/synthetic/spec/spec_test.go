package spec

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestHosts(t *testing.T) {
	got := Hosts(flow())
	want := []string{"api.wrw.com", "db.wrw.com", "edge.wrw.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Hosts = %v, want %v", got, want)
	}

	s := &Scenario{Steps: []Step{
		{Kind: KindHTTP, HTTP: &HTTPSpec{URL: "https://API.WRW.com.:8443/${x}"}},
		{Kind: KindHTTP, HTTP: &HTTPSpec{URL: "https://bücher.wrw.com/"}},
		{Kind: KindHTTP, HTTP: &HTTPSpec{URL: "http://169.254.169.254/"}},
		{Kind: KindHTTP, HTTP: &HTTPSpec{URL: "https://${h}/"}},
		{Kind: KindHTTP, HTTP: &HTTPSpec{URL: "not a url"}},
		{Kind: KindTCP, TCP: &TCPSpec{Host: "localhost"}},
		{Kind: KindDNS, DNS: &DNSSpec{Name: "Mail.wrw.com"}},
		{Kind: KindTLS, TLS: &TLSSpec{Host: "api.wrw.com"}},
	}}
	got = Hosts(s)
	want = []string{"api.wrw.com", "xn--bcher-kva.wrw.com", "mail.wrw.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Hosts = %v, want %v", got, want)
	}
	if Hosts(nil) != nil {
		t.Fatal("Hosts(nil) not nil")
	}
}

func TestRequestsPerMinute(t *testing.T) {
	cred, other := uuid.New(), uuid.New()
	s := single(KindHTTP)
	if got := RequestsPerMinute(s); got != 2 { // 1 step, 30 s
		t.Errorf("one step every 30 s: %v, want 2", got)
	}

	s = flow() // 5 steps, 1 retry, 60 s
	if got := RequestsPerMinute(s); got != 10 {
		t.Errorf("flow: %v, want 10", got)
	}
	s.Steps[0].CredentialID = &cred
	s.Steps[1].CredentialID = &cred
	if got := RequestsPerMinute(s); got != 11 {
		t.Errorf("flow with one credential on two steps: %v, want 11", got)
	}
	s.Steps[1].CredentialID = &other
	if got := RequestsPerMinute(s); got != 12 {
		t.Errorf("flow with two credentials: %v, want 12", got)
	}

	// 10 steps without redirects, 2 retries, every 30 s.
	s = &Scenario{IntervalSeconds: 30, StepRetries: MaxStepRetries, Steps: make([]Step, MaxSteps)}
	if got := RequestsPerMinute(s); got != 60 {
		t.Errorf("10 steps, 2 retries: %v, want 60", got)
	}

	// Redirects: an HTTP step that follows them counts 1 + MaxRedirects
	// requests per attempt.
	s = single(KindHTTP) // 1 step, no retries, 30 s
	s.Steps[0].HTTP.FollowRedirects = true
	if got := RequestsPerMinute(s); got != 12 {
		t.Errorf("one redirecting step every 30 s: %v, want 12", got)
	}
	s = flow() // 5 steps, 1 retry, 60 s
	s.Steps[0].HTTP.FollowRedirects = true
	if got := RequestsPerMinute(s); got != 20 { // 2×6 + 4×2
		t.Errorf("flow with one redirecting step: %v, want 20", got)
	}
	s.Steps[0].HTTP.FollowRedirects = false
	if got := RequestsPerMinute(s); got != 10 {
		t.Errorf("flow without redirects: %v, want 10", got)
	}

	// The worst valid case with redirects: 10 redirecting HTTP steps, 2
	// retries, every 30 s, one credential: (10×3×6 + 1) × 2.
	s = &Scenario{IntervalSeconds: 30, StepRetries: MaxStepRetries}
	for i := range MaxSteps {
		s.Steps = append(s.Steps, Step{Position: i, Kind: KindHTTP, CredentialID: &cred,
			HTTP: &HTTPSpec{Method: "GET", URL: "https://www.wrw.com/", FollowRedirects: true}})
	}
	if got := RequestsPerMinute(s); got != 362 {
		t.Errorf("worst case with redirects: %v, want 362", got)
	}

	s = &Scenario{IntervalSeconds: 45, Steps: make([]Step, 1)}
	if got := RequestsPerMinute(s); math.Abs(got-4.0/3) > 1e-9 {
		t.Errorf("45 s: %v, want 1.333", got)
	}
	if RequestsPerMinute(nil) != 0 || RequestsPerMinute(&Scenario{Steps: make([]Step, 1)}) != 0 {
		t.Error("no interval should give 0")
	}
}

func TestSubstitute(t *testing.T) {
	vars := map[string]string{"token": "abc", "id": "42", "evil": "${token}", "empty": ""}
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"${token}", "abc"},
		{"/orders/${id}?t=${token}&t2=${token}", "/orders/42?t=abc&t2=abc"},
		{"${unknown}", "${unknown}"},
		{"${evil}", "${token}"}, // one pass: values are not expanded again
		{"a${empty}b", "ab"},
		{"${token", "${token"},
		{"$token", "$token"},
		{"${${id}}", "${42}"},
		{"${a-b}", "${a-b}"},
		{"$${id}", "$42"},
		{"${}", "${}"},
	}
	for _, c := range cases {
		if got := Substitute(c.in, vars); got != c.want {
			t.Errorf("Substitute(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := Substitute("${token}", nil); got != "${token}" {
		t.Errorf("nil vars: %q", got)
	}
}

func TestVarRefs(t *testing.T) {
	cases := []struct {
		in    string
		names []string
		ok    bool
	}{
		{"none", nil, true},
		{"${a}/${b_2}/${a}", []string{"a", "b_2", "a"}, true},
		{"${_x}", []string{"_x"}, true},
		{"${1x}", nil, false},
		{"${x", nil, false},
		{"${}", nil, false},
		{"$x {y}", nil, true},
	}
	for _, c := range cases {
		names, ok := varRefs(c.in)
		if ok != c.ok || ok && !reflect.DeepEqual(names, c.names) {
			t.Errorf("varRefs(%q) = %v, %v; want %v, %v", c.in, names, ok, c.names, c.ok)
		}
	}
}

func TestJSONPath(t *testing.T) {
	var doc any
	if err := json.Unmarshal([]byte(`{"data":{"items":[{"id":7,"a.b":"dot","x]":"br"}],"n-1":true},"top":"t"}`), &doc); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want any
	}{
		{"$", doc},
		{"top", "t"},
		{"$.top", "t"},
		{"data.items[0].id", 7.0},
		{"$.data.items[0]['id']", 7.0},
		{`data.items[0]["a.b"]`, "dot"},
		{`data.items[0]["x]"]`, "br"},
		{"data.n-1", true},
		{`["data"]["items"][0].id`, 7.0},
	}
	for _, c := range cases {
		p, err := ParseJSONPath(c.path)
		if err != nil {
			t.Errorf("ParseJSONPath(%q): %v", c.path, err)
			continue
		}
		got, ok := LookupJSON(doc, p)
		if !ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("LookupJSON(%q) = %v, %v; want %v", c.path, got, ok, c.want)
		}
	}

	missing := []string{"nope", "data.items[1]", "top.x", "top[0]", "data.items.id"}
	for _, m := range missing {
		p, err := ParseJSONPath(m)
		if err != nil {
			t.Errorf("ParseJSONPath(%q): %v", m, err)
			continue
		}
		if v, ok := LookupJSON(doc, p); ok {
			t.Errorf("LookupJSON(%q) = %v, want missing", m, v)
		}
	}

	bad := []string{"", ".a", "a.", "a..b", "$a", "a[", "a[]", "a[-1]", "a[01]", "a[x]", "a b",
		`a["b]`, `a["b"c"]`, `a['b"]`, "a[0]b", "$$", string(make([]byte, maxJSONPath+1))}
	for _, b := range bad {
		if p, err := ParseJSONPath(b); err == nil {
			t.Errorf("ParseJSONPath(%q) = %v, want error", b, p)
		}
	}
}
