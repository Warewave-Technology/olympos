package spec

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
)

func taintStep(url string, cred *uuid.UUID, extract string, headers map[string]string, body string) Step {
	st := Step{Kind: KindHTTP, HTTP: &HTTPSpec{Method: "POST", URL: url, Headers: headers, Body: body}, CredentialID: cred}
	if extract != "" {
		st.Extracts = []Extract{{Name: extract, Source: SourceJSONPath, Expr: "v"}}
	}
	return st
}

// Ruling P11: a variable from a credentialed step may only go to the bound
// hosts of that credential, and so may any variable derived from it.
func TestValidateTaint(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	bounds := map[uuid.UUID][]hostallow.Rule{
		a: {{Pattern: "api.wrw.com", Kind: hostallow.Exact}},
		b: {{Pattern: "wrw.com", Kind: hostallow.Suffix}},
	}
	steps := func(st ...Step) *Scenario {
		for i := range st {
			st[i].Position = i
		}
		return &Scenario{Steps: st}
	}

	// Allowed: tainted variable back to the bound host; untainted anywhere.
	ok := steps(
		taintStep("https://api.wrw.com/login", &a, "tok", nil, ""),
		taintStep("https://api.wrw.com/x?t=${tok}", nil, "", map[string]string{"X-T": "${tok}"}, "${tok}"),
		taintStep("https://public.example.org/", nil, "free", nil, ""),
		taintStep("https://other.example.org/${free}", nil, "", nil, ""),
	)
	if f := ValidateTaint(ok, bounds); len(f) != 0 {
		t.Fatalf("refused: %v", f)
	}

	// Refused: to an unbound host in the URL, a header or the body.
	bad := steps(
		taintStep("https://api.wrw.com/login", &a, "tok", nil, ""),
		taintStep("https://evil.wrw.com/?t=${tok}", nil, "", map[string]string{"X-T": "${tok}"}, "b=${tok}"),
	)
	f := ValidateTaint(bad, bounds)
	for _, k := range []string{"steps.1.http.url", "steps.1.http.headers.X-T", "steps.1.http.body"} {
		if !strings.Contains(f[k], a.String()) {
			t.Errorf("%s: %q", k, f[k])
		}
	}

	// Inherited: a variable from a step that used ${tok} carries a's taint
	// (and b's, its own credential): the union must cover the host.
	inh := steps(
		taintStep("https://api.wrw.com/login", &a, "tok", nil, ""),
		taintStep("https://api.wrw.com/swap", &b, "tok2", map[string]string{"X-T": "${tok}"}, ""),
		taintStep("https://x.wrw.com/${tok2}", nil, "", nil, ""),
		taintStep("https://api.wrw.com/${tok2}", nil, "", nil, ""),
	)
	f = ValidateTaint(inh, bounds)
	if len(f) != 1 || !strings.Contains(f["steps.2.http.url"], a.String()) {
		t.Fatalf("inherited: %v", f)
	}

	// A credential without known bounds covers nothing.
	unknown := uuid.New()
	f = ValidateTaint(steps(
		taintStep("https://api.wrw.com/login", &unknown, "tok", nil, ""),
		taintStep("https://api.wrw.com/${tok}", nil, "", nil, ""),
	), bounds)
	if len(f) != 1 {
		t.Fatalf("unknown credential: %v", f)
	}
	if got := StepVars(&inh.Steps[1]); len(got) != 1 || got[0] != "tok" {
		t.Fatalf("StepVars %v", got)
	}
	if len(ValidateTaint(nil, nil)) != 0 {
		t.Fatal("nil scenario")
	}
}

// Ruling P12: an extract from a step on a bound host is tainted with that
// credential even when the step does not attach it.
func TestValidateTaintBoundHostResponses(t *testing.T) {
	a := uuid.New()
	rule, err := hostallow.ParseRule("wildcard:*.prod.wrw.com")
	if err != nil {
		t.Fatal(err)
	}
	bounds := map[uuid.UUID][]hostallow.Rule{a: {rule}}
	steps := func(st ...Step) *Scenario {
		for i := range st {
			st[i].Position = i
		}
		return &Scenario{Steps: st}
	}

	// No credential on the reading step: still tainted.
	f := ValidateTaint(steps(
		taintStep("https://api.prod.wrw.com/record", &a, "", nil, ""),
		taintStep("https://api.prod.wrw.com/last", nil, "v", nil, ""),
		taintStep("https://elsewhere.example.org/", nil, "", map[string]string{"X-V": "${v}"}, ""),
	), bounds)
	if len(f) != 1 || !strings.Contains(f["steps.2.http.headers.X-V"], a.String()) {
		t.Fatalf("bound-host response not tainted: %v", f)
	}

	// The mockup flow: the item id read from the catalog goes back to a
	// bound host, with or without the credential on the second step.
	for _, cred := range []*uuid.UUID{&a, nil} {
		f = ValidateTaint(steps(
			taintStep("https://api.prod.wrw.com/v1/catalog?limit=1", &a, "item", nil, ""),
			taintStep("https://api.prod.wrw.com/v1/items/${item}", cred, "", nil, ""),
		), bounds)
		if len(f) != 0 {
			t.Fatalf("mockup flow refused: %v", f)
		}
	}

	// A response from a host outside every bound host taints nothing.
	f = ValidateTaint(steps(
		taintStep("https://public.example.org/", nil, "v", nil, ""),
		taintStep("https://elsewhere.example.org/${v}", nil, "", nil, ""),
	), bounds)
	if len(f) != 0 {
		t.Fatalf("unbound response tainted: %v", f)
	}
}

// ParseStepVars reports a "${" that does not start a valid reference,
// which Substitute would read past ("${${a}" still replaces ${a}).
func TestParseStepVars(t *testing.T) {
	for _, tc := range []struct {
		url, header, body string
		ok                bool
	}{
		{"https://a/${x}", "${y}", "${x}", true},
		{"https://a/", "${${tok}", "", false},
		{"https://a/${${tok}", "", "", false},
		{"https://a/", "", "${tok", false},
		{"https://a/", "", "${1x}", false},
	} {
		st := taintStep(tc.url, nil, "", map[string]string{"X": tc.header}, tc.body)
		if _, ok := ParseStepVars(&st); ok != tc.ok {
			t.Errorf("%+v: ok=%v", tc, ok)
		}
	}
	st := taintStep("https://a/${x}", nil, "", map[string]string{"X": "${y}"}, "${x}")
	if names, _ := ParseStepVars(&st); strings.Join(names, ",") != "x,y" {
		t.Errorf("names %v", names)
	}
	if names, ok := ParseStepVars(nil); names != nil || !ok {
		t.Error("nil step")
	}
}
