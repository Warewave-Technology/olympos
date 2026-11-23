package spec

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
)

// Taint is the set of credentials a variable may carry a piece of
// (rulings P11 and P12). A variable extracted by a step is tainted with:
//   - the step's own credential, if it has one;
//   - the taint of every variable the step's request used;
//   - every credential of the run whose bound hosts cover the step's host,
//     whether or not the step attached it: a bound server has seen the
//     credential and may hand it back to a later step without it (P12).
type Taint map[uuid.UUID]bool

// Add adds every credential of o to t.
func (t Taint) Add(o Taint) {
	for id := range o {
		t[id] = true
	}
}

// IDs returns the credentials of t in a stable order.
func (t Taint) IDs() []uuid.UUID {
	ids := slices.Collect(maps.Keys(t))
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return ids
}

// StepVars returns the names of the variables an HTTP step's request uses
// (URL, header values, body), once each, in order. It stops at a "${" that
// does not start a valid reference; ParseStepVars reports that case.
func StepVars(st *Step) []string {
	names, _ := ParseStepVars(st)
	return names
}

// ParseStepVars is StepVars, with ok false when the URL, a header value or
// the body has a "${" that does not start a valid reference. Substitute
// still replaces references after such a "${" (in "${${a}" it replaces
// ${a}), so a caller that derives taint from these names must refuse a
// step that does not parse: then the names are exactly those Substitute
// can replace.
func ParseStepVars(st *Step) (names []string, ok bool) {
	if st == nil || st.HTTP == nil {
		return nil, true
	}
	ok = true
	seen := map[string]bool{}
	add := func(s string) {
		refs, good := varRefs(s)
		ok = ok && good
		for _, n := range refs {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	add(st.HTTP.URL)
	for _, name := range slices.Sorted(maps.Keys(st.HTTP.Headers)) {
		add(st.HTTP.Headers[name])
	}
	add(st.HTTP.Body)
	return names, ok
}

// ValidateTaint checks rulings P11 and P12 at save time: a tainted variable
// may only be used in a step whose host is within the bound hosts of every
// credential of its taint (see Taint for what taints a variable). bounds
// gives each credential's bound hosts (as
// stored, validated rules); a credential missing from bounds covers no
// host. It returns one message per offending field, keyed like Validate
// ("steps.2.http.url", "steps.2.http.headers.X-Token", "steps.2.http.body"),
// and an empty map when the scenario keeps to the rule. Call it after
// Validate; fields that Validate refuses are skipped. bounds must hold the
// same credentials the probe is given for the run, since P12 taints the
// extracts of a step on a bound host with every one of them.
//
// The probe enforces the same rule again at run time, on every request and
// redirect hop.
func ValidateTaint(s *Scenario, bounds map[uuid.UUID][]hostallow.Rule) map[string]string {
	f := map[string]string{}
	if s == nil {
		return f
	}
	taint := map[string]Taint{}
	for i := range s.Steps {
		st := &s.Steps[i]
		used := Taint{}
		if st.HTTP != nil {
			host := ""
			if u, ok := parseURL(st.HTTP.URL); ok {
				if n, err := hostallow.Normalize(u.Hostname()); err == nil {
					host = n
				}
			}
			p := fmt.Sprintf("steps.%d.http", i)
			check := func(key, text string) {
				names, _ := varRefs(text)
				for _, n := range names {
					t := taint[n]
					used.Add(t)
					for _, id := range t.IDs() {
						if host == "" || !covers(bounds[id], host) {
							if _, dup := f[key]; !dup {
								f[key] = fmt.Sprintf("${%s} comes from a step that uses credential %s, so it may only be sent to that credential's bound hosts", n, id)
							}
						}
					}
				}
			}
			check(p+".url", st.HTTP.URL)
			for _, name := range slices.Sorted(maps.Keys(st.HTTP.Headers)) {
				check(p+".headers."+name, st.HTTP.Headers[name])
			}
			check(p+".body", st.HTTP.Body)
			// P12: a response from a bound host may carry that
			// credential, attached by this step or not.
			if host != "" {
				for id, rules := range bounds {
					if covers(rules, host) {
						used[id] = true
					}
				}
			}
		}
		if st.CredentialID != nil {
			used[*st.CredentialID] = true
		}
		for _, e := range st.Extracts {
			if len(used) > 0 {
				t := Taint{}
				t.Add(used)
				taint[e.Name] = t
			}
		}
	}
	return f
}

// covers reports whether host matches one of rules.
func covers(rules []hostallow.Rule, host string) bool {
	_, ok := hostallow.List{Rules: rules}.Match(strings.TrimSuffix(host, "."))
	return ok
}
