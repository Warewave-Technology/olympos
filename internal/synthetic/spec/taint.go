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
// (ruling P11). A variable extracted by a step that uses a credential is
// tainted with that credential; one extracted by a step whose request used
// a tainted variable inherits that variable's taint as well.
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
// (URL, header values, body), once each, in order.
func StepVars(st *Step) []string {
	if st == nil || st.HTTP == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		names, _ := varRefs(s)
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	add(st.HTTP.URL)
	for _, name := range slices.Sorted(maps.Keys(st.HTTP.Headers)) {
		add(st.HTTP.Headers[name])
	}
	add(st.HTTP.Body)
	return out
}

// ValidateTaint checks ruling P11 at save time: a tainted variable may only
// be used in a step whose host is within the bound hosts of every
// credential of its taint. bounds gives each credential's bound hosts (as
// stored, validated rules); a credential missing from bounds covers no
// host. It returns one message per offending field, keyed like Validate
// ("steps.2.http.url", "steps.2.http.headers.X-Token", "steps.2.http.body"),
// and an empty map when the scenario keeps to the rule. Call it after
// Validate; fields that Validate refuses are skipped.
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
