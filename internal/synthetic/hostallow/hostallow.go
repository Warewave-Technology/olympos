// Package hostallow is the host allowlist of synthetic monitoring
// (docs/design/synthetic-monitoring.md §6.1). The server uses it to validate
// scenarios when they are saved; olympos-probe uses it at connect time,
// before it calls any host.
//
// Everything here fails closed: a host that cannot be normalized never
// matches, and a rule that does not validate is skipped.
//
// Callers that connect must use the name Normalize returns, not the raw
// input, so that the name checked is the name dialed. The probe resolves it
// as an absolute name (no search list), then checks every answer with
// DeniedIP.
package hostallow

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Kind is how a Rule's pattern matches host names.
type Kind string

const (
	// Exact matches the pattern only.
	Exact Kind = "exact"
	// Wildcard ("*.dev.wrw.com") matches every name under the base, at any
	// depth, but not the base itself.
	Wildcard Kind = "wildcard"
	// Suffix ("wrw.com") matches the pattern and every name under it.
	Suffix Kind = "suffix"
)

// Rule is one allowlist entry.
type Rule struct {
	Pattern string
	Kind    Kind
}

// List is a snapshot of the global allowlist.
type List struct {
	Version int64
	Rules   []Rule
}

var (
	// ErrIPLiteral means the host is an IP address, in any notation.
	ErrIPLiteral = errors.New("IP literals are not allowed")
	// ErrDeniedName means the host is a name that is always denied.
	ErrDeniedName = errors.New("host name is always denied")
	// ErrInvalidHost means the host is not a valid DNS host name.
	ErrInvalidHost = errors.New("invalid host name")
)

const (
	maxNameLen  = 253
	maxLabelLen = 63
)

// Normalize returns the canonical form of a host name: IDNA (UTS #46,
// lookup profile) to ASCII, lower case, trailing dot removed. It refuses IP
// literals (including bracketed, zoned and the short or numeric IPv4 forms
// such as "127.1", "0x7f.1" and "2130706433"), the always-denied names, and
// anything that is not a plain host name: ports, userinfo, paths, percent
// encoding, "*", empty labels, over-long names.
func Normalize(host string) (string, error) {
	if host == "" {
		return "", invalid(host, "empty")
	}
	if !utf8.ValidString(host) {
		return "", invalid(host, "not valid UTF-8")
	}

	// IP literals the IDNA step would only report as invalid characters.
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end > 0 {
			if _, err := netip.ParseAddr(host[1:end]); err == nil {
				return "", ipLiteral(host)
			}
		}
		return "", invalid(host, "brackets are only valid around an IPv6 address")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", ipLiteral(host)
	}
	if _, err := netip.ParseAddrPort(host); err == nil {
		return "", ipLiteral(host)
	}

	if i := strings.IndexFunc(host, isForbidden); i >= 0 {
		r, _ := utf8.DecodeRuneInString(host[i:])
		return "", invalid(host, fmt.Sprintf("character %q is not allowed", r))
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", invalid(host, "not a valid internationalized name")
	}
	name := strings.ToLower(ascii)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", invalid(host, "empty")
	}
	if len(name) > maxNameLen {
		return "", invalid(host, "longer than 253 characters")
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if why := checkLabel(l); why != "" {
			return "", invalid(host, why)
		}
	}

	// The IDNA mapping turns full-width digits and dots into ASCII, so the
	// IP checks run again on the result.
	if _, err := netip.ParseAddr(name); err == nil {
		return "", ipLiteral(host)
	}
	if last := labels[len(labels)-1]; allDigits(last) || strings.HasPrefix(last, "0x") {
		// No top-level domain is numeric. Resolvers that follow
		// inet_aton read such names as IPv4 addresses ("127.1",
		// "0x7f.1", "2130706433").
		return "", ipLiteral(host)
	}

	if deniedName(labels) {
		return "", fmt.Errorf("%w: %q", ErrDeniedName, host)
	}
	return name, nil
}

// isForbidden reports characters that never belong in a host name:
// separators of other URL parts, percent encoding, the wildcard star,
// control and space characters, and invisible characters. IDNA silently
// drops the invisible ones (zero-width space, soft hyphen, variation
// selectors), so a name that looks different from the one checked would
// pass; they are refused instead. This also refuses ZWJ and ZWNJ, which
// some scripts allow in labels.
func isForbidden(r rune) bool {
	switch r {
	case ':', '@', '%', '/', '\\', '?', '#', '[', ']', '*':
		return true
	}
	return r <= 0x20 || r == 0x7f ||
		unicode.IsControl(r) ||
		unicode.Is(unicode.White_Space, r) ||
		unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

func checkLabel(l string) string {
	if l == "" {
		return "empty label"
	}
	if len(l) > maxLabelLen {
		return "label longer than 63 characters"
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Sprintf("character %q is not allowed", c)
		}
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return "label starts or ends with a hyphen"
	}
	return ""
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// deniedName reports localhost and everything under it, and the names of
// the Kubernetes API service: "kubernetes", "kubernetes.default", and any
// name that contains the labels "kubernetes.default.svc"
// ("kubernetes.default.svc.cluster.local" and the like).
func deniedName(labels []string) bool {
	if labels[len(labels)-1] == "localhost" {
		return true
	}
	name := strings.Join(labels, ".")
	if name == "kubernetes" || name == "kubernetes.default" {
		return true
	}
	for i := 0; i+2 < len(labels); i++ {
		if labels[i] == "kubernetes" && labels[i+1] == "default" && labels[i+2] == "svc" {
			return true
		}
	}
	return false
}

func invalid(host, why string) error {
	return fmt.Errorf("%w %q: %s", ErrInvalidHost, host, why)
}

func ipLiteral(host string) error {
	return fmt.Errorf("%w: %q", ErrIPLiteral, host)
}

// ValidateRule checks a rule and returns it in normalized form. An exact
// rule is any valid host name; a suffix rule has at least two labels; a
// wildcard rule is "*." followed by at least two labels. "*" is not allowed
// anywhere else.
func ValidateRule(r Rule) (Rule, error) {
	var base string
	switch r.Kind {
	case Exact, Suffix:
		base = r.Pattern
	case Wildcard:
		if !strings.HasPrefix(r.Pattern, "*.") {
			return Rule{}, fmt.Errorf("%w %q: a wildcard rule starts with \"*.\"", ErrInvalidHost, r.Pattern)
		}
		base = r.Pattern[2:]
	default:
		return Rule{}, fmt.Errorf("hostallow: rule kind %q is not exact, wildcard or suffix", r.Kind)
	}
	if strings.Contains(base, "*") {
		return Rule{}, fmt.Errorf("%w %q: \"*\" is only allowed as the first label of a wildcard rule", ErrInvalidHost, r.Pattern)
	}
	n, err := Normalize(base)
	if err != nil {
		return Rule{}, err
	}
	if r.Kind != Exact && strings.Count(n, ".") < 1 {
		return Rule{}, fmt.Errorf("%w %q: a %s rule needs at least two labels", ErrInvalidHost, r.Pattern, r.Kind)
	}
	if r.Kind == Wildcard {
		n = "*." + n
	}
	return Rule{Pattern: n, Kind: r.Kind}, nil
}

// matches reports whether normalized host h is matched by validated rule v.
func matches(v Rule, h string) bool {
	switch v.Kind {
	case Exact:
		return h == v.Pattern
	case Wildcard:
		return under(h, v.Pattern[2:])
	case Suffix:
		return h == v.Pattern || under(h, v.Pattern)
	}
	return false
}

// under reports whether name h is strictly below name base, by whole labels.
func under(h, base string) bool {
	return len(h) > len(base)+1 && strings.HasSuffix(h, "."+base)
}

// Match returns the first rule that matches host. Rules that do not
// validate are skipped; a host that does not normalize matches nothing.
// The rule is returned as it appears in the list.
func (l List) Match(host string) (Rule, bool) {
	h, err := Normalize(host)
	if err != nil {
		return Rule{}, false
	}
	for _, r := range l.Rules {
		if v, err := ValidateRule(r); err == nil && matches(v, h) {
			return r, true
		}
	}
	return Rule{}, false
}

// MatchAll returns every rule that matches host, in list order.
func (l List) MatchAll(host string) []Rule {
	h, err := Normalize(host)
	if err != nil {
		return nil
	}
	var out []Rule
	for _, r := range l.Rules {
		if v, err := ValidateRule(r); err == nil && matches(v, h) {
			out = append(out, r)
		}
	}
	return out
}

// Covers reports whether every host that bound matches is also matched by
// l. It is used to check that a credential's bound hosts stay within the
// global allowlist. An invalid bound is never covered.
func (l List) Covers(bound Rule) bool {
	b, err := ValidateRule(bound)
	if err != nil {
		return false
	}
	switch b.Kind {
	case Exact:
		_, ok := l.Match(b.Pattern)
		return ok
	case Wildcard:
		return l.coversBelow(b.Pattern[2:])
	case Suffix:
		_, ok := l.Match(b.Pattern)
		return ok && l.coversBelow(b.Pattern)
	}
	return false
}

// coversBelow reports whether l matches every name strictly below base.
// That set has unboundedly many first labels, so only a single wildcard or
// suffix rule at base or above it can cover it; exact rules and rules below
// base never can.
func (l List) coversBelow(base string) bool {
	for _, r := range l.Rules {
		v, err := ValidateRule(r)
		if err != nil {
			continue
		}
		var p string
		switch v.Kind {
		case Wildcard:
			p = v.Pattern[2:]
		case Suffix:
			p = v.Pattern
		default:
			continue
		}
		if base == p || under(base, p) {
			return true
		}
	}
	return false
}
