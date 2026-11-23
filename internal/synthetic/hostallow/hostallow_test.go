package hostallow

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"api.prod.wrw.com", "api.prod.wrw.com"},
		{"API.Prod.WRW.com.", "api.prod.wrw.com"},
		{"bücher.wrw.com", "xn--bcher-kva.wrw.com"},
		{"BÜCHER.wrw.com", "xn--bcher-kva.wrw.com"},
		{"xn--bcher-kva.wrw.com", "xn--bcher-kva.wrw.com"},
		{"XN--BCHER-KVA.WRW.COM", "xn--bcher-kva.wrw.com"},
		{"svc.ns.svc.cluster.local", "svc.ns.svc.cluster.local"},
		{"my-host.example", "my-host.example"},
		{"a1.example", "a1.example"},
		{"example.com1", "example.com1"},
		{"kubernetes.io", "kubernetes.io"},
		{"docs.kubernetes.io", "docs.kubernetes.io"},
		{"localhost.example.com", "localhost.example.com"},
		{"intranet", "intranet"},
		// Full-width letters and dots are mapped by IDNA.
		{"ｗｒｗ.com", "wrw.com"},
		{"wrw\uff0ecom\uff0e", "wrw.com"},
		{"wrw\u3002com", "wrw.com"},
	}
	for _, c := range cases {
		got, err := Normalize(c.in)
		if err != nil {
			t.Errorf("Normalize(%q) error %v, want %q", c.in, err, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeRefused(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		// IP literals.
		{"127.0.0.1", ErrIPLiteral},
		{"127.0.0.1.", ErrIPLiteral},
		{"8.8.8.8", ErrIPLiteral},
		{"169.254.169.254", ErrIPLiteral},
		{"::1", ErrIPLiteral},
		{"fe80::1%eth0", ErrIPLiteral},
		{"::ffff:127.0.0.1", ErrIPLiteral},
		{"[::1]", ErrIPLiteral},
		{"[fd00:ec2::254]", ErrIPLiteral},
		{"[::1]:443", ErrIPLiteral},
		{"127.0.0.1:80", ErrIPLiteral},
		{"0x7f.1", ErrIPLiteral},
		{"0x7f000001", ErrIPLiteral},
		{"0X7F000001", ErrIPLiteral},
		{"2130706433", ErrIPLiteral},
		{"127.1", ErrIPLiteral},
		{"127.0.1", ErrIPLiteral},
		{"0177.0.0.1", ErrIPLiteral},
		{"010.0.0.1", ErrIPLiteral},
		{"1.2.3.0x4", ErrIPLiteral},
		{"0x", ErrIPLiteral},
		{"example.0x1f", ErrIPLiteral},
		{"example.123", ErrIPLiteral},
		{"0", ErrIPLiteral},
		// Full-width digits and the ideographic full stop map to an IP literal.
		{"１２７.０.０.１", ErrIPLiteral},
		{"127。0。0。1", ErrIPLiteral},

		// Denied names.
		{"localhost", ErrDeniedName},
		{"LOCALHOST", ErrDeniedName},
		{"localhost.", ErrDeniedName},
		{"a.localhost", ErrDeniedName},
		{"x.y.localhost", ErrDeniedName},
		{"ｌｏｃａｌｈｏｓｔ", ErrDeniedName},
		{"kubernetes", ErrDeniedName},
		{"Kubernetes.", ErrDeniedName},
		{"\u212Aubernetes", ErrDeniedName}, // Kelvin sign maps to "k".
		{"kubernetes.default", ErrDeniedName},
		{"kubernetes.default.svc", ErrDeniedName},
		{"kubernetes.default.svc.", ErrDeniedName},
		{"kubernetes.default.svc.cluster.local", ErrDeniedName},
		{"KUBERNETES.DEFAULT.SVC.CLUSTER.LOCAL.", ErrDeniedName},
		{"kubernetes.default.svc.my-cluster.example", ErrDeniedName},
		{"x.kubernetes.default.svc.cluster.local", ErrDeniedName},

		// Invalid hosts.
		{"", ErrInvalidHost},
		{".", ErrInvalidHost},
		{"..", ErrInvalidHost},
		{".example.com", ErrInvalidHost},
		{"a..example.com", ErrInvalidHost},
		{"example.com..", ErrInvalidHost},
		{"example.com:443", ErrInvalidHost},
		{"example.com:", ErrInvalidHost},
		{"user@example.com", ErrInvalidHost},
		{"user:pw@example.com", ErrInvalidHost},
		{"ex%61mple.com", ErrInvalidHost},
		{"%2e.example.com", ErrInvalidHost},
		{"exa mple.com", ErrInvalidHost},
		{" example.com", ErrInvalidHost},
		{"example.com\n", ErrInvalidHost},
		{"example.com\x00", ErrInvalidHost},
		{"example.com/path", ErrInvalidHost},
		{"example.com\\path", ErrInvalidHost},
		{"example.com?q", ErrInvalidHost},
		{"example.com#f", ErrInvalidHost},
		{"http://example.com", ErrInvalidHost},
		{"*", ErrInvalidHost},
		{"*.example.com", ErrInvalidHost},
		{"a.*.example.com", ErrInvalidHost},
		{"ex*mple.com", ErrInvalidHost},
		{"[example.com]", ErrInvalidHost},
		{"[::1", ErrInvalidHost},
		{"under_score.example.com", ErrInvalidHost},
		{"-lead.example.com", ErrInvalidHost},
		{"trail-.example.com", ErrInvalidHost},
		{"xn--zz-.example.com", ErrInvalidHost},
		{"xn--.example.com", ErrInvalidHost},
		{strings.Repeat("a", 64) + ".example.com", ErrInvalidHost},
		{strings.Repeat("a.", 127) + "example.com", ErrInvalidHost},
		{"\xff.example.com", ErrInvalidHost},
		// Invisible characters, which IDNA would silently drop.
		{"exam\u200bple.com", ErrInvalidHost}, // zero-width space
		{"exam\u00adple.com", ErrInvalidHost}, // soft hyphen
		{"\ufeffexample.com", ErrInvalidHost}, // byte order mark
		{"exam\u2060ple.com", ErrInvalidHost}, // word joiner
		{"examp\ufe0fle.com", ErrInvalidHost}, // variation selector
		{"exam\u034fple.com", ErrInvalidHost}, // combining grapheme joiner
		{"exam\u00a0ple.com", ErrInvalidHost}, // no-break space
		{"exam\u3000ple.com", ErrInvalidHost}, // ideographic space
		{"exa\u0000mple.com", ErrInvalidHost},
		// Full-width forms of forbidden characters, which IDNA maps to ASCII.
		{"user\uff20wrw.com", ErrInvalidHost},  // ＠
		{"wrw.com\uff1a443", ErrInvalidHost},   // ：
		{"\uff0a.wrw.com", ErrInvalidHost},     // ＊
		{"ex\uff0561mple.com", ErrInvalidHost}, // ％
		{"wrw.com\uff0fx", ErrInvalidHost},     // ／
	}
	for _, c := range cases {
		got, err := Normalize(c.in)
		if err == nil {
			t.Errorf("Normalize(%q) = %q, want error %v", c.in, got, c.want)
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("Normalize(%q) error %v, want %v", c.in, err, c.want)
		}
	}
}

func TestNormalizeLengthLimits(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	if _, err := Normalize(label63 + ".example.com"); err != nil {
		t.Errorf("63-octet label refused: %v", err)
	}
	// 253 octets is the longest name.
	name := strings.Repeat("a.", 124) + "abcde" // 248 + 5 = 253
	if len(name) != 253 {
		t.Fatalf("test setup: len %d", len(name))
	}
	if _, err := Normalize(name); err != nil {
		t.Errorf("253-octet name refused: %v", err)
	}
	if _, err := Normalize(name + "."); err != nil {
		t.Errorf("253-octet name with trailing dot refused: %v", err)
	}
	if _, err := Normalize("a" + name); !errors.Is(err, ErrInvalidHost) {
		t.Errorf("254-octet name: error %v, want ErrInvalidHost", err)
	}
}

func TestValidateRule(t *testing.T) {
	ok := []struct {
		in   Rule
		want Rule
	}{
		{Rule{"partner-sftp.acme.net", Exact}, Rule{"partner-sftp.acme.net", Exact}},
		{Rule{"Partner-SFTP.acme.net.", Exact}, Rule{"partner-sftp.acme.net", Exact}},
		{Rule{"intranet", Exact}, Rule{"intranet", Exact}},
		{Rule{"*.dev.wrw.com", Wildcard}, Rule{"*.dev.wrw.com", Wildcard}},
		{Rule{"*.DEV.wrw.com.", Wildcard}, Rule{"*.dev.wrw.com", Wildcard}},
		{Rule{"*.bücher.wrw.com", Wildcard}, Rule{"*.xn--bcher-kva.wrw.com", Wildcard}},
		{Rule{"*.wrw.com", Wildcard}, Rule{"*.wrw.com", Wildcard}},
		{Rule{"wrw.com", Suffix}, Rule{"wrw.com", Suffix}},
		{Rule{"WRW.com.", Suffix}, Rule{"wrw.com", Suffix}},
		{Rule{"svc.cluster.local", Suffix}, Rule{"svc.cluster.local", Suffix}},
	}
	for _, c := range ok {
		got, err := ValidateRule(c.in)
		if err != nil {
			t.Errorf("ValidateRule(%+v) error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ValidateRule(%+v) = %+v, want %+v", c.in, got, c.want)
		}
	}

	bad := []Rule{
		{"", Exact},
		{"", Wildcard},
		{"", Suffix},
		{"wrw.com", ""},
		{"wrw.com", "Exact"},
		{"wrw.com", "glob"},
		{"*", Exact},
		{"*", Wildcard},
		{"*", Suffix},
		{"*.", Wildcard},
		{"*.com", Wildcard},
		{"*.com.", Wildcard},
		{"**.wrw.com", Wildcard},
		{"*.*.wrw.com", Wildcard},
		{"a.*.wrw.com", Wildcard},
		{"*wrw.com", Wildcard},
		{"x*.wrw.com", Wildcard},
		{"dev.wrw.com", Wildcard},
		{"*.dev.wrw.com", Exact},
		{"*.dev.wrw.com", Suffix},
		{"com", Suffix},
		{"com.", Suffix},
		{".wrw.com", Suffix},
		{"localhost", Exact},
		{"*.localhost", Wildcard},
		{"app.localhost", Suffix},
		{"kubernetes", Exact},
		{"kubernetes.default.svc.cluster.local", Exact},
		{"*.kubernetes.default.svc", Wildcard},
		{"kubernetes.default.svc", Suffix},
		{"127.0.0.1", Exact},
		{"*.0.0.1", Wildcard},
		{"0.0.1", Suffix},
		{"[::1]", Exact},
		{"wrw.com:443", Suffix},
		{"user@wrw.com", Exact},
		{"*.wr%77.com", Wildcard},
	}
	for _, r := range bad {
		if got, err := ValidateRule(r); err == nil {
			t.Errorf("ValidateRule(%+v) = %+v, want error", r, got)
		}
	}
}

func TestValidateRuleUnknownKind(t *testing.T) {
	for _, k := range []Kind{"", "Exact", "glob"} {
		_, err := ValidateRule(Rule{"wrw.com", k})
		if !errors.Is(err, ErrInvalidHost) {
			t.Errorf("ValidateRule(kind %q) error %v, want ErrInvalidHost", k, err)
		}
	}
}

// TestReasonConstants pins the exported reason values; callers store and
// compare them.
func TestReasonConstants(t *testing.T) {
	cases := []struct{ got, want string }{
		{ReasonInvalid, "invalid"},
		{ReasonUnspecified, "unspecified"},
		{ReasonLoopback, "loopback"},
		{ReasonMetadata, "metadata"},
		{ReasonLinkLocal, "link_local"},
		{ReasonMulticast, "multicast"},
		{ReasonBroadcast, "broadcast"},
		{ReasonKubernetesAPI, "kubernetes_api"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("reason constant %q, want %q", c.got, c.want)
		}
	}
}

func TestMatch(t *testing.T) {
	list := List{Version: 7, Rules: []Rule{
		{"partner-sftp.acme.net", Exact},
		{"*.dev.wrw.com", Wildcard},
		{"wrw.com", Suffix},
		{"*.bücher.example", Wildcard},
		{"svc.cluster.local", Suffix},
	}}
	cases := []struct {
		host    string
		match   bool
		pattern string
	}{
		{"partner-sftp.acme.net", true, "partner-sftp.acme.net"},
		{"PARTNER-SFTP.acme.net.", true, "partner-sftp.acme.net"},
		{"x.partner-sftp.acme.net", false, ""},
		{"acme.net", false, ""},
		{"sftp.acme.net", false, ""},

		// Wildcard: any depth, never the base name. The first matching
		// rule wins, so hosts under dev.wrw.com report the wildcard.
		{"a.dev.wrw.com", true, "*.dev.wrw.com"},
		{"x.y.dev.wrw.com", true, "*.dev.wrw.com"},
		{"dev.wrw.com", true, "wrw.com"}, // only through the suffix rule

		// Suffix: the name itself and below, whole labels only.
		{"wrw.com", true, "wrw.com"},
		{"WRW.COM.", true, "wrw.com"},
		{"api.wrw.com", true, "wrw.com"},
		{"API.Prod.WRW.com.", true, "wrw.com"},
		{"notwrw.com", false, ""},
		{"xwrw.com", false, ""},
		{"wrw.com.evil.io", false, ""},
		{"wrw.comm", false, ""},
		{"rw.com", false, ""},
		{"com", false, ""},

		// IDNA equivalence.
		{"shop.bücher.example", true, "*.bücher.example"},
		{"shop.xn--bcher-kva.example", true, "*.bücher.example"},
		{"bücher.example", false, ""},

		// In-cluster names are written in full.
		{"api.payments.svc.cluster.local", true, "svc.cluster.local"},

		// Refused hosts never match, whatever the rules say.
		{"kubernetes.default.svc.cluster.local", false, ""},
		{"kubernetes", false, ""},
		{"localhost", false, ""},
		{"127.0.0.1", false, ""},
		{"0x7f.1", false, ""},
		{"wrw.com:443", false, ""},
		{"user@wrw.com", false, ""},
		{"*.wrw.com", false, ""},
		{"*", false, ""},
		{"", false, ""},
		{"a..wrw.com", false, ""},
	}
	for _, c := range cases {
		r, ok := list.Match(c.host)
		if ok != c.match {
			t.Errorf("Match(%q) ok = %v, want %v (rule %+v)", c.host, ok, c.match, r)
			continue
		}
		if ok && r.Pattern != c.pattern {
			t.Errorf("Match(%q) rule = %q, want %q", c.host, r.Pattern, c.pattern)
		}
	}
}

func TestMatchSkipsInvalidRules(t *testing.T) {
	list := List{Rules: []Rule{
		{"*", Wildcard},
		{"com", Suffix},
		{"*.com", Wildcard},
		{"localhost", Exact},
		{"evil.io", "glob"},
		{"wrw.com", Exact},
	}}
	for _, h := range []string{"evil.io", "a.com", "b.c.com", "localhost"} {
		if r, ok := list.Match(h); ok {
			t.Errorf("Match(%q) matched invalid rule %+v", h, r)
		}
	}
	if r, ok := list.Match("wrw.com"); !ok || r.Pattern != "wrw.com" {
		t.Errorf("Match(wrw.com) = %+v, %v", r, ok)
	}
}

func TestMatchEmptyList(t *testing.T) {
	var l List
	if _, ok := l.Match("wrw.com"); ok {
		t.Error("empty list matched")
	}
	if got := l.MatchAll("wrw.com"); len(got) != 0 {
		t.Errorf("empty list MatchAll = %v", got)
	}
}

func TestMatchAll(t *testing.T) {
	list := List{Rules: []Rule{
		{"*.dev.wrw.com", Wildcard},
		{"api.dev.wrw.com", Exact},
		{"other.io", Suffix},
		{"wrw.com", Suffix},
		{"*.wrw.com", Wildcard},
	}}
	got := list.MatchAll("API.dev.wrw.com.")
	want := []string{"*.dev.wrw.com", "api.dev.wrw.com", "wrw.com", "*.wrw.com"}
	if len(got) != len(want) {
		t.Fatalf("MatchAll = %+v, want patterns %v", got, want)
	}
	for i := range want {
		if got[i].Pattern != want[i] {
			t.Errorf("MatchAll[%d] = %q, want %q", i, got[i].Pattern, want[i])
		}
	}
	if got := list.MatchAll("wrw.com"); len(got) != 1 || got[0].Pattern != "wrw.com" {
		t.Errorf("MatchAll(wrw.com) = %+v", got)
	}
	if got := list.MatchAll("localhost"); got != nil {
		t.Errorf("MatchAll(localhost) = %+v, want nil", got)
	}
}

func TestCovers(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
		bound Rule
		want  bool
	}{
		{"exact under suffix", []Rule{{"wrw.com", Suffix}}, Rule{"api.wrw.com", Exact}, true},
		{"exact equal to suffix", []Rule{{"wrw.com", Suffix}}, Rule{"wrw.com", Exact}, true},
		{"exact under wildcard", []Rule{{"*.wrw.com", Wildcard}}, Rule{"api.wrw.com", Exact}, true},
		{"exact equal to wildcard base", []Rule{{"*.wrw.com", Wildcard}}, Rule{"wrw.com", Exact}, false},
		{"exact equal to exact", []Rule{{"api.wrw.com", Exact}}, Rule{"API.wrw.com.", Exact}, true},
		{"exact not under", []Rule{{"wrw.com", Suffix}}, Rule{"wrw.com.evil.io", Exact}, false},

		{"wildcard under same wildcard", []Rule{{"*.dev.wrw.com", Wildcard}}, Rule{"*.dev.wrw.com", Wildcard}, true},
		{"wildcard under wider wildcard", []Rule{{"*.wrw.com", Wildcard}}, Rule{"*.dev.wrw.com", Wildcard}, true},
		{"wildcard under suffix", []Rule{{"wrw.com", Suffix}}, Rule{"*.dev.wrw.com", Wildcard}, true},
		{"wildcard under same-base suffix", []Rule{{"dev.wrw.com", Suffix}}, Rule{"*.dev.wrw.com", Wildcard}, true},
		{"wider wildcard not under narrower", []Rule{{"*.dev.wrw.com", Wildcard}}, Rule{"*.wrw.com", Wildcard}, false},
		{"wildcard not under exact", []Rule{{"a.dev.wrw.com", Exact}}, Rule{"*.dev.wrw.com", Wildcard}, false},
		{"wildcard not under sibling", []Rule{{"*.prod.wrw.com", Wildcard}}, Rule{"*.dev.wrw.com", Wildcard}, false},

		{"suffix under same suffix", []Rule{{"wrw.com", Suffix}}, Rule{"wrw.com", Suffix}, true},
		{"suffix under wider suffix", []Rule{{"wrw.com", Suffix}}, Rule{"dev.wrw.com", Suffix}, true},
		{"suffix under wider wildcard", []Rule{{"*.wrw.com", Wildcard}}, Rule{"dev.wrw.com", Suffix}, true},
		{"suffix not under same-base wildcard", []Rule{{"*.wrw.com", Wildcard}}, Rule{"wrw.com", Suffix}, false},
		{"suffix not under narrower wildcard", []Rule{{"*.dev.wrw.com", Wildcard}}, Rule{"wrw.com", Suffix}, false},
		{"suffix covered by exact plus wildcard",
			[]Rule{{"wrw.com", Exact}, {"*.wrw.com", Wildcard}}, Rule{"wrw.com", Suffix}, true},
		{"suffix not covered by exact alone", []Rule{{"wrw.com", Exact}}, Rule{"wrw.com", Suffix}, false},
		{"suffix not under lookalike", []Rule{{"rw.com", Suffix}}, Rule{"wrw.com", Suffix}, false},

		{"invalid bound", []Rule{{"wrw.com", Suffix}}, Rule{"*", Wildcard}, false},
		{"bound is a denied name", []Rule{{"cluster.local", Suffix}}, Rule{"kubernetes.default.svc.cluster.local", Exact}, false},
		{"invalid list rule ignored", []Rule{{"com", Suffix}}, Rule{"wrw.com", Exact}, false},
		{"empty list", nil, Rule{"wrw.com", Exact}, false},
	}
	for _, c := range cases {
		l := List{Rules: c.rules}
		if got := l.Covers(c.bound); got != c.want {
			t.Errorf("%s: Covers(%+v) = %v, want %v", c.name, c.bound, got, c.want)
		}
	}
}

func TestDeniedIP(t *testing.T) {
	apiServer := []netip.Addr{netip.MustParseAddr("10.96.0.1"), netip.MustParseAddr("fd00:10:96::1")}
	cases := []struct {
		ip     string
		denied bool
		reason string
	}{
		{"127.0.0.1", true, "loopback"},
		{"127.255.255.254", true, "loopback"},
		{"::1", true, "loopback"},
		{"::ffff:127.0.0.1", true, "loopback"},
		{"64:ff9b::127.0.0.1", true, "loopback"},
		{"::127.0.0.1", true, "loopback"}, // IPv4-compatible (deprecated)
		{"::169.254.169.254", true, "metadata"},
		{"169.254.169.254", true, "metadata"},
		{"::ffff:169.254.169.254", true, "metadata"},
		{"64:ff9b::a9fe:a9fe", true, "metadata"},
		{"fd00:ec2::254", true, "metadata"},
		{"100.100.100.200", true, "metadata"},
		{"::ffff:100.100.100.200", true, "metadata"},
		{"64:ff9b::6464:64c8", true, "metadata"},
		{"192.0.0.192", true, "metadata"},
		{"::ffff:192.0.0.192", true, "metadata"},
		{"64:ff9b:1::a9fe:a9fe", true, "metadata"},
		{"64:ff9b:1::127.0.0.1", true, "loopback"},
		{"64:ff9b:1:ffff::a60:1", true, "kubernetes_api"},
		{"255.255.255.255", true, "broadcast"},
		{"::ffff:255.255.255.255", true, "broadcast"},
		{"64:ff9b::ffff:ffff", true, "broadcast"},
		{"169.254.1.1", true, "link_local"},
		{"fe80::1", true, "link_local"},
		{"fe80::1%eth0", true, "link_local"},
		{"febf::1", true, "link_local"},
		{"::ffff:169.254.0.1", true, "link_local"},
		{"0.0.0.0", true, "unspecified"},
		{"0.1.2.3", true, "unspecified"},
		{"::ffff:0.0.0.0", true, "unspecified"},
		{"::", true, "unspecified"},
		{"224.0.0.1", true, "multicast"},
		{"239.255.255.250", true, "multicast"},
		{"ff02::1", true, "multicast"},
		{"ff05::2", true, "multicast"},
		{"::ffff:224.0.0.1", true, "multicast"},
		{"10.96.0.1", true, "kubernetes_api"},
		{"::ffff:10.96.0.1", true, "kubernetes_api"},
		{"64:ff9b::a60:1", true, "kubernetes_api"},
		{"fd00:10:96::1", true, "kubernetes_api"},

		{"10.1.2.3", false, ""},
		{"8.8.8.8", false, ""},
		{"::ffff:8.8.8.8", false, ""},
		{"64:ff9b::808:808", false, ""},
		{"2001:4860:4860::8888", false, ""},
		{"10.96.0.2", false, ""},
		{"192.168.1.10", false, ""},
		{"fd00:ec2::253", false, ""},
		{"100.100.100.201", false, ""},
		{"100.64.0.10", false, ""}, // CGNAT: may be an in-cluster range
		{"192.0.0.193", false, ""},
		{"255.255.255.254", false, ""},
		{"64:ff9b:1::808:808", false, ""},
		{"64:ff9b:2::127.0.0.1", false, ""}, // outside 64:ff9b:1::/48
		{"2002:7f00:1::", false, ""},        // 6to4 is not decoded

		// SIIT IPv4-translated, ::ffff:0:0:0/96.
		{"::ffff:0:127.0.0.1", true, "loopback"},
		{"::ffff:0:7f00:1", true, "loopback"},
		{"::ffff:0:169.254.169.254", true, "metadata"},
		{"::ffff:0:100.100.100.200", true, "metadata"},
		{"::ffff:0:169.254.1.1", true, "link_local"},
		{"::ffff:0:0.0.0.0", true, "unspecified"},
		{"::ffff:0:224.0.0.1", true, "multicast"},
		{"::ffff:0:255.255.255.255", true, "broadcast"},
		{"::ffff:0:10.96.0.1", true, "kubernetes_api"},
		{"::ffff:0:8.8.8.8", false, ""},
		{"::ffff:1:127.0.0.1", false, ""}, // outside ::ffff:0:0/96
	}
	for _, c := range cases {
		reason, denied := DeniedIP(netip.MustParseAddr(c.ip), apiServer)
		if denied != c.denied || reason != c.reason {
			t.Errorf("DeniedIP(%s) = (%q, %v), want (%q, %v)", c.ip, reason, denied, c.reason, c.denied)
		}
	}
}

func TestDeniedIPEdgeCases(t *testing.T) {
	if reason, denied := DeniedIP(netip.Addr{}, nil); !denied {
		t.Errorf("zero Addr allowed (reason %q)", reason)
	}
	// An apiServer list given in mapped form still matches the plain address.
	mapped := []netip.Addr{netip.MustParseAddr("::ffff:10.96.0.1")}
	if reason, denied := DeniedIP(netip.MustParseAddr("10.96.0.1"), mapped); !denied || reason != "kubernetes_api" {
		t.Errorf("mapped apiServer: (%q, %v)", reason, denied)
	}
	// An invalid entry in apiServer is ignored, not matched against everything.
	if _, denied := DeniedIP(netip.MustParseAddr("8.8.8.8"), []netip.Addr{{}}); denied {
		t.Error("zero apiServer entry denied 8.8.8.8")
	}
	// An empty apiServer list still denies the fixed ranges.
	if _, denied := DeniedIP(netip.MustParseAddr("127.0.0.1"), nil); !denied {
		t.Error("loopback allowed with no apiServer")
	}
}

// FuzzNormalizeMatch checks that matching never panics, that Normalize is
// idempotent, and that a host that matches a rule is always that rule's
// pattern or a name under it, by whole labels.
func FuzzNormalizeMatch(f *testing.F) {
	seeds := []struct {
		host, pattern string
		kind          uint8
	}{
		{"a.dev.wrw.com", "*.dev.wrw.com", 1},
		{"dev.wrw.com", "*.dev.wrw.com", 1},
		{"wrw.com", "wrw.com", 2},
		{"wrw.com.evil.io", "wrw.com", 2},
		{"xwrw.com", "wrw.com", 2},
		{"API.Prod.WRW.com.", "wrw.com", 2},
		{"bücher.wrw.com", "xn--bcher-kva.wrw.com", 0},
		{"0x7f.1", "1", 0},
		{"127。0。0。1", "0.1", 2},
		{"kubernetes.default.svc.cluster.local", "cluster.local", 2},
		{"[::1]:443", "*", 1},
		{"user@wrw.com", "wrw.com", 2},
		{"%2e.wrw.com", "*.wrw.com", 1},
		{"\u212Aubernetes", "kubernetes", 0},
		{"a..b", "b", 2},
	}
	for _, s := range seeds {
		f.Add(s.host, s.pattern, s.kind)
	}
	kinds := []Kind{Exact, Wildcard, Suffix, "", "bogus"}
	f.Fuzz(func(t *testing.T, host, pattern string, kind uint8) {
		n, err := Normalize(host)
		if err == nil {
			n2, err2 := Normalize(n)
			if err2 != nil || n2 != n {
				t.Fatalf("Normalize not idempotent: %q -> %q -> (%q, %v)", host, n, n2, err2)
			}
		}

		r := Rule{Pattern: pattern, Kind: kinds[int(kind)%len(kinds)]}
		l := List{Rules: []Rule{r}}
		got, ok := l.Match(host)
		all := l.MatchAll(host)
		if ok != (len(all) > 0) {
			t.Fatalf("Match ok=%v but MatchAll=%v", ok, all)
		}
		_ = l.Covers(r)
		if !ok {
			return
		}
		if err != nil {
			t.Fatalf("host %q matched but Normalize failed: %v", host, err)
		}
		v, verr := ValidateRule(got)
		if verr != nil {
			t.Fatalf("matched rule %+v does not validate: %v", got, verr)
		}
		if !l.Covers(r) {
			t.Fatalf("list does not cover its own rule %+v", r)
		}
		base := strings.TrimPrefix(v.Pattern, "*.")
		hl := strings.Split(n, ".")
		bl := strings.Split(base, ".")
		if len(hl) < len(bl) {
			t.Fatalf("host %q shorter than pattern %q", n, base)
		}
		for i := range bl {
			if hl[len(hl)-len(bl)+i] != bl[i] {
				t.Fatalf("host %q is not under pattern %q by labels", n, base)
			}
		}
		switch v.Kind {
		case Exact:
			if n != base {
				t.Fatalf("exact %q matched %q", base, n)
			}
		case Wildcard:
			if len(hl) == len(bl) {
				t.Fatalf("wildcard %q matched its own base %q", v.Pattern, n)
			}
		}
	})
}
