package destinations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/destinations"
)

func TestParseSAS(t *testing.T) {
	exp := time.Date(2027, 1, 31, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		token     string
		wantErr   string
		perms     string
		missing   string
		extra     string
		scope     string
		canDelete bool
		userDeleg bool
		exp       *time.Time
		note      string
	}{
		{name: "container rcwt", token: "sv=2022-11-02&sr=c&sp=rcwt&se=2027-01-31T12:00:00Z&sig=abc%2B",
			perms: "rcwt", scope: "container", exp: &exp, note: "shared key"},
		{name: "leading question mark", token: "?sv=2022-11-02&sr=c&sp=rcwt&se=2027-01-31T12:00:00Z&sig=abc",
			perms: "rcwt", scope: "container", exp: &exp},
		{name: "full URL", token: "https://acct.blob.core.windows.net/backups?sv=2022-11-02&sr=c&sp=racwt&se=2027-01-31T12:00Z&sig=abc",
			perms: "racwt", extra: "a", scope: "container", exp: &exp},
		{name: "with delete and list", token: "sr=c&sp=rcwdlt&se=2027-01-31&sig=abc",
			perms: "rcwdlt", extra: "d,l", scope: "container", canDelete: true, exp: ptr(time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC))},
		{name: "missing c and t", token: "sr=c&sp=rw&se=2027-01-31T12:00:00Z&sig=abc",
			perms: "rw", missing: "c,t", scope: "container", exp: &exp},
		{name: "account SAS", token: "sv=2022-11-02&ss=b&srt=sco&sp=rwdlacupitfx&se=2027-01-31T12:00:00Z&spr=https&sig=abc",
			perms: "rwdlacupitfx", extra: "d,l,a,u,p,i,f,x", scope: "account", canDelete: true, exp: &exp, note: "account SAS"},
		{name: "account SAS without blob service", token: "ss=q&srt=o&sp=rcwt&se=2027-01-31T12:00:00Z&sig=abc",
			perms: "rcwt", scope: "account", exp: &exp, note: "lacks b"},
		{name: "user delegation", token: "sr=c&sp=rcwt&se=2027-01-31T12:00:00Z&skoid=1111&sktid=2222&skt=x&ske=y&sks=b&skv=z&sig=abc",
			perms: "rcwt", scope: "container", userDeleg: true, exp: &exp},
		{name: "blob scoped", token: "sr=b&sp=rcwt&se=2027-01-31T12:00:00Z&sig=abc", perms: "rcwt", scope: "service", exp: &exp, note: "sr=c"},
		{name: "no scope fields", token: "sp=rcwt&se=2027-01-31T12:00:00Z&sig=abc", perms: "rcwt", scope: "unknown", exp: &exp},
		{name: "permanent delete", token: "ss=b&srt=o&sp=rcwty&se=2027-01-31T12:00:00Z&sig=abc", perms: "rcwty", extra: "y", scope: "account", canDelete: true, exp: &exp},
		{name: "stored access policy", token: "sr=c&si=olympos-policy&sig=abc", scope: "container", note: "stored access policy"},
		{name: "no signature", token: "sr=c&sp=rcwt&se=2027-01-31", wantErr: "no signature"},
		{name: "no permissions", token: "sr=c&se=2027-01-31&sig=abc", wantErr: "no permissions"},
		{name: "no expiry", token: "sr=c&sp=rcwt&sig=abc", wantErr: "no expiry"},
		{name: "bad expiry", token: "sr=c&sp=rcwt&se=tomorrow&sig=abc", wantErr: "invalid expiry"},
		{name: "empty", token: "  ", wantErr: "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info, err := destinations.ParseSAS(c.token)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				if err != nil && strings.Contains(err.Error(), "abc") {
					t.Fatal("error leaks the signature")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.Permissions != c.perms || strings.Join(info.Missing, ",") != c.missing || strings.Join(info.Extra, ",") != c.extra ||
				info.Scope != c.scope || info.CanDelete() != c.canDelete || info.UserDelegation != c.userDeleg {
				t.Fatalf("got %+v", info)
			}
			if (c.exp == nil) != (info.ExpiresAt == nil) || (c.exp != nil && !c.exp.Equal(*info.ExpiresAt)) {
				t.Fatalf("expiry %v, want %v", info.ExpiresAt, c.exp)
			}
			if c.note != "" && !strings.Contains(strings.Join(info.Notes, " | "), c.note) {
				t.Fatalf("notes %q lack %q", info.Notes, c.note)
			}
			if !info.Expired(exp.Add(time.Hour)) && info.ExpiresAt != nil {
				t.Fatal("must be expired after se")
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }
