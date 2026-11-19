package targettls

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Security review #1: public CAs vouch for a target only when configured.
func TestTrustDefaults(t *testing.T) {
	t.Cleanup(func() { _ = Configure("", false) })
	if err := Configure("", false); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Usable(false, false), ErrNoRoots) {
		t.Fatal("nothing configured must be unusable")
	}
	if Usable(false, true) != nil || Usable(true, false) != nil {
		t.Fatal("a per-target CA or an admin-configured target is usable")
	}
	if !RootCAs().Equal(Roots(false)) || len(RootCAs().Subjects()) != 0 { //nolint:staticcheck // Subjects: empty-pool check only
		t.Fatal("cluster targets must not trust the system pool by default")
	}

	pem, err := os.ReadFile("testdata/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(f, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Configure(f, false); err != nil {
		t.Fatal(err)
	}
	if Usable(false, false) != nil || len(RootCAs().Subjects()) != 1 { //nolint:staticcheck
		t.Fatal("bundle only")
	}
	if err := Configure(f, true); err != nil {
		t.Fatal(err)
	}
	if !SystemRoots() || len(RootCAs().Subjects()) < 1 { //nolint:staticcheck
		t.Fatal("system roots when configured")
	}
}
