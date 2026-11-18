package secrets

import "testing"

func TestRecoverableLevel(t *testing.T) {
	for level, want := range map[string]bool{
		"Recoverable":                                 true,
		"Recoverable+ProtectedSubscription":           true,
		"CustomizedRecoverable":                       true,
		"CustomizedRecoverable+ProtectedSubscription": true,
		"Recoverable+Purgeable":                       false,
		"CustomizedRecoverable+Purgeable":             false,
		"Purgeable":                                   false,
		"":                                            false,
	} {
		if got := RecoverableLevel(level); got != want {
			t.Errorf("%q: %v", level, got)
		}
	}
}
