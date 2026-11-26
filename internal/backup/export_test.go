package backup

import (
	"testing"
	"time"
)

// MaxServedObjects is the serving path's object bound (8 Mi).
func MaxServedObjects() int { return maxServedObjects }

// SetServedBoundForTest lowers the serving path's bound to objects and
// keyBytes until t ends.
func SetServedBoundForTest(t *testing.T, objects, keyBytes int) {
	o, k := maxServedObjects, maxServedKeyBytes
	maxServedObjects, maxServedKeyBytes = objects, keyBytes
	t.Cleanup(func() { maxServedObjects, maxServedKeyBytes = o, k })
}

// SetNativeCheckTimeoutForTest sets how long a native check may take until t
// ends.
func SetNativeCheckTimeoutForTest(t *testing.T, d time.Duration) {
	old := nativeCheckTimeout
	nativeCheckTimeout = d
	t.Cleanup(func() { nativeCheckTimeout = old })
}
