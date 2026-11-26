package backup

import "testing"

// MaxServedObjects is the serving path's object bound (8 Mi).
func MaxServedObjects() int { return maxServedObjects }

// SetServedBoundForTest lowers the serving path's bound to objects and
// keyBytes until t ends.
func SetServedBoundForTest(t *testing.T, objects, keyBytes int) {
	o, k := maxServedObjects, maxServedKeyBytes
	maxServedObjects, maxServedKeyBytes = objects, keyBytes
	t.Cleanup(func() { maxServedObjects, maxServedKeyBytes = o, k })
}
