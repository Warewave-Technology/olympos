package approvals

import "time"

// SetTimingsForTest shortens the vault lock wait and the reconciler's
// give-up age; the returned func restores them.
func SetTimingsForTest(lockWait, giveUp time.Duration) func() {
	lw, gu := vaultLockWait, applyGiveUp
	vaultLockWait, applyGiveUp = lockWait, giveUp
	return func() { vaultLockWait, applyGiveUp = lw, gu }
}
