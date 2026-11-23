package restore

import (
	"testing"

	"github.com/google/uuid"
)

// UnregisterInspectorForTest removes engine's inspector until t ends.
func UnregisterInspectorForTest(t *testing.T, engine string) {
	inspectorsMu.Lock()
	old, ok := inspectors[engine]
	delete(inspectors, engine)
	inspectorsMu.Unlock()
	t.Cleanup(func() {
		if ok {
			RegisterInspector(engine, old)
		}
	})
}

// MarkInFlightForTest puts id on x's list of restores in flight, as Execute
// does, until the returned function is called.
func MarkInFlightForTest(x *Executor, id uuid.UUID) func() {
	x.track(id)
	return func() { x.untrack(id) }
}
