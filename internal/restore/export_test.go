package restore

import "testing"

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
