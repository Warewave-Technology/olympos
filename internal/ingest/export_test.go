package ingest

import "net/http"

// SetSpill sets where a handler holds out-of-order parts, and its per-run
// byte limit.
func SetSpill(h http.Handler, dir string, limit int64) {
	hh := h.(*handler)
	hh.mu.Lock()
	defer hh.mu.Unlock()
	hh.spillDir, hh.spillLimit = dir, limit
}
