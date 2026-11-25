package ingest

import "net/http"

// OpenUploads counts a handler's open multipart uploads.
func OpenUploads(h http.Handler) int {
	hh := h.(*handler)
	hh.mu.Lock()
	defer hh.mu.Unlock()
	return len(hh.uploads)
}

// Spilled is how many bytes of out-of-order parts a session holds on disk.
func Spilled(s *Session) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spilled
}
