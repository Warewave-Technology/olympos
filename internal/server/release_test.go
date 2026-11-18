//go:build !dev

package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// F6: a release build has no dev login, whatever the configuration says.
// Run without -tags dev: go test ./internal/server -run Release
func TestReleaseHasNoDevLogin(t *testing.T) {
	s := &Server{DevMode: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		SPA: fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}}
	h := s.Handler()
	for _, p := range []string{"/auth/dev-login", "/auth/dev-login?oid=x", "/auth/anything"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
}
