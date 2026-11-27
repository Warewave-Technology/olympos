package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// The SPA: a built asset is served as itself, a client route gets
// index.html, and an asset that is not in the build is a 404, not
// index.html. Found on the first VM install of v0.4.0: the packages
// embedded an index.html whose assets were missing, and the browser only
// said that the JavaScript came back as text/html.
func TestSPAHandler(t *testing.T) {
	s := &Server{SPA: fstest.MapFS{
		"index.html":          {Data: []byte(`<script type="module" src="/assets/index-abc.js"></script>`)},
		"assets/index-abc.js": {Data: []byte("console.log(1)")},
	}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h := s.spaHandler()
	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec
	}
	if rec := get("/assets/index-abc.js"); rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Errorf("built asset: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, p := range []string{"/", "/backups", "/clusters/abc"} {
		if rec := get(p); rec.Code != 200 || !strings.Contains(rec.Body.String(), "index-abc.js") {
			t.Errorf("client route %s: %d %s", p, rec.Code, rec.Body)
		}
	}
	for _, p := range []string{"/assets/index-missing.js", "/assets/index-missing.css", "/assets/sub/x.svg"} {
		if rec := get(p); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "index-abc.js") {
			t.Errorf("missing asset %s: %d %q", p, rec.Code, rec.Body)
		}
	}
}
