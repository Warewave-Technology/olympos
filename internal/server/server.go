// Package server is the user-facing HTTP server: the REST API under /api/v1
// (BFF session auth), Entra login, the embedded SPA, and health/metrics.
package server

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Module is an API module mounted under /api/v1 behind authentication.
type Module interface {
	Routes(r chi.Router)
}

// Server wires HTTP handlers.
type Server struct {
	DB              *store.DB
	Log             *slog.Logger
	OIDC            *OIDC
	Directory       Directory
	TenantID        string
	BootstrapAdmins []string
	DevMode         bool
	InsecureCookies bool
	SPA             fs.FS // contents of web/dist
	Modules         []Module
	// Ready reports readiness for /readyz (DB reachable, gateway up, ...).
	Ready func(ctx context.Context) error
}

// Handler builds the user-facing router.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.Recoverer, securityHeaders, s.accessLog)

	r.Get("/auth/login", s.handleLogin)
	r.Get("/auth/callback", s.handleCallback)
	r.Post("/auth/logout", s.handleLogout)
	s.devRoutes(r)
	// Unknown /auth paths are 404, never the SPA.
	r.Handle("/auth/*", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { httpx.NotFound(w) }))

	r.Route("/api/v1", func(api chi.Router) {
		api.Use(s.authenticate)
		api.Get("/me", s.handleMe)
		api.Get("/grants", s.handleListGrants)
		api.Post("/grants", s.handleCreateGrant)
		api.Delete("/grants/{id}", s.handleRevokeGrant)
		api.Get("/principals/search", s.handlePrincipalSearch)
		api.Get("/activity", s.handleActivity)
		for _, m := range s.Modules {
			m.Routes(api)
		}
		api.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		})
	})
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	r.Handle("/*", s.spaHandler())
	return r
}

// OpsHandler serves /metrics, /healthz and /readyz on the metrics port.
func (s *Server) OpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if s.Ready != nil {
			if err := s.Ready(ctx); err != nil {
				http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			return
		}
		// Query strings are not logged: they can carry OIDC codes.
		s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "status", ww.Status(), "dur_ms", time.Since(start).Milliseconds())
	})
}

// spaHandler serves static assets and falls back to index.html for client
// routes.
func (s *Server) spaHandler() http.Handler {
	files := http.FileServer(http.FS(s.SPA))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" {
			if f, err := s.SPA.Open(p); err == nil {
				st, _ := f.Stat()
				f.Close()
				if st != nil && !st.IsDir() {
					if strings.HasPrefix(p, "assets/") {
						w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					}
					files.ServeHTTP(w, r)
					return
				}
			}
		}
		b, err := fs.ReadFile(s.SPA, "index.html")
		if err != nil {
			http.Error(w, "UI not built", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	})
}
