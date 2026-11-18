//go:build dev

package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
)

// devRoutes adds the dev login. Only development builds (-tags dev) contain
// it; release builds answer 404 whatever the configuration says (F6).
func (s *Server) devRoutes(r chi.Router) {
	if s.DevMode {
		r.Get("/auth/dev-login", s.handleDevLogin)
	}
}

// handleDevLogin signs in as an existing or new principal. devMode only.
func (s *Server) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.DevMode {
		httpx.NotFound(w)
		return
	}
	q := r.URL.Query()
	oid := q.Get("oid")
	if oid == "" {
		httpx.Error(w, http.StatusBadRequest, "oid required")
		return
	}
	s.completeLogin(w, r, authz.Principal{TenantID: s.TenantID, ObjectID: oid, UPN: q.Get("upn"), DisplayName: q.Get("name"),
		UserType: q.Get("user_type"), AccountEnabled: true}, q.Get("return_to"), "dev")
}
