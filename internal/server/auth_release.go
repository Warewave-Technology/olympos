//go:build !dev

package server

import "github.com/go-chi/chi/v5"

// devRoutes is empty in release builds: there is no dev login (F6).
func (s *Server) devRoutes(chi.Router) {}
