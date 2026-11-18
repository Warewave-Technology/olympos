package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Session lifetimes (SPEC §3.1).
const (
	SessionAbsolute = 8 * time.Hour
	SessionIdle     = 30 * time.Minute
	loginStateTTL   = 10 * time.Minute

	sessionCookie = "olympos_session"
	csrfCookie    = "olympos_csrf"
	csrfHeader    = "X-CSRF-Token"
)

// OIDC handles Entra ID login with Authorization Code + PKCE (BFF).
type OIDC struct {
	TenantID        string
	ClientID        string
	ClientSecretRef string
	AuthorityHost   string // https://login.microsoftonline.com
	RedirectURL     string
	KV              secrets.KeyVault
	// ClientSecret is used only when ClientSecretRef is empty (tests).
	ClientSecret string

	once     sync.Once
	provider *oidc.Provider
	initErr  error
}

// Issuer is the only accepted issuer: authority/<tenantID>/v2.0.
func (o *OIDC) Issuer() string {
	return strings.TrimRight(o.AuthorityHost, "/") + "/" + o.TenantID + "/v2.0"
}

func (o *OIDC) init(ctx context.Context) (*oidc.Provider, error) {
	o.once.Do(func() {
		o.provider, o.initErr = oidc.NewProvider(ctx, o.Issuer())
	})
	if o.initErr != nil {
		// Allow a retry on the next login after transient failures.
		err := o.initErr
		o.once = sync.Once{}
		return nil, err
	}
	return o.provider, nil
}

func (o *OIDC) oauthConfig(p *oidc.Provider, secret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: o.ClientID, ClientSecret: secret, Endpoint: p.Endpoint(), RedirectURL: o.RedirectURL,
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

func (o *OIDC) clientSecret(ctx context.Context) (string, error) {
	if o.ClientSecretRef == "" {
		return o.ClientSecret, nil
	}
	b, err := secrets.Resolve(ctx, o.KV, o.ClientSecretRef)
	if err != nil {
		return "", fmt.Errorf("resolve oidc client secret: %w", err)
	}
	defer secrets.Zero(b)
	return string(b), nil
}

// Claims are the ID token claims Olympos uses.
type Claims struct {
	Issuer            string `json:"iss"`
	TenantID          string `json:"tid"`
	ObjectID          string `json:"oid"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Nonce             string `json:"nonce"`
	NotBefore         *int64 `json:"nbf"`
}

// ErrForeignTenant is returned when tid/iss do not match the configured tenant.
var ErrForeignTenant = errors.New("token is from a different tenant")

// VerifyIDToken checks signature (JWKS), iss, aud, exp, nbf, tid and nonce.
func (o *OIDC) VerifyIDToken(ctx context.Context, raw, nonce string) (*Claims, error) {
	p, err := o.init(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := p.Verifier(&oidc.Config{ClientID: o.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}
	var c Claims
	if err := tok.Claims(&c); err != nil {
		return nil, err
	}
	if c.Issuer != o.Issuer() || !strings.EqualFold(c.TenantID, o.TenantID) {
		return nil, ErrForeignTenant
	}
	if c.NotBefore != nil && time.Now().Add(time.Minute).Before(time.Unix(*c.NotBefore, 0)) {
		return nil, errors.New("token not yet valid")
	}
	if c.ObjectID == "" {
		return nil, errors.New("token has no oid claim")
	}
	if nonce != "" && subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("nonce mismatch")
	}
	return &c, nil
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashSession(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

// safeReturnTo only allows same-origin relative paths.
func safeReturnTo(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.Contains(s, "\\") {
		return "/"
	}
	if u, err := url.Parse(s); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return s
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		http.Redirect(w, r, "/login?error=sso_not_configured", http.StatusFound)
		return
	}
	p, err := s.OIDC.init(r.Context())
	if err != nil {
		s.Log.Error("oidc discovery", "err", err)
		http.Redirect(w, r, "/login?error=idp_unavailable", http.StatusFound)
		return
	}
	state, nonce, verifier := randToken(24), randToken(24), oauth2.GenerateVerifier()
	if _, err := s.DB.Exec(r.Context(), `INSERT INTO login_states (state, nonce, code_verifier, return_to) VALUES ($1,$2,$3,$4)`,
		state, nonce, verifier, safeReturnTo(r.URL.Query().Get("return_to"))); err != nil {
		httpx.Internal(w, r, s.Log, err)
		return
	}
	cfg := s.OIDC.oauthConfig(p, "")
	http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.Log.Warn("login error from idp", "error", e)
		http.Redirect(w, r, "/login?error=idp_error", http.StatusFound)
		return
	}
	var nonce, verifier, returnTo string
	var created time.Time
	err := s.DB.QueryRow(ctx, `DELETE FROM login_states WHERE state = $1 RETURNING nonce, code_verifier, return_to, created_at`,
		q.Get("state")).Scan(&nonce, &verifier, &returnTo, &created)
	if err != nil || time.Since(created) > loginStateTTL {
		http.Redirect(w, r, "/login?error=state", http.StatusFound)
		return
	}
	p, err := s.OIDC.init(ctx)
	if err != nil {
		http.Redirect(w, r, "/login?error=idp_unavailable", http.StatusFound)
		return
	}
	secret, err := s.OIDC.clientSecret(ctx)
	if err != nil {
		s.Log.Error("login", "err", err)
		http.Redirect(w, r, "/login?error=server", http.StatusFound)
		return
	}
	tok, err := s.OIDC.oauthConfig(p, secret).Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	secret = ""
	if err != nil {
		s.Log.Warn("code exchange failed", "err", err)
		http.Redirect(w, r, "/login?error=exchange", http.StatusFound)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	claims, err := s.OIDC.VerifyIDToken(ctx, raw, nonce)
	if err != nil {
		s.Log.Warn("id token rejected", "err", err)
		_ = activity.Record(ctx, s.DB, activity.Entry{Action: "login.rejected", ObjectType: "session", Details: map[string]any{"reason": err.Error()}})
		http.Redirect(w, r, "/login?error=token", http.StatusFound)
		return
	}
	s.completeLogin(w, r, authz.Principal{
		TenantID: claims.TenantID, ObjectID: claims.ObjectID, UPN: claims.PreferredUsername,
		DisplayName: claims.Name, AccountEnabled: true,
	}, returnTo, "entra")
}

// completeLogin upserts the principal and starts a session if it has grants.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, p authz.Principal, returnTo, method string) {
	ctx := r.Context()
	if _, err := authz.BootstrapAdmins(ctx, s.DB, s.TenantID, s.BootstrapAdmins); err != nil {
		s.Log.Error("bootstrap admins", "err", err)
	}
	var cookie, csrf string
	var denied bool
	err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		pr, err := authz.UpsertPrincipal(ctx, tx, p)
		if err != nil {
			return err
		}
		subj, err := authz.LoadSubject(ctx, tx, pr.ID)
		if err != nil {
			return err
		}
		id := pr.ID
		if !subj.CanAny(authz.PermRead) {
			denied = true
			return activity.Record(ctx, tx, activity.Entry{ActorID: &id, Action: "login.denied", ObjectType: "session",
				Details: map[string]any{"reason": "no active grants", "method": method}})
		}
		cookie, csrf = randToken(32), randToken(24)
		if _, err := tx.Exec(ctx, `INSERT INTO sessions (id, principal_id, expires_at, csrf_token) VALUES ($1, $2, $3, $4)`,
			hashSession(cookie), pr.ID, time.Now().Add(SessionAbsolute), csrf); err != nil {
			return err
		}
		return activity.Record(ctx, tx, activity.Entry{ActorID: &id, Action: "login.succeeded", ObjectType: "session",
			Details: map[string]any{"method": method, "ip": clientIP(r)}})
	})
	if err != nil {
		httpx.Internal(w, r, s.Log, err)
		return
	}
	if denied {
		http.Redirect(w, r, "/login?error=no_access", http.StatusFound)
		return
	}
	s.setCookies(w, cookie, csrf)
	http.Redirect(w, r, safeReturnTo(returnTo), http.StatusFound)
}

func (s *Server) setCookies(w http.ResponseWriter, session, csrf string) {
	secure := !s.InsecureCookies
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: session, Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(SessionAbsolute.Seconds())})
	// Readable by the SPA so it can echo it in X-CSRF-Token.
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/", HttpOnly: false, Secure: secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(SessionAbsolute.Seconds())})
}

func (s *Server) clearCookies(w http.ResponseWriter) {
	for _, n := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{Name: n, Value: "", Path: "/", MaxAge: -1, HttpOnly: n == sessionCookie,
			Secure: !s.InsecureCookies, SameSite: http.SameSiteStrictMode})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		var pid uuid.UUID
		if err := s.DB.QueryRow(r.Context(), `DELETE FROM sessions WHERE id = $1 RETURNING principal_id`, hashSession(c.Value)).Scan(&pid); err == nil {
			_ = activity.Record(r.Context(), s.DB, activity.Entry{ActorID: &pid, Action: "logout", ObjectType: "session"})
		}
	}
	s.clearCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

// authenticate is the session + CSRF middleware for /api/v1.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			httpx.Error(w, http.StatusUnauthorized, "not signed in")
			return
		}
		ctx := r.Context()
		var pid uuid.UUID
		var csrf string
		// Idle and absolute expiry are both enforced in SQL; last_seen_at slides.
		err = s.DB.QueryRow(ctx, `UPDATE sessions SET last_seen_at = now()
			WHERE id = $1 AND expires_at > now() AND last_seen_at > now() - $2::interval
			RETURNING principal_id, csrf_token`, hashSession(c.Value), fmt.Sprintf("%d seconds", int(SessionIdle.Seconds()))).Scan(&pid, &csrf)
		if err != nil {
			s.clearCookies(w)
			httpx.Error(w, http.StatusUnauthorized, "session expired")
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(csrf)) != 1 {
				httpx.Error(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
		}
		subj, err := authz.LoadSubject(ctx, s.DB, pid)
		if err != nil {
			httpx.Internal(w, r, s.Log, err)
			return
		}
		if !subj.CanAny(authz.PermRead) {
			httpx.Error(w, http.StatusForbidden, "your access to Olympos was revoked")
			return
		}
		next.ServeHTTP(w, r.WithContext(httpx.WithSubject(ctx, subj)))
	})
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	h := r.RemoteAddr
	if i := strings.LastIndexByte(h, ':'); i > 0 {
		h = h[:i]
	}
	return h
}

// CleanupSessions removes expired sessions and login states.
func (s *Server) CleanupSessions(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		_, _ = s.DB.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now() OR last_seen_at < now() - interval '1 day'`)
		_, _ = s.DB.Exec(ctx, `DELETE FROM login_states WHERE created_at < now() - interval '1 hour'`)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
