package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// scanAll queues a rescan of every running image in clusters the caller
// operates (Security › Scan now).
func (a *API) scanAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s := httpx.Subject(r)
	if !s.CanAny(authz.PermOperate) {
		httpx.Forbidden(w, "")
		return
	}
	ids, err := httpx.ScopedClusters(ctx, a.DB, s, authz.PermOperate)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	var n int64
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE images SET scan_status = 'pending', scan_error = ''
			WHERE scan_status <> 'scanning'
			  AND digest IN (SELECT digest FROM image_usage WHERE cluster_id = ANY($1))`, ids)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return httpx.Record(r, tx, "image.scan_all_requested", "image", "", nil, map[string]any{"images": n})
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.poke()
	httpx.JSON(w, http.StatusAccepted, map[string]any{"status": "queued", "images": n})
}

// RegistryHTTP is used by testRegistry (overridable in tests).
var RegistryHTTP = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
	return errors.New("redirects are not followed")
}}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// testRegistry checks a registry credential against the Docker Registry v2
// API (GET /v2/, following a Bearer token challenge). Nothing is pulled and
// the password is never echoed.
func (a *API) testRegistry(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	var in registryInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	defer zeroInput(&in)
	if in.HostPattern == nil {
		httpx.FieldErrors(w, "invalid registry", map[string]string{"host_pattern": "Required."})
		return
	}
	pattern, msg := ValidatePattern(*in.HostPattern)
	if msg != "" {
		httpx.FieldErrors(w, "invalid registry", map[string]string{"host_pattern": msg})
		return
	}
	host := HostOf(pattern)
	if strings.ContainsAny(host, "*?") {
		httpx.FieldErrors(w, "invalid registry", map[string]string{"host_pattern": "Test pull needs a concrete registry host, not a wildcard."})
		return
	}
	user, pass := "", []byte(nil)
	if in.Username != nil {
		user = strings.TrimSpace(*in.Username)
	}
	if in.Password != nil && in.Password.Source != "none" {
		if msg := validateSecret(in.Password, false); msg != "" {
			httpx.FieldErrors(w, "invalid registry", map[string]string{"password": msg})
			return
		}
		switch in.Password.Source {
		case "stored":
			pass = []byte(in.Password.Value)
		case "keyvault_ref":
			b, err := secrets.Resolve(r.Context(), a.Envelope.KV, in.Password.Ref)
			if err != nil {
				httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Key Vault reference could not be resolved"})
				return
			}
			pass = b
		}
	}
	defer secrets.Zero(pass)
	err := pingRegistry(r.Context(), host, user, string(pass))
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": secrets.RedactString(err.Error())})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func pingRegistry(ctx context.Context, host, user, pass string) error {
	base := "https://" + host + "/v2/"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	resp, err := RegistryHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("registry unreachable: %v", errors.Unwrap(err))
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if user != "" {
			return nil // anonymous access works; credential not exercised
		}
		return nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("registry answered %s", resp.Status)
	}
	ch := resp.Header.Get("WWW-Authenticate")
	scheme, _, _ := strings.Cut(ch, " ")
	switch strings.ToLower(scheme) {
	case "basic":
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
		req.SetBasicAuth(user, pass)
	case "bearer":
		params := map[string]string{}
		for _, m := range challengeParam.FindAllStringSubmatch(ch, -1) {
			params[m[1]] = m[2]
		}
		realm, err := url.Parse(params["realm"])
		if err != nil || realm.Scheme != "https" {
			return errors.New("registry token realm is not https")
		}
		q := realm.Query()
		if params["service"] != "" {
			q.Set("service", params["service"])
		}
		realm.RawQuery = q.Encode()
		treq, _ := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
		if user != "" {
			treq.SetBasicAuth(user, pass)
		}
		tresp, err := RegistryHTTP.Do(treq)
		if err != nil {
			return errors.New("token endpoint unreachable")
		}
		defer tresp.Body.Close()
		if tresp.StatusCode != http.StatusOK {
			return fmt.Errorf("credential rejected (%s)", tresp.Status)
		}
		var tok struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
		}
		_ = json.NewDecoder(tresp.Body).Decode(&tok)
		t := tok.Token
		if t == "" {
			t = tok.AccessToken
		}
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
		req.Header.Set("Authorization", "Bearer "+t)
	default:
		return errors.New("unsupported registry authentication")
	}
	resp, err = RegistryHTTP.Do(req)
	if err != nil {
		return errors.New("registry unreachable")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("credential rejected (%s)", resp.Status)
	}
	return nil
}
