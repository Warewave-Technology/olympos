package security

import (
	"context"
	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/server"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPingRegistryBearer(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			if r.Header.Get("Authorization") == "Bearer good-token" {
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="reg"`)
			w.WriteHeader(401)
		case "/token":
			u, p, _ := r.BasicAuth()
			if u != "bot" || p != "CANARY-reg-pw" || r.URL.Query().Get("service") != "reg" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"token":"good-token"}`))
		}
	}))
	defer srv.Close()
	old := RegistryHTTP
	RegistryHTTP = srv.Client()
	defer func() { RegistryHTTP = old }()
	host := strings.TrimPrefix(srv.URL, "https://")
	if err := pingRegistry(context.Background(), host, "bot", "CANARY-reg-pw"); err != nil {
		t.Fatalf("good credential: %v", err)
	}
	err := pingRegistry(context.Background(), host, "bot", "wrong")
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("bad credential: %v", err)
	}
}

func TestScanAllWithoutImages(t *testing.T) {
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&API{DB: e.DB, Log: e.Log, Envelope: e.Envelope}}
	}})
	c := e.Login(e.Principal("op", "Member", "operator"))
	code, body := c.Raw("POST", "/api/v1/images/scan", nil)
	if code != http.StatusConflict || !strings.Contains(body, "Add a cluster") {
		t.Fatalf("scan with no images: %d %s", code, body)
	}
}
