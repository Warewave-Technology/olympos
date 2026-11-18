package vclient

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func sealHandler(hits *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if r.URL.Path != "/v1/sys/seal-status" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Vault-Token") != "" {
			http.Error(w, "unexpected token", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"shamir","initialized":true,"sealed":false,"version":"1.18.5","storage_type":"raft"}`))
	})
}

func dialTo(addr string, dials *int32) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		atomic.AddInt32(dials, 1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func TestEndToEndTLSVerifiesServerNameAndBundle(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "hvs.environmentTokenMustBeIgnored000")
	var hits, dials int32
	srv := httptest.NewTLSServer(sealHandler(&hits))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	// httptest's certificate is issued for example.com.
	c, err := New(Options{Dial: dialTo(addr, &dials), TLS: true, ServerName: "example.com", CABundle: bundle})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Token() != "" {
		t.Fatal("VAULT_TOKEN from the environment must be ignored")
	}
	h, err := SealStatus(context.Background(), c)
	if err != nil {
		t.Fatalf("seal status over e2e TLS: %v", err)
	}
	if h.Version != "1.18.5" || h.Sealed || h.StorageType != "raft" {
		t.Fatalf("health: %+v", h)
	}
	if dials == 0 {
		t.Fatal("custom dialer not used")
	}

	// Wrong server name: refused (no InsecureSkipVerify anywhere).
	c2, _ := New(Options{Dial: dialTo(addr, &dials), TLS: true, ServerName: "vault.vault.svc", CABundle: bundle})
	defer c2.Close()
	if _, err := SealStatus(context.Background(), c2); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("wrong server name must fail TLS verification, got %v", err)
	}
	// Untrusted CA: refused.
	c3, _ := New(Options{Dial: dialTo(addr, &dials), TLS: true, ServerName: "example.com"})
	defer c3.Close()
	if _, err := SealStatus(context.Background(), c3); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("untrusted certificate must fail, got %v", err)
	}
	if _, err := New(Options{Dial: dialTo(addr, &dials), TLS: true, ServerName: "x", CABundle: []byte("not pem")}); err == nil {
		t.Fatal("invalid CA bundle must be rejected")
	}
}

func TestCompressedModeIsPlainHTTP(t *testing.T) {
	var hits, dials int32
	srv := httptest.NewServer(sealHandler(&hits))
	defer srv.Close()
	c, err := New(Options{Dial: dialTo(srv.Listener.Addr().String(), &dials), TLS: false, ServerName: "vault.vault.svc"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := SealStatus(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Address(), "http://vault.vault.svc") {
		t.Fatalf("address %s", c.Address())
	}
}

func TestSanitizeDropsRequestDetails(t *testing.T) {
	var dials int32
	c, _ := New(Options{Dial: dialTo("127.0.0.1:1", &dials), TLS: false, ServerName: "vault.vault.svc"})
	defer c.Close()
	c.SetToken("hvs.CAAAAAAAAAAAAAAAAAAAAAAAsecretTokenValue")
	_, err := c.Logical().ReadWithContext(context.Background(), "secret/metadata/x")
	if err == nil {
		t.Fatal("expected error")
	}
	s := Sanitize(err).Error()
	if strings.Contains(s, "secretTokenValue") || strings.Contains(s, "http://") {
		t.Fatalf("sanitized error leaks request details: %s", s)
	}
}
