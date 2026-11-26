package ingest_test

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/ingest"
)

// ClickHouse signs no payload over HTTPS (the AWS SDK's
// PayloadSigningPolicy::Never sends UNSIGNED-PAYLOAD on every request), so
// the endpoint takes UNSIGNED-PAYLOAD on its TLS listener and still refuses
// it over plain HTTP (devMode only), where the signature must cover the body.

func TestVerifyUnsignedPayloadOverTLSOnly(t *testing.T) {
	unsigned := func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", ingest.UnsignedPayload) }
	r := sign(t, http.MethodPut, "/olympos/run-1/data/x.bin", "body", unsigned)
	if _, _, err := ingest.Verify(r, lookup, time.Now()); !errors.Is(err, ingest.ErrUnsignedPayload) {
		t.Fatalf("plain HTTP: %v, want ErrUnsignedPayload", err)
	}
	r.TLS = &tls.ConnectionState{}
	key, hash, err := ingest.Verify(r, lookup, time.Now())
	if err != nil || key != testKey || hash != ingest.UnsignedPayload {
		t.Fatalf("TLS: %q %q %v", key, hash, err)
	}
	// The signature still covers everything else.
	r.Header.Set("X-Amz-Meta-Run", "run-2")
	if _, _, err := ingest.Verify(r, lookup, time.Now()); !errors.Is(err, ingest.ErrSignature) {
		t.Fatalf("changed signed header over TLS: %v, want ErrSignature", err)
	}
	for _, v := range []string{"STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "unsigned-payload", ""} {
		r := sign(t, http.MethodPut, "/olympos/run-1/data/x.bin", "body", func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", v) })
		r.TLS = &tls.ConnectionState{}
		if _, _, err := ingest.Verify(r, lookup, time.Now()); !errors.Is(err, ingest.ErrUnsignedPayload) {
			t.Errorf("%q over TLS: %v, want ErrUnsignedPayload", v, err)
		}
	}
}

func TestHandlerUnsignedPayloadOverTLS(t *testing.T) {
	e := newTLSEnv(t)
	a := e.backup(t)
	unsigned := withHeader("X-Amz-Content-Sha256", ingest.UnsignedPayload)
	target := "/olympos/" + a.prefix + "data/x.bin"
	if r := e.do(t, a.cred, http.MethodPut, target, "body", unsigned); r.status != http.StatusOK {
		t.Fatalf("PUT: %s", r)
	}
	if p := a.sink.all(); len(p) != 1 || string(p[0].body) != "body" || p[0].err != nil {
		t.Fatalf("sink: %+v", p)
	}
	lock := "/olympos/" + a.prefix + ".lock"
	if r := e.do(t, a.cred, http.MethodPut, lock, "lock-id", unsigned); r.status != http.StatusOK {
		t.Fatalf("PUT .lock: %s", r)
	}
	if r := e.do(t, a.cred, http.MethodGet, lock, "", unsigned); r.status != http.StatusOK || r.body != "lock-id" {
		t.Fatalf("GET .lock: %s", r)
	}
	// A body on a request that takes none is still refused.
	wantRefused(t, e.do(t, a.cred, http.MethodDelete, lock, "x", unsigned), http.StatusForbidden, "AccessDenied")
	if r := e.do(t, a.cred, http.MethodDelete, lock, "", unsigned); r.status != http.StatusNoContent {
		t.Fatalf("DELETE .lock: %s", r)
	}
	// Content-MD5 is still checked (a mismatch stops the run).
	sum := md5.Sum([]byte("other"))
	wrongMD5 := withHeader("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	wantRefused(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/y.bin", "body", unsigned, wrongMD5),
		http.StatusBadRequest, "BadDigest")
}
