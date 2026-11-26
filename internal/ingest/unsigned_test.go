package ingest_test

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7/pkg/signer"

	"github.com/Warewave-Technology/olympos/internal/ingest"
)

// ClickHouse signs no payload over HTTPS (the AWS SDK's
// PayloadSigningPolicy::Never sends UNSIGNED-PAYLOAD on every request), so
// the endpoint takes UNSIGNED-PAYLOAD on its TLS listener and still refuses
// it over plain HTTP (devMode only), where the signature must cover the body.
// A PutObject or UploadPart with UNSIGNED-PAYLOAD needs a signed Content-MD5,
// which ClickHouse 24.8 sends on both.

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
	if r := e.do(t, a.cred, http.MethodPut, target, "body", unsigned, md5Header("body")); r.status != http.StatusOK {
		t.Fatalf("PUT: %s", r)
	}
	if p := a.sink.all(); len(p) != 1 || string(p[0].body) != "body" || p[0].err != nil {
		t.Fatalf("sink: %+v", p)
	}
	lock := "/olympos/" + a.prefix + ".lock"
	if r := e.do(t, a.cred, http.MethodPut, lock, "lock-id", unsigned, md5Header("lock-id")); r.status != http.StatusOK {
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

	// Multipart, as ClickHouse sends it over HTTPS: parts with a signed
	// Content-MD5, a Complete without one (its part list must match the
	// parts received).
	key := a.prefix + "data/big.bin"
	rep := e.do(t, a.cred, http.MethodPost, "/olympos/"+key+"?uploads", "", unsigned)
	var up struct{ UploadId string }
	if err := xml.Unmarshal([]byte(rep.body), &up); err != nil || up.UploadId == "" {
		t.Fatalf("initiate: %s", rep)
	}
	partURL := func(n int) string { return fmt.Sprintf("/olympos/%s?partNumber=%d&uploadId=%s", key, n, up.UploadId) }
	if r := e.do(t, a.cred, http.MethodPut, partURL(1), "part-one", unsigned); r.status != http.StatusForbidden ||
		!strings.Contains(r.body, "needs a Content-MD5") {
		t.Errorf("part without Content-MD5: %s", r)
	}
	p1 := etagOf(t, e.do(t, a.cred, http.MethodPut, partURL(1), "part-one", unsigned, md5Header("part-one")))
	p2 := etagOf(t, e.do(t, a.cred, http.MethodPut, partURL(2), "part-two", unsigned, md5Header("part-two")))
	if r := e.do(t, a.cred, http.MethodPost, "/olympos/"+key+"?uploadId="+up.UploadId, completeXML(p1, p2), unsigned); r.status != http.StatusOK {
		t.Fatalf("complete: %s", r)
	}
	found := false
	for _, p := range a.sink.all() {
		found = found || p.key == key && string(p.body) == "part-onepart-two" && p.err == nil
	}
	if !found {
		t.Fatalf("multipart object not stored: %+v", a.sink.all())
	}

	// A PutObject with UNSIGNED-PAYLOAD needs a Content-MD5, and the
	// signature must cover it.
	noMD5 := e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/no-md5.bin", "body", unsigned)
	wantRefused(t, noMD5, http.StatusForbidden, "AccessDenied")
	if !strings.Contains(noMD5.body, "needs a Content-MD5") {
		t.Errorf("no Content-MD5: %s", noMD5)
	}
	req, err := http.NewRequest(http.MethodPut, e.srv.URL+"/olympos/"+a.prefix+"data/unsigned-md5.bin", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Content-Sha256", ingest.UnsignedPayload)
	signed := signer.SignV4(*req, a.cred.AccessKey, a.cred.Secret, "", testRegion)
	md5Header("body")(signed) // after signing: not a signed header
	notCovered := e.send(t, signed)
	wantRefused(t, notCovered, http.StatusForbidden, "AccessDenied")
	if !strings.Contains(notCovered.body, "needs a signed Content-MD5") {
		t.Errorf("unsigned Content-MD5: %s", notCovered)
	}
	notStopped(t, a.s)

	// Content-MD5 is still checked (a mismatch stops the run).
	wantRefused(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/y.bin", "body", unsigned, md5Header("other")),
		http.StatusBadRequest, "BadDigest")
}

// Over plain HTTP (devMode) the endpoint refuses UNSIGNED-PAYLOAD, signed
// Content-MD5 or not.
func TestHandlerUnsignedPayloadOverHTTP(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	wantRefused(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/x.bin", "body",
		withHeader("X-Amz-Content-Sha256", ingest.UnsignedPayload), md5Header("body")), http.StatusForbidden, "AccessDenied")
	if p := a.sink.all(); len(p) != 0 {
		t.Fatalf("sink got %d puts", len(p))
	}
}

// Parts that wait on disk (out of order) and parts sent again go through the
// same Content-MD5 rule with UNSIGNED-PAYLOAD over TLS.
func TestHandlerUnsignedPayloadSpilledAndRepeatedParts(t *testing.T) {
	e := newTLSEnv(t)
	unsigned := withHeader("X-Amz-Content-Sha256", ingest.UnsignedPayload)
	start := func(t *testing.T) (*run, func(n int, body string, mutate ...func(*http.Request)) reply, string, string) {
		a := e.backup(t)
		key := a.prefix + "data/big.bin"
		rep := e.do(t, a.cred, http.MethodPost, "/olympos/"+key+"?uploads", "", unsigned)
		var up struct{ UploadId string }
		if err := xml.Unmarshal([]byte(rep.body), &up); err != nil || up.UploadId == "" {
			t.Fatalf("initiate: %s", rep)
		}
		part := func(n int, body string, mutate ...func(*http.Request)) reply {
			return e.do(t, a.cred, http.MethodPut, fmt.Sprintf("/olympos/%s?partNumber=%d&uploadId=%s", key, n, up.UploadId), body,
				append([]func(*http.Request){unsigned}, mutate...)...)
		}
		return a, part, key, up.UploadId
	}

	t.Run("spilled part with a wrong MD5", func(t *testing.T) {
		a, part, _, _ := start(t)
		wantRefused(t, part(2, "part-two", md5Header("other")), http.StatusBadRequest, "BadDigest")
		if n := spillFiles(t, e.spillDir); n != 0 {
			t.Errorf("%d spill files left", n)
		}
		if p := a.sink.all(); len(p) != 0 && p[0].err == nil {
			t.Errorf("sink: %+v", p)
		}
	})
	t.Run("spilled and repeated parts with signed MD5s", func(t *testing.T) {
		a, part, key, id := start(t)
		if r := part(2, "part-two"); r.status != http.StatusForbidden || !strings.Contains(r.body, "needs a Content-MD5") {
			t.Errorf("spilled part without Content-MD5: %s", r)
		}
		p2 := etagOf(t, part(2, "part-two", md5Header("part-two"))) // waits on disk for part 1
		p1 := etagOf(t, part(1, "part-one", md5Header("part-one")))
		if r := part(1, "part-one"); r.status != http.StatusForbidden || !strings.Contains(r.body, "needs a Content-MD5") {
			t.Errorf("repeated part without Content-MD5: %s", r)
		}
		if again := etagOf(t, part(1, "part-one", md5Header("part-one"))); again != p1 {
			t.Errorf("repeated part: ETag %s, first %s", again, p1)
		}
		if r := e.do(t, a.cred, http.MethodPost, "/olympos/"+key+"?uploadId="+id, completeXML(p1, p2), unsigned); r.status != http.StatusOK {
			t.Fatalf("complete: %s", r)
		}
		found := false
		for _, p := range a.sink.all() {
			found = found || p.key == key && string(p.body) == "part-onepart-two" && p.err == nil
		}
		if !found {
			t.Fatalf("object not stored: %+v", a.sink.all())
		}
	})
	t.Run("repeated part with a wrong MD5", func(t *testing.T) {
		_, part, _, _ := start(t)
		etagOf(t, part(1, "part-one", md5Header("part-one")))
		wantRefused(t, part(1, "part-one", md5Header("other")), http.StatusBadRequest, "BadDigest")
	})
}
