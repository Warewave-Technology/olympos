package ingest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7/pkg/signer"

	"github.com/Warewave-Technology/olympos/internal/ingest"
)

const (
	testKey    = "OLYTESTACCESSKEY0001"
	testSecret = "0123456789abcdef0123456789abcdef01234567"
	testRegion = "us-east-1"
	testHost   = "olympos-ingest.example.test:9444"
)

func lookup(key string) (string, bool) {
	if key == testKey {
		return testSecret, true
	}
	return "", false
}

func hexSHA256(b string) string {
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])
}

// sign signs a request the way ClickHouse does (path style, the real body
// hash in x-amz-content-sha256) and returns it as a server would receive it:
// an origin-form URL, with the host in r.Host.
func sign(t *testing.T, method, target, body string, mutate ...func(*http.Request)) *http.Request {
	t.Helper()
	client, err := http.NewRequest(method, "https://"+testHost+target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	client.Header.Set("X-Amz-Content-Sha256", hexSHA256(body))
	client.Header.Set("X-Amz-Meta-Run", "run-1")
	for _, m := range mutate {
		m(client)
	}
	signed := signer.SignV4(*client, testKey, testSecret, "", testRegion)

	server := httptest.NewRequest(method, target, nil)
	server.Host = testHost
	server.Header = signed.Header.Clone()
	return server
}

func TestVerifySignedBySDK(t *testing.T) {
	cases := []struct {
		name, method, target, body string
	}{
		{"get", http.MethodGet, "/olympos/run-1/metadata.json", ""},
		{"put", http.MethodPut, "/olympos/run-1/data/part_1.bin", "some backup bytes"},
		{"initiate multipart", http.MethodPost, "/olympos/run-1/data/big.bin?uploads", ""},
		{"upload part", http.MethodPut, "/olympos/run-1/data/big.bin?partNumber=2&uploadId=abc%2Fdef%3D", "part"},
		{"delete", http.MethodDelete, "/olympos/run-1/.lock", ""},
		{"list", http.MethodGet, "/olympos?list-type=2&prefix=run-1%2Fdata%2F&max-keys=100&marker=run-1%2Fa+b", ""},
		{"list v1", http.MethodGet, "/olympos/?prefix=run-1/&max-keys=1000&marker=", ""},
		{"special characters", http.MethodPut, "/olympos/run-1/a%20b+c=d/%C3%BC~x_y-z.bin", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := sign(t, tc.method, tc.target, tc.body)
			key, hash, err := ingest.Verify(r, lookup, time.Now())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if key != testKey {
				t.Errorf("access key = %q, want %q", key, testKey)
			}
			if want := hexSHA256(tc.body); hash != want {
				t.Errorf("payload hash = %q, want %q", hash, want)
			}
		})
	}
}

func TestVerifyRefuses(t *testing.T) {
	const target = "/olympos/run-1/data/part_1.bin?partNumber=1&uploadId=abc"
	cases := []struct {
		name string
		req  func(t *testing.T) *http.Request
		now  time.Time
		want error
	}{
		{"changed signed header", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodPut, target, "body")
			r.Header.Set("X-Amz-Meta-Run", "run-2")
			return r
		}, time.Now(), ingest.ErrSignature},
		{"changed query", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodPut, target, "body")
			r.URL.RawQuery = "partNumber=2&uploadId=abc"
			return r
		}, time.Now(), ingest.ErrSignature},
		{"changed path", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodPut, target, "body")
			r.URL.Path = "/olympos/run-2/data/part_1.bin"
			return r
		}, time.Now(), ingest.ErrSignature},
		{"changed method", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodPut, target, "body")
			r.Method = http.MethodDelete
			return r
		}, time.Now(), ingest.ErrSignature},
		{"changed payload hash", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodPut, target, "body")
			r.Header.Set("X-Amz-Content-Sha256", hexSHA256("other"))
			return r
		}, time.Now(), ingest.ErrSignature},
		{"changed secret", func(t *testing.T) *http.Request {
			client, _ := http.NewRequest(http.MethodGet, "https://"+testHost+"/olympos/x", nil)
			client.Header.Set("X-Amz-Content-Sha256", hexSHA256(""))
			signed := signer.SignV4(*client, testKey, "wrong-secret", "", testRegion)
			r := httptest.NewRequest(http.MethodGet, "/olympos/x", nil)
			r.Host = testHost
			r.Header = signed.Header.Clone()
			return r
		}, time.Now(), ingest.ErrSignature},
		{"unknown key", func(t *testing.T) *http.Request {
			client, _ := http.NewRequest(http.MethodGet, "https://"+testHost+"/olympos/x", nil)
			client.Header.Set("X-Amz-Content-Sha256", hexSHA256(""))
			signed := signer.SignV4(*client, "OLYOTHERKEY", testSecret, "", testRegion)
			r := httptest.NewRequest(http.MethodGet, "/olympos/x", nil)
			r.Host = testHost
			r.Header = signed.Header.Clone()
			return r
		}, time.Now(), ingest.ErrUnknownKey},
		{"clock ahead", func(t *testing.T) *http.Request {
			return sign(t, http.MethodGet, "/olympos/x", "")
		}, time.Now().Add(16 * time.Minute), ingest.ErrClockSkew},
		{"clock behind", func(t *testing.T) *http.Request {
			return sign(t, http.MethodGet, "/olympos/x", "")
		}, time.Now().Add(-16 * time.Minute), ingest.ErrClockSkew},
		{"unsigned payload", func(t *testing.T) *http.Request {
			return sign(t, http.MethodPut, "/olympos/x", "body", func(r *http.Request) {
				r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
			})
		}, time.Now(), ingest.ErrUnsignedPayload},
		{"streaming payload", func(t *testing.T) *http.Request {
			return sign(t, http.MethodPut, "/olympos/x", "body", func(r *http.Request) {
				r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
			})
		}, time.Now(), ingest.ErrUnsignedPayload},
		{"streaming trailer payload", func(t *testing.T) *http.Request {
			return sign(t, http.MethodPut, "/olympos/x", "body", func(r *http.Request) {
				r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
			})
		}, time.Now(), ingest.ErrUnsignedPayload},
		{"payload hash header missing", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodGet, "/olympos/x", "")
			r.Header.Del("X-Amz-Content-Sha256")
			return r
		}, time.Now(), ingest.ErrUnsignedPayload},
		{"no authorization", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodGet, "/olympos/x", "")
			r.Header.Del("Authorization")
			return r
		}, time.Now(), ingest.ErrNoSigV4},
		{"other scheme", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodGet, "/olympos/x", "")
			r.Header.Set("Authorization", "Bearer abc")
			return r
		}, time.Now(), ingest.ErrNoSigV4},
		{"presigned query string", func(t *testing.T) *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/olympos/x?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential="+
				testKey+"%2F20261125%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261125T100000Z&X-Amz-Expires=600"+
				"&X-Amz-SignedHeaders=host&X-Amz-Signature="+strings.Repeat("0", 64), nil)
			r.Host = testHost
			return r
		}, time.Now(), ingest.ErrNoSigV4},
		{"malformed authorization", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodGet, "/olympos/x", "")
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=nope")
			return r
		}, time.Now(), ingest.ErrSignature},
		{"host not signed", func(t *testing.T) *http.Request {
			r := sign(t, http.MethodGet, "/olympos/x", "")
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "host;", "", 1))
			return r
		}, time.Now(), ingest.ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, hash, err := ingest.Verify(tc.req(t), lookup, tc.now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify error = %v, want %v", err, tc.want)
			}
			if key != "" || hash != "" {
				t.Errorf("Verify returned key %q and hash %q with an error", key, hash)
			}
		})
	}
}

func TestVerifyClockSkewEdge(t *testing.T) {
	r := sign(t, http.MethodGet, "/olympos/x", "")
	if _, _, err := ingest.Verify(r, lookup, time.Now().Add(14*time.Minute)); err != nil {
		t.Fatalf("14 minutes of skew: %v", err)
	}
}

func TestVerifyHostHeader(t *testing.T) {
	r := sign(t, http.MethodGet, "/olympos/x", "")
	r.Host = "evil.example.test"
	if _, _, err := ingest.Verify(r, lookup, time.Now()); !errors.Is(err, ingest.ErrSignature) {
		t.Fatalf("Verify error = %v, want ErrSignature", err)
	}
}
