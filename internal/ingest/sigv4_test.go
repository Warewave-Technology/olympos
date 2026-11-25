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

// TestVerifyAWSVectors checks Verify against the four S3 "Authorization
// header, single chunk" examples of the AWS documentation (SigV4 for S3,
// examplebucket in us-east-1, 2013-05-24). They come from AWS, not from an
// SDK that shares our encoding choices. The generic SigV4 suite is not used:
// its vectors encode the path twice, which S3 does not.
func TestVerifyAWSVectors(t *testing.T) {
	const (
		awsKey    = "AKIAIOSFODNN7EXAMPLE"
		awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)
	awsNow := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	awsLookup := func(key string) (string, bool) { return awsSecret, key == awsKey }

	cases := []struct {
		name, method, target, signedHeaders, signature, wantHash string
		headers                                                  map[string]string
	}{
		{
			name: "GET Object with Range", method: http.MethodGet, target: "/test.txt",
			signedHeaders: "host;range;x-amz-content-sha256;x-amz-date",
			signature:     "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
			wantHash:      emptyHash,
			headers: map[string]string{
				"Range":                "bytes=0-9",
				"X-Amz-Content-Sha256": emptyHash,
				"X-Amz-Date":           "20130524T000000Z",
			},
		},
		{
			name: "PUT Object", method: http.MethodPut, target: "/test%24file.text",
			signedHeaders: "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
			signature:     "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
			wantHash:      "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			headers: map[string]string{
				"Date":                 "Fri, 24 May 2013 00:00:00 GMT",
				"X-Amz-Storage-Class":  "REDUCED_REDUNDANCY",
				"X-Amz-Content-Sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
				"X-Amz-Date":           "20130524T000000Z",
			},
		},
		{
			name: "GET Bucket lifecycle", method: http.MethodGet, target: "/?lifecycle",
			signedHeaders: "host;x-amz-content-sha256;x-amz-date",
			signature:     "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
			wantHash:      emptyHash,
			headers: map[string]string{
				"X-Amz-Content-Sha256": emptyHash,
				"X-Amz-Date":           "20130524T000000Z",
			},
		},
		{
			name: "GET Bucket (List Objects)", method: http.MethodGet, target: "/?max-keys=2&prefix=J",
			signedHeaders: "host;x-amz-content-sha256;x-amz-date",
			signature:     "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
			wantHash:      emptyHash,
			headers: map[string]string{
				"X-Amz-Content-Sha256": emptyHash,
				"X-Amz-Date":           "20130524T000000Z",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, nil)
			r.Host = "examplebucket.s3.amazonaws.com"
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+awsKey+"/20130524/us-east-1/s3/aws4_request,"+
				"SignedHeaders="+tc.signedHeaders+",Signature="+tc.signature)

			key, hash, err := ingest.Verify(r, awsLookup, awsNow)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if key != awsKey || hash != tc.wantHash {
				t.Errorf("Verify = %q, %q; want %q, %q", key, hash, awsKey, tc.wantHash)
			}

			// The same request with the last signature digit changed must fail.
			flipped := tc.signature[:len(tc.signature)-1] + "0"
			if flipped == tc.signature {
				flipped = tc.signature[:len(tc.signature)-1] + "1"
			}
			bad := r.Clone(r.Context())
			bad.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), tc.signature, flipped, 1))
			if _, _, err := ingest.Verify(bad, awsLookup, awsNow); !errors.Is(err, ingest.ErrSignature) {
				t.Errorf("tampered signature: error = %v, want ErrSignature", err)
			}
		})
	}
}
