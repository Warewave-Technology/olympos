package agent

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// FuzzAPIProxy (F11): whatever the path, method and headers, the API proxy
// never forwards a non-GET, an upgrade, an exec/attach/portforward/proxy
// subresource or any Secret path, as the API server would read the path
// (decoded once; also checked decoded twice).
//
//	go test ./internal/agent -run '^$' -fuzz FuzzAPIProxy -fuzztime 60s
func FuzzAPIProxy(f *testing.F) {
	for _, s := range []string{
		"/api/v1/pods", "/api/v1/secrets", "/api/v1/namespaces/x/secrets/s", "//api/v1/namespaces/x/secrets",
		"/api/v1/namespaces/x/pods/../secrets", "/api/v1/namespaces/x/%73ecrets", "/api/v1/namespaces/x/%2573ecrets",
		"/api/v1/watch/namespaces/x/secrets", "/api/v1/namespaces/x/Secrets", "/api/v1/./namespaces/x/secrets/",
		"/api/v1/namespaces/x/secrets.", "/apis/example.io/v1/secrets", "/api/v1/namespaces/x/pods/p/exec",
		"/api/v1/nodes/n/proxy/x", "/api/v1/namespaces/x/pods/p/%61ttach", "/api/v1/namespaces/x/%2e%2e/secrets",
		"/api/v1/namespaces/x/pods?watch=1", "/api/v1/namespaces/x/configmaps",
	} {
		f.Add("GET", s, "", "")
	}
	f.Add("POST", "/api/v1/namespaces/x/pods", "", "")
	f.Add("GET", "/api/v1/pods", "Upgrade", "websocket")
	f.Add("GET", "/api/v1/pods", "Connection", "upgrade")
	f.Add("GET", "/api/v1/pods", "X-HTTP-Method-Override", "DELETE")
	f.Add("GET", "/api/v1/pods", "Accept", "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1")

	var mu sync.Mutex
	var seen []*http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Clone(r.Context()))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	f.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	h := APIProxyHandler(u, http.DefaultTransport)

	f.Fuzz(func(t *testing.T, method, rawPath, hk, hv string) {
		if !strings.HasPrefix(rawPath, "/") {
			rawPath = "/" + rawPath
		}
		req, err := http.NewRequest(method, "http://proxy"+rawPath, nil)
		if err != nil || req.URL.Host != "proxy" {
			return
		}
		if hk != "" && validHeader(hk) && validHeaderValue(hv) {
			req.Header.Set(hk, hv)
		}
		mu.Lock()
		seen = seen[:0]
		mu.Unlock()
		h.ServeHTTP(httptest.NewRecorder(), req)
		mu.Lock()
		defer mu.Unlock()
		for _, r := range seen {
			if r.Method != http.MethodGet {
				t.Fatalf("forwarded %s %s", r.Method, rawPath)
			}
			if r.Header.Get("Upgrade") != "" {
				t.Fatalf("forwarded an upgrade: %s", rawPath)
			}
			// What the API server routes on: the path decoded once.
			once := path(r.URL)
			for _, p := range []string{once, twiceDecoded(once)} {
				if secretPath.MatchString(p) {
					t.Fatalf("forwarded a Secret path: %q (seen %q)", rawPath, p)
				}
				if forbiddenSub.MatchString(strings.ToLower(p)) {
					t.Fatalf("forwarded a forbidden subresource: %q (seen %q)", rawPath, p)
				}
			}
		}
	})
}

func validHeader(k string) bool {
	for _, c := range k {
		if c <= ' ' || c >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", c) {
			return false
		}
	}
	return k != ""
}

func validHeaderValue(v string) bool {
	for _, c := range v {
		if c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}
