package agent

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAPIProxyReadOnly(t *testing.T) {
	var gotAuth, gotImp string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotImp = r.Header.Get("Authorization"), r.Header.Get("Impersonate-User")
		_, _ = w.Write([]byte(`{"kind":"PodList"}`))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := APIProxyHandler(u, http.DefaultTransport)

	cases := []struct {
		method, path string
		hdr          map[string]string
		want         int
	}{
		{"GET", "/api/v1/pods", nil, 200},
		{"GET", "/api/v1/namespaces/default/pods?watch=1", nil, 200},
		{"GET", "/apis/apps/v1/deployments", nil, 200},
		{"POST", "/api/v1/namespaces/default/pods", nil, 403},
		{"PUT", "/api/v1/namespaces/default/pods/x", nil, 403},
		{"PATCH", "/api/v1/nodes/n1", nil, 403},
		{"DELETE", "/api/v1/namespaces/default/pods/x", nil, 403},
		{"HEAD", "/api/v1/pods", nil, 403},
		{"GET", "/api/v1/secrets", nil, 403},
		{"GET", "/api/v1/namespaces/kube-system/secrets", nil, 403},
		{"GET", "/api/v1/namespaces/kube-system/secrets/admin-token", nil, 403},
		{"GET", "//api/v1/namespaces/x/secrets", nil, 403},
		{"GET", "/api/v1/namespaces/x/pods/../secrets", nil, 403},
		{"GET", "/api/v1/namespaces/x/%73ecrets", nil, 403},
		{"GET", "/api/v1/namespaces/x/pods/p/exec?command=sh", nil, 403},
		{"GET", "/api/v1/namespaces/x/pods/p/portforward", nil, 403},
		{"GET", "/api/v1/namespaces/x/services/s/proxy/", nil, 403},
		{"GET", "/api/v1/pods", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}, 403},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "http://proxy"+c.path, nil)
		for k, v := range c.hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s %s: got %d want %d", c.method, c.path, rec.Code, c.want)
		}
	}
	req := httptest.NewRequest("GET", "http://proxy/api/v1/pods", nil)
	req.Header.Set("Authorization", "Bearer attacker")
	req.Header.Set("Impersonate-User", "system:admin")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(gotAuth, "attacker") || gotImp != "" {
		t.Fatalf("client credentials/impersonation forwarded: auth=%q imp=%q", gotAuth, gotImp)
	}
}
