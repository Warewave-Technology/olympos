package audit

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// fakeAgentProxy stands in for the agent's read-only API proxy at the other
// end of the tunnel.
func fakeAgentProxy(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	var hits atomic.Int32
	var lastAuth atomic.Value
	lastAuth.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		lastAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"NamespaceList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"default"}},{"metadata":{"name":"kube-system"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &lastAuth
}

func TestAPIProxyKubeconfigAndForwarding(t *testing.T) {
	upstream, hits, lastAuth := fakeAgentProxy(t)
	var dials atomic.Int32
	dial := func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", strings.TrimPrefix(upstream.URL, "http://"))
	}
	p, err := StartAPIProxy(context.Background(), dial, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Kubeconfig: private, points at the local listener, no credentials.
	st, err := os.Stat(p.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("kubeconfig mode %v", st.Mode().Perm())
	}
	if dst, _ := os.Stat(p.Dir()); dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", dst.Mode().Perm())
	}
	raw, _ := os.ReadFile(p.Kubeconfig)
	kc := string(raw)
	if !strings.Contains(kc, "server: http://127.0.0.1:") {
		t.Errorf("kubeconfig server: %s", kc)
	}
	for _, bad := range []string{"token", "password", "client-certificate", "client-key", "exec", "auth-provider", "username"} {
		if strings.Contains(kc, bad) {
			t.Errorf("kubeconfig contains %q:\n%s", bad, kc)
		}
	}
	cfg, err := clientcmd.LoadFromFile(p.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range cfg.AuthInfos {
		if u.Token != "" || u.TokenFile != "" || len(u.ClientCertificateData) > 0 || u.Exec != nil || u.Username != "" {
			t.Fatalf("credentials in kubeconfig: %+v", u)
		}
	}

	// A real client-go client works through it.
	rc, err := clientcmd.BuildConfigFromFlags("", p.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := kube.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ns.Items) != 2 {
		t.Fatalf("namespaces = %d", len(ns.Items))
	}
	if dials.Load() == 0 || hits.Load() == 0 {
		t.Fatal("request did not cross the tunnel")
	}

	// Credentials a tool might add are stripped; writes never leave the server.
	req, _ := http.NewRequest("GET", p.URL+"/api/v1/pods", nil)
	req.Header.Set("Authorization", "Bearer should-not-leave")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if a := lastAuth.Load().(string); a != "" {
		t.Errorf("authorization forwarded: %q", a)
	}
	before := hits.Load()
	resp, err = http.Post(p.URL+"/api/v1/namespaces/default/pods", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || hits.Load() != before {
		t.Errorf("POST: status %d, upstream hits %d→%d", resp.StatusCode, before, hits.Load())
	}

	// Close removes the kubeconfig and stops the listener.
	dir, url := p.Dir(), p.URL
	p.Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("temp dir still exists: %v", err)
	}
	if _, err := http.Get(url + "/api"); err == nil {
		t.Error("listener still accepting after Close")
	}
}

func TestAPIProxyDialFailure(t *testing.T) {
	p, err := StartAPIProxy(context.Background(), func(context.Context) (net.Conn, error) {
		return nil, io.ErrUnexpectedEOF
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	resp, err := http.Get(p.URL + "/api")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
