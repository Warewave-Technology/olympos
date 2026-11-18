//go:build e2e

// Package e2e runs against the kind lab created by test/e2e/run.sh.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

const devAdminOID = "00000000-0000-0000-0000-00000000ad01"

func root() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..")
}

func work() string { return filepath.Join(root(), "test", "e2e", ".work") }

func kubeconfig(t *testing.T) string {
	t.Helper()
	k := os.Getenv("OLYMPOS_E2E_KUBECONFIG")
	if k == "" {
		t.Skip("OLYMPOS_E2E_KUBECONFIG not set; run test/e2e/run.sh")
	}
	return k
}

func baseURL() string {
	if u := os.Getenv("OLYMPOS_E2E_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:28080"
}

// run executes a command with the lab kubeconfig (never the user's context).
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig(t))
	cmd.Dir = root()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func runOK(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig(t))
	cmd.Dir = root()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func eventually(t *testing.T, timeout time.Duration, what string, f func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		ok, msg := f()
		if ok {
			return
		}
		last = msg
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("timed out waiting for %s (last: %s)", what, last)
}

// client is a signed-in browser session against the in-cluster server.
type client struct {
	t    *testing.T
	http *http.Client
	csrf string
}

func login(t *testing.T, oid, name string) *client {
	t.Helper()
	eventually(t, 2*time.Minute, "server healthz", func() (bool, string) {
		r, err := http.Get(baseURL() + "/healthz")
		if err != nil {
			return false, err.Error()
		}
		r.Body.Close()
		return r.StatusCode == 200, r.Status
	})
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := hc.Get(baseURL() + "/auth/dev-login?oid=" + url.QueryEscape(oid) + "&name=" + url.QueryEscape(name))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	c := &client{t: t, http: hc}
	u, _ := url.Parse(baseURL())
	for _, ck := range jar.Cookies(u) {
		if ck.Name == "olympos_csrf" {
			c.csrf = ck.Value
		}
	}
	if c.csrf == "" {
		t.Fatalf("dev login failed: %s", r.Status)
	}
	return c
}

func (c *client) do(method, path string, body, out any) (int, string) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, baseURL()+"/api/v1"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatalf("%s %s decode: %v: %s", method, path, err, raw)
		}
	}
	return resp.StatusCode, string(raw)
}

func (c *client) must(method, path string, body, out any, want int) {
	c.t.Helper()
	if code, raw := c.do(method, path, body, out); code != want {
		c.t.Fatalf("%s %s: status %d (want %d): %s", method, path, code, want, raw)
	}
}

var setRe = regexp.MustCompile(`--set ([a-zA-Z.]+)=(\S+)`)

// helmSets extracts --set key=value pairs from a generated install command.
func helmSets(cmd string) map[string]string {
	out := map[string]string{}
	for _, m := range setRe.FindAllStringSubmatch(cmd, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// installAgent installs the agent chart with values from an install command.
func installAgent(t *testing.T, release, namespace string, sets map[string]string) {
	t.Helper()
	args := []string{"upgrade", "--install", release, "deploy/helm/olympos-agent", "--namespace", namespace, "--create-namespace",
		"--set", "image.repository=olympos-agent", "--set", "image.tag=e2e", "--set", "image.pullPolicy=Never", "--wait", "--timeout", "3m"}
	for k, v := range sets {
		args = append(args, "--set", fmt.Sprintf("%s=%s", k, v))
	}
	run(t, "helm", args...)
}
