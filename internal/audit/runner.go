package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Warewave-Technology/olympos/internal/inventory"
)

// Tools.
const (
	ToolKubescape = "kubescape"
	ToolPolaris   = "polaris"
	ToolKubeBench = "kube-bench"
)

// Frameworks a kubescape schedule may select (SPEC §12.1).
var Frameworks = []string{"nsa", "cis", "mitre"}

// DefaultToolTimeout bounds one kubescape/polaris invocation.
const DefaultToolTimeout = 30 * time.Minute

// maxRawBytes caps a tool's JSON output.
const maxRawBytes = 256 << 20

// Invocation is a fully built command line. It is pure data so tests can
// assert it without the binaries being installed.
type Invocation struct {
	Bin  string
	Args []string
	// Env is added to a minimal environment (PATH, HOME, TMPDIR).
	Env []string
	// OutputFile is where the tool writes its JSON ("" = stdout).
	OutputFile string
}

// kubescapeFramework maps the schedule's framework choice to a kubescape
// framework name. "cis" depends on the provider: kubescape ships separate
// CIS frameworks for AKS and EKS, and a generic one otherwise.
func kubescapeFramework(fw, provider string) string {
	switch fw {
	case "nsa":
		return "nsa"
	case "mitre":
		return "mitre"
	case "cis":
		switch provider {
		case inventory.ProviderAzure:
			return "cis-aks-t1.2.0"
		case inventory.ProviderAWS:
			return "cis-eks-t1.2.0"
		}
		return "cis-v1.23-t1.0.1"
	}
	return ""
}

// KubescapeInvocation builds:
//
//	kubescape scan framework <fw,...> --format json --format-version v2
//	  --output <dir>/kubescape.json --keep-local
//
// The kubeconfig is passed as KUBECONFIG (its only context is current), not
// as a flag: kubescape's --kubeconfig is an inherited Go flag whose presence
// varies between releases.
//
// --keep-local keeps results off any configured backend (no upload); the
// environment disables update checks and telemetry. Kubescape downloads its
// framework definitions at scan time unless artifacts are pre-seeded in
// the image (KS_* cache dir); restricted networks should bake them in.
func KubescapeInvocation(bin string, frameworks []string, provider, kubeconfig, workDir string) (Invocation, error) {
	if len(frameworks) == 0 {
		frameworks = Frameworks
	}
	var fws []string
	seen := map[string]bool{}
	for _, f := range frameworks {
		name := kubescapeFramework(strings.ToLower(strings.TrimSpace(f)), provider)
		if name == "" {
			return Invocation{}, fmt.Errorf("unknown kubescape framework %q", f)
		}
		if !seen[name] {
			seen[name] = true
			fws = append(fws, name)
		}
	}
	out := filepath.Join(workDir, "kubescape.json")
	return Invocation{
		Bin: bin,
		Args: []string{"scan", "framework", strings.Join(fws, ","),
			"--format", "json", "--format-version", "v2", "--output", out, "--keep-local"},
		Env: []string{
			"KUBECONFIG=" + kubeconfig,
			"KS_SKIP_UPDATE_CHECK=true",
			"DO_NOT_TRACK=1",
		},
		OutputFile: out,
	}, nil
}

// PolarisInvocation builds:
//
//	polaris audit --format json --output-file <dir>/polaris.json
//
// with KUBECONFIG=<kubeconfig>: polaris has no --kubeconfig flag; it loads
// the standard client config (KUBECONFIG, current context).
func PolarisInvocation(bin, kubeconfig, workDir string) Invocation {
	out := filepath.Join(workDir, "polaris.json")
	return Invocation{
		Bin:        bin,
		Args:       []string{"audit", "--format", "json", "--output-file", out},
		Env:        []string{"KUBECONFIG=" + kubeconfig},
		OutputFile: out,
	}
}

// Exec runs an invocation and returns the JSON output. It is a variable so
// tests can stub it.
type Exec func(ctx context.Context, inv Invocation, workDir string) ([]byte, error)

// ExecTool runs inv with a timeout, captures stderr (redacted, truncated) for
// error messages and reads the output file.
func ExecTool(ctx context.Context, inv Invocation, workDir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, inv.Bin, inv.Args...)
	cmd.Dir = workDir
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + workDir,
		"TMPDIR=" + workDir,
	}
	// Egress proxy and CA settings for framework downloads. The kubeconfig
	// server is 127.0.0.1, which Go clients never send through a proxy.
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	cmd.Env = append(env, inv.Env...)
	var stdout bytes.Buffer
	stderr := &tailBuffer{max: 16 << 10}
	cmd.Stdout = &limitWriter{w: &stdout, n: maxRawBytes}
	cmd.Stderr = stderr
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out or was cancelled: %w", filepath.Base(inv.Bin), ctx.Err())
	}
	var raw []byte
	if inv.OutputFile != "" {
		b, rerr := readCapped(inv.OutputFile)
		if rerr == nil {
			raw = b
		}
	} else {
		raw = stdout.Bytes()
	}
	if err != nil {
		// kubescape/polaris exit non-zero when checks fail; a usable report
		// is still a successful scan.
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(bytes.TrimSpace(raw)) > 0 {
			return raw, nil
		}
		return nil, fmt.Errorf("%s failed: %v: %s", filepath.Base(inv.Bin), err, Redact(stderr.String()))
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%s produced no output: %s", filepath.Base(inv.Bin), Redact(stderr.String()))
	}
	return raw, nil
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRawBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxRawBytes {
		return nil, fmt.Errorf("output exceeds %d bytes", maxRawBytes)
	}
	return b, nil
}

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9\-_.~+/=]+`),
	regexp.MustCompile(`(?i)((?:token|password|secret|access[-_]?key|sig|authorization)["']?\s*[:=]\s*["']?)[^\s"',&]+`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
}

// Redact removes token-like values from tool output before it is stored or
// logged, and truncates it.
func Redact(s string) string {
	for _, re := range redactPatterns {
		if re.NumSubexp() > 0 {
			s = re.ReplaceAllString(s, "${1}[REDACTED]")
		} else {
			s = re.ReplaceAllString(s, "[REDACTED]")
		}
	}
	s = strings.TrimSpace(s)
	if len(s) > 2000 {
		s = "…" + s[len(s)-2000:]
	}
	return s
}

// tailBuffer keeps the last max bytes written.
type tailBuffer struct {
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.buf) }

type limitWriter struct {
	w io.Writer
	n int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if int64(len(q)) > l.n {
		q = q[:l.n]
	}
	n, err := l.w.Write(q)
	l.n -= int64(n)
	if err != nil {
		return n, err
	}
	return len(p), nil
}
