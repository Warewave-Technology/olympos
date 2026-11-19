package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

// Fallback CIS framework names (kubescape 4.0). The names change between
// kubescape releases, so the installed binary's list is preferred
// (ListKubescapeFrameworks) and these are used only when it is unavailable.
var cisFallback = map[string]string{
	inventory.ProviderAzure: "cis-aks-t1.8.0",
	inventory.ProviderAWS:   "cis-eks-t1.8.0",
	inventory.ProviderGCP:   "cis-gke-v1.9.0",
	"":                      "cis-v1.12.0",
}

// cisPrefix is the framework-name prefix per provider ("cis-v" = generic).
func cisPrefix(provider string) string {
	switch provider {
	case inventory.ProviderAzure:
		return "cis-aks-"
	case inventory.ProviderAWS:
		return "cis-eks-"
	case inventory.ProviderGCP:
		return "cis-gke-"
	}
	return "cis-v"
}

// pickCIS returns the newest available CIS framework for the provider.
func pickCIS(available []string, provider string) string {
	if len(available) == 0 {
		if fb, ok := cisFallback[provider]; ok {
			return fb
		}
		return cisFallback[""]
	}
	prefix, best := cisPrefix(provider), ""
	for _, f := range available {
		if strings.HasPrefix(strings.ToLower(f), prefix) && (best == "" || versionLess(best, f)) {
			best = f
		}
	}
	if best == "" && prefix != "cis-v" {
		return pickCIS(available, "") // managed provider without its own CIS
	}
	if best != "" {
		return best
	}
	if fb, ok := cisFallback[provider]; ok {
		return fb
	}
	return cisFallback[""]
}

// versionLess compares the numbers in two framework names (cis-v1.10.0 < cis-v1.12.0).
func versionLess(a, b string) bool {
	na, nb := nums(a), nums(b)
	for i := 0; i < len(na) && i < len(nb); i++ {
		if na[i] != nb[i] {
			return na[i] < nb[i]
		}
	}
	return len(na) < len(nb)
}

func nums(s string) []int {
	var out []int
	n, in := 0, false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n, in = n*10+int(c-'0'), true
			continue
		}
		if in {
			out = append(out, n)
			n, in = 0, false
		}
	}
	if in {
		out = append(out, n)
	}
	return out
}

// kubescapeFramework maps the schedule's framework choice to a kubescape
// framework name. "cis" depends on the provider and on the frameworks the
// installed kubescape ships (available; may be nil).
func kubescapeFramework(fw, provider string, available []string) string {
	switch fw {
	case "nsa":
		return "nsa"
	case "mitre":
		return "mitre"
	case "cis":
		return pickCIS(available, provider)
	}
	return ""
}

// ListKubescapeFrameworks asks the installed kubescape for its frameworks.
func ListKubescapeFrameworks(ctx context.Context, bin string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "list", "frameworks", "--format", "json")
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + os.TempDir(), "KS_SKIP_UPDATE_CHECK=true", "DO_NOT_TRACK=1"}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubescape list frameworks: %w", err)
	}
	var names []string
	if err := json.Unmarshal(out, &names); err != nil {
		return nil, fmt.Errorf("kubescape list frameworks: %w", err)
	}
	return names, nil
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
func KubescapeInvocation(bin string, frameworks []string, provider, kubeconfig, workDir string, available ...string) (Invocation, error) {
	if len(frameworks) == 0 {
		frameworks = Frameworks
	}
	var fws []string
	seen := map[string]bool{}
	for _, f := range frameworks {
		name := kubescapeFramework(strings.ToLower(strings.TrimSpace(f)), provider, available)
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

// DefaultKubescapeArtifacts is where the image and the packages put the
// kubescape frameworks, controls, exceptions and control inputs downloaded
// at build time (F14: no download at scan time, works air-gapped).
const DefaultKubescapeArtifacts = "/usr/share/olympos/kubescape-artifacts"

// WithKubescapeArtifacts makes kubescape load its artifacts from dir
// (--use-artifacts-from) when dir holds them; otherwise kubescape downloads
// them at scan time (needs egress to the ARMO API).
func WithKubescapeArtifacts(inv Invocation, dir string) Invocation {
	if dir == "" {
		return inv
	}
	if _, err := os.Stat(filepath.Join(dir, "controls-inputs.json")); err != nil {
		return inv
	}
	inv.Args = append(append([]string(nil), inv.Args...), "--use-artifacts-from", dir)
	return inv
}

// KubescapeArtifactFrameworks lists the framework names in an artifacts
// directory (each framework is <name>.json with a "name" field).
func KubescapeArtifactFrameworks(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".json") {
			continue
		}
		switch n {
		case "attack-tracks.json", "controls-inputs.json", "exceptions.json", "allcontrols.json":
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		var fw struct {
			Name     string            `json:"name"`
			Controls []json.RawMessage `json:"controls"`
		}
		if json.Unmarshal(b, &fw) == nil && fw.Name != "" && fw.Controls != nil {
			names = append(names, fw.Name)
		}
	}
	sort.Strings(names)
	return names, nil
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
// tests can stub it. A failure should be a *ToolError so the run keeps a
// short reason and the captured output apart.
type Exec func(ctx context.Context, inv Invocation, workDir string) ([]byte, error)

// MaxLogBytes caps the captured console output of a tool run (the tail is
// kept: errors come last).
const MaxLogBytes = 256 << 10

// ToolError is a failed kubescape/polaris run. Reason is short and human
// (audit_runs.error, e.g. "kubescape failed: framework 'x' not found"); Log
// is the captured console output (audit_runs.log, run detail only). Both
// are redacted by the caller before they are stored.
type ToolError struct {
	Reason string
	Log    string
}

func (e *ToolError) Error() string { return e.Reason }

// ExecTool runs inv with a timeout, captures the console output (stderr,
// plus stdout when the report goes to a file) and reads the output file.
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
	console := &tailBuffer{max: MaxLogBytes}
	cmd.Stdout = &limitWriter{w: &stdout, n: maxRawBytes}
	if inv.OutputFile != "" {
		// The report goes to a file: stdout is console output too.
		cmd.Stdout = console
	}
	cmd.Stderr = console
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	tool := filepath.Base(inv.Bin)
	if ctx.Err() != nil {
		return nil, &ToolError{Reason: fmt.Sprintf("%s timed out or was cancelled: %v", tool, ctx.Err()), Log: console.String()}
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
		reason := ShortReason(console.String())
		if reason == "" {
			reason = err.Error()
		}
		return nil, &ToolError{Reason: tool + " failed: " + reason, Log: console.String()}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		reason := "produced no output"
		if r := ShortReason(console.String()); r != "" {
			reason += ": " + r
		}
		return nil, &ToolError{Reason: tool + " " + reason, Log: console.String()}
	}
	return raw, nil
}

// maxReasonRunes bounds the short reason stored in audit_runs.error.
const maxReasonRunes = 300

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

var logfmtLevelRe = regexp.MustCompile(`(?i)\blevel=(error|fatal|panic)\b`)
var logfmtMsgRe = regexp.MustCompile(`\bmsg=("(?:[^"\\]|\\.)*"|\S+)`)

// ShortReason picks a one-line human reason from a tool's console output:
// the last "Error: …" line (cobra, e.g. kubescape's "Error: framework 'x'
// not found"), else the message of the last error-level log line (JSON as
// kubescape writes with --logger json, or logrus/logfmt as polaris writes),
// else the last non-empty line. "" when the output is empty.
func ShortReason(console string) string {
	lines := strings.Split(ansiRe.ReplaceAllString(console, ""), "\n")
	pick := func() string {
		for i := len(lines) - 1; i >= 0; i-- {
			l := strings.TrimSpace(lines[i])
			if rest, ok := strings.CutPrefix(l, "Error: "); ok && strings.TrimSpace(rest) != "" {
				return strings.TrimSpace(rest)
			}
		}
		for i := len(lines) - 1; i >= 0; i-- {
			if m := errorLogMessage(strings.TrimSpace(lines[i])); m != "" {
				return m
			}
		}
		for i := len(lines) - 1; i >= 0; i-- {
			if l := strings.TrimSpace(lines[i]); l != "" {
				if m := jsonLogMessage(l); m != "" {
					return m
				}
				return l
			}
		}
		return ""
	}
	r := Redact(pick())
	if rs := []rune(r); len(rs) > maxReasonRunes {
		r = string(rs[:maxReasonRunes-1]) + "…"
	}
	return r
}

// errorLogMessage returns the message of an error-level JSON or logfmt log
// line ("" for other lines).
func errorLogMessage(l string) string {
	if strings.HasPrefix(l, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			return ""
		}
		level := strings.ToLower(firstString(m, "level", "lvl", "severity"))
		if level != "error" && level != "fatal" && level != "panic" && level != "dpanic" {
			return ""
		}
		return jsonLogMessage(l)
	}
	if logfmtLevelRe.MatchString(l) {
		if mm := logfmtMsgRe.FindStringSubmatch(l); mm != nil {
			msg := mm[1]
			if uq, err := strconv.Unquote(msg); err == nil {
				msg = uq
			}
			return strings.TrimSpace(msg)
		}
		return l
	}
	return ""
}

// jsonLogMessage returns "msg: error" of a JSON log line ("" if not JSON).
func jsonLogMessage(l string) string {
	if !strings.HasPrefix(l, "{") {
		return ""
	}
	var m map[string]any
	if json.Unmarshal([]byte(l), &m) != nil {
		return ""
	}
	msg := firstString(m, "msg", "message")
	if e := firstString(m, "error", "err"); e != "" && !strings.Contains(msg, e) {
		if msg == "" {
			return e
		}
		msg += ": " + e
	}
	return strings.TrimSpace(msg)
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// RedactLog prepares captured console output for storage: token-like
// values redacted, NUL bytes and invalid UTF-8 removed (Postgres text),
// capped to the last MaxLogBytes.
func RedactLog(s string) string {
	s = redactAll(strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), ""))
	if len(s) > MaxLogBytes {
		s = strings.ToValidUTF8(s[len(s)-MaxLogBytes:], "")
	}
	return s
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

func redactAll(s string) string {
	for _, re := range redactPatterns {
		if re.NumSubexp() > 0 {
			s = re.ReplaceAllString(s, "${1}[REDACTED]")
		} else {
			s = re.ReplaceAllString(s, "[REDACTED]")
		}
	}
	return s
}

// Redact removes token-like values from tool output before it is stored or
// logged, and truncates it.
func Redact(s string) string {
	s = strings.TrimSpace(redactAll(s))
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
