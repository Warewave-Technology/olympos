package security

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
	"strings"
	"time"

	"github.com/Warewave-Technology/olympos/internal/secrets"
)

// Runner runs trivy. The scanner depends on this interface so tests can use
// a fake; TrivyCLI is the production implementation.
type Runner interface {
	// UpdateDB downloads the vulnerability DB (daily step, may use a mirror).
	UpdateDB(ctx context.Context) error
	// DBUpdatedAt reports when the local DB was downloaded (ok=false: no DB).
	DBUpdatedAt() (time.Time, bool)
	// Scan scans ref (repo@sha256:...) and returns trivy's JSON report. auth
	// may be nil (anonymous pull).
	Scan(ctx context.Context, ref string, auth *Auth) ([]byte, error)
}

// ScanError is a failed scan. Auth marks registry authentication failures,
// which the scanner reports as missing_credential.
type ScanError struct {
	Auth     bool
	NotFound bool // the digest does not exist in the registry
	Msg      string
}

func (e *ScanError) Error() string { return e.Msg }

// TrivyCLI runs the trivy binary.
type TrivyCLI struct {
	Bin      string
	CacheDir string
	DBRepo   string // optional mirror (--db-repository)
	Timeout  time.Duration
}

// passEnv are the only server environment variables a trivy child sees: the
// server's own environment (Azure identity, DSNs, ...) is never inherited.
var passEnv = []string{"PATH", "HOME", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR"}

func (t *TrivyCLI) baseEnv() []string {
	env := []string{"TRIVY_NO_PROGRESS=true", "TRIVY_DISABLE_VEX_NOTICE=true"}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func (t *TrivyCLI) bin() string {
	if t.Bin == "" {
		return "trivy"
	}
	return t.Bin
}

const maxTrivyOutput = 128 << 20

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("output too large")
	}
	return b.Buffer.Write(p)
}

// timeout bounds one trivy invocation (trivy's own default of 5 min is too
// short for large images).
func (t *TrivyCLI) timeout() time.Duration {
	if t.Timeout > 0 {
		return t.Timeout
	}
	return 15 * time.Minute
}

func (t *TrivyCLI) run(ctx context.Context, env []string, args ...string) (stdout []byte, stderr string, err error) {
	// The process deadline is a little longer than trivy's own --timeout so
	// trivy gets to report its error.
	ctx, cancel := context.WithTimeout(ctx, t.timeout()+time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, t.bin(), args...)
	cmd.Env = env
	out := &limitedBuffer{limit: maxTrivyOutput}
	errb := &limitedBuffer{limit: 1 << 20}
	cmd.Stdout, cmd.Stderr, cmd.Stdin = out, errb, nil
	err = cmd.Run()
	return out.Bytes(), errb.String(), err
}

// UpdateDB runs `trivy image --download-db-only` (and the Java DB, best
// effort) into CacheDir, honoring DBRepo for restricted networks.
func (t *TrivyCLI) UpdateDB(ctx context.Context) error {
	args := []string{"image", "--download-db-only", "--quiet", "--cache-dir", t.CacheDir}
	if t.DBRepo != "" {
		args = append(args, "--db-repository", t.DBRepo)
	}
	if _, stderr, err := t.run(ctx, t.baseEnv(), args...); err != nil {
		return fmt.Errorf("trivy db update: %v: %s", err, lastLines(stderr, 3))
	}
	// The Java DB is optional (jar scanning); failures are not fatal.
	_, _, _ = t.run(ctx, t.baseEnv(), "image", "--download-java-db-only", "--quiet", "--cache-dir", t.CacheDir)
	return nil
}

// DBUpdatedAt reads trivy's DB metadata from the cache directory.
func (t *TrivyCLI) DBUpdatedAt() (time.Time, bool) {
	b, err := os.ReadFile(filepath.Join(t.CacheDir, "db", "metadata.json"))
	if err != nil {
		return time.Time{}, false
	}
	var m struct{ DownloadedAt, UpdatedAt time.Time }
	if json.Unmarshal(b, &m) != nil {
		return time.Time{}, false
	}
	if !m.DownloadedAt.IsZero() {
		return m.DownloadedAt, true
	}
	return m.UpdatedAt, !m.UpdatedAt.IsZero()
}

// Scan runs trivy against a remote image. Credentials are passed only via
// TRIVY_USERNAME/TRIVY_PASSWORD in the child's environment (never argv).
func (t *TrivyCLI) Scan(ctx context.Context, ref string, auth *Auth) ([]byte, error) {
	if strings.HasPrefix(ref, "-") {
		return nil, &ScanError{Msg: "invalid image reference"}
	}
	env := t.baseEnv()
	var pw string
	if auth != nil && len(auth.Password) > 0 {
		pw = string(auth.Password)
		env = append(env, "TRIVY_USERNAME="+auth.Username, "TRIVY_PASSWORD="+pw)
	}
	out, stderr, err := t.run(ctx, env, "image", "--format", "json", "--quiet", "--skip-db-update", "--skip-java-db-update",
		"--scanners", "vuln", "--image-src", "remote", "--timeout", t.timeout().String(), "--cache-dir", t.CacheDir,
		// Concurrent scans share the DB read-only; the per-scan layer cache
		// stays in memory (the fs cache is a single locked bolt file).
		"--cache-backend", "memory", "--", ref)
	if err != nil {
		msg := lastLines(stderr, 4)
		if pw != "" {
			msg = strings.ReplaceAll(msg, pw, "[REDACTED]")
		}
		msg = secrets.RedactString(msg)
		if msg == "" {
			msg = err.Error()
		}
		return nil, &ScanError{Auth: IsAuthError(stderr), NotFound: IsNotFoundError(stderr), Msg: truncateStr(msg, 600)}
	}
	return out, nil
}

var authErrRe = regexp.MustCompile(`(?i)(unauthorized|authentication required|no basic auth credentials|access to the resource is denied|denied:|status code 401|status code 403|\b401 unauthorized|\b403 forbidden)`)

var notFoundRe = regexp.MustCompile(`(?i)(manifest unknown|MANIFEST_UNKNOWN|unable to find the specified image|status code 404|\b404 not found|NAME_UNKNOWN)`)

// IsNotFoundError reports whether trivy's stderr says the image digest does
// not exist in the registry (a permanent condition: not retried).
func IsNotFoundError(stderr string) bool {
	return notFoundRe.MatchString(stderr) && !authErrRe.MatchString(stderr)
}

// IsAuthError reports whether trivy's stderr shows a registry auth failure.
func IsAuthError(stderr string) bool { return authErrRe.MatchString(stderr) }

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// Vuln is one vulnerability of an image (per CVE and package).
type Vuln struct {
	CVEID     string `json:"cve_id"`
	Severity  string `json:"severity"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	FixedIn   string `json:"fixed_in"`
	Title     string `json:"title"`
}

type trivyReport struct {
	SchemaVersion int
	Results       []struct {
		Target          string
		Class           string
		Vulnerabilities []struct {
			VulnerabilityID  string
			PkgName          string
			PkgPath          string
			InstalledVersion string
			FixedVersion     string
			Severity         string
			Title            string
		}
	}
}

var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "unknown": true}

// ParseTrivy parses `trivy image --format json` output into deduplicated
// vulnerabilities (one per CVE+package), sorted by severity then ID.
func ParseTrivy(r io.Reader) ([]Vuln, error) {
	var rep trivyReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	if rep.SchemaVersion != 0 && rep.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported trivy schema version %d", rep.SchemaVersion)
	}
	seen := map[[2]string]int{}
	var out []Vuln
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" || v.PkgName == "" {
				continue
			}
			sev := strings.ToLower(v.Severity)
			if !severities[sev] {
				sev = "unknown"
			}
			k := [2]string{v.VulnerabilityID, v.PkgName}
			if i, dup := seen[k]; dup {
				// Same CVE in the same package under several targets: keep
				// the most severe, remember a fix if any.
				if sevRank(sev) < sevRank(out[i].Severity) {
					out[i].Severity = sev
				}
				if out[i].FixedIn == "" {
					out[i].FixedIn = v.FixedVersion
				}
				continue
			}
			seen[k] = len(out)
			out = append(out, Vuln{
				CVEID: truncateStr(v.VulnerabilityID, 64), Severity: sev, Package: truncateStr(v.PkgName, 256),
				Installed: truncateStr(v.InstalledVersion, 128), FixedIn: truncateStr(v.FixedVersion, 256), Title: truncateStr(v.Title, 300),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := sevRank(out[i].Severity), sevRank(out[j].Severity); a != b {
			return a < b
		}
		if out[i].CVEID != out[j].CVEID {
			return out[i].CVEID < out[j].CVEID
		}
		return out[i].Package < out[j].Package
	})
	return out, nil
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}
