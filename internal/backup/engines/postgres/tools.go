package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tool is a resolved pg_dump binary (pg_dumpall and pg_restore live next
// to it).
type Tool struct {
	PgDump    string
	PgDumpAll string
	// PgRestore is required by restores (FindRestoreTool); FindTool sets it
	// when present.
	PgRestore string
	Major     int
	Version   string // e.g. "pg_dump (PostgreSQL) 17.4"
}

var versionRe = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+)(?:\.(\d+))?`)

// toolVersion runs `<bin> --version` and returns the line and major.
func toolVersion(ctx context.Context, bin string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = []string{"LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return "", 0, fmt.Errorf("%s --version: %w", bin, err)
	}
	line := strings.TrimSpace(string(out))
	m := versionRe.FindStringSubmatch(line)
	if m == nil {
		return "", 0, fmt.Errorf("unrecognized version output from %s: %q", bin, line)
	}
	major, _ := strconv.Atoi(m[1])
	return line, major, nil
}

func executable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// FindTool selects the pg_dump whose major is >= serverMajor, preferring the
// closest major (restores then need the oldest possible pg_restore). dir is
// a ':'-separated list of layouts: a directory holding <major>/bin/ (the
// image, Debian PGDG /usr/lib/postgresql, /usr/lib/olympos/pg) or a pattern
// with {major} (RHEL PGDG /usr/pgsql-{major}/bin). Falls back to pg_dump on
// PATH when its major is high enough.
func FindTool(ctx context.Context, dir string, serverMajor int) (*Tool, error) {
	return findTool(ctx, dir, serverMajor, false)
}

// FindRestoreTool is FindTool for restores: pg_restore must be there too,
// with a major >= minMajor (the archive's pg_dump, or the server's).
func FindRestoreTool(ctx context.Context, dir string, minMajor int) (*Tool, error) {
	return findTool(ctx, dir, minMajor, true)
}

func findTool(ctx context.Context, dir string, serverMajor int, needRestore bool) (*Tool, error) {
	type cand struct {
		major int
		bin   string
	}
	var cands []cand
	for _, layout := range strings.Split(dir, ":") {
		if layout == "" {
			continue
		}
		if strings.Contains(layout, "{major}") {
			for m := serverMajor; m <= serverMajor+20; m++ {
				bin := strings.ReplaceAll(layout, "{major}", strconv.Itoa(m))
				if executable(filepath.Join(bin, "pg_dump")) {
					cands = append(cands, cand{m, bin})
				}
			}
			continue
		}
		entries, err := os.ReadDir(layout)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if m, err := strconv.Atoi(e.Name()); err == nil && m >= serverMajor {
				cands = append(cands, cand{m, filepath.Join(layout, e.Name(), "bin")})
			}
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].major < cands[j].major })
	var tried []string
	for _, c := range cands {
		if t, err := toolIn(ctx, filepath.Join(c.bin, "pg_dump"), serverMajor, needRestore); err == nil {
			return t, nil
		} else {
			tried = append(tried, err.Error())
		}
	}
	if p, err := exec.LookPath("pg_dump"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		t, err := toolIn(ctx, p, serverMajor, needRestore)
		if err == nil {
			return t, nil
		}
		tried = append(tried, err.Error())
	}
	what := "pg_dump"
	if needRestore {
		what = "pg_restore"
	}
	msg := fmt.Sprintf("no %s with major version >= %d found in %s (<major>/bin or {major} layouts) or PATH", what, serverMajor, dir)
	if len(tried) > 0 {
		msg += " (" + strings.Join(tried, "; ") + ")"
	}
	return nil, errors.New(msg)
}

func toolIn(ctx context.Context, pgDump string, serverMajor int, needRestore bool) (*Tool, error) {
	if !executable(pgDump) {
		return nil, fmt.Errorf("%s: not executable", pgDump)
	}
	all := filepath.Join(filepath.Dir(pgDump), "pg_dumpall")
	if !executable(all) {
		return nil, fmt.Errorf("%s: not executable", all)
	}
	restore := filepath.Join(filepath.Dir(pgDump), "pg_restore")
	if !executable(restore) {
		if needRestore {
			return nil, fmt.Errorf("%s: not executable", restore)
		}
		restore = ""
	}
	v, major, err := toolVersion(ctx, pgDump)
	if err != nil {
		return nil, err
	}
	if major < serverMajor {
		return nil, fmt.Errorf("%s is version %d, server is %d", pgDump, major, serverMajor)
	}
	return &Tool{PgDump: pgDump, PgDumpAll: all, PgRestore: restore, Major: major, Version: v}, nil
}

// systemRootsFile finds a CA bundle for libpq < 16 (no sslrootcert=system).
func systemRootsFile() string {
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		return f
	}
	for _, f := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"} {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return ""
}

// tailBuffer keeps the last max bytes written (stderr of tools).
type tailBuffer struct {
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return strings.TrimSpace(string(t.b)) }
