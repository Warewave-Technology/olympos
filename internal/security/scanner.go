package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// LockScanner is the advisory lock key of the scanner leader. Only the
// leader scans: it is also the replica whose cache holds a fresh trivy DB.
const LockScanner int64 = 0x4f4c5951

// Settings keys.
const (
	settingDBUpdatedAt = "security.trivy_db_updated_at"
	settingRescanAt    = "security.last_rescan_at"
)

// Scanner scans running images with trivy (SPEC §13.3): new digests as soon
// as they are reported, every in-use digest daily after the DB update.
type Scanner struct {
	DB       *store.DB
	Log      *slog.Logger
	KV       secrets.KeyVault
	Envelope *secrets.Envelope
	Runner   Runner
	// Concurrency is the number of parallel trivy processes (default 2).
	Concurrency int
	// Interval is the leader tick (default 5 s): pending images are picked up
	// within one interval on whichever replica is leader.
	Interval time.Duration
	// DBMaxAge triggers a DB update and full rescan (default 24 h).
	DBMaxAge time.Duration
	// Link builds absolute links for events (optional).
	Link func(path string) string

	mu            sync.Mutex
	lastDBAttempt time.Time
	wake          chan struct{}
	wakeOnce      sync.Once
}

func (s *Scanner) wakeCh() chan struct{} {
	s.wakeOnce.Do(func() { s.wake = make(chan struct{}, 1) })
	return s.wake
}

// Poke asks the scanner to look for pending images now (when this replica
// is the leader; otherwise the leader finds them within one interval).
func (s *Scanner) Poke() {
	select {
	case s.wakeCh() <- struct{}{}:
	default:
	}
}

func (s *Scanner) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return 5 * time.Second
}

func (s *Scanner) maxAge() time.Duration {
	if s.DBMaxAge > 0 {
		return s.DBMaxAge
	}
	return 24 * time.Hour
}

// Run is the background worker: leader-locked ticks.
func (s *Scanner) Run(ctx context.Context) {
	schedule.RunLeader(ctx, s.DB, LockScanner, s.interval(), s.Log, func(ctx context.Context) error {
		if err := s.Tick(ctx); err != nil {
			return err
		}
		// Wait briefly for a poke so new digests are scanned immediately.
		select {
		case <-s.wakeCh():
			return s.Tick(ctx)
		case <-time.After(s.interval() / 2):
		case <-ctx.Done():
		}
		return nil
	})
}

// Tick refreshes the DB when due, triggers the daily rescan, and scans every
// pending image. Exported for tests.
func (s *Scanner) Tick(ctx context.Context) error {
	// A crash mid-scan leaves rows in "scanning"; trivy times out well before.
	if _, err := s.DB.Exec(ctx, `UPDATE images SET scan_status = 'pending'
		WHERE scan_status = 'scanning' AND updated_at < now() - interval '30 minutes'`); err != nil {
		return err
	}
	ready, err := s.ensureDB(ctx)
	if err != nil {
		s.Log.Error("trivy db update failed", "err", err)
	}
	if !ready {
		return nil // keep images pending until a DB is available
	}
	if err := s.maybeRescanAll(ctx); err != nil {
		return err
	}
	return s.Drain(ctx)
}

// ensureDB updates the trivy DB when it is missing or older than DBMaxAge
// (at most one attempt per hour). ready is false when no DB is available.
func (s *Scanner) ensureDB(ctx context.Context) (ready bool, err error) {
	at, ok := s.Runner.DBUpdatedAt()
	if ok && time.Since(at) < s.maxAge() {
		return true, nil
	}
	s.mu.Lock()
	if !s.lastDBAttempt.IsZero() && time.Since(s.lastDBAttempt) < time.Hour {
		s.mu.Unlock()
		return ok, nil
	}
	s.lastDBAttempt = time.Now()
	s.mu.Unlock()
	s.Log.Info("updating trivy vulnerability db")
	if err := s.Runner.UpdateDB(ctx); err != nil {
		return ok, err
	}
	at, ok = s.Runner.DBUpdatedAt()
	if !ok {
		at = time.Now()
	}
	_ = setSetting(ctx, s.DB, settingDBUpdatedAt, at)
	return true, nil
}

// maybeRescanAll marks every in-use digest pending once per DBMaxAge (after
// the DB update of the day).
func (s *Scanner) maybeRescanAll(ctx context.Context) error {
	last, _ := getSetting(ctx, s.DB, settingRescanAt)
	if !last.IsZero() && time.Since(last) < s.maxAge() {
		return nil
	}
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE images i SET scan_status = 'pending'
			WHERE scan_status IN ('scanned','failed','missing_credential')
			  AND EXISTS (SELECT 1 FROM image_usage u WHERE u.digest = i.digest)`)
		if err != nil {
			return err
		}
		s.Log.Info("daily image rescan queued", "images", tag.RowsAffected())
		return setSetting(ctx, tx, settingRescanAt, time.Now())
	})
}

func setSetting(ctx context.Context, q store.Querier, key string, t time.Time) error {
	b, _ := json.Marshal(map[string]time.Time{"at": t.UTC()})
	_, err := q.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, b)
	return err
}

func getSetting(ctx context.Context, q store.Querier, key string) (time.Time, error) {
	var v struct{ At time.Time }
	var raw []byte
	if err := q.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&raw); err != nil {
		return time.Time{}, store.NotFound(err)
	}
	err := json.Unmarshal(raw, &v)
	return v.At, err
}

// Drain scans pending images with Concurrency workers until none is left.
func (s *Scanner) Drain(ctx context.Context) error {
	n := s.Concurrency
	if n <= 0 {
		n = 2
	}
	regs, err := registryRefs(ctx, s.DB)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				digest, repo, ok, err := s.claim(ctx)
				if err != nil {
					errc <- err
					return
				}
				if !ok {
					return
				}
				if err := s.scanOne(ctx, regs, digest, repo); err != nil && ctx.Err() == nil {
					s.Log.Error("image scan", "digest", digest, "err", err)
				}
			}
		}()
	}
	wg.Wait()
	close(errc)
	return <-errc
}

// claim takes one pending in-use image (SKIP LOCKED, so concurrent workers
// never pick the same digest).
func (s *Scanner) claim(ctx context.Context) (digest, repo string, ok bool, err error) {
	err = s.DB.QueryRow(ctx, `
		UPDATE images SET scan_status = 'scanning'
		WHERE digest = (
			SELECT i.digest FROM images i
			WHERE i.scan_status = 'pending' AND EXISTS (SELECT 1 FROM image_usage u WHERE u.digest = i.digest)
			ORDER BY i.last_scanned_at NULLS FIRST, i.created_at
			LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING digest, repo`).Scan(&digest, &repo)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	return digest, repo, err == nil, err
}

func (s *Scanner) setStatus(ctx context.Context, digest, status, msg string) error {
	metrics.ImageScans.WithLabelValues(status).Inc()
	_, err := s.DB.Exec(ctx, `UPDATE images SET scan_status = $2, scan_error = $3, last_scanned_at = now() WHERE digest = $1`,
		digest, status, truncateStr(msg, 600))
	return err
}

func (s *Scanner) scanOne(ctx context.Context, regs []RegistryRef, digest, repo string) error {
	if !DigestRe.MatchString(digest) || !ValidRepo(repo) {
		return s.setStatus(ctx, digest, "failed", "Invalid image reference.")
	}
	host := HostOf(repo)
	reg := MatchRegistry(regs, repo)
	if reg == nil && !IsPublicHost(host) {
		return s.setStatus(ctx, digest, "missing_credential",
			fmt.Sprintf("No registry credential matches %s. Add one in Settings › Registries.", host))
	}
	var auth *Auth
	if reg != nil && reg.CredentialID != nil {
		a, err := ResolveCredential(ctx, s.DB, s.Envelope, s.KV, *reg.CredentialID)
		if err != nil {
			s.Log.Warn("resolve registry credential", "registry", reg.HostPattern, "err", err)
			return s.setStatus(ctx, digest, "failed", fmt.Sprintf("Could not read the credential of registry %s.", reg.HostPattern))
		}
		auth = a
	}
	out, err := s.Runner.Scan(ctx, repo+"@"+digest, auth)
	auth.Zero()
	if err != nil {
		if ctx.Err() != nil {
			_, _ = s.DB.Exec(context.WithoutCancel(ctx), `UPDATE images SET scan_status = 'pending' WHERE digest = $1`, digest)
			return ctx.Err()
		}
		var se *ScanError
		if errors.As(err, &se) && se.Auth {
			msg := "The registry requires authentication. Add a credential in Settings › Registries."
			if auth != nil {
				msg = fmt.Sprintf("Registry %s rejected the stored credential.", reg.HostPattern)
			}
			return s.setStatus(ctx, digest, "missing_credential", msg)
		}
		return s.setStatus(ctx, digest, "failed", "trivy: "+err.Error())
	}
	vulns, err := ParseTrivy(bytes.NewReader(out))
	if err != nil {
		return s.setStatus(ctx, digest, "failed", err.Error())
	}
	if err := s.saveResults(ctx, digest, repo, vulns); err != nil {
		return err
	}
	metrics.ImageScans.WithLabelValues("scanned").Inc()
	return nil
}

// saveResults replaces an image's vulnerabilities, keeping first_seen_at of
// those already known, updates the counts and emits vuln.critical for
// critical CVEs this digest did not have before (when it is running).
func (s *Scanner) saveResults(ctx context.Context, digest, repo string, vulns []Vuln) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var tags []string
		if err := tx.QueryRow(ctx, `SELECT tags FROM images WHERE digest = $1 FOR UPDATE`, digest).Scan(&tags); err != nil {
			return err
		}
		prev := map[string]bool{}
		rows, err := tx.Query(ctx, `SELECT DISTINCT cve_id FROM image_vulns WHERE digest = $1`, digest)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			prev[id] = true
		}
		rows.Close()

		keys := make([]string, 0, len(vulns))
		b := &pgx.Batch{}
		counts := map[string]map[string]bool{}
		newCrit := map[string]Vuln{}
		for _, v := range vulns {
			keys = append(keys, v.CVEID+"\x1f"+v.Package)
			b.Queue(`INSERT INTO image_vulns (digest, cve_id, severity, package, installed, fixed_in, title)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (digest, cve_id, package) DO UPDATE SET severity = EXCLUDED.severity,
				  installed = EXCLUDED.installed, fixed_in = EXCLUDED.fixed_in, title = EXCLUDED.title`,
				digest, v.CVEID, v.Severity, v.Package, v.Installed, v.FixedIn, v.Title)
			if counts[v.Severity] == nil {
				counts[v.Severity] = map[string]bool{}
			}
			counts[v.Severity][v.CVEID] = true
			if v.Severity == "critical" && !prev[v.CVEID] {
				if _, dup := newCrit[v.CVEID]; !dup {
					newCrit[v.CVEID] = v
				}
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM image_vulns WHERE digest = $1 AND NOT (cve_id || chr(31) || package = ANY($2))`,
			digest, keys); err != nil {
			return err
		}
		if b.Len() > 0 {
			if err := tx.SendBatch(ctx, b).Close(); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE images SET scan_status = 'scanned', scan_error = '', last_scanned_at = now(),
			critical = $2, high = $3, medium = $4, low = $5 WHERE digest = $1`,
			digest, len(counts["critical"]), len(counts["high"]), len(counts["medium"]), len(counts["low"])); err != nil {
			return err
		}
		if len(newCrit) == 0 {
			return nil
		}
		return s.emitCritical(ctx, tx, digest, repo, tags, newCrit)
	})
}

func (s *Scanner) emitCritical(ctx context.Context, tx pgx.Tx, digest, repo string, tags []string, newCrit map[string]Vuln) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT c.name FROM image_usage u JOIN clusters c ON c.id = u.cluster_id WHERE u.digest = $1 ORDER BY 1`, digest)
	if err != nil {
		return err
	}
	var clusters []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		clusters = append(clusters, n)
	}
	rows.Close()
	if len(clusters) == 0 {
		return nil // not running anywhere any more
	}
	image := repo
	if len(tags) > 0 {
		image += ":" + tags[0]
	}
	ids := make([]string, 0, len(newCrit))
	for id := range newCrit {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	link := "/security?image=" + digest
	if s.Link != nil {
		link = s.Link(link)
	}
	for _, id := range ids {
		v := newCrit[id]
		fix := v.FixedIn
		if fix == "" {
			fix = "no fix yet"
		}
		if err := notify.Emit(ctx, tx, notify.Event{
			Type:  notify.VulnCritical,
			Key:   notify.VulnCritical + ":" + digest + ":" + id,
			Title: fmt.Sprintf("Critical %s in %s", id, image),
			Link:  link,
			Fields: map[string]string{
				"image": image, "digest": shortDigest(digest), "cve": id, "package": v.Package + " " + v.Installed,
				"fixed_in": fix, "clusters": strings.Join(clusters, ", "),
			},
			Payload: map[string]any{"digest": digest, "cve_id": id},
		}); err != nil {
			return err
		}
	}
	return nil
}

func shortDigest(d string) string {
	h := strings.TrimPrefix(d, "sha256:")
	if len(h) > 12 {
		h = h[:12]
	}
	return "sha256:" + h
}
