package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// LockScanner is the advisory lock key of the scanner leader. Only the
// leader scans: it is also the replica whose cache holds a fresh trivy DB.
const LockScanner = schedule.LockScanner

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
	if err := s.requeueRetries(ctx); err != nil {
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
			WHERE scan_status IN ('scanned','failed','missing_credential','unavailable')
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
				digest, repo, tags, ok, err := s.claim(ctx)
				if err != nil {
					errc <- err
					return
				}
				if !ok {
					return
				}
				if err := s.scanOne(ctx, regs, digest, repo, tags); err != nil && ctx.Err() == nil {
					s.Log.Error("image scan", "digest", digest, "err", err)
				}
			}
		}()
	}
	wg.Wait()
	close(errc)
	if err := <-errc; err != nil {
		return err
	}
	// End of the scan run: one grouped vuln.critical per cluster (F9).
	return s.flushCritical(context.WithoutCancel(ctx))
}

// claim takes one pending in-use image (SKIP LOCKED, so concurrent workers
// never pick the same digest).
func (s *Scanner) claim(ctx context.Context) (digest, repo string, tags []string, ok bool, err error) {
	err = s.DB.QueryRow(ctx, `
		UPDATE images SET scan_status = 'scanning'
		WHERE digest = (
			SELECT i.digest FROM images i
			WHERE i.scan_status = 'pending' AND EXISTS (SELECT 1 FROM image_usage u WHERE u.digest = i.digest)
			ORDER BY i.last_scanned_at NULLS FIRST, i.created_at
			LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING digest, repo, tags`).Scan(&digest, &repo, &tags)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil, false, nil
	}
	return digest, repo, tags, err == nil, err
}

// tagRe is a valid OCI tag.
var tagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// fallbackTag picks the tag to scan when the digest is not in the registry:
// the first valid tag in sort order, preferring any tag over "latest" (a
// moving tag is the least likely to match what runs). "" when none.
func fallbackTag(tags []string) string {
	sorted := append([]string{}, tags...)
	sort.Strings(sorted)
	pick := ""
	for _, t := range sorted {
		if !tagRe.MatchString(t) {
			continue
		}
		if t != "latest" {
			return t
		}
		pick = t
	}
	return pick
}

// TagScanNote is stored in images.scan_note for results obtained by tag.
func TagScanNote(tag string) string {
	return fmt.Sprintf("Scanned by tag %s — the running digest is not in the registry (built or retagged locally), "+
		"so results are for the registry's image with that tag.", tag)
}

func (s *Scanner) setStatus(ctx context.Context, digest, status, msg string) error {
	metrics.ImageScans.WithLabelValues(status).Inc()
	_, err := s.DB.Exec(ctx, `UPDATE images SET scan_status = $2, scan_error = $3, last_scanned_at = now(),
		scan_attempts = 0, next_retry_at = NULL WHERE digest = $1`, digest, status, truncateStr(msg, 600))
	return err
}

// MaxScanAttempts is how often a transient failure is retried automatically
// before the image waits for the daily rescan or a manual retry.
const MaxScanAttempts = 5

// retryBackoff is the delay before retry n (1-based).
func retryBackoff(n int) time.Duration {
	return [...]time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}[min(max(n, 1), 5)-1]
}

// fail records a transient failure and schedules the next retry (none
// after MaxScanAttempts; the daily rescan or a manual retry still applies).
func (s *Scanner) fail(ctx context.Context, digest, msg string) error {
	metrics.ImageScans.WithLabelValues("failed").Inc()
	var n int
	if err := s.DB.QueryRow(ctx, `UPDATE images SET scan_status = 'failed', scan_error = $2, last_scanned_at = now(),
		scan_attempts = scan_attempts + 1 WHERE digest = $1 RETURNING scan_attempts`, digest, truncateStr(msg, 600)).Scan(&n); err != nil {
		return err
	}
	var next *time.Time
	if n < MaxScanAttempts {
		t := time.Now().Add(retryBackoff(n))
		next = &t
	}
	_, err := s.DB.Exec(ctx, `UPDATE images SET next_retry_at = $2 WHERE digest = $1`, digest, next)
	return err
}

// requeueRetries moves failed images whose retry time has come back to pending.
func (s *Scanner) requeueRetries(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `UPDATE images SET scan_status = 'pending'
		WHERE scan_status = 'failed' AND next_retry_at IS NOT NULL AND next_retry_at <= now()`)
	return err
}

func (s *Scanner) scanOne(ctx context.Context, regs []RegistryRef, digest, repo string, tags []string) error {
	if !DigestRe.MatchString(digest) || !ValidRepo(repo) {
		return s.setStatus(ctx, digest, "failed", "Invalid image reference.")
	}
	host := HostOf(repo)
	// Without a matching credential the registry is tried anonymously:
	// many registries outside a fixed list are public (cgr.dev,
	// reg.kyverno.io, …). Only an auth failure means a credential is missing.
	reg := MatchRegistry(regs, repo)
	var auth *Auth
	if reg != nil && reg.CredentialID != nil {
		a, err := ResolveCredential(ctx, s.DB, s.Envelope, s.KV, *reg.CredentialID)
		if err != nil {
			s.Log.Warn("resolve registry credential", "registry", reg.HostPattern, "err", err)
			return s.setStatus(ctx, digest, "failed", fmt.Sprintf("Could not read the credential of registry %s.", reg.HostPattern))
		}
		auth = a
	}
	defer auth.Zero()
	authMsg := func() string {
		if auth != nil {
			return fmt.Sprintf("Registry %s rejected the stored credential.", reg.HostPattern)
		}
		return fmt.Sprintf("%s denied anonymous access: the image is private, or it does not exist there. Add a credential in Settings › Registries.", host)
	}
	requeue := func() error {
		_, _ = s.DB.Exec(context.WithoutCancel(ctx), `UPDATE images SET scan_status = 'pending' WHERE digest = $1`, digest)
		return ctx.Err()
	}
	scannedBy, note := "digest", ""
	out, err := s.Runner.Scan(ctx, repo+"@"+digest, auth)
	s.recordPull(ctx, reg, err)
	if err != nil {
		if ctx.Err() != nil {
			return requeue()
		}
		var se *ScanError
		if errors.As(err, &se) && se.Auth {
			return s.setStatus(ctx, digest, "missing_credential", authMsg())
		}
		if !errors.As(err, &se) || !se.NotFound {
			return s.fail(ctx, digest, "trivy: "+err.Error())
		}
		// The digest is not in the registry (built or retagged locally,
		// e.g. kind node images). Public images are still worth scanning:
		// scan the registry's image with the same tag, clearly marked.
		tag := fallbackTag(tags)
		if tag == "" {
			return s.setStatus(ctx, digest, "unavailable", fmt.Sprintf(
				"This digest is not in %s: the image was built or retagged locally (e.g. kind node images), and it has no tag to scan instead.", host))
		}
		out, err = s.Runner.Scan(ctx, repo+":"+tag, auth)
		s.recordPull(ctx, reg, err)
		if err != nil {
			if ctx.Err() != nil {
				return requeue()
			}
			switch {
			case errors.As(err, &se) && se.Auth:
				return s.setStatus(ctx, digest, "missing_credential", authMsg())
			case errors.As(err, &se) && se.NotFound:
				return s.setStatus(ctx, digest, "unavailable", fmt.Sprintf(
					"This digest is not in %s (built or retagged locally, e.g. kind node images), and tag %s is not there either.", host, tag))
			}
			return s.fail(ctx, digest, fmt.Sprintf("This digest is not in %s; scanning tag %s instead failed: trivy: %s", host, tag, err.Error()))
		}
		scannedBy, note = "tag", TagScanNote(tag)
	}
	vulns, err := ParseTrivy(bytes.NewReader(out))
	if err != nil {
		return s.fail(ctx, digest, err.Error())
	}
	if err := s.saveResults(ctx, digest, repo, vulns, scannedBy, note); err != nil {
		return err
	}
	metrics.ImageScans.WithLabelValues("scanned").Inc()
	return nil
}

// recordPull stores the last pull through a registry entry (F10). A
// "not found" is a successful pull from the registry's point of view.
func (s *Scanner) recordPull(ctx context.Context, reg *RegistryRef, err error) {
	if reg == nil || ctx.Err() != nil {
		return
	}
	var se *ScanError
	ok := err == nil || errors.As(err, &se) && se.NotFound
	reason := ""
	if !ok {
		reason = truncateStr("trivy: "+err.Error(), 300)
		if errors.As(err, &se) && se.Auth {
			reason = "the registry rejected the credential"
		}
	}
	if _, uerr := s.DB.Exec(ctx, `UPDATE registries SET last_pull_at = now(), last_pull_ok = $2, last_pull_error = $3 WHERE id = $1`,
		reg.ID, ok, reason); uerr != nil {
		s.Log.Warn("record registry pull", "registry", reg.HostPattern, "err", uerr)
	}
}

// saveResults replaces an image's vulnerabilities, keeping first_seen_at of
// those already known, updates the counts and emits vuln.critical for
// critical CVEs this digest did not have before (when it is running).
//
// scannedBy is "digest" or "tag". vuln.critical is emitted for digest scans
// only: a tag scan describes the registry's image with that tag, not what
// runs, so it must not page anyone as "critical CVE in a running image". Its
// results are still stored and shown (scanned_by=tag, scan_note).
func (s *Scanner) saveResults(ctx context.Context, digest, repo string, vulns []Vuln, scannedBy, note string) error {
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
		if _, err := tx.Exec(ctx, `UPDATE images SET scan_status = 'scanned', scan_error = '', last_scanned_at = now(), scan_attempts = 0, next_retry_at = NULL,
			critical = $2, high = $3, medium = $4, low = $5, scanned_by = $6, scan_note = $7 WHERE digest = $1`,
			digest, len(counts["critical"]), len(counts["high"]), len(counts["medium"]), len(counts["low"]), scannedBy, truncateStr(note, 600)); err != nil {
			return err
		}
		if len(newCrit) == 0 || scannedBy != "digest" {
			return nil
		}
		return s.emitCritical(ctx, tx, digest, repo, tags, newCrit)
	})
}

// emitCritical records new critical CVEs of a digest scan for every cluster
// running the image (F9): one activity row per item now, one grouped
// vuln.critical per cluster when the scan run ends (flushCritical).
func (s *Scanner) emitCritical(ctx context.Context, tx pgx.Tx, digest, repo string, tags []string, newCrit map[string]Vuln) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT u.cluster_id FROM image_usage u WHERE u.digest = $1`, digest)
	if err != nil {
		return err
	}
	var clusters []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		clusters = append(clusters, id)
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
	for _, cid := range clusters {
		cid := cid
		for _, id := range ids {
			v := newCrit[id]
			tag, err := tx.Exec(ctx, `INSERT INTO pending_vuln_alerts (cluster_id, digest, image, cve_id, package, fixed_in)
				VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, cid, digest, image, id, strings.TrimSpace(v.Package+" "+v.Installed), v.FixedIn)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				continue // already alerted (a CVE that disappeared and came back)
			}
			if err := activity.Record(ctx, tx, activity.Entry{ActorKind: "system", Action: notify.VulnCritical, ObjectType: "image", ObjectID: digest,
				ClusterID: &cid, Details: map[string]any{"cve_id": id, "image": image, "package": v.Package, "fixed_in": v.FixedIn}}); err != nil {
				return err
			}
		}
	}
	return nil
}

// flushCritical sends one vuln.critical per cluster for the CVEs collected
// during the scan run: counts, the top 5 and a link (F9).
func (s *Scanner) flushCritical(ctx context.Context) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM pending_vuln_alerts WHERE sent_at < now() - interval '180 days'`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE pending_vuln_alerts p SET sent_at = now() FROM clusters c
			WHERE c.id = p.cluster_id AND p.sent_at IS NULL
			RETURNING p.cluster_id, c.name, p.digest, p.image, p.cve_id, p.package, p.fixed_in`)
		if err != nil {
			return err
		}
		type item struct{ digest, image, cve, pkg, fix string }
		by := map[uuid.UUID][]item{}
		names := map[uuid.UUID]string{}
		for rows.Next() {
			var cid uuid.UUID
			var name string
			var it item
			if err := rows.Scan(&cid, &name, &it.digest, &it.image, &it.cve, &it.pkg, &it.fix); err != nil {
				rows.Close()
				return err
			}
			by[cid] = append(by[cid], it)
			names[cid] = name
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for cid, items := range by {
			sort.Slice(items, func(i, j int) bool {
				if (items[i].fix != "") != (items[j].fix != "") {
					return items[i].fix != "" // fixable first
				}
				if items[i].cve != items[j].cve {
					return items[i].cve > items[j].cve // newest CVE ids first
				}
				return items[i].image < items[j].image
			})
			images := map[string]bool{}
			payload := make([]map[string]any, 0, len(items))
			for _, it := range items {
				images[it.digest] = true
				payload = append(payload, map[string]any{"digest": it.digest, "cve_id": it.cve})
			}
			var top []string
			for _, it := range items[:min(5, len(items))] {
				fix := it.fix
				if fix == "" {
					fix = "no fix yet"
				}
				top = append(top, fmt.Sprintf("%s in %s (%s, fixed in %s)", it.cve, it.image, it.pkg, fix))
			}
			link := "/security?cluster=" + cid.String()
			if s.Link != nil {
				link = s.Link(link)
			}
			if err := notify.Emit(ctx, tx, notify.Event{
				Type:  notify.VulnCritical,
				Key:   notify.VulnCritical + ":" + cid.String() + ":" + uuid.NewString(),
				Title: fmt.Sprintf("%s in %s on %s", countNoun(len(items), "new critical CVE"), countNoun(len(images), "running image"), names[cid]),
				Link:  link,
				Fields: map[string]string{"cluster": names[cid], "new": fmt.Sprint(len(items)), "images": fmt.Sprint(len(images)),
					"top": strings.Join(top, "; ")},
				Payload: map[string]any{"cluster_id": cid.String(), "items": payload},
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func shortDigest(d string) string {
	h := strings.TrimPrefix(d, "sha256:")
	if len(h) > 12 {
		h = h[:12]
	}
	return "sha256:" + h
}
