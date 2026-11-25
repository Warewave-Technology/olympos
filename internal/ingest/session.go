package ingest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Keys and prefixes in this package are relative to the endpoint's bucket:
// what follows /olympos/ in the request path, so "<run-id>/.backup" or
// "<run-id>/metadata/db1.sql".

// The kinds of run a session serves.
const (
	KindBackup  = "backup"
	KindRestore = "restore"
)

// Stop reasons the session sets itself.
const (
	// ReasonQuota: the run wrote more than MaxBytes.
	ReasonQuota = "quota"
	// ReasonCaptureLimit: a body the manifest needs was over its capture
	// limit, or the kept bodies together were.
	ReasonCaptureLimit = "capture limit"
)

const (
	// reasonRestart is the revoke reason start-up recovery records.
	reasonRestart = "server restart"
	// The capture limits: a kept .backup (it lists every file of the
	// backup), a metadata/*.sql, a count.txt, and all kept bodies of one
	// session together.
	maxCaptureBackup = 64 << 20
	maxCaptureMeta   = 1 << 20
	maxCaptureCount  = 64
	maxCaptureTotal  = 64 << 20
	// revokeTimeout bounds the audit write of a revoke.
	revokeTimeout = 10 * time.Second
	// base32Alphabet is RFC 4648 base32, the access key's characters.
	base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

var (
	// ErrTooManyRuns means maxRuns sessions are open already.
	ErrTooManyRuns = errors.New("ingest: too many native runs are open")
	// ErrQuota means the run wrote more than its MaxBytes. The session is
	// stopped with ReasonQuota.
	ErrQuota = errors.New("ingest: the run wrote more than its byte limit")
)

// Scope says which prefixes a credential may use. Prefixes end in "/".
type Scope struct {
	// Write is a backup's own run prefix, "<run-id>/", which it may write,
	// list and read back. It is empty for a restore.
	Write string `json:"write,omitempty"`
	// Read are the other prefixes it may read and list: a backup's base
	// chain, a restore's chain.
	Read []string `json:"read,omitempty"`
}

// ObjectRecord is one stored object.
type ObjectRecord struct {
	Key    string // relative to the bucket: "<run-id>/<key>"
	Size   int64
	SHA256 string // lower-case hex
}

// Sink stores the objects a backup writes, under bucket-relative keys
// ("<run-id>/<key>"). Put reads r to EOF and returns
// what it stored; an error from r (a bad digest, an aborted upload) must
// abort the object.
type Sink interface {
	Put(ctx context.Context, key string, r io.Reader) (ObjectRecord, error)
}

// Source serves the objects a run may read, by bucket-relative key and
// prefix. Open returns an error that wraps fs.ErrNotExist for a key that does
// not exist.
type Source interface {
	Open(ctx context.Context, key string) (io.ReadCloser, ObjectRecord, error)
	List(ctx context.Context, prefix string) ([]ObjectRecord, error)
}

// OpenOptions describe the run a session is opened for.
type OpenOptions struct {
	// RunID is the backup run or the restore request.
	RunID uuid.UUID
	// Kind is KindBackup or KindRestore.
	Kind string
	// Scope must write exactly "<RunID>/" for a backup, and nothing for a
	// restore, which must read something.
	Scope Scope
	// TTL is the credential's lifetime from now.
	TTL time.Duration
	// Sink takes a backup's objects. Source serves the Read prefixes and is
	// required when there are any.
	Sink   Sink
	Source Source
	// MaxBytes is how many bytes a backup may write in all (required for a
	// backup).
	MaxBytes int64
}

func (o OpenOptions) validate() error {
	if o.RunID == uuid.Nil {
		return errors.New("ingest: open: no run ID")
	}
	if o.TTL <= 0 {
		return errors.New("ingest: open: the TTL must be positive")
	}
	for _, p := range o.Scope.Read {
		if !validPrefix(p) {
			return fmt.Errorf("ingest: open: read prefix %q is not a bucket prefix ending in /", p)
		}
	}
	if len(o.Scope.Read) > 0 && o.Source == nil {
		return errors.New("ingest: open: a read scope needs a Source")
	}
	switch o.Kind {
	case KindBackup:
		if o.Scope.Write != o.RunID.String()+"/" {
			return fmt.Errorf("ingest: open: a backup writes only its own prefix %s/, not %q", o.RunID, o.Scope.Write)
		}
		if o.Sink == nil {
			return errors.New("ingest: open: a backup needs a Sink")
		}
		if o.MaxBytes <= 0 {
			return errors.New("ingest: open: a backup needs a positive MaxBytes")
		}
	case KindRestore:
		if o.Scope.Write != "" {
			return errors.New("ingest: open: a restore writes nothing")
		}
		if len(o.Scope.Read) == 0 {
			return errors.New("ingest: open: a restore needs a read scope")
		}
	default:
		return fmt.Errorf("ingest: open: unknown kind %q", o.Kind)
	}
	return nil
}

// validPrefix: "a/" or "a/b/", with no empty, "." or ".." segment.
func validPrefix(p string) bool {
	rest, ok := strings.CutSuffix(p, "/")
	if !ok || rest == "" {
		return false
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Registry holds the open sessions, one per native run, by access key. The
// secrets live here and nowhere else: the database keeps an audit row per
// credential with its fingerprint (migration 00026).
type Registry struct {
	db      *store.DB
	fp      *secrets.Fingerprinter
	maxRuns int
	now     func() time.Time

	mu       sync.Mutex
	sessions map[string]*Session
	// opening counts the Opens that hold a slot while they write their row.
	opening int
}

// NewRegistry returns a registry that allows maxRuns open sessions at once.
// now is the clock (time.Now when nil).
func NewRegistry(db *store.DB, fp *secrets.Fingerprinter, maxRuns int, now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{db: db, fp: fp, maxRuns: maxRuns, now: now, sessions: map[string]*Session{}}
}

// Open mints a credential for one run and opens its session. It returns
// ErrTooManyRuns when maxRuns sessions are open; a session holds its slot
// until it is revoked or expires. The caller hands the secret to ClickHouse
// and to nothing else, and revokes the session when the run ends.
func (r *Registry) Open(ctx context.Context, o OpenOptions) (*Session, Credential, error) {
	if err := o.validate(); err != nil {
		return nil, Credential{}, err
	}
	if err := r.reserve(); err != nil {
		return nil, Credential{}, err
	}
	s, cred, err := r.open(ctx, o)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opening--
	if err != nil {
		return nil, Credential{}, err
	}
	r.sessions[cred.AccessKey] = s
	return s, cred, nil
}

// reserve takes a slot, first dropping the sessions that have expired.
func (r *Registry) reserve() error {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, s := range r.sessions {
		if s.expired(now) {
			delete(r.sessions, key)
		}
	}
	if len(r.sessions)+r.opening >= r.maxRuns {
		return ErrTooManyRuns
	}
	r.opening++
	return nil
}

func (r *Registry) open(ctx context.Context, o OpenOptions) (*Session, Credential, error) {
	cred, err := mint()
	if err != nil {
		return nil, Credential{}, err
	}
	now := r.now()
	s := &Session{
		reg: r, runID: o.RunID, kind: o.Kind,
		scope:    Scope{Write: o.Scope.Write, Read: slices.Clone(o.Scope.Read)},
		sink:     o.Sink,
		source:   o.Source,
		maxBytes: o.MaxBytes, accessKey: cred.AccessKey, expires: now.Add(o.TTL),
		secret: cred.Secret, stopped: make(chan string, 1), captured: map[string][]byte{},
		ended: make(chan struct{}), rate: rateBucket{tokens: maxRate, last: now},
	}
	if err := insertCredential(ctx, r.db, cred.AccessKey, o.RunID, o.Kind, s.scope,
		r.fp.Fingerprint([]byte(cred.Secret)), now, s.expires); err != nil {
		return nil, Credential{}, fmt.Errorf("ingest: record credential: %w", err)
	}
	return s, cred, nil
}

// mint returns a fresh access key (OLY and 17 base32 characters, 85 bits) and
// a 40-character secret (30 random bytes, URL-safe base64, which needs no
// quoting in a ClickHouse statement).
func mint() (Credential, error) {
	b := make([]byte, 17+30)
	if _, err := rand.Read(b); err != nil {
		return Credential{}, fmt.Errorf("ingest: mint credential: %w", err)
	}
	key := []byte("OLY")
	for _, c := range b[:17] {
		key = append(key, base32Alphabet[c&31])
	}
	return Credential{AccessKey: string(key), Secret: base64.RawURLEncoding.EncodeToString(b[17:])}, nil
}

// Lookup returns the session of accessKey and its secret, for Verify. A key
// that is unknown, revoked, expired or of a stopped session is not found.
func (r *Registry) Lookup(accessKey string) (*Session, string, bool) {
	r.mu.Lock()
	s := r.sessions[accessKey]
	r.mu.Unlock()
	if s == nil {
		return nil, "", false
	}
	now := r.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || s.stopReason != "" || s.expired(now) {
		return nil, "", false
	}
	return s, s.secret, true
}

// MarkInterrupted revokes, with the reason "server restart", every credential
// that is not revoked yet. It is called at start-up, before any Open: the
// secrets of those credentials were lost with the previous process.
func (r *Registry) MarkInterrupted(ctx context.Context) error {
	if err := revokeAllCredentials(ctx, r.db, reasonRestart, r.now()); err != nil {
		return fmt.Errorf("ingest: mark interrupted credentials: %w", err)
	}
	return nil
}

// openRuns counts the sessions that hold a slot: not revoked, not expired.
func (r *Registry) openRuns() int {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.sessions {
		if !s.expired(now) {
			n++
		}
	}
	return n
}

func (r *Registry) forget(accessKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, accessKey)
}

// Session is the endpoint's state for one run: its credential, its scope,
// where its objects go and come from, what it wrote, and its in-memory
// .lock. It is safe for concurrent use.
//
// The run's owner reads Stopped, Objects and Captured, and calls Revoke when
// the run ends. The handler calls the hooks: RecordObject, AddBytes,
// CaptureLimit and Capture, Stop, and the lock methods.
type Session struct {
	reg       *Registry
	runID     uuid.UUID
	kind      string
	scope     Scope
	sink      Sink
	source    Source
	maxBytes  int64
	accessKey string
	expires   time.Time
	stopped   chan string // buffered: the one stop reason
	// ended is closed when the session is stopped or revoked, so that the
	// handler aborts what is still streaming. Unlike stopped, every
	// goroutine can wait for it.
	ended   chan struct{}
	endOnce sync.Once

	mu         sync.Mutex
	secret     string // dropped on Revoke
	revoked    bool
	stopReason string
	written    int64
	objects    []ObjectRecord
	captured   map[string][]byte
	// capturedBytes is the size of all captured bodies.
	capturedBytes int64
	lock          []byte
	hasLock       bool
	// rate limits the session's requests; spilled is how many bytes of
	// out-of-order parts it holds on disk. Both are the handler's.
	rate    rateBucket
	spilled int64
}

// RunID is the run the session was opened for.
func (s *Session) RunID() uuid.UUID { return s.runID }

// Kind is KindBackup or KindRestore.
func (s *Session) Kind() string { return s.kind }

// Scope returns a copy of the session's scope.
func (s *Session) Scope() Scope {
	return Scope{Write: s.scope.Write, Read: slices.Clone(s.scope.Read)}
}

// Sink takes the run's objects (nil for a restore).
func (s *Session) Sink() Sink { return s.sink }

// Source serves the run's Read prefixes (nil when it has none).
func (s *Session) Source() Source { return s.source }

func (s *Session) expired(now time.Time) bool { return !now.Before(s.expires) }

// Revoke ends the credential: Lookup no longer finds it, the secret is
// dropped from memory, and the audit row gets revoked_at and reason. Only the
// first call counts. What the session recorded stays readable. A failed
// audit write is logged; start-up recovery revokes the row later.
func (s *Session) Revoke(reason string) {
	s.mu.Lock()
	if s.revoked {
		s.mu.Unlock()
		return
	}
	s.revoked = true
	s.secret = ""
	s.mu.Unlock()
	s.end()
	s.reg.forget(s.accessKey)

	ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
	defer cancel()
	if err := revokeCredential(ctx, s.reg.db, s.accessKey, reason, s.reg.now()); err != nil {
		slog.Default().Warn("ingest: could not record a revoked credential; start-up recovery revokes it",
			"run", s.runID, "access_key", s.accessKey, "err", err)
	}
}

// Stopped delivers the reason the session was stopped: a limit, a failed
// destination or a bad digest. The run's owner then ends the run (KILL
// QUERY) and revokes the session. It delivers one value, once.
func (s *Session) Stopped() <-chan string { return s.stopped }

// Stop stops the session for reason: Lookup no longer finds its key, and
// Stopped delivers the reason. Only the first call counts. It is the
// handler's hook; it does not revoke the credential.
func (s *Session) Stop(reason string) {
	if reason == "" {
		reason = "stopped"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopReason != "" {
		return
	}
	s.stopReason = reason
	s.stopped <- reason // never blocks: the buffer holds the one reason
	s.end()
}

func (s *Session) end() { s.endOnce.Do(func() { close(s.ended) }) }

// live reports whether the session still serves requests at now: it is not
// stopped, revoked or expired. The handler checks it before every write.
func (s *Session) live(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.revoked && s.stopReason == "" && !s.expired(now)
}

// allow takes one request from the session's rate bucket.
func (s *Session) allow(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rate.take(now)
}

// reserveSpill counts n more bytes held on disk and reports whether they fit
// under limit; when they do not, nothing is counted.
func (s *Session) reserveSpill(n, limit int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.spilled+n > limit {
		return false
	}
	s.spilled += n
	return true
}

// releaseSpill uncounts n bytes that left the disk.
func (s *Session) releaseSpill(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spilled -= n
}

// AddBytes counts n more bytes written by the run. Past MaxBytes it stops
// the session with ReasonQuota and returns ErrQuota. Handler hook.
func (s *Session) AddBytes(n int64) error {
	s.mu.Lock()
	s.written += n
	over := s.written > s.maxBytes
	s.mu.Unlock()
	if over {
		s.Stop(ReasonQuota)
		return ErrQuota
	}
	return nil
}

// RecordObject records an object the Sink stored. Handler hook.
func (s *Session) RecordObject(rec ObjectRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects = append(s.objects, rec)
}

// Objects returns the recorded objects, in the order they were stored.
func (s *Session) Objects() []ObjectRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.objects)
}

// CaptureLimit returns how many bytes of key's body the session keeps, or 0
// when it keeps none. key is bucket-relative ("<run-id>/.backup"). Under the
// run's own prefix it keeps the bodies the manifest is built from: .backup (up
// to 64 MiB), metadata/*.sql (up to 1 MiB each) and data/.../count.txt (up to
// 64 bytes), and at most 64 MiB of them in all. The handler copies at most
// this much, and one byte more so that Capture sees a body that is too large,
// while the body streams.
func (s *Session) CaptureLimit(key string) int64 {
	if s.scope.Write == "" {
		return 0
	}
	rel, ok := strings.CutPrefix(key, s.scope.Write)
	switch {
	case !ok:
		return 0
	case rel == ".backup":
		return maxCaptureBackup
	case strings.HasPrefix(rel, "metadata/") && strings.HasSuffix(rel, ".sql"):
		return maxCaptureMeta
	case strings.HasPrefix(rel, "data/") && path.Base(rel) == "count.txt":
		return maxCaptureCount
	}
	return 0
}

// Capture keeps a copy of key's body when CaptureLimit is not 0, and reports
// whether it did. The handler calls it after the body's digest was checked.
// A body over its limit, or one that would take the kept bodies over 64 MiB,
// is not kept, and it stops the session with ReasonCaptureLimit: the manifest
// cannot be built without it. Handler hook.
func (s *Session) Capture(key string, body []byte) bool {
	limit := s.CaptureLimit(key)
	if limit == 0 {
		return false
	}
	s.mu.Lock()
	total := s.capturedBytes + int64(len(body)) - int64(len(s.captured[key]))
	ok := int64(len(body)) <= limit && total <= maxCaptureTotal
	if ok {
		s.captured[key] = bytes.Clone(body)
		s.capturedBytes = total
	}
	s.mu.Unlock()
	if !ok {
		s.Stop(ReasonCaptureLimit)
	}
	return ok
}

// Captured returns a copy of the kept body of key, a bucket-relative key
// ("<run-id>/.backup").
func (s *Session) Captured(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.captured[key]
	return bytes.Clone(b), ok
}

// LockKey is the key of the run's .lock ("<run-id>/.lock"), or "" for a
// session that writes nothing. The lock never reaches the Sink: the lock
// methods keep it in memory, and its delete is real.
func (s *Session) LockKey() string {
	if s.scope.Write == "" {
		return ""
	}
	return s.scope.Write + ".lock"
}

// PutLock stores the .lock's body. Handler hook.
func (s *Session) PutLock(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lock, s.hasLock = bytes.Clone(body), true
}

// Lock returns a copy of the .lock's body, if there is one. Handler hook.
func (s *Session) Lock() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.lock), s.hasLock
}

// DeleteLock removes the .lock and reports whether there was one. Handler
// hook.
func (s *Session) DeleteLock() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	had := s.hasLock
	s.lock, s.hasLock = nil, false
	return had
}

// String, GoString and LogValue never print the secret.

func (s *Session) String() string   { return fmt.Sprintf("ingest.Session{run %s, %s}", s.runID, s.kind) }
func (s *Session) GoString() string { return s.String() }

// LogValue logs the run and the kind.
func (s *Session) LogValue() slog.Value {
	return slog.GroupValue(slog.String("run", s.runID.String()), slog.String("kind", s.kind))
}

func (c Credential) String() string   { return "ingest.Credential{" + c.AccessKey + ", secret redacted}" }
func (c Credential) GoString() string { return c.String() }

// LogValue logs the access key only.
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(slog.String("access_key", c.AccessKey))
}
