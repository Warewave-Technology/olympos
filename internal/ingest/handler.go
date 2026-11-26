package ingest

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

// Stop reasons the handler sets. The session sets ReasonQuota and
// ReasonCaptureLimit itself.
const (
	// ReasonRate: the run sent more than 200 requests a second for 30
	// seconds in a row (rateStorm). A shorter burst is answered 503 SlowDown
	// and the run goes on (R17).
	ReasonRate = "rate"
	// ReasonBadDigest: a body did not match its x-amz-content-sha256 or
	// Content-MD5. The object had already streamed to the destinations.
	ReasonBadDigest = "bad digest"
	// ReasonIncompleteBody: a body ended before its length, mostly a dropped
	// connection, while it streamed.
	ReasonIncompleteBody = "incomplete body"
	// ReasonDestination: no destination took an object.
	ReasonDestination = "destination failed"
	// ReasonSource: an object the run reads could not be read.
	ReasonSource = "source failed"
	// ReasonSpill: a part that came before its turn could not be held on
	// disk (a disk error). A full spill budget does not stop a run: the part
	// is refused 503 SlowDown and sent again (R18).
	ReasonSpill = "spill failed"
	// ReasonMultipart: a multipart upload broke the protocol: a part sent
	// again with another body, or a part list that does not match.
	ReasonMultipart = "multipart"
	// ReasonRewrite: the run sent another body for an object it had stored,
	// or another part list for an upload it had completed. Objects are never
	// overwritten, so the client broke the protocol.
	ReasonRewrite = "object rewritten"
	// ReasonUploadAborted: the run aborted a multipart upload. Its object is
	// partly on the destinations and cannot be written again under its name,
	// so the run cannot succeed.
	ReasonUploadAborted = "upload aborted"
)

const (
	bucket = "olympos"
	// maxRate is the requests a session may send per second, and its burst.
	maxRate = 200
	// rateStorm is how long a session may stay over its rate before it is
	// stopped with ReasonRate.
	rateStorm = 30 * time.Second
	// maxKeyLen is S3's key limit.
	maxKeyLen = 1024
	// maxListKeys is S3's page size limit and the default max-keys.
	maxListKeys = 1000
	// maxLockSize bounds a .lock body (ClickHouse writes a UUID).
	maxLockSize = 64 << 10
	// maxCompleteSize bounds a CompleteMultipartUpload body (10,000 parts).
	maxCompleteSize = 2 << 20
	maxPartNumber   = 10000
	// defaultSpillLimit is how many bytes of out-of-order parts a run may hold
	// on disk at once.
	defaultSpillLimit = 1 << 30
	// maxUploads is how many multipart uploads a run may have open at once.
	maxUploads = 256
	chunkSize  = 32 << 10
	// defaultWriteTimeout bounds the write of one chunk of a served object
	// (WithWriteTimeout).
	defaultWriteTimeout = 2 * time.Minute
	// emptySHA256 is the SHA-256 of an empty body.
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// The operations, by their S3 names. Only the first eight are served.
const (
	opListObjects     = "ListObjects"
	opPutObject       = "PutObject"
	opGetObject       = "GetObject"
	opDeleteObject    = "DeleteObject"
	opCreateMultipart = "CreateMultipartUpload"
	opUploadPart      = "UploadPart"
	opCompleteUpload  = "CompleteMultipartUpload"
	opAbortUpload     = "AbortMultipartUpload"

	opListObjectsV2  = "ListObjectsV2"
	opCopyObject     = "CopyObject"
	opUploadPartCopy = "UploadPartCopy"
	opDeleteObjects  = "DeleteObjects"
	opHeadBucket     = "HeadBucket"
	opHeadObject     = "HeadObject"
	opOther          = "Other"
)

var served = []string{opListObjects, opPutObject, opGetObject, opDeleteObject,
	opCreateMultipart, opUploadPart, opCompleteUpload, opAbortUpload}

// Internal causes of a failed body copy.
var (
	errBodyLost    = errors.New("ingest: the request body ended early")
	errRunStopped  = errors.New("ingest: the run was stopped")
	errWrite       = errors.New("ingest: write failed")
	errSinkDone    = errors.New("ingest: the sink returned")
	errDigest      = errors.New("ingest: the body does not match its digest")
	errAborted     = errors.New("ingest: the multipart upload was aborted")
	errMultipart   = errors.New("ingest: the multipart upload broke the protocol")
	errTooLarge    = errors.New("ingest: the body is too large")
	errSourceShort = errors.New("ingest: the source object ended early")
)

// Metrics are the endpoint's Prometheus metrics. Register it as one
// collector.
type Metrics struct {
	requests *prometheus.CounterVec
	bytes    prometheus.Counter
	refused  *prometheus.CounterVec
	stops    *prometheus.CounterVec
	runs     *prometheus.Desc

	mu  sync.Mutex
	reg *Registry
}

// NewMetrics returns the endpoint's metrics. olympos_ingest_runs reads the
// registry of the handler they are given to.
func NewMetrics() *Metrics {
	return &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "olympos_ingest_requests_total", Help: "Ingest endpoint requests by S3 operation and HTTP status.",
		}, []string{"op", "code"}),
		bytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "olympos_ingest_bytes_total", Help: "Object bytes the ingest endpoint received from native runs.",
		}),
		refused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "olympos_ingest_refused_total", Help: "Ingest endpoint requests that failed, by S3 error code.",
		}, []string{"reason"}),
		stops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "olympos_ingest_stops_total", Help: "Ingest sessions stopped before their run ended, by stop reason.",
		}, []string{"reason"}),
		runs: prometheus.NewDesc("olympos_ingest_runs", "Native runs with an open ingest session.", nil, nil),
	}
}

func (m *Metrics) attach(reg *Registry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reg = reg
	count := func(reason string) { m.stops.WithLabelValues(reason).Inc() }
	reg.onStop.Store(&count)
}

// Describe implements prometheus.Collector.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.requests.Describe(ch)
	m.bytes.Describe(ch)
	m.refused.Describe(ch)
	m.stops.Describe(ch)
	ch <- m.runs
}

// Collect implements prometheus.Collector.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.requests.Collect(ch)
	m.bytes.Collect(ch)
	m.refused.Collect(ch)
	m.stops.Collect(ch)
	m.mu.Lock()
	reg := m.reg
	m.mu.Unlock()
	n := 0
	if reg != nil {
		n = reg.openRuns()
	}
	ch <- prometheus.MustNewConstMetric(m.runs, prometheus.GaugeValue, float64(n))
}

// rateBucket is a token bucket of perSecond requests a second, with bursts
// of perSecond. Its zero value is full at the first take.
type rateBucket struct {
	tokens float64
	last   time.Time
}

func (b *rateBucket) take(now time.Time, perSecond float64) bool {
	if b.last.IsZero() {
		b.tokens, b.last = perSecond, now
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(perSecond, b.tokens+d.Seconds()*perSecond)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// handler serves the S3 subset ClickHouse uses for native backups (spike §1),
// path style, on the one bucket "olympos". Every key is bucket-relative,
// "<run-id>/<key>", and is taken from the decoded r.URL.Path, the same path
// Verify signs.
type handler struct {
	reg *Registry
	log *slog.Logger
	m   *Metrics

	spillDir   string // "" is the system's temporary directory
	spillLimit int64
	// rate is the requests a session may send per second (maxRate; a test
	// changes it).
	rate float64
	// writeTimeout bounds the write of one chunk of a served object.
	writeTimeout time.Duration

	mu      sync.Mutex
	uploads map[string]*upload
}

// HandlerOption configures NewHandler.
type HandlerOption func(*handler)

// WithSpillDir sets the directory that holds out-of-order parts until their
// turn. The default is the system's temporary directory.
func WithSpillDir(dir string) HandlerOption { return func(h *handler) { h.spillDir = dir } }

// WithSpillLimit sets how many bytes of out-of-order parts one run may hold
// on disk at once. The default is 1 GiB.
func WithSpillLimit(n int64) HandlerOption { return func(h *handler) { h.spillLimit = n } }

// WithWriteTimeout sets how long the write of one chunk of an object the
// endpoint serves may take: a client that stops reading in the middle of a
// GET then no longer holds the handler. The default is 2 minutes.
func WithWriteTimeout(d time.Duration) HandlerOption { return func(h *handler) { h.writeTimeout = d } }

// NewHandler returns the ingest endpoint for the sessions of reg. A nil log
// is slog.Default and nil metrics are not exported.
func NewHandler(reg *Registry, log *slog.Logger, m *Metrics, opts ...HandlerOption) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	if m == nil {
		m = NewMetrics()
	}
	m.attach(reg)
	h := &handler{reg: reg, log: log, m: m, spillLimit: defaultSpillLimit, rate: maxRate, writeTimeout: defaultWriteTimeout,
		uploads: map[string]*upload{}}
	for _, o := range opts {
		o(h)
	}
	return h
}

// etag is the ETag of a body: the first 32 hex characters of its SHA-256,
// quoted. The spike's endpoint answered so, and ClickHouse took it; the
// handler keeps no MD5 of stored objects.
func etag(sha256Hex string) string {
	if len(sha256Hex) < 32 {
		return ""
	}
	return `"` + sha256Hex[:32] + `"`
}

func (d bodyDigest) etag() string { return etag(hex.EncodeToString(d.sha.Sum(nil))) }

// request is one request on its way through the handler.
type request struct {
	h   *handler
	w   *statusWriter
	r   *http.Request
	id  string
	op  string
	key string // the object key, or a list's prefix
	s   *Session
	// payloadHash is the declared x-amz-content-sha256.
	payloadHash string
	failed      *s3Error
	aborted     bool
	// unwatch stops watchEnd, when it runs.
	unwatch func()
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := &request{h: h, w: &statusWriter{ResponseWriter: w}, r: r, id: randomHex(8), op: opOther}
	q.w.Header().Set("X-Amz-Request-Id", q.id)
	defer q.finish()
	if err := q.serve(); err != nil {
		q.failed = err
		writeError(q.w, err, r.URL.Path, q.id)
	}
}

func (q *request) serve() *s3Error {
	if err := q.classify(); err != nil {
		return err
	}
	if err := q.authenticate(); err != nil {
		return err
	}
	switch q.op {
	case opListObjects:
		return q.list()
	case opPutObject:
		return q.put()
	case opGetObject:
		return q.get()
	case opDeleteObject:
		return q.deleteObject()
	case opCreateMultipart:
		return q.createUpload()
	case opUploadPart:
		return q.uploadPart()
	case opCompleteUpload:
		return q.completeUpload()
	case opAbortUpload:
		return q.abortUpload()
	}
	return denied("The operation is not allowed.")
}

// finish counts and logs the request. It never logs a header or a body.
func (q *request) finish() {
	if q.unwatch != nil {
		q.unwatch()
	}
	status := q.w.status
	if status == 0 {
		status = http.StatusOK
	}
	code := strconv.Itoa(status)
	if q.aborted {
		code = "aborted"
	}
	q.h.m.requests.WithLabelValues(q.op, code).Inc()
	attrs := []slog.Attr{slog.String("op", q.op), slog.String("key", q.key), slog.String("status", code),
		slog.String("request_id", q.id)}
	if q.s != nil {
		attrs = append(attrs, slog.String("run", q.s.RunID().String()))
	}
	level := slog.LevelDebug
	if q.failed != nil {
		q.h.m.refused.WithLabelValues(q.failed.code).Inc()
		attrs = append(attrs, slog.String("error", q.failed.code))
		switch {
		case q.s == nil:
			// Refused before any session was found: anyone can send these,
			// so they are counted but not logged above Debug.
		case q.failed.status == http.StatusNotFound, q.failed.code == errSlowDown.code:
			// A 503 SlowDown (the rate, the spill budget) is back-pressure
			// the client retries, not a refusal.
			level = slog.LevelInfo
		default:
			level = slog.LevelWarn
		}
	}
	if q.aborted {
		level = slog.LevelWarn
	}
	q.h.log.LogAttrs(q.r.Context(), level, "ingest request", attrs...)
}

// stop stops the request's session for reason.
func (q *request) stop(reason string) {
	q.h.log.Warn("ingest: stopping the run", "run", q.s.RunID().String(), "reason", reason, "op", q.op, "key", q.key)
	q.s.Stop(reason)
}

// classify finds the operation and the key, and refuses what is not served
// before any credential is looked at: a path outside the bucket (another
// bucket, or a virtual-host request, whose path lacks /olympos/), an
// operation outside the table, and a key that is not plain.
func (q *request) classify() *s3Error {
	r := q.r
	// Path style is the path rule below: a virtual-host request has no
	// /olympos/ in its path. The Host is not looked at, so a server named
	// olympos.<domain> works.
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return denied("The query string is malformed.")
	}
	// Newer AWS SDKs name the operation in x-id; it changes nothing.
	query.Del("x-id")

	p := r.URL.Path
	switch {
	case p == "/"+bucket || p == "/"+bucket+"/":
		q.op = bucketOp(r.Method, query)
	case strings.HasPrefix(p, "/"+bucket+"/"):
		q.key = p[len(bucket)+2:]
		q.op = objectOp(r.Method, query, r.Header.Get("X-Amz-Copy-Source") != "")
	default:
		return denied("Only the bucket " + bucket + " is served.")
	}
	if !slices.Contains(served, q.op) {
		return denied(q.op + " is not allowed.")
	}
	if q.op != opListObjects {
		// The signature covers the decoded path, so an encoded slash would
		// sign one key and look like another.
		if strings.Contains(strings.ToLower(r.URL.RawPath), "%2f") || !validKey(q.key) {
			return denied("The key is not a plain key.")
		}
	}
	return nil
}

func bucketOp(method string, query url.Values) string {
	switch method {
	case http.MethodGet:
		if query.Has("list-type") {
			return opListObjectsV2
		}
		if onlyParams(query, "prefix", "max-keys", "marker") {
			return opListObjects
		}
	case http.MethodHead:
		return opHeadBucket
	case http.MethodPost:
		if query.Has("delete") {
			return opDeleteObjects
		}
	}
	return opOther
}

func objectOp(method string, query url.Values, copySource bool) string {
	switch method {
	case http.MethodPut:
		if len(query) == 2 && query.Has("partNumber") && query.Has("uploadId") {
			if copySource {
				return opUploadPartCopy
			}
			return opUploadPart
		}
		if len(query) == 0 {
			if copySource {
				return opCopyObject
			}
			return opPutObject
		}
	case http.MethodPost:
		if len(query) == 1 && query.Has("uploads") {
			return opCreateMultipart
		}
		if len(query) == 1 && query.Has("uploadId") {
			return opCompleteUpload
		}
	case http.MethodDelete:
		if len(query) == 0 {
			return opDeleteObject
		}
		if len(query) == 1 && query.Has("uploadId") {
			return opAbortUpload
		}
	case http.MethodGet:
		if len(query) == 0 {
			return opGetObject
		}
	case http.MethodHead:
		return opHeadObject
	}
	return opOther
}

func onlyParams(query url.Values, names ...string) bool {
	for name := range query {
		if !slices.Contains(names, name) {
			return false
		}
	}
	return true
}

// ValidKey reports whether k is a key the endpoint serves (validKey): a
// source can refuse to serve, or to be built from, any other.
func ValidKey(k string) bool { return validKey(k) }

// validKey: a key of at most 1024 bytes of printable UTF-8, without a
// backslash, whose "/"-separated segments are never empty, "." or "..". So
// no key starts or ends with "/" or holds "//".
func validKey(k string) bool {
	if k == "" || len(k) > maxKeyLen || !plainText(k) {
		return false
	}
	for _, seg := range strings.Split(k, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// validListPrefix is validKey for a list prefix, which may end in "/".
func validListPrefix(p string) bool {
	if p == "" || len(p) > maxKeyLen || !plainText(p) {
		return false
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if seg == "" && i == len(segs)-1 {
			continue
		}
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func plainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return false
		}
	}
	return true
}

// authenticate checks the signature, finds the session, and takes one
// request from its rate.
func (q *request) authenticate() *s3Error {
	for _, ce := range q.r.Header.Values("Content-Encoding") {
		if strings.Contains(strings.ToLower(ce), "aws-chunked") {
			return denied("aws-chunked bodies are not accepted.")
		}
	}
	now := q.h.reg.now()
	var s *Session
	_, payloadHash, err := Verify(q.r, func(accessKey string) (string, bool) {
		found, secret, ok := q.h.reg.Lookup(accessKey)
		s = found
		return secret, ok
	}, now)
	switch {
	case errors.Is(err, ErrUnknownKey):
		return refused("InvalidAccessKeyId", "The access key is not known, or its run has ended.")
	case errors.Is(err, ErrSignature):
		return refused("SignatureDoesNotMatch", "The request signature does not match.")
	case errors.Is(err, ErrClockSkew):
		return refused("RequestTimeTooSkewed", "The request time is too far from the server's time.")
	case errors.Is(err, ErrUnsignedPayload):
		return denied("The payload must be signed with its SHA-256.")
	case err != nil:
		return denied("Requests must be signed with AWS4-HMAC-SHA256 in the Authorization header.")
	}
	q.s, q.payloadHash = s, payloadHash
	// Over the rate, the request is refused before its body is read, and
	// the run goes on; only a storm stops it (R17).
	if ok, storm := s.allow(now, q.h.rate); !ok {
		if storm {
			q.stop(ReasonRate)
		}
		return errSlowDown
	}
	if !s.live(now) {
		return errStopped
	}
	q.watchEnd()
	return nil
}

// watchEnd cuts the request's body when its session ends (a stop, a revoke,
// expiry): a client that stopped sending in the middle of a body would
// otherwise hold the handler in Body.Read. finish stops the watch before the
// handler returns.
func (q *request) watchEnd() {
	rc := http.NewResponseController(q.w)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-q.s.ended:
			_ = rc.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	q.unwatch = func() {
		close(done)
		wg.Wait()
	}
}

// own reports whether key (or a prefix) lies in the run's own prefix.
func (s *Session) own(key string) bool {
	return s.scope.Write != "" && strings.HasPrefix(key, s.scope.Write)
}

// readable reports whether key (or a prefix) lies in a prefix the run reads.
func (s *Session) readable(key string) bool {
	for _, p := range s.scope.Read {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// bodyDigest is what a body copy saw.
type bodyDigest struct {
	sha, md5 hash.Hash
	n        int64
}

// copyBody copies the request body into dst in chunks while it hashes it.
// Before every write it checks that the session is still live and, when
// charge is set, counts the chunk against the run's quota. Errors:
// errBodyLost, errRunStopped, ErrQuota, or errWrite wrapping dst's error.
func (q *request) copyBody(dst io.Writer, charge bool) (bodyDigest, error) {
	d := bodyDigest{sha: sha256.New(), md5: md5.New()}
	buf := make([]byte, chunkSize)
	for {
		n, rerr := q.r.Body.Read(buf)
		if n > 0 {
			if !q.s.live(q.h.reg.now()) {
				return d, errRunStopped
			}
			if charge {
				if err := q.s.AddBytes(int64(n)); err != nil {
					return d, err
				}
				q.h.m.bytes.Add(float64(n))
			}
			d.sha.Write(buf[:n])
			d.md5.Write(buf[:n])
			d.n += int64(n)
			if _, err := dst.Write(buf[:n]); err != nil {
				return d, fmt.Errorf("%w: %w", errWrite, err)
			}
		}
		if rerr == io.EOF {
			return d, nil
		}
		if rerr != nil {
			if !q.s.live(q.h.reg.now()) {
				// watchEnd cut the read.
				return d, errRunStopped
			}
			return d, errBodyLost
		}
	}
}

// checkDigest compares the body with x-amz-content-sha256 (unless it is
// UNSIGNED-PAYLOAD, over TLS, where Content-MD5 stands in for it on a
// PutObject or UploadPart: unsignedNeedsMD5) and with Content-MD5.
func (q *request) checkDigest(d bodyDigest, wantMD5 []byte) *s3Error {
	if q.payloadHash != UnsignedPayload && hex.EncodeToString(d.sha.Sum(nil)) != q.payloadHash {
		return errSHA256
	}
	if wantMD5 != nil && !bytes.Equal(d.md5.Sum(nil), wantMD5) {
		return errBadDigest
	}
	return nil
}

// unsignedNeedsMD5 refuses a PutObject or UploadPart whose payload is
// UNSIGNED-PAYLOAD (accepted over TLS only) unless it carries a Content-MD5
// that the signature covers: the signature then binds the body again,
// through its MD5. ClickHouse 24.8 sends a signed Content-MD5 on every
// PutObject and UploadPart over HTTPS (lab, Task 19); checkDigest compares it
// with the body.
func (q *request) unsignedNeedsMD5() *s3Error {
	if q.payloadHash != UnsignedPayload {
		return nil
	}
	if q.r.Header.Get("Content-MD5") == "" {
		return denied("A request with UNSIGNED-PAYLOAD needs a Content-MD5.")
	}
	auth, _ := strings.CutPrefix(q.r.Header.Get("Authorization"), algorithm+" ")
	if _, signed, _, err := parseAuthorization(auth); err != nil || !slices.Contains(signed, "content-md5") {
		return denied("A request with UNSIGNED-PAYLOAD needs a signed Content-MD5.")
	}
	return nil
}

// contentMD5 returns the decoded Content-MD5, or nil when there is none.
func (q *request) contentMD5() ([]byte, *s3Error) {
	v := q.r.Header.Get("Content-MD5")
	if v == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != md5.Size {
		return nil, refused("InvalidDigest", "The Content-MD5 you specified is not valid.")
	}
	return b, nil
}

// noBody refuses a body on a request that takes none.
func (q *request) noBody() *s3Error {
	if q.payloadHash != emptySHA256 && q.payloadHash != UnsignedPayload {
		return denied("This request takes no body.")
	}
	if n, _ := io.Copy(io.Discard, io.LimitReader(q.r.Body, 1)); n > 0 {
		return denied("This request takes no body.")
	}
	return nil
}

// readSmall reads a body of at most limit bytes into memory, uncharged.
func (q *request) readSmall(limit int64) ([]byte, bodyDigest, error) {
	var buf bytes.Buffer
	d, err := q.copyBody(&limitWriter{w: &buf, left: limit}, false)
	return buf.Bytes(), d, err
}

type limitWriter struct {
	w    io.Writer
	left int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.left {
		return 0, errTooLarge
	}
	l.left -= int64(len(p))
	return l.w.Write(p)
}

// objectFailed maps a failed copy into an object to the reply, after abort
// has ended the object, and stops the session when the failure means the run
// cannot be trusted.
func (q *request) objectFailed(err error, abort func(error) error) *s3Error {
	sinkErr := abort(err)
	switch {
	case errors.Is(err, ErrQuota):
		// AddBytes stopped the session.
		return denied("The run wrote more than its byte limit.")
	case errors.Is(err, errRunStopped):
		return errStopped
	case errors.Is(err, errBodyLost):
		q.stop(ReasonIncompleteBody)
		return errIncomplete
	}
	// The write failed: the sink returned, or the session ended and the
	// stream was aborted.
	if !q.s.live(q.h.reg.now()) {
		return errStopped
	}
	q.h.log.Warn("ingest: no destination took an object", "run", q.s.RunID().String(), "key", q.key, "err", sinkErr)
	q.stop(ReasonDestination)
	return denied("No destination took the object.")
}

// stored records an object the sink took and keeps its body when the
// manifest needs it.
func (q *request) stored(rec ObjectRecord, kept []byte) *s3Error {
	q.s.RecordObject(rec)
	if q.s.CaptureLimit(rec.Key) > 0 && !q.s.Capture(rec.Key, kept) {
		return denied("The run's kept bodies are over their limit.")
	}
	return nil
}

func (q *request) put() *s3Error {
	s := q.s
	if !s.own(q.key) {
		return denied("The key is outside the run's prefix.")
	}
	if e := q.unsignedNeedsMD5(); e != nil {
		return e
	}
	wantMD5, e := q.contentMD5()
	if e != nil {
		return e
	}
	if q.key == s.LockKey() {
		return q.putLock(wantMD5)
	}
	stored, ok, release, err := s.claimPut(q.key)
	switch {
	case errors.Is(err, errUploadOpen):
		q.h.log.Warn("ingest: the run sent a PutObject of a key it is uploading in parts", "run", s.RunID().String(), "key", q.key)
		q.stop(ReasonRewrite)
		return denied("An upload of the object is open; objects are written once.")
	case err != nil:
		return errStopped
	case ok:
		return q.repeatPut(stored, wantMD5)
	}
	defer release()
	obj := q.h.newObject(q.r.Context(), s, q.key, s.Sink(), nil)
	d, err := q.copyBody(obj, true)
	if err != nil {
		return q.objectFailed(err, obj.abort)
	}
	if e := q.checkDigest(d, wantMD5); e != nil {
		_ = obj.abort(errDigest)
		q.stop(ReasonBadDigest)
		return e
	}
	rec, e := q.finishObject(obj)
	if e != nil {
		return e
	}
	if e := q.stored(rec, obj.kept); e != nil {
		return e
	}
	q.w.Header().Set("ETag", etag(rec.SHA256))
	q.w.WriteHeader(http.StatusOK)
	return nil
}

// repeatPut answers a PutObject of a key the run stored already. ClickHouse's
// S3 client sends a PUT again when it did not see the answer (its connection
// dropped after the body): the same body is read, nothing is written (every
// destination would refuse to overwrite), and the stored object is the
// answer. Another body would overwrite a stored object: the run is stopped.
func (q *request) repeatPut(stored ObjectRecord, wantMD5 []byte) *s3Error {
	d, err := q.copyBody(io.Discard, false)
	switch {
	case errors.Is(err, errRunStopped):
		return errStopped
	case err != nil:
		q.stop(ReasonIncompleteBody)
		return errIncomplete
	}
	if e := q.checkDigest(d, wantMD5); e != nil {
		q.stop(ReasonBadDigest)
		return e
	}
	if d.n != stored.Size || hex.EncodeToString(d.sha.Sum(nil)) != stored.SHA256 {
		q.h.log.Warn("ingest: the run sent another body for a stored object", "run", q.s.RunID().String(), "key", q.key)
		q.stop(ReasonRewrite)
		return denied("The object is stored with other content; objects are not overwritten.")
	}
	q.w.Header().Set("ETag", etag(stored.SHA256))
	q.w.WriteHeader(http.StatusOK)
	return nil
}

// finishObject ends a complete body: the sink stores it.
func (q *request) finishObject(obj *objectStream) (ObjectRecord, *s3Error) {
	if !q.s.live(q.h.reg.now()) {
		_ = obj.abort(errRunStopped)
		return ObjectRecord{}, errStopped
	}
	rec, err := obj.finish()
	if err != nil {
		if !q.s.live(q.h.reg.now()) {
			return ObjectRecord{}, errStopped
		}
		q.h.log.Warn("ingest: no destination took an object", "run", q.s.RunID().String(), "key", q.key, "err", err)
		q.stop(ReasonDestination)
		return ObjectRecord{}, denied("No destination took the object.")
	}
	return rec, nil
}

// putLock keeps the run's .lock in memory; it never reaches the sink.
func (q *request) putLock(wantMD5 []byte) *s3Error {
	body, d, err := q.readSmall(maxLockSize)
	switch {
	case errors.Is(err, errWrite):
		return denied("The .lock is too large.")
	case errors.Is(err, errRunStopped):
		return errStopped
	case err != nil:
		return errIncomplete
	}
	if e := q.checkDigest(d, wantMD5); e != nil {
		q.stop(ReasonBadDigest)
		return e
	}
	q.s.PutLock(body)
	q.w.Header().Set("ETag", d.etag())
	q.w.WriteHeader(http.StatusOK)
	return nil
}

func (q *request) get() *s3Error {
	if e := q.noBody(); e != nil {
		return e
	}
	s := q.s
	switch {
	case s.own(q.key):
		if q.key == s.LockKey() {
			b, ok := s.Lock()
			if !ok {
				return errNoSuchKey
			}
			return q.serveBytes(b)
		}
		if b, ok := s.Captured(q.key); ok {
			return q.serveBytes(b)
		}
		for _, o := range s.Objects() {
			if o.Key == q.key {
				return denied("The run's objects are not read back, except its .lock and its kept bodies.")
			}
		}
		return errNoSuchKey
	case s.readable(q.key):
		return q.serveSource()
	}
	return denied("The key is outside the run's scope.")
}

func (q *request) serveBytes(b []byte) *s3Error {
	start, end, partial, e := parseRange(q.r.Header.Get("Range"), int64(len(b)))
	if e != nil {
		return e
	}
	q.objectHeaders(start, end, int64(len(b)), partial)
	_, _ = q.w.Write(b[start : end+1])
	return nil
}

func (q *request) serveSource() *s3Error {
	s := q.s
	if _, whole := s.Source().(WholeSource); whole && q.r.Header.Get("Range") != "" {
		return denied("Objects of this run are served whole only.")
	}
	rc, rec, err := s.Source().Open(q.r.Context(), q.key)
	switch {
	case errors.Is(err, ErrNotServed):
		// A key the source does not serve, such as one its signed
		// manifests do not list: refused, and the run goes on.
		return denied("The key is not an object of the run's backup.")
	case errors.Is(err, fs.ErrNotExist):
		return errNoSuchKey
	}
	if err != nil {
		q.abortIfGone(err)
		q.h.log.Warn("ingest: could not read an object", "run", s.RunID().String(), "key", q.key, "err", err)
		q.stop(ReasonSource)
		return denied("The object could not be read.")
	}
	defer func() { _ = rc.Close() }()
	start, end, partial, e := parseRange(q.r.Header.Get("Range"), rec.Size)
	if e != nil {
		return e
	}
	if start > 0 {
		if _, err := io.CopyN(io.Discard, rc, start); err != nil {
			q.stop(ReasonSource)
			return denied("The object could not be read.")
		}
	}
	q.objectHeaders(start, end, rec.Size, partial)
	// Each chunk's write has its own deadline: a client that stops reading
	// would otherwise hold the handler in Write for as long as it keeps the
	// connection open. The deadline is cleared for the connection's next
	// request.
	wc := http.NewResponseController(q.w)
	defer func() { _ = wc.SetWriteDeadline(time.Time{}) }()
	left := end - start + 1
	buf := make([]byte, chunkSize)
	for left > 0 {
		n, rerr := rc.Read(buf[:min(int64(len(buf)), left)])
		if n > 0 {
			if !s.live(q.h.reg.now()) {
				q.abort()
			}
			_ = wc.SetWriteDeadline(time.Now().Add(q.h.writeTimeout))
			if _, err := q.w.Write(buf[:n]); err != nil {
				// The client went away, or stopped reading for longer than
				// the write timeout.
				q.aborted = true
				return nil
			}
			left -= int64(n)
		}
		if rerr != nil && left > 0 {
			q.abortIfGone(rerr)
		}
		if rerr != nil && left > 0 {
			q.h.log.Warn("ingest: could not read an object", "run", s.RunID().String(), "key", q.key, "err", errors.Join(errSourceShort, rerr))
			q.stop(ReasonSource)
			q.abort()
		}
	}
	return nil
}

// abortIfGone cuts the connection when err is the request's own context
// ending: the client went away, or closed its side, or its connection was
// cut when the session ended. The source did not fail, so the run is not
// stopped for it; and the reply is cut, never sent short or empty, which
// a client that still reads would take for the object.
func (q *request) abortIfGone(err error) {
	if q.r.Context().Err() == nil || !(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return
	}
	q.h.log.Info("ingest: the client went away while an object was read", "run", q.s.RunID().String(), "key", q.key)
	q.abort()
}

// abort cuts a reply whose headers are sent.
func (q *request) abort() {
	q.aborted = true
	panic(http.ErrAbortHandler)
}

func (q *request) objectHeaders(start, end, size int64, partial bool) {
	hd := q.w.Header()
	hd.Set("Content-Type", "application/octet-stream")
	hd.Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	hd.Set("Accept-Ranges", "bytes")
	if !partial {
		q.w.WriteHeader(http.StatusOK)
		return
	}
	hd.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	q.w.WriteHeader(http.StatusPartialContent)
}

// parseRange reads a Range header: none, "bytes=a-b" or "bytes=a-". Other
// forms (several ranges, a suffix) are refused.
func parseRange(h string, size int64) (start, end int64, partial bool, e *s3Error) {
	if h == "" {
		return 0, size - 1, false, nil
	}
	bad := denied("Only one range, bytes=a-b or bytes=a-, is served.")
	spec, ok := strings.CutPrefix(h, "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return 0, 0, false, bad
	}
	a, b, ok := strings.Cut(spec, "-")
	if !ok || !digits(a) || (b != "" && !digits(b)) {
		return 0, 0, false, bad
	}
	start, err := strconv.ParseInt(a, 10, 64)
	if err != nil {
		return 0, 0, false, bad
	}
	end = size - 1
	if b != "" {
		last, err := strconv.ParseInt(b, 10, 64)
		if err != nil || last < start {
			return 0, 0, false, bad
		}
		end = min(last, size-1)
	}
	if start >= size {
		return 0, 0, false, &s3Error{http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "The requested range is not satisfiable."}
	}
	return start, end, true, nil
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (q *request) list() *s3Error {
	if e := q.noBody(); e != nil {
		return e
	}
	query, _ := url.ParseQuery(q.r.URL.RawQuery) // classify parsed it
	prefix := query.Get("prefix")
	q.key = prefix
	if !validListPrefix(prefix) {
		return denied("The prefix is not a plain prefix.")
	}
	maxKeys := maxListKeys
	if query.Has("max-keys") {
		n, err := strconv.Atoi(query.Get("max-keys"))
		if err != nil || n < 0 {
			return refused("InvalidArgument", "max-keys must be a number from 0.")
		}
		maxKeys = min(n, maxListKeys)
	}
	marker := query.Get("marker")

	s := q.s
	var found []ObjectRecord
	switch {
	case s.own(prefix):
		found = s.Objects()
		if lock, ok := s.Lock(); ok {
			sum := sha256.Sum256(lock)
			found = append(found, ObjectRecord{Key: s.LockKey(), Size: int64(len(lock)), SHA256: hex.EncodeToString(sum[:])})
		}
	case s.readable(prefix):
		recs, err := s.Source().List(q.r.Context(), prefix)
		if err != nil {
			q.h.log.Warn("ingest: could not list objects", "run", s.RunID().String(), "prefix", prefix, "err", err)
			q.stop(ReasonSource)
			return denied("The prefix could not be listed.")
		}
		found = recs
	default:
		return denied("The prefix is outside the run's scope.")
	}

	// A source returns what lies under the prefix; the filter holds anyway.
	var keys []ObjectRecord
	for _, o := range found {
		if strings.HasPrefix(o.Key, prefix) && validKey(o.Key) && o.Key > marker {
			keys = append(keys, o)
		}
	}
	slices.SortFunc(keys, func(a, b ObjectRecord) int { return strings.Compare(a.Key, b.Key) })
	keys = slices.CompactFunc(keys, func(a, b ObjectRecord) bool { return a.Key == b.Key })

	res := listBucketResult{Xmlns: s3Namespace, Name: bucket, Prefix: prefix, Marker: marker, MaxKeys: maxKeys}
	if len(keys) > maxKeys {
		keys = keys[:maxKeys]
		res.IsTruncated = true
		if maxKeys > 0 {
			res.NextMarker = keys[maxKeys-1].Key
		}
	}
	modified := q.h.reg.now().UTC().Format("2006-01-02T15:04:05.000Z")
	for _, o := range keys {
		res.Contents = append(res.Contents, listEntry{Key: o.Key, LastModified: modified, ETag: etag(o.SHA256),
			Size: o.Size, StorageClass: "STANDARD"})
	}
	writeXML(q.w, http.StatusOK, res)
	return nil
}

// deleteObject deletes the run's .lock, from memory. Every other delete is
// refused (spike §2).
func (q *request) deleteObject() *s3Error {
	if e := q.noBody(); e != nil {
		return e
	}
	if !q.s.own(q.key) || q.key != q.s.LockKey() {
		return denied("Only the run's .lock may be deleted.")
	}
	q.s.DeleteLock()
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// objectStream is one object on its way into Sink.Put: a pipe the handler
// writes the body into, in order, and the sink's result. The record of the
// object is what the handler measured on the way: the bytes it checked
// against the signed digest.
type objectStream struct {
	key    string
	pw     *io.PipeWriter
	cancel context.CancelFunc
	// done is closed when Put returned, with err.
	done chan struct{}
	err  error
	// finished is closed when the object is finished or aborted, so that the
	// watcher returns.
	finished  chan struct{}
	finishOne sync.Once

	// Written by the one writer at a time.
	sha     hash.Hash
	size    int64
	kept    []byte
	keepMax int64
}

// newObject starts sink.Put for key (the session's Sink, or a drainSink). When the session ends first, the stream
// is aborted, and onEnd runs if it is not nil.
func (h *handler) newObject(ctx context.Context, s *Session, key string, sink Sink, onEnd func()) *objectStream {
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	o := &objectStream{key: key, pw: pw, cancel: cancel, done: make(chan struct{}), finished: make(chan struct{}),
		sha: sha256.New()}
	if limit := s.CaptureLimit(key); limit > 0 {
		o.keepMax = limit + 1 // one more byte, so that Capture sees a body over its limit
	}
	go func() {
		_, err := sink.Put(ctx, key, pr)
		// A sink that returned before EOF must not leave a writer blocked.
		pr.CloseWithError(errSinkDone)
		o.err = err
		close(o.done)
	}()
	go func() {
		select {
		case <-s.ended:
			o.pw.CloseWithError(errRunStopped)
			o.cancel()
			if onEnd != nil {
				onEnd()
			}
		case <-o.finished:
		}
	}()
	return o
}

func (o *objectStream) Write(p []byte) (int, error) {
	n, err := o.pw.Write(p)
	o.sha.Write(p[:n])
	o.size += int64(n)
	if room := o.keepMax - int64(len(o.kept)); room > 0 {
		o.kept = append(o.kept, p[:min(int64(n), room)]...)
	}
	return n, err
}

// abort fails the object with err, so that the sink drops it, and returns
// the sink's error. It may be called more than once.
func (o *objectStream) abort(err error) error {
	o.pw.CloseWithError(err)
	o.cancel()
	<-o.done
	o.finishOne.Do(func() { close(o.finished) })
	return o.err
}

// finish ends the body and waits for the sink to store the object.
func (o *objectStream) finish() (ObjectRecord, error) {
	_ = o.pw.Close() // a PipeWriter's Close never fails
	<-o.done
	o.finishOne.Do(func() { close(o.finished) })
	o.cancel()
	if o.err != nil {
		return ObjectRecord{}, o.err
	}
	return ObjectRecord{Key: o.key, Size: o.size, SHA256: hex.EncodeToString(o.sha.Sum(nil))}, nil
}

// statusWriter remembers the reply's status.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap gives http.ResponseController the connection's writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
