package ingest

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Multipart uploads are not stored as parts (design §3). Each upload is one
// Sink.Put: parts stream into it in order. A part that arrives before its
// turn waits in a file on disk, and the request that brings the missing part
// feeds the waiting ones after it. The disk is a per-run budget (R18): an
// early part that does not fit is refused 503 SlowDown before its body is
// read, and ClickHouse sends it again later. The part in order is always
// taken, so the upload always moves on.

// upload is one multipart upload of a session.
type upload struct {
	id  string
	s   *Session
	key string
	obj *objectStream

	// repeat is the stored record of key when the upload was created for a
	// stored key: it writes nothing and can only end as a repeat (R36).
	repeat *ObjectRecord
	// release gives up the upload's claim on key; finished is closed when
	// the upload ended (finish).
	release    func()
	finished   chan struct{}
	finishOnce sync.Once

	mu     sync.Mutex
	closed bool // completed, aborted or failed
	// completing: a CompleteMultipartUpload is storing the object; the
	// upload stays findable until it is recorded.
	completing bool
	// busy is set while one request writes into obj; next is the part obj
	// waits for. idle is closed, and made anew, each time busy is given up
	// (unbusy).
	busy  bool
	idle  chan struct{}
	next  int
	parts map[int]*part
}

// unbusy gives up u.busy and wakes the Completes that wait for the parts
// being written. Call it with u.mu held.
func (u *upload) unbusy() {
	u.busy = false
	close(u.idle)
	u.idle = make(chan struct{})
}

// part is a part received, or still arriving.
type part struct {
	size int64
	// sha256 is the part's SHA-256 in hex; its ETag is made from it.
	sha256  string
	pending bool
	// spill is the part's file while it waits for its turn.
	spill string
	// reserved is what the part holds of the run's spill budget (its
	// Content-Length) from the time it is taken until it left the disk.
	reserved int64
}

func (q *request) createUpload() *s3Error {
	if e := q.noBody(); e != nil {
		return e
	}
	s, h := q.s, q.h
	if !s.own(q.key) {
		return denied("The key is outside the run's prefix.")
	}
	if q.key == s.LockKey() {
		return denied("The .lock is not uploaded in parts.")
	}
	u := &upload{id: randomHex(16), s: s, key: q.key, next: 1, parts: map[int]*part{}, idle: make(chan struct{}),
		finished: make(chan struct{})}
	// One writer per key (R36). ClickHouse sends CreateMultipartUpload again
	// when it did not see the answer: the earlier upload of the key is
	// dropped, and its sink write ended, before this one starts (a
	// filesystem destination refuses a second write of a file in progress).
	// A stored key's upload writes nothing and can only end as a repeat.
	for {
		rec, stored, open, ended, release, err := s.claimUpload(q.key, u.id)
		if err != nil {
			return errStopped
		}
		if open != "" {
			if prev, e := h.findUpload(open, s, q.key); e == nil {
				h.failUpload(prev, errReplaced)
			}
			select {
			case <-ended:
			case <-s.ended:
				return errStopped
			}
			continue
		}
		if stored {
			u.repeat = &rec
		}
		u.release = release
		break
	}
	sink := s.Sink()
	if u.repeat != nil {
		sink = drainSink{}
	}
	// The cap is checked before the upload starts a Sink.Put. The upload
	// outlives this request; the session's end aborts it. Until obj is set,
	// u.mu keeps anything that ends the upload (onEnd, a later Create of the
	// key) waiting.
	u.mu.Lock()
	h.mu.Lock()
	open := 0
	for _, other := range h.uploads {
		if other.s == s {
			open++
		}
	}
	if open >= maxUploads {
		h.mu.Unlock()
		u.mu.Unlock()
		u.finish()
		return denied("The run has too many open multipart uploads.")
	}
	h.uploads[u.id] = u
	h.mu.Unlock()
	u.obj = h.newObject(context.Background(), s, q.key, sink, func() { h.failUpload(u, errRunStopped) })
	u.mu.Unlock()
	if !s.live(h.reg.now()) {
		// It ended before the upload was in the map.
		h.failUpload(u, errRunStopped)
		return errStopped
	}
	writeXML(q.w, http.StatusOK, initiateResult{Xmlns: s3Namespace, Bucket: bucket, Key: q.key, UploadID: u.id})
	return nil
}

// errReplaced aborts an upload whose key a new CreateMultipartUpload took.
var errReplaced = errors.New("ingest: the upload was replaced by a new upload of its key")

// drainSink takes the upload of a stored key, which can only end as a
// repeat: it reads the parts and writes nothing.
type drainSink struct{}

func (drainSink) Put(_ context.Context, key string, r io.Reader) (ObjectRecord, error) {
	n, err := io.Copy(io.Discard, r)
	return ObjectRecord{Key: key, Size: n}, err
}

// finish ends the upload's claim on its key and wakes a repeated Complete
// that waits for it. Only the first call counts.
func (u *upload) finish() {
	u.finishOnce.Do(func() {
		if u.release != nil {
			u.release()
		}
		close(u.finished)
	})
}

// endUpload drops a completed (or failed) upload from the map, then ends it.
func (h *handler) endUpload(u *upload) {
	h.mu.Lock()
	delete(h.uploads, u.id)
	h.mu.Unlock()
	u.finish()
}

// findUpload returns the upload id of this session and key.
func (h *handler) findUpload(id string, s *Session, key string) (*upload, *s3Error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	u := h.uploads[id]
	if u == nil || u.s != s || u.key != key {
		return nil, errNoSuchUpload
	}
	return u, nil
}

// failUpload ends an upload that will not complete: the sink drops the
// object, and the waiting parts leave the disk. Only the first call counts.
func (h *handler) failUpload(u *upload, err error) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.closed = true
	var spills []*part
	for _, p := range u.parts {
		if p.spill != "" {
			spills = append(spills, p)
		}
	}
	obj := u.obj
	u.mu.Unlock()
	for _, p := range spills {
		_ = os.Remove(p.spill)
		u.s.releaseSpill(p.reserved)
	}
	// The sink has returned once abort does: the claim is given up after
	// the write ended (a destination's partial file is gone).
	_ = obj.abort(err)
	h.endUpload(u)
}

// partFailed is objectFailed for an upload: a failure that is not the
// upload's own end fails it.
func (q *request) partFailed(u *upload, err error) *s3Error {
	u.mu.Lock()
	closed := u.closed
	u.mu.Unlock()
	if closed && errors.Is(err, errWrite) && q.s.live(q.h.reg.now()) {
		// The client aborted the upload meanwhile.
		return errNoSuchUpload
	}
	return q.objectFailed(err, func(err error) error {
		q.h.failUpload(u, err)
		return u.obj.abort(err) // the sink's error, once it returned
	})
}

// brokenUpload fails an upload whose client broke the protocol.
func (q *request) brokenUpload(u *upload, message string) *s3Error {
	q.h.failUpload(u, errMultipart)
	q.stop(ReasonMultipart)
	return refused("InvalidPart", message)
}

func (q *request) uploadPart() *s3Error {
	query, _ := url.ParseQuery(q.r.URL.RawQuery)
	n, err := strconv.Atoi(query.Get("partNumber"))
	if err != nil || n < 1 || n > maxPartNumber {
		return refused("InvalidArgument", "partNumber must be from 1 to 10000.")
	}
	s := q.s
	if !s.own(q.key) {
		return denied("The key is outside the run's prefix.")
	}
	// The length decides, before the body is read, whether an early part
	// fits on disk.
	if q.r.ContentLength < 0 || len(q.r.TransferEncoding) > 0 {
		return denied("A part needs a Content-Length.")
	}
	wantMD5, e := q.contentMD5()
	if e != nil {
		return e
	}
	u, e := q.h.findUpload(query.Get("uploadId"), s, q.key)
	if e != nil {
		return e
	}

	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return errNoSuchUpload
	}
	if p, ok := u.parts[n]; ok {
		seen := *p
		u.mu.Unlock()
		return q.repeatPart(u, n, seen, wantMD5)
	}
	if n == u.next && !u.busy {
		p := &part{pending: true}
		u.parts[n] = p
		u.busy = true
		u.mu.Unlock()
		return q.streamPart(u, p, wantMD5)
	}
	// The part waits on disk. An early part needs room in the run's budget,
	// or it is refused unread and sent again later; the part in order (it
	// came while another request still writes into the object) is always
	// taken.
	limit := q.h.spillLimit
	if n == u.next {
		limit = -1
	}
	if !s.reserveSpill(q.r.ContentLength, limit) {
		u.mu.Unlock()
		return errSpillFull
	}
	p := &part{pending: true, reserved: q.r.ContentLength}
	u.parts[n] = p
	u.mu.Unlock()
	return q.spillPart(u, n, p, wantMD5)
}

// streamPart writes the part the object waits for straight into it, then
// the waiting parts after it. It runs with u.busy set.
func (q *request) streamPart(u *upload, p *part, wantMD5 []byte) *s3Error {
	// The parts of a repeat are drained, not stored, so not charged (R39).
	d, err := q.copyBody(u.obj, u.repeat == nil)
	if err != nil {
		e := q.partFailed(u, err)
		q.release(u)
		return e
	}
	if e := q.checkDigest(d, wantMD5); e != nil {
		q.h.failUpload(u, errDigest)
		q.stop(ReasonBadDigest)
		q.release(u)
		return e
	}
	u.mu.Lock()
	p.size, p.sha256, p.pending = d.n, hex.EncodeToString(d.sha.Sum(nil)), false
	u.next++
	u.mu.Unlock()
	if e := q.drain(u); e != nil {
		return e
	}
	q.partOK(d.etag())
	return nil
}

func (q *request) release(u *upload) {
	u.mu.Lock()
	u.unbusy()
	u.mu.Unlock()
}

// drain feeds the waiting parts that are next in line into the object, then
// gives up u.busy.
func (q *request) drain(u *upload) *s3Error {
	for {
		u.mu.Lock()
		p, ok := u.parts[u.next]
		if u.closed || !ok || p.spill == "" {
			u.unbusy()
			closed := u.closed
			u.mu.Unlock()
			if closed {
				return errNoSuchUpload
			}
			return nil
		}
		path := p.spill
		p.spill = ""
		u.mu.Unlock()

		err := q.feed(u.obj, path)
		_ = os.Remove(path)
		u.s.releaseSpill(p.reserved)
		if err != nil {
			e := q.partFailed(u, err)
			q.release(u)
			return e
		}
		u.mu.Lock()
		u.next++
		u.mu.Unlock()
	}
}

// feed copies a waiting part's file into the object. Its bytes were checked
// and counted when it arrived.
func (q *request) feed(obj *objectStream, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %w", errWrite, err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, chunkSize)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if !q.s.live(q.h.reg.now()) {
				return errRunStopped
			}
			if _, err := obj.Write(buf[:n]); err != nil {
				return fmt.Errorf("%w: %w", errWrite, err)
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return fmt.Errorf("%w: %w", errWrite, rerr)
		}
	}
}

// spillPattern names the files of parts that wait on disk (os.CreateTemp).
const spillPattern = "olympos-ingest-*.part"

// spillPart holds a part that came before its turn on disk; it holds p's
// reservation of the spill budget, which it gives back when the part does
// not stay. When its turn came meanwhile and no request is streaming, it
// feeds the object itself.
func (q *request) spillPart(u *upload, n int, p *part, wantMD5 []byte) *s3Error {
	f, err := os.CreateTemp(q.h.spillDir, spillPattern)
	if err != nil {
		q.s.releaseSpill(p.reserved)
		q.h.log.Warn("ingest: could not hold a part on disk", "run", q.s.RunID().String(), "key", q.key, "err", err)
		q.h.failUpload(u, err)
		q.stop(ReasonSpill)
		return denied("The part could not be held until its turn.")
	}
	d, err := q.copyBody(f, u.repeat == nil)
	if cerr := f.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("%w: %w", errWrite, cerr)
	}
	discard := func() {
		_ = os.Remove(f.Name())
		q.s.releaseSpill(p.reserved)
	}
	if err != nil {
		discard()
		if errors.Is(err, errWrite) {
			q.h.log.Warn("ingest: could not hold a part on disk", "run", q.s.RunID().String(), "key", q.key, "err", err)
			q.h.failUpload(u, err)
			q.stop(ReasonSpill)
			return denied("The part could not be held until its turn.")
		}
		return q.partFailed(u, err)
	}
	if e := q.checkDigest(d, wantMD5); e != nil {
		discard()
		q.h.failUpload(u, errDigest)
		q.stop(ReasonBadDigest)
		return e
	}

	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		discard()
		return errNoSuchUpload
	}
	p.size, p.sha256, p.pending, p.spill = d.n, hex.EncodeToString(d.sha.Sum(nil)), false, f.Name()
	turn := n == u.next && !u.busy
	if turn {
		u.busy = true
	}
	u.mu.Unlock()
	if turn {
		if e := q.drain(u); e != nil {
			return e
		}
	}
	q.partOK(d.etag())
	return nil
}

// repeatPart answers a part that was sent again: a retry with the same body
// gets the same answer, and is not streamed twice; any other body fails the
// upload.
func (q *request) repeatPart(u *upload, n int, seen part, wantMD5 []byte) *s3Error {
	if seen.pending {
		return q.brokenUpload(u, fmt.Sprintf("Part %d is already arriving.", n))
	}
	d, err := q.copyBody(io.Discard, false)
	switch {
	case errors.Is(err, errRunStopped):
		return errStopped
	case err != nil:
		return errIncomplete
	}
	if e := q.checkDigest(d, wantMD5); e != nil {
		q.h.failUpload(u, errDigest)
		q.stop(ReasonBadDigest)
		return e
	}
	if d.n != seen.size || hex.EncodeToString(d.sha.Sum(nil)) != seen.sha256 {
		return q.brokenUpload(u, fmt.Sprintf("Part %d was sent again with another body.", n))
	}
	q.partOK(etag(seen.sha256))
	return nil
}

func (q *request) partOK(tag string) {
	q.w.Header().Set("ETag", tag)
	q.w.WriteHeader(http.StatusOK)
}

func (q *request) completeUpload() *s3Error {
	query, _ := url.ParseQuery(q.r.URL.RawQuery)
	s := q.s
	if !s.own(q.key) {
		return denied("The key is outside the run's prefix.")
	}
	wantMD5, e := q.contentMD5()
	if e != nil {
		return e
	}
	id := query.Get("uploadId")
	u, e := q.h.findUpload(id, s, q.key)
	if e != nil {
		if c, ok := s.completedUpload(id); ok && c.key == q.key {
			return q.repeatComplete(c, wantMD5)
		}
		return e
	}
	body, d, err := q.readSmall(maxCompleteSize)
	switch {
	case errors.Is(err, errWrite):
		return q.brokenUpload(u, "The part list is too large.")
	case errors.Is(err, errRunStopped):
		return errStopped
	case err != nil:
		return errIncomplete
	}
	if e := q.checkDigest(d, wantMD5); e != nil {
		q.h.failUpload(u, errDigest)
		q.stop(ReasonBadDigest)
		return e
	}
	listSHA := hex.EncodeToString(d.sha.Sum(nil))
	var list completeRequest
	if err := xml.Unmarshal(body, &list); err != nil {
		return q.brokenUpload(u, "The part list is not valid XML.")
	}

	u.mu.Lock()
	for {
		if u.closed {
			completing := u.completing
			u.mu.Unlock()
			if !completing {
				return errNoSuchUpload
			}
			// A repeat of a Complete still storing its object waits for it,
			// and gets its answer (R35, R36).
			select {
			case <-u.finished:
			case <-s.ended:
				return errStopped
			}
			c, ok := s.completedUpload(id)
			if !ok || c.key != q.key {
				return errNoSuchUpload
			}
			return q.answerRepeat(c, listSHA)
		}
		if !u.listsParts(list) {
			u.mu.Unlock()
			return q.brokenUpload(u, "The part list does not match the parts received.")
		}
		if !u.busy {
			break
		}
		// Every part arrived, and parts that waited on disk are still being
		// written into the object: a part sent again gets its answer at
		// once, so its client can send the Complete before then. It waits
		// for them.
		idle := u.idle
		u.mu.Unlock()
		select {
		case <-idle:
		case <-s.ended:
			return errStopped
		}
		u.mu.Lock()
	}
	// Every part from 1 was streamed, in order, and none waits.
	if len(list.Parts) != u.next-1 {
		u.mu.Unlock()
		return q.brokenUpload(u, "The part list does not match the parts received.")
	}
	u.closed, u.completing = true, true
	u.mu.Unlock()
	// The upload stays findable until its object is recorded, and its claim
	// on the key held until then.
	defer q.h.endUpload(u)

	rec, e := q.finishObject(u.obj)
	if e != nil {
		return e
	}
	if u.repeat != nil {
		// The upload of a stored key: the same object again is a repeat,
		// another one would overwrite it.
		if rec.Size != u.repeat.Size || rec.SHA256 != u.repeat.SHA256 {
			q.h.log.Warn("ingest: the run uploaded another object for a stored key", "run", s.RunID().String(), "key", q.key)
			q.stop(ReasonRewrite)
			return denied("The object is stored with other content; objects are not overwritten.")
		}
	} else if e := q.stored(rec, u.obj.kept); e != nil {
		return e
	}
	// The whole object's ETag, with the part count, as S3 marks a multipart
	// ETag.
	tag := fmt.Sprintf(`"%s-%d"`, rec.SHA256[:32], len(list.Parts))
	s.completeUpload(u.id, completedUpload{key: q.key, listSHA256: listSHA, etag: tag})
	q.completed(tag)
	return nil
}

// listsParts reports whether list names every part u received, from 1 and
// in order, none of them still arriving, each with its ETag. Call it with
// u.mu held.
func (u *upload) listsParts(list completeRequest) bool {
	if len(list.Parts) == 0 || len(list.Parts) != len(u.parts) {
		return false
	}
	for i, lp := range list.Parts {
		p := u.parts[i+1]
		if lp.PartNumber != i+1 || p == nil || p.pending || strings.Trim(lp.ETag, `"`) != strings.Trim(etag(p.sha256), `"`) {
			return false
		}
	}
	return true
}

func (q *request) completed(tag string) {
	writeXML(q.w, http.StatusOK, completeResult{Xmlns: s3Namespace, Location: "/" + bucket + "/" + q.key,
		Bucket: bucket, Key: q.key, ETag: tag})
}

// repeatComplete answers a CompleteMultipartUpload of an upload that
// completed already: a client that did not see the answer sends it again.
// The same part list gets the same answer; another one stops the run.
func (q *request) repeatComplete(c completedUpload, wantMD5 []byte) *s3Error {
	listSHA, e := q.readPartList(wantMD5)
	if e != nil {
		return e
	}
	return q.answerRepeat(c, listSHA)
}

// answerRepeat answers a repeated Complete with the part list of SHA-256
// listSHA.
func (q *request) answerRepeat(c completedUpload, listSHA string) *s3Error {
	if listSHA != c.listSHA256 {
		q.stop(ReasonRewrite)
		return denied("The upload completed with another part list.")
	}
	q.completed(c.etag)
	return nil
}

// readPartList reads a repeated Complete's part list and returns its
// SHA-256.
func (q *request) readPartList(wantMD5 []byte) (string, *s3Error) {
	_, d, err := q.readSmall(maxCompleteSize)
	switch {
	case errors.Is(err, errRunStopped):
		return "", errStopped
	case errors.Is(err, errWrite):
		q.stop(ReasonRewrite)
		return "", denied("The upload completed with another part list.")
	case err != nil:
		return "", errIncomplete
	}
	if e := q.checkDigest(d, wantMD5); e != nil {
		q.stop(ReasonBadDigest)
		return "", e
	}
	return hex.EncodeToString(d.sha.Sum(nil)), nil
}

func (q *request) abortUpload() *s3Error {
	if e := q.noBody(); e != nil {
		return e
	}
	query, _ := url.ParseQuery(q.r.URL.RawQuery)
	if !q.s.own(q.key) {
		return denied("The key is outside the run's prefix.")
	}
	u, e := q.h.findUpload(query.Get("uploadId"), q.s, q.key)
	if e != nil {
		return e
	}
	q.h.failUpload(u, errAborted)
	// The object is partly on the destinations and cannot be written again
	// under its name: the run cannot succeed.
	q.stop(ReasonUploadAborted)
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// RemoveSpillFiles removes the files of waiting parts that a previous
// process left in dir ("" is the system's temporary directory) when it
// ended without cleaning up, and returns how many it removed. Call it at
// start-up, before the endpoint serves: those parts' uploads are gone. A
// missing dir has none.
func RemoveSpillFiles(dir string) (int, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	files, err := filepath.Glob(filepath.Join(dir, spillPattern))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range files {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return n, fmt.Errorf("ingest: remove a spill file: %w", err)
		}
		n++
	}
	return n, nil
}
