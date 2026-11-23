package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
)

// Object is one stored blob opened for random reads: restores read a backup
// archive by ranges (the zip central directory first, then each entry)
// instead of downloading it. Size is fixed when the object is opened.
type Object interface {
	io.ReaderAt
	Size() int64
	Close() error
}

// Reader opens stored blobs for range reads. path is the full path including
// the destination prefix, the same as Writer.Upload takes.
type Reader interface {
	Open(ctx context.Context, path string) (Object, error)
}

// ReaderResolver opens a Reader for a destination row.
type ReaderResolver interface {
	ReaderFor(ctx context.Context, destinationID uuid.UUID) (Reader, error)
}

// ReaderFor implements ReaderResolver. It resolves the destination exactly
// like ForDestination; the Azure, S3 and NFS writers also read.
func (r *DestResolver) ReaderFor(ctx context.Context, destinationID uuid.UUID) (Reader, error) {
	w, err := r.ForDestination(ctx, destinationID)
	if err != nil {
		return nil, err
	}
	rd, ok := w.(Reader)
	if !ok {
		return nil, fmt.Errorf("destination %s does not support reads", destinationID)
	}
	return rd, nil
}

// sha256ChunkSize is the read size of SequentialSHA256.
const sha256ChunkSize = 8 << 20

// SequentialSHA256 hashes o in one front-to-back pass of 8 MiB reads and
// returns the hex digest. It stops with the context's error when ctx ends.
func SequentialSHA256(ctx context.Context, o Object) (string, error) {
	h := sha256.New()
	buf := make([]byte, sha256ChunkSize)
	size := o.Size()
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		want := int64(len(buf))
		if rest := size - off; rest < want {
			want = rest
		}
		n, err := o.ReadAt(buf[:want], off)
		h.Write(buf[:n])
		off += int64(n)
		if err != nil && !(errors.Is(err, io.EOF) && int64(n) == want) {
			return "", fmt.Errorf("read at offset %d: %w", off, err)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ErrObjectChanged is returned when the blob was replaced between opening it
// and a later ranged read (the ETag no longer matches).
var ErrObjectChanged = errors.New("the backup object changed while it was being read")

// scrubbedError is an error whose message has been cleaned of credentials
// (SAS query strings, signatures) while the original stays reachable for
// errors.Is / errors.As (context.Canceled, ...).
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// rangeFetch returns a stream of exactly n bytes of the blob starting at off
// (n > 0, off+n <= size).
type rangeFetch func(ctx context.Context, off, n int64) (io.ReadCloser, error)

// rangeObject is an Object over a ranged-GET function: one request per
// ReadAt, never more than len(p) bytes, nothing buffered.
type rangeObject struct {
	ctx   context.Context
	size  int64
	fetch rangeFetch
	// scrub turns a storage or transport error (from the request or from
	// reading the body) into one that is safe to show.
	scrub func(error) error
}

func (o *rangeObject) Size() int64  { return o.size }
func (o *rangeObject) Close() error { return nil }

func (o *rangeObject) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := o.ctx.Err(); err != nil {
		return 0, err
	}
	if off >= o.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if rest := o.size - off; rest < want {
		want = rest
	}
	rc, err := o.fetch(o.ctx, off, want)
	if err != nil {
		return 0, o.scrub(err)
	}
	defer rc.Close()
	n, err := io.ReadFull(rc, p[:want])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return n, io.ErrUnexpectedEOF // the service sent fewer bytes than the range
		}
		return n, o.scrub(err)
	}
	if int(want) < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// fsObject is an Object over an open file.
type fsObject struct {
	ctx  context.Context
	f    *os.File
	size int64
}

func (o *fsObject) Size() int64  { return o.size }
func (o *fsObject) Close() error { return o.f.Close() }

func (o *fsObject) ReadAt(p []byte, off int64) (int, error) {
	if err := o.ctx.Err(); err != nil {
		return 0, err
	}
	return o.f.ReadAt(p, off)
}
