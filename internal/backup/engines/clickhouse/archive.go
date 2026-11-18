package clickhouse

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"strings"
	"time"

	"github.com/klauspost/compress/flate"
)

// archive is a streaming zip container (same container as the PostgreSQL
// engine: archive/zip written front to back with data descriptors, no
// seeking, nothing buffered beyond the current entry chunk).
//
// Unlike pg_dump -Fc output, Native/RowBinary data is not compressed by the
// server, so entries use Deflate (klauspost/compress, fast level) instead
// of Store; any unzip tool can extract them.
type archive struct {
	zw       *zip.Writer
	modified time.Time
}

func newArchive(w io.Writer, modified time.Time) *archive {
	zw := zip.NewWriter(w)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestSpeed)
	})
	return &archive{zw: zw, modified: modified.UTC()}
}

// entry is an open zip entry that tracks size and sha256 of its content.
type entry struct {
	w    io.Writer
	h    hash.Hash
	size int64
}

func (e *entry) Write(p []byte) (int, error) {
	n, err := e.w.Write(p)
	e.h.Write(p[:n])
	e.size += int64(n)
	return n, err
}

func (e *entry) sum() string { return hex.EncodeToString(e.h.Sum(nil)) }

// create starts a new entry; the previous one is implicitly finished.
func (a *archive) create(name string) (*entry, error) {
	fw, err := a.zw.CreateHeader(&zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: a.modified,
	})
	if err != nil {
		return nil, err
	}
	return &entry{w: fw, h: sha256.New()}, nil
}

// writeFile writes a whole small entry.
func (a *archive) writeFile(name string, data []byte) (*entry, error) {
	e, err := a.create(name)
	if err != nil {
		return nil, err
	}
	if _, err := e.Write(data); err != nil {
		return nil, err
	}
	return e, nil
}

func (a *archive) close() error { return a.zw.Close() }

// pathSegment escapes a ClickHouse identifier into one safe zip path
// segment: [A-Za-z0-9_.-] stay, everything else is %XX; "." and ".." are
// fully escaped. The manifest keeps the real names next to entry paths.
func pathSegment(s string) string {
	if s == "" {
		return "%00"
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	out := b.String()
	if out == "." || out == ".." {
		return strings.Repeat("%2E", len(out))
	}
	return out
}
