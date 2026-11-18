// Package blob is the backup storage abstraction. The server is the only
// writer; it never deletes (retention is Blob lifecycle rules by tag).
package blob

import (
	"context"
	"io"

	"github.com/google/uuid"
)

// UploadResult describes a finished upload.
type UploadResult struct {
	Bytes  int64
	SHA256 string // hex
}

// Writer uploads blobs to one destination.
type Writer interface {
	// Upload streams r to path (relative to the destination prefix is NOT
	// applied: callers pass the full path incl. prefix). tags become blob
	// index tags (e.g. olympos-tier=daily).
	Upload(ctx context.Context, path string, r io.Reader, contentType string, tags map[string]string) (UploadResult, error)
	// Prefix is the destination's configured prefix ("" allowed).
	Prefix() string
}

// Resolver opens a Writer for a destination row.
type Resolver interface {
	ForDestination(ctx context.Context, destinationID uuid.UUID) (Writer, error)
}
