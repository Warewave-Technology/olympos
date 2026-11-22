package destinations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/blob"
)

// TestAzureReader reads a blob by ranges through blob.Azure.Open (SAS auth
// against Azurite).
func TestAzureReader(t *testing.T) {
	ep := azurite(t)
	ctx := context.Background()
	name := newContainer(t, ep)
	token := containerSAS(t, name, permsRCWT, time.Now().Add(time.Hour))
	a, err := blob.Open(blob.Target{Name: "az", Container: name, Prefix: "pfx", Auth: blob.AuthSAS, SAS: token, EndpointOverride: ep}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 700_000)
	for i := range payload {
		payload[i] = byte((i*131 + i/251) % 251)
	}
	path := "pfx/prod/run1.zip"
	if _, err := a.Upload(ctx, path, bytes.NewReader(payload), "application/zip", nil); err != nil {
		t.Fatal(err)
	}

	var r blob.Reader = a
	o, err := r.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if o.Size() != int64(len(payload)) {
		t.Fatalf("size %d", o.Size())
	}
	for _, c := range []struct{ off, n int }{{0, 10}, {7, 100}, {len(payload) / 2, 65536}, {len(payload) - 10, 10}} {
		p := make([]byte, c.n)
		n, err := o.ReadAt(p, int64(c.off))
		if err != nil && !(errors.Is(err, io.EOF) && c.off+c.n >= len(payload)) {
			t.Fatalf("ReadAt(%d,%d): %v", c.off, c.n, err)
		}
		if n != c.n || !bytes.Equal(p, payload[c.off:c.off+c.n]) {
			t.Fatalf("ReadAt(%d,%d): n=%d content mismatch", c.off, c.n, n)
		}
	}
	p := make([]byte, 50)
	n, err := o.ReadAt(p, int64(len(payload)-20))
	if n != 20 || !errors.Is(err, io.EOF) || !bytes.Equal(p[:n], payload[len(payload)-20:]) {
		t.Fatalf("ReadAt across end: n=%d err=%v", n, err)
	}
	if n, err := o.ReadAt(make([]byte, 8), int64(len(payload))); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt at end: n=%d err=%v", n, err)
	}

	sum := sha256.Sum256(payload)
	got, err := blob.SequentialSHA256(ctx, o)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha: %q %v", got, err)
	}

	if _, err := r.Open(ctx, "pfx/missing.zip"); err == nil {
		t.Fatal("opening a missing blob must fail")
	}
}
