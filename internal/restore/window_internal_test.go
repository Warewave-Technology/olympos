package restore

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

type countingReaderAt struct {
	*bytes.Reader
	reads int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.reads++
	return c.Reader.ReadAt(p, off)
}

func (c *countingReaderAt) Close() error { return nil }

// The read-ahead window returns exactly what the object holds, at any
// offset and size, and turns sequential small reads into few large ones.
func TestWindowObject(t *testing.T) {
	data := make([]byte, 100_000)
	rnd := rand.New(rand.NewSource(1))
	rnd.Read(data)
	under := &countingReaderAt{Reader: bytes.NewReader(data)}
	w := newWindowObject(under, 8192)
	for i := 0; i < 2000; i++ {
		off := rnd.Int63n(int64(len(data)) + 10)
		p := make([]byte, rnd.Intn(10_000))
		n, err := w.ReadAt(p, off)
		want := make([]byte, len(p))
		wn, werr := bytes.NewReader(data).ReadAt(want, off)
		if n != wn || !bytes.Equal(p[:n], want[:wn]) || (err == nil) != (werr == nil) {
			t.Fatalf("ReadAt(%d, %d) = %d, %v; want %d, %v", len(p), off, n, err, wn, werr)
		}
	}

	under.reads = 0
	w = newWindowObject(under, 8192)
	r := io.NewSectionReader(w, 0, w.Size())
	var out bytes.Buffer
	buf := make([]byte, 512)
	if _, err := io.CopyBuffer(struct{ io.Writer }{&out}, struct{ io.Reader }{r}, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("sequential read differs")
	}
	if want := (len(data) + 8191) / 8192; under.reads != want {
		t.Fatalf("%d reads of the object for a sequential pass, want %d", under.reads, want)
	}
}
