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

// The progress counts each byte of the backup once: the directory of a zip
// read at the end first, then the entries, and the read-ahead window
// reading again what it dropped, never add up to more than the copy.
func TestCoverage(t *testing.T) {
	var c coverage
	steps := []struct {
		off, end, want int64
	}{
		{900, 1000, 100}, // the zip directory, at the end
		{0, 100, 200},
		{50, 150, 250},  // overlaps the first span
		{150, 200, 300}, // adjacent: merged
		{0, 200, 300},   // read again
		{400, 500, 400},
		{190, 410, 600}, // bridges two spans
		{500, 500, 600}, // empty
		{0, 1000, 1000},
		{0, 1000, 1000},
	}
	for i, s := range steps {
		if got := c.add(s.off, s.end); got != s.want {
			t.Fatalf("step %d: add(%d, %d) = %d, want %d (spans %v)", i, s.off, s.end, got, s.want, c.spans)
		}
	}
	if len(c.spans) != 1 {
		t.Fatalf("spans %v", c.spans)
	}

	// Through the window, over a pass read twice: bytes stay at the size.
	data := make([]byte, 50_000)
	p := &progressWriter{kick: make(chan struct{}, 1)}
	w := newWindowObject(&countingObject{Object: &countingReaderAt{Reader: bytes.NewReader(data)}, p: p}, 8192)
	for pass := 0; pass < 2; pass++ {
		if _, err := io.Copy(io.Discard, io.NewSectionReader(w, 0, w.Size())); err != nil {
			t.Fatal(err)
		}
		if _, err := w.ReadAt(make([]byte, 100), w.Size()-100); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.read.Load(); got != int64(len(data)) {
		t.Fatalf("bytes read = %d, want %d", got, len(data))
	}
}
