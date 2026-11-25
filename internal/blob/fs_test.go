package blob_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/blob"
)

// nfsRoot builds <tmp>/nfs with mounts "nas" and "ro" (read-only), a
// hidden dir, a plain file and a symlinked "mount" pointing outside.
func nfsRoot(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "nfs")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{root + "/nas/olympos", root + "/ro", root + "/.snapshot", outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "nas", "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "ro"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "ro"), 0o755) })
	return root, outside
}

func TestListMounts(t *testing.T) {
	root, _ := nfsRoot(t)
	ms, err := blob.ListMounts(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Name != "nas" || ms[0].Path != filepath.Join(root, "nas") || !ms[0].Writable || ms[1].Name != "ro" {
		t.Fatalf("mounts: %+v", ms)
	}
	if os.Getuid() != 0 && ms[1].Writable {
		t.Fatal("read-only mount reported writable")
	}
	if ms, err := blob.ListMounts(filepath.Join(root, "missing")); err != nil || len(ms) != 0 {
		t.Fatalf("missing root: %v %v", ms, err)
	}
}

func TestResolveFSPath(t *testing.T) {
	root, outside := nfsRoot(t)
	ok := map[string]string{
		root + "/nas":               "nas",
		root + "/nas/olympos":       "nas",
		root + "/nas/new/deeper":    "nas", // creatable
		root + "/nas/./olympos/":    "nas",
		root + "/nas//olympos/x/./": "nas",
	}
	for p, mount := range ok {
		got, m, _, err := blob.ResolveFSPath(root, p)
		if err != nil || m.Name != mount || !strings.HasSuffix(got, strings.TrimSuffix(filepath.Clean(strings.TrimPrefix(p, root)), "/")) {
			t.Errorf("%s: %q %+v %v", p, got, m, err)
		}
	}
	bad := map[string]string{
		"nas/olympos":                  "absolute",
		root:                           "inside a mount",
		filepath.Dir(root):             "inside a mount",
		root + "/nas/../ro":            "'..'",
		root + "/nas/olympos/../../ro": "'..'",
		outside:                        "inside a mount",
		root + "/evil":                 "not a mounted volume", // symlinked mount
		root + "/evil/x":               "not a mounted volume",
		root + "/.snapshot":            "not a mounted volume",
		root + "/README":               "not a mounted volume",
		root + "/missing":              "not a mounted volume",
		root + "/nas/escape":           "symlink escape",
		root + "/nas/escape/sub/dir":   "symlink escape",
	}
	for p, want := range bad {
		if _, _, _, err := blob.ResolveFSPath(root, p); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error containing %q, got %v", p, want, err)
		}
	}
}

type failingReader struct {
	r io.Reader
	n int
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("engine failed")
	}
	if len(p) > f.n {
		p = p[:f.n]
	}
	n, err := f.r.Read(p)
	f.n -= n
	return n, err
}

func TestFSWriter(t *testing.T) {
	root, outside := nfsRoot(t)
	ctx := context.Background()
	w, err := blob.OpenFS(blob.FSTarget{Name: "nas", Path: root + "/nas/olympos/backups", Prefix: "pfx"}, blob.StorageOptions{NFSRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if w.Prefix() != "pfx" || w.Mount().Name != "nas" {
		t.Fatalf("writer: %q %+v", w.Prefix(), w.Mount())
	}
	if created, err := w.EnsureDir(); err != nil || !created {
		t.Fatalf("ensure dir: %v %v", created, err)
	}
	if created, err := w.EnsureDir(); err != nil || created {
		t.Fatalf("ensure dir again: %v %v", created, err)
	}

	payload := bytes.Repeat([]byte("olympos-nfs-"), 300_000) // ~3.6 MB
	sum := sha256.Sum256(payload)
	p := blob.Join(w.Prefix(), "prod/db/orders/postgres/2026/11/18/run1.dump")
	res, err := w.Upload(ctx, p, bytes.NewReader(payload), "application/octet-stream", map[string]string{"olympos-tier": "daily"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != int64(len(payload)) || res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("result: %+v", res)
	}
	file := filepath.Join(w.Dir(), filepath.FromSlash(p))
	got, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("file content: %v", err)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o640 {
		t.Fatalf("file mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Dir(file)); st.Mode().Perm() != 0o750 {
		t.Fatalf("dir mode %v", st.Mode().Perm())
	}
	if _, err := os.Stat(file + ".partial"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("partial file left behind")
	}
	var tags map[string]string
	tb, err := os.ReadFile(file + blob.TagsSuffix)
	if err != nil || json.Unmarshal(tb, &tags) != nil || tags["olympos-tier"] != "daily" {
		t.Fatalf("tags sidecar: %s %v", tb, err)
	}
	if got, err := w.GetTags(ctx, p); err != nil || got["olympos-tier"] != "daily" {
		t.Fatalf("get tags: %v %v", got, err)
	}

	// Never overwrite: the original stays intact.
	if _, err := w.Upload(ctx, p, strings.NewReader("evil"), "", nil); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("overwrite: %v", err)
	}
	if got, _ := os.ReadFile(file); !bytes.Equal(got, payload) {
		t.Fatal("original changed")
	}
	// Tags of a real backup cannot be rewritten.
	if err := w.SetTags(ctx, p, map[string]string{"olympos-tier": "monthly"}); err == nil {
		t.Fatal("SetTags on a backup")
	}

	// A failing stream leaves neither the file nor its partial.
	p2 := blob.Join(w.Prefix(), "prod/db/orders/postgres/2026/11/18/run2.dump")
	if _, err := w.Upload(ctx, p2, &failingReader{r: bytes.NewReader(payload), n: 100_000}, "", nil); err == nil {
		t.Fatal("failing stream must fail")
	}
	f2 := filepath.Join(w.Dir(), filepath.FromSlash(p2))
	for _, x := range []string{f2, f2 + ".partial"} {
		if _, err := os.Stat(x); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s left behind", x)
		}
	}
	// A stale partial blocks the upload instead of being clobbered.
	p3 := blob.Join(w.Prefix(), "x/run3.dump")
	_ = os.MkdirAll(filepath.Join(w.Dir(), "pfx/x"), 0o750)
	_ = os.WriteFile(filepath.Join(w.Dir(), "pfx/x/run3.dump.partial"), []byte("other writer"), 0o640)
	if _, err := w.Upload(ctx, p3, strings.NewReader("data"), "", nil); err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("stale partial: %v", err)
	}

	// Traversal and reserved names in blob paths.
	for _, bad := range []string{"../x", "pfx/../../x", "/abs", "pfx/a.partial", "pfx/a.tags.json", ""} {
		if _, err := w.Upload(ctx, bad, strings.NewReader("x"), "", nil); err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
	// A symlink planted inside the destination later must not let a write
	// escape the mount.
	if err := os.Symlink(outside, filepath.Join(w.Dir(), "pfx", "planted")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Upload(ctx, "pfx/planted/run.dump", strings.NewReader("x"), "", nil); err == nil || !strings.Contains(err.Error(), "symlink escape") {
		t.Fatalf("planted symlink: %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatal("wrote outside the mount")
	}

	// Probe: delete only under .olympos-probe/, and it succeeds on a plain
	// filesystem (= the server CAN delete).
	if _, err := w.ProbeDeleteRefused(ctx, p); err == nil {
		t.Fatal("delete of a backup must be refused by the code")
	}
	probe := blob.Join(w.Prefix(), blob.ProbeDir, "abc")
	if _, err := w.Upload(ctx, probe, strings.NewReader("probe"), "text/plain", nil); err != nil {
		t.Fatal(err)
	}
	if err := w.SetTags(ctx, probe, map[string]string{"olympos-probe": "1"}); err != nil {
		t.Fatal(err)
	}
	if tg, _ := w.GetTags(ctx, probe); tg["olympos-probe"] != "1" {
		t.Fatal("probe tag")
	}
	if b, err := w.Download(ctx, probe, 100); err != nil || string(b) != "probe" {
		t.Fatalf("download: %q %v", b, err)
	}
	refused, err := w.ProbeDeleteRefused(ctx, probe)
	if err != nil || refused {
		t.Fatalf("probe delete: %v %v", refused, err)
	}
	pf := filepath.Join(w.Dir(), filepath.FromSlash(probe))
	if _, err := os.Stat(pf + blob.TagsSuffix); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("probe tags sidecar left")
	}

	// A directory the server cannot modify refuses the delete (WORM-like).
	if os.Getuid() != 0 {
		probe2 := blob.Join(w.Prefix(), blob.ProbeDir, "def")
		if _, err := w.Upload(ctx, probe2, strings.NewReader("probe"), "text/plain", nil); err != nil {
			t.Fatal(err)
		}
		pd := filepath.Dir(filepath.Join(w.Dir(), filepath.FromSlash(probe2)))
		_ = os.Chmod(pd, 0o550)
		t.Cleanup(func() { _ = os.Chmod(pd, 0o750) })
		if refused, err := w.ProbeDeleteRefused(ctx, probe2); err != nil || !refused {
			t.Fatalf("read-only dir: %v %v", refused, err)
		}
	}

	// Opening a path outside any mount fails.
	if _, err := blob.OpenFS(blob.FSTarget{Path: outside}, blob.StorageOptions{NFSRoot: root}); err == nil {
		t.Fatal("outside mount")
	}
	// A read-only mount fails EnsureDir.
	if os.Getuid() != 0 {
		ro, err := blob.OpenFS(blob.FSTarget{Path: root + "/ro"}, blob.StorageOptions{NFSRoot: root})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ro.EnsureDir(); err == nil || !strings.Contains(err.Error(), "not writable") {
			t.Fatalf("ro mount: %v", err)
		}
	}
}

// TestFSSetTagsNativeRun: a native run's objects are tagged complete after
// its manifest is signed, so SetTags rewrites the tags of an object inside a
// run's directory (<…>/<run-id>/<key>) that exists; never of anything else.
func TestFSSetTagsNativeRun(t *testing.T) {
	root, _ := nfsRoot(t)
	ctx := context.Background()
	w, err := blob.OpenFS(blob.FSTarget{Name: "nas", Path: root + "/nas/olympos/backups", Prefix: "pfx"}, blob.StorageOptions{NFSRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	const run = "0f6b2a4e-8d1c-4f3a-9b7e-2c5d8a1f6e30"
	dir := blob.Join(w.Prefix(), "prod/db/orders/clickhouse/2026/11/26/"+run)
	obj := dir + "/data/sales/orders/all_1_1_0/data.bin"
	incomplete := map[string]string{"olympos-tier": "daily", "olympos-state": "incomplete"}
	if _, err := w.Upload(ctx, obj, strings.NewReader("part"), "application/octet-stream", incomplete); err != nil {
		t.Fatal(err)
	}
	complete := map[string]string{"olympos-tier": "daily", "olympos-state": "complete"}
	if err := w.SetTags(ctx, obj, complete); err != nil {
		t.Fatal(err)
	}
	if got, err := w.GetTags(ctx, obj); err != nil || got["olympos-state"] != "complete" || got["olympos-tier"] != "daily" {
		t.Fatalf("tags: %v %v", got, err)
	}
	if b, err := w.Download(ctx, obj, 100); err != nil || string(b) != "part" {
		t.Fatalf("the object changed: %q %v", b, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(filepath.Join(w.Dir(), filepath.FromSlash(obj))))
	if len(ents) != 2 {
		t.Fatalf("left behind: %v", ents)
	}

	// The run's manifest, next to its directory, is tagged complete last.
	manifest := blob.Join(w.Prefix(), "prod/db/orders/clickhouse/2026/11/26/"+run+".manifest.json")
	if _, err := w.Upload(ctx, manifest, strings.NewReader("{}"), "application/json", incomplete); err != nil {
		t.Fatal(err)
	}
	if err := w.SetTags(ctx, manifest, complete); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.GetTags(ctx, manifest); got["olympos-state"] != "complete" {
		t.Fatalf("manifest tags: %v", got)
	}

	const other = "7c2e9d14-3b6a-4e8f-a1d5-9f0b4c7e2a61"
	logical := blob.Join(w.Prefix(), "prod/db/orders/clickhouse/2026/11/26/"+other+".zip")
	logicalManifest := blob.Join(w.Prefix(), "prod/db/orders/clickhouse/2026/11/26/"+other+".manifest.json")
	for _, p := range []string{logical, logicalManifest} {
		if _, err := w.Upload(ctx, p, strings.NewReader("zip"), "", map[string]string{"olympos-tier": "daily"}); err != nil {
			t.Fatal(err)
		}
	}
	for name, p := range map[string]string{
		"a logical backup":            logical,
		"a logical run's manifest":    logicalManifest,
		"a native manifest missing":   blob.Join(w.Prefix(), "prod/db/orders/clickhouse/2026/11/27/"+run+".manifest.json"),
		"an object that is missing":   dir + "/data/sales/orders/all_1_1_0/missing.bin",
		"the run's directory":         dir,
		"under a name that is no run": blob.Join(w.Prefix(), "prod/db/orders/clickhouse/2026/11/26/run-1/data.bin"),
		"under an upper-case run":     blob.Join(w.Prefix(), "x/"+strings.ToUpper(run)+"/data.bin"),
		"a tags sidecar":              obj + blob.TagsSuffix,
		"climbing out":                dir + "/../" + other + ".zip",
	} {
		if err := w.SetTags(ctx, p, complete); err == nil {
			t.Errorf("SetTags on %s (%s)", name, p)
		}
	}
	for _, p := range []string{logical, logicalManifest} {
		if got, _ := w.GetTags(ctx, p); got["olympos-state"] != "" {
			t.Fatalf("a logical run's tags changed: %v", got)
		}
	}
}
