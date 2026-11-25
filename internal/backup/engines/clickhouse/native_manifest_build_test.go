package clickhouse

import (
	"context"
	"errors"
	"hash/crc32"
	"maps"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/ingest"
)

// A native run as the ingest endpoint leaves it, built from the captured
// testdata: what BuildNativeManifest reads.

// countBody is a count.txt body of size digits that differs from path to
// path, so that a part resolved from the wrong count.txt shows.
func countBody(run, name string, size uint64) []byte {
	digits := strconv.FormatUint(uint64(crc32.ChecksumIEEE([]byte(run+"/"+name)))|1<<31, 10)
	for uint64(len(digits)) < size {
		digits += digits
	}
	return []byte(digits[:size])
}

// nativeRun is the objects and kept bodies of testdata run (full or
// incremental) of version ver under run ID runID.
type nativeRunData struct {
	meta    *BackupMeta
	objects []ingest.ObjectRecord
	bodies  map[string][]byte
}

func nativeRunOf(t *testing.T, ver, run, runID string) nativeRunData {
	t.Helper()
	raw := readNative(t, ver, run, ".backup")
	meta := parseNative(t, ver, run)
	d := nativeRunData{meta: meta, bodies: metadataFiles(t, ver, run, runID)}
	d.bodies[runID+"/.backup"] = raw
	d.objects = append(d.objects, ingest.ObjectRecord{Key: runID + "/.backup", Size: int64(len(raw)), SHA256: sum(runID + "/.backup")})
	for _, f := range meta.Files {
		if !f.Written() {
			continue
		}
		key := runID + "/" + f.Name
		d.objects = append(d.objects, ingest.ObjectRecord{Key: key, Size: int64(f.Size - f.BaseSize), SHA256: sum(key)})
		if path.Base(f.Name) == "count.txt" {
			d.bodies[key] = countBody(runID, f.Name, f.Size)
		}
	}
	return d
}

func (d nativeRunData) body(key string) ([]byte, bool) {
	b, ok := d.bodies[key]
	return b, ok
}

func (d nativeRunData) build(runID string, base []*NativeManifest) (*NativeManifest, error) {
	return BuildNativeManifest(NativeBuild{RunID: runID, ServerVersion: "25.8.33.6", Settings: map[string]string{"id": runID},
		Objects: d.objects, Body: d.body, Base: base})
}

// wantPartRows is what a .backup's count.txt files hold: a written one its
// own body, a deduplicated one its data file's, one in the base the base's
// count.txt of the same size and checksum (baseMeta, base).
func wantPartRows(t *testing.T, runID string, meta, baseMeta *BackupMeta, base map[string]uint64) map[string]uint64 {
	t.Helper()
	byName := map[string]MetaFile{}
	for _, f := range meta.Files {
		byName[f.Name] = f
	}
	out := map[string]uint64{}
	for _, f := range meta.Files {
		if !strings.HasPrefix(f.Name, "data/") || path.Base(f.Name) != "count.txt" {
			continue
		}
		var n uint64
		var err error
		switch {
		case f.Written():
			n, err = ParseCount(countBody(runID, f.Name, f.Size))
		case f.DataFile != "":
			n, err = ParseCount(countBody(runID, f.DataFile, byName[f.DataFile].Size))
		default:
			found := false
			for _, bf := range baseMeta.Files {
				if bf.Size == f.Size && bf.Checksum == f.Checksum && path.Base(bf.Name) == "count.txt" {
					n, found = base[bf.Name], true
				}
			}
			if !found {
				t.Fatalf("%s: in the base, which has no such count.txt", f.Name)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = n
	}
	return out
}

func rowsOf(t *testing.T, m *NativeManifest, db, name string) uint64 {
	t.Helper()
	for _, d := range m.Databases {
		for _, o := range d.Objects {
			if d.Name == db && o.Name == name {
				return o.Rows
			}
		}
	}
	t.Fatalf("no %s.%s in %+v", db, name, m.Databases)
	return 0
}

// TestBuildNativeManifest (R27): the manifest of a full run lists its
// objects and the objects of its metadata, every part's rows, and per table
// the sum of its parts, a deduplicated count.txt counted from the file it
// names.
func TestBuildNativeManifest(t *testing.T) {
	for _, ver := range nativeVersions {
		t.Run(ver, func(t *testing.T) {
			full := nativeRunOf(t, ver, "full", captureFullRun)
			m, err := full.build(captureFullRun, nil)
			if err != nil {
				t.Fatal(err)
			}
			if m.Format != NativeManifestFormat || m.RunID != captureFullRun || m.BaseRunID != "" || m.ServerVersion != "25.8.33.6" ||
				m.Settings["id"] != captureFullRun || len(m.Objects) != len(full.objects) {
				t.Fatalf("manifest: %+v", m)
			}
			want := wantPartRows(t, captureFullRun, full.meta, nil, nil)
			if !maps.Equal(m.PartRows, want) || len(want) < 5 {
				t.Fatalf("part rows:\n got %v\nwant %v", m.PartRows, want)
			}
			part := func(p string) uint64 { return want["data/spike/"+p+"/count.txt"] }
			// The one part of a MergeTree table, whatever its name.
			only := func(table string) uint64 {
				var n uint64
				for p, rows := range want {
					if strings.HasPrefix(p, "data/spike/"+table+"/") && strings.Count(p, "/") == 4 {
						n += rows
					}
				}
				return n
			}
			for name, rows := range map[string]uint64{
				"events":      part("events/202611_1_1_0"),
				"countries":   only("countries"),
				"daily":       only("daily"),
				"applog":      part("applog"),
				"applog_copy": part("applog"), // its count.txt is applog's (data_file)
				// The inner table of an MV without TO is counted for the view.
				"big_amounts":    only("big_amounts"),
				"daily_mv":       0,
				"countries_dict": 0,
				"recent":         0,
			} {
				if got := rowsOf(t, m, "spike", name); got != rows || name == "events" && rows == 0 {
					t.Errorf("%s: %d rows, want %d", name, got, rows)
				}
			}
			// It signs: Sign accepts what BuildNativeManifest builds.
			if _, err := Sign(context.Background(), newFakeVault(), testManifestKey, m); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestBuildNativeManifestIncremental (R27, R32): an incremental's parts and
// metadata in its base come from the base chain: the rows from the base's
// part rows, the DDL from the base's object.
func TestBuildNativeManifestIncremental(t *testing.T) {
	for _, ver := range nativeVersions {
		t.Run(ver, func(t *testing.T) {
			full := nativeRunOf(t, ver, "full", captureFullRun)
			base, err := full.build(captureFullRun, nil)
			if err != nil {
				t.Fatal(err)
			}
			incr := nativeRunOf(t, ver, "incremental", captureIncrRun)
			// Without its base, an incremental is refused (R32).
			if _, err := incr.build(captureIncrRun, nil); !errors.Is(err, ErrNativeMeta) || !strings.Contains(err.Error(), "base") {
				t.Fatalf("an incremental without its base: %v", err)
			}
			maps.Copy(incr.bodies, full.bodies) // the base's metadata, as Task 13 serves it
			m, err := incr.build(captureIncrRun, []*NativeManifest{base})
			if err != nil {
				t.Fatal(err)
			}
			if m.BaseRunID != captureFullRun || m.BaseManifestSHA256 != base.SHA256() {
				t.Fatalf("base: %s %s", m.BaseRunID, m.BaseManifestSHA256)
			}
			want := wantPartRows(t, captureIncrRun, incr.meta, full.meta, base.PartRows)
			if !maps.Equal(m.PartRows, want) {
				t.Fatalf("part rows:\n got %v\nwant %v", m.PartRows, want)
			}
			var inBase int
			for _, f := range incr.meta.Files {
				if path.Base(f.Name) == "count.txt" && f.UseBase {
					inBase++
				}
			}
			if inBase == 0 {
				t.Fatal("the testdata has no count.txt in the base")
			}
			// Unchanged metadata is the base's object; changed metadata the run's.
			for _, d := range m.Databases {
				for _, o := range d.Objects {
					run := captureFullRun
					if o.Name == "events" || o.Name == "added" {
						run = captureIncrRun
					}
					if !strings.HasPrefix(o.DDLKey, run+"/") {
						t.Errorf("%s: DDL %s, want one of run %s", o.Name, o.DDLKey, run)
					}
				}
			}
			if _, err := Sign(context.Background(), newFakeVault(), testManifestKey, m); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestBuildNativeManifestRefuses: a run whose manifest cannot say what it
// stored, or how many rows a part holds, fails.
func TestBuildNativeManifestRefuses(t *testing.T) {
	const ver = "25.8"
	run := captureFullRun
	events := run + "/data/spike/events/202611_1_1_0/count.txt"
	for name, change := range map[string]func(d *nativeRunData) []*NativeManifest{
		"no .backup kept": func(d *nativeRunData) []*NativeManifest { delete(d.bodies, run+"/.backup"); return nil },
		".backup not XML": func(d *nativeRunData) []*NativeManifest { d.bodies[run+"/.backup"] = []byte("{}"); return nil },
		"a file not stored": func(d *nativeRunData) []*NativeManifest {
			d.objects = d.objects[:len(d.objects)-1]
			return nil
		},
		"a file stored short": func(d *nativeRunData) []*NativeManifest {
			d.objects[len(d.objects)-1].Size--
			return nil
		},
		"a count.txt not kept": func(d *nativeRunData) []*NativeManifest { delete(d.bodies, events); return nil },
		"a count.txt that is no count": func(d *nativeRunData) []*NativeManifest {
			d.bodies[events] = []byte("12 ")
			return nil
		},
		"a metadata file not kept": func(d *nativeRunData) []*NativeManifest {
			delete(d.bodies, run+"/metadata/spike/events.sql")
			return nil
		},
		"a base for a full backup": func(d *nativeRunData) []*NativeManifest {
			return []*NativeManifest{chainBase()}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := nativeRunOf(t, ver, "full", run)
			base := change(&d)
			if m, err := d.build(run, base); !errors.Is(err, ErrNativeMeta) && !errors.Is(err, ErrManifestInvalid) {
				t.Fatalf("built %v, %v", m != nil, err)
			}
		})
	}

	// A part of an incremental that the base chain does not count.
	full := nativeRunOf(t, ver, "full", captureFullRun)
	base, err := full.build(captureFullRun, nil)
	if err != nil {
		t.Fatal(err)
	}
	base.PartRows = map[string]uint64{}
	incr := nativeRunOf(t, ver, "incremental", captureIncrRun)
	maps.Copy(incr.bodies, full.bodies)
	if _, err := incr.build(captureIncrRun, []*NativeManifest{base}); !errors.Is(err, ErrNativeMeta) || !strings.Contains(err.Error(), "rows") {
		t.Fatalf("a part the base does not count: %v", err)
	}
}

// TestSignNativeManifest: the worker's manifest is built, signed and
// verified; what it returns is the stored form, as signed, that a reader
// verifies as the run's.
func TestSignNativeManifest(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	full := nativeRunOf(t, "25.8", "full", captureFullRun)
	res, err := Engine{}.SignNativeManifest(ctx, backup.NativeManifestInput{KV: kv, KeyName: testManifestKey, RunID: captureFullRun,
		ServerVersion: "25.8.33.6", Objects: full.objects, Captured: full.body})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(res.Signed), `{"key_id":"`+testManifestKey+`/1","manifest":{`) {
		t.Fatalf("stored form: %.80s", res.Signed)
	}
	m, err := VerifySigned(ctx, kv, testManifestKey, captureFullRun, res.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if res.SHA256 != m.SHA256() || m.Settings["id"] != captureFullRun || m.Settings["async"] != "1" || rowsOf(t, m, "spike", "events") == 0 {
		t.Fatalf("manifest %s: %+v", res.SHA256, m)
	}
	// What does not build is not signed.
	delete(full.bodies, captureFullRun+"/.backup")
	if _, err := (Engine{}).SignNativeManifest(ctx, backup.NativeManifestInput{KV: kv, KeyName: testManifestKey, RunID: captureFullRun,
		Objects: full.objects, Captured: full.body}); !errors.Is(err, ErrNativeMeta) {
		t.Fatalf("no .backup: %v", err)
	}
	// A vault that signs with another key than the trusted one fails the
	// verification right after the signature (R25).
	if _, err := (Engine{}).SignNativeManifest(ctx, backup.NativeManifestInput{KV: renamingVault{kv}, KeyName: testManifestKey,
		RunID: captureFullRun, Objects: nativeRunOf(t, "25.8", "full", captureFullRun).objects,
		Captured: nativeRunOf(t, "25.8", "full", captureFullRun).body}); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("signed by another key: %v", err)
	}
}

// renamingVault signs with the key it is asked for, and says another signed.
type renamingVault struct{ *fakeVault }

func (v renamingVault) Sign(ctx context.Context, keyName string, digest []byte) ([]byte, string, error) {
	sig, _, err := v.fakeVault.Sign(ctx, "other-key", digest)
	return sig, "other-key/1", err
}
