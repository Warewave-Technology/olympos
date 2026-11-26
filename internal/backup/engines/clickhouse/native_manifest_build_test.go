package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"maps"
	"path"
	"slices"
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

// build builds the run's manifest on base; an incremental's base URL is the
// one its .backup names (the capture's).
func (d nativeRunData) build(runID string, base []*NativeManifest) (*NativeManifest, error) {
	return BuildNativeManifest(NativeBuild{RunID: runID, ServerVersion: "25.8.33.6", Settings: map[string]string{"id": runID},
		Objects: d.objects, Body: d.body, Base: base, BaseURL: d.meta.BaseBackup})
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

// structureOnly is d as a BACKUP with structure_only = 1 leaves it (R40,
// seen on 24.8 and 25.8): a .backup that lists only the metadata/*.sql
// files, and only those objects.
func (d nativeRunData) structureOnly(t *testing.T, runID string) nativeRunData {
	t.Helper()
	var files strings.Builder
	out := nativeRunData{bodies: map[string][]byte{}}
	for _, f := range d.meta.Files {
		if !strings.HasPrefix(f.Name, "metadata/") {
			continue
		}
		fmt.Fprintf(&files, "<file><name>%s</name><size>%d</size><checksum>%s</checksum></file>", f.Name, f.Size, f.Checksum)
		key := runID + "/" + f.Name
		out.bodies[key] = d.bodies[key]
		out.objects = append(out.objects, ingest.ObjectRecord{Key: key, Size: int64(f.Size), SHA256: sum(key)})
	}
	raw := []byte("<config><version>1</version><deduplicate_files>1</deduplicate_files><timestamp>2026-11-25 23:47:49</timestamp>" +
		"<uuid>9a004670-dfb8-457c-a0eb-15bb4afc0f01</uuid><contents>" + files.String() + "</contents></config>")
	meta, err := ParseBackupMeta(raw)
	if err != nil {
		t.Fatal(err)
	}
	out.meta = meta
	out.bodies[runID+"/.backup"] = raw
	out.objects = append(out.objects, ingest.ObjectRecord{Key: runID + "/.backup", Size: int64(len(raw)), SHA256: sum(runID + "/.backup")})
	return out
}

// R40: a test run's BACKUP has structure_only = 1. Its manifest has the
// databases and their objects, no part rows and no rows; a structure-only
// build refuses a .backup that lists any data file.
func TestBuildNativeManifestStructureOnly(t *testing.T) {
	for _, ver := range nativeVersions {
		t.Run(ver, func(t *testing.T) {
			full := nativeRunOf(t, ver, "full", captureFullRun)
			so := full.structureOnly(t, captureFullRun)
			m, err := BuildNativeManifest(NativeBuild{RunID: captureFullRun, ServerVersion: "25.8.33.6",
				Settings: statementSettings(captureFullRun, true, ""), Objects: so.objects, Body: so.body, StructureOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(m.PartRows) != 0 || m.Settings["structure_only"] != "1" || len(m.Databases) != 1 || rowsOf(t, m, "spike", "events") != 0 {
				t.Fatalf("manifest: %+v", m)
			}
			if _, err := Sign(context.Background(), newFakeVault(), testManifestKey, m); err != nil {
				t.Fatal(err)
			}
			_, err = BuildNativeManifest(NativeBuild{RunID: captureFullRun, ServerVersion: "25.8.33.6",
				Settings: statementSettings(captureFullRun, true, ""), Objects: full.objects, Body: full.body, StructureOnly: true})
			if !errors.Is(err, ErrNativeMeta) || !strings.Contains(err.Error(), "structure-only") {
				t.Fatalf("a structure-only build of a backup with data: %v", err)
			}
		})
	}
	// Signed as a test run's: the settings say structure_only.
	so := nativeRunOf(t, "25.8", "full", captureFullRun).structureOnly(t, captureFullRun)
	res, err := Engine{}.SignNativeManifest(context.Background(), backup.NativeManifestInput{KV: newFakeVault(), KeyName: testManifestKey,
		RunID: captureFullRun, ServerVersion: "25.8.33.6", Objects: so.objects, Captured: so.body, StructureOnly: true})
	if err != nil || !strings.Contains(string(res.Signed), `"structure_only":"1"`) {
		t.Fatalf("signed: %v %.300s", err, res.Signed)
	}
}

// R43: an object the client stored that .backup does not list (other than
// .backup itself) is left out of the signed manifest: it signs only what
// ClickHouse declared. The run is not failed; the worker leaves the object
// tagged incomplete and logs it (Unlisted).
func TestBuildNativeManifestUnlisted(t *testing.T) {
	full := nativeRunOf(t, "25.8", "full", captureFullRun)
	declared := len(full.objects)
	extra := []ingest.ObjectRecord{
		{Key: captureFullRun + "/data/spike/events/extra.bin", Size: 3, SHA256: sum("extra")},
		{Key: captureFullRun + "/notes.txt", Size: 5, SHA256: sum("notes")},
	}
	objects := append(append([]ingest.ObjectRecord{}, extra[0]), full.objects...)
	objects = append(objects, extra[1])
	m, err := BuildNativeManifest(NativeBuild{RunID: captureFullRun, ServerVersion: "25.8.33.6", Settings: map[string]string{"id": captureFullRun},
		Objects: objects, Body: full.body})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Objects) != declared {
		t.Fatalf("%d objects in the manifest, want the %d .backup declares", len(m.Objects), declared)
	}
	for _, o := range m.Objects {
		if o.Key == extra[0].Key || o.Key == extra[1].Key {
			t.Fatalf("the unlisted %s is in the manifest", o.Key)
		}
	}
	res, err := Engine{}.SignNativeManifest(context.Background(), backup.NativeManifestInput{KV: newFakeVault(), KeyName: testManifestKey,
		RunID: captureFullRun, ServerVersion: "25.8.33.6", Objects: objects, Captured: full.body})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != declared || !slices.Equal(res.Unlisted, []string{extra[0].Key, extra[1].Key}) {
		t.Fatalf("signed %d objects, unlisted %v", len(res.Objects), res.Unlisted)
	}
}

// partRun is a small synthetic run of Log tables db.t and db.u, whose
// count.txt files sit right under the table: files are the .backup's file
// entries, written the bodies of what the run stored.
func partRun(t *testing.T, runID, extra, files string, written map[string]string) nativeRunData {
	t.Helper()
	raw := metaXML(extra, files)
	meta, err := ParseBackupMeta(raw)
	if err != nil {
		t.Fatal(err)
	}
	d := nativeRunData{meta: meta, bodies: map[string][]byte{runID + "/.backup": raw}}
	d.objects = append(d.objects, ingest.ObjectRecord{Key: runID + "/.backup", Size: int64(len(raw)), SHA256: sum(runID + "/.backup")})
	for name, body := range written {
		key := runID + "/" + name
		d.bodies[key] = []byte(body)
		d.objects = append(d.objects, ingest.ObjectRecord{Key: key, Size: int64(len(body)), SHA256: sum(key)})
	}
	return d
}

const (
	partDB  = "CREATE DATABASE db ENGINE = Atomic"
	partT   = "CREATE TABLE db.t (`id` UInt64) ENGINE = Log"
	partU   = "CREATE TABLE db.u (`id` UInt64) ENGINE = Log"
	sumC    = "0b3e1f8a9c7d6e5f4a3b2c1d0e9f8a7b"
	sumD    = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"
	sumMeta = "5ba78923f51d5edd121a52d16eff03fc"
)

// partFull is a full run whose db.t holds 7 rows ("7", checksum sumC).
func partFull(t *testing.T) (nativeRunData, *NativeManifest) {
	t.Helper()
	files := fileXML("metadata/db.sql", len(partDB), "<checksum>"+sumMeta+"</checksum>") +
		fileXML("metadata/db/t.sql", len(partT), "<checksum>"+sumA+"</checksum>") +
		fileXML("metadata/db/u.sql", len(partU), "<checksum>"+sumB+"</checksum>") +
		fileXML("data/db/t/count.txt", 1, "<checksum>"+sumC+"</checksum>")
	d := partRun(t, testBaseRunID, "", files, map[string]string{"metadata/db.sql": partDB, "metadata/db/t.sql": partT,
		"metadata/db/u.sql": partU, "data/db/t/count.txt": "7"})
	m, err := d.build(testBaseRunID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return d, m
}

// TestBuildNativeManifestPartlyInBase (task 13): a count.txt whose first
// bytes are its base's (a Log table that grew from 7 to 73 rows: ClickHouse
// writes "3" and takes "7" from the base) is the base's bytes followed by the
// run's, not the run's tail alone; one deduplicated to it counts the same.
// The base's bytes are the base's count.txt of that size and checksum
// (base_size, base_checksum), counted from the base's manifest.
func TestBuildNativeManifestPartlyInBase(t *testing.T) {
	full, base := partFull(t)
	baseXML := `<base_backup>S3('http://h/olympos/` + testBaseRunID + `/')</base_backup>` +
		`<base_backup_uuid>62c08f3c-f80a-4c02-aabb-255897f0c3fc</base_backup_uuid>`
	inMeta := fileXML("metadata/db.sql", len(partDB), "<checksum>"+sumMeta+"</checksum><use_base>true</use_base>") +
		fileXML("metadata/db/t.sql", len(partT), "<checksum>"+sumA+"</checksum><use_base>true</use_base>") +
		fileXML("metadata/db/u.sql", len(partU), "<checksum>"+sumB+"</checksum><use_base>true</use_base>")
	partly := func(baseSize int, baseSum string) string {
		return fmt.Sprintf("<checksum>%s</checksum><use_base>true</use_base><base_size>%d</base_size><base_checksum>%s</base_checksum>",
			sumD, baseSize, baseSum)
	}
	incr := func(t *testing.T, count, tail string) nativeRunData {
		d := partRun(t, testRunID, baseXML, inMeta+count, map[string]string{"data/db/t/count.txt": tail})
		maps.Copy(d.bodies, full.bodies)
		return d
	}

	d := incr(t, fileXML("data/db/u/count.txt", 2, partly(1, sumC)+"<data_file>data/db/t/count.txt</data_file>")+
		fileXML("data/db/t/count.txt", 2, partly(1, sumC)), "3")
	m, err := d.build(testRunID, []*NativeManifest{base})
	if err != nil {
		t.Fatal(err)
	}
	if m.PartRows["data/db/t/count.txt"] != 73 || m.PartRows["data/db/u/count.txt"] != 73 || rowsOf(t, m, "db", "t") != 73 {
		t.Fatalf("part rows %v", m.PartRows)
	}

	for name, d := range map[string]nativeRunData{
		// No count.txt of the base has that size and checksum.
		"another base checksum": incr(t, fileXML("data/db/t/count.txt", 2, partly(1, sumD)), "3"),
		// The base's bytes and the run's are no row count together.
		"no count": incr(t, fileXML("data/db/t/count.txt", 2, partly(1, sumC)), "x"),
	} {
		if _, err := d.build(testRunID, []*NativeManifest{base}); !errors.Is(err, ErrNativeMeta) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A base whose rows for that count.txt are not base_size digits.
	wrong := *base
	wrong.PartRows = map[string]uint64{"data/db/t/count.txt": 70}
	d = incr(t, fileXML("data/db/t/count.txt", 2, partly(1, sumC)), "3")
	if _, err := d.build(testRunID, []*NativeManifest{&wrong}); !errors.Is(err, ErrNativeMeta) {
		t.Errorf("base rows of another length: %v", err)
	}
}

// TestSignNativeManifestIncremental (task 13): the worker hands the engine
// its base chain's signed manifests and a reader of the chain's objects. The
// engine verifies the chain itself, reads from it only what is not the
// run's own (the base's .backup and the metadata the run did not write
// again), and the manifest names its base and the BACKUP's base settings.
func TestSignNativeManifestIncremental(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	full := nativeRunOf(t, "25.8", "full", captureFullRun)
	fullM, err := full.build(captureFullRun, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedFull := signedJSON(t, kv, testManifestKey, fullM)
	incr := nativeRunOf(t, "25.8", "incremental", captureIncrRun)
	var read []string
	baseURL := incr.meta.BaseBackup // the URL the BACKUP named its base by
	in := backup.NativeManifestInput{KV: kv, KeyName: testManifestKey, RunID: captureIncrRun, ServerVersion: "25.8.33.6",
		Objects: incr.objects, Captured: incr.body,
		Base: &backup.NativeManifestBase{RunID: captureFullRun, URL: baseURL, Signed: [][]byte{signedFull},
			Read: func(_ context.Context, key string, limit int64) ([]byte, error) {
				read = append(read, key)
				b, ok := full.bodies[key]
				if !ok || int64(len(b)) > limit {
					return nil, fmt.Errorf("no %s", key)
				}
				return b, nil
			}}}
	res, err := Engine{}.SignNativeManifest(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	m, err := VerifySigned(ctx, kv, testManifestKey, captureIncrRun, res.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if m.BaseRunID != captureFullRun || m.BaseManifestSHA256 != fullM.SHA256() || m.Settings["base_backup"] != "S3('"+baseURL+"')" ||
		m.Settings["use_same_s3_credentials_for_base_backup"] != "1" {
		t.Fatalf("manifest: base %s %s, settings %v", m.BaseRunID, m.BaseManifestSHA256, m.Settings)
	}
	if len(read) == 0 || !slices.Contains(read, captureFullRun+"/.backup") {
		t.Fatalf("read of the base: %v", read)
	}
	for _, k := range read {
		if !strings.HasPrefix(k, captureFullRun+"/") {
			t.Errorf("read %s, not an object of the base", k)
		}
	}
	if _, err := VerifyChain(ctx, kv, testManifestKey, captureIncrRun, [][]byte{signedFull, res.Signed}); err != nil {
		t.Fatalf("the chain: %v", err)
	}

	// A base chain that does not verify as the base run's is no base.
	other := in
	other.Base = &backup.NativeManifestBase{RunID: testOtherRunID, URL: baseURL, Signed: [][]byte{signedFull}, Read: in.Base.Read}
	if _, err := (Engine{}).SignNativeManifest(ctx, other); !IsNotVerified(err) {
		t.Fatalf("a chain of another run: %v", err)
	}
	// A base the reader cannot read fails the build, with the reader's error.
	broken := in
	broken.Base = &backup.NativeManifestBase{RunID: captureFullRun, URL: baseURL, Signed: [][]byte{signedFull},
		Read: func(context.Context, string, int64) ([]byte, error) { return nil, errors.New("storage unreachable") }}
	if _, err := (Engine{}).SignNativeManifest(ctx, broken); !errors.Is(err, ErrNativeMeta) || !strings.Contains(err.Error(), "storage unreachable") {
		t.Fatalf("an unreadable base: %v", err)
	}
}

// TestVerifyNativeChain: the worker verifies a base chain through the
// engine, and gets each run's objects and manifest hash.
func TestVerifyNativeChain(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	base := chainBase()
	inc := chainIncremental(base, testRunID)
	raws := [][]byte{signedJSON(t, kv, testManifestKey, base), signedJSON(t, kv, testManifestKey, inc)}
	got, err := Engine{}.VerifyNativeChain(ctx, kv, testManifestKey, testRunID, raws)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RunID != testBaseRunID || got[0].SHA256 != base.SHA256() || got[1].SHA256 != inc.SHA256() ||
		len(got[1].Objects) != len(inc.Objects) {
		t.Fatalf("chain: %+v", got)
	}
	if _, err := (Engine{}).VerifyNativeChain(ctx, kv, testManifestKey, testOtherRunID, raws); !IsNotVerified(err) {
		t.Fatalf("another run expected: %v", err)
	}
}

// TestBuildNativeManifestBoundToBase (task 13, fix round 1): an incremental
// is built only on the base it names: its .backup's base_backup is the URL
// the run gave ClickHouse, its base_backup_uuid the verified base .backup's
// <uuid>, and every file it takes from the base is a file of the base's
// .backup of that size and checksum.
func TestBuildNativeManifestBoundToBase(t *testing.T) {
	full, base := partFull(t)
	baseURL := "http://h/olympos/" + testBaseRunID + "/"
	baseXML := func(url, id string) string {
		return `<base_backup>S3('` + url + `')</base_backup><base_backup_uuid>` + id + `</base_backup_uuid>`
	}
	const fullUUID = "62c08f3c-f80a-4c02-aabb-255897f0c3fc"
	meta := func(tSum string) string {
		return fileXML("metadata/db.sql", len(partDB), "<checksum>"+sumMeta+"</checksum><use_base>true</use_base>") +
			fileXML("metadata/db/t.sql", len(partT), "<checksum>"+tSum+"</checksum><use_base>true</use_base>") +
			fileXML("metadata/db/u.sql", len(partU), "<checksum>"+sumB+"</checksum><use_base>true</use_base>") +
			fileXML("data/db/t/count.txt", 1, "<checksum>"+sumC+"</checksum><use_base>true</use_base>")
	}
	build := func(extra, files, url string) error {
		d := partRun(t, testRunID, extra, files, nil)
		maps.Copy(d.bodies, full.bodies)
		_, err := BuildNativeManifest(NativeBuild{RunID: testRunID, ServerVersion: "25.8.33.6", Settings: map[string]string{"id": testRunID},
			Objects: d.objects, Body: d.body, Base: []*NativeManifest{base}, BaseURL: url})
		return err
	}
	if err := build(baseXML(baseURL, fullUUID), meta(sumA), baseURL); err != nil {
		t.Fatalf("bound to its base: %v", err)
	}
	for name, err := range map[string]error{
		"another base URL":       build(baseXML("http://h/olympos/"+testOtherRunID+"/", fullUUID), meta(sumA), baseURL),
		"another URL expected":   build(baseXML(baseURL, fullUUID), meta(sumA), "http://other/olympos/"+testBaseRunID+"/"),
		"another base .backup":   build(baseXML(baseURL, "5d1492d5-3a5e-46db-a6ae-3e8afa751a45"), meta(sumA), baseURL),
		"a file not in the base": build(baseXML(baseURL, fullUUID), meta(sumD), baseURL),
	} {
		if !errors.Is(err, ErrNativeMeta) || !strings.Contains(err.Error(), "base") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
