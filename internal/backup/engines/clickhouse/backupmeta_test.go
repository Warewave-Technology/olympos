package clickhouse

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The parsers of a native backup's .backup, metadata/*.sql and count.txt,
// on what ClickHouse 24.8 and 25.8 wrote (testdata/native, captured by
// TestCaptureNativeTestdata) and on refusals.

var nativeVersions = []string{"24.8", "25.8"}

func readNative(t *testing.T, ver, run, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "native", ver, run, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseNative(t *testing.T, ver, run string) *BackupMeta {
	t.Helper()
	m, err := ParseBackupMeta(readNative(t, ver, run, ".backup"))
	if err != nil {
		t.Fatalf("%s %s: %v", ver, run, err)
	}
	return m
}

func fileOf(t *testing.T, m *BackupMeta, name string) MetaFile {
	t.Helper()
	for _, f := range m.Files {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no file %s", name)
	return MetaFile{}
}

// storedObjects reads objects.txt: what the run stored besides .backup, as
// key → size.
func storedObjects(t *testing.T, ver, run string) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	for _, line := range strings.Split(strings.TrimSpace(string(readNative(t, ver, run, "objects.txt"))), "\n") {
		size, key, ok := strings.Cut(line, " ")
		n, err := strconv.ParseUint(size, 10, 64)
		if !ok || err != nil {
			t.Fatalf("objects.txt line %q", line)
		}
		if key != ".backup" {
			out[key] = n
		}
	}
	return out
}

// written is what the parsed .backup says the run stored: key → size.
func written(m *BackupMeta) map[string]uint64 {
	out := map[string]uint64{}
	for _, f := range m.Files {
		if f.Written() {
			out[f.Name] = f.Size - f.BaseSize
		}
	}
	return out
}

func TestParseBackupMetaFull(t *testing.T) {
	for _, ver := range nativeVersions {
		t.Run(ver, func(t *testing.T) {
			m := parseNative(t, ver, "full")
			if m.Version != 1 || m.BaseBackup != "" {
				t.Fatalf("version %d, base %q", m.Version, m.BaseBackup)
			}
			// Every metadata object, with the size of the captured body.
			for _, name := range []string{"spike.sql", "spike/applog.sql", "spike/big_amounts.sql", "spike/countries.sql",
				"spike/countries_dict.sql", "spike/daily.sql", "spike/daily_mv.sql", "spike/events.sql", "spike/recent.sql"} {
				f := fileOf(t, m, "metadata/"+name)
				body := readNative(t, ver, "full", "metadata/"+name)
				if f.Size != uint64(len(body)) || len(f.Checksum) != 32 || f.UseBase || f.BaseSize != 0 || f.DataFile != "" || !f.Written() {
					t.Errorf("%s: %+v (body %d bytes)", name, f, len(body))
				}
			}
			ev := fileOf(t, m, "data/spike/events/202611_1_1_0/count.txt")
			if ev.Size != 6 || !ev.Written() {
				t.Errorf("events count.txt: %+v", ev)
			}
			// Identical files are stored once: the later ones name the first.
			dedup := 0
			for _, f := range m.Files {
				if f.DataFile != "" {
					dedup++
					if f.Written() {
						t.Errorf("%s is written and deduplicated", f.Name)
					}
				}
				if f.UseBase {
					t.Errorf("%s: use_base in a full backup", f.Name)
				}
			}
			if dedup == 0 {
				t.Error("no deduplicated file")
			}
			c := fileOf(t, m, "data/spike/countries/all_1_1_0/metadata_version.txt")
			if c.DataFile != "data/spike/big_amounts/all_1_1_0/metadata_version.txt" {
				t.Errorf("countries metadata_version.txt: %+v", c)
			}
			// What the .backup says was written is exactly what was stored.
			if got, want := written(m), storedObjects(t, ver, "full"); !reflect.DeepEqual(got, want) {
				t.Errorf("written %v\nstored %v", got, want)
			}
		})
	}
}

// TestParseBackupMetaIncremental is also the evidence of R23: an
// incremental does not write the metadata of objects whose DDL did not
// change; it marks them use_base.
func TestParseBackupMetaIncremental(t *testing.T) {
	for _, ver := range nativeVersions {
		t.Run(ver, func(t *testing.T) {
			m := parseNative(t, ver, "incremental")
			if m.Version != 1 {
				t.Fatalf("version %d", m.Version)
			}
			// The base's URL, without the credentials 24.8 writes next to it.
			if !strings.HasPrefix(m.BaseBackup, "http://minio:9000/backups/"+ver+"-") ||
				!strings.HasSuffix(m.BaseBackup, "/"+captureFullRun+"/") || strings.ContainsAny(m.BaseBackup, "', ") {
				t.Errorf("base %q", m.BaseBackup)
			}
			meta := map[string]bool{}
			for _, f := range m.Files {
				if strings.HasPrefix(f.Name, "metadata/") {
					meta[f.Name] = f.UseBase
				}
			}
			want := map[string]bool{
				"metadata/spike.sql":                true,
				"metadata/spike/added.sql":          false, // new
				"metadata/spike/applog.sql":         true,
				"metadata/spike/big_amounts.sql":    true,
				"metadata/spike/countries.sql":      true,
				"metadata/spike/countries_dict.sql": true,
				"metadata/spike/daily.sql":          true,
				"metadata/spike/daily_mv.sql":       true,
				"metadata/spike/events.sql":         false, // ALTER TABLE ADD COLUMN
				"metadata/spike/recent.sql":         true,
			}
			if !reflect.DeepEqual(meta, want) {
				t.Errorf("metadata use_base %v, want %v", meta, want)
			}
			for _, name := range []string{"spike/added.sql", "spike/events.sql"} {
				f := fileOf(t, m, "metadata/"+name)
				if f.Size != uint64(len(readNative(t, ver, "incremental", "metadata/"+name))) || !f.Written() {
					t.Errorf("%s: %+v", name, f)
				}
			}
			for _, name := range []string{"spike.sql", "spike/countries.sql", "spike/recent.sql"} {
				f := fileOf(t, m, "metadata/"+name)
				if f.BaseSize != f.Size || f.Written() {
					t.Errorf("%s: %+v", name, f)
				}
			}
			// An unchanged table's part is all in the base; a changed table's
			// new part is written.
			if f := fileOf(t, m, "data/spike/countries/all_1_1_0/data.bin"); !f.UseBase || f.Written() {
				t.Errorf("countries data.bin: %+v", f)
			}
			if f := fileOf(t, m, "data/spike/events/202611_2_2_0/count.txt"); f.UseBase || f.Size != 4 || !f.Written() {
				t.Errorf("new events part count.txt: %+v", f)
			}
			// The base is matched by content, not name: a new part's file
			// whose bytes are in the base is not written.
			if f := fileOf(t, m, "data/spike/events/202611_2_2_0/metadata_version.txt"); !f.UseBase || f.Written() {
				t.Errorf("new part's metadata_version.txt: %+v", f)
			}
			// An appended Log file: its first bytes are the base's, the rest is
			// written.
			if f := fileOf(t, m, "data/spike/applog/__marks.mrk"); !f.UseBase || f.Size != 64 || f.BaseSize != 32 || !f.Written() {
				t.Errorf("applog __marks.mrk: %+v", f)
			}
			// Two count.txt with the same count are stored once.
			if f := fileOf(t, m, "data/spike/applog/count.txt"); f.DataFile != "data/spike/added/count.txt" || f.Written() {
				t.Errorf("applog count.txt: %+v", f)
			}
			if got, want := written(m), storedObjects(t, ver, "incremental"); !reflect.DeepEqual(got, want) {
				t.Errorf("written %v\nstored %v", got, want)
			}
		})
	}
}

// metaXML builds a .backup around the given contents (and extra elements of
// <config> before them).
func metaXML(extra, files string) []byte {
	return []byte(`<config><version>1</version><deduplicate_files>1</deduplicate_files><timestamp>2026-11-25 10:00:00</timestamp>` +
		`<uuid>62c08f3c-f80a-4c02-aabb-255897f0c3fc</uuid>` + extra + `<contents>` + files + `</contents></config>`)
}

const (
	sumA    = "1dfd05dbe0d1ac5d5a3da12b084c2f7f"
	sumB    = "41976a775685ccc5db50e8f4cfc663a0"
	baseXML = `<base_backup>S3('http://h/olympos/r/')</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`
)

func fileXML(name string, size int, rest string) string {
	return fmt.Sprintf("<file><name>%s</name><size>%d</size>%s</file>", name, size, rest)
}

func TestParseBackupMetaAccepts(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want BackupMeta
	}{
		{"empty file has no checksum", metaXML("", fileXML("a", 0, "")),
			BackupMeta{Version: 1, Files: []MetaFile{{Name: "a"}}}},
		{"base with credentials", metaXML(`<base_backup>S3('http://h/olympos/r/', 'OLYKEY', 'it''s \x41 secret')</base_backup>`+
			`<base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, fileXML("a", 3, "<checksum>"+sumA+"</checksum><use_base>true</use_base>")),
			BackupMeta{Version: 1, BaseBackup: "http://h/olympos/r/", Files: []MetaFile{{Name: "a", Size: 3, Checksum: sumA, UseBase: true, BaseSize: 3}}}},
		{"base, credentials from the backup", metaXML(baseXML+`<base_backup_copy_s3_credentials_from_backup>true</base_backup_copy_s3_credentials_from_backup>`, ""),
			BackupMeta{Version: 1, BaseBackup: "http://h/olympos/r/"}},
		{"partial base", metaXML(baseXML, fileXML("a", 9, "<checksum>"+sumA+"</checksum><use_base>true</use_base><base_size>4</base_size><base_checksum>"+sumB+"</base_checksum>")),
			BackupMeta{Version: 1, BaseBackup: "http://h/olympos/r/", Files: []MetaFile{{Name: "a", Size: 9, Checksum: sumA, UseBase: true, BaseSize: 4}}}},
		{"deduplicated", metaXML("", fileXML("b", 2, "<checksum>"+sumA+"</checksum><data_file>a</data_file>")+fileXML("a", 2, "<checksum>"+sumA+"</checksum>")),
			BackupMeta{Version: 1, Files: []MetaFile{{Name: "b", Size: 2, Checksum: sumA, DataFile: "a"}, {Name: "a", Size: 2, Checksum: sumA}}}},
		{"xml declaration and whitespace", []byte("<?xml version=\"1.0\"?>\n<config>\n  <version>1</version>\n  <contents>\n    <file><name>x&amp;y</name><size>1</size><checksum>" + sumA + "</checksum></file>\n  </contents>\n</config>\n"),
			BackupMeta{Version: 1, Files: []MetaFile{{Name: "x&y", Size: 1, Checksum: sumA}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := ParseBackupMeta(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*m, c.want) {
				t.Errorf("got %+v\nwant %+v", *m, c.want)
			}
		})
	}
	written := map[string]bool{}
	m, _ := ParseBackupMeta(cases[4].in)
	for _, f := range m.Files {
		written[f.Name] = f.Written()
	}
	if !reflect.DeepEqual(written, map[string]bool{"a": true, "b": false}) {
		t.Errorf("written %v", written)
	}
	if (MetaFile{Name: "z"}).Written() {
		t.Error("an empty file is written")
	}
}

func TestParseBackupMetaRefuses(t *testing.T) {
	ok := fileXML("a", 2, "<checksum>"+sumA+"</checksum>")
	cases := map[string][]byte{
		"empty":                  nil,
		"not xml":                []byte("version=1"),
		"other root":             []byte(`<backup><version>1</version><contents></contents></backup>`),
		"trailing element":       append(metaXML("", ok), []byte("<config/>")...),
		"trailing text":          append(metaXML("", ok), []byte("x")...),
		"no version":             []byte(`<config><contents>` + ok + `</contents></config>`),
		"no contents":            []byte(`<config><version>1</version></config>`),
		"version 2":              []byte(`<config><version>2</version><contents></contents></config>`),
		"version text":           []byte(`<config><version>one</version><contents></contents></config>`),
		"unknown config element": metaXML("<encryption>x</encryption>", ok),
		"duplicate version":      metaXML("<version>1</version>", ok),
		"duplicate contents":     []byte(`<config><version>1</version><contents></contents><contents></contents></config>`),
		"attribute":              []byte(`<config><version x="1">1</version><contents></contents></config>`),
		"comment":                []byte(`<config><!-- x --><version>1</version><contents></contents></config>`),
		"directive":              []byte(`<!DOCTYPE config><config><version>1</version><contents></contents></config>`),
		"text in contents":       metaXML("", "x"+ok),
		"element in a value":     metaXML("", "<file><name><b>a</b></name><size>1</size></file>"),
		"unknown in contents":    metaXML("", "<dir><name>a</name></dir>"),
		"unknown file element":   metaXML("", fileXML("a", 2, "<checksum>"+sumA+"</checksum><encrypted_by_disk>true</encrypted_by_disk>")),
		"duplicate file element": metaXML("", fileXML("a", 2, "<checksum>"+sumA+"</checksum><checksum>"+sumA+"</checksum>")),
		"no name":                metaXML("", "<file><size>1</size><checksum>"+sumA+"</checksum></file>"),
		"no size":                metaXML("", "<file><name>a</name><checksum>"+sumA+"</checksum></file>"),
		"duplicate name":         metaXML("", ok+ok),
		"empty name":             metaXML("", fileXML("", 2, "<checksum>"+sumA+"</checksum>")),
		"absolute name":          metaXML("", fileXML("/a", 2, "<checksum>"+sumA+"</checksum>")),
		"dot-dot name":           metaXML("", fileXML("a/../b", 2, "<checksum>"+sumA+"</checksum>")),
		"empty segment":          metaXML("", fileXML("a//b", 2, "<checksum>"+sumA+"</checksum>")),
		"control in name":        metaXML("", fileXML("a&#x1;", 2, "<checksum>"+sumA+"</checksum>")),
		"size sign":              metaXML("", "<file><name>a</name><size>+2</size><checksum>"+sumA+"</checksum></file>"),
		"size leading zero":      metaXML("", "<file><name>a</name><size>02</size><checksum>"+sumA+"</checksum></file>"),
		"size overflow":          metaXML("", "<file><name>a</name><size>18446744073709551616</size><checksum>"+sumA+"</checksum></file>"),
		"size space":             metaXML("", "<file><name>a</name><size> 2</size><checksum>"+sumA+"</checksum></file>"),
		"no checksum":            metaXML("", fileXML("a", 2, "")),
		"checksum on empty":      metaXML("", fileXML("a", 0, "<checksum>"+sumA+"</checksum>")),
		"checksum upper":         metaXML("", fileXML("a", 2, "<checksum>"+strings.ToUpper(sumA)+"</checksum>")),
		"checksum short":         metaXML("", fileXML("a", 2, "<checksum>"+sumA[:30]+"</checksum>")),
		"use_base without base":  metaXML("", fileXML("a", 2, "<checksum>"+sumA+"</checksum><use_base>true</use_base>")),
		"use_base yes":           metaXML(baseXML, fileXML("a", 2, "<checksum>"+sumA+"</checksum><use_base>yes</use_base>")),
		"use_base false":         metaXML(baseXML, fileXML("a", 2, "<checksum>"+sumA+"</checksum><use_base>false</use_base>")),
		"base_size alone":        metaXML(baseXML, fileXML("a", 9, "<checksum>"+sumA+"</checksum><base_size>4</base_size><base_checksum>"+sumB+"</base_checksum>")),
		"base_size = size":       metaXML(baseXML, fileXML("a", 9, "<checksum>"+sumA+"</checksum><use_base>true</use_base><base_size>9</base_size><base_checksum>"+sumB+"</base_checksum>")),
		"base_size 0":            metaXML(baseXML, fileXML("a", 9, "<checksum>"+sumA+"</checksum><use_base>true</use_base><base_size>0</base_size><base_checksum>"+sumB+"</base_checksum>")),
		"base_size no checksum":  metaXML(baseXML, fileXML("a", 9, "<checksum>"+sumA+"</checksum><use_base>true</use_base><base_size>4</base_size>")),
		"base_checksum alone":    metaXML(baseXML, fileXML("a", 9, "<checksum>"+sumA+"</checksum><use_base>true</use_base><base_checksum>"+sumB+"</base_checksum>")),
		"use_base on empty":      metaXML(baseXML, fileXML("a", 0, "<use_base>true</use_base>")),
		"data_file missing":      metaXML("", fileXML("b", 2, "<checksum>"+sumA+"</checksum><data_file>a</data_file>")),
		"data_file self":         metaXML("", fileXML("a", 2, "<checksum>"+sumA+"</checksum><data_file>a</data_file>")),
		"data_file other sum":    metaXML("", fileXML("b", 2, "<checksum>"+sumA+"</checksum><data_file>a</data_file>")+fileXML("a", 2, "<checksum>"+sumB+"</checksum>")),
		"data_file other size":   metaXML("", fileXML("b", 2, "<checksum>"+sumA+"</checksum><data_file>a</data_file>")+fileXML("a", 3, "<checksum>"+sumA+"</checksum>")),
		"data_file chained": metaXML("", fileXML("c", 2, "<checksum>"+sumA+"</checksum><data_file>b</data_file>")+
			fileXML("b", 2, "<checksum>"+sumA+"</checksum><data_file>a</data_file>")+fileXML("a", 2, "<checksum>"+sumA+"</checksum>")),
		"data_file to base": metaXML(baseXML, fileXML("b", 2, "<checksum>"+sumA+"</checksum><data_file>a</data_file>")+
			fileXML("a", 2, "<checksum>"+sumA+"</checksum><use_base>true</use_base>")),
		"data_file and use_base": metaXML(baseXML, fileXML("b", 2, "<checksum>"+sumA+"</checksum><use_base>true</use_base><data_file>a</data_file>")+
			fileXML("a", 2, "<checksum>"+sumA+"</checksum>")),
		"base without uuid":       metaXML(`<base_backup>S3('http://h/olympos/r/')</base_backup>`, ok),
		"uuid without base":       metaXML(`<base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"bad uuid":                []byte(`<config><version>1</version><uuid>x</uuid><contents></contents></config>`),
		"bad base uuid":           metaXML(`<base_backup>S3('http://h/olympos/r/')</base_backup><base_backup_uuid>x</base_backup_uuid>`, ok),
		"copy credentials alone":  metaXML(`<base_backup_copy_s3_credentials_from_backup>true</base_backup_copy_s3_credentials_from_backup>`, ok),
		"copy credentials 1":      metaXML(baseXML+`<base_backup_copy_s3_credentials_from_backup>1</base_backup_copy_s3_credentials_from_backup>`, ok),
		"base File":               metaXML(`<base_backup>File('/b/')</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"base two args":           metaXML(`<base_backup>S3('http://h/', 'k')</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"base four args":          metaXML(`<base_backup>S3('http://h/', 'k', 's', 'x')</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"base not a string":       metaXML(`<base_backup>S3(url)</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"base trailing":           metaXML(`<base_backup>S3('http://h/') x</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"base empty url":          metaXML(`<base_backup>S3('')</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"base unterminated":       metaXML(`<base_backup>S3('http://h/</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"base empty":              metaXML(`<base_backup></base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok),
		"unterminated":            []byte(`<config><version>1</version><contents>`),
		"deduplicate_files other": []byte(`<config><version>1</version><deduplicate_files>2</deduplicate_files><contents></contents></config>`),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := ParseBackupMeta(in)
			if !errors.Is(err, ErrNativeMeta) {
				t.Fatalf("got %+v, %v; want ErrNativeMeta", m, err)
			}
			t.Log(err)
		})
	}
	t.Run("too large", func(t *testing.T) {
		big := metaXML("", strings.Repeat(" ", MaxBackupMetaBytes))
		if _, err := ParseBackupMeta(big); !errors.Is(err, ErrNativeMeta) || !strings.Contains(err.Error(), "larger") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("the secret is not in an XML error", func(t *testing.T) {
		in := metaXML(`<base_backup>S3('http://h/', 'OLYKEY', '&topsecret;')</base_backup>`, "")
		_, err := ParseBackupMeta(in)
		if !errors.Is(err, ErrNativeMeta) || strings.Contains(err.Error(), "topsecret") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("the secret is not in an error", func(t *testing.T) {
		in := metaXML(`<base_backup>S3('http://h/', 'OLYKEY', 'topsecret', 'x')</base_backup><base_backup_uuid>5d1492d5-3a5e-46db-a6ae-3e8afa751a45</base_backup_uuid>`, ok)
		_, err := ParseBackupMeta(in)
		if err == nil || strings.Contains(err.Error(), "topsecret") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestParseCount(t *testing.T) {
	for in, want := range map[string]uint64{"400000": 400000, "0": 0, "1": 1, "18446744073709551615": 1<<64 - 1} {
		got, err := ParseCount([]byte(in))
		if err != nil || got != want {
			t.Errorf("%q: %d, %v", in, got, err)
		}
	}
	for _, ver := range nativeVersions {
		got, err := ParseCount(readNative(t, ver, "full", "data/spike/events/202611_1_1_0/count.txt"))
		if err != nil || got != 400000 {
			t.Errorf("%s full: %d, %v", ver, got, err)
		}
		got, err = ParseCount(readNative(t, ver, "incremental", "data/spike/events/202611_2_2_0/count.txt"))
		if err != nil || got != 1000 {
			t.Errorf("%s incremental: %d, %v", ver, got, err)
		}
	}
	for _, in := range []string{"", "-1", "+1", "01", "00", "1\n", " 1", "1 ", "1a", "0x10", "1e3", "18446744073709551616",
		strings.Repeat("1", 65), "１"} {
		if n, err := ParseCount([]byte(in)); !errors.Is(err, ErrNativeMeta) {
			t.Errorf("%q: %d, %v; want ErrNativeMeta", in, n, err)
		}
	}
}

// metadataFiles reads testdata/native/<ver>/<run>/metadata as the ingest
// endpoint keeps it: "<run-id>/metadata/..." → body.
func metadataFiles(t *testing.T, ver, run, runID string) map[string][]byte {
	t.Helper()
	root := filepath.Join("testdata", "native", ver, run)
	out := map[string][]byte{}
	err := filepath.WalkDir(filepath.Join(root, "metadata"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		b, err := os.ReadFile(p)
		out[runID+"/"+filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestObjectsFromMetadata(t *testing.T) {
	for _, ver := range nativeVersions {
		t.Run(ver, func(t *testing.T) {
			k := func(run, name string) string { return run + "/metadata/spike/" + name + ".sql" }
			got, err := ObjectsFromMetadata(metadataFiles(t, ver, "full", captureFullRun))
			if err != nil {
				t.Fatal(err)
			}
			f := captureFullRun
			want := []NativeDatabase{{Name: "spike", Objects: []NativeObject{
				{Name: "applog", Kind: KindTable, Engine: "Log", DDLKey: k(f, "applog")},
				// An MV without TO: its inner table has no metadata of its own.
				{Name: "big_amounts", Kind: KindMaterializedView, Engine: "MaterializedView", DDLKey: k(f, "big_amounts")},
				{Name: "countries", Kind: KindTable, Engine: "MergeTree", DDLKey: k(f, "countries")},
				{Name: "countries_dict", Kind: KindDictionary, Engine: "Dictionary", DDLKey: k(f, "countries_dict")},
				{Name: "daily", Kind: KindTable, Engine: "AggregatingMergeTree", DDLKey: k(f, "daily")},
				{Name: "daily_mv", Kind: KindMaterializedView, Engine: "MaterializedView", DDLKey: k(f, "daily_mv")},
				{Name: "events", Kind: KindTable, Engine: "MergeTree", DDLKey: k(f, "events")},
				{Name: "recent", Kind: KindView, Engine: "View", DDLKey: k(f, "recent")},
			}}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("full:\n got %+v\nwant %+v", got, want)
			}
			// An incremental holds only the metadata it wrote.
			i := captureIncrRun
			got, err = ObjectsFromMetadata(metadataFiles(t, ver, "incremental", i))
			if err != nil {
				t.Fatal(err)
			}
			want = []NativeDatabase{{Name: "spike", Objects: []NativeObject{
				{Name: "added", Kind: KindTable, Engine: "Log", DDLKey: k(i, "added")},
				{Name: "events", Kind: KindTable, Engine: "MergeTree", DDLKey: k(i, "events")},
			}}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("incremental:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestObjectsFromMetadataForms(t *testing.T) {
	const r = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60"
	cases := []struct {
		name  string
		files map[string]string
		want  []NativeDatabase
	}{
		{"database only", map[string]string{r + "/metadata/empty.sql": "CREATE DATABASE empty ENGINE = Atomic"},
			[]NativeDatabase{{Name: "empty"}}},
		{"ordinary database, no UUIDs", map[string]string{
			r + "/metadata/ord.sql":    "CREATE DATABASE ord ENGINE = Ordinary",
			r + "/metadata/ord/mv.sql": "CREATE MATERIALIZED VIEW ord.mv (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS index_granularity = 8192 AS SELECT id FROM ord.src",
			r + "/metadata/ord/t.sql":  "CREATE TABLE ord.t (`id` UInt64) ENGINE = MergeTree ORDER BY id",
		}, []NativeDatabase{{Name: "ord", Objects: []NativeObject{
			{Name: "mv", Kind: KindMaterializedView, Engine: "MaterializedView", DDLKey: r + "/metadata/ord/mv.sql"},
			{Name: "t", Kind: KindTable, Engine: "MergeTree", DDLKey: r + "/metadata/ord/t.sql"},
		}}}},
		{"other engines are tables", map[string]string{
			r + "/metadata/db/u.sql": "CREATE TABLE db.u UUID '8c80fb00-b17b-4e99-ab96-dd031c263310' (`id` UInt64) ENGINE = URL('http://example.invalid/x', 'CSV')",
			r + "/metadata/db/d.sql": "CREATE TABLE db.d (`id` UInt64) ENGINE = Distributed('c', 'db', 'u', rand())",
			r + "/metadata/db/r.sql": "CREATE TABLE db.r (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/{database}/r', '{replica}') ORDER BY id",
		}, []NativeDatabase{{Name: "db", Objects: []NativeObject{
			{Name: "d", Kind: KindTable, Engine: "Distributed", DDLKey: r + "/metadata/db/d.sql"},
			{Name: "r", Kind: KindTable, Engine: "ReplicatedMergeTree", DDLKey: r + "/metadata/db/r.sql"},
			{Name: "u", Kind: KindTable, Engine: "URL", DDLKey: r + "/metadata/db/u.sql"},
		}}}},
		{"escaped and quoted names", map[string]string{
			r + "/metadata/my%2Ddb.sql":           "CREATE DATABASE `my-db` ENGINE = Atomic",
			r + "/metadata/my%2Ddb/a%20b%2Ec.sql": "CREATE TABLE `my-db`.`a b.c` (`x` UInt8) ENGINE = Memory",
			r + "/metadata/my%2Ddb/%C3%A7.sql":    "CREATE VIEW `my-db`.`ç` AS SELECT 1",
		}, []NativeDatabase{{Name: "my-db", Objects: []NativeObject{
			{Name: "a b.c", Kind: KindTable, Engine: "Memory", DDLKey: r + "/metadata/my%2Ddb/a%20b%2Ec.sql"},
			{Name: "ç", Kind: KindView, Engine: "View", DDLKey: r + "/metadata/my%2Ddb/%C3%A7.sql"},
		}}}},
		{"two runs, two databases", map[string]string{
			r + "/metadata/b/t.sql":                                    "CREATE TABLE b.t (x UInt8) ENGINE = Log",
			"6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61/metadata/a/v.sql":    "CREATE VIEW a.v (`x` UInt8) DEFINER = default SQL SECURITY DEFINER AS SELECT 1 AS x",
			"6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61/metadata/a/mv.sql":   "CREATE MATERIALIZED VIEW a.mv REFRESH EVERY 1 HOUR TO a.t (`x` UInt8) AS SELECT 1 AS x",
			"6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61/metadata/a/dict.sql": "CREATE DICTIONARY a.dict (`id` UInt64) PRIMARY KEY id SOURCE(NULL()) LIFETIME(0) LAYOUT(FLAT())",
		}, []NativeDatabase{
			{Name: "a", Objects: []NativeObject{
				{Name: "dict", Kind: KindDictionary, Engine: "Dictionary", DDLKey: "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61/metadata/a/dict.sql"},
				{Name: "mv", Kind: KindMaterializedView, Engine: "MaterializedView", DDLKey: "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61/metadata/a/mv.sql"},
				{Name: "v", Kind: KindView, Engine: "View", DDLKey: "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61/metadata/a/v.sql"},
			}},
			{Name: "b", Objects: []NativeObject{{Name: "t", Kind: KindTable, Engine: "Log", DDLKey: r + "/metadata/b/t.sql"}}},
		}},
		{"empty map", map[string]string{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string][]byte{}
			for k, v := range c.files {
				files[k] = []byte(v)
			}
			got, err := ObjectsFromMetadata(files)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestObjectsFromMetadataRefuses(t *testing.T) {
	const r = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60"
	tbl := "CREATE TABLE db.t (`x` UInt8) ENGINE = Log"
	cases := map[string]map[string]string{
		// Kinds the manifest has no place for are refused, not left out: a
		// RESTORE DATABASE would restore them without the allowlist seeing
		// them.
		"live view":             {r + "/metadata/db/lv.sql": "CREATE LIVE VIEW db.lv UUID '1c78f33f-4038-4c07-af2d-4348f363be72' (`1` UInt8) AS SELECT 1"},
		"window view":           {r + "/metadata/db/wv.sql": "CREATE WINDOW VIEW db.wv ENGINE = Memory AS SELECT 1"},
		"function":              {r + "/metadata/db/f.sql": "CREATE FUNCTION db.f AS x -> x"},
		"temporary":             {r + "/metadata/db/t.sql": "CREATE TEMPORARY TABLE db.t (`x` UInt8) ENGINE = Memory"},
		"table function":        {r + "/metadata/db/tf.sql": "CREATE TABLE db.tf UUID '79888162-18be-4c43-a452-adf265d3405d' (`id` UInt64) AS url('http://example.invalid/y', CSV, 'id UInt64')"},
		"table without columns": {r + "/metadata/db/t.sql": "CREATE TABLE db.t ENGINE = Log"},
		"table without engine":  {r + "/metadata/db/t.sql": "CREATE TABLE db.t (`x` UInt8)"},
		"quoted engine":         {r + "/metadata/db/t.sql": "CREATE TABLE db.t (`x` UInt8) ENGINE = `Log`"},
		"engine without =":      {r + "/metadata/db/t.sql": "CREATE TABLE db.t (`x` UInt8) ENGINE Log"},
		"attach":                {r + "/metadata/db/t.sql": "ATTACH TABLE db.t (`x` UInt8) ENGINE = Log"},
		"or replace":            {r + "/metadata/db/t.sql": "CREATE OR REPLACE TABLE db.t (`x` UInt8) ENGINE = Log"},
		"if not exists":         {r + "/metadata/db/t.sql": "CREATE TABLE IF NOT EXISTS db.t (`x` UInt8) ENGINE = Log"},
		"unqualified":           {r + "/metadata/db/t.sql": "CREATE TABLE t (`x` UInt8) ENGINE = Log"},
		"other database":        {r + "/metadata/db/t.sql": "CREATE TABLE other.t (`x` UInt8) ENGINE = Log"},
		"other name":            {r + "/metadata/db/t.sql": "CREATE TABLE db.u (`x` UInt8) ENGINE = Log"},
		"name case":             {r + "/metadata/db/t.sql": "CREATE TABLE db.T (`x` UInt8) ENGINE = Log"},
		"uuid not a string":     {r + "/metadata/db/t.sql": "CREATE TABLE db.t UUID x (`x` UInt8) ENGINE = Log"},
		"bad uuid":              {r + "/metadata/db/t.sql": "CREATE TABLE db.t UUID 'x' (`x` UInt8) ENGINE = Log"},
		"comment":               {r + "/metadata/db/t.sql": "CREATE TABLE db.t (`x` UInt8) ENGINE = Log -- x"},
		"query parameter":       {r + "/metadata/db/v.sql": "CREATE VIEW db.v AS SELECT {p:UInt8}"},
		"not utf-8":             {r + "/metadata/db/t.sql": "CREATE TABLE db.t (`\xff` UInt8) ENGINE = Log"},
		"empty statement":       {r + "/metadata/db/t.sql": ""},
		"two statements":        {r + "/metadata/db/t.sql": tbl + "; DROP TABLE db.t"},
		"database as table":     {r + "/metadata/db.sql": tbl},
		"database other name":   {r + "/metadata/db.sql": "CREATE DATABASE other ENGINE = Atomic"},
		"database no engine":    {r + "/metadata/db.sql": "CREATE DATABASE db"},
		"table as database":     {r + "/metadata/db/t.sql": "CREATE DATABASE db ENGINE = Atomic"},
		// ClickHouse 24.8 and 25.8 write no metadata for an MV's inner table
		// (it is in the MV's own statement, and its data under the MV's
		// name), Atomic and Ordinary alike.
		"inner_id table": {r + "/metadata/db/%2Einner_id%2E4b99399c%2D2e2e%2D41b9%2D9785%2D38b96b090af2.sql": "CREATE TABLE db.`.inner_id.4b99399c-2e2e-41b9-9785-38b96b090af2` (`x` UInt8) ENGINE = MergeTree ORDER BY x"},
		"inner table":    {r + "/metadata/db/%2Einner%2Emv.sql": "CREATE TABLE db.`.inner.mv` (`x` UInt8) ENGINE = MergeTree ORDER BY x"},
		// Keys.
		"no run":             {"metadata/db/t.sql": tbl},
		"two prefixes":       {"a/" + r + "/metadata/db/t.sql": tbl},
		"not metadata":       {r + "/data/db/t.sql": tbl},
		"not sql":            {r + "/metadata/db/t.txt": tbl},
		"too deep":           {r + "/metadata/db/x/t.sql": tbl},
		"empty table name":   {r + "/metadata/db/.sql": tbl},
		"empty db segment":   {r + "/metadata//t.sql": tbl},
		"lower-case escape":  {r + "/metadata/db/t%2ex.sql": "CREATE TABLE db.`t.x` (`x` UInt8) ENGINE = Log"},
		"needless escape":    {r + "/metadata/db/%74.sql": tbl},
		"unescaped dot":      {r + "/metadata/db/t.x.sql": "CREATE TABLE db.`t.x` (`x` UInt8) ENGINE = Log"},
		"broken escape":      {r + "/metadata/db/t%2.sql": tbl},
		"escape to bad utf8": {r + "/metadata/db/%FF.sql": "CREATE TABLE db.`\xff` (`x` UInt8) ENGINE = Log"},
		"same object twice": {
			r + "/metadata/db/t.sql":                                 tbl,
			"6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61/metadata/db/t.sql": tbl,
		},
		"same database twice": {
			r + "/metadata/db.sql":                                 "CREATE DATABASE db ENGINE = Atomic",
			"6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61/metadata/db.sql": "CREATE DATABASE db ENGINE = Atomic",
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			in := map[string][]byte{}
			for k, v := range files {
				in[k] = []byte(v)
			}
			got, err := ObjectsFromMetadata(in)
			if !errors.Is(err, ErrNativeMeta) {
				t.Fatalf("got %+v, %v; want ErrNativeMeta", got, err)
			}
			t.Log(err)
		})
	}
	t.Run("too large", func(t *testing.T) {
		in := map[string][]byte{r + "/metadata/db/t.sql": []byte(tbl + " COMMENT '" + strings.Repeat("x", maxSchemaEntry) + "'")}
		if _, err := ObjectsFromMetadata(in); !errors.Is(err, ErrNativeMeta) {
			t.Fatalf("err %v", err)
		}
	})
}
