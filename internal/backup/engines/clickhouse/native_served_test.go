package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/ingest"
)

// servedFile is a file of a synthetic .backup: its name, size and checksum
// number, what else its <file> holds, and whether the run stored it.
type servedFile struct {
	name    string
	size    int
	sum     int
	rest    string
	written bool
}

func sumN(n int) string { return fmt.Sprintf("%032x", n) }

// servedRun is a run's .backup and manifest of files.
func servedRun(runID, extra string, files []servedFile) (backup.NativeChainManifest, []byte) {
	var b strings.Builder
	m := backup.NativeChainManifest{RunID: runID}
	for _, f := range files {
		b.WriteString(fileXML(f.name, f.size, "<checksum>"+sumN(f.sum)+"</checksum>"+f.rest))
		if f.written {
			m.Objects = append(m.Objects, ingest.ObjectRecord{Key: runID + "/" + f.name, Size: int64(f.size), SHA256: sum(f.name)})
		}
	}
	raw := metaXML(extra, b.String())
	m.Objects = append(m.Objects, ingest.ObjectRecord{Key: runID + "/.backup", Size: int64(len(raw)), SHA256: sum("backup")})
	return m, raw
}

// TestNativeServed (security review v0.4, finding 5): a restore serves the
// .backup files, the definitions of the selected databases and the data of
// the objects it creates, resolved as ClickHouse reads them (by size and
// checksum, through data_file and the base); nothing of a database left
// unselected or an object left out.
func TestNativeServed(t *testing.T) {
	base := "<use_base>true</use_base>"
	full, fullRaw := servedRun(testBaseRunID, "", []servedFile{
		{"metadata/a.sql", 10, 1, "", true},
		{"metadata/a/t.sql", 10, 2, "", true},
		{"metadata/a/t2.sql", 10, 3, "", true},
		{"metadata/a/x.sql", 10, 4, "", true},
		{"metadata/b.sql", 10, 5, "", true},
		{"metadata/b/u.sql", 10, 6, "", true},
		{"data/a/t/p1/data.bin", 7, 7, "", true},
		{"data/a/t/p1/count.txt", 1, 8, "", true},
		{"data/a/t/log.bin", 2, 9, "", true},
		{"data/a/x/data.bin", 5, 10, "", true},
		{"data/b/u/data.bin", 6, 11, "", true},
		{"data/b/u/secret.bin", 6, 12, "", true},
		// a.t2's file holds b.u's bytes: ClickHouse reads them from b.u's.
		{"data/a/t2/data.bin", 6, 11, "<data_file>data/b/u/data.bin</data_file>", false},
	})
	onFull := `<base_backup>S3('http://h/olympos/` + testBaseRunID + `/')</base_backup><base_backup_uuid>62c08f3c-f80a-4c02-aabb-255897f0c3fc</base_backup_uuid>`
	inc, incRaw := servedRun(testRunID, onFull, []servedFile{
		{"metadata/a.sql", 10, 1, base, false},
		{"metadata/a/t.sql", 10, 2, base, false},
		{"metadata/a/t2.sql", 10, 3, base, false},
		{"metadata/a/x.sql", 10, 4, base, false},
		{"metadata/b.sql", 10, 5, base, false},
		{"metadata/b/u.sql", 10, 6, base, false},
		{"data/a/t/p1/data.bin", 7, 7, base, false},
		{"data/a/t/p1/count.txt", 1, 8, base, false},
		{"data/a/t/p2/data.bin", 4, 13, "", true},
		// Appended: the first 2 bytes are the full's data/a/t/log.bin.
		{"data/a/t/log.bin", 5, 14, base + "<base_size>2</base_size><base_checksum>" + sumN(9) + "</base_checksum>", true},
		{"data/a/x/data.bin", 5, 10, base, false},
		{"data/b/u/data.bin", 6, 11, base, false},
		{"data/b/u/secret.bin", 6, 12, base, false},
		{"data/a/t2/data.bin", 6, 11, base, false},
	})
	bodies := map[string][]byte{testBaseRunID + "/.backup": fullRaw, testRunID + "/.backup": incRaw}
	var reads []string
	read := func(_ context.Context, key string, limit int64) ([]byte, error) {
		reads = append(reads, key)
		b, ok := bodies[key]
		if !ok {
			return nil, errors.New("not stored")
		}
		return b, nil
	}
	decisions := []backup.NativeDecision{
		{Database: "a", Name: "t", Kind: KindTable, Allowed: true},
		{Database: "a", Name: "t2", Kind: KindTable, Allowed: true},
		{Database: "a", Name: "x", Kind: KindTable, Reason: "the URL engine is not on the restore allowlist"},
	}
	ms := []backup.NativeChainManifest{full, inc}
	got, err := Engine{}.NativeServed(context.Background(), read, ms, []string{"a"}, decisions)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		testBaseRunID + "/.backup", testRunID + "/.backup",
		testBaseRunID + "/metadata/a.sql", testBaseRunID + "/metadata/a/t.sql", testBaseRunID + "/metadata/a/t2.sql", testBaseRunID + "/metadata/a/x.sql",
		testBaseRunID + "/data/a/t/p1/data.bin", testBaseRunID + "/data/a/t/p1/count.txt", testBaseRunID + "/data/a/t/log.bin",
		testBaseRunID + "/data/b/u/data.bin",
		testRunID + "/data/a/t/p2/data.bin", testRunID + "/data/a/t/log.bin",
	}
	slices.Sort(want)
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, want) {
		t.Fatalf("served\n got %q\nwant %q", keys, want)
	}
	if !slices.Equal(reads, []string{testRunID + "/.backup", testBaseRunID + "/.backup"}) {
		t.Fatalf("read %v", reads)
	}

	// Every database: b's definitions and data too, not a.x's data.
	decisions = append(decisions, backup.NativeDecision{Database: "b", Name: "u", Kind: KindTable, Allowed: true})
	got, err = Engine{}.NativeServed(context.Background(), read, ms, nil, decisions)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"metadata/b.sql", "metadata/b/u.sql", "data/b/u/secret.bin"} {
		if !got[testBaseRunID+"/"+k] {
			t.Errorf("every database: %s not served", k)
		}
	}
	if got[testBaseRunID+"/data/a/x/data.bin"] {
		t.Error("every database: the data of an object left out is served")
	}

	// What cannot be resolved refuses the restore.
	if _, err := (Engine{}).NativeServed(context.Background(), read, ms, []string{"a"}, decisions); !errors.Is(err, backup.ErrNativeChain) {
		t.Fatalf("a decision of a database not selected: %v", err)
	}
	decisions = decisions[:3]
	noBase := []backup.NativeChainManifest{{RunID: full.RunID}, inc}
	bodies[testBaseRunID+"/.backup"] = metaXML("", "")
	if _, err := (Engine{}).NativeServed(context.Background(), read, noBase, []string{"a"}, decisions); !errors.Is(err, backup.ErrNativeChain) ||
		!strings.Contains(err.Error(), "has no file of") {
		t.Fatalf("a base without the file: %v", err)
	}
	bodies[testBaseRunID+"/.backup"] = fullRaw
	if _, err := (Engine{}).NativeServed(context.Background(), read, []backup.NativeChainManifest{{RunID: full.RunID}, inc}, []string{"a"}, decisions); !errors.Is(err, backup.ErrNativeChain) ||
		!strings.Contains(err.Error(), "does not list") {
		t.Fatalf("a file the manifest does not list: %v", err)
	}
	delete(bodies, testRunID+"/.backup")
	if _, err := (Engine{}).NativeServed(context.Background(), read, ms, []string{"a"}, decisions); !errors.Is(err, backup.ErrNativeNotVerified) {
		t.Fatalf("a .backup that cannot be read: %v", err)
	}
}
