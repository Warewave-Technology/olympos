package postgres

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/restore"
)

func TestReadArchiveHeader(t *testing.T) {
	b, err := os.ReadFile("testdata/probe-pg17.dump")
	if err != nil {
		t.Fatal(err)
	}
	h, err := readArchiveHeader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	want := archiveHeader{DBName: "toc_probe", ServerVersion: "16.15", DumpVersion: "17.4", DumpMajor: 17}
	if h != want {
		t.Fatalf("header %+v", h)
	}
	for name, in := range map[string][]byte{
		"not an archive": []byte("PK\x03\x04 a zip, not a dump"),
		"truncated":      b[:40],
		"plain format":   []byte("--\n-- PostgreSQL database dump\n--\n"),
	} {
		if _, err := readArchiveHeader(bytes.NewReader(in)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// chunky writes in small pieces, splitting lines.
func chunky(t *testing.T, s *tocScan, data []byte) {
	t.Helper()
	for len(data) > 0 {
		n := 7
		if n > len(data) {
			n = len(data)
		}
		if _, err := s.Write(data[:n]); err != nil {
			t.Fatal(err)
		}
		data = data[n:]
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTOCScan(t *testing.T) {
	// pg_restore --create -l of the probe database: TABLE entries are
	// public."Odd Name", s.p (partitioned), s.p1 and s.t; not views,
	// materialized views, sequences, TABLE DATA or TABLE ATTACH.
	s := &tocScan{DB: "toc_probe"}
	chunky(t, s, readTestdata(t, "probe-pg17.toc"))
	if s.Tables != 4 || !reflect.DeepEqual(s.DBEntries, []string{"3481", "3482", "3483", "3484"}) {
		t.Fatalf("tables %d, entries %v", s.Tables, s.DBEntries)
	}
	// The comment on a table is not the database's.
	s = &tocScan{DB: "inject_probe"}
	chunky(t, s, readTestdata(t, "inject-pg17.toc"))
	if s.Tables != 1 || !reflect.DeepEqual(s.DBEntries, []string{"3450", "3451", "3452"}) {
		t.Fatalf("tables %d, entries %v", s.Tables, s.DBEntries)
	}
	// A name pg_dump quotes in the COMMENT and ACL tags (a real dump of
	// "My-DB").
	s = &tocScan{DB: "My-DB"}
	chunky(t, s, readTestdata(t, "quoted-pg17.toc"))
	if s.Tables != 1 || !reflect.DeepEqual(s.DBEntries, []string{"3449", "3450", "3451", "3452"}) {
		t.Fatalf("quoted: tables %d, entries %v", s.Tables, s.DBEntries)
	}
	// A schema named "- DATABASE shop" makes lines that start like the
	// database's: they are not taken, however many there are.
	var spoof strings.Builder
	spoof.WriteString("9; 1262 5 DATABASE - shop o\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&spoof, "%d; 0 0 COMMENT - DATABASE shop TABLE t%d o\n", 100+i, i)
		fmt.Fprintf(&spoof, "%d; 0 0 ACL - DATABASE shop SCHEMA x o\n", 200+i)
	}
	spoof.WriteString("10; 0 0 COMMENT - DATABASE shop o\n")
	s = &tocScan{DB: "shop"}
	chunky(t, s, []byte(spoof.String()))
	if !reflect.DeepEqual(s.DBEntries, []string{"9", "10"}) {
		t.Fatalf("spoofed: entries %v", s.DBEntries)
	}
	// Entries about another database, or not about a database, are not taken.
	s = &tocScan{DB: "shop"}
	chunky(t, s, []byte("7; 0 0 COMMENT - DATABASE shopping x\n8; 0 0 COMMENT - SCHEMA shop x\n9; 1262 5 DATABASE - shop o\n"))
	if !reflect.DeepEqual(s.DBEntries, []string{"9"}) || string(listFile(s.DBEntries)) != "9;\n" {
		t.Fatalf("entries %v", s.DBEntries)
	}
}

func TestDatabaseDefinitionFromEntries(t *testing.T) {
	d, err := databaseDefinition(string(readTestdata(t, "probe-pg17-dbentries.sql")), "toc_probe")
	if err != nil {
		t.Fatal(err)
	}
	want := dbDefinition{
		Options:  [][2]string{{"ENCODING", "'UTF8'"}, {"LOCALE_PROVIDER", "libc"}, {"LOCALE", "'C'"}},
		Owner:    "olympos",
		Settings: []string{"ALTER DATABASE toc_probe SET work_mem TO '8MB';"},
		Comment:  []string{"COMMENT ON DATABASE toc_probe IS 'probe db';"},
		ACL:      []string{"REVOKE CONNECT,TEMPORARY ON DATABASE toc_probe FROM PUBLIC;", "GRANT CONNECT ON DATABASE toc_probe TO PUBLIC;"},
	}
	if !reflect.DeepEqual(d, want) {
		t.Fatalf("definition:\n%#v\nwant:\n%#v", d, want)
	}
	if got := d.createSQL("toc_probe", true); got != `CREATE DATABASE "toc_probe" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'C' OWNER = "olympos"` {
		t.Fatalf("create: %s", got)
	}
	if got := d.createSQL("toc_probe", false); strings.Contains(got, "OWNER") {
		t.Fatalf("create without owner: %s", got)
	}
}

// The database's comment carries fake TOC headers and statements; a
// function body and a table comment of the same archive do too (they are
// never printed: only the database's entries are).
func TestDatabaseDefinitionInjection(t *testing.T) {
	d, err := databaseDefinition(string(readTestdata(t, "inject-pg17-dbentries.sql")), "inject_probe")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Comment) != 1 || !strings.HasPrefix(d.Comment[0], "COMMENT ON DATABASE inject_probe IS 'line one\n") ||
		len(d.ACL) != 0 || len(d.RoleSettings) != 0 || len(d.Unused) != 0 ||
		!reflect.DeepEqual(d.Settings, []string{"ALTER DATABASE inject_probe SET work_mem TO '8MB';"}) {
		t.Fatalf("definition %#v", d)
	}
	// Statements of other forms, or about another database, are never run.
	script := `CREATE DATABASE shop WITH TEMPLATE = template0 ENCODING = 'UTF8';
ALTER ROLE postgres PASSWORD 'pwned';
ALTER DATABASE other SET work_mem TO '1MB';
ALTER DATABASE shop SET TABLESPACE fast;
ALTER DATABASE shop RENAME TO x;
ALTER DATABASE shop OWNER TO a, b;
GRANT ALL ON DATABASE shop, other TO PUBLIC;
GRANT ALL ON SCHEMA public TO PUBLIC;
COMMENT ON DATABASE shop IS 'a' || 'b';
SECURITY LABEL FOR p ON DATABASE shop IS 'x';
ALTER ROLE app IN DATABASE shop SET work_mem TO '2MB';
ALTER ROLE app IN DATABASE other SET work_mem TO '2MB';
SET ROLE postgres;
SELECT pg_catalog.set_config('search_path', '', false);
`
	d, err = databaseDefinition(script, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Settings) != 0 || len(d.Comment) != 0 || d.Owner != "" ||
		!reflect.DeepEqual(d.ACL, []string{"SECURITY LABEL FOR p ON DATABASE shop IS 'x';"}) ||
		!reflect.DeepEqual(d.RoleSettings, []string{"ALTER ROLE app IN DATABASE shop SET work_mem TO '2MB';"}) {
		t.Fatalf("definition %#v", d)
	}
	if want := []string{"ALTER ROLE postgres", "ALTER DATABASE other", "ALTER DATABASE shop", "ALTER DATABASE shop", "ALTER DATABASE shop",
		"GRANT ALL ON", "GRANT ALL ON", "COMMENT ON DATABASE", "ALTER ROLE app"}; !reflect.DeepEqual(d.Unused, want) {
		t.Fatalf("unused %q", d.Unused)
	}
	// SET … other than standard_conforming_strings off is a session line;
	// off is refused; CREATE DATABASE must name the database restored.
	if _, err := databaseDefinition("SET standard_conforming_strings = off;\n", "shop"); err == nil {
		t.Fatal("standard_conforming_strings off accepted")
	}
	if _, err := databaseDefinition("CREATE DATABASE other WITH ENCODING = 'UTF8';", "shop"); err == nil {
		t.Fatal("another database's CREATE accepted")
	}
	if _, err := databaseDefinition("CREATE DATABASE;", "shop"); err == nil {
		t.Fatal("CREATE DATABASE without a name accepted")
	}
	// The restore's own login is never a role setting's role.
	if d, err := databaseDefinition("ALTER ROLE CURRENT_USER IN DATABASE shop SET work_mem TO '1MB';", "shop"); err != nil ||
		len(d.RoleSettings) != 0 || len(d.Unused) != 1 {
		t.Fatalf("CURRENT_USER role setting: %#v %v", d, err)
	}
}

func TestDatabaseDefinitionOptions(t *testing.T) {
	script := `CREATE DATABASE "My ""DB""" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = icu LOCALE = 'en_US.UTF-8' ICU_LOCALE = 'en-US' TABLESPACE = fast CONNECTION LIMIT = -1;
ALTER DATABASE "My ""DB""" OWNER TO "App Owner";
SET default_tablespace = '';`
	d, err := databaseDefinition(script, `My "DB"`)
	if err != nil {
		t.Fatal(err)
	}
	if d.Owner != "App Owner" || !reflect.DeepEqual(d.Ignored, []string{"TABLESPACE", "CONNECTION LIMIT"}) {
		t.Fatalf("definition %#v", d)
	}
	got := d.createSQL(`My "DB"`, true)
	want := `CREATE DATABASE "My ""DB""" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = icu LOCALE = 'en_US.UTF-8' ICU_LOCALE = 'en-US' OWNER = "App Owner"`
	if got != want {
		t.Fatalf("create:\n%s\nwant:\n%s", got, want)
	}
	// Anything but a literal, a word or an identifier is refused.
	if _, err := databaseDefinition("CREATE DATABASE x WITH ENCODING = (SELECT 1);", "x"); err == nil {
		t.Fatal("expression accepted")
	}
}

func TestPgRestoreMessageDropsSQLAndRows(t *testing.T) {
	in := `pg_restore: error: could not execute query: ERROR:  duplicate key value violates unique constraint "t_pkey"
DETAIL:  Key (id)=(42) already exists.
CONTEXT:  COPY t, line 1: "42	secret-row-value"
Command was: COPY public.t (id, v) FROM stdin;
pg_restore: error: COPY failed for table "t": ERROR:  x
Command was: CREATE FUNCTION f() RETURNS int
    LANGUAGE sql
    AS $$select 'secret'$$;`
	got := pgRestoreMessage(in)
	want := "pg_restore: error: could not execute query: ERROR:  duplicate key value violates unique constraint \"t_pkey\"\n" +
		"pg_restore: error: COPY failed for table \"t\": ERROR:  x"
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestDescribeStmtHasNoSecrets(t *testing.T) {
	for in, want := range map[string]string{
		`ALTER ROLE "Mixed Case" WITH LOGIN PASSWORD 'SCRAM-SHA-256$4096:abc'`: `ALTER ROLE "Mixed Case"`,
		`alter database shop SET work_mem TO '8MB';`:                           `ALTER database shop`,
		`GRANT readers TO reporting`:                                           `GRANT readers TO`,
		`COMMENT ON ROLE r IS 'x'`:                                             `COMMENT ON ROLE`,
	} {
		if got := describeStmt(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

// fakeTools is a <major>/bin layout of stub tools that print their version.
func fakeTools(t *testing.T, majors ...int) string {
	t.Helper()
	dir := t.TempDir()
	for _, m := range majors {
		bin := filepath.Join(dir, fmt.Sprint(m), "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, tool := range []string{"pg_dump", "pg_dumpall", "pg_restore"} {
			script := fmt.Sprintf("#!/bin/sh\necho '%s (PostgreSQL) %d.9'\n", tool, m)
			if err := os.WriteFile(filepath.Join(bin, tool), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

func TestRestoreToolFollowsTheTargetMajor(t *testing.T) {
	t.Setenv("PATH", "") // no pg_dump from PATH
	ctx := context.Background()
	all := fakeTools(t, 13, 16, 17)
	for _, c := range []struct{ dump, server, want int }{
		{16, 16, 16}, // disaster recovery: same major
		{16, 17, 17}, // upgrade
		{13, 15, 16}, // the lowest major >= the server's
		{13, 13, 13},
	} {
		tool, err := restoreTool(ctx, all, c.dump, c.server)
		if err != nil || tool.Major != c.want || !strings.HasSuffix(tool.PgRestore, fmt.Sprintf("/%d/bin/pg_restore", c.want)) {
			t.Errorf("dump %d, server %d: %+v %v", c.dump, c.server, tool, err)
		}
	}
	for _, c := range []struct {
		dir          string
		dump, server int
		want         string
	}{
		{all, 17, 16, "the backup was made by pg_dump 17; the target runs PostgreSQL 16"},
		{fakeTools(t, 17), 16, 16, "no pg_restore 16 is installed, and pg_restore 17 cannot restore into PostgreSQL 16"},
		{all, 16, 18, "no pg_restore with major version >= 18"},
	} {
		if _, err := restoreTool(ctx, c.dir, c.dump, c.server); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("dump %d, server %d: %v, want %q", c.dump, c.server, err, c.want)
		}
	}
}

func TestCheckBackupComparesMajors(t *testing.T) {
	e := &Engine{}
	for _, c := range []struct {
		details map[string]any
		server  string
		want    string
	}{
		{map[string]any{"pg_dump_major": float64(17)}, "16.15", "the backup was made by pg_dump 17; the target runs PostgreSQL 16"},
		{map[string]any{"pg_dump_major": float64(16)}, "16.15", ""},
		{map[string]any{"pg_dump_major": float64(16)}, "17.2 (Debian 17.2-1.pgdg120+1)", ""},
		{map[string]any{"pg_dump_major": float64(13)}, "9.6.24", "the target runs PostgreSQL 9"},
		{map[string]any{"databases": []any{"shop"}}, "16.15", ""}, // older manifests
	} {
		got := e.CheckBackup(c.details, &restore.TargetReport{ServerVersion: c.server})
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%v on %s: %q, want %q", c.details, c.server, got, c.want)
		}
	}
}
