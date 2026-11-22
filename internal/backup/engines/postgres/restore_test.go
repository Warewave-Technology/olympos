package postgres

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
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
func chunky(t *testing.T, s *schemaScan, data []byte) {
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

func TestSchemaScanReadsTheDatabaseEntries(t *testing.T) {
	b, err := os.ReadFile("testdata/probe-pg17-schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := &schemaScan{}
	chunky(t, s, b)
	// TABLE entries: public."Odd Name", s.p (partitioned), s.p1, s.t; not
	// views, materialized views or sequences.
	if s.Tables != 4 {
		t.Fatalf("tables %d", s.Tables)
	}
	d, err := databaseDefinition(s.Blocks)
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

func TestDatabaseDefinitionOptions(t *testing.T) {
	blocks := []dbBlock{{Type: "DATABASE", SQL: `CREATE DATABASE "My ""DB""" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = icu LOCALE = 'en_US.UTF-8' ICU_LOCALE = 'en-US' TABLESPACE = fast CONNECTION LIMIT = -1;
ALTER DATABASE "My ""DB""" OWNER TO "App Owner";
SET default_tablespace = '';`}}
	d, err := databaseDefinition(blocks)
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
	if _, err := databaseDefinition([]dbBlock{{Type: "DATABASE", SQL: "CREATE DATABASE x WITH ENCODING = (SELECT 1);"}}); err == nil {
		t.Fatal("expression accepted")
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
