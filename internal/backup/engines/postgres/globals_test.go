package postgres

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// firstLines keeps each statement's first 60 bytes (the password hashes
// are long and of no interest here).
func firstLines(stmts []string) []string {
	out := make([]string, len(stmts))
	for i, s := range stmts {
		if len(s) > 60 {
			s = s[:60]
		}
		out[i] = s
	}
	return out
}

// prefixes: each statement starts with the wanted text.
func prefixes(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !strings.HasPrefix(got[i], want[i]) {
			return false
		}
	}
	return true
}

func TestFilterGlobalsPgDumpAll16(t *testing.T) {
	sql := readFixture(t, "globals-pg16.sql")
	stmts, skipped := filterGlobals(sql, map[string]bool{"postgres": true, "pg_read_all_data": true})
	want := []string{
		"SET default_transaction_read_only = off;",
		"SET client_encoding = 'UTF8';",
		"SET standard_conforming_strings = on;",
		`CREATE ROLE "Mixed Case";`,
		`ALTER ROLE "Mixed Case" WITH NOSUPERUSER INHERIT NOCREATEROLE NOC`,
		"CREATE ROLE app_owner;",
		"ALTER ROLE app_owner WITH NOSUPERUSER INHERIT NOCREATEROLE CREAT",
		"CREATE ROLE readers;",
		"ALTER ROLE readers WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREAT",
		`COMMENT ON ROLE readers IS 'read-only; for "reports"';`,
		"CREATE ROLE reporting;",
		"ALTER ROLE reporting WITH NOSUPERUSER INHERIT NOCREATEROLE NOCRE",
		"ALTER ROLE reporting SET search_path TO 'reporting', 'public';",
		`GRANT readers TO "Mixed Case" WITH ADMIN OPTION, INHERIT TRUE GR`,
		"GRANT readers TO reporting WITH INHERIT TRUE GRANTED BY postgres",
	}
	if !prefixes(stmts, want) {
		t.Fatalf("statements:\n%s\nwant:\n%s", strings.Join(firstLines(stmts), "\n"), strings.Join(want, "\n"))
	}
	for _, s := range stmts {
		if strings.HasPrefix(s, `\`) || strings.Contains(s, "restrict") || strings.Contains(s, "TABLESPACE") {
			t.Errorf("not filtered: %q", s)
		}
	}
	wantSkipped := []string{
		"role postgres: exists on the target, not changed (4 statements skipped)",
		"tablespace archive: not created, tablespaces are not restored (1 statement skipped)",
	}
	if !reflect.DeepEqual(skipped, wantSkipped) {
		t.Fatalf("skipped:\n%s", strings.Join(skipped, "\n"))
	}
	// A skipped entry never carries statement text (password hashes).
	for _, s := range skipped {
		if strings.Contains(s, "SCRAM") {
			t.Errorf("secret in %q", s)
		}
	}
}

func TestFilterGlobalsExistingRoles(t *testing.T) {
	sql := readFixture(t, "globals-pg16.sql")
	// A quoted name matches exactly; every statement about the role goes,
	// memberships where it is the member or the granted role too.
	stmts, skipped := filterGlobals(sql, map[string]bool{"postgres": true, "Mixed Case": true, "readers": true})
	for _, s := range stmts {
		if strings.Contains(s, "Mixed Case") || strings.Contains(s, "readers") {
			t.Errorf("statement about an existing role kept: %q", firstLines([]string{s})[0])
		}
	}
	want := []string{
		"role Mixed Case: exists on the target, not changed (3 statements skipped)",
		"role postgres: exists on the target, not changed (4 statements skipped)",
		"role readers: exists on the target, not changed (5 statements skipped)",
		"tablespace archive: not created, tablespaces are not restored (1 statement skipped)",
	}
	if !reflect.DeepEqual(skipped, want) {
		t.Fatalf("skipped:\n%s", strings.Join(skipped, "\n"))
	}
	// The other roles are created with all their statements.
	joined := strings.Join(stmts, "\n")
	for _, s := range []string{"CREATE ROLE app_owner;", "CREATE ROLE reporting;", "ALTER ROLE reporting SET search_path"} {
		if !strings.Contains(joined, s) {
			t.Errorf("missing %q", s)
		}
	}
}

func TestFilterGlobalsEdgeCases(t *testing.T) {
	sql := `\connect postgres
-- a comment; with a semicolon
SET standard_conforming_strings = on;
CREATE ROLE "semi;colon";
ALTER ROLE "semi;colon" WITH LOGIN PASSWORD 'md5abc;def''ghi';
COMMENT ON ROLE "semi;colon" IS E'line\'s; end';
/* block ; comment */ CREATE ROLE newbie;
GRANT pg_read_all_data TO newbie WITH INHERIT TRUE GRANTED BY postgres;
GRANT pg_monitor TO postgres GRANTED BY postgres;
GRANT SET ON PARAMETER work_mem TO newbie;
GRANT SET ON PARAMETER work_mem TO postgres;
GRANT ALL ON TABLESPACE fast TO newbie;
ALTER TABLESPACE fast OWNER TO newbie;
COMMENT ON TABLESPACE fast IS 'x';
ALTER ROLE newbie IN DATABASE shop SET work_mem TO '1MB';
ALTER ROLE ALL SET statement_timeout TO '1s';
DROP ROLE IF EXISTS gone;
SECURITY LABEL FOR selinux ON ROLE postgres IS 'x';
DO $body$ BEGIN PERFORM 1; END $body$;
CREATE ROLE "Upper"
`
	stmts, skipped := filterGlobals(sql, map[string]bool{"postgres": true, "pg_read_all_data": true, "pg_monitor": true})
	want := []string{
		"SET standard_conforming_strings = on;",
		`CREATE ROLE "semi;colon";`,
		`ALTER ROLE "semi;colon" WITH LOGIN PASSWORD 'md5abc;def''ghi';`,
		`COMMENT ON ROLE "semi;colon" IS E'line\'s; end';`,
		"CREATE ROLE newbie;",
		"GRANT pg_read_all_data TO newbie WITH INHERIT TRUE GRANTED BY postgres;",
		"GRANT SET ON PARAMETER work_mem TO newbie;",
		"DO $body$ BEGIN PERFORM 1; END $body$;",
		`CREATE ROLE "Upper"`,
	}
	if !reflect.DeepEqual(stmts, want) {
		t.Fatalf("statements:\n%s", strings.Join(stmts, "\n"))
	}
	wantSkipped := []string{
		"role postgres: exists on the target, not changed (3 statements skipped)",
		"tablespace fast: not created, tablespaces are not restored (3 statements skipped)",
		"role newbie: per-database setting not applied (ALTER ROLE … IN DATABASE shop)",
		"ALTER ROLE ALL: not applied, it would change the target's existing roles",
		"DROP ROLE: not executed, a restore drops nothing",
	}
	if !reflect.DeepEqual(skipped, wantSkipped) {
		t.Fatalf("skipped:\n%s", strings.Join(skipped, "\n"))
	}
}

func TestSplitSQLDollarAndComments(t *testing.T) {
	got := splitSQL("SELECT $$a;b$$; SELECT 'x--y'; -- c;\nSELECT \"a\"\"b;\" /* x; /* nested; */ y; */ ;\n\\unrestrict k\n  \\echo x\nSELECT 1")
	want := []string{"SELECT $$a;b$$;", "SELECT 'x--y';", `SELECT "a""b;"   ;`, "SELECT 1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}
