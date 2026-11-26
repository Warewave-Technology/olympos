package clickhouse

// The helpers that decide what a restore creates on its target, the
// logical one and the native one (design docs/design/clickhouse-native.md
// §6): how every name from a backup is quoted into the statements Olympos
// sends (CREATE, RESTORE, EXCEPT TABLES), the databases it creates and
// refuses, and the bounds of what it reads. A security-model path
// (scripts/security-model-paths.sh).

import (
	"fmt"
	"strings"
)

// quoteIdent quotes a ClickHouse identifier with backticks.
func quoteIdent(s string) string { return quoteWith(s, '`') }

// quoteString quotes a ClickHouse string literal.
func quoteString(s string) string { return quoteWith(s, '\'') }

// quoteWith quotes s strictly: the quote and backslash are escaped, and so
// is every control byte (\xHH), so the quoted text is one plain line that
// ClickHouse reads back as exactly s.
func quoteWith(s string, q byte) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte(q)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' || c == q:
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			const hexDigits = "0123456789abcdef"
			b.WriteString(`\x`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte(q)
	return b.String()
}

// maxSchemaEntry bounds the bytes of a schema entry (a metadata/*.sql) that
// are read into memory and lexed. A schema entry is only read for what it
// creates, and the lexer's cost grows with the number of tokens (a 16 MiB
// run of commas takes about 3.6 GB of heap), so the cap is small: a longer
// entry is not read, and the object it would have given is not created.
const maxSchemaEntry = 1 << 20

// systemDatabases are never backed up.
var systemDatabases = map[string]bool{
	"system":             true,
	"INFORMATION_SCHEMA": true,
	"information_schema": true,
}

func isSystemDatabase(name string) bool { return systemDatabases[name] }

// restorableDatabaseEngines are the database engines a restore creates. A
// Replicated database is refused (its Keeper path could collide with the
// source's when Keeper is shared); the others proxy external systems.
var restorableDatabaseEngines = map[string]bool{"Atomic": true, "Ordinary": true, "Lazy": true, "Memory": true}

func databaseEngineProblem(engine string) string {
	switch {
	case engine == "Replicated":
		return "it has the Replicated database engine, which Olympos does not restore: its Keeper path could collide with the source's " +
			"when Keeper is shared (restore its tables into an Atomic database by hand)"
	case !restorableDatabaseEngines[engine]:
		return "it has the " + engine + " database engine, a proxy for another system, which Olympos does not restore"
	}
	return ""
}

// databaseSQL is the CREATE DATABASE of a restored database.
func databaseSQL(db string) string { return "CREATE DATABASE " + quoteIdent(db) + " ENGINE = Atomic" }

// printable escapes control characters (names in the backup may hold
// any) so a message is one plain line.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			fmt.Fprintf(&b, "\\x%02x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
