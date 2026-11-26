package clickhouse

// The Keeper path of a restored Replicated table. The logical restore
// (table.go) writes it into the CREATE TABLE it generates; the native
// restore (design docs/design/clickhouse-native.md, §6 Execute step 3, and
// the spike's §8) creates each allowed Replicated table itself before its
// RESTORE, from the backup's own CREATE TABLE text with only the engine's
// first two arguments replaced, so the restored table never joins the
// source's replica set when the two servers share a Keeper (RESTORE would
// otherwise create it with the source's path). Nothing else of the text
// is rebuilt: codecs, TTLs, indexes and projections stay as the backup has
// them. A statement whose path and replica cannot be found exactly, as one
// plain string each, is refused.

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// keeperPath is the Keeper path of a restored Replicated table: under
// /olympos-restore/<request id>/, then the database and table names
// escaped as ClickHouse escapes file names ([A-Za-z0-9_] kept, every other
// byte %XX), so a name can add no path component and no macro. It is on
// the target's default Keeper: a path's auxiliary Keeper prefix
// (zookeeper_name:path) is never kept.
func keeperPath(requestID, db, table string) string {
	return "/olympos-restore/" + requestID + "/" + escapeForFileName(db) + "/" + escapeForFileName(table)
}

// requestIDRe is what a request id may look like in a Keeper path.
var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// escapeForFileName is ClickHouse's: [A-Za-z0-9_] stay, every other byte
// is %XX. The logical restore names metadata files with it too.
func escapeForFileName(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isWordByte(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// replicaName is the replica of a restored Replicated table: the target's
// {replica} macro (without it, the target refuses the CREATE).
const replicaName = "{replica}"

// errReplicatedEngine: the Replicated table's Keeper path and replica
// could not be found exactly in its definition; the table is not created.
var errReplicatedEngine = errors.New("its Replicated engine's Keeper path and replica could not be found exactly")

func replicatedErr(format string, a ...any) error {
	return fmt.Errorf("%w (%s)", errReplicatedEngine, fmt.Sprintf(format, a...))
}

// rewriteReplicatedEngine returns create, the backup's CREATE TABLE of
// db.table, with its engine's Keeper path and replica replaced by
// keeperPath(requestID, db, table) and replicaName; every other byte is
// create's. create is read with the strict lexer, by position:
//
//	CREATE TABLE db.table [UUID '…'] (…) ENGINE = Replicated…('path', 'replica'[, …]) …
//
// The engine is one of the allowlist's Replicated engines, named as
// ClickHouse names it (unquoted, in its case), and the path and replica are
// one non-empty string literal each. Refused, with no output: anything the
// lexer does not read (comments, query parameters, …), more than one
// statement, another statement or table, a path with {uuid} or a missing
// path or replica (the server's defaults, refused on an Atomic database
// outside ON CLUSTER, spike §8), a path or replica that is an expression,
// a second ENGINE clause or a second Replicated…( call, and a request id
// requestIDRe does not take.
func rewriteReplicatedEngine(create string, requestID, db, table string) (string, error) {
	if !requestIDRe.MatchString(requestID) {
		return "", replicatedErr("the request id %q cannot be in a Keeper path", requestID)
	}
	if db == "" || table == "" {
		return "", replicatedErr("an empty database or table name")
	}
	if len(create) > maxSchemaEntry || !utf8.ValidString(create) {
		return "", replicatedErr("its definition is too long or not UTF-8")
	}
	toks, err := lexSQL(create)
	if err != nil {
		return "", replicatedErr("%v", err)
	}
	for _, t := range toks {
		if t.punct(";") {
			return "", replicatedErr("more than one statement")
		}
	}
	at := func(i int) token { return tokenAt(toks, i) }

	// CREATE TABLE db.table [UUID '…'] (…)
	if !at(0).is("CREATE") || !at(1).is("TABLE") || !at(2).ident() || !at(3).punct(".") || !at(4).ident() {
		return "", replicatedErr("not a CREATE TABLE db.name")
	}
	if got, want := (objRef{at(2).val, at(4).val}), (objRef{db, table}); got != want {
		return "", replicatedErr("its definition creates %s, not %s", got, want)
	}
	i := 5
	if at(i).is("UUID") {
		if at(i+1).kind != tokString || !isRunID(at(i+1).val) {
			return "", replicatedErr("a UUID Olympos does not read")
		}
		i += 2
	}
	if !at(i).punct("(") {
		return "", replicatedErr("no column list")
	}
	if c := matching(toks, i); c < 0 || !at(c).punct(")") {
		return "", replicatedErr("no column list")
	} else {
		i = c + 1
	}

	// ENGINE = Replicated…('path', 'replica'[, …])
	if !at(i).is("ENGINE") || !at(i+1).punct("=") {
		return "", replicatedErr("no ENGINE = after the columns")
	}
	engine := i + 2
	name := at(engine)
	if name.kind != tokWord || !strings.HasPrefix(name.val, "Replicated") || !allowedEngines[name.val] {
		return "", replicatedErr("its engine is not a Replicated engine Olympos restores")
	}
	open := engine + 1
	if !at(open).punct("(") {
		return "", replicatedErr("no Keeper path or replica (the server's defaults)")
	}
	end := matching(toks, open)
	if end < 0 || !at(end).punct(")") {
		return "", replicatedErr("its engine arguments do not close")
	}
	args := splitArgs(toks, open, end)
	if len(args) < 2 {
		return "", replicatedErr("no Keeper path or replica (the server's defaults)")
	}
	path, replica := args[0], args[1]
	if len(path) != 1 || path[0].kind != tokString || path[0].val == "" {
		return "", replicatedErr("its Keeper path is not one plain string")
	}
	if len(replica) != 1 || replica[0].kind != tokString || replica[0].val == "" {
		return "", replicatedErr("its replica is not one plain string")
	}
	if strings.Contains(strings.ToLower(path[0].val), "{uuid}") {
		return "", replicatedErr("its Keeper path holds {uuid}")
	}

	// One engine: no other ENGINE clause, and no other Replicated…( call
	// anywhere (a column's default, a clause), so the arguments replaced
	// are the only ones a reader could take for the table's engine.
	for j, t := range toks {
		if j == i || j == engine {
			continue
		}
		if t.depth == 0 && t.is("ENGINE") {
			return "", replicatedErr("a second ENGINE clause")
		}
		if t.ident() && len(t.val) >= len("Replicated") && strings.EqualFold(t.val[:len("Replicated")], "Replicated") &&
			at(j+1).punct("(") {
			return "", replicatedErr("a second Replicated engine call")
		}
	}

	p, r := path[0], replica[0]
	var b strings.Builder
	b.Grow(len(create) + len(keeperPath(requestID, db, table)))
	b.WriteString(create[:p.start])
	b.WriteString(quoteString(keeperPath(requestID, db, table)))
	b.WriteString(create[p.end:r.start])
	b.WriteString(quoteString(replicaName))
	b.WriteString(create[r.end:])
	return b.String(), nil
}
