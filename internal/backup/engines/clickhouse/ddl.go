package clickhouse

import "errors"

// The restore never runs SQL text from the backup. It generates every
// CREATE DATABASE and CREATE TABLE itself (table.go) from structured data:
// the manifest's names, column types (read by the strict type grammar in
// types.go and written again), engine and keys. The lexer (sqllex.go) is used to
// read those fields and, for the engines whose parameters are columns
// (ReplacingMergeTree, SummingMergeTree, CollapsingMergeTree,
// VersionedCollapsingMergeTree), the ENGINE clause of the archive's schema
// entry; only bare column names that exist in the restored table are taken
// from it.

// ---------------------------------------------------------------- engine clause

var errEngineClause = errors.New("its ENGINE clause could not be read")

// sourceEngine reads the engine name and arguments of a table's schema
// entry (SHOW CREATE TABLE text) by position only:
//
//	CREATE TABLE [db.]name [UUID '…'] (columns) ENGINE = Name[(args)] …
//
// Nothing else of the statement is used. An entry longer than
// maxSchemaEntry is refused before it is lexed (the lexer's memory grows
// with the number of tokens).
func sourceEngine(ddl string) (string, [][]token, error) {
	if len(ddl) > maxSchemaEntry {
		return "", nil, errEngineClause
	}
	toks, err := lexSQL(ddl)
	if err != nil {
		return "", nil, errEngineClause
	}
	at := func(i int) token { return tokenAt(toks, i) }
	if !at(0).is("CREATE") || !at(1).is("TABLE") || !at(2).ident() {
		return "", nil, errEngineClause
	}
	i := 3
	if at(i).punct(".") {
		if !at(i + 1).ident() {
			return "", nil, errEngineClause
		}
		i += 2
	}
	if at(i).is("UUID") && at(i+1).kind == tokString {
		i += 2
	}
	if !at(i).punct("(") {
		return "", nil, errEngineClause
	}
	c := matching(toks, i)
	if c < 0 || !at(c).punct(")") {
		return "", nil, errEngineClause
	}
	i = c + 1
	if !at(i).is("ENGINE") || !at(i+1).punct("=") || !at(i+2).ident() {
		return "", nil, errEngineClause
	}
	name := at(i + 2).val
	i += 3
	if !at(i).punct("(") {
		return name, nil, nil
	}
	c = matching(toks, i)
	if c < 0 || !at(c).punct(")") {
		return "", nil, errEngineClause
	}
	return name, splitArgs(toks, i, c), nil
}
