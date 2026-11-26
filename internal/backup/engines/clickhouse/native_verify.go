package clickhouse

// What a native restore created, compared with what was approved (security
// review v0.4, finding 1, defence in depth). RESTORE creates each object from
// the backup's own files, read by size and checksum, so what it created is
// compared, after RESTORED, with the definition the allowlist decided on:
// system.tables' engine and create_table_query must be that definition, and
// the allowlist must allow create_table_query again, reading only objects the
// restore was to create. ClickHouse writes create_table_query as the
// backup's statement without its UUIDs (24.8 and 25.8, the same version or
// across them), with a dictionary source's PASSWORD as '[HIDDEN]'; nothing
// else may differ.

import (
	"strings"
)

// hiddenSecret is what ClickHouse shows in place of a secret.
const hiddenSecret = "[HIDDEN]"

// engineName is the engine system.tables shows for an object of def.
func (d definition) engineName() string {
	switch d.kind {
	case KindView:
		return "View"
	case KindMaterializedView:
		return "MaterializedView"
	case KindDictionary:
		return "Dictionary"
	}
	return d.engine
}

// definitionTokens lexes a definition without its UUID clauses, which
// RESTORE does not keep: UUID '…' right after "CREATE <kind> db.name", and a
// materialized view's TO INNER UUID '…' right after that; false when the
// lexer does not read it.
func definitionTokens(text string) ([]token, bool) {
	toks, err := lexSQL(text)
	if err != nil {
		return nil, false
	}
	at := func(i int) token { return tokenAt(toks, i) }
	h := 5 // after CREATE TABLE|VIEW|DICTIONARY db . name
	if at(1).is("MATERIALIZED") {
		h = 6
	}
	if !at(0).is("CREATE") || !at(h-2).punct(".") {
		return toks, true
	}
	out := append([]token(nil), toks[:h]...)
	i := h
	if at(i).is("UUID") && at(i+1).kind == tokString {
		i += 2
	}
	if h == 6 && at(i).is("TO") && at(i+1).is("INNER") && at(i+2).is("UUID") && at(i+3).kind == tokString {
		i += 4
	}
	return append(out, toks[min(i, len(toks)):]...), true
}

// sameDefinition reports whether got, a create_table_query, is approved, the
// definition decided on, as ClickHouse writes it: the same tokens, but for
// the UUIDs and a PASSWORD shown as '[HIDDEN]', or the same tokens as
// approved with the encrypt functions' secret arguments masked
// (maskSecretArguments).
func sameDefinition(approved, got string) bool {
	a, ok1 := definitionTokens(approved)
	g, ok2 := definitionTokens(got)
	if !ok1 || !ok2 {
		return false
	}
	return sameTokens(a, g) || sameTokens(maskSecretArguments(a), g)
}

// secretArgumentFunctions are the functions whose arguments from the second
// on ClickHouse 24.8 and 25.8 show as one '[HIDDEN]' in system.tables (fix
// round 1 of the security review v0.4, C): f('mode', x, 'key', …) is shown
// as f('mode', '[HIDDEN]'). The names are case-sensitive, as ClickHouse's.
var secretArgumentFunctions = map[string]bool{"encrypt": true, "decrypt": true, "tryDecrypt": true,
	"aes_encrypt_mysql": true, "aes_decrypt_mysql": true}

// maskSecretArguments is toks with the arguments of every call of a
// secretArgumentFunctions function from the second on replaced by one
// '[HIDDEN]', as ClickHouse shows it; a call with one argument is kept. What
// was in those arguments is not compared: it is the one part of a definition
// the target does not show.
func maskSecretArguments(toks []token) []token {
	closing := make([]int, len(toks))
	var open []int
	for i, t := range toks {
		closing[i] = -1
		switch {
		case t.punct("(") || t.punct("["):
			open = append(open, i)
		case (t.punct(")") || t.punct("]")) && len(open) > 0:
			closing[open[len(open)-1]] = i
			open = open[:len(open)-1]
		}
	}
	out := make([]token, 0, len(toks))
	for i := 0; i < len(toks); i++ {
		out = append(out, toks[i])
		if !toks[i].ident() || !secretArgumentFunctions[toks[i].val] || !tokenAt(toks, i+1).punct("(") || closing[i+1] < 0 {
			continue
		}
		o, c := i+1, closing[i+1]
		comma := -1
		for j := o + 1; j < c; j++ {
			if toks[j].punct(",") && toks[j].depth == toks[o].depth+1 {
				comma = j
				break
			}
		}
		if comma < 0 {
			continue
		}
		out = append(out, maskSecretArguments(toks[o:comma+1])...)
		out = append(out, token{kind: tokString, val: hiddenSecret}, toks[c])
		i = c
	}
	return out
}

// sameTokens is sameDefinition on lexed definitions.
func sameTokens(a, g []token) bool {
	if len(a) != len(g) {
		return false
	}
	for i := range a {
		x, y := a[i], g[i]
		switch {
		case x.kind == tokString && y.kind == tokString && y.val == hiddenSecret && i > 0 && g[i-1].is("PASSWORD"):
		case x.kind != y.kind || x.val != y.val:
			return false
		}
	}
	return true
}

// restoredMismatch says why o, an allowed object the target holds, is not
// what was approved ("" when it is): approved is its definition, or for a
// Replicated table the statement Olympos created it with; allowed are the
// objects the restore was to create.
func restoredMismatch(o restoredObject, kind string, approved string, allowed map[objRef]Decision) string {
	if approved == "" {
		return "its approved definition is not known"
	}
	want := readDefinition(o.db, o.name, []byte(approved))
	got := readDefinition(o.db, o.name, []byte(o.query))
	switch {
	case o.engine != want.engineName():
		return "it has the " + shortName(o.engine) + " engine, not the approved " + shortName(want.engineName())
	case !sameDefinition(approved, o.query):
		return "its definition is not the approved one"
	case got.reason != "":
		return "the allowlist refuses its definition on the target: " + got.reason
	case got.kind != kind:
		return "its definition on the target is not a " + kindName(kind)
	}
	return readsOutside(got, allowed)
}

// innerMismatch says why o, the inner table of the allowed materialized view
// mv, is not what the view's approved definition makes it ("" when it is):
// a table the allowlist allows, not Replicated, on the engine of the view's
// definition.
func innerMismatch(o restoredObject, mv objRef, mvApproved string) string {
	want := readDefinition(mv.db, mv.name, []byte(mvApproved))
	got := readDefinition(o.db, o.name, []byte(o.query))
	switch {
	case got.reason != "":
		return "the allowlist refuses its definition on the target: " + got.reason
	case got.kind != KindTable || got.replicated:
		return "its definition on the target is not a table of a local engine"
	case want.engine == "" || o.engine != want.engine || got.engine != want.engine:
		return "it has the " + shortName(o.engine) + " engine, not its view's " + shortName(want.engine)
	}
	return ""
}

// readsOutside says why what def reads is not all among allowed, or its TO
// table not an allowed table ("" when it is).
func readsOutside(def definition, allowed map[objRef]Decision) string {
	if t := def.target; t != nil {
		if d, ok := allowed[*t]; !ok || d.Kind != KindTable {
			return "on the target it writes to " + t.String() + ", which the restore was not to create as a table"
		}
	}
	for _, r := range def.reads {
		if _, ok := allowed[r]; !ok {
			return "on the target it reads " + r.String() + ", which the restore was not to create"
		}
	}
	return ""
}

// dropStatement is the statement that removes o, of system.tables' engine.
func dropStatement(o restoredObject) string {
	what := "TABLE"
	if strings.EqualFold(o.engine, "Dictionary") {
		what = "DICTIONARY"
	}
	return "DROP " + what + " " + quoteIdent(o.db) + "." + quoteIdent(o.name) + " SYNC"
}
