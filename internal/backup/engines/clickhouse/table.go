package clickhouse

import (
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------- CREATE

// kindDatabase is the kind checkCreate expects for CREATE DATABASE.
const kindDatabase = "database"

// createStmt is a checked CREATE TABLE or CREATE DATABASE statement.
type createStmt struct {
	src   string
	toks  []token // without a trailing ";"
	kind  string  // KindTable, KindMVInner or kindDatabase
	db    string  // database of the table (the database itself for kindDatabase)
	name  string
	nameT int // index of the name token
	body  int // index of the first token after the name (and its UUID)
	edits []edit
}

type edit struct {
	start, end int
	repl       string
}

func kindWord(kind string) string {
	switch kind {
	case KindTable, KindMVInner:
		return "table"
	case KindView:
		return "view"
	case KindMaterializedView:
		return "materialized view"
	case KindDictionary:
		return "dictionary"
	case KindOther:
		return "live or window view"
	}
	return kind
}

// checkCreate checks that stmt is exactly one CREATE TABLE db.name (kind
// KindTable or KindMVInner) or CREATE DATABASE db (kindDatabase) and
// returns it parsed. A UUID clause after the name is dropped (the target
// assigns its own).
func checkCreate(stmt, kind, db, name string) (*createStmt, error) {
	toks, err := lexSQL(stmt)
	if err != nil {
		if errors.Is(err, errNonASCII) {
			return nil, err
		}
		return nil, fmt.Errorf("cannot read the statement: %w", err)
	}
	if n := len(toks); n > 0 && toks[n-1].punct(";") {
		toks = toks[:n-1]
	}
	for _, t := range toks {
		if t.punct(";") {
			return nil, errors.New("the schema entry holds more than one statement")
		}
	}
	st := &createStmt{src: stmt, toks: toks, kind: kind}
	at := func(i int) token {
		if i < len(toks) {
			return toks[i]
		}
		return token{kind: tokPunct, val: ""}
	}
	if !at(0).is("CREATE") {
		return nil, errors.New("the schema entry is not a CREATE statement")
	}
	switch {
	case at(1).is("OR"):
		return nil, errors.New("CREATE OR REPLACE is refused: a restore never replaces anything")
	case at(1).is("TEMPORARY"):
		return nil, errors.New("CREATE TEMPORARY is refused")
	}
	want := "TABLE"
	if kind == kindDatabase {
		want = "DATABASE"
	}
	if !at(1).is(want) {
		return nil, fmt.Errorf("the schema entry does not create a %s", strings.ToLower(want))
	}
	i := 2
	if at(i).is("IF") {
		return nil, errors.New("CREATE … IF NOT EXISTS is refused")
	}
	if !at(i).ident() {
		return nil, errors.New("the schema entry names no object")
	}
	st.nameT = i
	if kind == kindDatabase {
		st.db = at(i).val
		if st.db != db {
			return nil, fmt.Errorf("the schema entry creates database %s, not %s", st.db, db)
		}
		i++
	} else {
		if !at(i+1).punct(".") || !at(i+2).ident() {
			return nil, fmt.Errorf("the schema entry for %s.%s names no database", db, name)
		}
		st.db, st.name, st.nameT = at(i).val, at(i+2).val, i+2
		if st.db != db || st.name != name {
			return nil, fmt.Errorf("the schema entry creates %s.%s, not %s.%s", st.db, st.name, db, name)
		}
		i += 3
	}
	if at(i).is("UUID") && at(i+1).kind == tokString {
		st.drop(i, i+1)
		i += 2
	}
	if at(i).is("ON") && at(i+1).is("CLUSTER") {
		return nil, errors.New("ON CLUSTER is refused: a restore only writes to the target server")
	}
	st.body = i
	return st, nil
}

// drop removes tokens i..j (inclusive) from the statement run.
func (s *createStmt) drop(i, j int) {
	end := s.toks[j].end
	if j+1 < len(s.toks) {
		end = s.toks[j+1].start
	}
	s.edits = append(s.edits, edit{start: s.toks[i].start, end: end})
}

// rename makes the statement create table name instead.
func (s *createStmt) rename(name string) {
	t := s.toks[s.nameT]
	s.edits = append(s.edits, edit{start: t.start, end: t.end, repl: quoteIdent(name)})
	s.name = name
}

// sql is the statement to run: the edits applied in order, without a
// trailing ";" or comments after the last token.
func (s *createStmt) sql() string {
	if len(s.toks) == 0 {
		return ""
	}
	for i := 1; i < len(s.edits); i++ {
		for j := i; j > 0 && s.edits[j].start < s.edits[j-1].start; j-- {
			s.edits[j], s.edits[j-1] = s.edits[j-1], s.edits[j]
		}
	}
	var b strings.Builder
	pos := 0
	for _, e := range s.edits {
		b.WriteString(s.src[pos:e.start])
		b.WriteString(e.repl)
		pos = e.end
	}
	b.WriteString(s.src[pos:s.toks[len(s.toks)-1].end])
	return b.String()
}

// close returns the index of the ")" matching the "(" at i.
func (s *createStmt) close(i int) int {
	d := s.toks[i].depth
	for j := i + 1; j < len(s.toks); j++ {
		if s.toks[j].punct(")") && s.toks[j].depth == d {
			return j
		}
	}
	return len(s.toks) - 1
}

// args splits the arguments of the "(" at i into token ranges [from, to).
func (s *createStmt) args(i int) [][2]int {
	end := s.close(i)
	if end == i+1 {
		return nil
	}
	var out [][2]int
	from := i + 1
	d := s.toks[i].depth + 1
	for j := i + 1; j <= end; j++ {
		if j == end || (s.toks[j].punct(",") && s.toks[j].depth == d) {
			out = append(out, [2]int{from, j})
			from = j + 1
		}
	}
	return out
}

// engine finds "ENGINE = Name[(args)]" at depth 0: the index of the name
// token (-1 without an ENGINE clause).
func (s *createStmt) engine() int {
	for i := s.body; i+2 < len(s.toks); i++ {
		t := s.toks[i]
		if t.depth == 0 && t.is("ENGINE") && s.toks[i+1].punct("=") && s.toks[i+2].ident() {
			return i + 2
		}
	}
	return -1
}

// engineName is the engine of the ENGINE clause ("" without one).
func (s *createStmt) engineName() string {
	if i := s.engine(); i >= 0 {
		return s.toks[i].val
	}
	return ""
}

// ---------------------------------------------------------------- engines

// tableEngines keep their data on the target and read nothing else; with
// the Replicated variants of the MergeTree ones (Keeper path rewritten)
// they are the only engines a restore creates.
var tableEngines = map[string]bool{
	"MergeTree": true, "ReplacingMergeTree": true, "SummingMergeTree": true, "AggregatingMergeTree": true,
	"CollapsingMergeTree": true, "VersionedCollapsingMergeTree": true, "GraphiteMergeTree": true,
	"Log": true, "TinyLog": true, "StripeLog": true, "Memory": true,
}

func restorableEngine(engine string) bool {
	if tableEngines[engine] {
		return true
	}
	base, ok := strings.CutPrefix(engine, "Replicated")
	return ok && isMergeTree(base) && tableEngines[base]
}

func engineSkipReason(engine string) string {
	if engine == "Distributed" {
		return "engine Distributed points at a cluster"
	}
	return "engine " + engine + " is not restored by Olympos (it restores MergeTree, Log and Memory tables)"
}

// storageSettings are the table SETTINGS a restored table may have.
var storageSettings = map[string]bool{
	"index_granularity": true, "index_granularity_bytes": true, "min_bytes_for_wide_part": true,
	"min_rows_for_wide_part": true, "ttl_only_drop_parts": true, "merge_with_ttl_timeout": true,
	"storage_policy": true, "allow_nullable_key": true, "enable_mixed_granularity_parts": true,
}

// pureFunctions may appear in a restored table's expressions (DEFAULT,
// MATERIALIZED, ALIAS, CODEC, TTL, INDEX, PARTITION BY, ORDER BY, ...):
// scalar functions that read nothing but their arguments, plus the type,
// codec, index type and engine names written with parentheses. Names are
// compared lower case.
var pureFunctions = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Fields(`
		plus minus multiply divide intdiv intdivorzero modulo moduloorzero negate abs gcd lcm
		equals notequals less greater lessorequals greaterorequals and or not xor
		if multiif coalesce ifnull nullif assumenotnull isnull isnotnull isnan isfinite isinfinite ifnotfinite
		cast accuratecast accuratecastornull accuratecastordefault
		now now64 today yesterday date_trunc datetrunc dateadd date_add datesub date_sub datediff date_diff
		timestamp_add timestamp_sub formatdatetime makedate makedate32 makedatetime makedatetime64 timeslot
		yyyymmddtodate yyyymmddhhmmsstodatetime
		lower upper lowerutf8 upperutf8 length lengthutf8 empty notempty concat concatwithseparator substring substr
		substringutf8 trim trimleft trimright trimboth replace replaceall replaceone replaceregexpall replaceregexpone
		position positioncaseinsensitive splitbychar splitbystring splitbyregexp lpad rpad leftpad rightpad left right
		reverse base64encode base64decode hex unhex extract extractall match like ilike notlike startswith endswith
		repeat
		cityhash64 siphash64 siphash128 xxhash32 xxhash64 xxh3 halfmd5 md5 sha1 sha224 sha256 sha512 crc32 crc64
		inthash32 inthash64 farmfingerprint64 wyhash64 javahash hiveHash
		rand rand32 rand64 randconstant generateuuidv4 generateuuidv7 generateulid generatesnowflakeid
		array tuple map has hasany hasall indexof range emptyarrayuint8 tupleelement mapkeys mapvalues mapcontains
		round roundbankers floor ceil trunc sqrt exp log ln log2 log10 pow power greatest least sign
		bitand bitor bitxor bitnot bitshiftleft bitshiftright materialize
		nullable lowcardinality nested decimal decimal32 decimal64 decimal128 decimal256 datetime datetime64
		fixedstring enum enum8 enum16 variant dynamic json object time time64 interval
		codec zstd lz4 lz4hc delta doubledelta gorilla t64 fpc gcd none
		minmax set bloom_filter tokenbf_v1 ngrambf_v1 full_text text vector_similarity
	`) {
		m[strings.ToLower(n)] = true
	}
	for e := range tableEngines {
		m[strings.ToLower(e)] = true
		if isMergeTree(e) {
			m["replicated"+strings.ToLower(e)] = true
		}
	}
	return m
}()

// purePrefixes: families of pure functions (toString, toStartOfDay,
// addDays, arrayMap, murmurHash3_64, ...).
var purePrefixes = []string{"to", "add", "subtract", "reinterpret", "parsedatetime", "fromunixtimestamp", "murmurhash",
	"array", "round", "datediff", "formatreadable"}

// aggregateTypes take aggregate function names (with parameters) as type
// arguments: their arguments are types, not calls.
var aggregateTypes = map[string]bool{"aggregatefunction": true, "simpleaggregatefunction": true}

// keywordParens are words that may precede "(" without being a call.
var keywordParens = map[string]bool{
	"by": true, "key": true, "default": true, "materialized": true, "alias": true, "ephemeral": true, "ttl": true,
	"check": true, "assume": true, "and": true, "or": true, "not": true, "like": true, "ilike": true, "between": true,
	"is": true, "then": true, "else": true, "when": true, "case": true, "delete": true, "where": true, "set": true,
	"to": true, "comment": true, "type": true, "granularity": true, "recompress": true, "statistics": true,
}

func pureFunction(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "addressto") {
		return false
	}
	if pureFunctions[n] {
		return true
	}
	for _, p := range purePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// tableProblem is why a checked CREATE TABLE of engine is not created
// ("": it is): no AS or EMPTY, a restorable engine, only storage settings,
// and expressions without subqueries, IN or functions outside
// pureFunctions.
func (s *createStmt) tableProblem() string {
	for i := s.body; i < len(s.toks); i++ {
		t := s.toks[i]
		if t.depth == 0 && (t.is("AS") || t.is("EMPTY")) {
			return "it is defined AS another table, a query or a table function"
		}
	}
	engine := s.engineName()
	if engine == "" {
		return "it has no ENGINE clause"
	}
	if !restorableEngine(engine) {
		return engineSkipReason(engine)
	}
	end := len(s.toks)
	for i := s.body; i < len(s.toks); i++ {
		if t := s.toks[i]; t.depth == 0 && t.is("SETTINGS") {
			if why := s.settingsProblem(i + 1); why != "" {
				return why
			}
			end = i
			break
		}
	}
	for i := s.body; i < end; i++ {
		t := s.toks[i]
		if t.kind == tokWord {
			switch strings.ToUpper(t.val) {
			case "SELECT", "WITH", "EXPLAIN", "DESCRIBE":
				return "an expression of it holds a query"
			case "IN", "GLOBAL":
				return "an expression of it uses IN"
			case "PROJECTION":
				return "it has a projection (a query)"
			}
		}
		if !t.ident() || i+1 >= end || !s.toks[i+1].punct("(") {
			continue
		}
		n := strings.ToLower(t.val)
		switch {
		case t.kind == tokWord && keywordParens[n]:
		case i > 0 && s.toks[i-1].is("INDEX"):
			// INDEX name (expr) TYPE ...
		case aggregateTypes[n]:
			i = s.close(i + 1)
		case t.kind == tokWord && pureFunction(n):
		default:
			return "an expression of it calls " + t.val + "(), which Olympos does not restore in a table definition"
		}
	}
	return ""
}

// settingsProblem checks "name = value[, ...] [COMMENT '…']" from i.
func (s *createStmt) settingsProblem(i int) string {
	for i < len(s.toks) {
		k := s.toks[i]
		if k.is("COMMENT") && i+2 == len(s.toks) && s.toks[i+1].kind == tokString {
			return ""
		}
		if k.kind != tokWord || i+1 >= len(s.toks) || !s.toks[i+1].punct("=") {
			return "its SETTINGS cannot be read"
		}
		if !storageSettings[strings.ToLower(k.val)] {
			return "it has setting " + k.val + ", which Olympos does not restore"
		}
		if i+2 >= len(s.toks) {
			return "its SETTINGS cannot be read"
		}
		v := s.toks[i+2]
		if v.kind != tokString && v.kind != tokNumber && v.kind != tokWord {
			return "its setting " + k.val + " has a value Olympos does not restore"
		}
		i += 3
		if i < len(s.toks) && s.toks[i].punct(",") {
			i++
		}
	}
	return ""
}

// databaseProblem: CREATE DATABASE name [ENGINE = E[(n)]] [COMMENT '…']
// and nothing else ("": it is so).
func (s *createStmt) databaseProblem() string {
	i := s.body
	if i+2 < len(s.toks) && s.toks[i].is("ENGINE") && s.toks[i+1].punct("=") && s.toks[i+2].ident() {
		i += 3
		if i+2 < len(s.toks) && s.toks[i].punct("(") && s.toks[i+1].kind == tokNumber && s.toks[i+2].punct(")") {
			i += 3
		}
	}
	if i+1 < len(s.toks) && s.toks[i].is("COMMENT") && s.toks[i+1].kind == tokString {
		i += 2
	}
	if i != len(s.toks) {
		return "CREATE DATABASE has clauses Olympos does not restore"
	}
	return ""
}

// ---------------------------------------------------------------- classify

// notRecreated is the reason for views, materialized views, dictionaries
// and live or window views.
const notRecreated = "not created: recreate it from your schema (Olympos restores tables and data)"

// classification is what the restore does with one table.
type classification struct {
	st     *createStmt
	create bool
	reason string // why it is not created (no DDL in it)
}

// classify checks ddl (a table's schema entry) against the manifest's
// table t of database db and decides whether it is created. Objects other
// than tables are never created. An error means the schema entry is not
// what the manifest says (the restore is refused).
func classify(db string, t Table, ddl string) (classification, error) {
	if t.Kind != KindTable && t.Kind != KindMVInner {
		return classification{reason: notRecreated}, nil
	}
	st, err := checkCreate(ddl, t.Kind, db, t.Name)
	if errors.Is(err, errNonASCII) {
		return classification{reason: err.Error() + "; not created (create it by hand)"}, nil
	}
	if err != nil {
		return classification{}, err
	}
	if e := st.engineName(); e != "" && e != t.Engine {
		return classification{}, fmt.Errorf("the schema entry has engine %s, the backup recorded %s", e, t.Engine)
	}
	if why := st.tableProblem(); why != "" {
		return classification{st: st, reason: why + "; not created (create it by hand)"}, nil
	}
	return classification{st: st, create: true}, nil
}

// ---------------------------------------------------------------- Keeper paths

// defaultReplicaPath is ClickHouse's default_replica_path (used when a
// Replicated table names no path; the restore always sets one).
const (
	defaultReplicaPath = "/clickhouse/tables/{uuid}/{shard}"
	defaultReplicaName = "{replica}"
)

// restorePath puts a Keeper path under /olympos-restore/<request id>/,
// keeping an auxiliary Keeper's "name:" prefix.
func restorePath(path, requestID string) string {
	aux := ""
	if i := strings.Index(path, ":"); i > 0 && !strings.Contains(path[:i], "/") {
		aux, path = path[:i+1], path[i+1:]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return aux + "/olympos-restore/" + requestID + path
}

// rewriteKeeperPaths puts the Keeper path of a Replicated*MergeTree under
// /olympos-restore/<request id>/, so the restored table never shares
// Keeper state with the source's when Keeper is shared. Without a path in
// the statement, one is set (with the default replica name). It returns
// whether anything was rewritten.
func (s *createStmt) rewriteKeeperPaths(requestID string) bool {
	i := s.engine()
	if i < 0 {
		return false
	}
	if engine := s.toks[i].val; !strings.HasPrefix(engine, "Replicated") || !isMergeTree(engine) {
		return false
	}
	hasParen := i+1 < len(s.toks) && s.toks[i+1].punct("(")
	var args [][2]int
	if hasParen {
		args = s.args(i + 1)
	}
	str := func(a [2]int) bool { return a[1]-a[0] == 1 && s.toks[a[0]].kind == tokString }
	// The path form: the first two arguments are strings (GraphiteMergeTree
	// takes one string of its own, so a single string is not a path).
	if len(args) >= 2 && str(args[0]) && str(args[1]) {
		t := s.toks[args[0][0]]
		s.edits = append(s.edits, edit{start: t.start, end: t.end, repl: quoteString(restorePath(t.val, requestID))})
		return true
	}
	prefix := quoteString(restorePath(defaultReplicaPath, requestID)) + ", " + quoteString(defaultReplicaName)
	switch {
	case !hasParen:
		s.edits = append(s.edits, edit{start: s.toks[i].end, end: s.toks[i].end, repl: "(" + prefix + ")"})
	case len(args) == 0:
		p := s.toks[i+1].end
		s.edits = append(s.edits, edit{start: p, end: p, repl: prefix})
	default:
		p := s.toks[args[0][0]].start
		s.edits = append(s.edits, edit{start: p, end: p, repl: prefix + ", "})
	}
	return true
}

// rewriteReplicatedPath rewrites the Keeper path of a Replicated*MergeTree
// CREATE TABLE statement to /olympos-restore/<request id>/…; ok is false
// (and ddl unchanged) for any other statement or one that cannot be read.
func rewriteReplicatedPath(ddl, requestID string) (string, bool) {
	toks, err := lexSQL(ddl)
	if err != nil || len(toks) < 3 || !toks[0].is("CREATE") || !toks[1].is("TABLE") {
		return ddl, false
	}
	st := &createStmt{src: ddl, toks: toks, kind: KindTable, body: 2}
	if n := len(st.toks); st.toks[n-1].punct(";") {
		st.toks = st.toks[:n-1]
	}
	if !st.rewriteKeeperPaths(requestID) {
		return ddl, false
	}
	return st.sql(), true
}
