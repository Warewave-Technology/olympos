package clickhouse

// The restore allowlist (design docs/design/clickhouse-native.md, §6 and
// Owner decision option 1). A native RESTORE runs the backup's own
// metadata/*.sql on the target, so Olympos reads each object's definition
// and lets only what it can prove harmless be created:
//
//   - MergeTree-family (Replicated too, not Graphite: R47), Log-family and
//     Memory tables, with any column or table feature, but not on a disk or
//     storage policy of their own (SETTINGS disk = …, storage_policy = …),
//     which can reach outside the server, nor with an encryption codec
//     (R49);
//   - views and materialized views whose query reads only objects restored,
//     with no table function; a materialized view's TO table is restored
//     too; its inner table is not Replicated (R48); a refreshable one is
//     not restored;
//   - dictionaries with a local ClickHouse source (no HOST or PORT) on an
//     object restored.
//
// Everything else is left out (RESTORE … EXCEPT TABLES) and listed with the
// reason. The manifest's Kind and Engine come from the statement's prefix
// only (ObjectsFromMetadata) and are never trusted: Classify reads the whole
// definition behind each object's DDLKey with the strict lexer of sqllex.go
// (no comments, no query parameters, nothing it does not read). A rule
// allows only what it matches positively; what it does not read with
// certainty is "cannot be parsed with certainty". A mistake here can only
// leave something out, never let something in.
//
// What a definition reads is collected from every FROM and JOIN source (the
// subqueries, CTEs and unions in it too), every "IN <table>", and the
// object a dictGet* or joinGet names. A source followed by "(" is a table
// function, and so is "IN f(…)" unless f is tuple or array. An unqualified name is of the object's own database, as
// ClickHouse qualifies a view's names when it creates it; a CTE's name is
// not a table within the SELECT that defines it. An object is restored only
// when everything it reads is, to a fixed point.

import (
	"fmt"
	"maps"
	"strings"
	"unicode/utf8"
)

// Decision is what a native restore does with one object of the backup:
// Allowed objects are created by RESTORE; the others are left out (EXCEPT
// TABLES), with the reason shown to the maker and the checker. Kind is the
// manifest's.
type Decision struct {
	Database string `json:"database"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`
}

// reasonUncertain: the definition holds text the lexer does not read, more
// than one statement, or syntax a decision depends on that the rules below
// do not know.
const reasonUncertain = "cannot be parsed with certainty"

const (
	reasonInlineDisk = "its settings define a disk inline"
	reasonRefresh    = "a refreshable materialized view runs its query on a schedule"
)

// maxNesting bounds the brackets of a definition the allowlist reads (its
// reader recurses on them).
const maxNesting = 256

// allowedEngines are the table engines restored: they keep their data on
// the server's own disks. GraphiteMergeTree is not among them (R47): it
// needs the graphite_rollup section of the server's configuration, which
// Olympos does not know on the target, and without it RESTORE fails as a
// whole (the v0.2 restore leaves it out too).
var allowedEngines = func() map[string]bool {
	m := map[string]bool{"Log": true, "TinyLog": true, "StripeLog": true, "Memory": true}
	for _, e := range []string{"MergeTree", "ReplacingMergeTree", "SummingMergeTree", "AggregatingMergeTree",
		"CollapsingMergeTree", "VersionedCollapsingMergeTree", "CoalescingMergeTree"} {
		m[e] = true
		m["Replicated"+e] = true
	}
	return m
}()

// tableClauses start what may follow a table's ENGINE = Name(…).
var tableClauses = map[string]bool{"PARTITION": true, "PRIMARY": true, "ORDER": true, "SAMPLE": true,
	"TTL": true, "SETTINGS": true, "COMMENT": true}

// clickhouseSourceKeys are the keys of a dictionary's CLICKHOUSE source that
// keep it on the local server (HOST and PORT have their own reasons).
var clickhouseSourceKeys = map[string]bool{"DB": true, "TABLE": true, "QUERY": true, "WHERE": true,
	"INVALIDATE_QUERY": true, "UPDATE_FIELD": true, "UPDATE_LAG": true, "USER": true, "PASSWORD": true}

// allowedLayouts are the dictionary layouts restored; SSD_CACHE names a
// path on the server's file system.
var allowedLayouts = map[string]bool{"FLAT": true, "HASHED": true, "SPARSE_HASHED": true,
	"COMPLEX_KEY_HASHED": true, "COMPLEX_KEY_SPARSE_HASHED": true, "HASHED_ARRAY": true,
	"COMPLEX_KEY_HASHED_ARRAY": true, "RANGE_HASHED": true, "COMPLEX_KEY_RANGE_HASHED": true,
	"CACHE": true, "COMPLEX_KEY_CACHE": true, "DIRECT": true, "COMPLEX_KEY_DIRECT": true, "IP_TRIE": true,
	"POLYGON": true, "POLYGON_SIMPLE": true, "POLYGON_INDEX_EACH": true, "POLYGON_INDEX_CELL": true}

// outsideCalls are functions (lower-case) that read a host, a URL, a file,
// a command or a model when called anywhere in a definition: the table
// functions (a FROM or JOIN source with "(" is one whatever its name; these
// are caught after IN and as scalars too) and the scalar functions that do.
var outsideCalls = map[string]bool{
	"url": true, "urlcluster": true, "s3": true, "s3cluster": true, "gcs": true, "cosn": true, "oss": true,
	"azureblobstorage": true, "azureblobstoragecluster": true, "remote": true, "remotesecure": true,
	"cluster": true, "clusterallreplicas": true, "file": true, "filecluster": true, "input": true,
	"mysql": true, "postgresql": true, "mongodb": true, "redis": true, "sqlite": true, "hdfs": true,
	"hdfscluster": true, "jdbc": true, "odbc": true, "executable": true, "deltalake": true,
	"deltalakecluster": true, "hudi": true, "hudicluster": true, "iceberg": true, "icebergs3": true,
	"icebergazure": true, "iceberghdfs": true, "iceberglocal": true, "icebergcluster": true,
	"icebergs3cluster": true, "icebergazurecluster": true, "iceberghdfscluster": true, "paimon": true,
	"arrowflight": true, "ytsaurus": true,
	"hascolumnintable": true, "catboostevaluate": true, "modelevaluate": true, "naivebayesclassifier": true,
}

// fromEnds are the words that end a SELECT's FROM clause.
var fromEnds = map[string]bool{"WHERE": true, "PREWHERE": true, "GROUP": true, "ORDER": true, "HAVING": true,
	"LIMIT": true, "OFFSET": true, "FETCH": true, "WINDOW": true, "QUALIFY": true, "SETTINGS": true,
	"FORMAT": true, "INTO": true, "INTERPOLATE": true}

// Classify decides, for every object of dbs, whether a native restore
// creates it. ddl holds the metadata/*.sql bodies of the backup's chain, by
// DDLKey. The decisions are in the order of dbs and their objects.
func Classify(dbs []NativeDatabase, ddl map[string][]byte) []Decision {
	listed := map[objRef]int{}
	for _, d := range dbs {
		for _, o := range d.Objects {
			listed[objRef{d.Name, o.Name}]++
		}
	}
	var out []Decision
	var defs []definition
	for _, d := range dbs {
		for _, o := range d.Objects {
			reason, def := classifyObject(d.Name, o, ddl, listed)
			out = append(out, Decision{Database: d.Name, Name: o.Name, Kind: o.Kind, Reason: reason})
			defs = append(defs, def)
		}
	}

	// An object is restored only when what it reads is: leave out, to a
	// fixed point, every object that reads one left out (or one the backup
	// does not hold).
	allowed := map[objRef]int{} // → index in out
	dependents := map[objRef][]int{}
	for i, dec := range out {
		if dec.Reason != "" {
			continue
		}
		allowed[objRef{dec.Database, dec.Name}] = i
		for _, r := range defs[i].deps() {
			dependents[r] = append(dependents[r], i)
		}
	}
	var queue []objRef
	leaveOut := func(i int) {
		r := objRef{out[i].Database, out[i].Name}
		delete(allowed, r)
		queue = append(queue, r)
	}
	for i := range out {
		if _, ok := allowed[objRef{out[i].Database, out[i].Name}]; ok && missingDependency(defs[i], allowed, listed, defs) != "" {
			leaveOut(i)
		}
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		for _, i := range dependents[r] {
			if _, ok := allowed[objRef{out[i].Database, out[i].Name}]; ok && missingDependency(defs[i], allowed, listed, defs) != "" {
				leaveOut(i)
			}
		}
	}
	for i := range out {
		if out[i].Reason == "" {
			// Named against the final set, so the reason does not depend on
			// the order objects were left out in.
			out[i].Reason = missingDependency(defs[i], allowed, listed, defs)
		}
		out[i].Allowed = out[i].Reason == ""
	}
	return out
}

// classifyObject reads one object's definition and returns why its own text
// leaves it out ("" when it does not) and what it reads.
func classifyObject(db string, o NativeObject, ddl map[string][]byte, listed map[objRef]int) (string, definition) {
	switch {
	case listed[objRef{db, o.Name}] > 1:
		return "the backup lists it twice", definition{}
	case isInnerName(o.Name):
		return "a file named like a materialized view's inner table", definition{}
	}
	if kdb, kname, err := metadataPath(o.DDLKey); err != nil || kdb != db || kname != o.Name {
		return "its definition is filed under another name", definition{}
	}
	body, ok := ddl[o.DDLKey]
	if !ok {
		return "its definition is not in the backup", definition{}
	}
	switch o.Kind {
	case KindTable, KindView, KindMaterializedView, KindDictionary, KindOther:
	default:
		return "its kind " + shortName(o.Kind) + " is not restored", definition{}
	}
	def := readDefinition(db, o.Name, body)
	switch {
	// An object ObjectsFromMetadata did not classify (R28) is never
	// restored; the reason is what its definition holds.
	case o.Kind == KindOther && def.reason != "":
		return def.reason, definition{}
	case o.Kind == KindOther:
		return "the backup lists it as an object Olympos does not classify", definition{}
	case def.kind != "" && def.kind != o.Kind:
		return fmt.Sprintf("its definition is a %s, not the %s the backup lists", kindName(def.kind), kindName(o.Kind)), definition{}
	}
	return def.reason, def
}

func kindName(kind string) string {
	if kind == KindMaterializedView {
		return "materialized view"
	}
	return kind
}

// missingDependency says why def cannot be restored with only the allowed
// objects: its TO table or the first object it reads is not among them.
func missingDependency(def definition, allowed, listed map[objRef]int, defs []definition) string {
	if t := def.target; t != nil {
		k, ok := allowed[*t]
		switch {
		case listed[*t] == 0:
			return "its target " + t.String() + " is not in the backup"
		case !ok:
			return "its target " + t.String() + " is not restored"
		case defs[k].kind != KindTable:
			return "its target " + t.String() + " is not a table"
		}
	}
	for _, r := range def.reads {
		if listed[r] == 0 {
			return "it reads " + r.String() + ", which is not in the backup"
		}
		if _, ok := allowed[r]; !ok {
			return "it reads " + r.String() + ", which is not restored"
		}
	}
	return ""
}

// ---------------------------------------------------------------- definitions

// objRef names an object: its database and name.
type objRef struct{ db, name string }

func (r objRef) String() string { return shortName(r.db) + "." + shortName(r.name) }

// definition is what the allowlist read from one object's statement.
type definition struct {
	kind   string   // what the statement creates; "" when its prefix is not read
	reads  []objRef // the objects it reads, in order
	target *objRef  // a materialized view's TO table
	reason string   // why its own text leaves it out; "" when it does not
}

func (d definition) deps() []objRef {
	if d.target != nil {
		return append([]objRef{*d.target}, d.reads...)
	}
	return d.reads
}

// reader reads one statement (or a query held in one of its strings).
type reader struct {
	toks     []token
	match    []int  // the index of the bracket closing each opening one
	db       string // the object's database: an unqualified name is of it
	embedded bool   // a dictionary source's query: every table must be qualified
	def      *definition
}

func (r *reader) fail(reason string) {
	if r.def.reason == "" {
		r.def.reason = reason
	}
}

func (r *reader) failed() bool      { return r.def.reason != "" }
func (r *reader) at(i int) token    { return tokenAt(r.toks, i) }
func (r *reader) uncertain()        { r.fail(reasonUncertain) }
func (r *reader) closing(i int) int { return r.match[i] }

// newReader lexes text; false when the lexer does not read it, or it holds
// more than one statement, brackets that do not pair or nest too deep.
func newReader(text, db string, def *definition) (*reader, bool) {
	toks, err := lexSQL(text)
	if err != nil {
		return nil, false
	}
	match := make([]int, len(toks))
	var open []int
	for i, t := range toks {
		match[i] = -1
		switch {
		case t.punct(";"):
			return nil, false
		case t.punct("(") || t.punct("["):
			if len(open) == maxNesting {
				return nil, false
			}
			open = append(open, i)
		case t.punct(")") || t.punct("]"):
			if len(open) == 0 {
				return nil, false
			}
			o := open[len(open)-1]
			open = open[:len(open)-1]
			if (toks[o].val == "(") != (t.val == ")") {
				return nil, false
			}
			match[o] = i
		}
	}
	if len(open) != 0 {
		return nil, false
	}
	return &reader{toks: toks, match: match, db: db, def: def}, true
}

// readDefinition reads the statement of db.name.
func readDefinition(db, name string, body []byte) definition {
	var def definition
	if len(body) > maxSchemaEntry || !utf8.Valid(body) {
		def.reason = reasonUncertain
		return def
	}
	r, ok := newReader(string(body), db, &def)
	if !ok {
		def.reason = reasonUncertain
		return def
	}
	i := r.header(name)
	if r.failed() {
		return def
	}
	switch def.kind {
	case KindTable:
		r.table(i)
	case KindView:
		r.view(i)
	case KindMaterializedView:
		r.materializedView(i)
	case KindDictionary:
		r.dictionary(i)
	}
	return def
}

// header reads "CREATE <kind> db.name [UUID '…']" and returns the index
// after it.
func (r *reader) header(name string) int {
	at := r.at
	if !at(0).is("CREATE") {
		r.uncertain()
		return 0
	}
	i := 2
	switch {
	case at(1).is("TABLE"):
		r.def.kind = KindTable
	case at(1).is("VIEW"):
		r.def.kind = KindView
	case at(1).is("MATERIALIZED") && at(2).is("VIEW"):
		r.def.kind, i = KindMaterializedView, 3
	case at(1).is("DICTIONARY"):
		r.def.kind = KindDictionary
	case at(1).is("LIVE") && at(2).is("VIEW"):
		r.fail("a live view is not restored")
	case at(1).is("WINDOW") && at(2).is("VIEW"):
		r.fail("a window view is not restored")
	case at(1).is("OR") && at(2).is("REPLACE"):
		r.fail("CREATE OR REPLACE is not restored")
	case at(1).kind == tokWord:
		r.fail("CREATE " + strings.ToUpper(shortName(at(1).val)) + " is not restored")
	default:
		r.uncertain()
	}
	if r.failed() {
		return 0
	}
	if !at(i).ident() || !at(i+1).punct(".") || !at(i+2).ident() {
		r.uncertain()
		return 0
	}
	if got, want := (objRef{at(i).val, at(i + 2).val}), (objRef{r.db, name}); got != want {
		r.fail("its definition creates " + got.String() + ", not " + want.String())
		return 0
	}
	i += 3
	if at(i).is("UUID") {
		if at(i+1).kind != tokString || !isRunID(at(i+1).val) {
			r.uncertain()
			return 0
		}
		i += 2
	}
	return i
}

// table reads "(columns) ENGINE = Name[(…)] [clauses]" at i.
func (r *reader) table(i int) {
	at := r.at
	if !at(i).punct("(") {
		r.uncertain()
		return
	}
	cols := i
	i = r.closing(i) + 1
	if at(i).is("AS") {
		if at(i+1).ident() && at(i+2).punct("(") {
			r.fail("a table over the table function " + shortName(at(i+1).val))
		} else {
			r.uncertain()
		}
		return
	}
	e := i
	k := r.engine(i)
	if r.failed() {
		return
	}
	if k < len(r.toks) && !(at(k).kind == tokWord && tableClauses[strings.ToUpper(at(k).val)]) {
		r.uncertain()
		return
	}
	// ClickHouse does not keep a CREATE TABLE … AS SELECT's query.
	for j := k; j < len(r.toks); j++ {
		if t := r.toks[j]; t.depth == 0 && t.is("AS") {
			r.uncertain()
			return
		}
	}
	r.storage(e, len(r.toks))
	r.encryptedCodecs(cols, len(r.toks))
	r.noQueries(cols, len(r.toks))
	r.walk(cols, len(r.toks), nil, false)
}

// engine reads "ENGINE = Name[(…)]" at i, refuses an engine not allowed,
// and returns the index after it.
func (r *reader) engine(i int) int {
	at := r.at
	if !at(i).is("ENGINE") || !at(i+1).punct("=") || at(i+2).kind != tokWord {
		r.uncertain()
		return i
	}
	switch name := at(i + 2).val; {
	case name == "GraphiteMergeTree" || name == "ReplicatedGraphiteMergeTree":
		r.fail("the " + name + " engine needs the graphite_rollup configuration on the target server")
		return i
	case !allowedEngines[name]:
		r.fail("the " + shortName(name) + " engine is not on the restore allowlist")
		return i
	}
	i += 3
	if at(i).punct("(") {
		i = r.closing(i) + 1
	}
	return i
}

// storage refuses, among the top-level tokens of toks[lo:hi] (a table's
// settings), a disk or storage policy other than the default: those can be
// outside the server (an S3 disk, a policy with one).
func (r *reader) storage(lo, hi int) {
	for j := lo; j < hi && !r.failed(); j++ {
		t := r.toks[j]
		if t.depth != 0 || !t.ident() || !r.at(j+1).punct("=") {
			continue
		}
		v := r.at(j + 2)
		switch {
		case strings.EqualFold(t.val, "disk"):
			switch {
			case v.ident() && r.at(j+3).punct("("):
				r.fail(reasonInlineDisk)
			case v.kind == tokString && v.val == "default":
			case v.kind == tokString:
				r.fail("its settings put it on the disk " + shortName(v.val))
			default:
				r.uncertain()
			}
		case strings.EqualFold(t.val, "storage_policy"):
			switch {
			case v.kind == tokString && v.val == "default":
			case v.kind == tokString:
				r.fail("its storage policy " + shortName(v.val) + " is not the default")
			default:
				r.uncertain()
			}
		}
	}
}

// encryptedCodecs refuses, in toks[lo:hi], a column CODEC with an
// encryption codec (R49): it encrypts with keys from the server's
// configuration, which the target may not have.
func (r *reader) encryptedCodecs(lo, hi int) {
	for j := lo; j < hi && !r.failed(); j++ {
		if !r.toks[j].is("CODEC") || !r.at(j+1).punct("(") {
			continue
		}
		for k, c := j+2, r.closing(j+1); k < c; k++ {
			if t := r.toks[k]; t.is("AES_128_GCM_SIV") || t.is("AES_256_GCM_SIV") {
				r.fail("its " + strings.ToUpper(t.val) + " codec needs encryption keys on the target server")
				return
			}
		}
	}
}

// noQueries refuses a query in a table's definition (a column's default,
// a TTL's WHERE, …), other than a projection's.
func (r *reader) noQueries(lo, hi int) {
	for j := lo; j < hi; j++ {
		if r.toks[j].punct("(") && r.queryAt(j+1) && !(r.at(j-2).is("PROJECTION") && r.at(j-1).ident()) {
			r.fail("its definition holds a query")
			return
		}
	}
}

// view reads "[(columns)] [DEFINER = …] [SQL SECURITY …] AS <query>" at i.
func (r *reader) view(i int) {
	if r.at(i).punct("(") {
		c := r.closing(i)
		r.walk(i, c+1, nil, false)
		i = c + 1
	}
	r.query(r.security(i))
}

// materializedView reads, at i:
//
//	TO db.t [(columns)] [DEFINER …] AS <query>
//	[TO INNER UUID '…'] (columns) ENGINE = Name … AS <query>
//
// A REFRESH clause is refused: its query runs on a schedule, on the target
// as soon as RESTORE creates it, and a refresh without APPEND replaces its
// table's rows, possibly before RESTORE has written the tables it reads.
func (r *reader) materializedView(i int) {
	at := r.at
	if at(i).is("REFRESH") {
		r.fail(reasonRefresh)
		return
	}
	inner := false
	if at(i).is("TO") {
		if at(i + 1).is("INNER") {
			if !at(i+2).is("UUID") || at(i+3).kind != tokString || !isRunID(at(i+3).val) {
				r.uncertain()
				return
			}
			inner, i = true, i+4
		} else {
			t, j, ok := r.name(i + 1)
			if !ok {
				r.uncertain()
				return
			}
			r.def.target, i = &t, j
		}
	}
	cols, colsEnd := i, i
	if at(i).punct("(") {
		c := r.closing(i)
		r.noQueries(i, c+1)
		r.walk(i, c+1, nil, false)
		i, colsEnd = c+1, c+1
	}
	if !at(i).is("ENGINE") {
		if r.def.target == nil || inner {
			r.uncertain()
			return
		}
		r.query(r.security(i))
		return
	}
	if r.def.target != nil {
		r.uncertain()
		return
	}
	e := i
	k := r.engine(i)
	if r.failed() {
		return
	}
	// RESTORE creates the inner table from the backup's own statement (R48):
	// a Replicated one would keep the source's Keeper path and, on a Keeper
	// the target shares, join the source's replication. Task 15 rewrites the
	// path of a CREATE TABLE only.
	if strings.HasPrefix(at(e+2).val, "Replicated") {
		r.fail("its inner table's Replicated engine keeps the backup's Keeper path")
		return
	}
	if r.encryptedCodecs(cols, colsEnd); r.failed() {
		return
	}
	q := -1
	for j := k; j < len(r.toks); j++ {
		if t := r.toks[j]; t.depth == 0 && (t.is("POPULATE") || t.is("EMPTY")) {
			r.uncertain()
			return
		} else if t.depth == 0 && t.is("AS") {
			q = j
			break
		}
	}
	if q < 0 || k < q && !(at(k).kind == tokWord && (tableClauses[strings.ToUpper(at(k).val)] || at(k).is("DEFINER") || at(k).is("SQL"))) {
		r.uncertain()
		return
	}
	r.storage(e, q)
	r.noQueries(e, q)
	r.walk(e, q, nil, false)
	r.query(q)
}

// security skips "DEFINER = name" and "SQL SECURITY DEFINER|INVOKER|NONE".
func (r *reader) security(i int) int {
	at := r.at
	for {
		switch {
		case at(i).is("DEFINER") && at(i+1).punct("=") && at(i+2).ident():
			i += 3
		case at(i).is("SQL") && at(i+1).is("SECURITY") && (at(i+2).is("DEFINER") || at(i+2).is("INVOKER") || at(i+2).is("NONE")):
			i += 3
		default:
			return i
		}
	}
}

// query reads "AS <query>" at i, to the end of the statement.
func (r *reader) query(i int) {
	if !r.at(i).is("AS") || !r.queryAt(i+1) {
		r.uncertain()
		return
	}
	r.walk(i+1, len(r.toks), nil, true)
}

// dictionary reads "(columns) PRIMARY KEY … SOURCE(…) LAYOUT(…) [LIFETIME(…)]
// [RANGE(…)] [SETTINGS(…)] [COMMENT '…']" at i, in any order.
func (r *reader) dictionary(i int) {
	at := r.at
	if !at(i).punct("(") {
		r.uncertain()
		return
	}
	cols := i
	i = r.closing(i) + 1
	clauses := map[string]int{} // → the index of its "("
	for i < len(r.toks) {
		t := at(i)
		key, open := strings.ToUpper(t.val), -1
		switch {
		case t.is("PRIMARY") && at(i+1).is("KEY"):
			key, i = "PRIMARY KEY", i+2
			for {
				if !at(i).ident() {
					r.uncertain()
					return
				}
				if i++; !at(i).punct(",") {
					break
				}
				i++
			}
		case (t.is("SOURCE") || t.is("LAYOUT") || t.is("LIFETIME") || t.is("RANGE") || t.is("SETTINGS")) && at(i+1).punct("("):
			open, i = i+1, r.closing(i+1)+1
		case t.is("COMMENT") && at(i+1).kind == tokString:
			i += 2
		default:
			r.uncertain()
			return
		}
		if _, dup := clauses[key]; dup {
			r.uncertain()
			return
		}
		clauses[key] = open
	}
	source, ok1 := clauses["SOURCE"]
	layout, ok2 := clauses["LAYOUT"]
	if !ok1 || !ok2 {
		r.uncertain()
		return
	}
	if r.source(source); r.failed() {
		return
	}
	if r.layout(layout); r.failed() {
		return
	}
	// The arguments of LIFETIME, RANGE, SETTINGS and LAYOUT are not walked,
	// deliberately: they hold numbers, column names, format settings and
	// layout sizes, none of which reads data (the layout's name is checked
	// above). What a dictionary reads is its source and its columns'
	// expressions.
	r.walk(cols, r.closing(cols)+1, nil, false)
}

// wrapped reads "(Name(…))" at toks[open], the brackets of SOURCE or
// LAYOUT, and returns Name and the index of its own "(". ok is false when
// the brackets hold anything else.
func (r *reader) wrapped(open int) (name string, args int, ok bool) {
	end := r.closing(open)
	n := r.at(open + 1)
	if n.kind != tokWord || !r.at(open+2).punct("(") || r.closing(open+2) != end-1 {
		return "", 0, false
	}
	return n.val, open + 2, true
}

// source reads a dictionary's SOURCE(…): only CLICKHOUSE, without HOST or
// PORT, with a TABLE (and DB) or a QUERY.
func (r *reader) source(open int) {
	name, args, ok := r.wrapped(open)
	if !ok {
		r.uncertain()
		return
	}
	if !strings.EqualFold(name, "CLICKHOUSE") {
		r.fail("its source is " + strings.ToUpper(shortName(name)) + ", not a local ClickHouse table")
		return
	}
	kv := map[string]token{}
	end := r.closing(args)
	for j := args + 1; j < end; j += 2 {
		k, v := r.at(j), r.at(j+1)
		if k.kind != tokWord || j+1 >= end || !(v.kind == tokString || v.kind == tokNumber || v.ident()) {
			r.uncertain()
			return
		}
		key := strings.ToUpper(k.val)
		if _, dup := kv[key]; dup {
			r.uncertain()
			return
		}
		kv[key] = v
		switch {
		case key == "HOST":
			r.fail("its ClickHouse source names a host")
			return
		case key == "PORT":
			r.fail("its ClickHouse source names a port")
			return
		case !clickhouseSourceKeys[key]:
			r.fail("its ClickHouse source has " + shortName(key) + ", which Olympos does not restore")
			return
		}
	}
	table, hasTable := kv["TABLE"]
	query, hasQuery := kv["QUERY"]
	db, hasDB := kv["DB"]
	switch {
	case hasTable == hasQuery, hasQuery && hasDB:
		r.uncertain()
		return
	case hasTable:
		if !(table.kind == tokString || table.ident()) || hasDB && !(db.kind == tokString || db.ident()) {
			r.uncertain()
			return
		}
		t := objRef{r.db, table.val}
		if hasDB {
			t.db = db.val
		}
		r.def.reads = append(r.def.reads, t)
	default:
		r.sourceSQL(query, true)
	}
	if w, ok := kv["WHERE"]; ok {
		r.sourceSQL(w, false)
	}
	if q, ok := kv["INVALIDATE_QUERY"]; ok {
		r.sourceSQL(q, true)
	}
}

// sourceSQL reads the SQL a dictionary source holds in a string: a query or
// a condition.
func (r *reader) sourceSQL(v token, query bool) {
	if r.failed() {
		return
	}
	if v.kind != tokString {
		r.uncertain()
		return
	}
	sub, ok := newReader(v.val, r.db, r.def)
	if !ok || len(sub.toks) == 0 || query && !sub.queryAt(0) {
		r.uncertain()
		return
	}
	sub.embedded = true
	sub.walk(0, len(sub.toks), nil, query)
}

// layout reads a dictionary's LAYOUT(Name(…)).
func (r *reader) layout(open int) {
	name, _, ok := r.wrapped(open)
	switch {
	case !ok:
		r.uncertain()
	case !allowedLayouts[strings.ToUpper(name)]:
		r.fail("its layout " + strings.ToUpper(shortName(name)) + " is not on the restore allowlist")
	}
}

// ---------------------------------------------------------------- queries

// queryAt reports whether toks[i] starts a query: SELECT, WITH, or a
// parenthesized query.
func (r *reader) queryAt(i int) bool {
	t := r.at(i)
	return t.is("SELECT") || t.is("WITH") || t.punct("(") && r.queryAt(i+1)
}

// name reads "db.name" or "name" at i, and returns the index after it.
func (r *reader) name(i int) (objRef, int, bool) {
	if !r.at(i).ident() {
		return objRef{}, i, false
	}
	if r.at(i + 1).punct(".") {
		if !r.at(i + 2).ident() {
			return objRef{}, i, false
		}
		return objRef{r.at(i).val, r.at(i + 2).val}, i + 3, true
	}
	return objRef{r.db, r.at(i).val}, i + 1, true
}

// read records that the definition reads o, unless o is an unqualified
// CTE's name.
func (r *reader) read(o objRef, unqualified bool, ctes map[string]bool) {
	switch {
	case unqualified && ctes[o.name]:
	case unqualified && r.embedded:
		r.uncertain()
	default:
		r.def.reads = append(r.def.reads, o)
	}
}

// walk reads toks[lo:hi], one bracket level, and the levels it holds: what
// it reads and the functions it calls. query: toks[lo:hi] is a query,
// "[WITH …] SELECT … [UNION|EXCEPT|INTERSECT …]"; outer are the CTE names
// visible to it.
func (r *reader) walk(lo, hi int, outer map[string]bool, query bool) {
	ctes := outer
	start := query
	from, source, arrayJoin := false, false, false
	for i := lo; i < hi && !r.failed(); i++ {
		t := r.toks[i]
		if start {
			// A SELECT of this level: its WITH clause names CTEs for it
			// only, not for another branch of a union.
			start, ctes = false, outer
			if t.is("WITH") {
				if i, ctes = r.with(i, hi, outer); r.failed() {
					return
				}
				t = r.toks[i]
			}
		}
		if source {
			source = false
			i = r.from(i, ctes)
			continue
		}
		switch {
		case t.punct("(") || t.punct("["):
			c := r.closing(i)
			r.walk(i+1, c, ctes, t.val == "(" && r.queryAt(i+1))
			i = c
		case t.is("FROM"):
			from, source, arrayJoin = true, true, false
		case t.is("JOIN"):
			// ARRAY JOIN is followed by arrays, not by a table.
			arrayJoin = r.at(i - 1).is("ARRAY")
			source = !arrayJoin
		case t.punct(","):
			source = from && !arrayJoin
		case t.is("IN"):
			i = r.inTable(i, ctes)
		case t.is("UNION") || t.is("EXCEPT") || t.is("INTERSECT"):
			from, arrayJoin = false, false
			k := i + 1
			for r.at(k).is("ALL") || r.at(k).is("DISTINCT") {
				k++
			}
			if query && k < hi && (r.at(k).is("SELECT") || r.at(k).is("WITH")) {
				start, i = true, k-1
			}
		case t.kind == tokWord && fromEnds[strings.ToUpper(t.val)]:
			from, arrayJoin = false, false
		case t.is("APPLY"):
			// A column transformer, "* APPLY(f)" or "* APPLY f", calls f
			// by name (a lambda's parameter is not a function).
			j := i + 1
			if r.at(j).punct("(") {
				j++
			}
			if r.at(j).ident() && !r.at(j+1).punct("(") && !r.at(j+1).punct("->") {
				r.function(j, false)
			}
		case t.ident() && r.at(i+1).punct("("):
			r.function(i, true)
		}
	}
	if source {
		r.uncertain() // FROM or JOIN with nothing after it
	}
}

// with reads the WITH clause at toks[i] and returns the index of the SELECT
// after it, with the CTE names it adds to outer. A CTE sees the CTEs before
// it, not itself.
func (r *reader) with(i, hi int, outer map[string]bool) (int, map[string]bool) {
	if r.at(i + 1).is("RECURSIVE") {
		r.uncertain()
		return i, outer
	}
	ctes := maps.Clone(outer)
	if ctes == nil {
		ctes = map[string]bool{}
	}
	item := i + 1
	for j := i + 1; j < hi; j++ {
		t := r.toks[j]
		switch {
		case t.punct("(") || t.punct("["):
			j = r.closing(j)
		case t.punct(",") || t.is("SELECT"):
			if r.withItem(item, j, ctes); r.failed() || t.is("SELECT") {
				return j, ctes
			}
			item = j + 1
		}
	}
	r.uncertain()
	return i, ctes
}

// withItem reads one element of a WITH clause, toks[a:b]: "name AS
// (<query>)", a CTE, or "<expression> AS alias".
func (r *reader) withItem(a, b int, ctes map[string]bool) {
	switch {
	case a >= b:
		r.uncertain()
	case b-a >= 4 && r.toks[a].ident() && r.toks[a+1].is("AS") && r.toks[a+2].punct("(") &&
		r.closing(a+2) == b-1 && r.queryAt(a+3):
		r.walk(a+3, b-1, ctes, true)
		ctes[r.toks[a].val] = true
	default:
		r.walk(a, b, ctes, false)
	}
}

// from reads one FROM or JOIN source at toks[i] and returns the index of
// its last token: a table, a subquery, or a table function (refused).
func (r *reader) from(i int, ctes map[string]bool) int {
	if r.toks[i].punct("(") {
		c := r.closing(i)
		if !r.queryAt(i + 1) {
			r.uncertain()
			return c
		}
		r.walk(i+1, c, ctes, true)
		return c
	}
	o, j, ok := r.name(i)
	if !ok {
		r.uncertain()
		return i
	}
	if r.at(j).punct("(") {
		r.fail("it reads the table function " + shortName(r.at(j-1).val))
		return j
	}
	r.read(o, j-i == 1, ctes)
	return j - 1
}

// inTable reads what follows IN at toks[i] and returns the index of its
// last token read: a table ("IN db.t"), or "IN f(…)", where f is a table
// function unless it is tuple or array. A bracket (a tuple or a subquery)
// is left to walk.
func (r *reader) inTable(i int, ctes map[string]bool) int {
	o, j, ok := r.name(i + 1)
	switch {
	case !ok:
		return i
	case r.at(j).punct("("):
		if f := strings.ToLower(r.at(j - 1).val); j-i == 2 && (f == "tuple" || f == "array") {
			return i
		}
		r.fail("it reads the table function " + shortName(r.at(j-1).val))
		return j
	}
	r.read(o, j-i == 2, ctes)
	return j - 1
}

// function checks the function at toks[i], called with its arguments or,
// after APPLY, by name: one that reads outside the server is refused; a
// dictGet* or joinGet reads the object its first argument names.
func (r *reader) function(i int, called bool) {
	if r.at(i - 1).is("PROJECTION") { // a projection's name, not a call
		return
	}
	name := strings.ToLower(r.toks[i].val)
	switch {
	case name == "disk":
		r.fail(reasonInlineDisk)
	case outsideCalls[name]:
		r.fail("it calls " + shortName(r.toks[i].val) + ", which reads outside the restored set")
	case strings.HasPrefix(name, "dictget") || strings.HasPrefix(name, "dicthas") || strings.HasPrefix(name, "dictisin") ||
		name == "joinget" || name == "joingetornull":
		if !called {
			r.fail("it calls " + shortName(r.toks[i].val) + " on a name Olympos cannot read")
			return
		}
		r.namedObject(i)
	}
}

// namedObject reads the object a dictGet* or joinGet at toks[i] names in
// its first argument: 'db.name', 'name', db.name or name.
func (r *reader) namedObject(i int) {
	args := splitArgs(r.toks, i+1, r.closing(i+1))
	bad := func() { r.fail("it calls " + shortName(r.toks[i].val) + " on a name Olympos cannot read") }
	if len(args) == 0 {
		bad()
		return
	}
	switch a := args[0]; {
	case len(a) == 1 && a[0].kind == tokString:
		db, name, qualified := strings.Cut(a[0].val, ".")
		if !qualified {
			db, name = r.db, a[0].val
		}
		if db == "" || name == "" || strings.Contains(name, ".") {
			bad()
			return
		}
		r.read(objRef{db, name}, !qualified, nil)
	case len(a) == 1 && a[0].ident():
		r.read(objRef{r.db, a[0].val}, true, nil)
	case len(a) == 3 && a[0].ident() && a[1].punct(".") && a[2].ident():
		r.read(objRef{a[0].val, a[2].val}, false, nil)
	default:
		bad()
	}
}
