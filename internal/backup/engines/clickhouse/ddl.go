package clickhouse

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The restore runs DDL from the archive's schema entries only (never from
// table data), one statement at a time, and only after it was checked
// here: exactly one CREATE of the kind the manifest records, for the
// database and name the manifest records, without OR REPLACE, IF NOT
// EXISTS or ON CLUSTER. Objects whose definition reaches outside the
// restored databases (external engines and table functions, dictionaries
// with other sources, materialized views writing elsewhere) are not
// created; they are reported by name, never with their DDL, which can
// carry the source system's credentials.

// ---------------------------------------------------------------- lexer

type tokKind int

const (
	tokWord   tokKind = iota // bare word: keyword or identifier
	tokQIdent                // `quoted` or "quoted" identifier
	tokString                // 'literal' or $heredoc$
	tokNumber
	tokPunct
)

type token struct {
	kind       tokKind
	val        string // decoded value (identifiers, strings), else the text
	start, end int    // byte offsets in the statement
	depth      int    // parenthesis depth at the token (an opening one is outside)
}

func (t token) is(word string) bool { return t.kind == tokWord && strings.EqualFold(t.val, word) }
func (t token) punct(p string) bool { return t.kind == tokPunct && t.val == p }
func (t token) ident() bool         { return t.kind == tokWord || t.kind == tokQIdent }

// lexSQL splits ClickHouse SQL into tokens, dropping whitespace and
// comments (--, # and #! to the end of the line, nested /* */). It fails on
// unterminated literals and on bytes ClickHouse would not accept, so text it
// misreads is refused rather than run.
func lexSQL(s string) ([]token, error) {
	var out []token
	depth := 0
	add := func(k tokKind, val string, start, end int) {
		d := depth
		if k == tokPunct {
			switch val {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
				d = depth
			}
		}
		out = append(out, token{kind: k, val: val, start: start, end: end, depth: d})
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-', c == '#' && i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '!'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			n, j := 1, i+2
			for n > 0 {
				switch {
				case j+1 >= len(s):
					return nil, errors.New("unterminated comment")
				case s[j] == '/' && s[j+1] == '*':
					n, j = n+1, j+2
				case s[j] == '*' && s[j+1] == '/':
					n, j = n-1, j+2
				default:
					j++
				}
			}
			i = j
		case c == '\'' || c == '`' || c == '"':
			val, j, err := lexQuoted(s, i)
			if err != nil {
				return nil, err
			}
			k := tokQIdent
			if c == '\'' {
				k = tokString
			}
			add(k, val, i, j)
			i = j
		case c == '$':
			j := i + 1
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			if j >= len(s) || s[j] != '$' {
				return nil, fmt.Errorf("unexpected $ at byte %d", i)
			}
			tag := s[i : j+1]
			end := strings.Index(s[j+1:], tag)
			if end < 0 {
				return nil, errors.New("unterminated heredoc literal")
			}
			add(tokString, s[j+1:j+1+end], i, j+1+end+len(tag))
			i = j + 1 + end + len(tag)
		case c >= '0' && c <= '9':
			j := i + 1
			for j < len(s) && (isWordByte(s[j]) || s[j] == '.' ||
				((s[j] == '+' || s[j] == '-') && strings.ContainsRune("eEpP", rune(s[j-1])))) {
				j++
			}
			add(tokNumber, s[i:j], i, j)
			i = j
		case isWordByte(c):
			j := i + 1
			for j < len(s) && (isWordByte(s[j]) || s[j] == '$') {
				j++
			}
			add(tokWord, s[i:j], i, j)
			i = j
		case strings.IndexByte("()[]{},.;:=<>!+-*/%|?@^~&", c) >= 0:
			add(tokPunct, s[i:i+1], i, i+1)
			i++
		default:
			return nil, fmt.Errorf("unexpected character %q at byte %d", c, i)
		}
		if depth < 0 {
			return nil, errors.New("unbalanced parentheses")
		}
	}
	if depth != 0 {
		return nil, errors.New("unbalanced parentheses")
	}
	return out, nil
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}

// lexQuoted reads a quoted literal or identifier starting at s[i]: the quote
// doubled or backslash-escaped stands for itself.
func lexQuoted(s string, i int) (string, int, error) {
	q := s[i]
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch {
		case c == '\\':
			if j+1 >= len(s) {
				return "", 0, errors.New("unterminated literal")
			}
			j++
			switch e := s[j]; e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0':
				b.WriteByte(0)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'a':
				b.WriteByte('\a')
			case 'v':
				b.WriteByte('\v')
			case 'x':
				if j+2 < len(s) {
					if v, err := strconv.ParseUint(s[j+1:j+3], 16, 8); err == nil {
						b.WriteByte(byte(v))
						j += 2
						continue
					}
				}
				b.WriteByte(e)
			default:
				b.WriteByte(e)
			}
		case c == q:
			if j+1 < len(s) && s[j+1] == q {
				b.WriteByte(q)
				j++
				continue
			}
			return b.String(), j + 1, nil
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, errors.New("unterminated literal")
}

// ---------------------------------------------------------------- CREATE

// Statement kinds checkCreate expects (besides the manifest's kinds).
const kindDatabase = "database"

// createStmt is a checked CREATE statement.
type createStmt struct {
	src   string
	toks  []token // without a trailing ";"
	kind  string  // a manifest kind, or kindDatabase
	db    string  // database of the object (the database itself for kindDatabase)
	name  string
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

// checkCreate checks that stmt is exactly one CREATE of kind for db.name
// (for kindDatabase: CREATE DATABASE db) and returns it parsed. A UUID
// clause after the name is dropped (the target assigns its own).
func checkCreate(stmt, kind, db, name string) (*createStmt, error) {
	toks, err := lexSQL(stmt)
	if err != nil {
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
	st := &createStmt{src: stmt, toks: toks}
	at := func(i int) token {
		if i < len(toks) {
			return toks[i]
		}
		return token{kind: tokPunct, val: ""}
	}
	if !at(0).is("CREATE") {
		return nil, errors.New("the schema entry is not a CREATE statement")
	}
	i := 1
	switch {
	case at(i).is("OR"):
		return nil, errors.New("CREATE OR REPLACE is refused: a restore never replaces anything")
	case at(i).is("TEMPORARY"):
		return nil, errors.New("CREATE TEMPORARY is refused")
	}
	var got string
	switch {
	case at(i).is("TABLE"):
		got, i = KindTable, i+1
	case at(i).is("VIEW"):
		got, i = KindView, i+1
	case at(i).is("MATERIALIZED") && at(i+1).is("VIEW"):
		got, i = KindMaterializedView, i+2
	case at(i).is("DICTIONARY"):
		got, i = KindDictionary, i+1
	case at(i).is("DATABASE"):
		got, i = kindDatabase, i+1
	case (at(i).is("LIVE") || at(i).is("WINDOW")) && at(i+1).is("VIEW"):
		got, i = KindOther, i+2
	default:
		return nil, errors.New("the schema entry creates an object of an unknown kind")
	}
	want := kind
	if want == KindMVInner {
		want = KindTable
	}
	if got != want {
		return nil, fmt.Errorf("the schema entry creates a %s, not a %s", kindWord(got), kindWord(want))
	}
	st.kind = kind
	if at(i).is("IF") {
		return nil, errors.New("CREATE … IF NOT EXISTS is refused")
	}
	if !at(i).ident() {
		return nil, errors.New("the schema entry names no object")
	}
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
		st.db, st.name = at(i).val, at(i+2).val
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
	if kind == KindMaterializedView {
		if j := st.find(i, "TO"); j >= 0 && at(j+1).is("INNER") {
			k := j + 2
			if at(k).is("UUID") && at(k+1).kind == tokString {
				k += 2
			}
			st.drop(j, k-1)
		}
	}
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

// sql is the statement to run: the edits applied, without a trailing ";"
// or comments after the last token.
func (s *createStmt) sql() string {
	if len(s.toks) == 0 {
		return ""
	}
	s.sortedEdits()
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

// find returns the index of the first depth-0 word w at or after i, -1 if
// none; it stops at the depth-0 AS that starts a view's query.
func (s *createStmt) find(i int, w string) int {
	for ; i < len(s.toks); i++ {
		t := s.toks[i]
		if t.depth != 0 {
			continue
		}
		if t.is(w) {
			return i
		}
		if t.is("AS") && s.kind != kindDatabase && s.kind != KindTable && s.kind != KindMVInner {
			return -1
		}
	}
	return -1
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
		if t.depth == 0 && t.is("AS") && s.kind == KindMaterializedView {
			return -1
		}
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

// engineArgs are the ENGINE clause's arguments (nil without parentheses).
func (s *createStmt) engineArgs() [][2]int {
	i := s.engine()
	if i < 0 || i+1 >= len(s.toks) || !s.toks[i+1].punct("(") {
		return nil
	}
	return s.args(i + 1)
}

// selectStart is the index after the depth-0 AS of a view's query (-1 if
// none).
func (s *createStmt) selectStart() int {
	for i := s.body; i < len(s.toks); i++ {
		if s.toks[i].depth == 0 && s.toks[i].is("AS") {
			return i + 1
		}
	}
	return -1
}

// mvTarget is a materialized view's "TO [db.]table" (ok false without TO).
func (s *createStmt) mvTarget(db string) (string, string, bool) {
	j := s.find(s.body, "TO")
	if j < 0 || j+1 >= len(s.toks) || !s.toks[j+1].ident() {
		return "", "", false
	}
	if j+3 < len(s.toks) && s.toks[j+2].punct(".") && s.toks[j+3].ident() {
		return s.toks[j+1].val, s.toks[j+3].val, true
	}
	return db, s.toks[j+1].val, true
}

// sources are the "db.table" names after FROM and JOIN in a view's query
// (unqualified names are in db). Table functions and subqueries are not
// listed.
func (s *createStmt) sources(db string) []string {
	var out []string
	from := s.selectStart()
	if from < 0 {
		return nil
	}
	for i := from; i+1 < len(s.toks); i++ {
		t := s.toks[i]
		if !(t.is("FROM") || (t.is("JOIN") && !(i > 0 && s.toks[i-1].is("ARRAY")))) {
			continue
		}
		n := s.toks[i+1]
		if !n.ident() || (i+2 < len(s.toks) && s.toks[i+2].punct("(")) {
			continue
		}
		if i+3 < len(s.toks) && s.toks[i+2].punct(".") && s.toks[i+3].ident() {
			out = append(out, n.val+"."+s.toks[i+3].val)
			continue
		}
		out = append(out, db+"."+n.val)
	}
	return out
}

// hasHidden: the statement holds a secret ClickHouse masked in SHOW CREATE.
func (s *createStmt) hasHidden() bool {
	for _, t := range s.toks {
		if t.kind == tokString && t.val == "[HIDDEN]" {
			return true
		}
	}
	return false
}

// externalFunctions are table functions (and file()) that reach outside the
// server or its databases; a definition calling one is not created.
var externalFunctions = map[string]bool{
	"url": true, "urlcluster": true, "s3": true, "s3cluster": true, "gcs": true, "oss": true, "cosn": true,
	"azureblobstorage": true, "azureblobstoragecluster": true, "hdfs": true, "hdfscluster": true,
	"remote": true, "remotesecure": true, "cluster": true, "clusterallreplicas": true,
	"mysql": true, "postgresql": true, "mongodb": true, "redis": true, "sqlite": true, "jdbc": true, "odbc": true,
	"iceberg": true, "icebergs3": true, "icebergazure": true, "iceberghdfs": true, "iceberglocal": true,
	"icebergcluster": true, "icebergs3cluster": true, "icebergazurecluster": true, "iceberghdfscluster": true,
	"deltalake": true, "deltalakecluster": true, "deltalakelocal": true, "deltalakeazure": true,
	"hudi": true, "hudicluster": true, "hive": true, "file": true, "filecluster": true,
	"executable": true, "ytsaurus": true, "arrowflight": true, "paimon": true, "kafka": true, "disk": true,
}

// externalCall is the first external function the statement calls ("").
func (s *createStmt) externalCall() string {
	for i := 0; i+1 < len(s.toks); i++ {
		t := s.toks[i]
		if t.kind == tokWord && s.toks[i+1].punct("(") && externalFunctions[strings.ToLower(t.val)] {
			return t.val
		}
	}
	return ""
}

// ---------------------------------------------------------------- engines

// localEngines are created without data entries of their own (or, for
// Merge, Buffer and Dictionary, after checking the database they use).
var localEngines = map[string]bool{
	"Null": true, "Set": true, "Join": true, "Merge": true, "Buffer": true, "Dictionary": true, "GenerateRandom": true,
}

// externalEngines read from, write to or follow a system outside the
// server (the skip reason names it as such).
var externalEngines = map[string]bool{
	"Kafka": true, "S3": true, "S3Queue": true, "AzureBlobStorage": true, "AzureQueue": true, "URL": true,
	"MySQL": true, "PostgreSQL": true, "MongoDB": true, "JDBC": true, "ODBC": true, "HDFS": true,
	"RabbitMQ": true, "NATS": true, "Redis": true, "Hive": true, "DeltaLake": true, "DeltaLakeS3": true,
	"DeltaLakeAzure": true, "DeltaLakeLocal": true, "Iceberg": true, "IcebergS3": true, "IcebergAzure": true,
	"IcebergHDFS": true, "IcebergLocal": true, "Hudi": true, "File": true, "FileLog": true, "SQLite": true,
	"MaterializedPostgreSQL": true, "MaterializedMySQL": true, "Executable": true, "ExecutablePool": true,
	"COSN": true, "OSS": true, "GCS": true, "YTsaurus": true, "ArrowFlight": true, "Paimon": true,
}

func engineSkipReason(engine string) string {
	switch {
	case engine == "Distributed":
		return "engine Distributed points at a cluster; not created (create it by hand)"
	case externalEngines[engine]:
		return "engine " + engine + " reads from or writes to a system outside the target; not created (create it by hand)"
	}
	return "engine " + engine + " is not restored by Olympos; not created (create it by hand)"
}

// restorableEngine: the restore creates a table of this engine.
func restorableEngine(engine string) bool {
	return isMergeTree(engine) || dataEngines[engine] || localEngines[engine]
}

// argDatabase is the database an engine argument names: a bare or quoted
// identifier, a string, or currentDatabase() (ok false for anything else,
// such as REGEXP(...)).
func (s *createStmt) argDatabase(a [2]int) (string, bool) {
	ts := s.toks[a[0]:a[1]]
	switch {
	case len(ts) == 1 && (ts[0].ident() || ts[0].kind == tokString):
		return ts[0].val, true
	case len(ts) == 3 && ts[0].is("currentDatabase") && ts[1].punct("(") && ts[2].punct(")"):
		return s.db, true
	}
	return "", false
}

// ---------------------------------------------------------------- classify

// classification is what the restore does with one object.
type classification struct {
	st     *createStmt
	create bool
	reason string // why it is not created (no DDL in it)
	hidden bool   // its DDL holds a secret masked by the backup ([HIDDEN])
}

// classify checks ddl (the object's schema entry) against the manifest's
// table t of database db and decides whether it is created. restored are
// the databases this restore creates. An error means the schema entry is
// not what the manifest says (the restore is refused).
func classify(db string, t Table, ddl string, restored map[string]bool) (classification, error) {
	st, err := checkCreate(ddl, t.Kind, db, t.Name)
	if err != nil {
		return classification{}, err
	}
	c := classification{st: st, hidden: st.hasHidden()}
	skip := func(reason string) (classification, error) {
		c.create, c.reason = false, reason
		return c, nil
	}
	engine := st.engineName()
	switch t.Kind {
	case KindTable, KindMVInner:
		if st.selectStart() >= 0 || engine == "" {
			return skip("engine " + t.Engine + " is defined over a table function; not created (create it by hand)")
		}
		if engine != t.Engine {
			return classification{}, fmt.Errorf("the schema entry has engine %s, the backup recorded %s", engine, t.Engine)
		}
		if !restorableEngine(engine) {
			return skip(engineSkipReason(engine))
		}
		if f := st.externalCall(); f != "" {
			return skip("its definition calls " + f + "(), which reaches outside the target; not created (create it by hand)")
		}
		args := st.engineArgs()
		switch engine {
		case "Merge", "Buffer":
			if len(args) == 0 {
				return skip("engine " + engine + " without arguments; not created")
			}
			other, ok := st.argDatabase(args[0])
			switch {
			case !ok:
				return skip("engine " + engine + " reads databases matching a pattern; not created (create it by hand)")
			case !restored[other]:
				return skip("engine " + engine + " uses database " + other + ", which is not restored; not created (create it by hand)")
			}
		case "Dictionary":
			if len(args) == 1 {
				ts := st.toks[args[0][0]:args[0][1]]
				other := db
				if len(ts) == 3 && ts[1].punct(".") {
					other = ts[0].val
				} else if len(ts) == 1 && ts[0].kind == tokString {
					if d, _, ok := strings.Cut(ts[0].val, "."); ok {
						other = d
					}
				}
				if !restored[other] {
					return skip("engine Dictionary uses database " + other + ", which is not restored; not created (create it by hand)")
				}
			}
		}
	case KindView:
		if f := st.externalCall(); f != "" {
			return skip("its query calls " + f + "(), which reaches outside the target; not created (create it by hand)")
		}
	case KindMaterializedView:
		if engine != "" && !restorableEngine(engine) {
			return skip("its inner table has " + engineSkipReason(engine))
		}
		if f := st.externalCall(); f != "" {
			return skip("its definition calls " + f + "(), which reaches outside the target; not created (create it by hand)")
		}
		if tdb, tname, ok := st.mvTarget(db); ok && !restored[tdb] {
			return skip("it writes into " + tdb + "." + tname + ", which is not restored; not created (create it by hand)")
		}
		for _, src := range st.sources(db) {
			if d, _, _ := strings.Cut(src, "."); !restored[d] {
				return skip("it reads from " + src + ", which is not restored; not created (create it by hand)")
			}
		}
	case KindDictionary:
		if why := st.dictionarySource(restored); why != "" {
			return skip(why)
		}
		if f := st.externalCall(); f != "" {
			return skip("its definition calls " + f + "(), which reaches outside the target; not created (create it by hand)")
		}
	default:
		return skip("a " + t.Engine + " is not restored by Olympos; not created (create it by hand)")
	}
	c.create = true
	return c, nil
}

// dictionarySource is why a dictionary's SOURCE is not restored ("": it is
// a ClickHouse table in a restored database on the target itself).
func (s *createStmt) dictionarySource(restored map[string]bool) string {
	i := -1
	for j := s.body; j+3 < len(s.toks); j++ {
		if s.toks[j].depth == 0 && s.toks[j].is("SOURCE") && s.toks[j+1].punct("(") {
			i = j + 2
			break
		}
	}
	if i < 0 || !s.toks[i].ident() || !s.toks[i+1].punct("(") {
		return "its source cannot be read; not created (create it by hand)"
	}
	typ := strings.ToUpper(s.toks[i].val)
	if typ != "CLICKHOUSE" {
		return "its source is " + typ + ", outside the target; not created (create it by hand)"
	}
	kv := map[string]string{}
	end := s.close(i + 1)
	for j := i + 2; j < end; {
		k := s.toks[j]
		if k.kind != tokWord || j+1 >= end {
			return "its ClickHouse source cannot be read; not created (create it by hand)"
		}
		v := s.toks[j+1]
		if v.punct("(") || (j+2 < end && s.toks[j+2].punct("(")) {
			return "its ClickHouse source uses " + strings.ToUpper(k.val) + "(…), which Olympos does not check; not created (create it by hand)"
		}
		key := strings.ToUpper(k.val)
		switch key {
		case "HOST", "PORT", "USER", "PASSWORD", "DB", "TABLE", "WHERE", "INVALIDATE_QUERY", "SECURE", "UPDATE_FIELD", "UPDATE_LAG":
		default:
			return "its ClickHouse source uses " + key + ", which Olympos does not check; not created (create it by hand)"
		}
		kv[key] = v.val
		j += 2
		if j < end && s.toks[j].punct(",") {
			j++
		}
	}
	if h, ok := kv["HOST"]; ok {
		switch strings.ToLower(h) {
		case "localhost", "127.0.0.1", "::1":
		default:
			return "its ClickHouse source is on another host; not created (create it by hand)"
		}
	}
	switch db, ok := kv["DB"]; {
	case !ok || kv["TABLE"] == "":
		return "its ClickHouse source names no database and table; not created (create it by hand)"
	case !restored[db]:
		return "its ClickHouse source is in database " + db + ", which is not restored; not created (create it by hand)"
	}
	return ""
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

// rewriteKeeperPaths puts the Keeper path of a Replicated*MergeTree or
// KeeperMap engine (a table's or a materialized view's inner table's)
// under /olympos-restore/<request id>/, so the restored table never shares
// Keeper state with the source's when Keeper is shared. Without a path in
// the statement, one is set (with the default replica name). It returns
// whether anything was rewritten.
func (s *createStmt) rewriteKeeperPaths(requestID string) bool {
	i := s.engine()
	if i < 0 {
		return false
	}
	engine := s.toks[i].val
	replicated := strings.HasPrefix(engine, "Replicated") && isMergeTree(engine)
	if !replicated && engine != "KeeperMap" {
		return false
	}
	hasParen := i+1 < len(s.toks) && s.toks[i+1].punct("(")
	var args [][2]int
	if hasParen {
		args = s.args(i + 1)
	}
	str := func(a [2]int) bool { return a[1]-a[0] == 1 && s.toks[a[0]].kind == tokString }
	if engine == "KeeperMap" {
		if len(args) == 0 || !str(args[0]) {
			return false
		}
		t := s.toks[args[0][0]]
		s.edits = append(s.edits, edit{start: t.start, end: t.end, repl: quoteString(restorePath(t.val, requestID))})
		return true
	}
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
// (or KeeperMap) CREATE statement to /olympos-restore/<request id>/…; ok
// is false (and ddl unchanged) for any other statement or one that cannot
// be read.
func rewriteReplicatedPath(ddl, requestID string) (string, bool) {
	toks, err := lexSQL(ddl)
	if err != nil || len(toks) < 3 || !toks[0].is("CREATE") {
		return ddl, false
	}
	kind := KindTable
	if toks[1].is("MATERIALIZED") {
		kind = KindMaterializedView
	}
	st := &createStmt{src: ddl, toks: toks, kind: kind}
	if n := len(st.toks); st.toks[n-1].punct(";") {
		st.toks = st.toks[:n-1]
	}
	// The name: CREATE TABLE|MATERIALIZED VIEW db.name.
	st.body = 2
	if kind == KindMaterializedView {
		st.body = 3
	}
	if !st.rewriteKeeperPaths(requestID) {
		return ddl, false
	}
	return st.sql(), true
}

// sortedEdits keeps edits in statement order (they are applied front to
// back).
func (s *createStmt) sortedEdits() {
	for i := 1; i < len(s.edits); i++ {
		for j := i; j > 0 && s.edits[j].start < s.edits[j-1].start; j-- {
			s.edits[j], s.edits[j-1] = s.edits[j-1], s.edits[j]
		}
	}
}
