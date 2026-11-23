package clickhouse

import (
	"errors"
	"fmt"
	"regexp"
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
		return nil, err
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

// pureFunctions may be called in a restored table's expressions
// (DEFAULT, MATERIALIZED, ALIAS, TTL, PARTITION BY, ORDER BY, INDEX, ...):
// built-in scalar functions that read nothing but their arguments, by
// their exact names (a target's user-defined function cannot take a
// built-in's name, so it is never called). ciFunctions are built-ins that
// ClickHouse also accepts in any case.
var pureFunctions = words(`
	plus minus multiply divide intDiv intDivOrZero modulo moduloOrZero negate abs gcd lcm
	equals notEquals less greater lessOrEquals greaterOrEquals and or not xor
	if multiIf coalesce ifNull nullIf assumeNotNull toNullable isNull isNotNull isNaN isFinite isInfinite ifNotFinite
	CAST accurateCast accurateCastOrNull accurateCastOrDefault
	toString toFixedString toInt8 toInt16 toInt32 toInt64 toInt128 toInt256 toUInt8 toUInt16 toUInt32 toUInt64
	toUInt128 toUInt256 toFloat32 toFloat64 toDecimal32 toDecimal64 toDecimal128 toDecimal256 toDate toDate32
	toDateTime toDateTime64 toUUID toIPv4 toIPv6 toBool
	toInt32OrZero toInt64OrZero toUInt32OrZero toUInt64OrZero toFloat64OrZero toDateOrZero toDateTimeOrZero toUUIDOrZero
	toInt32OrNull toInt64OrNull toUInt32OrNull toUInt64OrNull toFloat64OrNull toDateOrNull toDateTimeOrNull toUUIDOrNull
	reinterpretAsUInt64 reinterpretAsInt64 reinterpretAsString
	now now64 today yesterday toYear toQuarter toMonth toDayOfYear toDayOfMonth toDayOfWeek toHour toMinute toSecond
	toUnixTimestamp toStartOfYear toStartOfQuarter toStartOfMonth toStartOfWeek toMonday toStartOfDay toStartOfHour
	toStartOfMinute toStartOfSecond toStartOfFiveMinutes toStartOfTenMinutes toStartOfFifteenMinutes toStartOfInterval
	toYYYYMM toYYYYMMDD toYYYYMMDDhhmmss toISOWeek toISOYear toWeek toYearWeek toTimeZone
	toRelativeDayNum toRelativeHourNum toRelativeMonthNum toRelativeWeekNum toRelativeYearNum
	toIntervalSecond toIntervalMinute toIntervalHour toIntervalDay toIntervalWeek toIntervalMonth toIntervalQuarter toIntervalYear
	addSeconds addMinutes addHours addDays addWeeks addMonths addQuarters addYears
	subtractSeconds subtractMinutes subtractHours subtractDays subtractWeeks subtractMonths subtractQuarters subtractYears
	dateDiff date_diff dateTrunc date_trunc formatDateTime parseDateTimeBestEffort parseDateTimeBestEffortOrZero
	parseDateTimeBestEffortOrNull parseDateTime64BestEffort fromUnixTimestamp fromUnixTimestamp64Milli
	fromUnixTimestamp64Micro fromUnixTimestamp64Nano toUnixTimestamp64Milli toUnixTimestamp64Micro toUnixTimestamp64Nano
	makeDate makeDate32 makeDateTime makeDateTime64 timeSlot YYYYMMDDToDate YYYYMMDDhhmmssToDateTime
	lower upper lowerUTF8 upperUTF8 length lengthUTF8 empty notEmpty concat concatWithSeparator substring substr
	substringUTF8 trim trimLeft trimRight trimBoth replace replaceAll replaceOne replaceRegexpAll replaceRegexpOne
	position positionCaseInsensitive splitByChar splitByString splitByRegexp leftPad rightPad lpad rpad left right
	reverse base64Encode base64Decode hex unhex extract extractAll match like ilike notLike startsWith endsWith repeat
	cityHash64 sipHash64 sipHash128 xxHash32 xxHash64 xxh3 halfMD5 MD5 SHA1 SHA224 SHA256 SHA512 CRC32 CRC64
	intHash32 intHash64 farmFingerprint64 farmHash64 wyHash64 javaHash hiveHash
	murmurHash2_32 murmurHash2_64 murmurHash3_32 murmurHash3_64 murmurHash3_128 gccMurmurHash
	rand rand32 rand64 randConstant generateUUIDv4 generateUUIDv7 generateULID generateSnowflakeID
	array tuple map has hasAny hasAll indexOf range emptyArrayUInt8 emptyArrayString tupleElement
	mapKeys mapValues mapContains arrayMap arrayFilter arrayConcat arrayElement arraySort arrayReverseSort
	arrayDistinct arrayStringConcat arraySlice arrayCount arraySum arrayMin arrayMax arrayExists arrayAll
	arrayFirst arrayUniq arrayCompact arrayPushBack arrayPushFront arrayResize arrayZip arrayEnumerate
	arrayReverse arrayFlatten arrayIntersect
	round roundBankers floor ceil trunc sqrt exp log ln log2 log10 pow power greatest least sign
	bitAnd bitOr bitXor bitNot bitShiftLeft bitShiftRight
`)

var ciFunctions = words(`
	if not cast lower upper length concat substring substr coalesce ifnull nullif round floor ceil abs
	sqrt exp ln log log2 log10 pow power greatest least now replace reverse position left right lpad
	rpad repeat date_trunc datediff mod sign hex unhex
`)

// typeNames, codecNames and indexTypes are written with parentheses in a
// table's DDL (any case): they are accepted only where ClickHouse reads a
// type, a codec or an index type, never as calls in an expression (a
// target's user-defined function could have such a name).
var (
	typeNames = words(`
		array nullable lowcardinality map tuple nested decimal decimal32 decimal64 decimal128 decimal256
		datetime datetime64 fixedstring enum enum8 enum16 variant dynamic json object time time64`)
	codecNames = words(`zstd lz4 lz4hc delta doubledelta gorilla t64 fpc gcd none aes_128_gcm_siv aes_256_gcm_siv`)
	indexTypes = words(`minmax set bloom_filter tokenbf_v1 ngrambf_v1 full_text text vector_similarity`)
)

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// aggregateTypes take aggregate function names (with literal parameters)
// as type arguments.
var aggregateTypes = map[string]bool{"aggregatefunction": true, "simpleaggregatefunction": true}

// refusedWords never appear in a restored table's DDL: queries, IN,
// projections, column transformers and functions written without
// parentheses that read the session.
var refusedWords = map[string]string{
	"SELECT": "an expression of it holds a query", "WITH": "an expression of it holds a query",
	"EXPLAIN": "an expression of it holds a query", "DESCRIBE": "an expression of it holds a query",
	"IN": "an expression of it uses IN", "GLOBAL": "an expression of it uses IN",
	"PROJECTION": "it has a projection (a query)",
	"APPLY":      "an expression of it uses a column transformer", "EXCEPT": "an expression of it uses a column transformer",
	"COLUMNS":      "an expression of it uses COLUMNS",
	"CURRENT_USER": "an expression of it reads the session", "SESSION_USER": "an expression of it reads the session",
	"CURRENT_DATABASE": "an expression of it reads the session", "CURRENT_ROLE": "an expression of it reads the session",
	"CURRENT_SCHEMA": "an expression of it reads the session",
}

// operatorWords are keywords that take an operand on their left: before
// "(" after an operand they are operators, not calls.
var operatorWords = words(`AND OR NOT LIKE ILIKE BETWEEN IS DIV MOD`)

// nonOperands are words after which a "*" or "(" starts something new.
var nonOperands = words(`AND OR NOT LIKE ILIKE BETWEEN IS DIV MOD CASE WHEN THEN ELSE DEFAULT MATERIALIZED ALIAS EPHEMERAL
	BY KEY CHECK ASSUME TTL WHERE SET DELETE TO AS INTERVAL TYPE`)

// operandEnd: the token ends an operand (so a following operator is infix).
func operandEnd(t token) bool {
	switch t.kind {
	case tokNumber, tokString, tokQIdent:
		return true
	case tokWord:
		return !nonOperands[strings.ToUpper(t.val)]
	}
	return t.punct(")") || t.punct("]")
}

// tableProblem is why a checked CREATE TABLE is not created ("": it is).
// Every part is read by its role: the column list (types, DEFAULT,
// MATERIALIZED, ALIAS and EPHEMERAL expressions, CODEC, TTL, COMMENT),
// INDEX, CONSTRAINT and PRIMARY KEY elements, and the ENGINE, PARTITION
// BY, ORDER BY, PRIMARY KEY, SAMPLE BY, TTL, SETTINGS and COMMENT clauses.
// Types, codecs and index types are only accepted in their places;
// expressions only call pureFunctions (and ciFunctions in any case).
func (s *createStmt) tableProblem() string {
	n := len(s.toks)
	for i := s.body; i < n; i++ {
		t := s.toks[i]
		if t.depth == 0 && (t.is("AS") || t.is("EMPTY")) {
			return "it is defined AS another table, a query or a table function"
		}
		if t.kind == tokWord {
			if why := refusedWords[strings.ToUpper(t.val)]; why != "" {
				return why
			}
		}
		if t.kind == tokString && strings.Contains(strings.ToLower(t.val), "aggregatefunction") {
			return "a string of it names an AggregateFunction type"
		}
	}
	engine := s.engineName()
	if engine == "" {
		return "it has no ENGINE clause"
	}
	if !restorableEngine(engine) {
		return engineSkipReason(engine)
	}
	end := n
	for i := s.body; i < n; i++ {
		if t := s.toks[i]; t.depth == 0 && t.is("SETTINGS") {
			if why := s.settingsProblem(i + 1); why != "" {
				return why
			}
			end = i
			break
		}
	}
	i := s.body
	if i < end && s.toks[i].punct("(") {
		for _, el := range s.args(i) {
			if why := s.elementProblem(el[0], el[1]); why != "" {
				return why
			}
		}
		i = s.close(i) + 1
	}
	return s.clausesProblem(i, end)
}

// clausesProblem reads the depth-0 clauses in [from, to).
func (s *createStmt) clausesProblem(from, to int) string {
	type clause struct{ at, body int }
	var cs []clause
	for i := from; i < to; i++ {
		t := s.toks[i]
		if t.depth != 0 || t.kind != tokWord {
			continue
		}
		next := func(w string) bool { return i+1 < to && s.toks[i+1].is(w) }
		switch {
		case t.is("ENGINE") || t.is("TTL") || t.is("COMMENT"):
			cs = append(cs, clause{at: i, body: i + 1})
		case (t.is("PARTITION") || t.is("ORDER") || t.is("SAMPLE")) && next("BY"), t.is("PRIMARY") && next("KEY"):
			cs = append(cs, clause{at: i, body: i + 2})
			i++
		}
	}
	if len(cs) == 0 || cs[0].at != from {
		return "it has a clause Olympos does not restore"
	}
	for k, c := range cs {
		stop := to
		if k+1 < len(cs) {
			stop = cs[k+1].at
		}
		var why string
		switch kw := s.toks[c.at]; {
		case kw.is("ENGINE"):
			why = s.engineClauseProblem(c.body, stop)
		case kw.is("TTL"):
			why = s.ttlProblem(c.body, stop)
		case kw.is("COMMENT"):
			if stop != c.body+1 || s.toks[c.body].kind != tokString {
				why = "its COMMENT is not a string"
			}
		default:
			why = s.exprProblem(c.body, stop)
		}
		if why != "" {
			return why
		}
	}
	return ""
}

// engineClauseProblem reads "= Engine[(literals and column names)]".
func (s *createStmt) engineClauseProblem(from, to int) string {
	if to-from < 2 || !s.toks[from].punct("=") || !s.toks[from+1].ident() {
		return "its ENGINE clause cannot be read"
	}
	i := from + 2
	if i == to {
		return ""
	}
	if !s.toks[i].punct("(") || s.close(i) != to-1 {
		return "its ENGINE clause cannot be read"
	}
	for _, t := range s.toks[i+1 : to-1] {
		switch {
		case t.ident() || t.kind == tokString || t.kind == tokNumber || t.punct(",") || t.punct("(") || t.punct(")"):
		default:
			return "its engine arguments are not literals or column names"
		}
	}
	// No calls among the arguments.
	for j := i + 1; j < to-1; j++ {
		if s.toks[j].ident() && s.toks[j+1].punct("(") {
			return "its engine arguments are not literals or column names"
		}
	}
	if strings.HasSuffix(s.toks[from+1].val, "GraphiteMergeTree") {
		// The rollup configuration section's name, last string argument.
		args := s.args(i)
		last := args[len(args)-1]
		t := s.toks[last[0]]
		if last[1]-last[0] != 1 || t.kind != tokString || !graphiteSection.MatchString(t.val) {
			return "its GraphiteMergeTree configuration section is not a plain name"
		}
	}
	return ""
}

var graphiteSection = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

// elementProblem reads one element of the column list.
func (s *createStmt) elementProblem(from, to int) string {
	if from >= to {
		return "its column list cannot be read"
	}
	first := s.toks[from]
	at := func(i int, w string) bool { return i < to && s.toks[i].is(w) }
	switch {
	case first.is("INDEX"):
		// INDEX name expr TYPE type[(literals)] [GRANULARITY n]
		if from+1 >= to || !s.toks[from+1].ident() {
			return "an INDEX of it cannot be read"
		}
		ty := -1
		for j := from + 2; j < to; j++ {
			if s.toks[j].depth == first.depth && s.toks[j].is("TYPE") {
				ty = j
			}
		}
		if ty < 0 {
			return "an INDEX of it cannot be read"
		}
		if why := s.exprProblem(from+2, ty); why != "" {
			return why
		}
		j := ty + 1
		if j >= to || s.toks[j].kind != tokWord || !indexTypes[strings.ToLower(s.toks[j].val)] {
			return "an INDEX of it has a type Olympos does not restore"
		}
		j++
		if j < to && s.toks[j].punct("(") {
			c := s.close(j)
			if !literalsOnly(s.toks[j+1 : c]) {
				return "an INDEX type of it has parameters Olympos does not restore"
			}
			j = c + 1
		}
		if at(j, "GRANULARITY") && j+1 < to && s.toks[j+1].kind == tokNumber {
			j += 2
		}
		if j != to {
			return "an INDEX of it cannot be read"
		}
		return ""
	case first.is("CONSTRAINT"):
		if from+2 >= to || !s.toks[from+1].ident() || !(at(from+2, "CHECK") || at(from+2, "ASSUME")) {
			return "a CONSTRAINT of it cannot be read"
		}
		return s.exprProblem(from+3, to)
	case first.is("PRIMARY") && at(from+1, "KEY"):
		return s.exprProblem(from+2, to)
	case first.is("STATISTICS"):
		return "it has statistics, which Olympos does not restore"
	case !first.ident():
		return "its column list cannot be read"
	}
	// A column: name [type] [NULL | NOT NULL] [DEFAULT|MATERIALIZED|ALIAS|EPHEMERAL [expr]]
	// [CODEC(...)] [TTL expr] [COMMENT 'x'] [PRIMARY KEY].
	d := first.depth
	isMod := func(j int) bool {
		t := s.toks[j]
		if t.depth != d || t.kind != tokWord {
			return false
		}
		switch strings.ToUpper(t.val) {
		case "DEFAULT", "MATERIALIZED", "ALIAS", "EPHEMERAL", "CODEC", "TTL", "COMMENT", "SETTINGS", "STATISTICS", "NULL", "NOT", "PRIMARY":
			return true
		}
		return false
	}
	nextMod := func(j int) int {
		for ; j < to && !isMod(j); j++ {
		}
		return j
	}
	j := nextMod(from + 1)
	if why := s.typeProblem(from+1, j); why != "" {
		return why
	}
	for j < to {
		t := s.toks[j]
		switch strings.ToUpper(t.val) {
		case "NULL":
			j++
		case "NOT":
			if !at(j+1, "NULL") {
				return "a column of it cannot be read"
			}
			j += 2
		case "DEFAULT", "MATERIALIZED", "ALIAS", "EPHEMERAL", "TTL":
			k := nextMod(j + 1)
			if why := s.exprProblem(j+1, k); why != "" {
				return why
			}
			j = k
		case "CODEC":
			if j+1 >= to || !s.toks[j+1].punct("(") {
				return "a CODEC of it cannot be read"
			}
			c := s.close(j + 1)
			if why := s.codecProblem(j+2, c); why != "" {
				return why
			}
			j = c + 1
		case "COMMENT":
			if j+1 >= to || s.toks[j+1].kind != tokString {
				return "a column COMMENT of it is not a string"
			}
			j += 2
		case "PRIMARY":
			if !at(j+1, "KEY") {
				return "a column of it cannot be read"
			}
			j += 2
		default: // SETTINGS, STATISTICS
			return "a column of it has " + strings.ToUpper(t.val) + ", which Olympos does not restore"
		}
	}
	return ""
}

func literalsOnly(ts []token) bool {
	for _, t := range ts {
		if t.kind != tokNumber && t.kind != tokString && !t.punct(",") && !t.punct("-") {
			return false
		}
	}
	return true
}

// typeProblem reads a column type in [from, to): every call is a type
// name, or AggregateFunction / SimpleAggregateFunction read by
// aggregateTypeProblem.
func (s *createStmt) typeProblem(from, to int) string {
	for i := from; i < to; i++ {
		t := s.toks[i]
		if !t.ident() || i+1 >= to || !s.toks[i+1].punct("(") {
			continue
		}
		n := strings.ToLower(t.val)
		switch {
		case t.kind != tokWord || (i > from && s.toks[i-1].punct(".")):
			return "a column type of it cannot be read"
		case aggregateTypes[n]:
			if why := s.aggregateTypeProblem(i + 1); why != "" {
				return why
			}
			i = s.close(i + 1)
		case typeNames[n]:
		default:
			return "a column type of it uses " + t.val + "(), which Olympos does not restore"
		}
	}
	return ""
}

// codecProblem reads the codecs in [from, to): codec names, each with
// literal parameters.
func (s *createStmt) codecProblem(from, to int) string {
	for i := from; i < to; i++ {
		t := s.toks[i]
		switch {
		case t.punct(","):
		case t.kind == tokWord && codecNames[strings.ToLower(t.val)]:
			if i+1 < to && s.toks[i+1].punct("(") {
				c := s.close(i + 1)
				if !literalsOnly(s.toks[i+2 : c]) {
					return "a CODEC of it has parameters Olympos does not restore"
				}
				i = c
			}
		default:
			return "a CODEC of it is not one Olympos restores"
		}
	}
	return ""
}

// ttlProblem reads TTL items in [from, to): expr [DELETE | RECOMPRESS
// CODEC(...) | TO DISK|VOLUME 'name'] [WHERE expr], comma separated.
func (s *createStmt) ttlProblem(from, to int) string {
	if from >= to {
		return "its TTL cannot be read"
	}
	d := s.toks[from].depth
	start := from
	for i := from; i <= to; i++ {
		if i < to && !(s.toks[i].punct(",") && s.toks[i].depth == d) {
			continue
		}
		// One item: [start, i).
		kw := i
		for j := start; j < i; j++ {
			t := s.toks[j]
			if t.depth == d && (t.is("DELETE") || t.is("RECOMPRESS") || t.is("TO") || t.is("WHERE") || t.is("GROUP")) {
				kw = j
				break
			}
		}
		if why := s.exprProblem(start, kw); why != "" {
			return why
		}
		for j := kw; j < i; {
			t := s.toks[j]
			switch {
			case t.is("DELETE"):
				j++
			case t.is("RECOMPRESS") && j+2 < i && s.toks[j+1].is("CODEC") && s.toks[j+2].punct("("):
				c := s.close(j + 2)
				if why := s.codecProblem(j+3, c); why != "" {
					return why
				}
				j = c + 1
			case t.is("TO") && j+2 < i && (s.toks[j+1].is("DISK") || s.toks[j+1].is("VOLUME")) && s.toks[j+2].kind == tokString:
				j += 3
			case t.is("WHERE"):
				return s.exprProblem(j+1, i)
			default:
				return "its TTL has a part Olympos does not restore"
			}
		}
		start = i + 1
	}
	return ""
}

// exprProblem reads an expression in [from, to): calls are pureFunctions
// (exact) or ciFunctions (any case), not preceded by "."; CAST(x AS T) and
// x::T read T as a type; "*" is only multiplication.
func (s *createStmt) exprProblem(from, to int) string {
	caseDepth := 0
	for i := from; i < to; i++ {
		t := s.toks[i]
		var prev token
		if i > from {
			prev = s.toks[i-1]
		}
		switch {
		case t.is("CASE"):
			caseDepth++
		case t.is("END") && caseDepth > 0:
			caseDepth--
		case t.punct("*"):
			if i == from || !operandEnd(prev) {
				return "an expression of it uses *"
			}
		case t.punct("::"):
			// x::Type or x::Type(...)
			if i+1 >= to || s.toks[i+1].kind != tokWord {
				return "an expression of it has a cast Olympos does not read"
			}
			k := i + 2
			if k < to && s.toks[k].punct("(") {
				k = s.close(k) + 1
			}
			if why := s.typeProblem(i+1, k); why != "" {
				return why
			}
			i = k - 1
			continue
		case t.is("REPLACE") && i > from && operandEnd(prev):
			return "an expression of it uses a column transformer"
		}
		if !t.ident() || i+1 >= to || !s.toks[i+1].punct("(") {
			continue
		}
		up := strings.ToUpper(t.val)
		switch {
		case t.kind != tokWord || (i > from && prev.punct(".")):
			return "an expression of it calls a function Olympos does not read"
		case operatorWords[up] && i > from && operandEnd(prev):
			// x AND (y): an operator.
		case (up == "WHEN" || up == "THEN" || up == "ELSE") && caseDepth > 0:
		case up == "CAST" || up == "ACCURATECAST" || up == "ACCURATECASTORNULL" || up == "ACCURATECASTORDEFAULT":
			if !callableName(t.val) {
				return "an expression of it calls " + t.val + "(), which Olympos does not restore in a table definition"
			}
			// CAST(expr AS Type): the type after the depth-level AS.
			c := s.close(i + 1)
			for j := i + 2; j < c; j++ {
				if s.toks[j].depth == t.depth+1 && s.toks[j].is("AS") {
					if why := s.exprProblem(i+2, j); why != "" {
						return why
					}
					if why := s.typeProblem(j+1, c); why != "" {
						return why
					}
					i = c
					break
				}
			}
		case callableName(t.val):
		default:
			return "an expression of it calls " + t.val + "(), which Olympos does not restore in a table definition"
		}
	}
	return ""
}

// callableName: an exact pure function, or a case-insensitive one in any
// case.
func callableName(name string) bool {
	return pureFunctions[name] || ciFunctions[strings.ToLower(name)]
}

// aggregateTypeProblem checks AggregateFunction(...) at open: inside, a
// call is a type or an aggregate function with literal parameters only.
func (s *createStmt) aggregateTypeProblem(open int) string {
	end := s.close(open)
	for i := open + 1; i < end; i++ {
		t := s.toks[i]
		if !t.ident() || !s.toks[i+1].punct("(") {
			continue
		}
		if t.kind == tokWord && typeNames[strings.ToLower(t.val)] {
			continue
		}
		args := s.args(i + 1)
		ok := t.kind == tokWord && len(args) > 0
		for _, a := range args {
			if a[1]-a[0] != 1 || (s.toks[a[0]].kind != tokNumber && s.toks[a[0]].kind != tokString) {
				ok = false
			}
		}
		if !ok {
			return "an AggregateFunction type of it has parameters Olympos does not restore"
		}
		i = s.close(i + 1)
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
	if errors.Is(err, errLex) {
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

// defaultReplicaPath is the Keeper path a restored Replicated table gets
// when its statement names none (under /olympos-restore/<request id>/).
// {uuid} is never used: the restore drops the UUID clause, so the target
// cannot expand it; the request id and {database}/{table} keep the path
// unique.
const (
	defaultReplicaPath = "/clickhouse/tables/{database}/{table}/{shard}"
	defaultReplicaName = "{replica}"
)

// restorePath puts a Keeper path under /olympos-restore/<request id>/,
// keeping an auxiliary Keeper's "name:" prefix, with {uuid} replaced by
// {database}/{table}.
func restorePath(path, requestID string) string {
	aux := ""
	if i := strings.Index(path, ":"); i > 0 && !strings.Contains(path[:i], "/") {
		aux, path = path[:i+1], path[i+1:]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.ReplaceAll(path, "{uuid}", "{database}/{table}")
	return aux + "/olympos-restore/" + requestID + path
}

// plainKeeperPath: no empty, "." or ".." component (after an auxiliary
// Keeper's "name:" prefix).
func plainKeeperPath(p string) bool {
	if i := strings.Index(p, ":"); i > 0 && !strings.Contains(p[:i], "/") {
		p = p[i+1:]
	}
	for _, c := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// rewriteKeeperPaths puts the Keeper path of a Replicated*MergeTree under
// /olympos-restore/<request id>/, so the restored table never shares
// Keeper state with the source's when Keeper is shared. Without a path in
// the statement (only engine parameters, or none), one is set with the
// default replica name. rewritten reports a Replicated table; why is set
// when its arguments are not literals Olympos reads (it is not created).
func (s *createStmt) rewriteKeeperPaths(requestID string) (rewritten bool, why string) {
	i := s.engine()
	if i < 0 {
		return false, ""
	}
	engine := s.toks[i].val
	if !strings.HasPrefix(engine, "Replicated") || !isMergeTree(engine) {
		return false, ""
	}
	hasParen := i+1 < len(s.toks) && s.toks[i+1].punct("(")
	var args [][2]int
	if hasParen {
		args = s.args(i + 1)
	}
	single := func(a [2]int) bool { return a[1]-a[0] == 1 }
	str := func(a [2]int) bool { return single(a) && s.toks[a[0]].kind == tokString }
	for _, a := range args {
		if a[1] <= a[0] {
			return true, "its engine arguments cannot be read"
		}
	}
	switch {
	case len(args) >= 2 && str(args[0]) && str(args[1]) && !plainKeeperPath(s.toks[args[0][0]].val):
		return true, "its Keeper path has empty, . or .. components"
	case len(args) >= 2 && str(args[0]) && str(args[1]):
		t := s.toks[args[0][0]]
		s.edits = append(s.edits, edit{start: t.start, end: t.end, repl: quoteString(restorePath(t.val, requestID))})
		return true, ""
	case len(args) >= 1 && (!single(args[0]) || (len(args) >= 2 && !single(args[1]))):
		return true, "its Keeper path or replica name is not a literal Olympos reads"
	case len(args) >= 2 && str(args[0]) != str(args[1]):
		return true, "its Keeper path or replica name is not a literal Olympos reads"
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
	return true, ""
}
