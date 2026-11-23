package clickhouse

import (
	"strings"
)

// The objects a restore creates may only read the restored databases: a
// view or materialized view (whose DEFINER may have more rights than its
// readers), a column's DEFAULT, MATERIALIZED, ALIAS or TTL expression, a
// dictionary's attribute expressions. scanRefs walks every query and
// expression of a statement and fails closed: a table function that is not
// a local, side-effect-free one, a function that reaches outside the
// server, an object named by a string it cannot check, or a table
// expression it cannot read makes the object not created.

// localTableFunctions read nothing but their arguments (merge, loop and
// dictionary are checked for the database they read; view's query is
// walked like any subquery).
var localTableFunctions = map[string]bool{
	"numbers": true, "numbers_mt": true, "zeros": true, "zeros_mt": true, "generaterandom": true,
	"generate_series": true, "generateseries": true, "values": true, "null": true, "view": true,
	"merge": true, "loop": true, "dictionary": true,
}

// outsideFunctions reach outside the server or its databases wherever they
// are called (file() reads the server's files, the model functions load
// files, hasColumnInTable may connect to another host; the rest are table
// functions, which are never allowed outside a table position either).
var outsideFunctions = map[string]bool{
	"file": true, "filecluster": true, "catboostevaluate": true, "modelevaluate": true, "naivebayesclassifier": true,
	"hascolumnintable": true, "disk": true,
	"url": true, "urlcluster": true, "s3": true, "s3cluster": true, "gcs": true, "oss": true, "cosn": true,
	"azureblobstorage": true, "azureblobstoragecluster": true, "hdfs": true, "hdfscluster": true,
	"remote": true, "remotesecure": true, "cluster": true, "clusterallreplicas": true,
	"mysql": true, "postgresql": true, "mongodb": true, "redis": true, "sqlite": true, "jdbc": true, "odbc": true,
	"executable": true, "kafka": true,
}

// namedObjectFunction: the function names a dictionary or Join table by
// a string as its first argument.
func namedObjectFunction(name string) bool {
	return strings.HasPrefix(name, "dictget") || strings.HasPrefix(name, "joinget") ||
		name == "dicthas" || name == "dictisin" || name == "dictgethierarchy" || name == "dictgetchildren" ||
		name == "dictgetdescendants"
}

// clauseEnd ends a FROM clause (at the same depth).
var clauseEnd = map[string]bool{
	"WHERE": true, "PREWHERE": true, "GROUP": true, "HAVING": true, "ORDER": true, "LIMIT": true, "SETTINGS": true,
	"UNION": true, "WINDOW": true, "QUALIFY": true, "INTERSECT": true, "EXCEPT": true, "FORMAT": true, "SELECT": true,
	"OFFSET": true, "INTO": true,
}

// scanRefs returns the objects the statement reads ("db.name"; an
// unqualified name is in db unless it names a CTE) and why the statement is
// not created ("" when it only reads through local means).
func (s *createStmt) scanRefs(db string) ([]string, string) {
	toks := s.toks
	n := len(toks)
	ctes := map[string]bool{}
	for i := 0; i+3 < n; i++ {
		if toks[i].ident() && toks[i+1].is("AS") && toks[i+2].punct("(") && (toks[i+3].is("SELECT") || toks[i+3].is("WITH")) {
			ctes[toks[i].val] = true
		}
	}
	var refs []string
	seen := map[string]bool{}
	ref := func(r string) {
		if !seen[r] {
			seen[r] = true
			refs = append(refs, r)
		}
	}
	type frame struct{ query, from, expect bool }
	stack := []frame{{}}
	selectAt := -1
	if s.kind == KindView || s.kind == KindMaterializedView {
		selectAt = s.selectStart()
	}
	call := func(i int) bool { return i+1 < n && toks[i].ident() && toks[i+1].punct("(") }
	// tableAt handles a table expression at i: why ("" if fine).
	tableAt := func(i int) string {
		t := toks[i]
		switch {
		case t.punct("("):
			return "" // a subquery or parenthesized join: walked as it comes
		case call(i):
			name := strings.ToLower(t.val)
			if !localTableFunctions[name] {
				return "it reads through table function " + t.val + "(), which Olympos does not restore"
			}
			args := s.args(i + 1)
			switch name {
			case "merge":
				if len(args) == 0 {
					return "it reads through merge() without arguments"
				}
				d, ok := s.argDatabase(args[0])
				if !ok {
					return "it reads through merge() over databases matching a pattern"
				}
				ref(d + ".*")
			case "loop":
				switch {
				case len(args) == 2:
					d, ok := s.argDatabase(args[0])
					if !ok {
						return "it reads through loop() with an argument Olympos cannot check"
					}
					ref(d + ".*")
				case len(args) == 1 && args[0][1]-args[0][0] == 3 && toks[args[0][0]+1].punct("."):
					ref(toks[args[0][0]].val + "." + toks[args[0][0]+2].val)
				case len(args) == 1 && args[0][1]-args[0][0] == 1 && toks[args[0][0]].ident():
					ref(db + "." + toks[args[0][0]].val)
				default:
					return "it reads through loop() with an argument Olympos cannot check"
				}
			case "dictionary":
				if len(args) != 1 || args[0][1]-args[0][0] != 1 || toks[args[0][0]].kind != tokString {
					return "it reads through dictionary() with an argument Olympos cannot check"
				}
				ref(qualify(db, toks[args[0][0]].val))
			}
			return ""
		case t.ident():
			if i+2 < n && toks[i+1].punct(".") {
				if !toks[i+2].ident() || (i+3 < n && (toks[i+3].punct(".") || toks[i+3].punct("("))) {
					return "Olympos cannot read one of its table references"
				}
				ref(t.val + "." + toks[i+2].val)
				return ""
			}
			if !ctes[t.val] {
				ref(db + "." + t.val)
			}
			return ""
		}
		return "Olympos cannot read one of its table references"
	}
	for i := s.body; i < n; i++ {
		t := toks[i]
		top := &stack[len(stack)-1]
		if i == selectAt && len(stack) == 1 {
			top.query = true
		}
		if top.expect {
			top.expect = false
			if why := tableAt(i); why != "" {
				return refs, why
			}
		}
		switch {
		case t.punct("(") || t.punct("[") || t.punct("{"):
			q := i+1 < n && (toks[i+1].is("SELECT") || toks[i+1].is("WITH"))
			stack = append(stack, frame{query: q})
			continue
		case t.punct(")") || t.punct("]") || t.punct("}"):
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if call(i) {
			name := strings.ToLower(t.val)
			// A table position's call was handled by tableAt (and an
			// allowed table function is not an outside one).
			if outsideFunctions[name] && !localTableFunctions[name] {
				return refs, "its definition calls " + t.val + "(), which reaches outside the target"
			}
			if namedObjectFunction(name) {
				args := s.args(i + 1)
				if len(args) == 0 || args[0][1]-args[0][0] != 1 || toks[args[0][0]].kind != tokString {
					return refs, "it calls " + t.val + "() with an object name Olympos cannot check"
				}
				ref(qualify(db, toks[args[0][0]].val))
			}
		}
		if t.kind != tokWord {
			if top.query && top.from && t.punct(",") {
				top.expect = true
			}
			continue
		}
		up := strings.ToUpper(t.val)
		switch {
		case up == "IN":
			// x IN [db.]table or IN a table function; a subquery or a list
			// in parentheses is walked, a literal or a scalar function
			// (tuple(...)) is an expression.
			if i+1 < n && toks[i+1].ident() && (!call(i+1) || localTableFunctions[strings.ToLower(toks[i+1].val)]) {
				if why := tableAt(i + 1); why != "" {
					return refs, why
				}
			}
		case !top.query:
		case up == "FROM":
			top.from, top.expect = true, true
		case up == "JOIN":
			if i > 0 && toks[i-1].is("ARRAY") {
				// ARRAY JOIN lists columns, not tables.
				top.from = false
				break
			}
			top.from, top.expect = true, true
		case clauseEnd[up]:
			top.from = false
		}
	}
	return refs, ""
}

// qualify reads "db.name" or "name" (in db).
func qualify(db, name string) string {
	if strings.Contains(name, ".") {
		return name
	}
	return db + "." + name
}

// refOutside is the first reference outside the restored databases ("").
func refOutside(refs []string, restored map[string]bool) string {
	for _, r := range refs {
		if d, _, _ := strings.Cut(r, "."); !restored[d] {
			return r
		}
	}
	return ""
}
