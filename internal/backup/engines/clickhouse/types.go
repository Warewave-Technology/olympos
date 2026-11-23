package clickhouse

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// A restored table's column types come from the manifest (system.columns
// on the source), which the restore does not trust: canonicalType reads a
// type with a strict grammar and writes it again from what it read, so the
// generated CREATE TABLE holds only allowlisted type names, integer and
// string literals Olympos quoted itself, quoted element names and
// allowlisted aggregate function names. Anything else is refused and the
// table is not created.

var errType = errors.New("a column type Olympos does not restore")

// maxTypeText bounds a type's text and maxTypeDepth its nesting.
const (
	maxTypeText  = 1 << 20
	maxTypeDepth = 32
)

// simpleTypes take no parameters (exact names, as system.columns writes
// them).
var simpleTypes = words(`
	Int8 Int16 Int32 Int64 Int128 Int256 UInt8 UInt16 UInt32 UInt64 UInt128 UInt256
	Float32 Float64 BFloat16 Bool String UUID IPv4 IPv6 Date Date32 Time Nothing
	Point Ring LineString MultiLineString Polygon MultiPolygon JSON`)

// aggregateBases are built-in aggregate functions an AggregateFunction or
// SimpleAggregateFunction type may name, with a suffix of
// aggregateCombinators (-Resample is not among them).
var (
	aggregateBases = words(`
		count sum sumWithOverflow sumKahan avg avgWeighted min max any anyLast anyHeavy any_value first_value last_value
		argMin argMax uniq uniqExact uniqCombined uniqCombined64 uniqHLL12 uniqTheta uniqUpTo
		groupArray groupArrayLast groupUniqArray groupArrayInsertAt groupArraySample groupArrayMovingSum groupArrayMovingAvg
		groupBitAnd groupBitOr groupBitXor groupBitmap groupBitmapAnd groupBitmapOr groupBitmapXor
		sumMap minMap maxMap sumMapWithOverflow topK topKWeighted
		quantile quantiles quantileExact quantilesExact quantileExactLow quantileExactHigh quantileExactWeighted
		quantilesExactWeighted quantileTiming quantilesTiming quantileTimingWeighted quantilesTimingWeighted
		quantileTDigest quantilesTDigest quantileTDigestWeighted quantilesTDigestWeighted quantileBFloat16
		quantilesBFloat16 quantileDeterministic quantilesDeterministic median
		varSamp varPop stddevSamp stddevPop covarSamp covarPop corr skewSamp skewPop kurtSamp kurtPop
		entropy simpleLinearRegression histogram windowFunnel retention sequenceMatch sequenceCount
		deltaSum deltaSumTimestamp boundingRatio maxIntersections maxIntersectionsPosition`)
	aggregateCombinators = []string{"If", "Array", "ForEach", "State", "Merge", "SimpleState", "Distinct", "OrNull", "OrDefault", "Map"}
)

// aggregateName: a base with combinators, by exact names.
func aggregateName(name string) bool {
	if len(name) > 128 {
		return false
	}
	for base := range aggregateBases {
		if rest, ok := strings.CutPrefix(name, base); ok && combinatorSuffix(rest) {
			return true
		}
	}
	return false
}

func combinatorSuffix(s string) bool {
	if s == "" {
		return true
	}
	for _, c := range aggregateCombinators {
		if rest, ok := strings.CutPrefix(s, c); ok && combinatorSuffix(rest) {
			return true
		}
	}
	return false
}

var (
	timeZoneRe  = regexp.MustCompile(`^[A-Za-z0-9_+\-/]{1,64}$`)
	paramNumRe  = regexp.MustCompile(`^[0-9]{1,30}(\.[0-9]{1,30})?$`)
	unsignedRe  = regexp.MustCompile(`^[0-9]{1,19}$`)
	nullableKey = regexp.MustCompile(`^(LowCardinality\()?Nullable\(`)
)

// canonicalType reads a column type and returns it written by Olympos.
func canonicalType(s string) (string, error) {
	if s == "" || len(s) > maxTypeText {
		return "", errType
	}
	toks, err := lexSQL(s)
	if err != nil {
		return "", errType
	}
	r := &typeReader{toks: toks}
	out, err := r.typ(0)
	if err != nil {
		return "", err
	}
	if r.i != len(toks) {
		return "", errType
	}
	return out, nil
}

// typeReader walks a type's tokens; every read is bounds-checked.
type typeReader struct {
	toks []token
	i    int
}

func (r *typeReader) peek(k int) token {
	if j := r.i + k; j >= 0 && j < len(r.toks) {
		return r.toks[j]
	}
	return token{kind: tokPunct, val: "<end>"}
}

func (r *typeReader) next() token {
	t := r.peek(0)
	if r.i < len(r.toks) {
		r.i++
	}
	return t
}

func (r *typeReader) accept(p string) bool {
	if r.peek(0).punct(p) {
		r.i++
		return true
	}
	return false
}

func (r *typeReader) expect(p string) error {
	if !r.accept(p) {
		return errType
	}
	return nil
}

// unsigned reads a decimal integer and writes it back.
func (r *typeReader) unsigned() (string, error) {
	t := r.next()
	if t.kind != tokNumber || !unsignedRe.MatchString(t.val) {
		return "", errType
	}
	n, err := strconv.ParseUint(t.val, 10, 64)
	if err != nil {
		return "", errType
	}
	return strconv.FormatUint(n, 10), nil
}

// signed reads [-]integer.
func (r *typeReader) signed() (string, error) {
	neg := r.accept("-")
	n, err := r.unsigned()
	if err != nil {
		return "", err
	}
	if neg {
		return "-" + n, nil
	}
	return n, nil
}

func (r *typeReader) str() (string, error) {
	t := r.next()
	if t.kind != tokString {
		return "", errType
	}
	return t.val, nil
}

// list reads "(" item {"," item} ")" with at least one item.
func (r *typeReader) list(item func() (string, error)) ([]string, error) {
	if err := r.expect("("); err != nil {
		return nil, err
	}
	var out []string
	for {
		s, err := item()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		if r.accept(")") {
			return out, nil
		}
		if err := r.expect(","); err != nil {
			return nil, err
		}
	}
}

func (r *typeReader) typ(depth int) (string, error) {
	if depth > maxTypeDepth {
		return "", errType
	}
	t := r.next()
	if t.kind != tokWord {
		return "", errType
	}
	name := t.val
	if simpleTypes[name] {
		if r.peek(0).punct("(") {
			return "", errType
		}
		return name, nil
	}
	sub := func() (string, error) { return r.typ(depth + 1) }
	join := func(items []string, err error) (string, error) {
		if err != nil {
			return "", err
		}
		return name + "(" + strings.Join(items, ", ") + ")", nil
	}
	switch name {
	case "Nullable", "LowCardinality", "Array":
		items, err := r.list(sub)
		if err == nil && len(items) != 1 {
			err = errType
		}
		return join(items, err)
	case "Map":
		items, err := r.list(sub)
		if err == nil && len(items) != 2 {
			err = errType
		}
		return join(items, err)
	case "Variant":
		return join(r.list(sub))
	case "Tuple", "Nested":
		return join(r.elements(name == "Nested", depth))
	case "Decimal":
		items, err := r.list(r.unsigned)
		if err == nil && len(items) != 2 {
			err = errType
		}
		return join(items, err)
	case "Decimal32", "Decimal64", "Decimal128", "Decimal256", "FixedString", "Time64":
		items, err := r.list(r.unsigned)
		if err == nil && len(items) != 1 {
			err = errType
		}
		return join(items, err)
	case "DateTime":
		if !r.peek(0).punct("(") {
			return name, nil
		}
		items, err := r.list(r.timeZone)
		if err == nil && len(items) != 1 {
			err = errType
		}
		return join(items, err)
	case "DateTime64":
		if err := r.expect("("); err != nil {
			return "", err
		}
		p, err := r.unsigned()
		if err != nil {
			return "", err
		}
		items := []string{p}
		if r.accept(",") {
			tz, err := r.timeZone()
			if err != nil {
				return "", err
			}
			items = append(items, tz)
		}
		return join(items, r.expect(")"))
	case "Enum8", "Enum16", "Enum":
		return join(r.list(func() (string, error) {
			s, err := r.str()
			if err != nil {
				return "", err
			}
			if err := r.expect("="); err != nil {
				return "", err
			}
			n, err := r.signed()
			if err != nil {
				return "", err
			}
			return quoteString(s) + " = " + n, nil
		}))
	case "Object":
		items, err := r.list(r.str)
		if err == nil && (len(items) != 1 || items[0] != "json") {
			err = errType
		}
		return name + "('json')", err
	case "Dynamic":
		if !r.peek(0).punct("(") {
			return name, nil
		}
		items, err := r.list(func() (string, error) {
			if k := r.next(); !k.is("max_types") || k.kind != tokWord {
				return "", errType
			}
			if err := r.expect("="); err != nil {
				return "", err
			}
			n, err := r.unsigned()
			return "max_types = " + n, err
		})
		if err == nil && len(items) != 1 {
			err = errType
		}
		return join(items, err)
	case "AggregateFunction", "SimpleAggregateFunction":
		return join(r.aggregateArgs(name == "SimpleAggregateFunction", depth))
	}
	return "", errType
}

func (r *typeReader) timeZone() (string, error) {
	s, err := r.str()
	if err != nil || !timeZoneRe.MatchString(s) {
		return "", errType
	}
	return quoteString(s), nil
}

// elements reads a Tuple's or Nested's elements: all named
// ("name Type", the name quoted by Olympos) or, for a Tuple, all unnamed.
func (r *typeReader) elements(nested bool, depth int) ([]string, error) {
	named := -1 // unknown until the first element
	return r.list(func() (string, error) {
		first, second := r.peek(0), r.peek(1)
		isNamed := first.kind == tokQIdent || (first.kind == tokWord && second.kind == tokWord)
		n := 0
		if isNamed {
			n = 1
		}
		if named == -1 {
			named = n
		}
		if named != n || (nested && !isNamed) {
			return "", errType
		}
		prefix := ""
		if isNamed {
			nm := r.next()
			if nm.val == "" {
				return "", errType
			}
			prefix = quoteIdent(nm.val) + " "
		}
		ty, err := r.typ(depth + 1)
		if err != nil {
			return "", err
		}
		return prefix + ty, nil
	})
}

// aggregateArgs reads [version,] agg[(params)] {, Type}: params are
// numbers or strings, written by Olympos.
func (r *typeReader) aggregateArgs(simple bool, depth int) ([]string, error) {
	if err := r.expect("("); err != nil {
		return nil, err
	}
	var out []string
	if !simple && r.peek(0).kind == tokNumber {
		v, err := r.unsigned()
		if err != nil {
			return nil, err
		}
		if err := r.expect(","); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	fn := r.next()
	if fn.kind != tokWord || !aggregateName(fn.val) {
		return nil, errType
	}
	agg := fn.val
	if r.peek(0).punct("(") {
		params, err := r.list(r.aggregateParam)
		if err != nil {
			return nil, err
		}
		agg += "(" + strings.Join(params, ", ") + ")"
	}
	out = append(out, agg)
	types := 0
	for r.accept(",") {
		ty, err := r.typ(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, ty)
		types++
	}
	if simple && types == 0 {
		return nil, errType
	}
	return out, r.expect(")")
}

func (r *typeReader) aggregateParam() (string, error) {
	if r.peek(0).kind == tokString {
		s, err := r.str()
		return quoteString(s), err
	}
	neg := r.accept("-")
	t := r.next()
	if t.kind != tokNumber || !paramNumRe.MatchString(t.val) {
		return "", errType
	}
	if neg {
		return "-" + t.val, nil
	}
	return t.val, nil
}

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}
