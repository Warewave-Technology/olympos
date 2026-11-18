package clickhouse

import (
	"context"
	"strings"
)

// Grant analysis for the connection test. ClickHouse hides tables a user
// has no privilege on, so a backup user with table-level grants would
// silently produce a partial backup. The real SELECT checks only see
// visible tables; the grant check catches the invisible ones by requiring
// SELECT on db.* (or *.*) — or on each table of the "tables" allow-list.

type grant struct {
	revoke bool
	privs  []string
	target string // unquoted: "*.*", "db.*", "db.table"
}

// userGrants returns SHOW GRANTS of the user plus those of its enabled
// roles (SHOW GRANTS has no FINAL on 24.8).
func (s *session) userGrants(ctx context.Context) ([]string, error) {
	rows, err := s.queryStrings(ctx, "SHOW GRANTS")
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, r := range rows {
		lines = append(lines, r[0])
	}
	roles, err := s.queryStrings(ctx, "SELECT role_name FROM system.enabled_roles ORDER BY role_name")
	if err != nil {
		return lines, nil // older servers / restricted: user grants only
	}
	for _, r := range roles {
		rr, err := s.queryStrings(ctx, "SHOW GRANTS FOR "+quoteIdent(r[0]))
		if err != nil {
			continue
		}
		for _, x := range rr {
			lines = append(lines, x[0])
		}
	}
	return lines, nil
}

func parseGrant(line string) (grant, bool) {
	var g grant
	rest, ok := strings.CutPrefix(line, "GRANT ")
	sep := " TO "
	if !ok {
		if rest, ok = strings.CutPrefix(line, "REVOKE "); !ok {
			return g, false
		}
		g.revoke, sep = true, " FROM "
	}
	privs, rest, ok := strings.Cut(rest, " ON ")
	if !ok {
		return g, false // role grant: "GRANT r1 TO u"
	}
	target, _, ok := strings.Cut(rest, sep)
	if !ok {
		return g, false
	}
	g.privs = splitTopLevel(privs)
	g.target = unquoteTarget(target)
	return g, true
}

// splitTopLevel splits "SELECT(a, b), SHOW TABLES" on commas outside ().
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func unquoteTarget(t string) string {
	var b strings.Builder
	for i := 0; i < len(t); i++ {
		switch c := t[i]; c {
		case '`':
		case '\\':
			if i+1 < len(t) {
				i++
				b.WriteByte(t[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// fullSelect: whole-table SELECT (not column-level) or ALL.
func fullSelect(p string) bool {
	return p == "SELECT" || p == "ALL" || p == "ALL PRIVILEGES"
}

func anySelect(p string) bool { return fullSelect(p) || strings.HasPrefix(p, "SELECT(") }

// selectCovered reports whether the grants give SELECT on db.table (or on
// all of db when table is ""), and why not.
func selectCovered(lines []string, db, table string) (bool, string) {
	want := db + ".*"
	if table != "" {
		want = db + "." + table
	}
	granted := false
	for _, l := range lines {
		g, ok := parseGrant(l)
		if !ok {
			continue
		}
		for _, p := range g.privs {
			switch {
			case !g.revoke && fullSelect(p):
				if g.target == "*.*" || g.target == db+".*" || g.target == want {
					granted = true
				}
			case g.revoke && anySelect(p):
				if g.target == "*.*" || g.target == db+".*" || g.target == want ||
					(table == "" && strings.HasPrefix(g.target, db+".")) {
					return false, "partially revoked: " + l
				}
			}
		}
	}
	if !granted {
		return false, "SELECT is not granted on " + want + " (tables without a grant are invisible and would be missing from backups)"
	}
	return true, ""
}
