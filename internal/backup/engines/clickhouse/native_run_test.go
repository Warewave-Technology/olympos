package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ClickHouse/ch-go"
)

const (
	nrRunID  = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61"
	nrBaseID = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60"
	nrKey    = "OLYABCDEFGHIJKLMNOPQ"
	nrSecret = "secret-canary-0123456789abcdefghijklmnop"
)

func testNativeRun() NativeRun {
	return NativeRun{
		URL:       "https://olympos-ingest.contoso.internal:9444/olympos/" + nrRunID + "/",
		AccessKey: nrKey,
		Secret:    nrSecret,
		RunID:     nrRunID,
		Databases: []string{"db1", "web-shop"},
	}
}

func TestBackupStatementGolden(t *testing.T) {
	full := testNativeRun()
	incr := testNativeRun()
	incr.Base = &NativeBase{URL: "https://olympos-ingest.contoso.internal:9444/olympos/" + nrBaseID + "/", RunID: nrBaseID}

	for _, tc := range []struct {
		name string
		nr   NativeRun
		want string
	}{
		{"full", full, "BACKUP DATABASE `db1`, DATABASE `web-shop` TO S3(" +
			"'https://olympos-ingest.contoso.internal:9444/olympos/" + nrRunID + "/', '" + nrKey + "', '" + nrSecret + "')" +
			" SETTINGS async = 1, allow_s3_native_copy = 0, id = '" + nrRunID + "'"},
		{"incremental", incr, "BACKUP DATABASE `db1`, DATABASE `web-shop` TO S3(" +
			"'https://olympos-ingest.contoso.internal:9444/olympos/" + nrRunID + "/', '" + nrKey + "', '" + nrSecret + "')" +
			" SETTINGS async = 1, allow_s3_native_copy = 0, id = '" + nrRunID + "'" +
			", base_backup = S3('https://olympos-ingest.contoso.internal:9444/olympos/" + nrBaseID + "/')" +
			", use_same_s3_credentials_for_base_backup = 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := backupStatement(tc.nr); got != tc.want {
				t.Fatalf("statement\n got %s\nwant %s", got, tc.want)
			}
		})
	}

	// Names are quoted, so a database name cannot end the statement's list.
	odd := testNativeRun()
	odd.Databases = []string{"a`b", "c'd"}
	if got, want := backupStatement(odd), "BACKUP DATABASE `a\\`b`, DATABASE `c'd` TO S3("; !strings.HasPrefix(got, want) {
		t.Fatalf("quoting: %s", got)
	}
}

func TestRedactStatement(t *testing.T) {
	full := testNativeRun()
	incr := testNativeRun()
	incr.Base = &NativeBase{URL: "https://olympos-ingest.contoso.internal:9444/olympos/" + nrBaseID + "/", RunID: nrBaseID}

	for name, stmt := range map[string]string{
		"full":        backupStatement(full),
		"incremental": backupStatement(incr),
		// A base with credentials of its own (the form R26 replaced) is
		// redacted as well.
		"base with credentials": backupStatement(full) + ", base_backup = S3('https://h/olympos/" + nrBaseID + "/', '" +
			nrKey + "', '" + nrSecret + "')",
		"lower case":  strings.Replace(backupStatement(full), "S3(", "s3(", 1),
		"spaces":      strings.Replace(backupStatement(full), "S3(", "S3 ( ", 1),
		"session key": strings.Replace(backupStatement(full), "')", "', 'token-"+nrSecret+"')", 1),
	} {
		t.Run(name, func(t *testing.T) {
			got := redactStatement(stmt)
			if strings.Contains(got, nrSecret) {
				t.Fatalf("the secret survived: %s", got)
			}
			for _, keep := range []string{nrKey, full.URL, "id = '" + nrRunID + "'", "DATABASE `web-shop`"} {
				if !strings.Contains(got, keep) {
					t.Fatalf("%q is gone: %s", keep, got)
				}
			}
			if !strings.Contains(got, "'[HIDDEN]'") {
				t.Fatalf("no [HIDDEN]: %s", got)
			}
		})
	}

	// A secret with quotes and backslashes is quoted in the statement and
	// still removed whole.
	odd := testNativeRun()
	odd.Secret = `it's\a-secret`
	if got := redactStatement(backupStatement(odd)); strings.Contains(got, "secret") || strings.Contains(got, `it\'s`) {
		t.Fatalf("an escaped secret survived: %s", got)
	}

	// A quoted name that holds "S3(" is not an S3 call.
	named := testNativeRun()
	named.Databases = []string{"S3('x', 'y', 'z')"}
	got := redactStatement(backupStatement(named))
	if !strings.Contains(got, "DATABASE `S3('x', 'y', 'z')`") || strings.Contains(got, nrSecret) {
		t.Fatalf("a quoted name: %s", got)
	}

	// What cannot be read is hidden from that point on.
	for _, bad := range []string{
		"BACKUP DATABASE a TO S3('https://h/olympos/r/', 'key', '" + nrSecret,
		"BACKUP DATABASE a TO S3('https://h/olympos/r/', 'key', concat('" + nrSecret + "'))",
		"BACKUP DATABASE a TO S3('https://h/olympos/r/', 'key' '" + nrSecret + "')",
		"BACKUP DATABASE `a TO S3('https://h/olympos/r/', 'key', '" + nrSecret + "')",
	} {
		got := redactStatement(bad)
		if strings.Contains(got, nrSecret) || !strings.HasPrefix(got, "BACKUP DATABASE ") || !strings.HasSuffix(got, "[HIDDEN]") {
			t.Errorf("unreadable statement: %s", got)
		}
	}
}

// fakeQuerier answers checkNativeTarget's queries by the first fragment of
// the query each answer names.
type fakeQuerier struct {
	answers map[string][][]string
	fail    map[string]error
	asked   []string
}

func (f *fakeQuerier) queryStrings(_ context.Context, body string, _ ...ch.Setting) ([][]string, error) {
	f.asked = append(f.asked, body)
	for frag, err := range f.fail {
		if strings.Contains(body, frag) {
			return nil, err
		}
	}
	for frag, rows := range f.answers {
		if strings.Contains(body, frag) {
			return rows, nil
		}
	}
	return nil, nil
}

func healthyTarget(version string) *fakeQuerier {
	return &fakeQuerier{answers: map[string][][]string{"version()": {{version}}}}
}

func TestCheckNativeTarget(t *testing.T) {
	dbs := []string{"db1", "web-shop"}
	for _, v := range []string{"24.8.14.39", "24.12.1.1", "25.8.33.6", "26.1.2.3"} {
		if err := checkNativeTarget(context.Background(), healthyTarget(v), dbs); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}

	for _, v := range []string{"24.3.12.75", "23.8.16.40", "22.12.1.1"} {
		err := checkNativeTarget(context.Background(), healthyTarget(v), dbs)
		if !errors.Is(err, ErrNativeVersion) || !strings.Contains(err.Error(), "24.8 or later") ||
			!strings.Contains(err.Error(), v) || !strings.Contains(err.Error(), "logical") {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"", "24", "x.y.z", "24.x.1"} {
		if err := checkNativeTarget(context.Background(), healthyTarget(v), dbs); err == nil {
			t.Errorf("version %q: accepted", v)
		}
	}

	// A Distributed table in one of the run's databases.
	q := healthyTarget("24.8.14.39")
	q.answers["'Distributed'"] = [][]string{{"web-shop", "events_all"}}
	err := checkNativeTarget(context.Background(), q, dbs)
	if !errors.Is(err, ErrNativeSharded) || !strings.Contains(err.Error(), "web-shop.events_all") ||
		!strings.Contains(err.Error(), "one shard") || !strings.Contains(err.Error(), "logical") {
		t.Fatalf("distributed: %v", err)
	}
	var distributed string
	for _, a := range q.asked {
		if strings.Contains(a, "'Distributed'") {
			distributed = a
		}
	}
	if !strings.Contains(distributed, "'db1'") || !strings.Contains(distributed, "'web-shop'") {
		t.Fatalf("the Distributed check does not name the run's databases: %s", distributed)
	}

	// A cluster of this host with two shards.
	q = healthyTarget("25.8.33.6")
	q.answers["system.clusters"] = [][]string{{"analytics", "2"}}
	err = checkNativeTarget(context.Background(), q, dbs)
	if !errors.Is(err, ErrNativeSharded) || !strings.Contains(err.Error(), "analytics") || !strings.Contains(err.Error(), "2 shards") {
		t.Fatalf("clusters: %v", err)
	}

	// The Altinity operator's all-sharded alone does not refuse (R30); a
	// sharded cluster next to it does, and is named.
	q = healthyTarget("24.8.14.39")
	q.answers["system.clusters"] = [][]string{{"all-sharded", "2"}}
	if err := checkNativeTarget(context.Background(), q, dbs); err != nil {
		t.Fatalf("all-sharded alone: %v", err)
	}
	q.answers["system.clusters"] = [][]string{{"all-sharded", "2"}, {"events", "2"}}
	err = checkNativeTarget(context.Background(), q, dbs)
	if !errors.Is(err, ErrNativeSharded) || !strings.Contains(err.Error(), "events with 2 shards") || strings.Contains(err.Error(), "all-sharded") {
		t.Fatalf("all-sharded and a sharded cluster: %v", err)
	}
	// A Distributed table refuses even when all-sharded is the only cluster.
	q.answers["system.clusters"] = [][]string{{"all-sharded", "3"}}
	q.answers["'Distributed'"] = [][]string{{"db1", "all_events"}}
	if err := checkNativeTarget(context.Background(), q, dbs); !errors.Is(err, ErrNativeSharded) || !strings.Contains(err.Error(), "db1.all_events") {
		t.Fatalf("all-sharded and a Distributed table: %v", err)
	}

	// A check that cannot be made refuses the run.
	for _, frag := range []string{"version()", "'Distributed'", "system.clusters"} {
		q := healthyTarget("24.8.14.39")
		q.fail = map[string]error{frag: fmt.Errorf("ACCESS_DENIED")}
		if err := checkNativeTarget(context.Background(), q, dbs); err == nil || !strings.Contains(err.Error(), "ACCESS_DENIED") {
			t.Errorf("%s fails: %v", frag, err)
		}
	}
}

// TestNativeThrottle pins the query settings of the native statements (R29):
// put and get together stay under the endpoint's 200 requests a second per
// run, bursts included.
func TestNativeThrottle(t *testing.T) {
	asMap := func(settings []ch.Setting) map[string]string {
		m := map[string]string{}
		for _, s := range settings {
			if !s.Important {
				t.Errorf("%s is not important: a server that does not know it would run unthrottled", s.Key)
			}
			m[s.Key] = s.Value
		}
		return m
	}
	want := map[string]string{"s3_max_put_rps": "150", "s3_max_put_burst": "150", "s3_max_get_rps": "40", "s3_max_get_burst": "40"}
	if got := asMap(nativeBackupSettings); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("backup settings %v, want %v", got, want)
	}
	want = map[string]string{"s3_max_put_rps": "40", "s3_max_put_burst": "40", "s3_max_get_rps": "150", "s3_max_get_burst": "150"}
	if got := asMap(nativeRestoreSettings); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("restore settings %v, want %v", got, want)
	}
}

func TestNativeRunValidate(t *testing.T) {
	ok := testNativeRun()
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	incr := testNativeRun()
	incr.Base = &NativeBase{URL: "https://olympos-ingest.contoso.internal:9444/olympos/" + nrBaseID + "/", RunID: nrBaseID}
	if err := incr.validate(); err != nil {
		t.Fatal(err)
	}

	bad := map[string]func(*NativeRun){
		"run id upper case": func(n *NativeRun) { n.RunID = strings.ToUpper(n.RunID) },
		"run id not a uuid": func(n *NativeRun) { n.RunID = "run-1" },
		"url of another run": func(n *NativeRun) {
			n.URL = "https://olympos-ingest.contoso.internal:9444/olympos/" + nrBaseID + "/"
		},
		"url of another bucket":   func(n *NativeRun) { n.URL = "https://h:9444/backups/" + nrRunID + "/" },
		"url without slash":       func(n *NativeRun) { n.URL = strings.TrimSuffix(n.URL, "/") },
		"url with a query":        func(n *NativeRun) { n.URL += "?x=1" },
		"url with an empty query": func(n *NativeRun) { n.URL += "?" },
		"url with a fragment":     func(n *NativeRun) { n.URL += "#f" },
		"url with an escaped path": func(n *NativeRun) {
			n.URL = "https://h:9444/olympos%2F/olympos/" + nrRunID + "/"
		},
		"url with user info": func(n *NativeRun) { n.URL = "https://u:p@h:9444/olympos/" + nrRunID + "/" },
		"url not http":       func(n *NativeRun) { n.URL = "ftp://h/olympos/" + nrRunID + "/" },
		"no key":             func(n *NativeRun) { n.AccessKey = "" },
		"no secret":          func(n *NativeRun) { n.Secret = "" },
		"empty database":     func(n *NativeRun) { n.Databases = []string{"db1", ""} },
		"system database":    func(n *NativeRun) { n.Databases = []string{"system"} },
		"base is the run": func(n *NativeRun) {
			n.Base = &NativeBase{URL: n.URL, RunID: n.RunID}
		},
		"base url of another run": func(n *NativeRun) {
			n.Base = &NativeBase{URL: "https://olympos-ingest.contoso.internal:9444/olympos/" + nrRunID + "/", RunID: nrBaseID}
		},
		"base on another endpoint": func(n *NativeRun) {
			n.Base = &NativeBase{URL: "https://elsewhere:9444/olympos/" + nrBaseID + "/", RunID: nrBaseID}
		},
	}
	for name, mod := range bad {
		nr := testNativeRun()
		mod(&nr)
		err := nr.validate()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), nrSecret) {
			t.Errorf("%s: the error holds the secret: %v", name, err)
		}
	}
}

func TestNativeRunHidesSecret(t *testing.T) {
	nr := testNativeRun()
	for _, s := range []string{fmt.Sprint(nr), fmt.Sprintf("%v %+v %#v", nr, nr, nr), fmt.Sprint(&nr), nr.LogValue().String()} {
		if strings.Contains(s, nrSecret) {
			t.Fatalf("printed the secret: %s", s)
		}
	}
}
