//go:build dev

package destinations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/destinations"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/targetid"
)

// groupFixture seeds destinations straight into the table (the group API
// does not probe them) and returns their ids by name.
type groupFixture struct {
	t  *testing.T
	e  *apitest.Env
	id map[string]string
}

func (f *groupFixture) nfs(name, path, prefix string) {
	f.t.Helper()
	var id string
	if err := f.e.DB.QueryRow(context.Background(), `INSERT INTO destinations (name, kind, account, container, path, prefix, auth)
		VALUES ($1, 'nfs', '', '', $2, $3, 'none') RETURNING id::text`, name, path, prefix).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	f.id[name] = id
}

func (f *groupFixture) azure(name, account, container, prefix, endpoint string) {
	f.t.Helper()
	var id string
	if err := f.e.DB.QueryRow(context.Background(), `INSERT INTO destinations (name, kind, account, container, prefix, endpoint_override, auth)
		VALUES ($1, 'azure_blob', $2, $3, $4, $5, 'managed_identity') RETURNING id::text`, name, account, container, prefix, endpoint).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	f.id[name] = id
}

func TestDestinationGroupsAPI(t *testing.T) {
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&destinations.API{DB: e.DB, Log: e.Log, KV: e.KV, Env: e.Envelope}}
	}})
	ctx := context.Background()
	admin := e.Login(e.Principal("ada", "Member", "admin"))
	scopedAdmin := e.Login(e.Principal("sam", "Member", "admin@env=prod"))
	op := e.Login(e.Principal("olga", "Member", "operator@env=prod"))
	viewer := e.Login(e.Principal("vic", "Member", "viewer"))

	f := &groupFixture{t: t, e: e, id: map[string]string{}}
	f.nfs("nas-a", "/var/lib/olympos/nfs/a/olympos", "prod")
	f.nfs("nas-b", "/var/lib/olympos/nfs/b/olympos", "prod")
	f.nfs("nas-a-twin", "/var/lib/olympos/nfs/a/olympos", "prod")
	f.nfs("nas-a-other-prefix", "/var/lib/olympos/nfs/a/olympos", "dev")
	f.azure("blob-a", "acct", "backups", "olympos", "")
	f.azure("blob-a-twin", "acct", "backups", "olympos", "")
	f.azure("blob-sovereign", "acct", "backups", "olympos", "https://acct.blob.core.chinacloudapi.cn")
	f.azure("blob-b", "acct", "other", "olympos", "")
	for _, n := range []string{"x1", "x2", "x3"} {
		f.nfs(n, "/var/lib/olympos/nfs/"+n, "")
	}
	ids := func(names ...string) []string {
		out := make([]string, len(names))
		for i, n := range names {
			out[i] = f.id[n]
		}
		return out
	}

	// Permissions: reads for any role, writes admin (scope all) only.
	var list struct{ Items []destinations.GroupView }
	if code := op.Do("GET", "/api/v1/destination-groups", nil, &list); code != 200 || len(list.Items) != 0 {
		t.Fatalf("operator list: %d %+v", code, list)
	}
	if code := viewer.Do("GET", "/api/v1/destination-groups", nil, nil); code != 200 {
		t.Fatalf("viewer list: %d", code)
	}
	for _, cl := range []*apitest.Client{viewer, op, scopedAdmin} {
		if code := cl.Do("POST", "/api/v1/destination-groups", map[string]any{"name": "x", "member_ids": ids("nas-a", "nas-b")}, nil); code != 403 {
			t.Fatalf("%s create: %d", cl.P.DisplayName, code)
		}
	}

	// Create (members keep the order given), get, list.
	var g destinations.GroupView
	code, body := admin.Raw("POST", "/api/v1/destination-groups", map[string]any{
		"name": " mirror ", "description": "prod copies", "member_ids": ids("nas-b", "blob-a", "nas-a")})
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	admin.Do("GET", "/api/v1/destination-groups", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("list: %+v", list)
	}
	g = list.Items[0]
	if g.Name != "mirror" || g.Description != "prod copies" || g.Jobs != 0 || len(g.Members) != 3 ||
		g.Members[0].ID.String() != f.id["nas-b"] || g.Members[0].Name != "nas-b" || g.Members[0].Kind != "nfs" ||
		g.Members[1].ID.String() != f.id["blob-a"] || g.Members[1].Kind != "azure_blob" || g.Members[2].ID.String() != f.id["nas-a"] {
		t.Fatalf("group: %+v", g)
	}
	var got destinations.GroupView
	if code := op.Do("GET", "/api/v1/destination-groups/"+g.ID.String(), nil, &got); code != 200 || got.ID != g.ID || len(got.Members) != 3 {
		t.Fatalf("operator get: %d %+v", code, got)
	}
	if code := admin.Do("GET", "/api/v1/destination-groups/"+uuid.NewString(), nil, nil); code != 404 {
		t.Fatalf("get unknown: %d", code)
	}

	// Validation (422 with field errors). Nothing is saved by a refused request.
	fieldErr := func(label, method, path string, in map[string]any, field, contains string) {
		t.Helper()
		var eb struct {
			Error  string
			Fields map[string]string
		}
		if code := admin.Do(method, path, in, &eb); code != 422 || !strings.Contains(eb.Fields[field], contains) {
			t.Fatalf("%s: %d %+v (want field %q containing %q)", label, code, eb, field, contains)
		}
	}
	post := func(label string, in map[string]any, field, contains string) {
		t.Helper()
		fieldErr(label, "POST", "/api/v1/destination-groups", in, field, contains)
	}
	post("no name", map[string]any{"member_ids": ids("nas-a", "nas-b")}, "name", "required")
	post("blank name", map[string]any{"name": "  ", "member_ids": ids("nas-a", "nas-b")}, "name", "required")
	post("long name", map[string]any{"name": strings.Repeat("n", 81), "member_ids": ids("nas-a", "nas-b")}, "name", "80")
	post("no members", map[string]any{"name": "g"}, "member_ids", "2 to 4")
	post("one member", map[string]any{"name": "g", "member_ids": ids("nas-a")}, "member_ids", "2 to 4")
	post("five members", map[string]any{"name": "g", "member_ids": ids("nas-a", "nas-b", "blob-a", "x1", "x2")}, "member_ids", "2 to 4")
	post("duplicate member", map[string]any{"name": "g", "member_ids": ids("nas-a", "nas-b", "nas-a")}, "member_ids", "only once")
	post("unknown member", map[string]any{"name": "g", "member_ids": []string{f.id["nas-a"], uuid.NewString()}}, "member_ids", "unknown destination")
	post("same nfs location", map[string]any{"name": "g", "member_ids": ids("nas-a", "nas-a-twin")}, "member_ids", "nas-a and nas-a-twin write to the same location")
	post("same azure location", map[string]any{"name": "g", "member_ids": ids("blob-a", "nas-b", "blob-a-twin")}, "member_ids", "blob-a and blob-a-twin write to the same location")
	var eb struct{ Fields map[string]string }
	if code := admin.Do("POST", "/api/v1/destination-groups", map[string]any{"name": "mirror", "member_ids": ids("x1", "x2")}, &eb); code != 422 ||
		eb.Fields["name"] == "" {
		t.Fatalf("name taken: %d %+v", code, eb)
	}
	// Same kind but a different prefix, container or endpoint is a different location.
	var ok destinations.GroupView
	if code := admin.Do("POST", "/api/v1/destination-groups", map[string]any{"name": "distinct",
		"member_ids": ids("nas-a", "nas-a-other-prefix", "blob-a", "blob-b")}, &ok); code != 201 || len(ok.Members) != 4 {
		t.Fatalf("distinct locations: %d %+v", code, ok)
	}
	if code := admin.Do("DELETE", "/api/v1/destination-groups/"+ok.ID.String(), nil, nil); code != 204 {
		t.Fatalf("delete distinct: %d", code)
	}
	if code := admin.Do("POST", "/api/v1/destination-groups", map[string]any{"name": "sovereign",
		"member_ids": ids("blob-a", "blob-sovereign")}, &ok); code != 201 {
		t.Fatalf("endpoint differs: %d", code)
	}
	if code := admin.Do("DELETE", "/api/v1/destination-groups/"+ok.ID.String(), nil, nil); code != 204 {
		t.Fatalf("delete sovereign: %d", code)
	}
	if code := admin.Do("POST", "/api/v1/destination-groups", map[string]any{"name": "g", "bogus": 1}, nil); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}
	if n := count(t, e, `SELECT count(*) FROM destination_groups`); n != 1 {
		t.Fatalf("refused requests saved groups: %d", n)
	}

	// Patch: rename, change members (positions follow member_ids), keep what is absent.
	path := "/api/v1/destination-groups/" + g.ID.String()
	var patched destinations.GroupView
	if code := admin.Do("PATCH", path, map[string]any{"member_ids": ids("nas-a", "nas-b")}, &patched); code != 200 ||
		patched.Name != "mirror" || patched.Description != "prod copies" || len(patched.Members) != 2 ||
		patched.Members[0].ID.String() != f.id["nas-a"] || patched.Members[1].ID.String() != f.id["nas-b"] {
		t.Fatalf("patch members: %d %+v", code, patched)
	}
	rows, _ := e.DB.Query(ctx, `SELECT position FROM destination_group_members WHERE group_id = $1 ORDER BY position`, g.ID)
	var pos []int
	for rows.Next() {
		var p int
		_ = rows.Scan(&p)
		pos = append(pos, p)
	}
	rows.Close()
	if len(pos) != 2 || pos[0] != 0 || pos[1] != 1 {
		t.Fatalf("positions not contiguous: %v", pos)
	}
	if code := admin.Do("PATCH", path, map[string]any{"name": "mirror2", "description": ""}, &patched); code != 200 ||
		patched.Name != "mirror2" || patched.Description != "" || len(patched.Members) != 2 {
		t.Fatalf("patch fields: %d %+v", code, patched)
	}
	if code := admin.Do("PATCH", path, map[string]any{"member_ids": ids("nas-b", "nas-a", "x1")}, &patched); code != 200 ||
		patched.Members[0].Name != "nas-b" || patched.Members[2].Name != "x1" {
		t.Fatalf("reorder: %d %+v", code, patched)
	}
	fieldErr("patch one member", "PATCH", path, map[string]any{"member_ids": ids("nas-a")}, "member_ids", "2 to 4")
	fieldErr("patch same location", "PATCH", path, map[string]any{"member_ids": ids("nas-a", "nas-a-twin")}, "member_ids", "same location")
	fieldErr("patch blank name", "PATCH", path, map[string]any{"name": ""}, "name", "required")
	if code := admin.Do("POST", "/api/v1/destination-groups", map[string]any{"name": "second", "member_ids": ids("x2", "x3")}, &ok); code != 201 {
		t.Fatalf("second: %d", code)
	}
	fieldErr("patch name taken", "PATCH", path, map[string]any{"name": "second"}, "name", "")
	var after destinations.GroupView
	admin.Do("GET", path, nil, &after)
	if after.Name != "mirror2" || len(after.Members) != 3 {
		t.Fatalf("refused patch changed the group: %+v", after)
	}
	if code := admin.Do("PATCH", "/api/v1/destination-groups/"+uuid.NewString(), map[string]any{"name": "z"}, nil); code != 404 {
		t.Fatalf("patch unknown: %d", code)
	}
	for _, cl := range []*apitest.Client{op, scopedAdmin} {
		if code := cl.Do("PATCH", path, map[string]any{"name": "hijack"}, nil); code != 403 {
			t.Fatalf("%s patch: %d", cl.P.DisplayName, code)
		}
		if code := cl.Do("DELETE", path, nil, nil); code != 403 {
			t.Fatalf("%s delete: %d", cl.P.DisplayName, code)
		}
	}

	// A destination that is a member cannot be deleted; the destination view counts groups.
	var dv destinations.View
	if code := admin.Do("GET", "/api/v1/destinations/"+f.id["nas-b"], nil, &dv); code != 200 || dv.Groups != 1 {
		t.Fatalf("destination groups count: %d %+v", code, dv)
	}
	var del struct{ Error string }
	if code := admin.Do("DELETE", "/api/v1/destinations/"+f.id["nas-b"], nil, &del); code != 409 ||
		del.Error != "destination is in 1 destination group(s); remove it there first" {
		t.Fatalf("delete member destination: %d %+v", code, del)
	}

	// A group used by a job cannot be deleted and the view carries only the count.
	var jobID string
	if err := e.DB.QueryRow(ctx, `INSERT INTO backup_jobs (system, destination_group_id, cron, timezone)
		VALUES ('olympos-self', $1, '0 2 * * *', 'UTC') RETURNING id::text`, g.ID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	code, body = op.Raw("GET", path, nil)
	var generic map[string]any
	admin.Do("GET", path, nil, &generic)
	if code != 200 || strings.Contains(body, jobID) || generic["jobs"] != float64(1) {
		t.Fatalf("job leak or count: %d %s", code, body)
	}
	if _, has := generic["job_ids"]; has {
		t.Fatalf("view carries job ids: %v", generic)
	}
	code, body = admin.Raw("GET", "/api/v1/destination-groups", nil)
	if code != 200 || strings.Contains(body, jobID) {
		t.Fatalf("list leaks a job id: %d %s", code, body)
	}
	if code := admin.Do("DELETE", path, nil, &del); code != 409 || del.Error != "destination group is used by 1 backup job(s); move them first" {
		t.Fatalf("delete used group: %d %+v", code, del)
	}
	// A soft-deleted job still counts (the FK keeps pointing at the group).
	var clusterID, targetID, deletedJob string
	if err := e.DB.QueryRow(ctx, `INSERT INTO clusters (name, labels, status, last_seen_at) VALUES ('c1', '{"env":"prod"}', 'online', now()) RETURNING id::text`).Scan(&clusterID); err != nil {
		t.Fatal(err)
	}
	targetID = targetid.Compute(clusterID, "shop", "orders-pg", 5432)
	if _, err := e.DB.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine) VALUES ($1,$2,'shop','orders-pg',5432,'postgresql')`, targetID, clusterID); err != nil {
		t.Fatal(err)
	}
	if err := e.DB.QueryRow(ctx, `INSERT INTO backup_jobs (target_id, destination_group_id, cron, timezone, deleted_at)
		VALUES ($1, $2, '0 2 * * *', 'UTC', now()) RETURNING id::text`, targetID, ok.ID).Scan(&deletedJob); err != nil {
		t.Fatal(err)
	}
	if code := admin.Do("DELETE", "/api/v1/destination-groups/"+ok.ID.String(), nil, &del); code != 409 || del.Error != "destination group is used by 1 backup job(s); move them first" {
		t.Fatalf("delete group with a deleted job: %d %+v", code, del)
	}
	if _, err := e.DB.Exec(ctx, `DELETE FROM backup_jobs WHERE id = $1`, deletedJob); err != nil {
		t.Fatal(err)
	}

	// Delete an unused group: members are released, the destinations stay.
	var other destinations.GroupView
	admin.Do("GET", "/api/v1/destination-groups/"+ok.ID.String(), nil, &other)
	if code := admin.Do("DELETE", "/api/v1/destination-groups/"+other.ID.String(), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code := admin.Do("DELETE", "/api/v1/destination-groups/"+other.ID.String(), nil, nil); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
	if n := count(t, e, `SELECT count(*) FROM destinations WHERE name IN ('x2','x3')`); n != 2 {
		t.Fatalf("destinations deleted with the group: %d", n)
	}
	if n := count(t, e, `SELECT count(*) FROM destination_group_members WHERE group_id = '`+other.ID.String()+`'`); n != 0 {
		t.Fatalf("members left: %d", n)
	}
	// Once no group holds it, the destination can go.
	if code := admin.Do("DELETE", "/api/v1/destinations/"+f.id["x3"], nil, nil); code != 204 {
		t.Fatalf("delete freed destination: %d", code)
	}

	// Audit trail.
	arows, _ := e.DB.Query(ctx, `SELECT action, object_id, details::text FROM activity_log WHERE object_type = 'destination_group' ORDER BY at`)
	var actions []string
	var updated []string
	for arows.Next() {
		var a, oid, det string
		_ = arows.Scan(&a, &oid, &det)
		actions = append(actions, a)
		if a == "destination_group.updated" {
			updated = append(updated, det)
		}
	}
	arows.Close()
	want := "destination_group.created,destination_group.created,destination_group.deleted,destination_group.created,destination_group.deleted," +
		"destination_group.updated,destination_group.updated,destination_group.updated,destination_group.created,destination_group.deleted"
	if strings.Join(actions, ",") != want {
		t.Fatalf("activity: %v", actions)
	}
	// First update: blob-a removed, nas-a / nas-b stay (nas-b, blob-a, nas-a -> nas-a, nas-b).
	if !strings.Contains(updated[0], f.id["blob-a"]) || !strings.Contains(updated[0], `"removed"`) || !strings.Contains(updated[0], `"added"`) {
		t.Fatalf("member diff missing: %s", updated[0])
	}
	if !strings.Contains(updated[1], `"name"`) || !strings.Contains(updated[1], "mirror2") {
		t.Fatalf("field diff missing: %s", updated[1])
	}
	if !strings.Contains(updated[2], f.id["x1"]) {
		t.Fatalf("added member missing: %s", updated[2])
	}
}

func count(t *testing.T, e *apitest.Env, sql string) int {
	t.Helper()
	var n int
	if err := e.DB.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
