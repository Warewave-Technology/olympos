package destinations_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/destinations"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

func stepOf(rep *destinations.Report, name string) *destinations.Step {
	if rep == nil {
		return nil
	}
	for i := range rep.Steps {
		if rep.Steps[i].Name == name {
			return &rep.Steps[i]
		}
	}
	return nil
}

func findView(t *testing.T, c *apitest.Client, name string) destinations.View {
	t.Helper()
	var list struct{ Items []destinations.View }
	c.Do("GET", "/api/v1/destinations", nil, &list)
	for _, v := range list.Items {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("destination %s not listed", name)
	return destinations.View{}
}

func TestS3DestinationsAPI(t *testing.T) {
	srv := testutil.MinIO(t)
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&destinations.API{DB: e.DB, Log: e.Log, KV: e.KV, Env: e.Envelope}}
	}})
	ctx := context.Background()
	admin := e.Login(e.Principal("ada", "Member", "admin"))
	op := e.Login(e.Principal("olga", "Member", "operator"))

	bucket := "b-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	rc, err := minio.New(srv.HostPort, &minio.Options{Creds: credentials.NewStaticV4(srv.RootUser, srv.RootPassword, ""), BucketLookup: minio.BucketLookupPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	ak, sk := srv.MinIOUser(t, "api-"+bucket[2:10], testutil.NoDeleteS3Policy(bucket))
	canaries := []string{sk, srv.RootPassword}
	checkNoSecret := func(where, s string) {
		t.Helper()
		for _, c := range canaries {
			if c != "" && strings.Contains(s, c) {
				t.Fatalf("S3 secret key leaked in %s", where)
			}
		}
	}
	input := func(name, keyID, secret string) map[string]any {
		return map[string]any{"name": name, "kind": "s3", "bucket": bucket, "region": "eu-central-1", "prefix": "olympos",
			"endpoint_override": srv.Endpoint, "path_style": true, "auth": "access_key", "access_key_id": keyID,
			"secret_key": map[string]any{"source": "stored", "value": secret}}
	}

	if code := op.Do("POST", "/api/v1/destinations", input("x", ak, sk), nil); code != 403 {
		t.Fatalf("operator create: %d", code)
	}

	// Least-privilege user: saved, delete refused, no warning.
	code, body := admin.Raw("POST", "/api/v1/destinations", input("s3-main", ak, sk))
	checkNoSecret("create", body)
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	if strings.Contains(body, `"warnings"`) {
		t.Fatalf("unexpected warnings: %s", body)
	}
	d := findView(t, admin, "s3-main")
	if d.Kind != "s3" || d.Bucket != bucket || d.Region != "eu-central-1" || !d.PathStyle || d.AccessKeyID != ak || d.SecretKeySource != "stored" ||
		d.SecretKeyRef != "" || d.Auth != "access_key" || d.EndpointOverride != srv.Endpoint || d.Account != "" || d.LastTest == nil ||
		d.LastTest.CanDelete || !d.LastTest.OK {
		t.Fatalf("view: %+v", d)
	}
	for _, s := range []string{destinations.StepEndpoint, destinations.StepWrite, destinations.StepRead, destinations.StepTag, destinations.StepDeleteRefused} {
		if st := stepOf(d.LastTest, s); st == nil || !st.OK {
			t.Fatalf("step %s: %+v", s, d.LastTest.Steps)
		}
	}
	if st := stepOf(d.LastTest, destinations.StepEndpoint); !strings.Contains(st.Detail, "plain HTTP") || !strings.Contains(st.Detail, "path-style") {
		t.Fatalf("endpoint detail: %s", st.Detail)
	}

	// Root credentials can delete: saved with a warning, never silently.
	code, body = admin.Raw("POST", "/api/v1/destinations", input("s3-root", srv.RootUser, srv.RootPassword))
	checkNoSecret("root create", body)
	if code != 201 || !strings.Contains(body, "can delete objects") || !strings.Contains(body, `"can_delete":true`) {
		t.Fatalf("root create: %d %s", code, body)
	}

	// Failures: wrong secret, missing bucket → 422 with the endpoint step.
	var failed destinations.TestFailed
	if code := admin.Do("POST", "/api/v1/destinations", input("s3-bad", ak, "WRONG-"+sk), &failed); code != 422 || failed.Test == nil ||
		stepOf(failed.Test, destinations.StepEndpoint) == nil || stepOf(failed.Test, destinations.StepEndpoint).OK {
		t.Fatalf("wrong secret: %d %+v", code, failed)
	}
	in := input("s3-missing", srv.RootUser, srv.RootPassword)
	in["bucket"] = "no-such-bucket-olympos"
	if code := admin.Do("POST", "/api/v1/destinations", in, &failed); code != 422 || !strings.Contains(failed.Error, "does not exist") {
		t.Fatalf("missing bucket: %d %+v", code, failed)
	}

	// Validation per kind.
	code, body = admin.Raw("POST", "/api/v1/destinations", map[string]any{"name": "v", "kind": "s3", "bucket": "Bad_Bucket", "account": "acct",
		"endpoint_override": "https://minio.example/path", "auth": "sas_token", "region": "EU WEST"})
	for _, f := range []string{"bucket", "account", "endpoint_override", "auth", "access_key_id", "secret_key", "region"} {
		if !strings.Contains(body, `"`+f+`"`) {
			t.Fatalf("validation: %d %s (missing %s)", code, body, f)
		}
	}
	if code := admin.Do("POST", "/api/v1/destinations", map[string]any{"name": "k", "kind": "ftp"}, nil); code != 422 {
		t.Fatalf("unknown kind: %d", code)
	}

	// Key Vault reference for the secret key.
	if err := e.KV.SetSecret(ctx, "kv-weu", "s3-secret", []byte(sk)); err != nil {
		t.Fatal(err)
	}
	in = input("s3-kv", ak, "")
	in["secret_key"] = map[string]any{"source": "keyvault_ref", "ref": "kv://kv-weu/s3-secret"}
	if code, body := admin.Raw("POST", "/api/v1/destinations", in); code != 201 {
		t.Fatalf("kv create: %d %s", code, body)
	}
	kvd := findView(t, admin, "s3-kv")
	if kvd.SecretKeySource != "keyvault_ref" || kvd.SecretKeyRef != "kv://kv-weu/s3-secret" {
		t.Fatalf("kv view: %+v", kvd)
	}

	// PATCH: rename re-tests with the stored secret; kind cannot change;
	// a new secret replaces (and removes) the old credential.
	var patched destinations.View
	if code := admin.Do("PATCH", "/api/v1/destinations/"+d.ID.String(), map[string]any{"name": "s3-main-2", "path_style": true}, &patched); code != 200 ||
		patched.Name != "s3-main-2" || patched.SecretKeySource != "stored" {
		t.Fatalf("rename: %d %+v", code, patched)
	}
	if code, body := admin.Raw("PATCH", "/api/v1/destinations/"+d.ID.String(), map[string]any{"kind": "nfs"}); code != 422 || !strings.Contains(body, "cannot be changed") {
		t.Fatalf("kind change: %d %s", code, body)
	}
	root := findView(t, admin, "s3-root")
	var oldCred uuid.UUID
	_ = e.DB.QueryRow(ctx, `SELECT secret_credential_id FROM destinations WHERE id = $1`, root.ID).Scan(&oldCred)
	code, body = admin.Raw("PATCH", "/api/v1/destinations/"+root.ID.String(), map[string]any{"access_key_id": ak,
		"secret_key": map[string]any{"source": "stored", "value": sk}})
	checkNoSecret("patch", body)
	if code != 200 || strings.Contains(body, "can delete") {
		t.Fatalf("replace secret: %d %s", code, body)
	}
	var n int
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE id = $1`, oldCred).Scan(&n)
	if n != 0 {
		t.Fatal("replaced secret credential must be removed")
	}

	// Saved and unsaved tests.
	var rep destinations.Report
	if code, body := admin.Raw("POST", "/api/v1/destinations/"+kvd.ID.String()+"/test", nil); code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("saved test: %d %s", code, body)
	}
	if code := admin.Do("POST", "/api/v1/destinations/test", input("", srv.RootUser, srv.RootPassword), &rep); code != 200 || !rep.CanDelete || !rep.OK {
		t.Fatalf("unsaved test: %d %+v", code, rep)
	}

	// Delete removes the secret credential.
	var kvCred uuid.UUID
	_ = e.DB.QueryRow(ctx, `SELECT secret_credential_id FROM destinations WHERE id = $1`, kvd.ID).Scan(&kvCred)
	if code := admin.Do("DELETE", "/api/v1/destinations/"+kvd.ID.String(), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE id = $1`, kvCred).Scan(&n)
	if n != 0 {
		t.Fatal("credential of deleted destination must be removed")
	}

	// The resolver opens the saved destination and writes through it.
	w, err := blob.NewResolver(e.DB, e.KV, e.Envelope, nil).ForDestination(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Upload(ctx, blob.Join(w.Prefix(), "resolver", uuid.NewString()), strings.NewReader("x"), "", map[string]string{"olympos-tier": "daily"}); err != nil {
		t.Fatal(err)
	}

	// No secret anywhere.
	rows, _ := e.DB.Query(ctx, `SELECT details::text FROM activity_log WHERE object_type = 'destination'`)
	for rows.Next() {
		var det string
		_ = rows.Scan(&det)
		checkNoSecret("activity", det)
	}
	rows.Close()
	var reports string
	_ = e.DB.QueryRow(ctx, `SELECT string_agg(last_test_report::text, ' ') FROM destinations`).Scan(&reports)
	checkNoSecret("last_test_report", reports)
	checkNoSecret("logs", e.LogBuf.String())
	code, body = admin.Raw("GET", "/api/v1/destinations", nil)
	checkNoSecret("list", body)
}

func TestNFSDestinationsAPI(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "nfs")
	for _, d := range []string{root + "/backup-nas", root + "/other", base + "/outside"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(base+"/outside", root+"/backup-nas/link"); err != nil {
		t.Fatal(err)
	}
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&destinations.API{DB: e.DB, Log: e.Log, KV: e.KV, Env: e.Envelope, Storage: blob.StorageOptions{NFSRoot: root}}}
	}})
	ctx := context.Background()
	admin := e.Login(e.Principal("ada", "Member", "admin"))
	viewer := e.Login(e.Principal("vic", "Member", "viewer"))

	var mounts struct{ Items []blob.Mount }
	if code := viewer.Do("GET", "/api/v1/destinations/mounts", nil, &mounts); code != 200 || len(mounts.Items) != 2 ||
		mounts.Items[0].Name != "backup-nas" || mounts.Items[0].Path != root+"/backup-nas" || !mounts.Items[0].Writable {
		t.Fatalf("mounts: %d %+v", code, mounts)
	}

	path := root + "/backup-nas/olympos"
	code, body := admin.Raw("POST", "/api/v1/destinations", map[string]any{"name": "nas", "kind": "nfs", "path": path + "/", "prefix": "prod"})
	if code != 201 || !strings.Contains(body, "can delete files on this export") || !strings.Contains(body, "snapshots") {
		t.Fatalf("create: %d %s", code, body)
	}
	d := findView(t, admin, "nas")
	if d.Kind != "nfs" || d.Path != path || d.Auth != "none" || d.Prefix != "prod" || d.LastTest == nil || !d.LastTest.OK || !d.LastTest.CanDelete {
		t.Fatalf("view: %+v", d)
	}
	st := stepOf(d.LastTest, destinations.StepPath)
	if st == nil || !st.OK || !strings.Contains(st.Detail, "backup-nas") || !strings.Contains(st.Detail, "created") {
		t.Fatalf("path step: %+v", d.LastTest.Steps)
	}
	if st := stepOf(d.LastTest, destinations.StepDeleteRefused); st == nil || st.OK || !strings.Contains(st.Detail, "WORM") {
		t.Fatalf("delete step: %+v", st)
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Fatal("destination directory not created")
	}

	for name, p := range map[string]string{
		"traversal": root + "/backup-nas/../other",
		"outside":   base + "/outside",
		"symlink":   root + "/backup-nas/link/x",
		"relative":  "backup-nas/x",
		"no mount":  root + "/missing/x",
	} {
		if code, body := admin.Raw("POST", "/api/v1/destinations", map[string]any{"name": "bad", "kind": "nfs", "path": p}); code != 422 ||
			!strings.Contains(body, `"path"`) {
			t.Fatalf("%s: %d %s", name, code, body)
		}
	}
	if code, body := admin.Raw("POST", "/api/v1/destinations", map[string]any{"name": "bad", "kind": "nfs", "path": path, "bucket": "b",
		"secret_key": map[string]any{"source": "stored", "value": "x"}, "auth": "access_key"}); code != 422 ||
		!strings.Contains(body, `"bucket"`) || !strings.Contains(body, `"secret_key"`) || !strings.Contains(body, `"auth"`) {
		t.Fatalf("foreign fields: %d %s", code, body)
	}

	// Patch to another mount; saved test.
	var patched destinations.View
	if code := admin.Do("PATCH", "/api/v1/destinations/"+d.ID.String(), map[string]any{"path": root + "/other/olympos"}, &patched); code != 200 ||
		patched.Path != root+"/other/olympos" {
		t.Fatalf("patch: %d %+v", code, patched)
	}
	var rep destinations.Report
	if code := admin.Do("POST", "/api/v1/destinations/"+d.ID.String()+"/test", nil, &rep); code != 200 || !rep.OK || !rep.CanDelete {
		t.Fatalf("saved test: %d %+v", code, rep)
	}
	// Probe files are gone (delete succeeded), the directory stays.
	if ents, _ := os.ReadDir(root + "/other/olympos/prod/" + blob.ProbeDir); len(ents) != 0 {
		t.Fatalf("probe files left: %v", ents)
	}

	// Constraint: an nfs row cannot carry S3 credentials.
	if _, err := e.DB.Exec(ctx, `UPDATE destinations SET access_key_id = 'x' WHERE id = $1`, d.ID); err == nil {
		t.Fatal("nfs check constraint missing")
	}
}

func TestDestinationKindConstraints(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	var cred uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO credentials (kind, keyvault_name, secret_name) VALUES ('keyvault_ref', 'kv', 's') RETURNING id`).Scan(&cred); err != nil {
		t.Fatal(err)
	}
	ok := []string{
		`INSERT INTO destinations (name, account, container, auth) VALUES ('az-mi', 'acct', 'c', 'managed_identity')`,
		`INSERT INTO destinations (name, account, container, auth, sas_credential_id) VALUES ('az-sas', 'acct', 'c', 'sas_token', '` + cred.String() + `')`,
		`INSERT INTO destinations (name, kind, account, container, bucket, auth, access_key_id, secret_credential_id) VALUES ('s3', 's3', '', '', 'b', 'access_key', 'AK', '` + cred.String() + `')`,
		`INSERT INTO destinations (name, kind, account, container, path, auth) VALUES ('nfs', 'nfs', '', '', '/var/lib/olympos/nfs/x', 'none')`,
	}
	for _, q := range ok {
		if _, err := db.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	bad := []string{
		`INSERT INTO destinations (name, account, container, auth) VALUES ('x1', 'acct', 'c', 'sas_token')`,
		`INSERT INTO destinations (name, account, container, auth) VALUES ('x2', '', 'c', 'managed_identity')`,
		`INSERT INTO destinations (name, account, container, auth) VALUES ('x3', 'acct', 'c', 'access_key')`,
		`INSERT INTO destinations (name, kind, account, container, bucket, auth, access_key_id) VALUES ('x4', 's3', '', '', 'b', 'access_key', 'AK')`,
		`INSERT INTO destinations (name, kind, account, container, bucket, auth, access_key_id, secret_credential_id) VALUES ('x5', 's3', '', '', '', 'access_key', 'AK', '` + cred.String() + `')`,
		`INSERT INTO destinations (name, kind, account, container, path, auth) VALUES ('x6', 'nfs', '', '', '', 'none')`,
		`INSERT INTO destinations (name, kind, account, container, path, auth) VALUES ('x7', 'nfs', '', '', '/p', 'managed_identity')`,
		`INSERT INTO destinations (name, kind, account, container, auth) VALUES ('x8', 'gcs', 'a', 'c', 'none')`,
	}
	for _, q := range bad {
		if _, err := db.Exec(ctx, q); err == nil {
			t.Fatalf("accepted: %s", q)
		}
	}
}

func TestAzureEndpointOverrideAPI(t *testing.T) {
	ep := azurite(t)
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&destinations.API{DB: e.DB, Log: e.Log, KV: e.KV, Env: e.Envelope, ProbeTimeout: 3 * time.Second}}
	}})
	admin := e.Login(e.Principal("ada", "Member", "admin"))
	c := newContainer(t, ep)
	token := containerSAS(t, c, permsRCWT, time.Now().Add(60*24*time.Hour))
	in := map[string]any{"name": "azurite", "kind": "azure_blob", "account": devAccount, "container": c, "auth": "sas_token",
		"endpoint_override": ep + "/", "sas": map[string]any{"source": "stored", "value": token}}

	// Unsaved test against the cluster-internal Azurite name: accepted by
	// validation (no field error) and used: the probe tries that host, which
	// does not resolve here, so the write step fails.
	cluster := map[string]any{}
	for k, v := range in {
		cluster[k] = v
	}
	cluster["endpoint_override"] = "http://azurite.olympos.svc:10000/devstoreaccount1"
	var rep destinations.Report
	if code := admin.Do("POST", "/api/v1/destinations/test", cluster, &rep); code != 200 || rep.OK ||
		stepOf(&rep, destinations.StepWrite) == nil || stepOf(&rep, destinations.StepWrite).OK {
		t.Fatalf("cluster endpoint test: %d %+v", code, rep)
	}

	var d destinations.View
	if code, body := admin.Raw("POST", "/api/v1/destinations", in); code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	d = findView(t, admin, "azurite")
	if d.EndpointOverride != ep || d.Kind != "azure_blob" || !*d.LastTestOK {
		t.Fatalf("view: %+v", d)
	}
	// PATCH to an unreachable endpoint is refused by the test (proves the
	// override is used), the stored one keeps working.
	if code := admin.Do("PATCH", "/api/v1/destinations/"+d.ID.String(), map[string]any{"endpoint_override": "http://127.0.0.1:1/devstoreaccount1"}, nil); code != 422 {
		t.Fatalf("patch to dead endpoint: %d", code)
	}
	if code := admin.Do("PATCH", "/api/v1/destinations/"+d.ID.String(), map[string]any{"endpoint_override": "ftp://x"}, nil); code != 422 {
		t.Fatalf("invalid endpoint: %d", code)
	}
	if code := admin.Do("POST", "/api/v1/destinations/"+d.ID.String()+"/test", nil, &rep); code != 200 || !rep.OK {
		t.Fatalf("saved test: %d %+v", code, rep)
	}
	// Resolver honours the override for runs.
	w, err := blob.NewResolver(e.DB, e.KV, e.Envelope, nil).ForDestination(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Upload(context.Background(), "run/"+uuid.NewString(), strings.NewReader("x"), "", map[string]string{"olympos-tier": "daily"}); err != nil {
		t.Fatal(err)
	}
}
