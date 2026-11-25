package backup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/targetid"
)

// fakeEngineName uses an engine name allowed by the targets CHECK. The fake
// is registered over the real ClickHouse engine, whose native manifest code
// the native tests use (native_test.go).
const fakeEngineName = "clickhouse"

// fakeEngine dials the target twice, then writes payload.
type fakeEngine struct{}

type fakeOpts struct {
	Fail       bool `json:"fail"`
	LeakSecret bool `json:"leak_secret"`
	NoTLS      bool `json:"no_tls"`
	Payload    int  `json:"payload"`
	// FailAfterWrite: write the payload, then fail.
	FailAfterWrite bool `json:"fail_after_write"`
}

var fakePayload = bytes.Repeat([]byte("olympos-backup-"), 1000)

func (fakeEngine) Name() string        { return fakeEngineName }
func (fakeEngine) Ext() string         { return "tar" }
func (fakeEngine) ContentType() string { return "application/x-tar" }

func (fakeEngine) TestConnection(ctx context.Context, ec backup.EngineContext) (*backup.ConnectionTest, error) {
	var o fakeOpts
	_ = json.Unmarshal(ec.Options, &o)
	c, err := ec.Credential(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := ec.Dial(ctx)
	if err != nil {
		return nil, err
	}
	conn.Close()
	ct := &backup.ConnectionTest{OK: !o.Fail, ServerVersion: "fake 1.0", TLS: !o.NoTLS, Databases: []string{"a", "b"},
		Privileges: []backup.Privilege{{Name: "connect", OK: true, Detail: "as " + c.Username}}}
	if o.LeakSecret {
		ct.Error = "auth failed for password " + string(c.Secret)
		ct.OK = false
	}
	return ct, nil
}

func (fakeEngine) Run(ctx context.Context, ec backup.EngineContext, w io.Writer) (*backup.RunResult, error) {
	var o fakeOpts
	_ = json.Unmarshal(ec.Options, &o)
	c, _ := ec.Credential(ctx) // jobs without a credential are fine for the fake
	for i := 0; i < 2; i++ {
		conn, err := ec.Dial(ctx)
		if err != nil {
			return nil, err
		}
		conn.Close()
	}
	if o.Fail {
		msg := "dump failed"
		if o.LeakSecret {
			msg += ": password=" + string(c.Secret) + " rejected (" + string(c.Secret) + ")"
		}
		return nil, errors.New(msg)
	}
	if _, err := w.Write(fakePayload); err != nil {
		return nil, err
	}
	if o.FailAfterWrite {
		msg := "dump failed after writing"
		if o.LeakSecret {
			msg += ": password=" + string(c.Secret)
		}
		return nil, errors.New(msg)
	}
	tls := !o.NoTLS && ec.UseTLS
	return &backup.RunResult{ServerVersion: "fake 1.0", ToolVersion: "fakedump 2", TLS: &tls, Details: map[string]any{"restore": "cat"}}, nil
}

// CheckOptions mirrors the real engine's method check, which is tested in the
// engine's own package; here it lets the API tests see the field errors.
func (fakeEngine) CheckOptions(raw json.RawMessage, env backup.OptionsEnv) map[string]string {
	var o struct{ Method string }
	_ = json.Unmarshal(raw, &o)
	switch {
	case o.Method != "" && o.Method != "native" && o.Method != "logical":
		return map[string]string{"method": `must be "native" or "logical"`}
	case o.Method == "native" && !env.IngestEnabled:
		return map[string]string{"method": "native backups need the ingest endpoint"}
	}
	return nil
}

func init() { backup.RegisterEngine(fakeEngine{}) }

// fakeDialer pretends agents are connected; every tunnel reports wire bytes.
type fakeDialer struct {
	mu        sync.Mutex
	connected map[uuid.UUID]bool
	dials     int
}

const wirePerConn = 1000

func newDialer(ids ...uuid.UUID) *fakeDialer {
	d := &fakeDialer{connected: map[uuid.UUID]bool{}}
	for _, id := range ids {
		d.connected[id] = true
	}
	return d
}

func (d *fakeDialer) Connected(id uuid.UUID) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connected[id]
}

func (d *fakeDialer) Dial(ctx context.Context, clusterID uuid.UUID, targetID string, opt gateway.DialOptions) (gateway.Conn, error) {
	if !d.Connected(clusterID) {
		return nil, gateway.ErrAgentOffline
	}
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	a, b := net.Pipe()
	b.Close()
	return &fakeConn{Conn: a}, nil
}

type fakeConn struct{ net.Conn }

func (fakeConn) WireBytes() int64 { return wirePerConn }

// fakeBlobs stores uploads in memory. It serves every destination itself,
// unless a destination was given its own fake with dest.
type fakeBlobs struct {
	mu     sync.Mutex
	prefix string
	blobs  map[string][]byte
	tags   map[string]map[string]string
	fail   error
	// failOnly > 0: only that many uploads fail with fail, later ones work.
	failOnly int
	// failAfter > 0: Upload reads that many bytes, then fails (with fail, or
	// a connection reset when fail is nil).
	failAfter int64
	// openErr is what ForDestination returns for this destination.
	openErr error
	// failManifest fails manifest uploads only (the data blob is stored).
	failManifest error
	// wrapReadErr wraps a read error without %w, as the Azure and S3
	// writers do.
	wrapReadErr bool
	// failOn: fail and failAfter apply only to paths that contain it.
	failOn string
	// failTags is what SetTags returns, after failTagsAfter calls that
	// work.
	failTags      error
	failTagsAfter int
	// holdOn: an upload of a path that contains it, once it read its body,
	// closes held and waits for its context to end.
	holdOn   string
	held     chan struct{}
	holdOnce sync.Once
	// uploads counts the stored uploads.
	uploads int
	dests   map[uuid.UUID]*fakeBlobs
}

func newBlobs(prefix string) *fakeBlobs {
	return &fakeBlobs{prefix: prefix, blobs: map[string][]byte{}, tags: map[string]map[string]string{}}
}

// dest gives destination id its own fake writer with prefix.
func (f *fakeBlobs) dest(id uuid.UUID, prefix string) *fakeBlobs {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dests == nil {
		f.dests = map[uuid.UUID]*fakeBlobs{}
	}
	d := newBlobs(prefix)
	f.dests[id] = d
	return d
}

func (f *fakeBlobs) ForDestination(ctx context.Context, id uuid.UUID) (blob.Writer, error) {
	f.mu.Lock()
	d, ok := f.dests[id]
	f.mu.Unlock()
	if !ok {
		d = f
	}
	if d.openErr != nil {
		return nil, d.openErr
	}
	return d, nil
}
func (f *fakeBlobs) Prefix() string { return f.prefix }

func (f *fakeBlobs) Upload(ctx context.Context, path string, r io.Reader, ct string, tags map[string]string) (blob.UploadResult, error) {
	if f.failOn != "" && !strings.Contains(path, f.failOn) {
		return f.storeCtx(ctx, path, r, tags)
	}
	if f.failAfter > 0 {
		_, _ = io.CopyN(io.Discard, r, f.failAfter)
		if f.fail != nil {
			return blob.UploadResult{}, f.fail
		}
		return blob.UploadResult{}, errors.New("connection reset by peer")
	}
	f.mu.Lock()
	failErr := f.fail
	if failErr != nil && f.failOnly > 0 {
		if f.failOnly--; f.failOnly == 0 {
			f.fail = nil
		}
	}
	f.mu.Unlock()
	if failErr != nil {
		return blob.UploadResult{}, failErr
	}
	if f.failManifest != nil && strings.HasSuffix(path, ".manifest.json") {
		return blob.UploadResult{}, f.failManifest
	}
	return f.storeCtx(ctx, path, r, tags)
}

func (f *fakeBlobs) store(path string, r io.Reader, tags map[string]string) (blob.UploadResult, error) {
	return f.storeCtx(context.Background(), path, r, tags)
}

func (f *fakeBlobs) storeCtx(ctx context.Context, path string, r io.Reader, tags map[string]string) (blob.UploadResult, error) {
	b, err := io.ReadAll(r)
	if err == nil && f.holdOn != "" && strings.Contains(path, f.holdOn) {
		f.holdOnce.Do(func() { close(f.held) })
		<-ctx.Done()
		return blob.UploadResult{}, ctx.Err()
	}
	if err != nil {
		if f.wrapReadErr {
			return blob.UploadResult{}, fmt.Errorf("upload %s: %s", path, err)
		}
		return blob.UploadResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.blobs[path]; ok {
		return blob.UploadResult{}, fmt.Errorf("%s already exists; refusing to overwrite", path)
	}
	f.blobs[path] = b
	f.tags[path] = tags
	f.uploads++
	return blob.UploadResult{Bytes: int64(len(b))}, nil
}

// SetTags replaces the tags of a stored blob, as every real writer does.
func (f *fakeBlobs) SetTags(ctx context.Context, path string, tags map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failTags != nil {
		if f.failTagsAfter == 0 {
			return f.failTags
		}
		f.failTagsAfter--
	}
	if _, ok := f.blobs[path]; !ok {
		return fmt.Errorf("%s does not exist", path)
	}
	f.tags[path] = tags
	return nil
}

// fixture is a cluster with one target and a destination.
type fixture struct {
	ClusterID uuid.UUID
	Cluster   string
	TargetID  string
	DestID    uuid.UUID
}

func seed(t *testing.T, db *store.DB, name string, labels map[string]string, status string) fixture {
	t.Helper()
	ctx := context.Background()
	f := fixture{Cluster: name}
	lb, _ := json.Marshal(labels)
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, labels, status, last_seen_at) VALUES ($1, $2, $3, now()) RETURNING id`,
		name, lb, status).Scan(&f.ClusterID); err != nil {
		t.Fatal(err)
	}
	f.TargetID = targetid.Compute(f.ClusterID.String(), "db", "orders", 9000)
	if _, err := db.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine) VALUES ($1,$2,'db','orders',9000,$3)`,
		f.TargetID, f.ClusterID, fakeEngineName); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ($1, 'acct', 'backups', 'olympos', 'managed_identity')
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`, "dest").Scan(&f.DestID); err != nil {
		t.Fatal(err)
	}
	return f
}

// addDest adds another destination.
func addDest(t *testing.T, db *store.DB, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(context.Background(), `INSERT INTO destinations (name, account, container, prefix, auth)
		VALUES ($1, 'acct', 'backups', 'olympos', 'managed_identity') RETURNING id`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// addGroup adds a destination group with members in that order.
func addGroup(t *testing.T, db *store.DB, name string, members ...uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO destination_groups (name) VALUES ($1) RETURNING id`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for i, m := range members {
		if _, err := db.Exec(ctx, `INSERT INTO destination_group_members (group_id, destination_id, position) VALUES ($1,$2,$3)`, id, m, i); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

type jobOpts struct {
	cron, tz   string
	enabled    bool
	last       *time.Time
	options    string
	credential *uuid.UUID
	channel    *uuid.UUID
	group      *uuid.UUID // the job targets this group instead of f.DestID
}

func addJob(t *testing.T, db *store.DB, f fixture, o jobOpts) uuid.UUID {
	t.Helper()
	if o.cron == "" {
		o.cron = "0 2 * * *"
	}
	if o.tz == "" {
		o.tz = "UTC"
	}
	if o.options == "" {
		o.options = "{}"
	}
	dest := &f.DestID
	if o.group != nil {
		dest = nil
	}
	var id uuid.UUID
	if err := db.QueryRow(context.Background(), `INSERT INTO backup_jobs (target_id, destination_id, destination_group_id, cron, timezone, enabled,
		last_scheduled_for, engine_options, credential_id, notify_channel_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		f.TargetID, dest, o.group, o.cron, o.tz, o.enabled, o.last, o.options, o.credential, o.channel).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func addChannel(t *testing.T, db *store.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(context.Background(), `INSERT INTO notification_channels (slack_channel_id, name) VALUES ('C123', 'backups') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

type event struct {
	Type    string
	Channel *uuid.UUID
	Payload map[string]any
}

func events(t *testing.T, db *store.DB, typ string) []event {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT event_type, channel_id, payload FROM outbox WHERE event_type LIKE $1 ORDER BY created_at`, typ)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []event
	for rows.Next() {
		var e event
		var p []byte
		if err := rows.Scan(&e.Type, &e.Channel, &p); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(p, &e.Payload)
		out = append(out, e)
	}
	return out
}

func ptr[T any](v T) *T { return &v }

// yearly gives a retry window of weeks: half the time to the next 1 January.
const yearly = "0 0 1 1 *"

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("%q does not contain %q", s, sub)
	}
}

type pgxTx = pgx.Tx

func pbTarget(id string) *pb.Target { return &pb.Target{TargetId: id} }
