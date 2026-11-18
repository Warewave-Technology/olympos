//go:build dev

package backup_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// A run through the real resolver lands on an NFS destination: data file,
// manifest and their tags sidecars, written once, never overwritten.
func TestWorkerNFSDestination(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	f := seed(t, db, "prod-aks", nil, "online")
	root := filepath.Join(t.TempDir(), "nfs")
	if err := os.MkdirAll(filepath.Join(root, "backup-nas"), 0o755); err != nil {
		t.Fatal(err)
	}
	var destID uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO destinations (name, kind, account, container, prefix, auth, path)
		VALUES ('nas', 'nfs', '', '', 'olympos', 'none', $1) RETURNING id`, filepath.Join(root, "backup-nas", "backups")).Scan(&destID); err != nil {
		t.Fatal(err)
	}
	f.DestID = destID
	job := addJob(t, db, f, jobOpts{enabled: true})

	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	w := &backup.Worker{DB: db, Log: quietLog(), Dialer: newDialer(f.ClusterID),
		Blobs: blob.NewResolver(db, kv, &secrets.Envelope{KV: kv}, nil, blob.WithStorage(blob.StorageOptions{NFSRoot: root})),
		Creds: &backup.Credentials{KV: kv, Envelope: &secrets.Envelope{KV: kv}}, Global: 4, PerCluster: 1}

	at := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	run := queue(t, db, job, "schedule", &at)
	claimAndRun(t, w, run)
	r := loadRun(t, db, run)
	if r.Status != "succeeded" || r.Error != "" {
		t.Fatalf("run: %+v", r)
	}
	sum := sha256.Sum256(fakePayload)
	if r.SHA != hex.EncodeToString(sum[:]) || r.Bytes != int64(len(fakePayload)) {
		t.Fatalf("sha/bytes: %+v", r)
	}
	dir := filepath.Join(root, "backup-nas", "backups")
	file := filepath.Join(dir, filepath.FromSlash(r.BlobPath))
	data, err := os.ReadFile(file)
	if err != nil || string(data) != string(fakePayload) {
		t.Fatalf("backup file %s: %v", file, err)
	}
	var tags map[string]string
	tb, _ := os.ReadFile(file + blob.TagsSuffix)
	if json.Unmarshal(tb, &tags) != nil || tags[backup.TierTag] != r.Tier || r.Tier == "" {
		t.Fatalf("tags sidecar %s (tier %s)", tb, r.Tier)
	}
	mfile := filepath.Join(dir, filepath.FromSlash(backup.ManifestPath(r.BlobPath, run)))
	mb, err := os.ReadFile(mfile)
	if err != nil {
		t.Fatal(err)
	}
	var m backup.Manifest
	if err := json.Unmarshal(mb, &m); err != nil || m.RunID != run || m.Blob.SHA256 != r.SHA || m.Blob.Size != r.Bytes || m.Tier != r.Tier ||
		m.Blob.Path != r.BlobPath {
		t.Fatalf("manifest: %+v %v", m, err)
	}
	if _, err := os.Stat(mfile + blob.TagsSuffix); err != nil {
		t.Fatal("manifest tags sidecar missing")
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(file), "*.partial"))
	if len(matches) != 0 {
		t.Fatalf("partial files left: %v", matches)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}

	// A destination path that left the mount fails the run clearly.
	if _, err := db.Exec(ctx, `UPDATE destinations SET path = $2 WHERE id = $1`, destID, filepath.Join(filepath.Dir(root), "elsewhere")); err != nil {
		t.Fatal(err)
	}
	run2 := queue(t, db, job, "manual", nil)
	claimAndRun(t, w, run2)
	if r2 := loadRun(t, db, run2); r2.Status != "failed" {
		t.Fatalf("run outside mount: %+v", r2)
	} else {
		mustContain(t, r2.Error, "open destination")
	}
}
