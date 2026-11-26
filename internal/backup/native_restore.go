package backup

// The restore check of a native backup (design docs/design/clickhouse-native.md
// §6 and §7, task 16). A restore reads one copy of a native run: its
// directory on one destination. The copy's chain is the run's base chain,
// the full first (its backup credential's read scope, as selectBase reads
// it), and the run itself. Every run of the chain must have a succeeded copy
// on the copy's destination; their sidecars are read from there, at most
// MaxNativeSidecarBytes each, and the engine verifies the signed manifests
// as a chain (VerifyNativeChain's rules), then reads each object's
// definition from the chain through chainSource, which serves only objects
// the verified manifests list and checks each against its size and SHA-256,
// and decides what the restore creates. A copy whose chain does not verify
// is never restored (ErrNativeNotVerified).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// NativeRestoreEngine is implemented by engines whose native backups are
// restored (ClickHouse).
type NativeRestoreEngine interface {
	// CheckNativeRestore verifies in.Signed as the chain of run in.RunID,
	// the full first, binds the verified manifests for reads (in.Bind),
	// reads the definitions of the selected databases' objects through the
	// reader it gets, and decides for each whether the restore creates it.
	// A chain that does not verify, or an object that cannot be read, is
	// ErrNativeNotVerified; a chain that verifies but cannot be restored
	// here is ErrNativeChain. With ErrNativeNotVerified the result, when not
	// nil, lists what the copy's own signed manifest holds, every object
	// left out; it is never bound for reads.
	CheckNativeRestore(ctx context.Context, in NativeRestoreInput) (*NativeRestoreCheck, error)
}

// NativeRestoreInput is what an engine checks a native restore with.
type NativeRestoreInput struct {
	// KV and KeyName verify the manifests (keyVault.manifestKeyName).
	KV      secrets.KeyVault
	KeyName string
	// RunID is the copy's run, the chain's last.
	RunID string
	// Signed are the chain's signed manifests as stored, the full first.
	Signed [][]byte
	// IngestURL is ingest.url: an incremental's .backup names its base by
	// its URL under the endpoint it was taken through, and the restore's
	// ClickHouse reads it there.
	IngestURL string
	// Bind takes the verified manifests, in the order of Signed, and returns
	// the reader of the chain's objects: only those the manifests list,
	// each checked against its size and SHA-256.
	Bind func(ms []NativeChainManifest) (NativeObjectReader, error)
	// Databases are the selected databases; empty selects every one.
	Databases []string
}

// NativeObjectReader returns an object of a verified chain whole, by
// bucket-relative key, at most limit bytes.
type NativeObjectReader func(ctx context.Context, key string, limit int64) ([]byte, error)

// NativeDecision is what a native restore does with one object of the
// backup: Allowed objects are created by the restore; the others are left
// out, with the reason shown to the maker and the checker.
type NativeDecision struct {
	Database string `json:"database"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`
}

// NativeRestoreCheck is what the check of a native copy found.
type NativeRestoreCheck struct {
	// Databases are every database of the backup, in the manifest's order.
	Databases []string
	// Objects are the decisions for the objects of the selected databases.
	Objects []NativeDecision
	// Manifests are the chain's verified manifests, the full first; nil
	// when the chain does not verify.
	Manifests []NativeChainManifest
}

var (
	// ErrNativeNotVerified: the copy's chain was not read and verified
	// whole: a sidecar could not be read, a manifest or a link does not
	// verify, or an object does not match its manifest. Its message is
	// what the check shows; the cause is logged, never shown.
	ErrNativeNotVerified = errors.New("the backup's manifest does not verify")
	// ErrNativeChain: the copy's chain cannot be restored from this
	// destination or through this endpoint; the error says why.
	ErrNativeChain = errors.New("the backup chain cannot be restored")
)

// NativeRestoreConfig is what a native restore needs from the server.
type NativeRestoreConfig struct {
	// KV and ManifestKeyName verify the manifests.
	KV              secrets.KeyVault
	ManifestKeyName string
	// URL is ingest.url.
	URL string
}

// NativeRestore is a native copy checked for a restore: the chain, read
// from the copy's destination and verified, and the decisions for the
// selected databases. Source serves the chain to the restore's ClickHouse.
type NativeRestore struct {
	NativeRestoreCheck
	// Runs are the chain's runs, the full first, the copy's run last.
	Runs []uuid.UUID
	src  *chainSource
}

// Source serves the chain's objects as the verified manifests list them,
// each checked against its manifest while it streams; nil when the chain
// was not verified.
func (n *NativeRestore) Source() ingest.Source {
	if n.src == nil {
		return nil
	}
	return n.src
}

// nativeRestoreSlots bounds how many native checks read their chain at
// once: a chain holds up to nativeMaxChain sidecars of up to
// MaxNativeSidecarBytes in memory while it is verified.
var nativeRestoreSlots = make(chan struct{}, 1)

// CheckNativeRestore resolves the chain of the native copy src, reads its
// sidecars from r (the copy's destination), and has eng verify and decide
// for databases (empty: every one). Errors are ErrNativeChain or
// ErrNativeNotVerified, with the cause, and internal errors of q. With
// ErrNativeNotVerified the result may list the decisions eng could make
// (every object left out); the caller shows ErrNativeNotVerified's message
// only and logs the cause.
func CheckNativeRestore(ctx context.Context, q store.Querier, r blob.Reader, eng NativeRestoreEngine, cfg NativeRestoreConfig,
	src *RestoreSource, databases []string, log *slog.Logger) (*NativeRestore, error) {
	runs, copies, err := restoreChain(ctx, q, src)
	if err != nil {
		return nil, err
	}
	select {
	case nativeRestoreSlots <- struct{}{}:
		defer func() { <-nativeRestoreSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	signed := make([][]byte, len(runs))
	for i, run := range runs {
		raw, err := readSidecarManifest(ctx, r, ManifestPath(copies[i].dir, run))
		if err != nil {
			return nil, fmt.Errorf("%w: the manifest of run %s: %v", ErrNativeNotVerified, run, err)
		}
		signed[i] = raw
	}
	var cs *chainSource
	bind := func(ms []NativeChainManifest) (NativeObjectReader, error) {
		if len(ms) != len(runs) {
			return nil, fmt.Errorf("%d manifests for a chain of %d runs", len(ms), len(runs))
		}
		dirs := make([]string, len(runs))
		for i, m := range ms {
			if m.RunID != runs[i].String() || m.SHA256 != copies[i].sha256 {
				return nil, fmt.Errorf("the manifest of run %s is not the one its copy was written with", runs[i])
			}
			dirs[i] = copies[i].dir
		}
		s, err := newChainSourceOn(r, dirs, ms, log)
		if err != nil {
			return nil, err
		}
		cs = s
		return s.read, nil
	}
	check, err := eng.CheckNativeRestore(ctx, NativeRestoreInput{KV: cfg.KV, KeyName: cfg.ManifestKeyName, RunID: src.CopyRunID.String(),
		Signed: signed, IngestURL: cfg.URL, Bind: bind, Databases: databases})
	var out *NativeRestore
	if check != nil {
		out = &NativeRestore{NativeRestoreCheck: *check, Runs: runs}
	}
	switch {
	case err == nil && (check == nil || cs == nil):
		return out, fmt.Errorf("%w: the engine did not bind the chain", ErrNativeNotVerified)
	case errors.Is(err, ErrNativeChain) || errors.Is(err, ErrNativeNotVerified):
		return out, err
	case err != nil:
		return out, fmt.Errorf("%w: %v", ErrNativeNotVerified, err)
	}
	out.src = cs
	return out, nil
}

// restoreChain is the chain of the native copy src, the full first, and
// each run's succeeded copy on src's destination: the copy's run and its
// backup credential's read scope (its base chain, as selectBase gave it),
// at most nativeMaxChain runs.
func restoreChain(ctx context.Context, q store.Querier, src *RestoreSource) ([]uuid.UUID, []chainCopy, error) {
	run := src.CopyRunID
	var read []byte
	err := q.QueryRow(ctx, `SELECT COALESCE(scope -> 'read', '[]'::jsonb) FROM ingest_credentials WHERE run_id = $1 AND kind = 'backup'`, run).Scan(&read)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, fmt.Errorf("%w: run %s has no record of the chain it was taken on", ErrNativeChain, run)
	}
	if err != nil {
		return nil, nil, err
	}
	var prefixes []string
	if err := json.Unmarshal(read, &prefixes); err != nil {
		return nil, nil, fmt.Errorf("%w: the base chain of run %s is not readable", ErrNativeChain, run)
	}
	if len(prefixes)+1 > nativeMaxChain {
		return nil, nil, fmt.Errorf("%w: its chain has %d runs, more than the %d a restore reads", ErrNativeChain, len(prefixes)+1, nativeMaxChain)
	}
	runs := make([]uuid.UUID, 0, len(prefixes)+1)
	for _, p := range prefixes {
		id, err := uuid.Parse(strings.TrimSuffix(p, "/"))
		if err != nil || id.String()+"/" != p {
			return nil, nil, fmt.Errorf("%w: the base chain of run %s holds %q, not a run's prefix", ErrNativeChain, run, p)
		}
		runs = append(runs, id)
	}
	runs = append(runs, run)

	rows, err := q.Query(ctx, `SELECT run_id, blob_path, sha256 FROM backup_run_copies
		WHERE run_id = ANY($1) AND destination_id = $2 AND status = 'succeeded'`, runs, src.DestinationID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	found := map[uuid.UUID]chainCopy{}
	for rows.Next() {
		var id uuid.UUID
		var cc chainCopy
		if err := rows.Scan(&id, &cc.dir, &cc.sha256); err != nil {
			return nil, nil, err
		}
		found[id] = cc
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	copies := make([]chainCopy, len(runs))
	for i, id := range runs {
		cc, ok := found[id]
		if !ok || cc.dir == "" {
			return nil, nil, fmt.Errorf("%w: run %s of its chain has no succeeded copy on %s", ErrNativeChain, id, src.DestinationName)
		}
		copies[i] = cc
	}
	return runs, copies, nil
}
