package clickhouse

// The restore check of a native backup (design docs/design/clickhouse-native.md
// §6, task 16): the copy's chain verifies (VerifyChain), every incremental of
// it was taken through the endpoint the restore uses, and the allowlist
// decides for the selected databases, from the definitions read through the
// chain's checked reader. What the restore then runs is task 17's.

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

var _ backup.NativeRestoreEngine = Engine{}

// CheckNativeRestore implements backup.NativeRestoreEngine.
//
// When the chain does not verify, nothing of it is read: the copy's own
// manifest is verified alone (VerifySigned), and when it verifies, the
// objects of the selected databases it lists are returned, every one left
// out because the backup's manifest does not verify, with the error. A
// manifest that verifies alone vouches for what the backup holds, not for
// the DDL it takes from other runs (VerifySigned), so nothing is allowed on
// it.
func (Engine) CheckNativeRestore(ctx context.Context, in backup.NativeRestoreInput) (*backup.NativeRestoreCheck, error) {
	ms, err := VerifyChain(ctx, in.KV, in.KeyName, in.RunID, in.Signed)
	if err != nil {
		return unverifiedCheck(ctx, in), fmt.Errorf("%w: %v", backup.ErrNativeNotVerified, err)
	}
	last := ms[len(ms)-1]
	check := &backup.NativeRestoreCheck{Databases: []string{}, Objects: []backup.NativeDecision{}}
	for _, d := range last.Databases {
		check.Databases = append(check.Databases, d.Name)
	}
	// Each incremental's BACKUP named its base by URL (statementSettings),
	// and its .backup keeps that URL: the restore's ClickHouse reads the
	// base from there, so it must be the endpoint the restore is served on.
	for i := 1; i < len(ms); i++ {
		want := "S3(" + quoteString(backup.NativeRunURL(in.IngestURL, ms[i-1].RunID)) + ")"
		if got := ms[i].Settings["base_backup"]; got != want {
			return check, fmt.Errorf("%w: run %s was taken through another ingest endpoint (its base is %s), and ClickHouse would read its base "+
				"from there; restore a full backup, or a run whose chain was taken through ingest.url as it is now",
				backup.ErrNativeChain, ms[i].RunID, short(strings.TrimSuffix(strings.TrimPrefix(got, "S3('"), "')")))
		}
	}
	chain := make([]backup.NativeChainManifest, len(ms))
	for i, m := range ms {
		chain[i] = backup.NativeChainManifest{RunID: m.RunID, SHA256: m.SHA256(), Objects: slices.Clone(m.Objects)}
	}
	read, err := in.Bind(chain)
	if err != nil {
		return check, fmt.Errorf("%w: %v", backup.ErrNativeNotVerified, err)
	}
	selected := selectedDatabases(in.Databases)
	ddl := map[string][]byte{}
	for _, d := range last.Databases {
		if selected != nil && !selected[d.Name] {
			continue
		}
		for _, o := range d.Objects {
			if _, ok := ddl[o.DDLKey]; ok {
				continue
			}
			// The manifest was built only from definitions up to
			// maxSchemaEntry (ObjectsFromMetadata).
			b, err := read(ctx, o.DDLKey, maxSchemaEntry)
			if err != nil {
				return check, fmt.Errorf("%w: the definition of %s.%s: %v", backup.ErrNativeNotVerified, clip(d.Name), clip(o.Name), err)
			}
			ddl[o.DDLKey] = b
		}
	}
	for _, dec := range classify(last.Databases, selected, ddl) {
		check.Objects = append(check.Objects, backup.NativeDecision(dec))
	}
	check.Manifests = chain
	return check, nil
}

// unverifiedCheck lists the objects of the selected databases that the
// copy's own manifest holds, when it verifies alone and is the one its copy
// row records (in.SHA256), every one left out; none otherwise.
func unverifiedCheck(ctx context.Context, in backup.NativeRestoreInput) *backup.NativeRestoreCheck {
	check := &backup.NativeRestoreCheck{Databases: []string{}, Objects: []backup.NativeDecision{}}
	if len(in.Signed) == 0 {
		return check
	}
	// It must also be the manifest the copy row records: a sidecar copied
	// from another copy of the run, or one written again, lists nothing.
	m, err := VerifySigned(ctx, in.KV, in.KeyName, in.RunID, in.Signed[len(in.Signed)-1])
	if err != nil || m.SHA256() != in.SHA256 {
		return check
	}
	selected := selectedDatabases(in.Databases)
	for _, d := range m.Databases {
		check.Databases = append(check.Databases, d.Name)
		if selected != nil && !selected[d.Name] {
			continue
		}
		for _, o := range d.Objects {
			check.Objects = append(check.Objects, backup.NativeDecision{Database: d.Name, Name: o.Name, Kind: o.Kind,
				Reason: backup.ErrNativeNotVerified.Error()})
		}
	}
	return check
}

// selectedDatabases is the set of names (trimmed, as the restore takes
// them); nil selects every database.
func selectedDatabases(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, n := range names {
		out[strings.TrimSpace(n)] = true
	}
	return out
}
