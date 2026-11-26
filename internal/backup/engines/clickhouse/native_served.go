package clickhouse

// What a native restore's credential may read (security review v0.4,
// finding 5): the RESTORE of the selected databases reads the .backup of
// every run of the chain, the definitions of those databases and the data
// of the objects it creates; the source serves only those objects, so the
// target, which holds the credential while the restore runs, can read
// nothing else of the backup.

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/ingest"
)

// NativeServed implements backup.NativeRestoreEngine: the keys of the objects of the
// chain ms (the full first) that the RESTORE of decisions reads, resolved as
// ClickHouse resolves them. A file of the last run is needed when it is a
// definition of a selected database (metadata/<db>.sql, metadata/<db>/…) or
// a file of an allowed object's data (data/<db>/<name>/…). ClickHouse reads
// a file by its size and checksum, from the first file of its .backup with
// them: that file's own object, or the one its data_file names, and for
// what the base holds (all of it, or the first base_size bytes) the base's
// first file of that size and checksum, run by run back to the full. Every
// run's .backup is served too: ClickHouse opens each one. The .backup files
// are read through read, one run at a time.
func (Engine) NativeServed(ctx context.Context, read backup.NativeObjectReader, ms []backup.NativeChainManifest, databases []string,
	decisions []backup.NativeDecision) (map[string]bool, error) {
	if len(ms) == 0 {
		return nil, fmt.Errorf("%w: no manifest", backup.ErrNativeChain)
	}
	selected := selectedDatabases(databases)
	data := map[string]bool{} // "data/<db>/<name>/" of every allowed object
	for _, d := range decisions {
		if selected != nil && !selected[d.Database] {
			return nil, fmt.Errorf("%w: a decision for %s.%s, of a database not selected", backup.ErrNativeChain, clip(d.Database), clip(d.Name))
		}
		if d.Allowed {
			data["data/"+escapeForFileName(d.Database)+"/"+escapeForFileName(d.Name)+"/"] = true
		}
	}
	needed := func(name string) bool {
		if rest, ok := strings.CutPrefix(name, "metadata/"); ok {
			db, _, _ := strings.Cut(strings.TrimSuffix(rest, ".sql"), "/")
			n, ok := unescapeFileName(db)
			return ok && (selected == nil || selected[n])
		}
		if rest, ok := strings.CutPrefix(name, "data/"); ok {
			segs := strings.SplitN(rest, "/", 3)
			return len(segs) == 3 && data["data/"+segs[0]+"/"+segs[1]+"/"]
		}
		return false
	}

	served := map[string]bool{}
	for _, m := range ms {
		served[m.RunID+"/.backup"] = true
	}
	// pending are the contents run k is to give: what the run after it
	// takes from its base.
	pending := map[contentKey]bool{}
	for k := len(ms) - 1; k >= 0; k-- {
		if k < len(ms)-1 && len(pending) == 0 {
			break
		}
		raw, err := read(ctx, ms[k].RunID+"/.backup", MaxBackupMetaBytes)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("%w: the .backup of run %s: %v", backup.ErrNativeNotVerified, ms[k].RunID, err)
		}
		meta, err := ParseBackupMeta(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: the .backup of run %s: %v", backup.ErrNativeChain, ms[k].RunID, err)
		}
		holders := meta.holders()
		var wants []contentKey
		if k == len(ms)-1 {
			for _, f := range meta.Files {
				if f.Size > 0 && needed(f.Name) {
					wants = append(wants, f.content())
				}
			}
		} else {
			for c := range pending {
				wants = append(wants, c)
			}
		}
		next := map[contentKey]bool{}
		for _, c := range wants {
			i, ok := holders[c]
			if !ok {
				return nil, fmt.Errorf("%w: run %s has no file of %d bytes with checksum %s, which the restore reads from it",
					backup.ErrNativeChain, ms[k].RunID, c.size, clip(c.checksum))
			}
			h := meta.Files[i]
			if h.UseBase && h.BaseSize == h.Size {
				next[c] = true
				continue
			}
			name := h.Name
			if h.DataFile != "" {
				name = h.DataFile
			}
			key := ms[k].RunID + "/" + name
			if !slices.ContainsFunc(ms[k].Objects, func(o ingest.ObjectRecord) bool { return o.Key == key }) {
				return nil, fmt.Errorf("%w: the restore reads %s, which the manifest of run %s does not list", backup.ErrNativeChain, clip(key), ms[k].RunID)
			}
			served[key] = true
			if h.UseBase {
				next[contentKey{h.BaseSize, h.BaseChecksum}] = true
			}
		}
		if len(next) > 0 && k == 0 {
			return nil, fmt.Errorf("%w: the full run %s takes files from a base", backup.ErrNativeChain, ms[0].RunID)
		}
		pending = next
	}
	return served, nil
}
