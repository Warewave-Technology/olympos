package restore

// The execution of a native restore request (design
// docs/design/clickhouse-native.md §6 Execute, task 17): the copy's chain is
// checked again and must decide exactly what the request was approved with
// (R50), the target is checked again, a read-only ingest credential is
// minted over the chain, and the engine has the target RESTORE it, reading
// through the endpoint only what the chain's verified manifests list, each
// object checked while it streams.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/ingest"
)

const (
	// errNativeChanged: the check at start does not decide what the
	// request was approved with (R50).
	errNativeChanged = "the backup changed since the request was approved: the objects the restore would leave out are not the ones " +
		"approved; nothing was written to the target; open a new request"
	// errNativeUnrecorded: the request records no decisions (opened before
	// they were recorded), so none were approved.
	errNativeUnrecorded = "the request does not record the objects the restore leaves out, so they were not approved; " +
		"nothing was written to the target; open a new request"
	// errNativeBusy: the ingest endpoint has no session left.
	errNativeBusy = "too many native backups and restores run on this server now (ingest.maxRuns); nothing was written to the target; " +
		"open a new request later"
	// nativeRestoreEnded is the revoke reason of a restore's credential.
	nativeRestoreEnded = "restore ended"
	// nativeRestoreTTL is the credential's lifetime when MaxRunDuration is
	// 0, as a backup's.
	nativeRestoreTTL = 6 * time.Hour
)

// performNative executes a native request whose rules passed (perform).
func (x *Executor) performNative(ctx context.Context, j *job, src *backup.RestoreSource, pw *progressWriter, res *backup.RestoreResult,
	tr *backup.SecretScrubber) (*backup.RestoreResult, string) {
	fail := func(msg string) (*backup.RestoreResult, string) { return res, tr.Scrub(msg) }
	internal := func(what string, err error) (*backup.RestoreResult, string) {
		x.Log.Error("restore: "+what, "restore_id", j.id, "err", tr.Scrub(err.Error()))
		return res, "internal error: could not " + what
	}
	cfg := x.Native
	if cfg == nil || cfg.Registry == nil {
		return fail(errNativeIngestOff + "; nothing was read or written")
	}
	eng, _ := backup.EngineFor(j.engine)
	checker, ok := eng.(backup.NativeRestoreEngine)
	restorer, _ := backup.RestorerFor(j.engine)
	runner, ok2 := restorer.(backup.NativeRestorer)
	if !ok || !ok2 {
		return fail(errNativeEngine)
	}
	if _, ok := InspectorFor(j.engine); !ok {
		return fail(noInspectorMessage(j.engine))
	}
	if j.opts.Native == nil {
		return fail(errNativeUnrecorded)
	}

	// 2. The chain again (time passed since the approval): read from the
	// copy's destination, verified, and decided for the request's
	// databases. The check's slot is held only for this; what the restore
	// keeps of it is the source (its own bound) and the decisions.
	pw.phase("verify")
	rd, err := x.Blobs.ReaderFor(ctx, src.DestinationID)
	if err != nil {
		return fail("open the backup's destination: " + err.Error())
	}
	var run backup.NativeRestoreRun
	var source *backup.NativeRestoreSource
	var prefixes []string
	changed, refused := false, ""
	err = backup.WithNativeRestore(ctx, x.DB, rd, checker, *cfg, src, j.databases, x.Log, func(n *backup.NativeRestore) error {
		if n.Source() == nil {
			return nil // not verified: WithNativeRestore returns why
		}
		if msg := refusedDatabases(n.RefusedDatabases); msg != "" {
			refused = msg
			return nil
		}
		if !sameNative(nativeOptions(j.databases, n.Objects), j.opts.Native) {
			changed = true
			return nil
		}
		s, err := n.RestoreSource()
		if err != nil {
			return err // ErrNativeChain: why the chain is not served
		}
		source = s
		run.Decisions, run.DDL, run.Rows = n.Objects, n.DDL, n.Rows
		for _, id := range n.Runs {
			prefixes = append(prefixes, id.String()+"/")
		}
		return nil
	})
	switch {
	case ctx.Err() != nil:
		return fail("the restore was interrupted before it started; nothing was written to the target")
	case errors.Is(err, backup.ErrNativeChain):
		return fail("the restore cannot start: " + err.Error() + "; nothing was written to the target")
	case errors.Is(err, backup.ErrNativeNotVerified):
		x.Log.Warn("restore: the native backup does not verify", "restore_id", j.id, "copy_run_id", src.CopyRunID,
			"destination_id", src.DestinationID, "err", err.Error())
		return fail("the restore cannot start: " + backup.ErrNativeNotVerified.Error() + "; nothing was written to the target")
	case err != nil:
		return internal("check the native backup", err)
	case refused != "":
		return fail("the restore cannot start: " + refused + "; nothing was written to the target")
	case changed:
		x.Log.Warn("restore: a native request does not decide what it was approved with", "restore_id", j.id)
		return fail(errNativeChanged)
	}

	// 3. The target again, over the tunnel and with the request's
	// credential (reads only).
	pw.phase("check")
	ec, opts, _, msg, err := x.checkTarget(ctx, j, tr, res)
	if err != nil {
		return internal("build the target's connection", err)
	}
	if msg != "" {
		return fail(msg)
	}
	raw, err := json.Marshal(opts)
	if err != nil {
		return internal("encode the options", err)
	}

	// 4. The credential: read-only over the chain, minted now (design §2),
	// served by the source; revoked when the engine returns.
	ttl := cfg.MaxRunDuration
	if ttl <= 0 {
		ttl = nativeRestoreTTL
	}
	sess, cred, err := cfg.Registry.Open(ctx, ingest.OpenOptions{RunID: j.id, Kind: ingest.KindRestore,
		Scope: ingest.Scope{Read: prefixes}, TTL: ttl, Source: source})
	if errors.Is(err, ingest.ErrTooManyRuns) {
		return fail(errNativeBusy)
	}
	if err != nil {
		return internal("open the ingest session", err)
	}
	defer sess.Revoke(nativeRestoreEnded)
	tr.Track(backup.Credential{Secret: []byte(cred.Secret)})
	run.URL, run.RunID = backup.NativeRunURL(cfg.URL, src.CopyRunID.String()), src.CopyRunID.String()
	run.AccessKey, run.Secret, run.Stop = cred.AccessKey, cred.Secret, sess.Stopped()
	x.Log.Info("restore: native restore starting", "restore_id", j.id, "copy_run_id", src.CopyRunID, "runs", len(prefixes),
		"objects", source.Objects(), "access_key", cred.AccessKey)

	// 5. The engine.
	pw.phase("restore")
	rc := backup.RestoreContext{EngineContext: ec, RequestID: j.id.String(), Databases: j.databases, Options: raw, Progress: pw.report}
	out, err := runner.RestoreNativeBackup(ctx, rc, run)
	sess.Revoke(nativeRestoreEnded)
	failed := ""
	if key := source.Failed(); key != "" {
		// The endpoint aborted the GET of an object that is not the one
		// signed: that, not what the target made of it, is why.
		// The target's own error is not added: what it says is about the
		// aborted read, and it may quote the backup's DDL (R52).
		failed = fmt.Sprintf("the restore failed: the backup's object %s does not match its signed manifest; its read was aborted", key)
	}
	return x.restored(res, out, err, tr, failed)
}

// sameNative reports whether two records of decisions are the same, as
// they are stored.
func sameNative(a, b *NativeOptions) bool {
	ja, err1 := json.Marshal(a)
	jb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(ja, jb)
}
