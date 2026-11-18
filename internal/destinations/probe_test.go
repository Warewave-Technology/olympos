package destinations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/destinations"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

func stepOK(rep destinations.Report, name string) (bool, bool) {
	for _, s := range rep.Steps {
		if s.Name == name {
			return s.OK, true
		}
	}
	return false, false
}

func TestProbeAzurite(t *testing.T) {
	ep := azurite(t)
	p := &destinations.Prober{}
	target := func(c, token string) blob.Target {
		return blob.Target{Name: "t", Account: devAccount, Container: c, Prefix: "olympos/prod", Auth: blob.AuthSAS, EndpointOverride: ep, SAS: token}
	}

	t.Run("rcwt: ok and delete refused", func(t *testing.T) {
		c := newContainer(t, ep)
		rep := p.Test(context.Background(), target(c, containerSAS(t, c, permsRCWT, time.Now().Add(30*24*time.Hour))))
		if !rep.OK || rep.CanDelete {
			t.Fatalf("report: %+v", rep)
		}
		for _, s := range []string{destinations.StepSASExpiry, destinations.StepSASPermissions, destinations.StepWrite, destinations.StepRead,
			destinations.StepTag, destinations.StepDeleteRefused} {
			if ok, found := stepOK(rep, s); !ok || !found {
				t.Errorf("step %s: ok=%v found=%v (%+v)", s, ok, found, rep.Steps)
			}
		}
		if !strings.HasPrefix(rep.ProbePath, "olympos/prod/.olympos-probe/") {
			t.Fatalf("probe path %q", rep.ProbePath)
		}
		if rep.SAS == nil || rep.SAS.Scope != destinations.ScopeContainer || len(rep.SAS.Missing) != 0 {
			t.Fatalf("sas: %+v", rep.SAS)
		}
	})

	t.Run("account key SAS with d: saved with warning", func(t *testing.T) {
		c := newContainer(t, ep)
		rep := p.Test(context.Background(), target(c, containerSAS(t, c, permsRCWTD, time.Now().Add(30*24*time.Hour))))
		if !rep.OK || !rep.CanDelete {
			t.Fatalf("expected ok with can_delete warning: %+v", rep)
		}
		if ok, _ := stepOK(rep, destinations.StepDeleteRefused); ok {
			t.Fatal("delete_refused step must fail when delete succeeds")
		}
		if !rep.SAS.CanDelete() || strings.Join(rep.SAS.Extra, ",") != "d" {
			t.Fatalf("sas: %+v", rep.SAS)
		}
	})

	t.Run("missing permissions", func(t *testing.T) {
		c := newContainer(t, ep)
		rep := p.Test(context.Background(), target(c, containerSAS(t, c, permsRW, time.Now().Add(30*24*time.Hour))))
		if rep.OK || strings.Join(rep.SAS.Missing, ",") != "c,t" {
			t.Fatalf("report: %+v", rep)
		}
		if ok, _ := stepOK(rep, destinations.StepSASPermissions); ok {
			t.Fatal("sas_permissions must fail")
		}
	})

	t.Run("expired SAS fails fast", func(t *testing.T) {
		c := newContainer(t, ep)
		rep := p.Test(context.Background(), target(c, containerSAS(t, c, permsRCWT, time.Now().Add(-time.Hour))))
		if rep.OK || !strings.Contains(rep.Error, "expired") {
			t.Fatalf("report: %+v", rep)
		}
		if _, found := stepOK(rep, destinations.StepWrite); found {
			t.Fatal("no storage call expected for an expired SAS")
		}
	})

	t.Run("wrong signature", func(t *testing.T) {
		c := newContainer(t, ep)
		tok := containerSAS(t, c, permsRCWT, time.Now().Add(24*time.Hour))
		bad := strings.Replace(tok, "sig="+sigOf(tok), "sig="+url.QueryEscape("AAAA"+strings.Repeat("B", 40)+"="), 1)
		rep := p.Test(context.Background(), target(c, bad))
		if rep.OK {
			t.Fatalf("report: %+v", rep)
		}
		if strings.Contains(rep.Error+stepsText(rep), "AAAABBBB") {
			t.Fatalf("signature leaked in report: %+v", rep)
		}
	})
}

func stepsText(rep destinations.Report) string {
	var b strings.Builder
	for _, s := range rep.Steps {
		b.WriteString(s.Detail)
	}
	return b.String()
}

func TestUploadAzurite(t *testing.T) {
	ep := azurite(t)
	c := newContainer(t, ep)
	az, err := blob.Open(blob.Target{Account: devAccount, Container: c, Auth: blob.AuthSAS, EndpointOverride: ep,
		SAS: containerSAS(t, c, permsRCWT, time.Now().Add(time.Hour))}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// 21 MiB + a bit from a stream (several blocks, never fully buffered by us).
	const size = 21<<20 + 12345
	src := io.LimitReader(rand.NewChaCha8([32]byte{7}), size)
	want := sha256.New()
	path := blob.Join("pfx", "prod", "db", "orders-pg", "postgresql", "2026", "11", "18", uuid.NewString()+".dump")
	res, err := az.Upload(context.Background(), path, io.TeeReader(src, want), "application/octet-stream", map[string]string{"olympos-tier": "daily"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != size || res.SHA256 != hex.EncodeToString(want.Sum(nil)) {
		t.Fatalf("result %+v", res)
	}
	tags, err := az.GetTags(context.Background(), path)
	if err != nil || tags["olympos-tier"] != "daily" {
		t.Fatalf("tags %v %v", tags, err)
	}
	head, err := az.Download(context.Background(), path, 16)
	if err != nil || len(head) != 16 {
		t.Fatalf("download %v %v", head, err)
	}
	// Never overwrite an existing blob.
	if _, err := az.Upload(context.Background(), path, bytes.NewReader([]byte("x")), "", nil); err == nil {
		t.Fatal("overwrite must be refused")
	}
	// Delete is only possible on probe paths.
	if _, err := az.ProbeDeleteRefused(context.Background(), path); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("delete of a backup path must be refused by code: %v", err)
	}
	if _, err := az.Upload(context.Background(), "../escape", bytes.NewReader(nil), "", nil); err == nil {
		t.Fatal("invalid path accepted")
	}
}

func TestResolverAzurite(t *testing.T) {
	ep := azurite(t)
	db := testutil.DB(t)
	ctx := context.Background()
	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	env := &secrets.Envelope{KV: kv}
	c := newContainer(t, ep)

	insert := func(name string, token string, stored bool) uuid.UUID {
		credID := uuid.New()
		if stored {
			sealed, err := env.Seal(ctx, []byte(token), []byte("credentials:"+credID.String()))
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(ctx, `INSERT INTO credentials (id, kind, ciphertext, wrapped_dek, kek_version) VALUES ($1,'stored',$2,$3,$4)`,
				credID, sealed.Ciphertext, sealed.WrappedDEK, sealed.KEKVersion)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			if err := kv.SetSecret(ctx, "kv-test", "sas-"+name, []byte(token)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO credentials (id, kind, keyvault_name, secret_name) VALUES ($1,'keyvault_ref','kv-test',$2)`,
				credID, "sas-"+name); err != nil {
				t.Fatal(err)
			}
		}
		var id uuid.UUID
		if err := db.QueryRow(ctx, `INSERT INTO destinations (name, account, container, prefix, auth, sas_credential_id, endpoint_override)
			VALUES ($1, $2, $3, 'pfx', 'sas_token', $4, $5) RETURNING id`, name, devAccount, c, credID, ep).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	good := containerSAS(t, c, permsRCWT, time.Now().Add(time.Hour))
	r := blob.NewResolver(db, kv, env, nil)
	for _, stored := range []bool{true, false} {
		id := insert(map[bool]string{true: "stored", false: "kvref"}[stored], good, stored)
		w, err := r.ForDestination(ctx, id)
		if err != nil {
			t.Fatalf("stored=%v: %v", stored, err)
		}
		if w.Prefix() != "pfx" {
			t.Fatalf("prefix %q", w.Prefix())
		}
		if _, err := w.Upload(ctx, blob.Join(w.Prefix(), uuid.NewString()), strings.NewReader("hello"), "text/plain", map[string]string{"olympos-tier": "weekly"}); err != nil {
			t.Fatalf("stored=%v upload: %v", stored, err)
		}
	}
	expired := insert("expired", containerSAS(t, c, permsRCWT, time.Now().Add(-time.Minute)), true)
	if _, err := r.ForDestination(ctx, expired); !errors.Is(err, blob.ErrSASExpired) {
		t.Fatalf("expired SAS: %v", err)
	}
	if _, err := r.ForDestination(ctx, uuid.New()); err == nil {
		t.Fatal("unknown destination")
	}
	mi := uuid.New()
	if _, err := db.Exec(ctx, `INSERT INTO destinations (id, name, account, container, auth) VALUES ($1, 'mi', 'acct', 'backups', 'managed_identity')`, mi); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ForDestination(ctx, mi); err == nil || !strings.Contains(err.Error(), "managed identity") {
		t.Fatalf("MI without credential: %v", err)
	}
}
