//go:build dev

package secrets

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestEnvelopeRoundTripAndAAD(t *testing.T) {
	ctx := context.Background()
	e := &Envelope{KV: &LocalKeyVault{Dir: t.TempDir()}}
	s, err := e.Seal(ctx, []byte("s3cr3t"), []byte("credential:1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, []byte("s3cr3t")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	got, err := e.Open(ctx, s, []byte("credential:1"))
	if err != nil || string(got) != "s3cr3t" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := e.Open(ctx, s, []byte("credential:2")); err == nil {
		t.Fatal("open with different AAD must fail")
	}
	s2, _ := e.Seal(ctx, []byte("s3cr3t"), nil)
	if bytes.Equal(s.WrappedDEK, s2.WrappedDEK) {
		t.Fatal("DEK must be unique per record")
	}
}

func TestFingerprintFormat(t *testing.T) {
	f, err := NewFingerprinter(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fp := f.Fingerprint([]byte("value"))
	if !regexp.MustCompile(`^hm:[0-9a-f]{4}·[0-9a-f]{4}·[0-9a-f]{4}$`).MatchString(fp) {
		t.Fatalf("bad fingerprint %q", fp)
	}
	g, _ := NewFingerprinter(bytes.Repeat([]byte{8}, 32))
	if g.Fingerprint([]byte("value")) == fp {
		t.Fatal("fingerprint must depend on the key (HMAC, not a plain hash)")
	}
	if _, err := NewFingerprinter([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestParseRef(t *testing.T) {
	r, err := ParseRef("kv://kv-platform-weu/olympos-db-dsn")
	if err != nil || r.Vault != "kv-platform-weu" || r.Secret != "olympos-db-dsn" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{"kv://", "kv://a", "http://a/b", "kv://a/b/c", "kv://a/../b"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
	canaries := []string{
		"CANARY-PW-91c2", "sv=2024&sig=CANARYSIGabc123", "hvs.CANARYvaulttoken0123456789abcd",
		"postgres://u:CANARYdsnpw@db:5432/x", "xoxb-CANARY-slack-token",
	}
	log.Info("connecting", "password", canaries[0], "url", "https://acct.blob.core.windows.net/c?"+canaries[1])
	log.Info("vault token "+canaries[2], "dsn_hint", canaries[3])
	log.Error("slack failed", "err", errString("token "+canaries[4]+" invalid"))
	log.With("secret_id", "CANARY-secretid").Info("x")
	log.Info("login", "creds", groupValuer{}) // a LogValuer that resolves to a group
	out := buf.String()
	for _, c := range []string{"CANARY-PW-91c2", "CANARYSIGabc123", "CANARYvaulttoken", "CANARYdsnpw", "xoxb-CANARY", "CANARY-secretid", "CANARY-in-group"} {
		if strings.Contains(out, c) {
			t.Errorf("secret %q leaked into logs:\n%s", c, out)
		}
	}
}

type groupValuer struct{}

func (groupValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", "u"), slog.String("password", "CANARY-in-group"))
}

type errString string

func (e errString) Error() string { return string(e) }

func TestEnvelopeOpenDecryptError(t *testing.T) {
	ctx := context.Background()
	e := &Envelope{KV: &LocalKeyVault{Dir: t.TempDir()}}
	s, err := e.Seal(ctx, []byte("s3cr3t"), []byte("credential:1"))
	if err != nil {
		t.Fatal(err)
	}
	s.Ciphertext[len(s.Ciphertext)-1] ^= 0xff
	if _, err := e.Open(ctx, s, []byte("credential:1")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("corrupted ciphertext: want ErrDecrypt, got %v", err)
	}
}

// failingUnwrapKV fails UnwrapKey like a KEK that cannot be reached.
type failingUnwrapKV struct{ KeyVault }

func (failingUnwrapKV) UnwrapKey(context.Context, []byte, string) ([]byte, error) {
	return nil, errors.New("kek unreachable")
}

func TestEnvelopeOpenUnwrapErrorIsNotDecrypt(t *testing.T) {
	ctx := context.Background()
	kv := &LocalKeyVault{Dir: t.TempDir()}
	s, err := (&Envelope{KV: kv}).Seal(ctx, []byte("s3cr3t"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&Envelope{KV: failingUnwrapKV{kv}}).Open(ctx, s, nil)
	if err == nil || errors.Is(err, ErrDecrypt) {
		t.Fatalf("unwrap failure must not be ErrDecrypt, got %v", err)
	}
}

func TestLocalGetSecretForbidden(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	kv := &LocalKeyVault{Dir: t.TempDir()}
	ctx := context.Background()
	if err := kv.SetSecret(ctx, "vault", "name", []byte("x")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(kv.Dir, "secrets", "vault", "name")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.GetSecret(ctx, "vault", "name"); !errors.Is(err, ErrSecretForbidden) {
		t.Fatalf("unreadable file: want ErrSecretForbidden, got %v", err)
	}
}
