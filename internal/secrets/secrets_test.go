//go:build dev

package secrets

import (
	"bytes"
	"context"
	"log/slog"
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
	out := buf.String()
	for _, c := range []string{"CANARY-PW-91c2", "CANARYSIGabc123", "CANARYvaulttoken", "CANARYdsnpw", "xoxb-CANARY", "CANARY-secretid"} {
		if strings.Contains(out, c) {
			t.Errorf("secret %q leaked into logs:\n%s", c, out)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
