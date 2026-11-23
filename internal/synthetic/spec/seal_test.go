package spec

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const (
	runID     = "0b6f9c1e-3f43-4a8e-9a1f-6d0f7e2a4b11"
	clusterID = "d2a7b0c4-5e61-4f3a-8c2d-9e1b7a6f0c22"
)

func testCreds() []RunCredential {
	return []RunCredential{
		{
			ID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), Kind: CredBearer,
			BoundHosts: []string{"api.wrw.com", "*.dev.wrw.com"}, Secret: []byte("CANARY-bearer-token"),
		},
		{
			ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Kind: CredBasic,
			BoundHosts: []string{"wrw.com"}, Username: "probe", Secret: []byte("CANARY-password"),
		},
		{
			ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Kind: CredOAuth2,
			BoundHosts: []string{"api.wrw.com"}, Username: "client-id", Secret: []byte("CANARY-client-secret"),
			TokenURL: "https://login.wrw.com/oauth2/token", Scopes: "orders.read orders.write",
		},
		{
			ID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), Kind: CredHeader,
			BoundHosts: []string{"partner.acme.net"}, HeaderName: "X-Api-Key", Secret: []byte("CANARY-key"),
		},
	}
}

func newKey(t *testing.T) hpke.PrivateKey {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func seal(t *testing.T, k hpke.PrivateKey, creds []RunCredential) (enc, ct []byte) {
	t.Helper()
	enc, ct, err := SealCredentials(k.PublicKey().Bytes(), runID, clusterID, creds)
	if err != nil {
		t.Fatal(err)
	}
	return enc, ct
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := newKey(t)
	want := testCreds()
	enc, ct := seal(t, k, want)
	if bytes.Contains(ct, []byte("CANARY")) || bytes.Contains(enc, []byte("CANARY")) {
		t.Fatal("secret visible in sealed message")
	}
	got, err := OpenCredentials(k, runID, clusterID, enc, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip:\n got %#v\nwant %#v", got, want)
	}
	for i := range got {
		if !bytes.Equal(got[i].Secret, want[i].Secret) {
			t.Fatalf("secret %d differs", i)
		}
	}

	// No credentials, and a credential with empty fields, round-trip too.
	for _, creds := range [][]RunCredential{nil, {{ID: uuid.New(), Kind: CredBearer}}} {
		enc, ct := seal(t, k, creds)
		got, err := OpenCredentials(k, runID, clusterID, enc, ct)
		if err != nil || len(got) != len(creds) || len(creds) == 1 && (got[0].ID != creds[0].ID || got[0].Secret != nil) {
			t.Fatalf("open %v: %v, %v", creds, got, err)
		}
	}
}

// TestOpenRefused is §9 "per-run encryption cannot be decrypted by another
// probe identity": another key, run or cluster, or a changed message.
func TestOpenRefused(t *testing.T) {
	k := newKey(t)
	enc, ct := seal(t, k, testCreds())
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 0x01
		return c
	}
	cases := []struct {
		name         string
		key          hpke.PrivateKey
		run, cluster string
		enc, ct      []byte
	}{
		{"another key", newKey(t), runID, clusterID, enc, ct},
		{"another run", k, "0b6f9c1e-3f43-4a8e-9a1f-6d0f7e2a4b12", clusterID, enc, ct},
		{"another cluster", k, runID, "d2a7b0c4-5e61-4f3a-8c2d-9e1b7a6f0c23", enc, ct},
		{"run and cluster swapped", k, clusterID, runID, enc, ct},
		{"ciphertext first byte", k, runID, clusterID, enc, flip(ct, 0)},
		{"ciphertext tag", k, runID, clusterID, enc, flip(ct, len(ct)-1)},
		{"ciphertext truncated", k, runID, clusterID, enc, ct[:len(ct)-1]},
		{"ciphertext extended", k, runID, clusterID, enc, append(bytes.Clone(ct), 0)},
		{"ciphertext empty", k, runID, clusterID, enc, nil},
		{"enc first byte", k, runID, clusterID, flip(enc, 0), ct},
		{"enc last byte", k, runID, clusterID, flip(enc, len(enc)-1), ct},
		{"enc truncated", k, runID, clusterID, enc[:len(enc)-1], ct},
		{"enc empty", k, runID, clusterID, nil, ct},
		{"empty run", k, "", clusterID, enc, ct},
		{"empty cluster", k, runID, "", enc, ct},
		{"nil key", nil, runID, clusterID, enc, ct},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := OpenCredentials(c.key, c.run, c.cluster, c.enc, c.ct)
			if err == nil {
				t.Fatalf("opened: %v", got)
			}
			if got != nil {
				t.Fatalf("result with error: %v", got)
			}
		})
	}
}

func TestOpenRefusesOtherSuite(t *testing.T) {
	k := newKey(t)
	enc, ct := seal(t, k, testCreds())
	p256, err := hpke.DHKEM(ecdh.P256()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCredentials(p256, runID, clusterID, enc, ct); err == nil {
		t.Fatal("opened with a P-256 key")
	}
	if _, _, err := SealCredentials(p256.PublicKey().Bytes(), runID, clusterID, testCreds()); err == nil {
		t.Fatal("sealed to a P-256 public key")
	}
	if _, _, err := SealCredentials([]byte("short"), runID, clusterID, testCreds()); err == nil {
		t.Fatal("sealed to a malformed public key")
	}
}

// TestSealWireFormat pins the suite, info and AAD: a recipient built
// directly from crypto/hpke with the literal strings opens the message.
func TestSealWireFormat(t *testing.T) {
	k := newKey(t)
	enc, ct := seal(t, k, testCreds())
	if k.KEM().ID() != 0x0020 {
		t.Fatalf("KEM id %#x, want DHKEM(X25519, HKDF-SHA256)", k.KEM().ID())
	}
	r, err := hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("olympos-synthetic-credentials-v1"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := r.Open([]byte("olympos-synthetic-run:"+runID+":"+clusterID), ct)
	if err != nil {
		t.Fatalf("open with the literal info and AAD: %v", err)
	}
	if got, err := decodeCredentials(pt); err != nil || len(got) != 4 {
		t.Fatalf("decode: %v, %v", got, err)
	}

	// Another info or AES-128 does not open it.
	r, err = hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("olympos-synthetic-credentials-v2"))
	if err == nil {
		if _, err := r.Open([]byte("olympos-synthetic-run:"+runID+":"+clusterID), ct); err == nil {
			t.Fatal("opened with another info")
		}
	}
	r, err = hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(sealInfo))
	if err == nil {
		if _, err := r.Open([]byte("olympos-synthetic-run:"+runID+":"+clusterID), ct); err == nil {
			t.Fatal("opened with AES-128-GCM")
		}
	}
}

func TestSealFresh(t *testing.T) {
	k := newKey(t)
	enc1, ct1 := seal(t, k, testCreds())
	enc2, ct2 := seal(t, k, testCreds())
	if bytes.Equal(enc1, enc2) || bytes.Equal(ct1, ct2) {
		t.Fatal("two seals of the same credentials are equal")
	}
}

func TestSealRefusesIDs(t *testing.T) {
	pub := newKey(t).PublicKey().Bytes()
	for _, ids := range [][2]string{{"", clusterID}, {runID, ""}, {"a:b", "c"}, {"a", "b:c"}} {
		if _, _, err := SealCredentials(pub, ids[0], ids[1], nil); err == nil {
			t.Errorf("sealed for run %q cluster %q", ids[0], ids[1])
		}
	}
	many := make([]RunCredential, maxRunCredentials+1)
	if _, _, err := SealCredentials(pub, runID, clusterID, many); err == nil {
		t.Error("sealed more credentials than steps")
	}
}

// TestPlaintextZeroed checks that the plaintext is all zeros once sealing
// and opening are done.
func TestPlaintextZeroed(t *testing.T) {
	var seen [][]byte
	testHookPlaintext = func(b []byte) { seen = append(seen, b) }
	defer func() { testHookPlaintext = nil }()

	k := newKey(t)
	enc, ct := seal(t, k, testCreds())
	got, err := OpenCredentials(k, runID, clusterID, enc, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("hook saw %d buffers, want 2 (seal and open)", len(seen))
	}
	for i, b := range seen {
		if len(b) == 0 {
			t.Fatalf("buffer %d empty", i)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("buffer %d not zeroed", i)
		}
	}
	// The opened secrets are copies, still intact.
	if string(got[0].Secret) != "CANARY-bearer-token" {
		t.Fatalf("opened secret %q", got[0].Secret)
	}
}

func TestZeroCredentials(t *testing.T) {
	creds := testCreds()
	secrets := make([][]byte, len(creds))
	for i := range creds {
		secrets[i] = creds[i].Secret
	}
	ZeroCredentials(creds)
	for i := range creds {
		if creds[i].Secret != nil {
			t.Errorf("credential %d keeps its secret", i)
		}
		if !bytes.Equal(secrets[i], make([]byte, len(secrets[i]))) {
			t.Errorf("secret %d not zeroed: %q", i, secrets[i])
		}
	}
	ZeroCredentials(nil)
}

func TestRunCredentialPrinting(t *testing.T) {
	c := testCreds()[1]
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(format, c)
		if strings.Contains(out, "CANARY") || strings.Contains(out, "probe") {
			t.Errorf("%s prints secret or user name: %s", format, out)
		}
	}
	out := fmt.Sprintf("%+v", []RunCredential{c})
	if strings.Contains(out, "CANARY") {
		t.Errorf("slice prints secret: %s", out)
	}
}

func TestDecodeMalformed(t *testing.T) {
	good, err := encodeCredentials(testCreds())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCredentials(good); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":         nil,
		"version":       append([]byte{2}, good[1:]...),
		"trailing byte": append(bytes.Clone(good), 0),
		"huge count":    {1, 0xff, 0xff, 0xff, 0xff, 0x0f},
		"count too big": {1, maxRunCredentials + 1},
		"short id":      {1, 1, 0, 0},
	}
	for i := 1; i < len(good); i++ {
		cases[fmt.Sprintf("truncated at %d", i)] = good[:i]
	}
	for name, b := range cases {
		if got, err := decodeCredentials(b); err == nil || got != nil {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}

func FuzzDecodeCredentials(f *testing.F) {
	good, _ := encodeCredentials(testCreds())
	f.Add(good)
	f.Add([]byte{1, 0})
	f.Add([]byte{1, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := decodeCredentials(b)
		if err != nil {
			return
		}
		again, err := encodeCredentials(got)
		if err != nil {
			t.Fatalf("decoded credentials do not encode: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("encoding is not canonical: %x -> %x", b, again)
		}
	})
}
