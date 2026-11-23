package spec

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const (
	runID     = "0b6f9c1e-3f43-4a8e-9a1f-6d0f7e2a4b11"
	clusterID = "d2a7b0c4-5e61-4f3a-8c2d-9e1b7a6f0c22"
)

// canaries are every user name and secret in testCreds.
var canaries = []string{
	"CANARY-bearer-token", "CANARY-USER-probe", "CANARY-password",
	"CANARY-USER-client-id", "CANARY-client-secret", "CANARY-key",
}

func secret(s string) *Secret { return NewSecret([]byte(s)) }

// fieldsOf shows a credential's non-secret fields, for failure messages.
func fieldsOf(c RunCredential) []any {
	return []any{c.ID.String(), c.Kind, c.BoundHosts, c.HeaderName, c.TokenURL, c.Scopes}
}

func testCreds() []RunCredential {
	return []RunCredential{
		{
			ID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), Kind: CredBearer,
			BoundHosts: []string{"api.wrw.com", "*.dev.wrw.com"}, Secret: secret("CANARY-bearer-token"),
		},
		{
			ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Kind: CredBasic,
			BoundHosts: []string{"wrw.com"}, Username: secret("CANARY-USER-probe"), Secret: secret("CANARY-password"),
		},
		{
			ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Kind: CredOAuth2,
			BoundHosts: []string{"api.wrw.com"}, Username: secret("CANARY-USER-client-id"), Secret: secret("CANARY-client-secret"),
			TokenURL: "https://login.wrw.com/oauth2/token", Scopes: "orders.read orders.write",
		},
		{
			ID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), Kind: CredHeader,
			BoundHosts: []string{"partner.acme.net"}, HeaderName: "X-Api-Key", Secret: secret("CANARY-key"),
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
	if len(got) != len(want) {
		t.Fatalf("round trip: %d credentials, want %d", len(got), len(want))
	}
	for i := range got {
		g, w := got[i], want[i]
		g.Username, g.Secret, w.Username, w.Secret = nil, nil, nil, nil
		if !reflect.DeepEqual(g, w) {
			t.Fatalf("credential %d: %+v, want %+v", i, fieldsOf(g), fieldsOf(w))
		}
	}
	for i := range got {
		if !bytes.Equal(got[i].Secret.Bytes(), want[i].Secret.Bytes()) ||
			!bytes.Equal(got[i].Username.Bytes(), want[i].Username.Bytes()) {
			t.Fatalf("credential %d differs", i)
		}
	}

	// No credentials, and a credential with empty fields, round-trip too.
	for _, creds := range [][]RunCredential{nil, {{ID: uuid.New(), Kind: CredBearer}}} {
		enc, ct := seal(t, k, creds)
		got, err := OpenCredentials(k, runID, clusterID, enc, ct)
		if err != nil || len(got) != len(creds) || len(creds) == 1 && (got[0].ID != creds[0].ID || got[0].Secret != nil || got[0].Username != nil) {
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
	if string(got[0].Secret.Bytes()) != "CANARY-bearer-token" || string(got[1].Username.Bytes()) != "CANARY-USER-probe" {
		t.Fatal("opened secrets are not intact")
	}
}

func TestZeroCredentials(t *testing.T) {
	creds := testCreds()
	var bufs [][]byte
	for i := range creds {
		bufs = append(bufs, creds[i].Secret.Bytes(), creds[i].Username.Bytes())
	}
	ZeroCredentials(creds)
	for i := range creds {
		if creds[i].Secret != nil || creds[i].Username != nil {
			t.Errorf("credential %d keeps its secret or user name", i)
		}
	}
	for i, b := range bufs {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("buffer %d not zeroed", i)
		}
	}
	ZeroCredentials(nil)
}

func TestSecret(t *testing.T) {
	var nilSecret *Secret
	if nilSecret.Bytes() != nil || nilSecret.Len() != 0 {
		t.Fatal("nil secret not empty")
	}
	nilSecret.Zero()
	if NewSecret(nil) != nil || NewSecret([]byte{}) != nil {
		t.Fatal("empty secret not nil")
	}
	b := []byte("CANARY-x")
	sec := NewSecret(b)
	if &sec.Bytes()[0] != &b[0] || sec.Len() != 8 {
		t.Fatal("NewSecret copied or lost its bytes")
	}
	sec.Zero()
	if sec.Bytes() != nil || !bytes.Equal(b, make([]byte, 8)) {
		t.Fatal("Zero did not clear the bytes")
	}
	j, err := json.Marshal(struct{ S *Secret }{secret("CANARY-x")})
	if err != nil || string(j) != `{"S":"[redacted]"}` {
		t.Fatalf("JSON %s, %v", j, err)
	}
}

// leaks reports which canary, in any of the forms fmt can print bytes in,
// appears in out.
func leaks(out string) string {
	for _, c := range canaries {
		forms := []string{
			c, hex.EncodeToString([]byte(c)), strings.ToUpper(hex.EncodeToString([]byte(c))),
			base64.StdEncoding.EncodeToString([]byte(c)), strings.Trim(fmt.Sprint([]byte(c)), "[]"),
			strings.Trim(fmt.Sprintf("% x", []byte(c)), " "),
		}
		for _, f := range forms {
			if strings.Contains(out, f) {
				return f
			}
		}
	}
	// The common prefix, in case a form above was cut.
	for _, f := range []string{"CANARY", "43414e415259", "43414E415259", "67 65 78 65 82 89"} {
		if strings.Contains(out, f) {
			return f
		}
	}
	return ""
}

type exportedHolder struct {
	Creds []RunCredential
	One   RunCredential
	Ptr   *RunCredential
	Map   map[string]RunCredential
}

type unexportedHolder struct {
	creds []RunCredential
	one   RunCredential
	ptr   *RunCredential
	m     map[string]RunCredential
}

func TestRunCredentialPrinting(t *testing.T) {
	creds := testCreds()
	c := creds[1] // basic: user name and password
	values := map[string]any{
		"value":      c,
		"pointer":    &c,
		"slice":      creds,
		"exported":   exportedHolder{creds, c, &c, map[string]RunCredential{"k": c}},
		"unexported": unexportedHolder{creds, c, &c, map[string]RunCredential{"k": c}},
		"secret":     c.Secret,
	}
	values["exported pointer"] = &exportedHolder{creds, c, &c, nil}
	values["unexported pointer"] = &unexportedHolder{creds, c, &c, nil}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "% x"}
	for name, v := range values {
		for _, verb := range verbs {
			if f := leaks(fmt.Sprintf(verb, v)); f != "" {
				t.Errorf("%s with %s prints %q: %s", name, verb, f, fmt.Sprintf(verb, v))
			}
		}
		for _, h := range []struct {
			name string
			new  func(*bytes.Buffer) slog.Handler
		}{
			{"text", func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
			{"json", func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
		} {
			var buf bytes.Buffer
			slog.New(h.new(&buf)).Info("run", "v", v)
			if f := leaks(buf.String()); f != "" {
				t.Errorf("%s with slog %s prints %q: %s", name, h.name, f, buf.String())
			}
		}
	}
	// What a credential prints as.
	want := "RunCredential{22222222-2222-4222-8222-222222222222 basic}"
	if got := fmt.Sprintf("%x", c); got != want {
		t.Errorf("%%x = %q, want %q", got, want)
	}
	if got := fmt.Sprint(c.Secret); got != "[redacted]" {
		t.Errorf("secret prints %q", got)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("run", "cred", c)
	if !strings.Contains(buf.String(), `"cred":{"id":"22222222-2222-4222-8222-222222222222","kind":"basic"}`) {
		t.Errorf("slog JSON: %s", buf.String())
	}
	// The JSON form of a credential has neither field.
	j, err := json.Marshal(c)
	if err != nil || leaks(string(j)) != "" || strings.Contains(string(j), "username") || strings.Contains(string(j), "secret") {
		t.Errorf("JSON %s, %v", j, err)
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
