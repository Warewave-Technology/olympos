package clickhouse

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
)

const (
	testManifestKey = "olympos-manifest"
	// Run IDs are canonical lower-case UUIDs.
	testRunID      = "0f6b2a4e-8d1c-4f3a-9b7e-2c5d8a1f6e30"
	testBaseRunID  = "7c2e9d14-3b6a-4e8f-a1d5-9f0b4c7e2a61"
	testOtherRunID = "d41e7a90-5c2b-4b8e-9e3f-61a0c8b7d2f4"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// testNativeManifest is a small full manifest: an incremental with a base,
// two databases, every object kind.
func testNativeManifest() *NativeManifest {
	return &NativeManifest{
		Format:             NativeManifestFormat,
		RunID:              testRunID,
		BaseRunID:          testBaseRunID,
		BaseManifestSHA256: sum("base"),
		ServerVersion:      "25.8.1.1",
		Settings:           map[string]string{"compression_method": "zstd", "base_backup": testBaseRunID, "id": testRunID},
		// Every DDLKey below is one of these objects. The data part is last:
		// TestVerifyRefusesTamper drops it.
		Objects: []ingest.ObjectRecord{
			{Key: testRunID + "/metadata/sales/orders.sql", Size: 120, SHA256: sum("orders.sql")},
			{Key: testRunID + "/.backup", Size: 4096, SHA256: sum(".backup")},
			{Key: testRunID + "/metadata/sales/orders_mv.sql", Size: 140, SHA256: sum("orders_mv.sql")},
			{Key: testRunID + "/metadata/sales/by_day.sql", Size: 90, SHA256: sum("by_day.sql")},
			{Key: testRunID + "/metadata/dicts/countries.sql", Size: 300, SHA256: sum("countries.sql")},
			{Key: testRunID + "/metadata/sales.sql", Size: 0, SHA256: sum("")},
			{Key: testRunID + "/data/sales/orders/all_1_1_0/data.bin", Size: 1 << 20, SHA256: sum("data.bin")},
		},
		Databases: []NativeDatabase{
			{Name: "sales", Objects: []NativeObject{
				{Name: "orders_mv", Kind: KindMaterializedView, Engine: "MaterializedView", DDLKey: testRunID + "/metadata/sales/orders_mv.sql"},
				{Name: "orders", Kind: KindTable, Engine: "MergeTree", Rows: 42, DDLKey: testRunID + "/metadata/sales/orders.sql"},
				{Name: "by_day", Kind: KindView, Engine: "View", DDLKey: testRunID + "/metadata/sales/by_day.sql"},
			}},
			{Name: "dicts", Objects: []NativeObject{
				{Name: "countries", Kind: KindDictionary, Engine: "Dictionary", DDLKey: testRunID + "/metadata/dicts/countries.sql"},
			}},
		},
	}
}

// fakeVault is an in-memory ES256 Key Vault: one version ("1") per key,
// created on first Sign. It counts Verify calls so tests can tell a refusal
// before the vault from one by it.
type fakeVault struct {
	secrets.KeyVault // the rest is not used here
	keys             map[string]*ecdsa.PrivateKey
	verifies         atomic.Int32
	verifyErr        error // returned by Verify when set: a vault that is down
}

func newFakeVault() *fakeVault { return &fakeVault{keys: map[string]*ecdsa.PrivateKey{}} }

func (f *fakeVault) Sign(_ context.Context, keyName string, digest []byte) ([]byte, string, error) {
	k := f.keys[keyName]
	if k == nil {
		var err error
		if k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, "", err
		}
		f.keys[keyName] = k
	}
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, keyName + "/1", nil
}

func (f *fakeVault) Verify(_ context.Context, keyID string, digest, sig []byte) error {
	f.verifies.Add(1)
	if f.verifyErr != nil {
		return f.verifyErr
	}
	name, ver, _ := strings.Cut(keyID, "/")
	k := f.keys[name]
	if k == nil || ver != "1" {
		return secrets.ErrKeyNotFound
	}
	if len(sig) != 64 || !ecdsa.Verify(&k.PublicKey, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return secrets.ErrSignatureInvalid
	}
	return nil
}

func signedJSON(t *testing.T, kv secrets.KeyVault, keyName string, m *NativeManifest) []byte {
	t.Helper()
	s, err := Sign(context.Background(), kv, keyName, m)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestCanonicalGolden pins the encoding only: its manifest is deliberately
// not a valid one (run ID "r", a DDL key outside its objects).
func TestCanonicalGolden(t *testing.T) {
	m := &NativeManifest{
		Format:        NativeManifestFormat,
		RunID:         "r",
		ServerVersion: "24.8",
		Settings:      map[string]string{"b": "2", "a": "1"},
		Objects: []ingest.ObjectRecord{
			{Key: "r/b", Size: 2, SHA256: strings.Repeat("b", 64)},
			{Key: "r/a", Size: 1, SHA256: strings.Repeat("a", 64)},
		},
		Databases: []NativeDatabase{{Name: "db", Objects: []NativeObject{
			{Name: "t", Kind: KindTable, Engine: "MergeTree", Rows: 7, DDLKey: "r/metadata/db/t.sql"},
		}}},
	}
	want := `{"base_manifest_sha256":"","base_run_id":"","databases":[{"name":"db","objects":[` +
		`{"ddl_key":"r/metadata/db/t.sql","engine":"MergeTree","kind":"table","name":"t","rows":7}]}],` +
		`"format":"olympos.clickhouse.native/v1","objects":[` +
		`{"key":"r/a","sha256":"` + strings.Repeat("a", 64) + `","size":1},` +
		`{"key":"r/b","sha256":"` + strings.Repeat("b", 64) + `","size":2}],` +
		`"run_id":"r","server_version":"24.8","settings":{"a":"1","b":"2"}}`
	if got := string(m.Canonical()); got != want {
		t.Fatalf("canonical:\n got %s\nwant %s", got, want)
	}
	// Empty and nil collections are the same manifest.
	empty := &NativeManifest{Format: NativeManifestFormat, RunID: "r"}
	if got, want := string(empty.Canonical()), `{"base_manifest_sha256":"","base_run_id":"","databases":[],`+
		`"format":"olympos.clickhouse.native/v1","objects":[],"run_id":"r","server_version":"","settings":{}}`; got != want {
		t.Fatalf("empty canonical:\n got %s\nwant %s", got, want)
	}
	empty.Settings, empty.Objects, empty.Databases = map[string]string{}, []ingest.ObjectRecord{}, []NativeDatabase{}
	if got := string(empty.Canonical()); !strings.Contains(got, `"databases":[]`) || !strings.Contains(got, `"settings":{}`) {
		t.Fatalf("empty, non-nil collections: %s", got)
	}
}

func TestCanonicalStable(t *testing.T) {
	want := testNativeManifest().Canonical()
	if !json.Valid(want) {
		t.Fatalf("not JSON: %s", want)
	}
	for i := range 50 {
		m := testNativeManifest()
		// The same settings inserted in another order, every list reversed.
		m.Settings = map[string]string{}
		for _, k := range []string{"id", "base_backup", "compression_method"} {
			m.Settings[k] = testNativeManifest().Settings[k]
		}
		reverse(m.Objects)
		reverse(m.Databases)
		for j := range m.Databases {
			reverse(m.Databases[j].Objects)
		}
		if got := m.Canonical(); !bytes.Equal(got, want) {
			t.Fatalf("round %d: canonical depends on order:\n got %s\nwant %s", i, got, want)
		}
	}
	// Canonical sorts a copy: the caller's lists keep their order.
	m := testNativeManifest()
	_ = m.Canonical()
	if !reflect.DeepEqual(m, testNativeManifest()) {
		t.Fatal("Canonical changed the manifest")
	}
	// Sorted by key, by name; within a database by name.
	got := string(want)
	for _, pair := range [][2]string{
		{`"key":"` + testRunID + `/.backup"`, `"key":"` + testRunID + `/data/`}, {`"key":"` + testRunID + `/metadata/sales.sql"`, `"key":"` + testRunID + `/metadata/sales/orders.sql"`},
		{`"name":"dicts"`, `"name":"sales"`}, {`"name":"by_day"`, `"name":"orders"`}, {`"name":"orders"`, `"name":"orders_mv"`},
	} {
		if strings.Index(got, pair[0]) > strings.Index(got, pair[1]) {
			t.Errorf("%s is not before %s in %s", pair[0], pair[1], got)
		}
	}
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func TestCanonicalStrings(t *testing.T) {
	odd := "q\"b\\s/<&>\x00\x1f\n\t\u00e9\u2028\u65e5\u672c"
	m := &NativeManifest{Format: NativeManifestFormat, RunID: odd, Settings: map[string]string{odd: odd}}
	c := m.Canonical()
	want := `q\"b\\s/<&>\u0000\u001f\n\t` + "\u00e9\u2028\u65e5\u672c"
	if !bytes.Contains(c, []byte(`"run_id":"`+want+`"`)) {
		t.Fatalf("string encoding: %s", c)
	}
	var back struct {
		RunID    string            `json:"run_id"`
		Settings map[string]string `json:"settings"`
	}
	if err := json.Unmarshal(c, &back); err != nil || back.RunID != odd || back.Settings[odd] != odd {
		t.Fatalf("does not decode to the same strings: %v %+v", err, back)
	}
	// Numbers as Go writes integers: no exponent, no fraction.
	m = &NativeManifest{Format: NativeManifestFormat, RunID: "r",
		Objects:   []ingest.ObjectRecord{{Key: "r/k", Size: 1 << 62, SHA256: sum("k")}},
		Databases: []NativeDatabase{{Name: "d", Objects: []NativeObject{{Name: "t", Kind: KindTable, Rows: 1<<64 - 1}}}},
	}
	c = m.Canonical()
	if !bytes.Contains(c, []byte(`"size":4611686018427387904`)) || !bytes.Contains(c, []byte(`"rows":18446744073709551615`)) {
		t.Fatalf("numbers: %s", c)
	}
}

func TestSignVerify(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	m := testNativeManifest()
	s, err := Sign(ctx, kv, testManifestKey, m)
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyID != testManifestKey+"/1" || s.Manifest == m || !reflect.DeepEqual(s.Manifest, m) {
		t.Fatalf("signed: key %q, manifest %p (a copy of %p)", s.KeyID, s.Manifest, m)
	}
	if sig, err := base64.StdEncoding.DecodeString(s.Signature); err != nil || len(sig) != 64 {
		t.Fatalf("signature %q: %v", s.Signature, err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	// The wire form: sorted keys, the manifest in its canonical form.
	want := `{"key_id":"` + s.KeyID + `","manifest":` + string(m.Canonical()) + `,"signature":"` + s.Signature + `"}`
	if string(raw) != want {
		t.Fatalf("wire form:\n got %s\nwant %s", raw, want)
	}
	got, err := VerifySigned(ctx, kv, testManifestKey, testRunID, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Canonical(), m.Canonical()) {
		t.Fatalf("verified manifest differs:\n got %s\nwant %s", got.Canonical(), m.Canonical())
	}
	if got.RunID != testRunID || got.Settings["id"] != testRunID || len(got.Objects) != 7 || len(got.Databases) != 2 {
		t.Fatalf("verified manifest: %+v", got)
	}

	// json.Marshal escapes <, > and & in what MarshalJSON returns: other
	// bytes than Canonical, the same manifest, so it verifies.
	m.Settings["note"] = "<a & b>"
	raw = signedJSON(t, kv, testManifestKey, m)
	if bytes.ContainsAny(raw, "<&>") || !bytes.Contains(m.Canonical(), []byte("<a & b>")) {
		t.Fatalf("expected encoding/json to escape HTML: %s", raw)
	}
	if got, err := VerifySigned(ctx, kv, testManifestKey, testRunID, raw); err != nil || got.Settings["note"] != "<a & b>" {
		t.Fatalf("HTML-escaped form: %v", err)
	}
}

// TestVerifyReordered: VerifySigned checks the manifest, not the bytes it
// arrived as. The same manifest with its keys in another order, its lists
// shuffled and whitespace added still verifies.
func TestVerifyReordered(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	raw := signedJSON(t, kv, testManifestKey, testNativeManifest())
	var wire struct {
		Manifest  *NativeManifest
		Signature string
		KeyID     string
	}
	wire.Manifest = testNativeManifest()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(top["signature"], &wire.Signature)
	_ = json.Unmarshal(top["key_id"], &wire.KeyID)

	// Hand-written in another key order, lists reversed, indented.
	m := wire.Manifest
	reverse(m.Objects)
	reverse(m.Databases)
	var b strings.Builder
	fmt.Fprintf(&b, "{\n  \"signature\": %q,\n  \"manifest\": {\n    \"run_id\": %q, \"format\": %q,\n", wire.Signature, m.RunID, m.Format)
	fmt.Fprintf(&b, "    \"settings\": {\"id\": %q, \"compression_method\": %q, \"base_backup\": %q},\n",
		m.Settings["id"], m.Settings["compression_method"], m.Settings["base_backup"])
	b.WriteString("    \"objects\": [")
	for i, o := range m.Objects {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, `{"size": %d, "sha256": %q, "key": %q}`, o.Size, o.SHA256, o.Key)
	}
	b.WriteString("],\n    \"databases\": [")
	for i, d := range m.Databases {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, `{"objects": [`)
		for j, o := range d.Objects {
			if j > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"rows": %d, "name": %q, "kind": %q, "engine": %q, "ddl_key": %q}`, o.Rows, o.Name, o.Kind, o.Engine, o.DDLKey)
		}
		fmt.Fprintf(&b, `], "name": %q}`, d.Name)
	}
	fmt.Fprintf(&b, "],\n    \"server_version\": %q, \"base_run_id\": %q, \"base_manifest_sha256\": %q\n  },\n  \"key_id\": %q\n}\n",
		m.ServerVersion, m.BaseRunID, m.BaseManifestSHA256, wire.KeyID)

	if bytes.Equal([]byte(b.String()), raw) {
		t.Fatal("the reordered form is the canonical one")
	}
	got, err := VerifySigned(ctx, kv, testManifestKey, testRunID, []byte(b.String()))
	if err != nil {
		t.Fatalf("a reordered but equal manifest is refused: %v\n%s", err, b.String())
	}
	if !bytes.Equal(got.Canonical(), testNativeManifest().Canonical()) {
		t.Fatal("verified manifest differs")
	}
	// The lists come back in canonical order, not in the stored one: the
	// same manifest, whatever the order it was stored in.
	want := testNativeManifest()
	slices.SortFunc(want.Objects, func(x, y ingest.ObjectRecord) int { return strings.Compare(x.Key, y.Key) })
	slices.SortFunc(want.Databases, func(x, y NativeDatabase) int { return strings.Compare(x.Name, y.Name) })
	for _, d := range want.Databases {
		slices.SortFunc(d.Objects, func(x, y NativeObject) int { return strings.Compare(x.Name, y.Name) })
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("not in canonical order:\n got %+v\nwant %+v", got, want)
	}
	if got.Objects[0].Key != testRunID+"/.backup" || got.Databases[0].Name != "dicts" || got.Databases[1].Objects[0].Name != "by_day" {
		t.Fatalf("not sorted: %+v", got)
	}
}

// TestVerifyRefusesTamper: one byte changed anywhere in the signed JSON is
// refused, and so is a signature moved under another key ID.
func TestVerifyRefusesTamper(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	raw := signedJSON(t, kv, testManifestKey, testNativeManifest())
	for i := range raw {
		bad := bytes.Clone(raw)
		bad[i] ^= 0x01
		if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, bad); err == nil {
			t.Fatalf("byte %d changed (%q -> %q) and still verifies: ...%s...", i, raw[i], bad[i], bad[max(0, i-20):min(len(bad), i+20)])
		}
	}
	// One value changed, re-encoded properly: the signature no longer covers it.
	for _, change := range []func(m *NativeManifest){
		func(m *NativeManifest) { m.Objects[0].Size++ },
		func(m *NativeManifest) { m.Databases[0].Objects[1].Rows = 41 },
		func(m *NativeManifest) { m.Settings["extra"] = "1" },
		func(m *NativeManifest) { m.Objects = m.Objects[:len(m.Objects)-1] },
	} {
		var top map[string]json.RawMessage
		_ = json.Unmarshal(raw, &top)
		m := testNativeManifest()
		change(m)
		top["manifest"] = m.Canonical()
		bad, _ := json.Marshal(top)
		if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, bad); !errors.Is(err, secrets.ErrSignatureInvalid) {
			t.Fatalf("changed manifest: %v", err)
		}
	}
	// The signature of the trusted key moved onto a manifest of another
	// version, or the key ID swapped: refused.
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	top["key_id"] = json.RawMessage(`"` + testManifestKey + `/2"`)
	bad, _ := json.Marshal(top)
	if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, bad); !errors.Is(err, secrets.ErrKeyNotFound) {
		t.Fatalf("swapped key version: %v", err)
	}
}

// TestVerifyPinsTrustedKey (R21): a manifest signed by another key in the
// vault is refused before the vault is asked, however valid its signature;
// the trusted name is compared case-insensitively, as Key Vault names are.
func TestVerifyPinsTrustedKey(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	raw := signedJSON(t, kv, "other-key", testNativeManifest())
	if _, err := VerifySigned(ctx, kv, "other-key", testRunID, raw); err != nil {
		t.Fatalf("the signature itself is valid: %v", err)
	}
	kv.verifies.Store(0)
	if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, raw); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("manifest signed by another key: %v", err)
	}
	if n := kv.verifies.Load(); n != 0 {
		t.Fatalf("the vault was asked %d times about an untrusted key", n)
	}
	raw = signedJSON(t, kv, testManifestKey, testNativeManifest())
	if _, err := VerifySigned(ctx, kv, "OLYMPOS-Manifest", testRunID, raw); err != nil {
		t.Fatalf("trusted name in another case: %v", err)
	}
	if _, err := VerifySigned(ctx, kv, "", testRunID, raw); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("no trusted key: %v", err)
	}
}

// TestVerifyRefusesMalformed: what is not a well-formed native manifest is
// refused before the vault is asked.
func TestVerifyRefusesMalformed(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	raw := string(signedJSON(t, kv, testManifestKey, testNativeManifest()))
	h := sum("x")
	cases := map[string]string{
		"not JSON":               `{`,
		"trailing data":          raw + `{}`,
		"null":                   `null`,
		"null manifest":          `{"key_id":"olympos-manifest/1","manifest":null,"signature":"AA=="}`,
		"unknown top level":      strings.Replace(raw, `"key_id"`, `"comment":"x","key_id"`, 1),
		"top level in caps":      strings.Replace(raw, `"key_id"`, `"Key_id"`, 1),
		"no signature":           strings.Replace(raw, `"signature"`, `"sig"`, 1),
		"duplicate top level":    strings.Replace(raw, `"key_id"`, `"key_id":"other-key/1","key_id"`, 1),
		"unknown manifest key":   strings.Replace(raw, `"run_id"`, `"note":"x","run_id"`, 1),
		"manifest key in caps":   strings.Replace(raw, `"run_id"`, `"Run_id"`, 1),
		"duplicate run_id":       strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":"`+testOtherRunID+`","run_id":"`+testRunID+`"`, 1),
		"duplicate setting":      strings.Replace(raw, `"id":"`+testRunID+`"`, `"id":"`+testOtherRunID+`","id":"`+testRunID+`"`, 1),
		"unknown object key":     strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+testRunID+`/.backup","mode":1`, 1),
		"null settings":          strings.Replace(raw, `"settings":{"base_backup":"`+testBaseRunID+`","compression_method":"zstd","id":"`+testRunID+`"}`, `"settings":null`, 1),
		"other format":           strings.Replace(raw, NativeManifestFormat, "olympos.clickhouse.native/v2", 1),
		"logical format":         strings.Replace(raw, NativeManifestFormat, ManifestFormat, 1),
		"empty run_id":           strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":""`, 1),
		"empty object key":       strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":""`, 1),
		"upper-case sha256":      strings.Replace(raw, sum(".backup"), strings.ToUpper(sum(".backup")), 1),
		"short sha256":           strings.Replace(raw, sum(".backup"), sum(".backup")[:63], 1),
		"negative size":          strings.Replace(raw, `"size":4096`, `"size":-1`, 1),
		"fractional size":        strings.Replace(raw, `"size":4096`, `"size":4096.0`, 1),
		"duplicate object key":   strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+testRunID+`/data/sales/orders/all_1_1_0/data.bin"`, 1),
		"unknown kind":           strings.Replace(raw, `"kind":"view"`, `"kind":"live_view"`, 1),
		"empty database name":    strings.Replace(raw, `"name":"dicts"`, `"name":""`, 1),
		"duplicate database":     strings.Replace(raw, `"name":"dicts"`, `"name":"sales"`, 1),
		"duplicate table":        strings.Replace(raw, `"name":"by_day"`, `"name":"orders"`, 1),
		"base without its hash":  strings.Replace(raw, sum("base"), "", 1),
		"hash without a base":    strings.Replace(raw, `"base_run_id":"`+testBaseRunID+`"`, `"base_run_id":""`, 1),
		"bad base hash":          strings.Replace(raw, sum("base"), h[:10], 1),
		"key id without version": strings.Replace(raw, `"key_id":"olympos-manifest/1"`, `"key_id":"olympos-manifest"`, 1),
		"DDL not an object":      strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+testRunID+`/metadata/sales/nope.sql"`, 1),
		"no DDL":                 strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":""`, 1),
		// A DDL key under another run is well formed (R23: an incremental's
		// unchanged metadata is in its base); its run segment follows the run
		// ID's rules and its path the object key's.
		"DDL under a run that is no UUID": strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"run-1/metadata/sales/by_day.sql"`, 1),
		"DDL under an upper-case run":     strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+strings.ToUpper(testBaseRunID)+`/metadata/sales/by_day.sql"`, 1),
		"DDL that is a run id":            strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+testBaseRunID+`"`, 1),
		"DDL that is a run's prefix":      strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+testBaseRunID+`/"`, 1),
		"DDL of another run with a dot":   strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+testBaseRunID+`/./metadata/sales/by_day.sql"`, 1),
		"DDL of another run, empty part":  strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+testBaseRunID+`/metadata//by_day.sql"`, 1),
		"DDL of another run climbing out": strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+testBaseRunID+`/../x.sql"`, 1),
		"DDL with a leading slash":        strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"/`+testBaseRunID+`/metadata/sales/by_day.sql"`, 1),
		"DDL climbing out":                strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+testRunID+`/../`+testBaseRunID+`/metadata/sales/by_day.sql"`, 1),
		"object of another run":           strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+testBaseRunID+`/.backup"`, 1),
		"object climbing out":             strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+testRunID+`/../`+testBaseRunID+`/.backup"`, 1),
		"object with a dot":               strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+testRunID+`/./.backup"`, 1),
		"object with empty part":          strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+testRunID+`//.backup"`, 1),
		"object that is the run":          strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+testRunID+`/"`, 1),
		"object under a prefix":           strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+testRunID+`2/.backup"`, 1),
		"run id with a slash":             strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":"`+testRunID+`/data"`, 1),
		"run id dot-dot":                  strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":".."`, 1),
		// Run IDs are canonical lower-case UUIDs (uuid.UUID.String()).
		"run id not a UUID":      strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":"run-2"`, 1),
		"run id upper-case":      strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":"`+strings.ToUpper(testRunID)+`"`, 1),
		"run id in braces":       strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":"{`+testRunID+`}"`, 1),
		"run id as a URN":        strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":"urn:uuid:`+testRunID+`"`, 1),
		"run id without hyphens": strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":"`+strings.ReplaceAll(testRunID, "-", "")+`"`, 1),
		"base run id not a UUID": strings.Replace(raw, `"base_run_id":"`+testBaseRunID+`"`, `"base_run_id":"run-1"`, 1),
		"base run id upper-case": strings.Replace(raw, `"base_run_id":"`+testBaseRunID+`"`, `"base_run_id":"`+strings.ToUpper(testBaseRunID)+`"`, 1),
		"base run id with slash": strings.Replace(raw, `"base_run_id":"`+testBaseRunID+`"`, `"base_run_id":"`+testBaseRunID+`/x"`, 1),
		"base run id dot-dot":    strings.Replace(raw, `"base_run_id":"`+testBaseRunID+`"`, `"base_run_id":".."`, 1),
		"base run id is the run": strings.Replace(raw, `"base_run_id":"`+testBaseRunID+`"`, `"base_run_id":"`+testRunID+`"`, 1),
		"null signature":         regexpSig.ReplaceAllString(raw, `"signature":null`),
		"empty signature":        regexpSig.ReplaceAllString(raw, `"signature":""`),
		"short signature":        regexpSig.ReplaceAllString(raw, `"signature":"`+base64.StdEncoding.EncodeToString(make([]byte, 63))+`"`),
		"long signature":         regexpSig.ReplaceAllString(raw, `"signature":"`+base64.StdEncoding.EncodeToString(make([]byte, 65))+`"`),
		"signature not base64":   strings.Replace(raw, `"signature":"`, `"signature":"*`, 1),
	}
	for name, bad := range cases {
		if bad == raw {
			t.Fatalf("%s: the case does not change the manifest", name)
		}
		kv.verifies.Store(0)
		if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, []byte(bad)); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if n := kv.verifies.Load(); n != 0 {
			t.Errorf("%s: the vault was asked", name)
		}
	}
	// Base64 with non-zero padding bits decodes to the same signature with
	// a lenient decoder; it is another encoding, refused.
	// 64 bytes end in "X==": X carries 2 bits of the last byte and 4 zero bits.
	var top map[string]json.RawMessage
	_ = json.Unmarshal([]byte(raw), &top)
	var sig string
	_ = json.Unmarshal(top["signature"], &sig)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := len(sig) - 3
	alt := []byte(sig)
	alt[last] = alphabet[strings.IndexByte(alphabet, sig[last])^1]
	if lenient, err := base64.StdEncoding.DecodeString(string(alt)); err != nil || !bytes.Equal(lenient, mustB64(t, sig)) {
		t.Fatalf("test setup: %v", err)
	}
	bad := strings.Replace(raw, sig, string(alt), 1)
	if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, []byte(bad)); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("non-canonical base64: %v", err)
	}
}

var regexpSig = regexp.MustCompile(`"signature":"[^"]*"`)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSignRefusesInvalid: Sign does not sign what VerifySigned would refuse.
func TestSignRefusesInvalid(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(m *NativeManifest){
		"no run id":     func(m *NativeManifest) { m.RunID = "" },
		"other format":  func(m *NativeManifest) { m.Format = ManifestFormat },
		"bad sha256":    func(m *NativeManifest) { m.Objects[0].SHA256 = "x" },
		"negative size": func(m *NativeManifest) { m.Objects[0].Size = -1 },
		"bad utf-8":     func(m *NativeManifest) { m.Settings["k"] = "\xff" },
		"DDL not an object": func(m *NativeManifest) {
			m.Databases[0].Objects[0].DDLKey = testRunID + "/metadata/sales/nope.sql"
		},
		"object of another run":  func(m *NativeManifest) { m.Objects[1].Key = testBaseRunID + "/.backup" },
		"object climbing out":    func(m *NativeManifest) { m.Objects[1].Key = testRunID + "/../" + testBaseRunID + "/.backup" },
		"run id not a UUID":      func(m *NativeManifest) { m.RunID = "run-2" },
		"run id upper-case":      func(m *NativeManifest) { m.RunID = strings.ToUpper(m.RunID) },
		"base run id not a UUID": func(m *NativeManifest) { m.BaseRunID = "run-1" },
		"base run id is the run": func(m *NativeManifest) { m.BaseRunID = m.RunID },
		"DDL under a run that is no UUID": func(m *NativeManifest) {
			m.Databases[0].Objects[0].DDLKey = "run-1/metadata/sales/orders_mv.sql"
		},
		"DDL of another run climbing out": func(m *NativeManifest) {
			m.Databases[0].Objects[0].DDLKey = testBaseRunID + "/../x.sql"
		},
		"object of another run, the DDL in it": func(m *NativeManifest) {
			m.Objects[0].Key = testBaseRunID + "/metadata/sales/orders.sql"
			m.Databases[0].Objects[1].DDLKey = testBaseRunID + "/metadata/sales/orders.sql"
		},
	} {
		kv := newFakeVault()
		m := testNativeManifest()
		change(m)
		if _, err := Sign(ctx, kv, testManifestKey, m); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if len(kv.keys) != 0 {
			t.Errorf("%s: the vault signed", name)
		}
	}
	if _, err := Sign(ctx, newFakeVault(), testManifestKey, nil); !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("nil manifest: %v", err)
	}
}

// withRunID moves a manifest to another run ID, its keys with it.
func withRunID(m *NativeManifest, id string) *NativeManifest {
	old := m.RunID + "/"
	m.RunID = id
	for i := range m.Objects {
		m.Objects[i].Key = id + "/" + strings.TrimPrefix(m.Objects[i].Key, old)
	}
	for _, d := range m.Databases {
		for j := range d.Objects {
			d.Objects[j].DDLKey = id + "/" + strings.TrimPrefix(d.Objects[j].DDLKey, old)
		}
	}
	return m
}

// TestRunIDsAreUUIDs: a run ID, and a base run ID, is a canonical lower-case
// UUID (uuid.UUID.String()); everything else is refused, even with every key
// under it.
func TestRunIDsAreUUIDs(t *testing.T) {
	ctx := context.Background()
	for _, id := range []string{"run-2", strings.ToUpper(testRunID), "{" + testRunID + "}", "urn:uuid:" + testRunID,
		strings.ReplaceAll(testRunID, "-", ""), testRunID + "0", " " + testRunID, "..", "."} {
		kv := newFakeVault()
		_, err := Sign(ctx, kv, testManifestKey, withRunID(testNativeManifest(), id))
		if !errors.Is(err, ErrManifestInvalid) || !strings.Contains(err.Error(), "UUID") {
			t.Errorf("run id %q: %v", id, err)
		}
		m := testNativeManifest()
		m.BaseRunID = id
		if _, err := Sign(ctx, kv, testManifestKey, m); !errors.Is(err, ErrManifestInvalid) || !strings.Contains(err.Error(), "UUID") {
			t.Errorf("base run id %q: %v", id, err)
		}
		if len(kv.keys) != 0 {
			t.Errorf("%q: the vault signed", id)
		}
	}
	m := testNativeManifest()
	m.BaseRunID = m.RunID
	if _, err := Sign(ctx, newFakeVault(), testManifestKey, m); !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("base run id is the run: %v", err)
	}
	// Any canonical UUID is a run ID, not only version 4.
	raw := signedJSON(t, newFakeVault(), testManifestKey, withRunID(testNativeManifest(), "00000000-0000-0000-0000-000000000000"))
	if !bytes.Contains(raw, []byte(`"run_id":"00000000-0000-0000-0000-000000000000"`)) {
		t.Fatal("nil UUID")
	}
}

// TestVerifyExpectedRunID (R24): a manifest verifies only as the run it was
// asked for; a sidecar swapped in from another run is refused before the
// vault is asked.
func TestVerifyExpectedRunID(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	raw := signedJSON(t, kv, testManifestKey, testNativeManifest())
	for _, want := range []string{testOtherRunID, testBaseRunID, strings.ToUpper(testRunID), ""} {
		kv.verifies.Store(0)
		if _, err := VerifySigned(ctx, kv, testManifestKey, want, raw); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("expected run %q: %v", want, err)
		}
		if n := kv.verifies.Load(); n != 0 {
			t.Errorf("expected run %q: the vault was asked", want)
		}
	}
	if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, raw); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyDDLUnderAnotherRun (R23): an incremental's DDL key may name its
// base's metadata (ClickHouse stores unchanged files once); alone it
// verifies, and VerifyChain decides whether that key is in the chain.
func TestVerifyDDLUnderAnotherRun(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	m := testNativeManifest()
	m.Databases[0].Objects[1].DDLKey = testBaseRunID + "/metadata/sales/orders.sql"
	got, err := VerifySigned(ctx, kv, testManifestKey, testRunID, signedJSON(t, kv, testManifestKey, m))
	if err != nil {
		t.Fatal(err)
	}
	if got.Databases[1].Objects[1].DDLKey != testBaseRunID+"/metadata/sales/orders.sql" {
		t.Fatalf("DDL key: %+v", got.Databases[1].Objects)
	}
	// Under its own run it must be one of the run's objects.
	m.Databases[0].Objects[1].DDLKey = testRunID + "/metadata/sales/nope.sql"
	if _, err := Sign(ctx, kv, testManifestKey, m); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("own-run DDL that is no object: %v", err)
	}
}

// chainBase is a full backup holding the metadata its incrementals reuse.
func chainBase() *NativeManifest {
	return &NativeManifest{
		Format: NativeManifestFormat, RunID: testBaseRunID, ServerVersion: "25.8.1.1",
		Settings: map[string]string{"id": testBaseRunID},
		Objects: []ingest.ObjectRecord{
			{Key: testBaseRunID + "/.backup", Size: 2048, SHA256: sum("base .backup")},
			{Key: testBaseRunID + "/metadata/sales/orders.sql", Size: 120, SHA256: sum("orders.sql")},
			{Key: testBaseRunID + "/metadata/sales/by_day.sql", Size: 90, SHA256: sum("by_day.sql")},
			{Key: testBaseRunID + "/data/sales/orders/all_1_1_0/data.bin", Size: 1 << 20, SHA256: sum("data.bin")},
		},
		Databases: []NativeDatabase{{Name: "sales", Objects: []NativeObject{
			{Name: "orders", Kind: KindTable, Engine: "MergeTree", Rows: 40, DDLKey: testBaseRunID + "/metadata/sales/orders.sql"},
			{Name: "by_day", Kind: KindView, Engine: "View", DDLKey: testBaseRunID + "/metadata/sales/by_day.sql"},
		}}},
	}
}

// chainIncremental is an incremental on base: orders unchanged (its DDL is
// the base's), one new table with its own DDL.
func chainIncremental(base *NativeManifest, runID string) *NativeManifest {
	return &NativeManifest{
		Format: NativeManifestFormat, RunID: runID, BaseRunID: base.RunID, BaseManifestSHA256: base.SHA256(),
		ServerVersion: "25.8.1.1",
		Settings:      map[string]string{"id": runID, "base_backup": base.RunID},
		Objects: []ingest.ObjectRecord{
			{Key: runID + "/.backup", Size: 1024, SHA256: sum(runID + " .backup")},
			{Key: runID + "/metadata/sales/refunds.sql", Size: 80, SHA256: sum("refunds.sql")},
			{Key: runID + "/data/sales/orders/all_2_2_0/data.bin", Size: 4096, SHA256: sum("data2.bin")},
		},
		Databases: []NativeDatabase{{Name: "sales", Objects: []NativeObject{
			{Name: "orders", Kind: KindTable, Engine: "MergeTree", Rows: 42, DDLKey: testBaseRunID + "/metadata/sales/orders.sql"},
			{Name: "by_day", Kind: KindView, Engine: "View", DDLKey: testBaseRunID + "/metadata/sales/by_day.sql"},
			{Name: "refunds", Kind: KindTable, Engine: "MergeTree", Rows: 1, DDLKey: runID + "/metadata/sales/refunds.sql"},
		}}},
	}
}

// TestVerifyChain (R23): a chain verifies base first, each link to the one
// before by run ID and canonical SHA-256, ends at the expected run, and
// every DDL key is an object of the chain.
func TestVerifyChain(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	sign := func(m *NativeManifest) []byte { return signedJSON(t, kv, testManifestKey, m) }
	base := chainBase()
	inc := chainIncremental(base, testRunID)
	rawBase, rawInc := sign(base), sign(inc)

	// A full backup is a chain of one.
	got, err := VerifyChain(ctx, kv, testManifestKey, testBaseRunID, [][]byte{rawBase})
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].Canonical(), base.Canonical()) {
		t.Fatalf("full backup: %v %v", got, err)
	}
	// The incremental's unchanged DDL lives in its base: it verifies as a
	// chain, base first.
	got, err = VerifyChain(ctx, kv, testManifestKey, testRunID, [][]byte{rawBase, rawInc})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RunID != testBaseRunID || got[1].RunID != testRunID {
		t.Fatalf("chain: %+v", got)
	}
	// Two levels: the second incremental's orders DDL is still the base's.
	inc2 := chainIncremental(inc, testOtherRunID)
	inc2.Databases[0].Objects[2].DDLKey = testRunID + "/metadata/sales/refunds.sql" // refunds unchanged since inc
	inc2.Objects = slices.DeleteFunc(inc2.Objects, func(o ingest.ObjectRecord) bool { return strings.HasSuffix(o.Key, "refunds.sql") })
	if _, err := VerifyChain(ctx, kv, testManifestKey, testOtherRunID, [][]byte{rawBase, rawInc, sign(inc2)}); err != nil {
		t.Fatalf("two incrementals: %v", err)
	}

	refused := func(name, expected string, raws ...[]byte) {
		t.Helper()
		if _, err := VerifyChain(ctx, kv, testManifestKey, expected, raws); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	refused("no manifest", testRunID)
	// Alone, the incremental is not a chain: its first manifest has a base.
	refused("incremental alone", testRunID, rawInc)
	refused("base last", testRunID, rawInc, rawBase)
	refused("last is not the expected run", testOtherRunID, rawBase, rawInc)
	refused("full backup, another run expected", testRunID, rawBase)

	// A DDL key in neither manifest's objects.
	outside := chainIncremental(base, testRunID)
	outside.Databases[0].Objects[0].DDLKey = testBaseRunID + "/metadata/sales/gone.sql"
	refused("DDL outside the chain", testRunID, rawBase, sign(outside))
	// A DDL key under a run that is not in the chain.
	stranger := chainIncremental(base, testRunID)
	stranger.Databases[0].Objects[0].DDLKey = "5b0c3e8a-1f2d-4c6b-8a9e-7d4f2b1c0e93/metadata/sales/orders.sql"
	refused("DDL under a run not in the chain", testRunID, rawBase, sign(stranger))

	// Broken links: the incremental names another base, or the base's hash
	// is not this base's.
	wrongID := chainIncremental(base, testRunID)
	wrongID.BaseRunID = testOtherRunID
	wrongID.Settings["base_backup"] = testOtherRunID
	refused("link to another base run", testRunID, rawBase, sign(wrongID))
	wrongHash := chainIncremental(base, testRunID)
	wrongHash.BaseManifestSHA256 = sum("another base")
	refused("link to another base manifest", testRunID, rawBase, sign(wrongHash))
	// The base re-signed with one value changed: the same run, another hash.
	changed := chainBase()
	changed.Databases[0].Objects[0].Rows++
	refused("base changed after the incremental", testRunID, sign(changed), rawInc)

	// A run twice, with every link good: the base's run signed again on top
	// of the incremental.
	again := chainIncremental(inc, testBaseRunID)
	again.Databases[0].Objects = again.Databases[0].Objects[2:] // refunds, its own DDL
	refused("a run twice", testBaseRunID, rawBase, rawInc, sign(again))

	// A manifest of the chain that does not verify fails the chain with the
	// vault's error.
	var top map[string]json.RawMessage
	_ = json.Unmarshal(rawBase, &top)
	top["signature"] = json.RawMessage(`"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"`)
	badSig, _ := json.Marshal(top)
	if _, err := VerifyChain(ctx, kv, testManifestKey, testRunID, [][]byte{badSig, rawInc}); !errors.Is(err, secrets.ErrSignatureInvalid) {
		t.Fatalf("base signature does not verify: %v", err)
	}
}

// TestSignedIsSnapshot: Signed is what was signed. Changing the caller's
// manifest, or Signed.Manifest, after Sign does not change what MarshalJSON
// writes, so the stored form always verifies.
func TestSignedIsSnapshot(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	m := testNativeManifest()
	want := m.Canonical()
	s, err := Sign(ctx, kv, testManifestKey, m)
	if err != nil {
		t.Fatal(err)
	}
	m.Objects[0].Size++
	m.Settings["late"] = "1"
	m.Databases[0].Objects[0].Rows = 7
	s.Manifest.Objects[1].Size++
	s.Manifest.Settings["later"] = "2"
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifySigned(ctx, kv, testManifestKey, testRunID, raw)
	if err != nil {
		t.Fatalf("stored form after the manifests changed: %v", err)
	}
	if !bytes.Equal(got.Canonical(), want) {
		t.Fatalf("stored form is not what was signed:\n got %s\nwant %s", got.Canonical(), want)
	}
}

func TestManifestSHA256(t *testing.T) {
	m := testNativeManifest()
	h := sha256.Sum256(m.Canonical())
	if got := m.SHA256(); got != hex.EncodeToString(h[:]) || !isSHA256Hex(got) {
		t.Fatalf("SHA256 %q, want the hex SHA-256 of Canonical", got)
	}
	if got := m.SHA256(); got != hex.EncodeToString(m.digest()) {
		t.Fatal("SHA256 is not the signed digest")
	}
	r := testNativeManifest()
	reverse(r.Objects)
	if r.SHA256() != m.SHA256() {
		t.Fatal("SHA256 depends on list order")
	}
	r.Objects[0].Size++
	if r.SHA256() == m.SHA256() {
		t.Fatal("SHA256 does not change with a value")
	}
}

func TestClip(t *testing.T) {
	short := strings.Repeat("é", 128)
	if got := clip(short); got != strconv.Quote(short) {
		t.Fatalf("128 runes are cut: %s", got)
	}
	long := strings.Repeat("é", 129)
	if got, want := clip(long), strconv.Quote(strings.Repeat("é", 128)+"…"); got != want {
		t.Fatalf("129 runes:\n got %s\nwant %s", got, want)
	}
	if got := clip("a\x00\"b"); got != `"a\x00\"b"` {
		t.Fatalf("still %%q-quoted: %s", got)
	}
}

// TestErrorsClipAttackerStrings: strings from the stored manifest appear in
// errors cut to 128 runes, so a multi-megabyte key does not land in a log
// line or a job's error.
func TestErrorsClipAttackerStrings(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	huge := strings.Repeat("k", 2<<20)
	raw := string(signedJSON(t, kv, testManifestKey, testNativeManifest()))
	cases := map[string]string{
		"object of another run": strings.Replace(raw, `"key":"`+testRunID+`/.backup"`, `"key":"`+huge+`/.backup"`, 1),
		"DDL key":               strings.Replace(raw, `"ddl_key":"`+testRunID+`/metadata/sales/by_day.sql"`, `"ddl_key":"`+huge+`"`, 1),
		"run id":                strings.Replace(raw, `"run_id":"`+testRunID+`"`, `"run_id":"`+huge+`"`, 1),
		"format":                strings.Replace(raw, NativeManifestFormat, huge, 1),
		"kind":                  strings.Replace(raw, `"kind":"view"`, `"kind":"`+huge+`"`, 1),
		"object sha256":         strings.Replace(raw, sum(".backup"), huge, 1),
		"key id":                strings.Replace(raw, `"key_id":"`+testManifestKey+`/1"`, `"key_id":"`+huge+`"`, 1),
		"key id name":           strings.Replace(raw, `"key_id":"`+testManifestKey+`/1"`, `"key_id":"`+strings.Repeat("a", 127)+`/1"`, 1),
		"unknown field":         strings.Replace(raw, `"run_id"`, `"`+huge+`":"x","run_id"`, 1),
		"duplicate key":         strings.Replace(raw, `"run_id"`, `"`+huge+`":"x","`+huge+`":"x","run_id"`, 1),
		"database name twice":   strings.Replace(strings.Replace(raw, `"name":"dicts"`, `"name":"`+huge+`"`, 1), `"name":"sales"`, `"name":"`+huge+`"`, 1),
	}
	for name, bad := range cases {
		_, err := VerifySigned(ctx, kv, testManifestKey, testRunID, []byte(bad))
		if !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if n := len(err.Error()); n > 1024 {
			t.Errorf("%s: a %d-byte error: %.200s...", name, n, err)
		}
	}
	for name, change := range map[string]func(m *NativeManifest){
		"object key": func(m *NativeManifest) { m.Objects[1].Key = huge },
		"not UTF-8":  func(m *NativeManifest) { m.Settings["compression_method"] = huge + "\xff" },
	} {
		m := testNativeManifest()
		change(m)
		_, err := Sign(ctx, kv, testManifestKey, m)
		if !errors.Is(err, ErrManifestInvalid) || len(err.Error()) > 1024 || !strings.Contains(err.Error(), strings.Repeat("k", 128)+`…"`) {
			t.Errorf("Sign, %s: %.300s", name, err)
		}
	}
}

// TestManifestSizeCap: Sign refuses a manifest whose stored form would be
// over MaxNativeManifestBytes, and VerifySigned refuses such input before
// parsing it.
func TestManifestSizeCap(t *testing.T) {
	ctx := context.Background()
	kv := newFakeVault()
	m := testNativeManifest()
	m.Settings["pad"] = ""
	m.Settings["pad"] = strings.Repeat("x", MaxNativeManifestBytes-len(m.Canonical()))
	if len(m.Canonical()) != MaxNativeManifestBytes {
		t.Fatalf("test setup: %d bytes", len(m.Canonical()))
	}
	if _, err := Sign(ctx, kv, testManifestKey, m); !errors.Is(err, ErrManifestInvalid) || len(kv.keys) != 0 {
		t.Fatalf("Sign at the cap (the stored form is over it): %v", err)
	}
	// The largest manifest Sign takes is stored within the cap, even with
	// the longest key ID. (Parsing 64 MiB is left out: it is slow under
	// -race, and the size check is the first thing VerifySigned does.)
	m.Settings["pad"] = m.Settings["pad"][:len(m.Settings["pad"])-maxSignedOverhead]
	s, err := Sign(ctx, kv, testManifestKey, m)
	if err != nil {
		t.Fatalf("Sign under the cap: %v", err)
	}
	s.KeyID = strings.Repeat("k", 127) + "/" + strings.Repeat("v", 127)
	raw, err := s.MarshalJSON()
	if err != nil || len(raw) != MaxNativeManifestBytes {
		t.Fatalf("stored form: %d bytes, want exactly the cap; %v", len(raw), err)
	}
	// Over the cap: refused for its size, before it is parsed.
	kv.verifies.Store(0)
	if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, append(raw, ' ')); !errors.Is(err, ErrManifestInvalid) || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("over the cap: %v", err)
	}
	if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, bytes.Repeat([]byte("{"), MaxNativeManifestBytes+1)); !errors.Is(err, ErrManifestInvalid) || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("over the cap, not JSON: %v", err)
	}
	if n := kv.verifies.Load(); n != 0 {
		t.Fatal("the vault was asked")
	}
}

func TestIsNotVerified(t *testing.T) {
	for _, err := range []error{ErrManifestInvalid, secrets.ErrSignatureInvalid, secrets.ErrKeyNotFound, secrets.ErrKeyDisabled} {
		if !IsNotVerified(err) || !IsNotVerified(fmt.Errorf("verify native manifest: %w", err)) {
			t.Errorf("%v: not IsNotVerified", err)
		}
	}
	for _, err := range []error{nil, errors.New("get key: 503 ServiceUnavailable"), context.DeadlineExceeded, secrets.ErrSecretForbidden} {
		if IsNotVerified(err) {
			t.Errorf("%v: IsNotVerified", err)
		}
	}
	// From VerifySigned: a refused manifest is not verified; a vault that is
	// down is a transient error, not a verdict.
	ctx := context.Background()
	kv := newFakeVault()
	raw := signedJSON(t, kv, testManifestKey, testNativeManifest())
	if _, err := VerifySigned(ctx, kv, testManifestKey, testOtherRunID, raw); !IsNotVerified(err) {
		t.Errorf("another run: %v", err)
	}
	kv.verifyErr = errors.New("get key olympos-manifest/1: 503 ServiceUnavailable")
	if _, err := VerifySigned(ctx, kv, testManifestKey, testRunID, raw); err == nil || IsNotVerified(err) {
		t.Errorf("vault down: %v", err)
	}
}

// writeStringByRune is writeString as it was first written, rune by rune:
// the reference the faster one must match byte for byte.
func writeStringByRune(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0xf])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func TestWriteStringMatchesByRune(t *testing.T) {
	// Random bytes biased to what needs care: controls, quotes, backslashes,
	// multi-byte runes, invalid and truncated UTF-8, U+FFFD itself.
	pieces := []string{"a", "z", "\x00", "\x1f", "\x7f", "\"", "\\", "\b", "\f", "\n", "\r", "\t", "/",
		"é", "\u2028", "日本", "\U0001F600", "\ufffd", "\xff", "\xc3", "\xe6\x97", "\xed\xa0\x80", "\xf4\x90\x80\x80"}
	rnd := func(n int) int {
		var b [1]byte
		_, _ = rand.Read(b[:])
		return int(b[0]) % n
	}
	for range 20000 {
		var s strings.Builder
		for range rnd(12) {
			s.WriteString(pieces[rnd(len(pieces))])
		}
		var got, want bytes.Buffer
		writeString(&got, s.String())
		writeStringByRune(&want, s.String())
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("%q:\n got %q\nwant %q", s.String(), got.Bytes(), want.Bytes())
		}
	}
}
