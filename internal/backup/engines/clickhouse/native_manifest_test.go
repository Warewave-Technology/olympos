package clickhouse

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
)

const testManifestKey = "olympos-manifest"

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// testNativeManifest is a small full manifest: an incremental with a base,
// two databases, every object kind.
func testNativeManifest() *NativeManifest {
	return &NativeManifest{
		Format:             NativeManifestFormat,
		RunID:              "run-2",
		BaseRunID:          "run-1",
		BaseManifestSHA256: sum("base"),
		ServerVersion:      "25.8.1.1",
		Settings:           map[string]string{"compression_method": "zstd", "base_backup": "run-1", "id": "run-2"},
		// Every DDLKey below is one of these objects. The data part is last:
		// TestVerifyRefusesTamper drops it.
		Objects: []ingest.ObjectRecord{
			{Key: "run-2/metadata/sales/orders.sql", Size: 120, SHA256: sum("orders.sql")},
			{Key: "run-2/.backup", Size: 4096, SHA256: sum(".backup")},
			{Key: "run-2/metadata/sales/orders_mv.sql", Size: 140, SHA256: sum("orders_mv.sql")},
			{Key: "run-2/metadata/sales/by_day.sql", Size: 90, SHA256: sum("by_day.sql")},
			{Key: "run-2/metadata/dicts/countries.sql", Size: 300, SHA256: sum("countries.sql")},
			{Key: "run-2/metadata/sales.sql", Size: 0, SHA256: sum("")},
			{Key: "run-2/data/sales/orders/all_1_1_0/data.bin", Size: 1 << 20, SHA256: sum("data.bin")},
		},
		Databases: []NativeDatabase{
			{Name: "sales", Objects: []NativeObject{
				{Name: "orders_mv", Kind: KindMaterializedView, Engine: "MaterializedView", DDLKey: "run-2/metadata/sales/orders_mv.sql"},
				{Name: "orders", Kind: KindTable, Engine: "MergeTree", Rows: 42, DDLKey: "run-2/metadata/sales/orders.sql"},
				{Name: "by_day", Kind: KindView, Engine: "View", DDLKey: "run-2/metadata/sales/by_day.sql"},
			}},
			{Name: "dicts", Objects: []NativeObject{
				{Name: "countries", Kind: KindDictionary, Engine: "Dictionary", DDLKey: "run-2/metadata/dicts/countries.sql"},
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
		{`"key":"run-2/.backup"`, `"key":"run-2/data/`}, {`"key":"run-2/metadata/sales.sql"`, `"key":"run-2/metadata/sales/orders.sql"`},
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
	if s.KeyID != testManifestKey+"/1" || s.Manifest != m {
		t.Fatalf("signed: key %q, manifest %p", s.KeyID, s.Manifest)
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
	got, err := VerifySigned(ctx, kv, testManifestKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Canonical(), m.Canonical()) {
		t.Fatalf("verified manifest differs:\n got %s\nwant %s", got.Canonical(), m.Canonical())
	}
	if got.RunID != "run-2" || got.Settings["id"] != "run-2" || len(got.Objects) != 7 || len(got.Databases) != 2 {
		t.Fatalf("verified manifest: %+v", got)
	}

	// json.Marshal escapes <, > and & in what MarshalJSON returns: other
	// bytes than Canonical, the same manifest, so it verifies.
	m.Settings["note"] = "<a & b>"
	raw = signedJSON(t, kv, testManifestKey, m)
	if bytes.ContainsAny(raw, "<&>") || !bytes.Contains(m.Canonical(), []byte("<a & b>")) {
		t.Fatalf("expected encoding/json to escape HTML: %s", raw)
	}
	if got, err := VerifySigned(ctx, kv, testManifestKey, raw); err != nil || got.Settings["note"] != "<a & b>" {
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
	got, err := VerifySigned(ctx, kv, testManifestKey, []byte(b.String()))
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
	if got.Objects[0].Key != "run-2/.backup" || got.Databases[0].Name != "dicts" || got.Databases[1].Objects[0].Name != "by_day" {
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
		if _, err := VerifySigned(ctx, kv, testManifestKey, bad); err == nil {
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
		if _, err := VerifySigned(ctx, kv, testManifestKey, bad); !errors.Is(err, secrets.ErrSignatureInvalid) {
			t.Fatalf("changed manifest: %v", err)
		}
	}
	// The signature of the trusted key moved onto a manifest of another
	// version, or the key ID swapped: refused.
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	top["key_id"] = json.RawMessage(`"` + testManifestKey + `/2"`)
	bad, _ := json.Marshal(top)
	if _, err := VerifySigned(ctx, kv, testManifestKey, bad); !errors.Is(err, secrets.ErrKeyNotFound) {
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
	if _, err := VerifySigned(ctx, kv, "other-key", raw); err != nil {
		t.Fatalf("the signature itself is valid: %v", err)
	}
	kv.verifies.Store(0)
	if _, err := VerifySigned(ctx, kv, testManifestKey, raw); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("manifest signed by another key: %v", err)
	}
	if n := kv.verifies.Load(); n != 0 {
		t.Fatalf("the vault was asked %d times about an untrusted key", n)
	}
	raw = signedJSON(t, kv, testManifestKey, testNativeManifest())
	if _, err := VerifySigned(ctx, kv, "OLYMPOS-Manifest", raw); err != nil {
		t.Fatalf("trusted name in another case: %v", err)
	}
	if _, err := VerifySigned(ctx, kv, "", raw); !errors.Is(err, ErrManifestInvalid) {
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
		"duplicate run_id":       strings.Replace(raw, `"run_id":"run-2"`, `"run_id":"run-9","run_id":"run-2"`, 1),
		"duplicate setting":      strings.Replace(raw, `"id":"run-2"`, `"id":"run-9","id":"run-2"`, 1),
		"unknown object key":     strings.Replace(raw, `"key":"run-2/.backup"`, `"key":"run-2/.backup","mode":1`, 1),
		"null settings":          strings.Replace(raw, `"settings":{"base_backup":"run-1","compression_method":"zstd","id":"run-2"}`, `"settings":null`, 1),
		"other format":           strings.Replace(raw, NativeManifestFormat, "olympos.clickhouse.native/v2", 1),
		"logical format":         strings.Replace(raw, NativeManifestFormat, ManifestFormat, 1),
		"empty run_id":           strings.Replace(raw, `"run_id":"run-2"`, `"run_id":""`, 1),
		"empty object key":       strings.Replace(raw, `"key":"run-2/.backup"`, `"key":""`, 1),
		"upper-case sha256":      strings.Replace(raw, sum(".backup"), strings.ToUpper(sum(".backup")), 1),
		"short sha256":           strings.Replace(raw, sum(".backup"), sum(".backup")[:63], 1),
		"negative size":          strings.Replace(raw, `"size":4096`, `"size":-1`, 1),
		"fractional size":        strings.Replace(raw, `"size":4096`, `"size":4096.0`, 1),
		"duplicate object key":   strings.Replace(raw, `"key":"run-2/.backup"`, `"key":"run-2/data/sales/orders/all_1_1_0/data.bin"`, 1),
		"unknown kind":           strings.Replace(raw, `"kind":"view"`, `"kind":"live_view"`, 1),
		"empty database name":    strings.Replace(raw, `"name":"dicts"`, `"name":""`, 1),
		"duplicate database":     strings.Replace(raw, `"name":"dicts"`, `"name":"sales"`, 1),
		"duplicate table":        strings.Replace(raw, `"name":"by_day"`, `"name":"orders"`, 1),
		"base without its hash":  strings.Replace(raw, sum("base"), "", 1),
		"hash without a base":    strings.Replace(raw, `"base_run_id":"run-1"`, `"base_run_id":""`, 1),
		"bad base hash":          strings.Replace(raw, sum("base"), h[:10], 1),
		"key id without version": strings.Replace(raw, `"key_id":"olympos-manifest/1"`, `"key_id":"olympos-manifest"`, 1),
		"DDL not an object":      strings.Replace(raw, `"ddl_key":"run-2/metadata/sales/by_day.sql"`, `"ddl_key":"run-2/metadata/sales/nope.sql"`, 1),
		"no DDL":                 strings.Replace(raw, `"ddl_key":"run-2/metadata/sales/by_day.sql"`, `"ddl_key":""`, 1),
		"DDL of another run":     strings.Replace(raw, `"ddl_key":"run-2/metadata/sales/by_day.sql"`, `"ddl_key":"run-1/metadata/sales/by_day.sql"`, 1),
		"DDL climbing out":       strings.Replace(raw, `"ddl_key":"run-2/metadata/sales/by_day.sql"`, `"ddl_key":"run-2/../run-1/metadata/sales/by_day.sql"`, 1),
		"object of another run":  strings.Replace(raw, `"key":"run-2/.backup"`, `"key":"run-1/.backup"`, 1),
		"object climbing out":    strings.Replace(raw, `"key":"run-2/.backup"`, `"key":"run-2/../run-1/.backup"`, 1),
		"object with a dot":      strings.Replace(raw, `"key":"run-2/.backup"`, `"key":"run-2/./.backup"`, 1),
		"object with empty part": strings.Replace(raw, `"key":"run-2/.backup"`, `"key":"run-2//.backup"`, 1),
		"object that is the run": strings.Replace(raw, `"key":"run-2/.backup"`, `"key":"run-2/"`, 1),
		"object under a prefix":  strings.Replace(raw, `"key":"run-2/.backup"`, `"key":"run-22/.backup"`, 1),
		"run id with a slash":    strings.Replace(raw, `"run_id":"run-2"`, `"run_id":"run-2/data"`, 1),
		"run id dot-dot":         strings.Replace(raw, `"run_id":"run-2"`, `"run_id":".."`, 1),
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
		if _, err := VerifySigned(ctx, kv, testManifestKey, []byte(bad)); !errors.Is(err, ErrManifestInvalid) {
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
	if _, err := VerifySigned(ctx, kv, testManifestKey, []byte(bad)); !errors.Is(err, ErrManifestInvalid) {
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
			m.Databases[0].Objects[0].DDLKey = "run-2/metadata/sales/nope.sql"
		},
		"object of another run": func(m *NativeManifest) { m.Objects[1].Key = "run-1/.backup" },
		"object climbing out":   func(m *NativeManifest) { m.Objects[1].Key = "run-2/../run-1/.backup" },
		"DDL of another run": func(m *NativeManifest) {
			m.Objects[0].Key = "run-1/metadata/sales/orders.sql"
			m.Databases[0].Objects[1].DDLKey = "run-1/metadata/sales/orders.sql"
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
