package clickhouse

// The signed manifest of a native ClickHouse backup (design
// docs/design/clickhouse-native.md §5).
//
// A native run writes many objects through the ingest endpoint; at the end
// the server lists them all in a NativeManifest, signs it with the Key Vault
// key keyVault.manifestKeyName (ES256) and writes it to every destination.
// A native run whose manifest does not verify does not exist for restore.
//
// What is signed is the SHA-256 of the manifest's canonical JSON
// (Canonical), not of the bytes as stored: VerifySigned parses the stored
// form, refuses anything that is not exactly a manifest (unknown or
// duplicate keys, nulls, another format), re-canonicalises it and verifies
// that. The same manifest with its keys or lists in another order verifies;
// one changed value does not.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
)

// NativeManifestFormat is the Format of a native backup's manifest.
const NativeManifestFormat = "olympos.clickhouse.native/v1"

// ErrManifestInvalid is returned when a native manifest is not one: badly
// formed, of another format, or signed by a key that is not the trusted
// one. A signature that does not verify is secrets.ErrSignatureInvalid (or
// ErrKeyNotFound, ErrKeyDisabled) from the vault, wrapped.
var ErrManifestInvalid = errors.New("clickhouse: native manifest refused")

// NativeManifest lists everything a native backup run stored.
type NativeManifest struct {
	Format string // NativeManifestFormat
	RunID  string
	// BaseRunID is the run an incremental is based on, with the SHA-256 of
	// that run's canonical manifest; both empty for a full backup.
	BaseRunID          string
	BaseManifestSHA256 string
	ServerVersion      string            // SELECT version()
	Settings           map[string]string // the BACKUP statement's settings
	// Objects is every object of the run, as the ingest endpoint stored it.
	Objects   []ingest.ObjectRecord
	Databases []NativeDatabase
}

// NativeDatabase is one database of the backup and what it holds.
type NativeDatabase struct {
	Name    string         `json:"name"`
	Objects []NativeObject `json:"objects"`
}

// NativeObject is a table, view, materialized view or dictionary, read from
// its metadata/*.sql object (DDLKey). Rows is the row count of the BACKUP
// snapshot, for tables.
type NativeObject struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // KindTable, KindView, KindMaterializedView or KindDictionary
	Engine string `json:"engine"`
	Rows   uint64 `json:"rows"`
	DDLKey string `json:"ddl_key"`
}

// Signed is a manifest with its signature, as it is stored:
// {"key_id":"<name>/<version>","manifest":{...},"signature":"<base64>"}.
type Signed struct {
	Manifest  *NativeManifest
	Signature string // base64 (standard, padded) of the raw r||s ES256 signature
	KeyID     string // <name>/<version>, as secrets.KeyVault.Sign returns it
}

// MarshalJSON writes the stored form, the manifest in its canonical form.
func (s Signed) MarshalJSON() ([]byte, error) {
	if s.Manifest == nil {
		return nil, fmt.Errorf("%w: no manifest", ErrManifestInvalid)
	}
	var b bytes.Buffer
	b.WriteString(`{"key_id":`)
	writeString(&b, s.KeyID)
	b.WriteString(`,"manifest":`)
	b.Write(s.Manifest.Canonical())
	b.WriteString(`,"signature":`)
	writeString(&b, s.Signature)
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Canonical returns the manifest's canonical JSON, what its signature
// covers: object keys sorted, no whitespace, UTF-8 strings with only '"',
// '\\' and control characters escaped, integers in decimal. Objects are
// sorted by Key, databases by Name, the objects of a database by Name (ties,
// which a valid manifest does not have, by their encoding). Nil and empty
// collections are the same. The encoding is written here, not left to
// encoding/json, so it does not change with Go versions. m is not modified.
func (m *NativeManifest) Canonical() []byte {
	var b bytes.Buffer
	b.WriteString(`{"base_manifest_sha256":`)
	writeString(&b, m.BaseManifestSHA256)
	b.WriteString(`,"base_run_id":`)
	writeString(&b, m.BaseRunID)

	dbs := make([]keyed, len(m.Databases))
	for i, d := range m.Databases {
		objs := make([]keyed, len(d.Objects))
		for j, o := range d.Objects {
			objs[j] = keyed{o.Name, canonicalObject(o)}
		}
		var db bytes.Buffer
		db.WriteString(`{"name":`)
		writeString(&db, d.Name)
		db.WriteString(`,"objects":`)
		writeArray(&db, objs)
		db.WriteByte('}')
		dbs[i] = keyed{d.Name, db.Bytes()}
	}
	b.WriteString(`,"databases":`)
	writeArray(&b, dbs)

	b.WriteString(`,"format":`)
	writeString(&b, m.Format)

	objs := make([]keyed, len(m.Objects))
	for i, o := range m.Objects {
		var ob bytes.Buffer
		ob.WriteString(`{"key":`)
		writeString(&ob, o.Key)
		ob.WriteString(`,"sha256":`)
		writeString(&ob, o.SHA256)
		ob.WriteString(`,"size":`)
		ob.WriteString(strconv.FormatInt(o.Size, 10))
		ob.WriteByte('}')
		objs[i] = keyed{o.Key, ob.Bytes()}
	}
	b.WriteString(`,"objects":`)
	writeArray(&b, objs)

	b.WriteString(`,"run_id":`)
	writeString(&b, m.RunID)
	b.WriteString(`,"server_version":`)
	writeString(&b, m.ServerVersion)

	b.WriteString(`,"settings":{`)
	keys := make([]string, 0, len(m.Settings))
	for k := range m.Settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(&b, k)
		b.WriteByte(':')
		writeString(&b, m.Settings[k])
	}
	b.WriteString("}}")
	return b.Bytes()
}

func canonicalObject(o NativeObject) []byte {
	var b bytes.Buffer
	b.WriteString(`{"ddl_key":`)
	writeString(&b, o.DDLKey)
	b.WriteString(`,"engine":`)
	writeString(&b, o.Engine)
	b.WriteString(`,"kind":`)
	writeString(&b, o.Kind)
	b.WriteString(`,"name":`)
	writeString(&b, o.Name)
	b.WriteString(`,"rows":`)
	b.WriteString(strconv.FormatUint(o.Rows, 10))
	b.WriteByte('}')
	return b.Bytes()
}

// keyed is an encoded list element and the key the list is sorted by.
type keyed struct {
	key string
	enc []byte
}

// writeArray writes elems as a JSON array, sorted by key, then by encoding:
// a total order, so the result does not depend on the input order.
func writeArray(b *bytes.Buffer, elems []keyed) {
	slices.SortFunc(elems, func(x, y keyed) int {
		if c := strings.Compare(x.key, y.key); c != 0 {
			return c
		}
		return bytes.Compare(x.enc, y.enc)
	})
	b.WriteByte('[')
	for i, e := range elems {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(e.enc)
	}
	b.WriteByte(']')
}

// writeString writes s as a JSON string: '"' and '\\' escaped, control
// characters as \b \f \n \r \t or \u00XX, everything else as is. An invalid
// UTF-8 byte (validate refuses them) is written as U+FFFD, as encoding/json
// would decode it.
func writeString(b *bytes.Buffer, s string) {
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
			b.WriteRune(r) // utf8.RuneError for an invalid byte
		}
	}
	b.WriteByte('"')
}

// digest is what the signature covers.
func (m *NativeManifest) digest() []byte {
	d := sha256.Sum256(m.Canonical())
	return d[:]
}

// Sign signs m with the newest version of the Key Vault key keyName. It
// refuses a manifest VerifySigned would refuse.
func Sign(ctx context.Context, kv secrets.KeyVault, keyName string, m *NativeManifest) (Signed, error) {
	if m == nil {
		return Signed{}, fmt.Errorf("%w: no manifest", ErrManifestInvalid)
	}
	if err := m.validate(); err != nil {
		return Signed{}, err
	}
	sig, keyID, err := kv.Sign(ctx, keyName, m.digest())
	if err != nil {
		return Signed{}, fmt.Errorf("sign native manifest: %w", err)
	}
	return Signed{Manifest: m, Signature: base64.StdEncoding.EncodeToString(sig), KeyID: keyID}, nil
}

// VerifySigned parses a stored Signed manifest and verifies it. The key ID
// must name trustedKeyName (keyVault.manifestKeyName; compared
// case-insensitively, as Key Vault key names are): a key ID read from
// storage can name any key in the vault, and kv.Verify does not decide which
// is trusted. Everything that is not exactly a valid manifest is
// ErrManifestInvalid, refused before the vault is asked; a signature that
// does not verify is the vault's error, wrapped.
func VerifySigned(ctx context.Context, kv secrets.KeyVault, trustedKeyName string, raw []byte) (*NativeManifest, error) {
	refuse := func(format string, a ...any) (*NativeManifest, error) {
		return nil, fmt.Errorf("%w: %s", ErrManifestInvalid, fmt.Sprintf(format, a...))
	}
	if err := noDuplicateKeys(raw); err != nil {
		return refuse("%v", err)
	}
	// encoding/json matches field names case-insensitively: the top level is
	// read as a map, its keys compared exactly.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return refuse("%v", err)
	}
	if len(top) != 3 || top["manifest"] == nil || top["signature"] == nil || top["key_id"] == nil {
		return refuse("want exactly manifest, signature and key_id")
	}
	var sig64, keyID string
	if err := json.Unmarshal(top["signature"], &sig64); err != nil {
		return refuse("signature: %v", err)
	}
	if err := json.Unmarshal(top["key_id"], &keyID); err != nil {
		return refuse("key_id: %v", err)
	}
	m, err := decodeManifest(top["manifest"])
	if err != nil {
		return refuse("%v", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}

	name, err := secrets.KeyIDName(keyID)
	if err != nil {
		return refuse("%v", err)
	}
	if trustedKeyName == "" || !strings.EqualFold(name, trustedKeyName) {
		return refuse("signed by key %q, not by the manifest key %q", name, trustedKeyName)
	}
	// Strict: the unused bits of the last character must be zero, so a
	// signature has one encoding.
	sig, err := base64.StdEncoding.Strict().DecodeString(sig64)
	if err != nil {
		return refuse("signature: %v", err)
	}
	if err := kv.Verify(ctx, keyID, m.digest(), sig); err != nil {
		return nil, fmt.Errorf("verify native manifest %s: %w", m.RunID, err)
	}
	return m, nil
}

// manifestJSON is the manifest as it is parsed. Objects has its own type as
// ingest.ObjectRecord carries no JSON names.
type manifestJSON struct {
	Format             string            `json:"format"`
	RunID              string            `json:"run_id"`
	BaseRunID          string            `json:"base_run_id"`
	BaseManifestSHA256 string            `json:"base_manifest_sha256"`
	ServerVersion      string            `json:"server_version"`
	Settings           map[string]string `json:"settings"`
	Objects            []objectJSON      `json:"objects"`
	Databases          []NativeDatabase  `json:"databases"`
}

type objectJSON struct {
	Key    string `json:"key"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// decodeManifest parses the manifest and checks that it is, as a JSON
// value, its own canonical form: every key present, spelled exactly (not in
// another case), no nulls, numbers as integers. Only the order of keys and
// list elements and the whitespace may differ.
func decodeManifest(raw []byte) (*NativeManifest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var w manifestJSON
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	m := &NativeManifest{
		Format: w.Format, RunID: w.RunID, BaseRunID: w.BaseRunID, BaseManifestSHA256: w.BaseManifestSHA256,
		ServerVersion: w.ServerVersion, Settings: w.Settings, Databases: w.Databases,
	}
	for _, o := range w.Objects {
		m.Objects = append(m.Objects, ingest.ObjectRecord{Key: o.Key, Size: o.Size, SHA256: o.SHA256})
	}
	same, err := sameJSON(raw, m.Canonical())
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if !same {
		return nil, errors.New("manifest is not in its canonical form (a key in another case, a null or a missing key)")
	}
	return m, nil
}

// sameJSON reports whether a and b are the same JSON value, lists compared
// as multisets (the canonical form sorts them).
func sameJSON(a, b []byte) (bool, error) {
	va, err := decodeAny(a)
	if err != nil {
		return false, err
	}
	vb, err := decodeAny(b)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(sortLists(va), sortLists(vb)), nil
}

func decodeAny(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}

// sortLists sorts every list in v by the elements' JSON encoding.
func sortLists(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = sortLists(e)
		}
	case []any:
		type elem struct {
			enc string
			v   any
		}
		elems := make([]elem, len(v))
		for i, e := range v {
			e = sortLists(e)
			b, _ := json.Marshal(e) // the same encoder on both sides; maps sorted
			elems[i] = elem{string(b), e}
		}
		slices.SortFunc(elems, func(x, y elem) int { return strings.Compare(x.enc, y.enc) })
		for i, e := range elems {
			v[i] = e.v
		}
	}
	return v
}

// noDuplicateKeys refuses a JSON object with a key twice, at any depth:
// parsers disagree about which one counts.
func noDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	type frame struct {
		keys      map[string]bool // nil for a list
		expectKey bool
	}
	var stack []*frame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].keys != nil {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if n := len(stack); n > 0 && stack[n-1].keys != nil && stack[n-1].expectKey {
			if tok == json.Delim('}') {
				stack = stack[:n-1]
				valueDone()
				continue
			}
			k, _ := tok.(string)
			if stack[n-1].keys[k] {
				return fmt.Errorf("key %q twice", k)
			}
			stack[n-1].keys[k], stack[n-1].expectKey = true, false
			continue
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{keys: map[string]bool{}, expectKey: true})
		case json.Delim('['):
			stack = append(stack, &frame{})
		case json.Delim(']'), json.Delim('}'):
			stack = stack[:len(stack)-1]
			valueDone()
		default:
			valueDone()
		}
	}
}

// validate checks what a manifest must hold to be restored from. Every
// refusal is ErrManifestInvalid.
func (m *NativeManifest) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrManifestInvalid, fmt.Sprintf(format, a...))
	}
	if m.Format != NativeManifestFormat {
		return bad("format %q, want %q", m.Format, NativeManifestFormat)
	}
	if m.RunID == "" {
		return bad("no run id")
	}
	if (m.BaseRunID == "") != (m.BaseManifestSHA256 == "") {
		return bad("a base run id and its manifest's SHA-256 go together")
	}
	if m.BaseRunID != "" && !isSHA256Hex(m.BaseManifestSHA256) {
		return bad("base manifest SHA-256 %q is not 64 lower-case hex digits", m.BaseManifestSHA256)
	}
	strs := []string{m.RunID, m.BaseRunID, m.ServerVersion}
	for k, v := range m.Settings {
		strs = append(strs, k, v)
	}
	keys := map[string]bool{}
	for _, o := range m.Objects {
		switch {
		case o.Key == "":
			return bad("an object without a key")
		case keys[o.Key]:
			return bad("object %q twice", o.Key)
		case o.Size < 0:
			return bad("object %q: size %d", o.Key, o.Size)
		case !isSHA256Hex(o.SHA256):
			return bad("object %q: SHA-256 %q is not 64 lower-case hex digits", o.Key, o.SHA256)
		}
		keys[o.Key] = true
		strs = append(strs, o.Key)
	}
	dbs := map[string]bool{}
	for _, d := range m.Databases {
		if d.Name == "" || dbs[d.Name] {
			return bad("database %q: empty or twice", d.Name)
		}
		dbs[d.Name] = true
		names := map[string]bool{}
		for _, o := range d.Objects {
			if o.Name == "" || names[o.Name] {
				return bad("database %q: object %q empty or twice", d.Name, o.Name)
			}
			names[o.Name] = true
			switch o.Kind {
			case KindTable, KindView, KindMaterializedView, KindDictionary:
			default:
				return bad("%s.%s: kind %q", d.Name, o.Name, o.Kind)
			}
			strs = append(strs, d.Name, o.Name, o.Engine, o.DDLKey)
		}
	}
	for _, s := range strs {
		if !utf8.ValidString(s) {
			return bad("%q is not UTF-8", s)
		}
	}
	return nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
