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
//
// An incremental's unchanged metadata is stored once, in an earlier run of
// its chain, so its DDL keys may name another run. VerifySigned checks one
// manifest; VerifyChain checks a chain, base first, and that every DDL key is
// an object of the chain. Restore uses VerifyChain.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
)

// NativeManifestFormat is the Format of a native backup's manifest.
const NativeManifestFormat = "olympos.clickhouse.native/v1"

// ErrManifestInvalid is returned when a native manifest is not one: badly
// formed, of another format or another run, too large, signed by a key that
// is not the trusted one, or not a chain. A signature that does not verify
// is secrets.ErrSignatureInvalid (or ErrKeyNotFound, ErrKeyDisabled) from
// the vault, wrapped. IsNotVerified tells all of these from a vault that
// could not be asked.
var ErrManifestInvalid = errors.New("clickhouse: native manifest refused")

// MaxNativeManifestBytes caps a native manifest's stored form (Signed's
// JSON). Sign refuses a manifest whose stored form could be larger;
// VerifySigned refuses larger input before parsing it. Readers cap what
// they read from storage at the same size.
const MaxNativeManifestBytes = 64 << 20

// maxSignedOverhead is the most the stored form adds to the canonical
// manifest: the key ID (two Key Vault names of at most 127 characters, which
// need no escaping) and the base64 of a 64-byte signature (88 characters).
const maxSignedOverhead = len(`{"key_id":"","manifest":,"signature":""}`) + 127 + 1 + 127 + 88

// IsNotVerified reports whether err says a manifest does not verify (it is
// refused, or its signature, key or key version is not good) rather than
// that the vault could not be asked: a transient error is not a verdict.
func IsNotVerified(err error) bool {
	return errors.Is(err, ErrManifestInvalid) || errors.Is(err, secrets.ErrSignatureInvalid) ||
		errors.Is(err, secrets.ErrKeyNotFound) || errors.Is(err, secrets.ErrKeyDisabled)
}

// NativeManifest lists everything a native backup run stored.
type NativeManifest struct {
	Format string // NativeManifestFormat
	RunID  string // a canonical lower-case UUID (uuid.UUID.String())
	// BaseRunID is the run an incremental is based on (a UUID, as RunID),
	// with the SHA-256 of that run's canonical manifest (its SHA256()); both
	// empty for a full backup.
	BaseRunID          string
	BaseManifestSHA256 string
	ServerVersion      string            // SELECT version()
	Settings           map[string]string // the BACKUP statement's settings
	// Objects is every object of the run, as the ingest endpoint stored it,
	// each under "<RunID>/".
	Objects []ingest.ObjectRecord
	// PartRows is the row count of every part of the backup, by the path of
	// its count.txt relative to the run ("data/<db>/<table>/<part>/count.txt"):
	// the parts this run wrote, and those it holds in its base, whose
	// count.txt it did not store (R27). A table's Rows is the sum over its
	// parts.
	PartRows  map[string]uint64
	Databases []NativeDatabase
}

// NativeDatabase is one database of the backup and what it holds.
type NativeDatabase struct {
	Name    string         `json:"name"`
	Objects []NativeObject `json:"objects"`
}

// NativeObject is a table, view, materialized view or dictionary, read from
// its metadata/*.sql object (DDLKey), or an object of kind other: one whose
// CREATE ObjectsFromMetadata does not classify with certainty (a LIVE or
// WINDOW VIEW, a table over a table function, …, R28). The restore leaves
// other objects out. DDLKey is an object of this run or, for an
// incremental's unchanged metadata, of an earlier run of its chain. Rows is
// the row count of the BACKUP snapshot, for tables.
type NativeObject struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // KindTable, KindView, KindMaterializedView, KindDictionary or KindOther
	Engine string `json:"engine"`
	Rows   uint64 `json:"rows"`
	DDLKey string `json:"ddl_key"`
}

// Signed is a manifest with its signature, as it is stored:
// {"key_id":"<name>/<version>","manifest":{...},"signature":"<base64>"}.
type Signed struct {
	// Manifest is a copy of the manifest Sign signed, taken when it signed:
	// changing the caller's manifest afterwards does not change it.
	Manifest  *NativeManifest
	Signature string // base64 (standard, padded) of the raw r||s ES256 signature
	KeyID     string // <name>/<version>, as secrets.KeyVault.Sign returns it
	// canonical is what Sign signed. MarshalJSON writes it, so a change to
	// Manifest cannot make the stored form differ from the signature.
	canonical []byte
}

// MarshalJSON writes the stored form: for a Signed from Sign, the canonical
// manifest that was signed; otherwise Manifest's canonical form.
func (s Signed) MarshalJSON() ([]byte, error) {
	c := s.canonical
	if c == nil {
		if s.Manifest == nil {
			return nil, fmt.Errorf("%w: no manifest", ErrManifestInvalid)
		}
		c = s.Manifest.Canonical()
	}
	var b bytes.Buffer
	b.Grow(len(c) + maxSignedOverhead)
	b.WriteString(`{"key_id":`)
	writeString(&b, s.KeyID)
	b.WriteString(`,"manifest":`)
	b.Write(c)
	b.WriteString(`,"signature":`)
	writeString(&b, s.Signature)
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Canonical returns the manifest's canonical JSON, what its signature
// covers: object keys sorted, no whitespace, UTF-8 strings with only '"',
// '\\' and control characters escaped, integers in decimal. Objects are
// sorted by Key, databases by Name, the objects of a database by Name (ties,
// which a valid manifest does not have, by their encoding), part rows by
// path. Nil and empty collections are the same. The encoding is written here, not left to
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

	b.WriteString(`,"part_rows":{`)
	for i, p := range slices.Sorted(maps.Keys(m.PartRows)) {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(&b, p)
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(m.PartRows[p], 10))
	}
	b.WriteByte('}')

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
// would decode it. Runs of bytes that need nothing are copied at once: a
// manifest can be tens of megabytes.
func writeString(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	done := 0 // s[:done] is written
	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf {
			r, size := utf8.DecodeRuneInString(s[i:])
			if r != utf8.RuneError || size != 1 {
				i += size
				continue
			}
			b.WriteString(s[done:i])
			b.WriteRune(utf8.RuneError)
			i++
			done = i
			continue
		}
		if c >= 0x20 && c != '"' && c != '\\' {
			i++
			continue
		}
		b.WriteString(s[done:i])
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteString(`\u00`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		}
		i++
		done = i
	}
	b.WriteString(s[done:])
	b.WriteByte('"')
}

// digest is what the signature covers.
func (m *NativeManifest) digest() []byte {
	d := sha256.Sum256(m.Canonical())
	return d[:]
}

// SHA256 is the hex SHA-256 of the canonical manifest: what the signature
// covers, and what an incremental names as BaseManifestSHA256.
func (m *NativeManifest) SHA256() string {
	return hex.EncodeToString(m.digest())
}

// clone is a deep copy of m.
func (m *NativeManifest) clone() *NativeManifest {
	c := *m
	c.Settings = maps.Clone(m.Settings)
	c.Objects = slices.Clone(m.Objects)
	c.PartRows = maps.Clone(m.PartRows)
	c.Databases = slices.Clone(m.Databases)
	for i := range c.Databases {
		c.Databases[i].Objects = slices.Clone(c.Databases[i].Objects)
	}
	return &c
}

// Sign signs m with the newest version of the Key Vault key keyName. It
// refuses a manifest VerifySigned would refuse, one whose stored form could
// be over MaxNativeManifestBytes included. The Signed it returns holds a
// copy of m.
func Sign(ctx context.Context, kv secrets.KeyVault, keyName string, m *NativeManifest) (Signed, error) {
	if m == nil {
		return Signed{}, fmt.Errorf("%w: no manifest", ErrManifestInvalid)
	}
	m = m.clone()
	c := m.Canonical()
	if len(c) > MaxNativeManifestBytes-maxSignedOverhead {
		return Signed{}, fmt.Errorf("%w: the manifest is %d bytes, over the %d bytes a stored manifest may have",
			ErrManifestInvalid, len(c), MaxNativeManifestBytes-maxSignedOverhead)
	}
	if err := m.validate(); err != nil {
		return Signed{}, err
	}
	d := sha256.Sum256(c)
	sig, keyID, err := kv.Sign(ctx, keyName, d[:])
	if err != nil {
		return Signed{}, fmt.Errorf("sign native manifest: %w", err)
	}
	return Signed{Manifest: m, Signature: base64.StdEncoding.EncodeToString(sig), KeyID: keyID, canonical: c}, nil
}

// VerifySigned parses a stored Signed manifest and verifies it as the
// manifest of run expectedRunID: a sidecar copied from another run is
// refused. The key ID must name trustedKeyName (keyVault.manifestKeyName;
// compared case-insensitively, as Key Vault key names are): a key ID read
// from storage can name any key in the vault, and kv.Verify does not decide
// which is trusted. Everything that is not exactly a valid manifest of that
// run, or is over MaxNativeManifestBytes, is ErrManifestInvalid, refused
// before the vault is asked; a signature that does not verify is the
// vault's error, wrapped. The manifest it returns has its lists in
// canonical order, whatever order they were stored in.
//
// A DDL key under another run is not checked here: use VerifyChain.
func VerifySigned(ctx context.Context, kv secrets.KeyVault, trustedKeyName, expectedRunID string, raw []byte) (*NativeManifest, error) {
	refuse := func(format string, a ...any) (*NativeManifest, error) {
		return nil, fmt.Errorf("%w: %s", ErrManifestInvalid, fmt.Sprintf(format, a...))
	}
	if len(raw) > MaxNativeManifestBytes {
		return refuse("%d bytes, over the %d bytes a stored manifest may have", len(raw), MaxNativeManifestBytes)
	}
	// encoding/json errors can quote the input (an unknown field's name):
	// they are clipped too.
	if err := noDuplicateKeys(raw); err != nil {
		return refuse("%s", short(err.Error()))
	}
	// encoding/json matches field names case-insensitively: the top level is
	// read as a map, its keys compared exactly.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return refuse("%s", short(err.Error()))
	}
	if len(top) != 3 || top["manifest"] == nil || top["signature"] == nil || top["key_id"] == nil {
		return refuse("want exactly manifest, signature and key_id")
	}
	var sig64, keyID string
	if err := json.Unmarshal(top["signature"], &sig64); err != nil {
		return refuse("signature: %s", short(err.Error()))
	}
	if err := json.Unmarshal(top["key_id"], &keyID); err != nil {
		return refuse("key_id: %s", short(err.Error()))
	}
	m, err := decodeManifest(top["manifest"])
	if err != nil {
		return refuse("%s", short(err.Error()))
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	if m.RunID != expectedRunID {
		return refuse("the manifest of run %s, not of run %s", clip(m.RunID), clip(expectedRunID))
	}

	name, err := secrets.KeyIDName(keyID)
	if err != nil {
		return refuse("key_id %s is not <name>/<version>", clip(keyID))
	}
	if trustedKeyName == "" || !strings.EqualFold(name, trustedKeyName) {
		return refuse("signed by key %s, not by the manifest key %s", clip(name), clip(trustedKeyName))
	}
	// Strict refuses non-zero unused bits in the last character. That is
	// tidiness, not uniqueness: Strict still skips \r and \n, and ES256
	// signatures are malleable anyway. Nothing relies on one encoding.
	sig, err := base64.StdEncoding.Strict().DecodeString(sig64)
	if err != nil {
		return refuse("signature: %v", err)
	}
	if len(sig) != 64 {
		return refuse("signature is %d bytes, want 64 (ES256 r||s)", len(sig))
	}
	if err := kv.Verify(ctx, keyID, m.digest(), sig); err != nil {
		return nil, fmt.Errorf("verify native manifest %q: %w", m.RunID, err)
	}
	m.sortCanonical()
	return m, nil
}

// VerifyChain verifies the manifests of a backup chain, base first: a full
// backup is a chain of one, an incremental's chain starts at its full
// backup. Each manifest verifies (VerifySigned); the first has no base; each
// other one's BaseRunID and BaseManifestSHA256 are the previous one's RunID
// and SHA256(); the last is run expectedRunID; no run is in the chain twice;
// and every DDL key of every manifest is an object of the chain. It returns
// the verified manifests in the same order. A chain that is not one is
// ErrManifestInvalid.
func VerifyChain(ctx context.Context, kv secrets.KeyVault, trustedKeyName, expectedRunID string, raws [][]byte) ([]*NativeManifest, error) {
	refuse := func(format string, a ...any) ([]*NativeManifest, error) {
		return nil, fmt.Errorf("%w: chain: %s", ErrManifestInvalid, fmt.Sprintf(format, a...))
	}
	if len(raws) == 0 {
		return refuse("no manifest")
	}
	// From the last manifest back: each one names the run, and the hash, of
	// the one before it.
	ms := make([]*NativeManifest, len(raws))
	runs := map[string]bool{}
	want := expectedRunID
	for i := len(raws) - 1; i >= 0; i-- {
		m, err := VerifySigned(ctx, kv, trustedKeyName, want, raws[i])
		if err != nil {
			return nil, fmt.Errorf("chain manifest %d of %d: %w", i+1, len(raws), err)
		}
		if runs[m.RunID] {
			return refuse("run %s twice", clip(m.RunID))
		}
		runs[m.RunID] = true
		if i < len(raws)-1 && ms[i+1].BaseManifestSHA256 != m.SHA256() {
			return refuse("run %s is based on another manifest of run %s", clip(ms[i+1].RunID), clip(m.RunID))
		}
		ms[i] = m
		switch want = m.BaseRunID; {
		case i == 0 && want != "":
			return refuse("the first manifest, of run %s, is an incremental on run %s", clip(m.RunID), clip(want))
		case i > 0 && want == "":
			return refuse("run %s is a full backup, not the first of the chain", clip(m.RunID))
		}
	}
	keys := map[string]bool{}
	for _, m := range ms {
		for _, o := range m.Objects {
			keys[o.Key] = true
		}
	}
	for _, m := range ms {
		for _, d := range m.Databases {
			for _, o := range d.Objects {
				if !keys[o.DDLKey] {
					return refuse("run %s: %s.%s: DDL %s is not an object of the chain",
						clip(m.RunID), clip(d.Name), clip(o.Name), clip(o.DDLKey))
				}
			}
		}
	}
	return ms, nil
}

// NativeBuild is what a native run left when ClickHouse reported its backup
// created: the input of BuildNativeManifest.
type NativeBuild struct {
	RunID, ServerVersion string
	// Settings are the BACKUP statement's settings.
	Settings map[string]string
	// Objects are the objects the ingest endpoint stored (Session.Objects).
	Objects []ingest.ObjectRecord
	// Body returns a body by bucket-relative key: the run's .backup,
	// metadata/*.sql and count.txt the ingest session kept
	// (Session.Captured) and, for an incremental, objects of its base chain:
	// the metadata/*.sql it did not write again and its base's .backup. Those
	// are read from storage, so checked against the chain's manifests.
	Body func(key string) ([]byte, bool)
	// Base is an incremental's base chain, verified, base first
	// (VerifyChain); nil for a full backup.
	Base []*NativeManifest
}

// BuildNativeManifest builds the manifest of a native run from its .backup
// (ParseBackupMeta), its metadata (ObjectsFromMetadata) and its count.txt
// files (ParseCount). It checks that every file the .backup lists as written
// by the run was stored whole. Every part's rows go into PartRows (R27): a
// written count.txt is read, a deduplicated one (data_file) counts as the
// file it names, one in the base counts as the base's count.txt of the same
// content: ClickHouse takes a file from its base by size and checksum, not by
// name, so it counts as the base's count.txt of that size and checksum
// (whose rows the base's manifest holds, written or inherited). A table's
// Rows is the sum over its parts: the count.txt files
// directly under data/<db>/<table>/ (a Log table's) or one level below (a
// MergeTree part's), not a projection's deeper down. A materialized view
// without TO is counted for the view, which holds its inner table's data.
// Anything that cannot be resolved for certain is ErrNativeMeta: the run
// fails rather than sign a manifest that does not hold.
func BuildNativeManifest(b NativeBuild) (*NativeManifest, error) {
	run := b.RunID + "/"
	raw, ok := b.Body(run + ".backup")
	if !ok {
		return nil, metaErr("the run kept no .backup")
	}
	meta, err := ParseBackupMeta(raw)
	if err != nil {
		return nil, err
	}
	m := &NativeManifest{Format: NativeManifestFormat, RunID: b.RunID, ServerVersion: b.ServerVersion,
		Settings: maps.Clone(b.Settings), Objects: slices.Clone(b.Objects), PartRows: map[string]uint64{}}
	switch {
	case meta.BaseBackup != "" && len(b.Base) == 0:
		return nil, metaErr(".backup is an incremental's, and the run has no base")
	case meta.BaseBackup == "" && len(b.Base) > 0:
		return nil, metaErr(".backup is a full backup's, and the run has a base")
	case len(b.Base) > 0:
		last := b.Base[len(b.Base)-1]
		m.BaseRunID, m.BaseManifestSHA256 = last.RunID, last.SHA256()
	}

	stored := map[string]int64{}
	for _, o := range b.Objects {
		stored[o.Key] = o.Size
	}
	if _, ok := stored[run+".backup"]; !ok {
		return nil, metaErr("the run stored no .backup")
	}
	byName := map[string]MetaFile{}
	for _, f := range meta.Files {
		byName[f.Name] = f
		if !f.Written() {
			continue
		}
		size, ok := stored[run+f.Name]
		switch {
		case !ok:
			return nil, metaErr("%s is in .backup but was not stored", clip(f.Name))
		case size < 0 || uint64(size) != f.Size-f.BaseSize:
			return nil, metaErr("%s: stored %d bytes, .backup says %d", clip(f.Name), size, f.Size-f.BaseSize)
		}
	}
	body := func(key string) ([]byte, error) {
		bb, ok := b.Body(key)
		if !ok {
			return nil, metaErr("%s was not kept", clip(key))
		}
		return bb, nil
	}

	metadata := map[string][]byte{}
	for _, f := range meta.Files {
		if !strings.HasPrefix(f.Name, "metadata/") || !strings.HasSuffix(f.Name, ".sql") {
			continue
		}
		key := run + f.Name
		if !f.Written() {
			// Unchanged metadata is the base chain's object (R23).
			if key, err = baseObject(b.Base, f); err != nil {
				return nil, err
			}
		}
		if metadata[key], err = body(key); err != nil {
			return nil, err
		}
	}
	if m.Databases, err = ObjectsFromMetadata(metadata); err != nil {
		return nil, err
	}

	inBase := baseCounts(b.Base, body)
	for _, f := range meta.Files {
		if !strings.HasPrefix(f.Name, "data/") || path.Base(f.Name) != "count.txt" {
			continue
		}
		if !isCountPath(f.Name) {
			return nil, metaErr("%s is not a part's count.txt", clip(f.Name))
		}
		if m.PartRows[f.Name], err = partRows(b.RunID, byName, f, body, inBase); err != nil {
			return nil, err
		}
	}
	for i := range m.Databases {
		d := &m.Databases[i]
		for j := range d.Objects {
			o := &d.Objects[j]
			if o.Rows, err = tableRows(m.PartRows, d.Name, o.Name); err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// baseObject is the key of the base chain's object that holds f, a file of
// an incremental that is all in its base: the newest run of the chain that
// stored a file of that name.
func baseObject(base []*NativeManifest, f MetaFile) (string, error) {
	if !f.UseBase || f.BaseSize != f.Size {
		return "", metaErr("%s was not stored and is not in the base", clip(f.Name))
	}
	for i := len(base) - 1; i >= 0; i-- {
		key := base[i].RunID + "/" + f.Name
		if slices.ContainsFunc(base[i].Objects, func(o ingest.ObjectRecord) bool { return o.Key == key }) {
			return key, nil
		}
	}
	return "", metaErr("%s is in the base, and no run of the base chain stored it", clip(f.Name))
}

// baseCounts returns the rows of a count.txt of the base by its size and
// checksum, read from the base's .backup and its manifest's part rows; it
// reads the .backup on its first call. Without a base it finds nothing.
func baseCounts(base []*NativeManifest, body func(string) ([]byte, error)) func(f MetaFile) (uint64, error) {
	var byContent map[[2]string]uint64
	var readErr error
	return func(f MetaFile) (uint64, error) {
		if len(base) == 0 {
			return 0, metaErr("%s is in the base, and the run has none", clip(f.Name))
		}
		last := base[len(base)-1]
		if byContent == nil && readErr == nil {
			byContent = map[[2]string]uint64{}
			raw, err := body(last.RunID + "/.backup")
			var bm *BackupMeta
			if err == nil {
				bm, err = ParseBackupMeta(raw)
			}
			if err != nil {
				readErr = fmt.Errorf("the base's .backup: %w", err)
				return 0, readErr
			}
			for _, bf := range bm.Files {
				if n, ok := last.PartRows[bf.Name]; ok && path.Base(bf.Name) == "count.txt" {
					byContent[[2]string{strconv.FormatUint(bf.Size, 10), bf.Checksum}] = n
				}
			}
		}
		if readErr != nil {
			return 0, readErr
		}
		n, ok := byContent[[2]string{strconv.FormatUint(f.Size, 10), f.Checksum}]
		if !ok {
			return 0, metaErr("%s is in the base, and the base has no rows for a count.txt of its size and checksum", clip(f.Name))
		}
		return n, nil
	}
}

// partRows is the row count of the part whose count.txt is f, a file of run.
func partRows(run string, byName map[string]MetaFile, f MetaFile, body func(string) ([]byte, error),
	inBase func(MetaFile) (uint64, error)) (uint64, error) {
	name := f.Name
	switch {
	case f.Written():
	case f.DataFile != "":
		// ParseBackupMeta checked that the data file is a written file of
		// the same size and checksum: the same bytes.
		name = byName[f.DataFile].Name
	case f.UseBase && f.BaseSize == f.Size:
		return inBase(f)
	default:
		return 0, metaErr("%s: the rows of an empty or partly stored count.txt cannot be read", clip(f.Name))
	}
	raw, err := body(run + "/" + name)
	if err != nil {
		return 0, err
	}
	n, err := ParseCount(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", clip(name), err)
	}
	return n, nil
}

// tableRows sums the rows of the parts of db.name: the count.txt files right
// under data/<db>/<name>/ or one level below it.
func tableRows(parts map[string]uint64, db, name string) (uint64, error) {
	dir := "data/" + escapeForFileName(db) + "/" + escapeForFileName(name) + "/"
	var total uint64
	for p, n := range parts {
		rest, ok := strings.CutPrefix(p, dir)
		if !ok || rest != "count.txt" && strings.Count(rest, "/") != 1 {
			continue
		}
		if total+n < total {
			return 0, metaErr("%s.%s: more rows than a count holds", clip(db), clip(name))
		}
		total += n
	}
	return total, nil
}

// SignNativeManifest implements backup.NativeEngine: it builds the run's
// manifest (BuildNativeManifest), signs it, and verifies the stored form, as
// a reader will (VerifySigned, the trusted key and the run), before anything
// writes it (R25).
func (Engine) SignNativeManifest(ctx context.Context, in backup.NativeManifestInput) (*backup.NativeManifestResult, error) {
	m, err := BuildNativeManifest(NativeBuild{RunID: in.RunID, ServerVersion: in.ServerVersion, Settings: statementSettings(in.RunID),
		Objects: in.Objects, Body: in.Captured})
	if err != nil {
		return nil, err
	}
	s, err := Sign(ctx, in.KV, in.KeyName, m)
	if err != nil {
		return nil, err
	}
	raw, err := s.MarshalJSON()
	if err != nil {
		return nil, err
	}
	v, err := VerifySigned(ctx, in.KV, in.KeyName, in.RunID, raw)
	if err != nil {
		return nil, fmt.Errorf("the signed manifest does not verify: %w", err)
	}
	return &backup.NativeManifestResult{Signed: raw, SHA256: v.SHA256()}, nil
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
	PartRows           map[string]uint64 `json:"part_rows"`
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
		ServerVersion: w.ServerVersion, Settings: w.Settings, PartRows: w.PartRows, Databases: w.Databases,
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
				return fmt.Errorf("key %s twice", clip(k))
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
// refusal is ErrManifestInvalid. Strings from the manifest are clipped in
// its errors (clip).
func (m *NativeManifest) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrManifestInvalid, fmt.Sprintf(format, a...))
	}
	if m.Format != NativeManifestFormat {
		return bad("format %s, want %q", clip(m.Format), NativeManifestFormat)
	}
	// Run IDs are UUIDs, so one path segment: every object key is under
	// "<run-id>/", and a manifest vouches only for its own run's objects,
	// never for another run's or a path that climbs out.
	if !isRunID(m.RunID) {
		return bad("run id %s is not a lower-case UUID", clip(m.RunID))
	}
	if (m.BaseRunID == "") != (m.BaseManifestSHA256 == "") {
		return bad("a base run id and its manifest's SHA-256 go together")
	}
	if m.BaseRunID != "" {
		switch {
		case !isRunID(m.BaseRunID):
			return bad("base run id %s is not a lower-case UUID", clip(m.BaseRunID))
		case m.BaseRunID == m.RunID:
			return bad("run %s is its own base", clip(m.RunID))
		case !isSHA256Hex(m.BaseManifestSHA256):
			return bad("base manifest SHA-256 %s is not 64 lower-case hex digits", clip(m.BaseManifestSHA256))
		}
	}
	strs := []string{m.ServerVersion}
	for k, v := range m.Settings {
		strs = append(strs, k, v)
	}
	keys := map[string]bool{}
	for _, o := range m.Objects {
		switch {
		case o.Key == "":
			return bad("an object without a key")
		case keys[o.Key]:
			return bad("object %s twice", clip(o.Key))
		case !m.ownKey(o.Key):
			return bad("object %s is not under %q", clip(o.Key), m.RunID+"/")
		case o.Size < 0:
			return bad("object %s: size %d", clip(o.Key), o.Size)
		case !isSHA256Hex(o.SHA256):
			return bad("object %s: SHA-256 %s is not 64 lower-case hex digits", clip(o.Key), clip(o.SHA256))
		}
		keys[o.Key] = true
	}
	for p := range m.PartRows {
		if !isCountPath(p) {
			return bad("part rows of %s: not data/<db>/<table>/[<part>/…]count.txt", clip(p))
		}
		strs = append(strs, p)
	}
	dbs := map[string]bool{}
	for _, d := range m.Databases {
		if d.Name == "" || dbs[d.Name] {
			return bad("database %s: empty or twice", clip(d.Name))
		}
		dbs[d.Name] = true
		names := map[string]bool{}
		for _, o := range d.Objects {
			if o.Name == "" || names[o.Name] {
				return bad("database %s: object %s empty or twice", clip(d.Name), clip(o.Name))
			}
			names[o.Name] = true
			switch o.Kind {
			case KindTable, KindView, KindMaterializedView, KindDictionary, KindOther:
			default:
				return bad("%s.%s: kind %s", clip(d.Name), clip(o.Name), clip(o.Kind))
			}
			// The DDL runs as SQL on the target, so its SHA-256 must be signed:
			// it is an object of this run, or a well-formed key of another run
			// (an incremental's unchanged metadata, stored by its base) that
			// VerifyChain finds among the chain's objects.
			run, rest, _ := strings.Cut(o.DDLKey, "/")
			switch {
			case !isRunID(run) || !validPath(rest):
				return bad("%s.%s: DDL %s is not <run-id>/<path>", clip(d.Name), clip(o.Name), clip(o.DDLKey))
			case run == m.RunID && !keys[o.DDLKey]:
				return bad("%s.%s: DDL %s is not an object of the run", clip(d.Name), clip(o.Name), clip(o.DDLKey))
			}
			strs = append(strs, d.Name, o.Name, o.Engine)
		}
	}
	// Run IDs, object keys and DDL keys are checked above: a UUID, and keys
	// that have one as their first segment. Their other segments, and these
	// strings, must be UTF-8.
	for k := range keys {
		strs = append(strs, k)
	}
	for _, d := range m.Databases {
		for _, o := range d.Objects {
			strs = append(strs, o.DDLKey)
		}
	}
	for _, s := range strs {
		if !utf8.ValidString(s) {
			return bad("%s is not UTF-8", clip(s))
		}
	}
	return nil
}

// isRunID reports whether s is a run ID: a UUID in its canonical form,
// lower-case and hyphenated, as uuid.UUID.String() writes it.
func isRunID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

// ownKey reports whether key is "<run-id>/<path>" for m's run.
func (m *NativeManifest) ownKey(key string) bool {
	rest, ok := strings.CutPrefix(key, m.RunID+"/")
	return ok && validPath(rest)
}

// isCountPath reports whether p is the path of a part's count.txt relative to
// the run: data/<db>/<table>/count.txt (a Log table), or deeper (a part's,
// a projection's).
func isCountPath(p string) bool {
	segs := strings.Split(p, "/")
	return len(segs) >= 4 && segs[0] == "data" && segs[len(segs)-1] == "count.txt" && validPath(p)
}

// validPath reports whether p is a relative path with no empty, "." or ".."
// segment.
func validPath(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// maxQuoted is how many runes of a string from a manifest an error quotes.
const maxQuoted = 128

// short cuts s to maxQuoted runes, with an ellipsis when it cut.
func short(s string) string {
	n := 0
	for i := range s {
		if n == maxQuoted {
			return s[:i] + "…"
		}
		n++
	}
	return s
}

// clip quotes s (%q) for an error, cut to maxQuoted runes: a manifest read
// from storage can hold a key of megabytes, which does not belong in a log
// line or a job's error.
func clip(s string) string {
	return strconv.Quote(short(s))
}

// sortCanonical puts the lists in the order Canonical writes them, so what
// VerifySigned returns does not depend on the order it was stored in. Keys
// and names are unique in a valid manifest: the order is total.
func (m *NativeManifest) sortCanonical() {
	slices.SortFunc(m.Objects, func(x, y ingest.ObjectRecord) int { return strings.Compare(x.Key, y.Key) })
	slices.SortFunc(m.Databases, func(x, y NativeDatabase) int { return strings.Compare(x.Name, y.Name) })
	for _, d := range m.Databases {
		slices.SortFunc(d.Objects, func(x, y NativeObject) int { return strings.Compare(x.Name, y.Name) })
	}
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
