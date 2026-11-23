package spec

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/google/uuid"
)

// RunCredential is a credential as one run needs it: the secret and what it
// may be sent to. It travels only sealed (SealCredentials).
//
// Username and Secret are *Secret: never encoded as JSON, and printed as
// "[redacted]" or as an address, whatever the verb and however the
// credential is reached (value, pointer, slice, a struct's exported or
// unexported field, fmt or slog). RunCredential itself prints and logs as
// its id and kind only. Call ZeroCredentials when the run is over.
type RunCredential struct {
	ID         uuid.UUID `json:"id"`
	Kind       string    `json:"kind"`
	BoundHosts []string  `json:"bound_hosts"`
	Username   *Secret   `json:"-"`
	Secret     *Secret   `json:"-"`
	HeaderName string    `json:"header_name,omitempty"`
	TokenURL   string    `json:"token_url,omitempty"`
	Scopes     string    `json:"scopes,omitempty"`
}

// String describes c by its id and kind, without its user name or secret.
func (c RunCredential) String() string {
	return fmt.Sprintf("RunCredential{%s %s}", c.ID, c.Kind)
}

// Format writes String for every verb, so that %x, %d or %#v cannot reach
// the fields.
func (c RunCredential) Format(f fmt.State, _ rune) { io.WriteString(f, c.String()) }

// LogValue logs c by its id and kind.
func (c RunCredential) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", c.ID.String()), slog.String("kind", c.Kind))
}

// ZeroCredentials overwrites every user name and secret with zeros and
// drops them.
func ZeroCredentials(creds []RunCredential) {
	for i := range creds {
		creds[i].Username.Zero()
		creds[i].Secret.Zero()
		creds[i].Username, creds[i].Secret = nil, nil
	}
}

// The HPKE suite (decision 2): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// AES-256-GCM, in base mode.
const (
	sealInfo      = "olympos-synthetic-credentials-v1"
	sealAADPrefix = "olympos-synthetic-run:"
	// kemX25519 is the RFC 9180 id of DHKEM(X25519, HKDF-SHA256).
	kemX25519 = 0x0020
)

func sealKEM() hpke.KEM   { return hpke.DHKEM(ecdh.X25519()) }
func sealKDF() hpke.KDF   { return hpke.HKDFSHA256() }
func sealAEAD() hpke.AEAD { return hpke.AES256GCM() }

// GenerateKey makes a key pair for the sealing suite. The probe makes one
// for each Connect stream and keeps it in memory only; it sends
// PublicKey().Bytes() to the server.
func GenerateKey() (hpke.PrivateKey, error) {
	return sealKEM().GenerateKey()
}

// sealAAD binds a sealed message to one run on one cluster.
func sealAAD(runID, clusterID string) ([]byte, error) {
	// A ":" in either id would make two pairs of ids give the same AAD.
	if runID == "" || clusterID == "" || strings.Contains(runID, ":") || strings.Contains(clusterID, ":") {
		return nil, errors.New("spec: run id and cluster id must be non-empty and contain no \":\"")
	}
	return []byte(sealAADPrefix + runID + ":" + clusterID), nil
}

// maxRunCredentials is the most credentials one run carries: one per step.
const maxRunCredentials = MaxSteps

// testHookPlaintext, when set, sees each plaintext buffer after it has
// been zeroed. Tests use it to check the zeroing.
var testHookPlaintext func([]byte)

func zeroPlaintext(pt []byte) {
	clear(pt)
	if testHookPlaintext != nil {
		testHookPlaintext(pt)
	}
}

// SealCredentials encrypts creds to pub, the raw X25519 public key of the
// probe's current Connect stream, for one run on one cluster: with HPKE
// (RFC 9180) in base mode, info "olympos-synthetic-credentials-v1" and AAD
// "olympos-synthetic-run:<runID>:<clusterID>". It returns the encapsulated
// key and the ciphertext. The plaintext buffer is zeroed before it returns.
func SealCredentials(pub []byte, runID, clusterID string, creds []RunCredential) (enc, ct []byte, err error) {
	aad, err := sealAAD(runID, clusterID)
	if err != nil {
		return nil, nil, err
	}
	pk, err := sealKEM().NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("spec: probe public key: %w", err)
	}
	pt, err := encodeCredentials(creds)
	if err != nil {
		return nil, nil, err
	}
	defer zeroPlaintext(pt)
	enc, sender, err := hpke.NewSender(pk, sealKDF(), sealAEAD(), []byte(sealInfo))
	if err != nil {
		return nil, nil, fmt.Errorf("spec: seal credentials: %w", err)
	}
	ct, err = sender.Seal(aad, pt)
	if err != nil {
		return nil, nil, fmt.Errorf("spec: seal credentials: %w", err)
	}
	return enc, ct, nil
}

// OpenCredentials decrypts what SealCredentials sealed for runID on
// clusterID. It fails for another key, another run or cluster, or a
// message that was changed. The decrypted buffer is zeroed before it
// returns; the secrets in the result are copies the caller zeroes with
// ZeroCredentials.
func OpenCredentials(priv hpke.PrivateKey, runID, clusterID string, enc, ct []byte) ([]RunCredential, error) {
	aad, err := sealAAD(runID, clusterID)
	if err != nil {
		return nil, err
	}
	if priv == nil || priv.KEM().ID() != kemX25519 {
		return nil, errors.New("spec: open credentials: key is not a DHKEM(X25519) key")
	}
	r, err := hpke.NewRecipient(enc, priv, sealKDF(), sealAEAD(), []byte(sealInfo))
	if err != nil {
		return nil, fmt.Errorf("spec: open credentials: %w", err)
	}
	pt, err := r.Open(aad, ct)
	if err != nil {
		return nil, fmt.Errorf("spec: open credentials: %w", err)
	}
	defer zeroPlaintext(pt)
	return decodeCredentials(pt)
}

// The plaintext is a small binary encoding rather than JSON so that every
// buffer holding a secret is one this package allocates, sizes exactly and
// zeroes (encoding/json keeps its working buffers in a pool):
//
//	version byte (1)
//	uvarint count
//	per credential: 16-byte id, then the strings kind, username, secret,
//	header name, token URL, scopes, each as uvarint length + bytes, then
//	uvarint count of bound hosts and each as uvarint length + bytes.
const encodingVersion = 1

var errEncoding = errors.New("spec: credentials: malformed plaintext")

func encodeCredentials(creds []RunCredential) ([]byte, error) {
	if len(creds) > maxRunCredentials {
		return nil, fmt.Errorf("spec: at most %d credentials per run", maxRunCredentials)
	}
	size := 1 + uvarintLen(uint64(len(creds)))
	for i := range creds {
		c := &creds[i]
		size += 16 +
			fieldLen(c.Kind) + fieldLen(c.Username.Bytes()) + fieldLen(c.Secret.Bytes()) +
			fieldLen(c.HeaderName) + fieldLen(c.TokenURL) + fieldLen(c.Scopes)
		size += uvarintLen(uint64(len(c.BoundHosts)))
		for _, h := range c.BoundHosts {
			size += fieldLen(h)
		}
	}
	// Sized exactly, so that append never moves the plaintext and leaves
	// a copy behind. Strings are appended as they are, without a []byte
	// copy that would stay behind unzeroed.
	buf := make([]byte, 0, size)
	buf = append(buf, encodingVersion)
	buf = binary.AppendUvarint(buf, uint64(len(creds)))
	for i := range creds {
		c := &creds[i]
		buf = append(buf, c.ID[:]...)
		buf = appendField(buf, c.Kind)
		buf = appendField(buf, c.Username.Bytes())
		buf = appendField(buf, c.Secret.Bytes())
		buf = appendField(buf, c.HeaderName)
		buf = appendField(buf, c.TokenURL)
		buf = appendField(buf, c.Scopes)
		buf = binary.AppendUvarint(buf, uint64(len(c.BoundHosts)))
		for _, h := range c.BoundHosts {
			buf = appendField(buf, h)
		}
	}
	if len(buf) != size || cap(buf) != size {
		// Cannot happen; refuse rather than seal a buffer of unknown origin.
		clear(buf[:cap(buf)])
		return nil, errors.New("spec: credentials: encoding size mismatch")
	}
	return buf, nil
}

// fieldLen is the encoded length of a length-prefixed field.
func fieldLen[T string | []byte](v T) int { return uvarintLen(uint64(len(v))) + len(v) }

func appendField[T string | []byte](buf []byte, v T) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(v)))
	return append(buf, v...)
}

func uvarintLen(v uint64) int {
	var b [binary.MaxVarintLen64]byte
	return binary.PutUvarint(b[:], v)
}

type decoder struct{ b []byte }

func (d *decoder) uvarint() (uint64, bool) {
	v, n := binary.Uvarint(d.b)
	// Only the shortest encoding is accepted, so that one plaintext has
	// one meaning and one form.
	if n <= 0 || n != uvarintLen(v) {
		return 0, false
	}
	d.b = d.b[n:]
	return v, true
}

// bytes returns the next length-prefixed field. It aliases the plaintext.
func (d *decoder) bytes() ([]byte, bool) {
	n, ok := d.uvarint()
	if !ok || n > uint64(len(d.b)) {
		return nil, false
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v, true
}

func decodeCredentials(pt []byte) (out []RunCredential, err error) {
	defer func() {
		if err != nil {
			ZeroCredentials(out)
			out = nil
		}
	}()
	d := &decoder{b: pt}
	if len(d.b) == 0 || d.b[0] != encodingVersion {
		return nil, errEncoding
	}
	d.b = d.b[1:]
	count, ok := d.uvarint()
	if !ok || count > maxRunCredentials {
		return nil, errEncoding
	}
	out = make([]RunCredential, 0, count)
	for range count {
		if len(d.b) < 16 {
			return out, errEncoding
		}
		var c RunCredential
		copy(c.ID[:], d.b[:16])
		d.b = d.b[16:]
		var fields [6][]byte
		for i := range fields {
			if fields[i], ok = d.bytes(); !ok {
				return out, errEncoding
			}
		}
		c.Kind = string(fields[0])
		// Copies: the plaintext they come from is zeroed.
		c.Username = NewSecret(bytes.Clone(fields[1]))
		c.Secret = NewSecret(bytes.Clone(fields[2]))
		c.HeaderName = string(fields[3])
		c.TokenURL = string(fields[4])
		c.Scopes = string(fields[5])
		// The credential is in out before anything else can fail, so the
		// deferred zeroing reaches its secret.
		out = append(out, c)
		hosts, ok := d.uvarint()
		if !ok || hosts > uint64(len(d.b)) {
			return out, errEncoding
		}
		for range hosts {
			h, ok := d.bytes()
			if !ok {
				return out, errEncoding
			}
			out[len(out)-1].BoundHosts = append(out[len(out)-1].BoundHosts, string(h))
		}
	}
	if len(d.b) != 0 {
		return out, errEncoding
	}
	return out, nil
}
