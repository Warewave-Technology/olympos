package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// The files of the olympos-probe-identity Secret, as mounted.
const (
	identityCertFile = "tls.crt"
	identityKeyFile  = "tls.key"
	identityCAFile   = "ca.crt"
	// identityDataLink is the symlink through which Kubernetes swaps a
	// Secret volume's contents in one step.
	identityDataLink = "..data"
	// IdentityPoll is how often the identity files are read again.
	IdentityPoll = 30 * time.Second
	// identityRemind is how often a missing or broken identity is logged
	// again while it stays so.
	identityRemind = 10 * time.Minute
	probeCNSuffix  = "/probe"
)

// identitySnapshot is one valid version of the identity files.
type identitySnapshot struct {
	cert      *tls.Certificate
	pool      *x509.CertPool
	clusterID string
	serial    string
	notAfter  time.Time
	gen       uint64
}

// Identity is the probe's mTLS identity, read from the mounted
// olympos-probe-identity Secret. The agent writes a renewed certificate to
// that Secret and, from then on, the server accepts only the new one, so
// Identity reads the files again every IdentityPoll and reports a change at
// once: the client then closes its stream and dials again with the new
// certificate.
//
// The files are compared by content (a hash of all three), not by inode or
// modification time: Kubernetes updates a Secret volume by swapping the
// "..data" symlink, which leaves the files' own symlinks untouched. When
// "..data" exists, the three files are read through one resolution of it,
// so a swap during the read cannot mix two versions.
type Identity struct {
	dir string
	log *slog.Logger
	// poll is IdentityPoll; tests shorten it.
	poll time.Duration

	mu      sync.Mutex
	cur     *identitySnapshot // nil until a valid identity was read
	hash    [sha256.Size]byte // of the files cur came from
	changed chan struct{}     // closed, and replaced, on each change of cur
	gen     uint64
	lastErr string
	lastLog time.Time
}

// NewIdentity returns the identity in dir. Nothing is read until Watch.
func NewIdentity(dir string, log *slog.Logger) *Identity {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Identity{dir: dir, log: log, poll: IdentityPoll, changed: make(chan struct{})}
}

// Watch reads the files now and then every poll interval until ctx ends.
func (i *Identity) Watch(ctx context.Context) {
	i.reload()
	t := time.NewTicker(i.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			i.reload()
		}
	}
}

// current returns the identity (nil when none was read yet) and a channel
// closed at its next change.
func (i *Identity) current() (*identitySnapshot, <-chan struct{}) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.cur, i.changed
}

// GetClientCertificate serves the current certificate to a TLS handshake.
// Without an identity it returns an empty certificate, which the server
// refuses.
func (i *Identity) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cur, _ := i.current()
	if cur == nil {
		return &tls.Certificate{}, nil
	}
	return cur.cert, nil
}

// reload reads the files and, when their content changed and is valid,
// makes them the current identity. A missing or broken identity keeps the
// previous one (the server may still accept it) and is logged.
func (i *Identity) reload() {
	files, err := i.read()
	if err != nil {
		i.fail(err)
		return
	}
	defer func() {
		for _, f := range files {
			clear(f)
		}
	}()
	h := sha256.New()
	for _, f := range files {
		// Length-prefixed, so that moving bytes between files changes the
		// hash.
		fmt.Fprintf(h, "%d:", len(f))
		h.Write(f)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	i.mu.Lock()
	same := i.cur != nil && sum == i.hash
	i.mu.Unlock()
	if same {
		i.ok()
		return
	}
	snap, err := parseIdentity(files[0], files[1], files[2])
	if err != nil {
		i.fail(err)
		return
	}
	i.set(snap, sum)
}

// read returns the contents of tls.crt, tls.key and ca.crt. Through a
// "..data" link it tries twice: the kubelet removes the directory the link
// pointed to right after a swap, which can fail a read that resolved the
// link just before.
func (i *Identity) read() ([3][]byte, error) {
	out, viaLink, err := i.readOnce()
	if err != nil && viaLink {
		out, _, err = i.readOnce()
	}
	return out, err
}

func (i *Identity) readOnce() (out [3][]byte, viaLink bool, err error) {
	dir := i.dir
	link := filepath.Join(dir, identityDataLink)
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if d, err := filepath.EvalSymlinks(link); err == nil {
			dir, viaLink = d, true
		}
	}
	for n, name := range []string{identityCertFile, identityKeyFile, identityCAFile} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			for _, f := range out {
				clear(f)
			}
			switch {
			case errors.Is(err, fs.ErrNotExist) && name != identityCAFile:
				return out, viaLink, fmt.Errorf("%w (%s missing)", errNoIdentity, name)
			case errors.Is(err, fs.ErrNotExist):
				return out, viaLink, fmt.Errorf("%s missing: the Olympos CA is mounted next to the identity", name)
			}
			return out, viaLink, fmt.Errorf("read %s: %w", name, err)
		}
		out[n] = b
	}
	return out, viaLink, nil
}

var errNoIdentity = errors.New("no probe identity yet: the agent writes it once the probe is enrolled (Install probe in Olympos)")

// parseIdentity checks the files: a certificate with the key that matches
// it, a probe identity (CN <cluster-uuid>/probe), and a CA bundle.
func parseIdentity(certPEM, keyPEM, caPEM []byte) (*identitySnapshot, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls.crt and tls.key: %w", err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("tls.crt: %w", err)
		}
		cert.Leaf = leaf
	}
	id, ok := strings.CutSuffix(leaf.Subject.CommonName, probeCNSuffix)
	if !ok {
		return nil, fmt.Errorf("tls.crt: CN %q is not a probe identity (<cluster-uuid>/probe)", leaf.Subject.CommonName)
	}
	cid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("tls.crt: CN %q is not a probe identity (<cluster-uuid>/probe)", leaf.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bytes.Clone(caPEM)) {
		return nil, errors.New("ca.crt holds no certificate")
	}
	return &identitySnapshot{cert: &cert, pool: pool, clusterID: cid.String(),
		serial: fmt.Sprintf("%x", leaf.SerialNumber), notAfter: leaf.NotAfter}, nil
}

func (i *Identity) set(snap *identitySnapshot, sum [sha256.Size]byte) {
	i.mu.Lock()
	i.gen++
	snap.gen = i.gen
	first := i.cur == nil
	i.cur, i.hash = snap, sum
	close(i.changed)
	i.changed = make(chan struct{})
	i.lastErr = ""
	i.mu.Unlock()
	msg := "probe identity loaded"
	if !first {
		msg = "probe identity changed"
	}
	i.log.Info(msg, "cluster_id", snap.clusterID, "serial", snap.serial, "expires", snap.notAfter)
	if time.Now().After(snap.notAfter) {
		i.log.Warn("probe certificate has expired; the agent renews it", "serial", snap.serial, "expires", snap.notAfter)
	}
}

func (i *Identity) ok() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.lastErr = ""
}

// fail logs err when it is new, and again every identityRemind.
func (i *Identity) fail(err error) {
	i.mu.Lock()
	msg := err.Error()
	have := i.cur != nil
	logIt := msg != i.lastErr || time.Since(i.lastLog) >= identityRemind
	if logIt {
		i.lastErr, i.lastLog = msg, time.Now()
	}
	i.mu.Unlock()
	if !logIt {
		return
	}
	switch {
	case errors.Is(err, errNoIdentity) && !have:
		i.log.Warn("waiting for the probe identity", "dir", i.dir, "reason", msg)
	case have:
		i.log.Warn("cannot read the probe identity files; keeping the identity loaded before", "dir", i.dir, "err", msg)
	default:
		i.log.Error("cannot read the probe identity files; waiting for valid ones", "dir", i.dir, "err", msg)
	}
}
