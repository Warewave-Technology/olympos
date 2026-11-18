package blob

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Destination kinds (destinations.kind).
const (
	KindAzureBlob = "azure_blob"
	KindS3        = "s3"
	KindNFS       = "nfs"
)

// DefaultNFSRoot is where the server expects NFS volumes: every first-level
// subdirectory is one mount (config backup.nfsRoot).
const DefaultNFSRoot = "/var/lib/olympos/nfs"

// DefaultS3PartSize is the multipart part size for uploads of unknown
// length: memory per running upload, and ×10000 the largest object.
const DefaultS3PartSize = 32 << 20

// StorageOptions is the server-wide storage configuration that is not part
// of a destination row (config backup.*).
type StorageOptions struct {
	// NFSRoot: first-level subdirectories are the mounts NFS destinations
	// may use. Default DefaultNFSRoot.
	NFSRoot string
	// CABundleFile adds PEM CAs to the system roots for S3 endpoints.
	CABundleFile string
	// S3PartSize in bytes (default DefaultS3PartSize, min 5 MiB).
	S3PartSize uint64
	// Transport overrides the S3 HTTP transport (tests only).
	Transport http.RoundTripper
}

func (o StorageOptions) nfsRoot() string {
	if o.NFSRoot == "" {
		return DefaultNFSRoot
	}
	return o.NFSRoot
}

func (o StorageOptions) partSize() uint64 {
	switch {
	case o.S3PartSize == 0:
		return DefaultS3PartSize
	case o.S3PartSize < 5<<20:
		return 5 << 20
	}
	return o.S3PartSize
}

// S3Transport returns the HTTP transport for S3 endpoints: system roots plus
// CABundleFile, TLS ≥ 1.2. It fails when the bundle cannot be read.
func (o StorageOptions) S3Transport() (http.RoundTripper, error) {
	if o.Transport != nil {
		return o.Transport, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if o.CABundleFile != "" {
		pem, err := os.ReadFile(o.CABundleFile)
		if err != nil {
			return nil, fmt.Errorf("backup.storageCABundleFile: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("backup.storageCABundleFile %s: no PEM certificates found", o.CABundleFile)
		}
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ExpectContinueTimeout: time.Second,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}, nil
}

// ResolverOption configures NewResolver.
type ResolverOption func(*DestResolver)

// WithStorage sets the S3/NFS storage options.
func WithStorage(o StorageOptions) ResolverOption {
	return func(r *DestResolver) { r.Storage = o }
}

// DestResolver opens Writers for destinations rows of every kind.
type DestResolver struct {
	DB      *store.DB
	KV      secrets.KeyVault
	Env     *secrets.Envelope
	Cred    azcore.TokenCredential
	Now     func() time.Time
	Storage StorageOptions
}

// NewResolver returns the resolver for destinations rows. It dispatches by
// destinations.kind (azure_blob, s3, nfs).
func NewResolver(db *store.DB, kv secrets.KeyVault, env *secrets.Envelope, cred azcore.TokenCredential, opts ...ResolverOption) Resolver {
	r := &DestResolver{DB: db, KV: kv, Env: env, Cred: cred}
	for _, o := range opts {
		o(r)
	}
	return r
}

// ForDestination implements Resolver. Credentials (SAS, S3 secret key) are
// loaded at use time and live only inside the returned client.
func (r *DestResolver) ForDestination(ctx context.Context, destinationID uuid.UUID) (Writer, error) {
	var kind string
	if err := r.DB.QueryRow(ctx, `SELECT kind FROM destinations WHERE id = $1`, destinationID).Scan(&kind); err != nil {
		return nil, fmt.Errorf("load destination: %w", store.NotFound(err))
	}
	switch kind {
	case KindAzureBlob:
		t, err := LoadTarget(ctx, r.DB, r.KV, r.Env, destinationID)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		if r.Now != nil {
			now = r.Now()
		}
		return Open(t, r.Cred, now)
	case KindS3:
		t, err := LoadS3Target(ctx, r.DB, r.KV, r.Env, destinationID)
		if err != nil {
			return nil, err
		}
		return OpenS3(t, r.Storage)
	case KindNFS:
		t, err := LoadFSTarget(ctx, r.DB, destinationID)
		if err != nil {
			return nil, err
		}
		return OpenFS(t, r.Storage)
	}
	return nil, fmt.Errorf("unsupported destination kind %q", kind)
}

// LoadSecret returns the plaintext of a credentials row: envelope-opened
// (AAD "credentials:<id>") or resolved from Key Vault at use time. what
// names the secret in errors ("SAS", "S3 secret key"). The caller should
// secrets.Zero the result.
func LoadSecret(ctx context.Context, q store.Querier, kv secrets.KeyVault, env *secrets.Envelope, credID uuid.UUID, what string) ([]byte, error) {
	var kind, vault, name, kekVersion string
	var ct, dek []byte
	err := q.QueryRow(ctx, `SELECT kind, keyvault_name, secret_name, ciphertext, wrapped_dek, kek_version FROM credentials WHERE id = $1`, credID).
		Scan(&kind, &vault, &name, &ct, &dek, &kekVersion)
	if err != nil {
		return nil, fmt.Errorf("load %s credential: %w", what, store.NotFound(err))
	}
	switch kind {
	case "stored":
		if env == nil {
			return nil, errors.New("no envelope configured")
		}
		b, err := env.Open(ctx, secrets.Sealed{Ciphertext: ct, WrappedDEK: dek, KEKVersion: kekVersion}, []byte("credentials:"+credID.String()))
		if err != nil {
			return nil, fmt.Errorf("open stored %s: %w", what, err)
		}
		return b, nil
	case "keyvault_ref":
		b, err := kv.GetSecret(ctx, vault, name)
		if err != nil {
			return nil, fmt.Errorf("resolve %s from kv://%s/%s: %w", what, vault, name, err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("unknown credential kind %q", kind)
}
