package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Auth options. azure_blob: exactly managed_identity and sas_token (SPEC
// §10.3); s3: access_key; nfs: none.
const (
	AuthManagedIdentity = "managed_identity"
	AuthSAS             = "sas_token"
	AuthAccessKey       = "access_key"
	AuthNone            = "none"
)

// ProbeDir is the folder (under the destination prefix) that holds probe
// blobs written by "Test destination". It is the only place where the
// server ever attempts a delete, and only to verify that delete is refused.
const ProbeDir = ".olympos-probe"

// ErrSASExpired is returned when a destination's SAS token is past its
// expiry: runs fail fast instead of producing confusing 403s.
var ErrSASExpired = errors.New("SAS token expired")

// Target is everything needed to open one destination container. SAS is the
// plaintext token (only for AuthSAS); callers drop the Target after Open.
type Target struct {
	Name             string
	Account          string
	Container        string
	Prefix           string
	Auth             string
	EndpointOverride string // e.g. http://127.0.0.1:10000/devstoreaccount1 (Azurite)
	SAS              string
}

// ContainerURL returns the container URL without credentials.
func (t Target) ContainerURL() string {
	if t.EndpointOverride != "" {
		return strings.TrimRight(t.EndpointOverride, "/") + "/" + t.Container
	}
	return "https://" + t.Account + ".blob.core.windows.net/" + t.Container
}

// NormalizeSAS accepts a bare SAS token, a token with a leading '?', or a
// full SAS URL, and returns the query string only.
func NormalizeSAS(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
		if u, err := url.Parse(s); err == nil {
			return u.RawQuery
		}
	}
	return strings.TrimPrefix(s, "?")
}

// ParseSASTime parses the st/se fields of a SAS (ISO 8601 UTC; Azure accepts
// date-only, minute and second precision).
func ParseSASTime(v string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00", "2006-01-02T15:04:05Z", "2006-01-02T15:04Z", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid SAS time %q", v)
}

// SASExpiry returns the se (expiry) of a SAS token.
func SASExpiry(sas string) (time.Time, bool) {
	q, err := url.ParseQuery(NormalizeSAS(sas))
	if err != nil || q.Get("se") == "" {
		return time.Time{}, false
	}
	t, err := ParseSASTime(q.Get("se"))
	return t, err == nil
}

// Azure writes to one Azure Blob container. It implements Writer and the
// probe operations used by the destination test.
type Azure struct {
	cc     *container.Client
	prefix string
}

var _ Writer = (*Azure)(nil)

func clientOptions() *container.ClientOptions {
	return &container.ClientOptions{ClientOptions: azcore.ClientOptions{
		Retry:     policy.RetryOptions{MaxRetries: 4, TryTimeout: 2 * time.Minute},
		Telemetry: policy.TelemetryOptions{ApplicationID: "olympos"},
	}}
}

// Open builds a container client. cred is the server's Managed Identity
// credential (used only for AuthManagedIdentity). It fails fast when a SAS
// has expired.
func Open(t Target, cred azcore.TokenCredential, now time.Time) (*Azure, error) {
	if t.Container == "" || (t.Account == "" && t.EndpointOverride == "") {
		return nil, errors.New("destination needs an account and a container")
	}
	cu := t.ContainerURL()
	if _, err := url.Parse(cu); err != nil {
		return nil, fmt.Errorf("invalid container URL: %w", err)
	}
	var cc *container.Client
	var err error
	switch t.Auth {
	case AuthManagedIdentity:
		if cred == nil {
			return nil, errors.New("managed identity is not available on this server (no Azure credential configured)")
		}
		cc, err = container.NewClient(cu, cred, clientOptions())
	case AuthSAS:
		sas := NormalizeSAS(t.SAS)
		if sas == "" {
			return nil, errors.New("SAS token is empty")
		}
		if exp, ok := SASExpiry(sas); ok && !now.Before(exp) {
			return nil, fmt.Errorf("destination %q: %w at %s; paste a new token in Settings › Destinations",
				t.Name, ErrSASExpired, exp.Format(time.RFC3339))
		}
		cc, err = container.NewClientWithNoCredential(cu+"?"+sas, clientOptions())
	default:
		return nil, fmt.Errorf("unsupported auth %q", t.Auth)
	}
	if err != nil {
		return nil, errors.New("blob client: " + Describe(err))
	}
	return &Azure{cc: cc, prefix: strings.Trim(t.Prefix, "/")}, nil
}

// Prefix implements Writer.
func (a *Azure) Prefix() string { return a.prefix }

// Join builds a blob path below prefix.
func Join(prefix string, parts ...string) string {
	out := []string{}
	if p := strings.Trim(prefix, "/"); p != "" {
		out = append(out, p)
	}
	for _, p := range parts {
		if p = strings.Trim(p, "/"); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "/")
}

func validPath(p string) error {
	if p == "" || len(p) > 1024 || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return fmt.Errorf("invalid blob path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("invalid blob path %q", p)
		}
	}
	return nil
}

type hashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if n > 0 {
		h.h.Write(p[:n])
		h.n += int64(n)
	}
	return n, err
}

// Upload implements Writer. It streams r in blocks (bounded memory:
// BlockSize × Concurrency, no temp file), computes sha256 and the byte count
// on the fly, sets blob index tags and refuses to overwrite an existing blob.
func (a *Azure) Upload(ctx context.Context, path string, r io.Reader, contentType string, tags map[string]string) (UploadResult, error) {
	if err := validPath(path); err != nil {
		return UploadResult{}, err
	}
	hr := &hashingReader{r: r, h: sha256.New()}
	etagAny := azcore.ETagAny
	opts := &blockblob.UploadStreamOptions{
		BlockSize:   8 << 20,
		Concurrency: 3,
		Tags:        tags,
		AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{
			IfNoneMatch: &etagAny,
		}},
	}
	if contentType != "" {
		opts.HTTPHeaders = &blob.HTTPHeaders{BlobContentType: &contentType}
	}
	if _, err := a.cc.NewBlockBlobClient(path).UploadStream(ctx, hr, opts); err != nil {
		return UploadResult{}, fmt.Errorf("upload %s: %s", path, Describe(err))
	}
	return UploadResult{Bytes: hr.n, SHA256: hex.EncodeToString(hr.h.Sum(nil))}, nil
}

// Download reads at most max bytes of a blob (probe/manifest use only).
func (a *Azure) Download(ctx context.Context, path string, max int64) ([]byte, error) {
	if err := validPath(path); err != nil {
		return nil, err
	}
	resp, err := a.cc.NewBlobClient(path).DownloadStream(ctx, nil)
	if err != nil {
		return nil, errors.New(Describe(err))
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// SetTags replaces a blob's index tags.
func (a *Azure) SetTags(ctx context.Context, path string, tags map[string]string) error {
	if err := validPath(path); err != nil {
		return err
	}
	if _, err := a.cc.NewBlobClient(path).SetTags(ctx, tags, nil); err != nil {
		return errors.New(Describe(err))
	}
	return nil
}

// GetTags reads a blob's index tags.
func (a *Azure) GetTags(ctx context.Context, path string) (map[string]string, error) {
	if err := validPath(path); err != nil {
		return nil, err
	}
	resp, err := a.cc.NewBlobClient(path).GetTags(ctx, nil)
	if err != nil {
		return nil, errors.New(Describe(err))
	}
	out := map[string]string{}
	for _, t := range resp.BlobTagSet {
		if t != nil && t.Key != nil && t.Value != nil {
			out[*t.Key] = *t.Value
		}
	}
	return out, nil
}

// ProbeDeleteRefused attempts to delete a probe blob and reports whether the
// storage refused it (the expected, healthy outcome). It only accepts paths
// inside ProbeDir: the server has no other delete code path (SPEC §0.6).
// deleted=true means the credential CAN delete (a warning for the caller).
func (a *Azure) ProbeDeleteRefused(ctx context.Context, path string) (refused bool, err error) {
	if err := validPath(path); err != nil {
		return false, err
	}
	if !IsProbePath(path) {
		return false, fmt.Errorf("refusing to delete %q: only probe blobs under %s/ may be touched", path, ProbeDir)
	}
	_, err = a.cc.NewBlobClient(path).Delete(ctx, nil)
	if err == nil {
		return false, nil
	}
	var re *azcore.ResponseError
	if errors.As(err, &re) && re.StatusCode == http.StatusForbidden {
		return true, nil
	}
	return false, errors.New(Describe(err))
}

// IsProbePath reports whether path is a probe blob path.
func IsProbePath(path string) bool {
	segs := strings.Split(path, "/")
	return len(segs) >= 2 && segs[len(segs)-2] == ProbeDir
}

var urlQueryRe = regexp.MustCompile(`(https?://[^\s"'?]+)\?[^\s"']*`)

// Describe turns an Azure SDK error into a short message without request
// URLs' query strings (which carry SAS signatures).
func Describe(err error) string {
	if err == nil {
		return ""
	}
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		code := re.ErrorCode
		if code == "" {
			code = http.StatusText(re.StatusCode)
		}
		return fmt.Sprintf("%s (HTTP %d)", code, re.StatusCode)
	}
	return secrets.RedactString(urlQueryRe.ReplaceAllString(err.Error(), "$1?"+secrets.Redacted))
}

// LoadSAS returns the plaintext SAS of a credentials row (see LoadSecret).
// The caller should secrets.Zero the result.
func LoadSAS(ctx context.Context, q store.Querier, kv secrets.KeyVault, env *secrets.Envelope, credID uuid.UUID) ([]byte, error) {
	return LoadSecret(ctx, q, kv, env, credID, "SAS")
}

// LoadTarget reads a destinations row and, for SAS auth, its token.
func LoadTarget(ctx context.Context, q store.Querier, kv secrets.KeyVault, env *secrets.Envelope, id uuid.UUID) (Target, error) {
	var t Target
	var credID *uuid.UUID
	var kind string
	err := q.QueryRow(ctx, `SELECT kind, name, account, container, prefix, auth, endpoint_override, sas_credential_id FROM destinations WHERE id = $1`, id).
		Scan(&kind, &t.Name, &t.Account, &t.Container, &t.Prefix, &t.Auth, &t.EndpointOverride, &credID)
	if err != nil {
		return Target{}, fmt.Errorf("load destination: %w", store.NotFound(err))
	}
	if kind != KindAzureBlob {
		return Target{}, fmt.Errorf("destination %q is of kind %s, not %s", t.Name, kind, KindAzureBlob)
	}
	if t.Auth == AuthSAS {
		if credID == nil {
			return Target{}, errors.New("destination has no SAS credential")
		}
		b, err := LoadSAS(ctx, q, kv, env, *credID)
		if err != nil {
			return Target{}, err
		}
		t.SAS = strings.TrimSpace(string(b))
		secrets.Zero(b)
	}
	return t, nil
}
