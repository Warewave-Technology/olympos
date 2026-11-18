package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/tags"

	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// DefaultS3Region is used when a destination has no region.
const DefaultS3Region = "us-east-1"

// s3SinglePutMax: uploads that end within this many bytes go as a single
// PutObject with If-None-Match: * (atomic no-overwrite); longer streams go
// multipart with the configured part size.
const s3SinglePutMax = 8 << 20

// S3Target is everything needed to open one S3 bucket. SecretKey is the
// plaintext secret access key; callers drop the target after OpenS3.
type S3Target struct {
	Name             string
	Bucket           string
	Region           string
	Prefix           string
	EndpointOverride string // http(s)://host[:port] of an S3-compatible service; "" = AWS
	PathStyle        bool
	AccessKeyID      string
	SecretKey        string
}

// S3Endpoint returns the endpoint URL (scheme://host[:port]) of t.
func (t S3Target) S3Endpoint() string {
	if t.EndpointOverride != "" {
		return strings.TrimRight(t.EndpointOverride, "/")
	}
	return "https://s3." + t.region() + ".amazonaws.com"
}

func (t S3Target) region() string {
	if t.Region == "" {
		return DefaultS3Region
	}
	return t.Region
}

// S3 writes to one S3 bucket. It implements Writer and the probe
// operations used by the destination test.
type S3 struct {
	c        *minio.Client
	bucket   string
	prefix   string
	partSize uint64
	endpoint string
}

var _ Writer = (*S3)(nil)

// OpenS3 builds an S3 client with static credentials. TLS is decided by the
// endpoint scheme; certificates are verified against the system roots plus
// opts.CABundleFile.
func OpenS3(t S3Target, opts StorageOptions) (*S3, error) {
	if t.Bucket == "" {
		return nil, errors.New("destination needs a bucket")
	}
	if t.AccessKeyID == "" || t.SecretKey == "" {
		return nil, errors.New("destination needs an access key id and a secret key")
	}
	ep := t.S3Endpoint()
	u, err := url.Parse(ep)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("invalid S3 endpoint %q: use scheme://host[:port]", ep)
	}
	tr, err := opts.S3Transport()
	if err != nil {
		return nil, err
	}
	lookup := minio.BucketLookupDNS
	if t.PathStyle {
		lookup = minio.BucketLookupPath
	}
	c, err := minio.New(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(t.AccessKeyID, t.SecretKey, ""),
		Secure:       u.Scheme == "https",
		Region:       t.region(),
		BucketLookup: lookup,
		Transport:    tr,
		MaxRetries:   4,
	})
	if err != nil {
		return nil, errors.New("s3 client: " + DescribeS3(err))
	}
	c.SetAppInfo("olympos", "1")
	return &S3{c: c, bucket: t.Bucket, prefix: strings.Trim(t.Prefix, "/"), partSize: opts.partSize(), endpoint: u.Scheme + "://" + u.Host}, nil
}

// Prefix implements Writer.
func (s *S3) Prefix() string { return s.prefix }

// Endpoint is scheme://host of the S3 service (for reports).
func (s *S3) Endpoint() string { return s.endpoint }

// CheckBucket verifies the endpoint is reachable (TLS verified) and the
// bucket exists. It needs s3:ListBucket on the bucket.
func (s *S3) CheckBucket(ctx context.Context) error {
	ok, err := s.c.BucketExists(ctx, s.bucket)
	if err != nil {
		if r := minio.ToErrorResponse(err); r.StatusCode == http.StatusForbidden {
			return fmt.Errorf("%s: grant s3:ListBucket on the bucket (needed to check that it exists and that backups are never overwritten)", DescribeS3(err))
		}
		return errors.New(DescribeS3(err))
	}
	if !ok {
		return fmt.Errorf("bucket %q does not exist", s.bucket)
	}
	return nil
}

// exists reports whether an object exists (needs s3:ListBucket so a
// missing key is 404, not 403).
func (s *S3) exists(ctx context.Context, path string) (bool, error) {
	_, err := s.c.StatObject(ctx, s.bucket, path, minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	r := minio.ToErrorResponse(err)
	if r.StatusCode == http.StatusNotFound || r.Code == "NoSuchKey" || r.Code == "NotFound" {
		return false, nil
	}
	return false, errors.New(DescribeS3(err))
}

// Upload implements Writer. It streams r with unknown length: the first
// s3SinglePutMax bytes are buffered; a stream that ends there is one
// PutObject with If-None-Match: * (the service refuses an overwrite
// atomically where supported), a longer one is a multipart upload with the
// configured part size (memory: one part). Before writing, a HEAD refuses
// an existing key (multipart completion carries no condition in the client
// library, so for large objects this check is the overwrite guard; keys
// contain the run ID, so a collision would be a bug, and Object Lock /
// versioning protect the bucket anyway). sha256 and the byte count are
// computed while streaming; tags are set with the upload (x-amz-tagging).
func (s *S3) Upload(ctx context.Context, path string, r io.Reader, contentType string, tags map[string]string) (UploadResult, error) {
	if err := validPath(path); err != nil {
		return UploadResult{}, err
	}
	exists, err := s.exists(ctx, path)
	if err != nil {
		return UploadResult{}, fmt.Errorf("upload %s: check existing object: %s", path, err)
	}
	if exists {
		return UploadResult{}, fmt.Errorf("upload %s: object already exists; refusing to overwrite", path)
	}
	hr := &hashingReader{r: r, h: sha256.New()}
	var head bytes.Buffer
	n, err := io.CopyN(&head, hr, s3SinglePutMax+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return UploadResult{}, fmt.Errorf("upload %s: %w", path, err)
	}
	opts := minio.PutObjectOptions{ContentType: contentType, UserTags: tags, PartSize: s.partSize}
	if contentType == "" {
		opts.ContentType = "application/octet-stream"
	}
	if n <= s3SinglePutMax {
		opts.SetMatchETagExcept("*")
		_, err = s.c.PutObject(ctx, s.bucket, path, bytes.NewReader(head.Bytes()), n, opts)
	} else {
		_, err = s.c.PutObject(ctx, s.bucket, path, io.MultiReader(&head, hr), -1, opts)
	}
	if err != nil {
		if r := minio.ToErrorResponse(err); r.StatusCode == http.StatusPreconditionFailed {
			return UploadResult{}, fmt.Errorf("upload %s: object already exists; refusing to overwrite", path)
		}
		return UploadResult{}, fmt.Errorf("upload %s: %s", path, DescribeS3(err))
	}
	return UploadResult{Bytes: hr.n, SHA256: hex.EncodeToString(hr.h.Sum(nil))}, nil
}

// Download reads at most max bytes of an object (probe/manifest use only).
func (s *S3) Download(ctx context.Context, path string, max int64) ([]byte, error) {
	if err := validPath(path); err != nil {
		return nil, err
	}
	o, err := s.c.GetObject(ctx, s.bucket, path, minio.GetObjectOptions{})
	if err != nil {
		return nil, errors.New(DescribeS3(err))
	}
	defer o.Close()
	b, err := io.ReadAll(io.LimitReader(o, max))
	if err != nil {
		return nil, errors.New(DescribeS3(err))
	}
	return b, nil
}

// SetTags replaces an object's tags.
func (s *S3) SetTags(ctx context.Context, path string, m map[string]string) error {
	if err := validPath(path); err != nil {
		return err
	}
	t, err := tags.NewTags(m, true)
	if err != nil {
		return err
	}
	if err := s.c.PutObjectTagging(ctx, s.bucket, path, t, minio.PutObjectTaggingOptions{}); err != nil {
		return errors.New(DescribeS3(err))
	}
	return nil
}

// GetTags reads an object's tags.
func (s *S3) GetTags(ctx context.Context, path string) (map[string]string, error) {
	if err := validPath(path); err != nil {
		return nil, err
	}
	t, err := s.c.GetObjectTagging(ctx, s.bucket, path, minio.GetObjectTaggingOptions{})
	if err != nil {
		return nil, errors.New(DescribeS3(err))
	}
	return t.ToMap(), nil
}

// ProbeDeleteRefused attempts to delete a probe object and reports whether
// the service refused it (AccessDenied, the healthy outcome). Only paths in
// ProbeDir are accepted: the server has no other delete code path.
func (s *S3) ProbeDeleteRefused(ctx context.Context, path string) (refused bool, err error) {
	if err := validPath(path); err != nil {
		return false, err
	}
	if !IsProbePath(path) {
		return false, fmt.Errorf("refusing to delete %q: only probe objects under %s/ may be touched", path, ProbeDir)
	}
	err = s.c.RemoveObject(ctx, s.bucket, path, minio.RemoveObjectOptions{})
	if err == nil {
		return false, nil
	}
	if r := minio.ToErrorResponse(err); r.StatusCode == http.StatusForbidden || r.Code == "AccessDenied" {
		return true, nil
	}
	return false, errors.New(DescribeS3(err))
}

var s3SigRe = regexp.MustCompile(`(?i)(X-Amz-(Signature|Credential|Security-Token)=)[^&\s"']+`)

// DescribeS3 turns an S3 client error into a short message (error code,
// HTTP status, message) without signatures or credentials.
func DescribeS3(err error) string {
	if err == nil {
		return ""
	}
	r := minio.ToErrorResponse(err)
	if r.StatusCode != 0 || r.Code != "" {
		code := r.Code
		if code == "" {
			code = http.StatusText(r.StatusCode)
		}
		msg := fmt.Sprintf("%s (HTTP %d)", code, r.StatusCode)
		if r.Message != "" && len(r.Message) < 300 {
			msg += ": " + r.Message
		}
		return secrets.RedactString(msg)
	}
	s := s3SigRe.ReplaceAllString(err.Error(), "$1"+secrets.Redacted)
	return secrets.RedactString(urlQueryRe.ReplaceAllString(s, "$1?"+secrets.Redacted))
}

// LoadS3Target reads an s3 destinations row and its secret key.
func LoadS3Target(ctx context.Context, q store.Querier, kv secrets.KeyVault, env *secrets.Envelope, id uuid.UUID) (S3Target, error) {
	var t S3Target
	var kind string
	var credID *uuid.UUID
	err := q.QueryRow(ctx, `SELECT kind, name, bucket, region, prefix, endpoint_override, path_style, access_key_id, secret_credential_id
		FROM destinations WHERE id = $1`, id).
		Scan(&kind, &t.Name, &t.Bucket, &t.Region, &t.Prefix, &t.EndpointOverride, &t.PathStyle, &t.AccessKeyID, &credID)
	if err != nil {
		return S3Target{}, fmt.Errorf("load destination: %w", store.NotFound(err))
	}
	if kind != KindS3 {
		return S3Target{}, fmt.Errorf("destination %q is of kind %s, not %s", t.Name, kind, KindS3)
	}
	if credID == nil {
		return S3Target{}, errors.New("destination has no secret key credential")
	}
	b, err := LoadSecret(ctx, q, kv, env, *credID, "S3 secret key")
	if err != nil {
		return S3Target{}, err
	}
	t.SecretKey = strings.TrimSpace(string(b))
	secrets.Zero(b)
	return t, nil
}
