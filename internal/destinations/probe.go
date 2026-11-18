package destinations

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/blob"
)

// Step names (openapi DestinationTest.steps[].name).
const (
	StepSASExpiry      = "sas_expiry"
	StepSASPermissions = "sas_permissions"
	StepWrite          = "write"
	StepRead           = "read"
	StepTag            = "tag"
	StepDeleteRefused  = "delete_refused"
	StepEndpoint       = "endpoint" // s3: reachable, TLS, bucket exists
	StepPath           = "path"     // nfs: inside a mount, exists or creatable, writable
)

// Step is one check of the destination test.
type Step struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Report is the result of "Test destination".
type Report struct {
	// OK: SAS usable (when SAS) and write, read and tag succeeded.
	OK bool `json:"ok"`
	// CanDelete is a WARNING: the credential can delete blobs.
	CanDelete bool     `json:"can_delete"`
	Steps     []Step   `json:"steps"`
	SAS       *SASInfo `json:"sas"`
	Error     string   `json:"error,omitempty"`
	ProbePath string   `json:"probe_path,omitempty"`
}

func (r *Report) add(name string, ok bool, format string, args ...any) {
	r.Steps = append(r.Steps, Step{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)})
}

func (r *Report) step(name string) *Step {
	for i := range r.Steps {
		if r.Steps[i].Name == name {
			return &r.Steps[i]
		}
	}
	return nil
}

// Prober runs destination tests.
type Prober struct {
	Cred    azcore.TokenCredential
	Now     func() time.Time
	Timeout time.Duration // per storage operation, default 30s
	Storage blob.StorageOptions
}

// probeStore is what the probe needs from a writer of any kind.
type probeStore interface {
	blob.Writer
	Download(ctx context.Context, path string, max int64) ([]byte, error)
	SetTags(ctx context.Context, path string, tags map[string]string) error
	GetTags(ctx context.Context, path string) (map[string]string, error)
	ProbeDeleteRefused(ctx context.Context, path string) (bool, error)
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout == 0 {
		return 30 * time.Second
	}
	return p.Timeout
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Test writes a probe blob under {prefix}/.olympos-probe/<uuid>, reads it
// back, sets and reads a tag, then attempts to delete it and expects the
// storage to refuse (SPEC §10.3). A successful delete sets CanDelete (a
// warning) and removes the probe; a refused delete leaves the small probe
// blob in place (lifecycle rules may expire .olympos-probe/).
func (p *Prober) Test(ctx context.Context, t blob.Target) Report {
	rep := Report{Steps: []Step{}}
	now := p.now()
	sasOK := true
	if t.Auth == blob.AuthSAS {
		info, err := ParseSAS(t.SAS)
		if err != nil {
			rep.add(StepSASPermissions, false, "%s", err.Error())
			rep.Error = "SAS token: " + err.Error()
			return rep
		}
		rep.SAS = &info
		switch {
		case info.Expired(now):
			rep.add(StepSASExpiry, false, "expired at %s", info.ExpiresAt.Format(time.RFC3339))
			rep.Error = "SAS token expired at " + info.ExpiresAt.Format(time.RFC3339)
			return rep
		case info.ExpiresAt != nil:
			days := int(info.ExpiresAt.Sub(now).Hours() / 24)
			rep.add(StepSASExpiry, true, "expires %s (in %d days)", info.ExpiresAt.Format(time.RFC3339), days)
		default:
			rep.add(StepSASExpiry, true, "expiry not visible (stored access policy)")
		}
		var parts []string
		ok := len(info.Missing) == 0 && info.Scope != ScopeService
		if len(info.Missing) > 0 {
			parts = append(parts, "missing required: "+names(info.Missing))
		}
		if len(info.Extra) > 0 {
			parts = append(parts, "not needed: "+names(info.Extra))
		}
		if info.CanDelete() {
			parts = append(parts, "WARNING: grants delete; Olympos never deletes backups, remove d/x/y from the SAS")
		}
		parts = append(parts, "scope: "+info.Scope)
		parts = append(parts, info.Notes...)
		rep.add(StepSASPermissions, ok, "permissions %q; %s", info.Permissions, strings.Join(parts, "; "))
		sasOK = ok
		if !ok {
			rep.Error = "SAS token does not grant what the server needs (r, c, w, t on the container)"
		}
	}

	az, err := blob.Open(t, p.Cred, now)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	p.probe(ctx, &rep, az, t.Prefix, kindTexts[blob.KindAzureBlob])
	if !sasOK {
		rep.OK = false
	}
	if !rep.OK && rep.Error == "" {
		rep.Error = "destination test failed"
	}
	return rep
}

// kindText holds the per-kind wording of the probe steps.
type kindText struct {
	noun, container, tag, canDelete string
}

var kindTexts = map[string]kindText{
	blob.KindAzureBlob: {noun: "blob", container: "container", tag: "blob index tag",
		canDelete: "WARNING: the credential can delete blobs (probe deleted). Remove the delete permission"},
	blob.KindS3: {noun: "object", container: "bucket", tag: "object tag",
		canDelete: "WARNING: the credential can delete objects (probe deleted). Remove s3:DeleteObject / s3:DeleteObjectVersion from its policy"},
	blob.KindNFS: {noun: "file", container: "directory", tag: "tags sidecar file",
		canDelete: "WARNING: Olympos can delete files on this export (probe deleted). Filesystems cannot refuse deletes per operation; protect backups with storage snapshots / WORM"},
}

// TestS3 checks the endpoint (reachable, TLS, bucket exists), then runs the
// probe (write, read, tag, delete refused).
func (p *Prober) TestS3(ctx context.Context, t blob.S3Target) Report {
	rep := Report{Steps: []Step{}}
	s3, err := blob.OpenS3(t, p.Storage)
	if err != nil {
		rep.add(StepEndpoint, false, "%s", err.Error())
		rep.Error = err.Error()
		return rep
	}
	c, cancel := context.WithTimeout(ctx, p.timeout())
	err = s3.CheckBucket(c)
	cancel()
	if err != nil {
		rep.add(StepEndpoint, false, "%s: %s", s3.Endpoint(), err.Error())
		rep.Error = "S3 endpoint check failed: " + err.Error()
		return rep
	}
	tlsText := "TLS verified"
	if strings.HasPrefix(s3.Endpoint(), "http://") {
		tlsText = "plain HTTP (no TLS)"
	}
	style := "virtual-hosted-style"
	if t.PathStyle {
		style = "path-style"
	}
	rep.add(StepEndpoint, true, "%s reachable (%s, %s); bucket %s exists", s3.Endpoint(), tlsText, style, t.Bucket)
	p.probe(ctx, &rep, s3, t.Prefix, kindTexts[blob.KindS3])
	if !rep.OK && rep.Error == "" {
		rep.Error = "destination test failed"
	}
	return rep
}

// TestFS checks the path (inside a mount, exists or creatable, writable),
// then runs the probe. Deleting the probe normally succeeds on a
// filesystem: the report then has CanDelete (a warning), never silently.
func (p *Prober) TestFS(ctx context.Context, t blob.FSTarget) Report {
	rep := Report{Steps: []Step{}}
	f, err := blob.OpenFS(t, p.Storage)
	if err != nil {
		rep.add(StepPath, false, "%s", err.Error())
		rep.Error = err.Error()
		return rep
	}
	created, err := f.EnsureDir()
	if err != nil {
		rep.add(StepPath, false, "%s", err.Error())
		rep.Error = "destination path: " + err.Error()
		return rep
	}
	state := "exists"
	if created {
		state = "created"
	}
	m := f.Mount()
	rep.add(StepPath, true, "%s inside mount %s (%s); directory %s and writable", f.Dir(), m.Name, m.Path, state)
	p.probe(ctx, &rep, f, t.Prefix, kindTexts[blob.KindNFS])
	if !rep.OK && rep.Error == "" {
		rep.Error = "destination test failed"
	}
	return rep
}

// probe writes {prefix}/.olympos-probe/<uuid>, reads it back, sets and reads
// a tag, then attempts to delete it and expects a refusal. It sets rep.OK
// from write, read, tag and any earlier step.
func (p *Prober) probe(ctx context.Context, rep *Report, st probeStore, prefix string, kt kindText) {
	now := p.now()
	op := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, p.timeout()) }
	path := blob.Join(prefix, blob.ProbeDir, uuid.NewString())
	rep.ProbePath = path
	body := []byte("olympos destination probe " + now.UTC().Format(time.RFC3339) + "\n")

	c, cancel := op()
	_, err := st.Upload(c, path, bytes.NewReader(body), "text/plain", nil)
	cancel()
	if err != nil {
		rep.add(StepWrite, false, "%s", err.Error())
		rep.add(StepRead, false, "skipped")
		rep.add(StepTag, false, "skipped")
		rep.add(StepDeleteRefused, false, "skipped")
		rep.Error = "cannot write to the " + kt.container
		return
	}
	rep.add(StepWrite, true, "wrote %s (%d bytes)", path, len(body))

	c, cancel = op()
	got, err := st.Download(c, path, 4096)
	cancel()
	switch {
	case err != nil:
		rep.add(StepRead, false, "%s", err.Error())
	case !bytes.Equal(got, body):
		rep.add(StepRead, false, "read back %d bytes that differ from what was written", len(got))
	default:
		rep.add(StepRead, true, "read back and verified")
	}

	tagVal := now.UTC().Format("20060102T150405Z")
	c, cancel = op()
	err = st.SetTags(c, path, map[string]string{"olympos-probe": tagVal})
	cancel()
	if err != nil {
		rep.add(StepTag, false, "set tag: %s", err.Error())
	} else {
		c, cancel = op()
		tags, err := st.GetTags(c, path)
		cancel()
		switch {
		case err != nil:
			rep.add(StepTag, false, "read tags: %s", err.Error())
		case tags["olympos-probe"] != tagVal:
			rep.add(StepTag, false, "tag olympos-probe not read back")
		default:
			rep.add(StepTag, true, "set and read %s olympos-probe", kt.tag)
		}
	}

	c, cancel = op()
	refused, err := st.ProbeDeleteRefused(c, path)
	cancel()
	switch {
	case err != nil:
		rep.add(StepDeleteRefused, false, "could not verify that delete is refused: %s", err.Error())
	case refused:
		rep.add(StepDeleteRefused, true, "delete refused, as expected")
	default:
		rep.CanDelete = true
		rep.add(StepDeleteRefused, false, "%s", kt.canDelete)
	}

	rep.OK = true
	for _, s := range []string{StepWrite, StepRead, StepTag} {
		if st := rep.step(s); st == nil || !st.OK {
			rep.OK = false
		}
	}
	for _, s := range rep.Steps {
		if (s.Name == StepEndpoint || s.Name == StepPath) && !s.OK {
			rep.OK = false
		}
	}
}

func names(ps []string) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p + " (" + PermissionName(p) + ")"
	}
	return strings.Join(out, ", ")
}
