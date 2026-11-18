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
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	op := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, timeout) }
	path := blob.Join(t.Prefix, blob.ProbeDir, uuid.NewString())
	rep.ProbePath = path
	body := []byte("olympos destination probe " + now.UTC().Format(time.RFC3339) + "\n")

	c, cancel := op()
	_, err = az.Upload(c, path, bytes.NewReader(body), "text/plain", nil)
	cancel()
	if err != nil {
		rep.add(StepWrite, false, "%s", err.Error())
		rep.add(StepRead, false, "skipped")
		rep.add(StepTag, false, "skipped")
		rep.add(StepDeleteRefused, false, "skipped")
		rep.Error = "cannot write to the container"
		return rep
	}
	rep.add(StepWrite, true, "wrote %s (%d bytes)", path, len(body))

	c, cancel = op()
	got, err := az.Download(c, path, 4096)
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
	err = az.SetTags(c, path, map[string]string{"olympos-probe": tagVal})
	cancel()
	if err != nil {
		rep.add(StepTag, false, "set tag: %s", err.Error())
	} else {
		c, cancel = op()
		tags, err := az.GetTags(c, path)
		cancel()
		switch {
		case err != nil:
			rep.add(StepTag, false, "read tags: %s", err.Error())
		case tags["olympos-probe"] != tagVal:
			rep.add(StepTag, false, "tag olympos-probe not read back")
		default:
			rep.add(StepTag, true, "set and read blob index tag olympos-probe")
		}
	}

	c, cancel = op()
	refused, err := az.ProbeDeleteRefused(c, path)
	cancel()
	switch {
	case err != nil:
		rep.add(StepDeleteRefused, false, "could not verify that delete is refused: %s", err.Error())
	case refused:
		rep.add(StepDeleteRefused, true, "delete refused, as expected")
	default:
		rep.CanDelete = true
		rep.add(StepDeleteRefused, false, "WARNING: the credential can delete blobs (probe deleted). Remove the delete permission")
	}

	rep.OK = sasOK
	for _, s := range []string{StepWrite, StepRead, StepTag} {
		if st := rep.step(s); st == nil || !st.OK {
			rep.OK = false
		}
	}
	if !rep.OK && rep.Error == "" {
		rep.Error = "destination test failed"
	}
	return rep
}

func names(ps []string) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p + " (" + PermissionName(p) + ")"
	}
	return strings.Join(out, ", ")
}
