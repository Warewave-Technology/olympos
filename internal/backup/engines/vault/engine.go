// Package vault is the HashiCorp Vault / OpenBao raft snapshot backup engine
// (SPEC §10.2): GET /v1/sys/storage/raft/snapshot through the tunnel with
// the Olympos AppRole token, streamed into the blob without buffering. The
// snapshot is encrypted by the vault's barrier.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/vaults/vclient"
)

func init() { backup.RegisterEngine(Engine{}) }

// SnapshotPath is the only path the engine reads.
const SnapshotPath = "sys/storage/raft/snapshot"

// Options are the engine_options of a vault backup job.
type Options struct {
	// CABundle (PEM) overrides the bundle configured on the Vaults page.
	CABundle string `json:"ca_bundle,omitempty"`
}

// Engine implements backup.Engine.
type Engine struct{}

func (Engine) Name() string        { return "vault" }
func (Engine) Ext() string         { return "snap" }
func (Engine) ContentType() string { return "application/gzip" }

func (Engine) client(ctx context.Context, ec backup.EngineContext) (*vclient.Client, error) {
	var opt Options
	if len(ec.Options) > 0 && string(ec.Options) != "null" {
		if err := json.Unmarshal(ec.Options, &opt); err != nil {
			return nil, fmt.Errorf("invalid engine options: %w", err)
		}
	}
	bundle := []byte(opt.CABundle)
	if len(bundle) == 0 && ec.UseTLS && vclient.CABundleFor != nil {
		if b, err := vclient.CABundleFor(ctx, ec.Target.ID); err == nil {
			bundle = b
		}
	}
	sn := ec.TLSServerName
	if sn == "" {
		sn = ec.Target.TLSServerName
	}
	if sn == "" {
		sn = vclient.DefaultServerName(ec.Target.Service, ec.Target.Namespace)
	}
	return vclient.New(vclient.Options{Dial: ec.Dial, TLS: ec.UseTLS, ServerName: sn, CABundle: bundle})
}

// login resolves the AppRole credential, logs in and zeroes the secret_id.
func login(ctx context.Context, c *vclient.Client, ec backup.EngineContext) error {
	if ec.Credential == nil {
		return errors.New("no AppRole credential provider for this vault")
	}
	cred, err := ec.Credential(ctx)
	if err != nil {
		return err
	}
	defer secrets.Zero(cred.Secret)
	return vclient.AppRoleLogin(ctx, c, cred.Username, cred.Secret)
}

// TestConnection reports version, seal state, raft storage and whether the
// Olympos token may read the snapshot endpoint.
func (e Engine) TestConnection(ctx context.Context, ec backup.EngineContext) (*backup.ConnectionTest, error) {
	res := &backup.ConnectionTest{TLS: ec.UseTLS, Privileges: []backup.Privilege{}, Databases: []string{}}
	c, err := e.client(ctx, ec)
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	defer c.Close()
	h, err := vclient.SealStatus(ctx, c)
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	res.ServerVersion = h.Version
	res.Privileges = append(res.Privileges, backup.Privilege{Name: "unsealed", OK: !h.Sealed && h.Initialized,
		Detail: sealDetail(h)})
	raft := h.StorageType == "raft"
	res.Privileges = append(res.Privileges, backup.Privilege{Name: "raft storage", OK: raft, Detail: "storage: " + orUnknown(h.StorageType)})
	if err := login(ctx, c, ec); err != nil {
		res.Privileges = append(res.Privileges, backup.Privilege{Name: "approle login", OK: false, Detail: err.Error()})
		res.Error = "AppRole login failed"
		return res, nil
	}
	defer vclient.RevokeSelf(c)
	res.Privileges = append(res.Privileges, backup.Privilege{Name: "approle login", OK: true})
	caps, err := c.Sys().CapabilitiesSelfWithContext(ctx, SnapshotPath)
	canRead := err == nil && (slices.Contains(caps, "read") || slices.Contains(caps, "root"))
	detail := strings.Join(caps, ", ")
	if err != nil {
		detail = vclient.Sanitize(err).Error()
	}
	res.Privileges = append(res.Privileges, backup.Privilege{Name: "read " + SnapshotPath, OK: canRead, Detail: detail})
	res.OK = !h.Sealed && raft && canRead
	if !res.OK && res.Error == "" {
		switch {
		case h.Sealed:
			res.Error = "the vault is sealed"
		case !raft:
			res.Error = "snapshots require integrated (raft) storage"
		default:
			res.Error = "the Olympos policy does not allow reading " + SnapshotPath
		}
	}
	return res, nil
}

func sealDetail(h vclient.Health) string {
	switch {
	case !h.Initialized:
		return "not initialized"
	case h.Sealed:
		return "sealed"
	}
	return "unsealed"
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Run streams the raft snapshot into w. Test runs take a full snapshot too:
// there is no partial raft snapshot.
func (e Engine) Run(ctx context.Context, ec backup.EngineContext, w io.Writer) (*backup.RunResult, error) {
	c, err := e.client(ctx, ec)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	h, err := vclient.SealStatus(ctx, c)
	if err != nil {
		return nil, err
	}
	if h.Sealed {
		return nil, errors.New("the vault is sealed")
	}
	if err := login(ctx, c, ec); err != nil {
		return nil, err
	}
	defer vclient.RevokeSelf(c)
	if err := c.Sys().RaftSnapshotWithContext(ctx, w); err != nil {
		if errors.Is(err, vaultapi.ErrIncompleteSnapshot) {
			return nil, errors.New("raft snapshot is incomplete (SHA256SUMS.sealed missing); the vault may have failed mid-stream")
		}
		if vclient.StatusCode(err) == 0 && ctx.Err() == nil {
			// Writer (blob) or stream error: keep it, it carries no request data.
			return nil, fmt.Errorf("raft snapshot stream: %w", err)
		}
		return nil, fmt.Errorf("raft snapshot: %w", vclient.Sanitize(err))
	}
	return &backup.RunResult{ServerVersion: h.Version, Details: map[string]any{
		"provider": ec.Target.VaultProvider, "storage_type": h.StorageType, "format": "raft-snapshot (tar.gz, barrier-encrypted)"}}, nil
}
