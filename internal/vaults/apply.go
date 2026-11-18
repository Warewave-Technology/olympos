package vaults

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/vaults/vclient"
)

var (
	_ approvals.Applier   = (*Service)(nil)
	_ approvals.Inspector = (*Service)(nil)
)

// KVMetadata reads <mount>metadata/<path> with the Olympos AppRole (for
// approvals.ReconcileApplying). nil, nil when the path does not exist.
func (s *Service) KVMetadata(ctx context.Context, vaultID uuid.UUID, mount, path string) (*approvals.KVMeta, error) {
	r, err := loadRow(ctx, s.DB, vaultID)
	if err != nil {
		return nil, err
	}
	c, done, err := s.approle(ctx, r, requestTimout)
	if err != nil {
		return nil, err
	}
	defer done()
	md, err := c.Logical().ReadWithContext(ctx, mount+"metadata/"+path)
	if err != nil {
		if vclient.StatusCode(err) == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("read metadata of %s%s: %w", mount, path, vclient.Sanitize(err))
	}
	if md == nil || md.Data == nil {
		return nil, nil
	}
	m := &approvals.KVMeta{Current: intOf(md.Data["current_version"]), Versions: map[int]approvals.KVVersion{}}
	if vs, ok := md.Data["versions"].(map[string]any); ok {
		for k, v := range vs {
			n, err := strconv.Atoi(k)
			if err != nil {
				continue
			}
			x, _ := v.(map[string]any)
			var kv approvals.KVVersion
			if ts, ok := x["created_time"].(string); ok {
				kv.Created, _ = time.Parse(time.RFC3339Nano, ts)
			}
			kv.Destroyed, _ = x["destroyed"].(bool)
			m.Versions[n] = kv
		}
	}
	return m, nil
}

// Apply writes an approved plan with the Olympos AppRole (§11.3):
//   - patch:   PATCH <mount>data/<path>, merge-patch+json, options.cas = base
//     (a deleted key is {"KEY": null});
//   - create:  POST <mount>data/<path> with options.cas = 0 (new path);
//   - destroy: POST <mount>destroy/<path> {"versions": [...]}.
//
// Errors are *approvals.SafeError: never a value or a raw Vault response.
func (s *Service) Apply(ctx context.Context, vaultID uuid.UUID, writes []approvals.Write) ([]approvals.Applied, error) {
	r, err := loadRow(ctx, s.DB, vaultID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &approvals.SafeError{Msg: "vault not found"}
	}
	if err != nil {
		return nil, err
	}
	if r.Status != "configured" {
		return nil, &approvals.SafeError{Msg: "the vault is not configured"}
	}
	c, done, err := s.approle(ctx, r, requestTimout)
	if err != nil {
		s.Log.Warn("vault login for apply failed", "vault_id", vaultID, "err", err)
		return nil, &approvals.SafeError{Msg: "could not log in to the vault with the Olympos AppRole"}
	}
	defer done()
	var applied []approvals.Applied
	for _, w := range writes {
		ver, err := s.applyOne(ctx, c, w)
		if err != nil {
			return applied, err
		}
		applied = append(applied, approvals.Applied{Mount: w.Mount, Path: w.Path, Kind: w.Kind, Version: ver})
	}
	return applied, nil
}

func (s *Service) applyOne(ctx context.Context, c *vclient.Client, w approvals.Write) (int, error) {
	ref := w.Ref()
	switch w.Kind {
	case approvals.WriteCreate, approvals.WritePatch:
		data := make(map[string]any, len(w.Set)+len(w.Delete))
		for k, v := range w.Set {
			data[k] = string(v)
		}
		for _, k := range w.Delete {
			data[k] = nil
		}
		body := map[string]any{"data": data, "options": map[string]any{"cas": w.BaseVersion}}
		path := w.Mount + "data/" + w.Path
		var err error
		var ver int
		if w.Kind == approvals.WriteCreate {
			sec, e := c.Logical().WriteWithContext(ctx, path, body)
			err = e
			if sec != nil {
				ver = intOf(sec.Data["version"])
			}
		} else {
			sec, e := c.Logical().JSONMergePatch(ctx, path, body)
			err = e
			if sec != nil {
				ver = intOf(sec.Data["version"])
			}
		}
		clear(data)
		if err != nil {
			return 0, writeError(ref, w, err)
		}
		if ver == 0 {
			return 0, &approvals.SafeError{Msg: fmt.Sprintf("Vault did not report a version for %s", ref)}
		}
		return ver, nil
	case approvals.WriteDestroy:
		if _, err := c.Logical().WriteWithContext(ctx, w.Mount+"destroy/"+w.Path, map[string]any{"versions": w.Versions}); err != nil {
			return 0, writeError(ref, w, err)
		}
		return 0, nil
	}
	return 0, &approvals.SafeError{Msg: "unknown write kind"}
}

func writeError(ref string, w approvals.Write, err error) error {
	code := vclient.StatusCode(err)
	text := strings.ToLower(vclient.ErrorText(err))
	switch {
	case strings.Contains(text, "check-and-set"):
		return &approvals.SafeError{Msg: fmt.Sprintf("check-and-set conflict on %s: the secret changed after the request was opened (base version %d)", ref, w.BaseVersion)}
	case code == 403 && w.Kind == approvals.WriteCreate:
		return &approvals.SafeError{Msg: fmt.Sprintf("Vault denied creating %s (HTTP 403); the secret may already exist", ref)}
	case code == 403:
		return &approvals.SafeError{Msg: fmt.Sprintf("Vault denied the write on %s (HTTP 403)", ref)}
	case code == 404:
		return &approvals.SafeError{Msg: fmt.Sprintf("%s does not exist or its latest version is deleted", ref)}
	case code != 0:
		return &approvals.SafeError{Msg: fmt.Sprintf("Vault rejected the write on %s (HTTP %d)", ref, code)}
	case errors.Is(err, context.DeadlineExceeded):
		return &approvals.SafeError{Msg: fmt.Sprintf("timed out writing %s", ref)}
	}
	return &approvals.SafeError{Msg: fmt.Sprintf("could not reach the vault to write %s", ref)}
}
