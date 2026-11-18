package vaults

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/vaults/vclient"
)

// UserError is shown to the caller with its HTTP status.
type UserError struct {
	Code   int
	Msg    string
	Fields map[string]string
}

func (e *UserError) Error() string { return e.Msg }

func userErr(code int, format string, a ...any) error {
	return &UserError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Policy renders the olympos policy (§11.1, §10.2) for the managed KV v2
// mounts. There is no read or update capability on <mount>/data/*, so the
// Olympos token can never read a secret value. KV v1 mounts never appear.
//
// The two auth/approle lines let Olympos rotate its own secret_id monthly
// (§11.1 step 4) without the root token; they grant nothing beyond minting
// secret_ids for this same role.
func Policy(mounts []string) string {
	ms := append([]string(nil), mounts...)
	sort.Strings(ms)
	var b strings.Builder
	b.WriteString("# olympos policy - managed by Olympos. Values are unreadable: no read/update on <mount>/data/*.\n")
	for _, m := range ms {
		fmt.Fprintf(&b, "path %q { capabilities = [\"list\", \"read\"] }\n", m+"metadata/*")
		fmt.Fprintf(&b, "path %q { capabilities = [\"read\"] }\n", m+"subkeys/*")
		fmt.Fprintf(&b, "path %q { capabilities = [\"create\", \"patch\"] }\n", m+"data/*")
		fmt.Fprintf(&b, "path %q { capabilities = [\"update\"] }\n", m+"destroy/*")
	}
	b.WriteString(`path "sys/mounts" { capabilities = ["read"] }` + "\n")
	b.WriteString(`path "sys/storage/raft/snapshot" { capabilities = ["read"] }` + "\n")
	b.WriteString(`path "auth/approle/role/olympos/secret-id" { capabilities = ["update"] }` + "\n")
	b.WriteString(`path "auth/approle/role/olympos/secret-id-accessor/destroy" { capabilities = ["update"] }` + "\n")
	return b.String()
}

// RoleSettings are the AppRole parameters (§11.1).
var RoleSettings = map[string]any{
	"token_policies":     []string{PolicyName},
	"secret_id_ttl":      "720h",
	"token_ttl":          "1h",
	"token_max_ttl":      "24h",
	"secret_id_num_uses": 0,
}

// InspectResult is returned by Inspect (nothing is stored).
type InspectResult struct {
	Version string    `json:"version"`
	Sealed  bool      `json:"sealed"`
	Storage string    `json:"storage_type"`
	Mounts  []KVMount `json:"mounts"`
}

// rootClient returns a client authenticated with the root token. The token
// string handed to the Vault client is unavoidable (http headers are
// strings); the caller zeroes its byte slice and calls done().
func (s *Service) rootClient(r *row, token []byte, caBundle *string) (*vclient.Client, func(), error) {
	c, err := s.client(r, caBundle, requestTimout)
	if err != nil {
		return nil, nil, err
	}
	c.SetToken(string(token))
	return c, func() { c.ClearToken(); c.Close() }, nil
}

func listKVMounts(ctx context.Context, c *vclient.Client, managed map[string]bool) ([]KVMount, error) {
	ms, err := c.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return nil, vclient.Sanitize(err)
	}
	var out []KVMount
	for p, m := range ms {
		if m == nil {
			continue
		}
		ver := 0
		switch m.Type {
		case "kv":
			ver = 1
			if m.Options["version"] == "2" {
				ver = 2
			}
		case "generic":
			ver = 1
		default:
			continue
		}
		p = approvals.NormalizeMount(p)
		out = append(out, KVMount{Path: p, Version: ver, Managed: ver == 2 && managed[p], Description: m.Description})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Inspect reads seal status and KV mounts with the root token.
func (s *Service) Inspect(ctx context.Context, vaultID uuid.UUID, rootToken []byte, caBundle *string) (*InspectResult, error) {
	defer secrets.Zero(rootToken)
	r, err := loadRow(ctx, s.DB, vaultID)
	if err != nil {
		return nil, err
	}
	c, done, err := s.rootClient(r, rootToken, caBundle)
	if err != nil {
		return nil, userErr(422, "%s", err.Error())
	}
	defer done()
	h, err := vclient.SealStatus(ctx, c)
	if err != nil {
		return nil, userErr(502, "%s", err.Error())
	}
	res := &InspectResult{Version: h.Version, Sealed: h.Sealed, Storage: h.StorageType, Mounts: []KVMount{}}
	if h.Sealed {
		return res, nil
	}
	managed := map[string]bool{}
	for _, m := range r.managedMounts() {
		managed[m] = true
	}
	ms, err := listKVMounts(ctx, c, managed)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 403") {
			return nil, userErr(422, "the token was rejected by Vault (it needs root or equivalent sys privileges)")
		}
		return nil, userErr(502, "%s", err.Error())
	}
	res.Mounts = append(res.Mounts, ms...)
	return res, nil
}

// ConfigureInput is the admin's configure request.
type ConfigureInput struct {
	RootToken []byte
	Mounts    []string
	CABundle  *string
	Actor     uuid.UUID
}

// Configure creates policy + AppRole olympos, stores the secret_id in Key
// Vault, verifies the AppRole login and discards the root token (§11.1).
func (s *Service) Configure(ctx context.Context, vaultID uuid.UUID, in ConfigureInput) error {
	defer secrets.Zero(in.RootToken)
	r, err := loadRow(ctx, s.DB, vaultID)
	if err != nil {
		return err
	}
	if r.Status == "gone" {
		return userErr(409, "this vault is gone from its cluster")
	}
	want := map[string]bool{}
	fields := map[string]string{}
	for _, m := range in.Mounts {
		m = approvals.NormalizeMount(m)
		if !approvals.ValidMountName(m) {
			fields["mounts"] = fmt.Sprintf("invalid mount %q", m)
			continue
		}
		want[m] = true
	}
	if len(want) == 0 && len(fields) == 0 {
		fields["mounts"] = "select at least one KV v2 mount"
	}
	if len(fields) > 0 {
		return &UserError{Code: 422, Msg: "invalid configuration", Fields: fields}
	}
	if in.CABundle != nil {
		if _, err := vclient.RootCAs([]byte(*in.CABundle)); err != nil {
			return &UserError{Code: 422, Msg: "invalid configuration", Fields: map[string]string{"ca_bundle": err.Error()}}
		}
	}

	c, done, err := s.rootClient(r, in.RootToken, in.CABundle)
	if err != nil {
		return userErr(422, "%s", err.Error())
	}
	defer done()
	h, err := vclient.SealStatus(ctx, c)
	if err != nil {
		return userErr(502, "%s", err.Error())
	}
	if h.Sealed || !h.Initialized {
		return userErr(409, "the vault is sealed or not initialized")
	}
	mounts, err := listKVMounts(ctx, c, want)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 403") {
			return userErr(422, "the token was rejected by Vault (it needs root or equivalent sys privileges)")
		}
		return userErr(502, "%s", err.Error())
	}
	found := map[string]int{}
	for _, m := range mounts {
		found[m.Path] = m.Version
	}
	var selected []string
	for m := range want {
		switch found[m] {
		case 2:
			selected = append(selected, m)
		case 1:
			fields["mounts"] = fmt.Sprintf("%s is a KV v1 mount: upgrade to KV v2 to manage it", m)
		default:
			fields["mounts"] = fmt.Sprintf("%s is not a KV mount on this vault", m)
		}
	}
	if len(fields) > 0 {
		return &UserError{Code: 422, Msg: "invalid configuration", Fields: fields}
	}
	sort.Strings(selected)

	step := func(what string, err error) error {
		if err == nil {
			return nil
		}
		return userErr(502, "%s: %s", what, vclient.Sanitize(err).Error())
	}
	if err := step("create policy olympos", c.Sys().PutPolicyWithContext(ctx, PolicyName, Policy(selected))); err != nil {
		return err
	}
	auths, err := c.Sys().ListAuthWithContext(ctx)
	if err := step("list auth methods", err); err != nil {
		return err
	}
	if a, ok := auths["approle/"]; !ok {
		if err := step("enable AppRole auth", c.Sys().EnableAuthWithOptionsWithContext(ctx, "approle", &vaultapi.EnableAuthOptions{Type: "approle",
			Description: "Olympos"})); err != nil {
			return err
		}
	} else if a.Type != "approle" {
		return userErr(409, "auth path approle/ is used by a %q auth method", a.Type)
	}
	if _, err := c.Logical().WriteWithContext(ctx, "auth/approle/role/"+RoleName, RoleSettings); err != nil {
		return step("create AppRole olympos", err)
	}
	sec, err := c.Logical().ReadWithContext(ctx, "auth/approle/role/"+RoleName+"/role-id")
	if err := step("read role_id", err); err != nil {
		return err
	}
	roleID, _ := dataString(sec, "role_id")
	if roleID == "" {
		return userErr(502, "read role_id: empty response")
	}
	secretID, accessor, err := generateSecretID(ctx, c)
	if err != nil {
		return step("generate secret_id", err)
	}
	defer secrets.Zero(secretID)

	if err := s.KV.SetSecret(ctx, s.KeyVaultName, SecretIDName(r.ID), secretID); err != nil {
		return userErr(502, "store secret_id in Key Vault: %v", err)
	}
	ref := secrets.Ref{Vault: s.KeyVaultName, Secret: SecretIDName(r.ID)}.String()

	// Verify the AppRole login works, with a client that never saw the root token.
	vc, err := s.client(r, in.CABundle, requestTimout)
	if err != nil {
		return userErr(502, "%s", err.Error())
	}
	if err := vclient.AppRoleLogin(ctx, vc, roleID, secretID); err != nil {
		vc.Close()
		return userErr(502, "verify AppRole login: %v", err)
	}
	vclient.RevokeSelf(vc)
	vc.Close()

	// Re-configure: the previous secret_id is no longer needed.
	if r.SecretIDAccessor != "" && r.SecretIDAccessor != accessor {
		if _, err := c.Logical().WriteWithContext(ctx, "auth/approle/role/"+RoleName+"/secret-id-accessor/destroy",
			map[string]any{"secret_id_accessor": r.SecretIDAccessor}); err != nil && vclient.StatusCode(err) != 404 && vclient.StatusCode(err) != 400 {
			s.Log.Warn("destroy previous secret_id", "vault_id", r.ID, "err", vclient.Sanitize(err))
		}
	}
	// The root token is not needed past this point.
	done()
	secrets.Zero(in.RootToken)

	mb, _ := json.Marshal(mounts)
	indexed := []string{}
	for _, m := range r.IndexedMounts {
		if want[m] {
			indexed = append(indexed, m)
		}
	}
	bundle := r.CABundle
	if in.CABundle != nil {
		bundle = *in.CABundle
	}
	now := s.now()
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE vaults SET status = 'configured', version = $2, kv_mounts = $3, role_id = $4,
			secret_id_ref = $5, secret_id_accessor = $6, secret_id_rotated_at = $7, configured_by = $8, configured_at = $7,
			last_error = '', ca_bundle = $9, indexed_mounts = $10 WHERE id = $1`,
			r.ID, h.Version, mb, roleID, ref, accessor, now, in.Actor, bundle, indexed); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE targets SET detected_version = $2 WHERE id = $1`, r.TargetID, h.Version); err != nil {
			return err
		}
		// Drop index rows of mounts that are no longer managed.
		if _, err := tx.Exec(ctx, `DELETE FROM vault_secret_index WHERE vault_id = $1 AND NOT (mount = ANY($2))`, r.ID, selected); err != nil {
			return err
		}
		actor := in.Actor
		return activity.Record(ctx, tx, activity.Entry{ActorID: &actor, Action: "vault.configured", ObjectType: "vault", ObjectID: r.ID.String(),
			ClusterID: &r.ClusterID, Details: map[string]any{"mounts": selected, "version": h.Version, "provider": r.Provider,
				"policy": PolicyName, "approle": RoleName, "secret_id_ref": ref}})
	})
}

func dataString(sec *vaultapi.Secret, key string) (string, bool) {
	if sec == nil || sec.Data == nil {
		return "", false
	}
	v, ok := sec.Data[key].(string)
	return v, ok
}

func generateSecretID(ctx context.Context, c *vclient.Client) ([]byte, string, error) {
	sec, err := c.Logical().WriteWithContext(ctx, "auth/approle/role/"+RoleName+"/secret-id", map[string]any{"metadata": `{"issued_by":"olympos"}`})
	if err != nil {
		return nil, "", err
	}
	sid, _ := dataString(sec, "secret_id")
	acc, _ := dataString(sec, "secret_id_accessor")
	if sid == "" || acc == "" {
		return nil, "", errors.New("empty secret_id response")
	}
	return []byte(sid), acc, nil
}

// RotateSecretID generates a new secret_id with the AppRole itself, stores it
// in Key Vault, verifies it, then destroys the previous one (§11.1 step 4).
func (s *Service) RotateSecretID(ctx context.Context, vaultID uuid.UUID) error {
	r, err := loadRow(ctx, s.DB, vaultID)
	if err != nil {
		return err
	}
	c, done, err := s.approle(ctx, r, requestTimout)
	if err != nil {
		return err
	}
	defer done()
	sid, acc, err := generateSecretID(ctx, c)
	if err != nil {
		return fmt.Errorf("generate secret_id: %w", vclient.Sanitize(err))
	}
	defer secrets.Zero(sid)
	vc, err := s.client(r, nil, requestTimout)
	if err != nil {
		return err
	}
	err = vclient.AppRoleLogin(ctx, vc, r.RoleID, sid)
	if err == nil {
		vclient.RevokeSelf(vc)
	}
	vc.Close()
	if err != nil {
		return fmt.Errorf("verify new secret_id: %w", err)
	}
	if err := s.KV.SetSecret(ctx, s.KeyVaultName, SecretIDName(r.ID), sid); err != nil {
		return fmt.Errorf("store secret_id in Key Vault: %w", err)
	}
	ref := secrets.Ref{Vault: s.KeyVaultName, Secret: SecretIDName(r.ID)}.String()
	old := r.SecretIDAccessor
	if err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE vaults SET secret_id_ref = $2, secret_id_accessor = $3, secret_id_rotated_at = $4, last_error = ''
			WHERE id = $1`, r.ID, ref, acc, s.now()); err != nil {
			return err
		}
		return activity.Record(ctx, tx, activity.Entry{Action: "vault.secret_id_rotated", ObjectType: "vault", ObjectID: r.ID.String(),
			ClusterID: &r.ClusterID, Details: map[string]any{"secret_id_ref": ref}})
	}); err != nil {
		return err
	}
	if old != "" && old != acc {
		if _, err := c.Logical().WriteWithContext(ctx, "auth/approle/role/"+RoleName+"/secret-id-accessor/destroy",
			map[string]any{"secret_id_accessor": old}); err != nil {
			s.Log.Warn("destroy previous secret_id", "vault_id", r.ID, "err", vclient.Sanitize(err))
		}
	}
	s.Log.Info("vault secret_id rotated", "vault_id", r.ID)
	return nil
}

// RotateDue rotates every configured vault whose secret_id is older than
// RotateAfter.
func (s *Service) RotateDue(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT v.id FROM vaults v JOIN targets t ON t.id = v.target_id JOIN clusters c ON c.id = t.cluster_id
		WHERE v.status = 'configured' AND c.status <> 'revoked'
		  AND (v.secret_id_rotated_at IS NULL OR v.secret_id_rotated_at < $1)`, s.now().Add(-RotateAfter))
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		if err := s.RotateSecretID(cctx, id); err != nil {
			s.Log.Error("rotate vault secret_id", "vault_id", id, "err", err)
			s.setError(ctx, id, "secret_id rotation failed: "+err.Error())
		}
		cancel()
	}
	return rows.Err()
}
