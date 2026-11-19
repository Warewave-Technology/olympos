package secrets

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/labels"
)

// Key Vault references users enter (backup credentials, registries,
// destinations) are resolved with Olympos' own identity, which can read
// every secret in the vault. Without a policy a user scoped to one cluster
// could have any secret sent to a target they control (security review #2).
//
//   - Olympos' own secrets (HMAC key, database DSN, Entra client secret,
//     Slack token, AppRole secret_ids) are never resolved for a user.
//   - Global admins may reference any other secret.
//   - Everyone else only what a keyVault.references rule allows for the
//     labels of the cluster the secret is used for.

// RefRule allows references matching Ref (a glob on "vault/secret", e.g.
// "kv-platform-weu/dev-*") for clusters matching Scope (a label selector,
// "" or "all" for every cluster).
type RefRule struct {
	Ref   string `yaml:"ref"`
	Scope string `yaml:"scope"`
}

var (
	// ErrRefReserved: the reference names one of Olympos' own secrets.
	ErrRefReserved = errors.New("this Key Vault secret is used by Olympos itself and cannot be referenced")
	// ErrRefNotAllowed: no keyVault.references rule allows it here.
	ErrRefNotAllowed = errors.New("this Key Vault reference is not allowed for this cluster: an admin has to allow it (keyVault.references)")
)

type refRule struct {
	glob string
	all  bool
	sel  labels.Selector
}

type refPolicy struct {
	reserved map[string]bool // "vault/secret" or "*/secret", lower case
	prefixes []string        // reserved secret-name prefixes, lower case
	rules    []refRule
}

var (
	policyMu sync.RWMutex
	// AppRole secret_ids (vaults.SecretIDName) are reserved by default.
	policy = &refPolicy{reserved: map[string]bool{}, prefixes: []string{"olympos-vault-"}}
)

// ConfigureRefPolicy sets the rules and Olympos' own secrets (call once at
// startup). Reserved references without a vault reserve the name in every
// vault.
func ConfigureRefPolicy(rules []RefRule, reserved []Ref, reservedPrefixes []string) error {
	p := &refPolicy{reserved: map[string]bool{}, prefixes: []string{"olympos-vault-"}}
	for _, r := range reserved {
		v := strings.ToLower(r.Vault)
		if v == "" {
			v = "*"
		}
		if r.Secret != "" {
			p.reserved[v+"/"+strings.ToLower(r.Secret)] = true
		}
	}
	for _, pre := range reservedPrefixes {
		p.prefixes = append(p.prefixes, strings.ToLower(pre))
	}
	for i, r := range rules {
		g := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(r.Ref), "kv://"))
		if _, err := path.Match(g, "x/y"); err != nil || !strings.Contains(g, "/") {
			return fmt.Errorf("keyVault.references[%d].ref %q: want a glob on <vault>/<secret>", i, r.Ref)
		}
		rr := refRule{glob: g}
		if s := strings.TrimSpace(r.Scope); s == "" || s == "all" {
			rr.all = true
		} else {
			sel, err := labels.Parse(s)
			if err != nil {
				return fmt.Errorf("keyVault.references[%d].scope: %w", i, err)
			}
			rr.sel = sel
		}
		p.rules = append(p.rules, rr)
	}
	policyMu.Lock()
	policy = p
	policyMu.Unlock()
	return nil
}

func (p *refPolicy) isReserved(r Ref) bool {
	v, s := strings.ToLower(r.Vault), strings.ToLower(r.Secret)
	if p.reserved[v+"/"+s] || p.reserved["*/"+s] {
		return true
	}
	for _, pre := range p.prefixes {
		if strings.HasPrefix(s, pre) {
			return true
		}
	}
	return false
}

// RefUse says who enters a reference and for which cluster: GlobalAdmin is
// admin with scope all; Labels are the labels of the cluster the secret is
// sent to (nil for global settings such as registries and destinations).
type RefUse struct {
	GlobalAdmin bool
	Labels      map[string]string
}

// CheckUserRef parses ref and reports whether u may use it.
func CheckUserRef(ref string, u RefUse) (Ref, error) {
	r, err := ParseRef(ref)
	if err != nil {
		return r, err
	}
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	if p.isReserved(r) {
		return r, ErrRefReserved
	}
	if u.GlobalAdmin {
		return r, nil
	}
	key := strings.ToLower(r.Vault + "/" + r.Secret)
	for _, rule := range p.rules {
		if ok, _ := path.Match(rule.glob, key); !ok {
			continue
		}
		if rule.all || (u.Labels != nil && rule.sel.Matches(labels.Set(u.Labels))) {
			return r, nil
		}
	}
	return r, ErrRefNotAllowed
}

// ResolveUserRef resolves a reference a user entered. It refuses Olympos'
// own secrets whoever asks, also for references stored before a policy
// change; who may enter it is checked by CheckUserRef when it is saved.
func ResolveUserRef(ctx context.Context, kv KeyVault, ref string) ([]byte, error) {
	r, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	policyMu.RLock()
	reserved := policy.isReserved(r)
	policyMu.RUnlock()
	if reserved {
		return nil, ErrRefReserved
	}
	return kv.GetSecret(ctx, r.Vault, r.Secret)
}
