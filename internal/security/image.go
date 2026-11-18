// Package security implements SPEC §13: ingest of Kyverno, NetworkPolicy and
// image reports from agents, findings, the trivy image scanner (server side,
// with registry credentials stored in Olympos) and the security API.
package security

import (
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// DigestRe is the only digest form accepted from agents and the API.
var DigestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// repoRe is a conservative form of the distribution reference grammar
// (lowercase host[:port]/path). It also guarantees a reference never starts
// with "-", so it cannot be parsed as a trivy flag.
var repoRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]+([._-]+[a-z0-9]+)*)+$`)

// ValidRepo reports whether repo is a well-formed, fully qualified repository.
func ValidRepo(repo string) bool { return len(repo) <= 512 && repoRe.MatchString(repo) }

// ParseReference normalizes an image string the way the container runtime
// does: "nginx:1.25" → host docker.io, repo docker.io/library/nginx, tag 1.25.
// A digest suffix (@sha256:...) is dropped. tag is "" when the string pins
// only a digest, "latest" when it has neither.
func ParseReference(image string) (host, repo, tag string) {
	s := strings.TrimSpace(image)
	hadDigest := false
	if at := strings.IndexByte(s, '@'); at >= 0 {
		s, hadDigest = s[:at], true
	}
	path := s
	host = "docker.io"
	if i := strings.IndexByte(s, '/'); i >= 0 {
		first := s[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			host, path = strings.ToLower(first), s[i+1:]
		}
	}
	if j := strings.LastIndexByte(path, ':'); j >= 0 && !strings.Contains(path[j:], "/") {
		path, tag = path[:j], path[j+1:]
	}
	switch host {
	case "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		host = "docker.io"
	}
	if host == "docker.io" && !strings.Contains(path, "/") {
		path = "library/" + path
	}
	if tag == "" && !hadDigest {
		tag = "latest"
	}
	return host, host + "/" + strings.ToLower(path), tag
}

// HostOf returns the registry host of a normalized repository.
func HostOf(repo string) string {
	if i := strings.IndexByte(repo, '/'); i >= 0 {
		return repo[:i]
	}
	return repo
}

// publicHosts are tried anonymously when no registry entry matches. Any
// other host without a matching entry is reported as missing_credential
// without contacting it.
var publicHosts = map[string]bool{
	"docker.io": true, "ghcr.io": true, "quay.io": true, "mcr.microsoft.com": true,
	"registry.k8s.io": true, "k8s.gcr.io": true, "public.ecr.aws": true,
}

// IsPublicHost reports whether host is a well-known public registry.
func IsPublicHost(host string) bool { return publicHosts[strings.ToLower(host)] }

// RegistryRef is the part of a registry row needed for matching.
type RegistryRef struct {
	ID           uuid.UUID
	HostPattern  string
	CredentialID *uuid.UUID
}

// normalizePattern lowercases a host pattern, drops a scheme or trailing
// slash and maps Docker Hub aliases to docker.io.
func normalizePattern(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	p = strings.TrimPrefix(strings.TrimPrefix(p, "https://"), "http://")
	p = strings.TrimRight(p, "/")
	for _, alias := range []string{"index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"} {
		if p == alias || strings.HasPrefix(p, alias+"/") {
			p = "docker.io" + p[len(alias):]
		}
	}
	return p
}

// PatternMatches reports whether a host pattern matches a normalized repo.
// Patterns without "/" match the host ("*.azurecr.io", "acr.contoso.io");
// patterns with "/" match the repository path ("ghcr.io/contoso/*", or
// "ghcr.io/contoso" for everything below it). "*" matches any run of
// characters, "?" one character.
func PatternMatches(pattern, repo string) bool {
	p := normalizePattern(pattern)
	if p == "" {
		return false
	}
	if !strings.Contains(p, "/") {
		return glob(p, HostOf(repo))
	}
	return glob(p, repo) || glob(p+"/*", repo)
}

// specificity ranks patterns: more literal characters win; on a tie a path
// pattern beats a host pattern.
func specificity(pattern string) (int, int) {
	p := normalizePattern(pattern)
	lit := len(p) - strings.Count(p, "*") - strings.Count(p, "?")
	path := 0
	if strings.Contains(p, "/") {
		path = 1
	}
	return lit, path
}

// MatchRegistry returns the most specific registry whose pattern matches repo,
// or nil.
func MatchRegistry(regs []RegistryRef, repo string) *RegistryRef {
	var cands []RegistryRef
	for _, r := range regs {
		if PatternMatches(r.HostPattern, repo) {
			cands = append(cands, r)
		}
	}
	if len(cands) == 0 {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		li, pi := specificity(cands[i].HostPattern)
		lj, pj := specificity(cands[j].HostPattern)
		if li != lj {
			return li > lj
		}
		if pi != pj {
			return pi > pj
		}
		return cands[i].HostPattern < cands[j].HostPattern
	})
	return &cands[0]
}

// glob matches s against a pattern with "*" (any run) and "?" (one byte).
func glob(pattern, s string) bool {
	px, sx := 0, 0
	starP, starS := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]):
			px++
			sx++
		case px < len(pattern) && pattern[px] == '*':
			starP, starS = px, sx
			px++
		case starP >= 0:
			px = starP + 1
			starS++
			sx = starS
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// MatchesAny reports whether name matches one of the glob patterns (used for
// the system namespace list).
func MatchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if glob(strings.TrimSpace(p), name) {
			return true
		}
	}
	return false
}
