package hostallow

import "net/netip"

// The reasons DeniedIP returns. Their values are stable, so callers can
// report them and compare against them.
const (
	ReasonInvalid       = "invalid"
	ReasonUnspecified   = "unspecified"
	ReasonLoopback      = "loopback"
	ReasonMetadata      = "metadata"
	ReasonLinkLocal     = "link_local"
	ReasonMulticast     = "multicast"
	ReasonBroadcast     = "broadcast"
	ReasonKubernetesAPI = "kubernetes_api"
)

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	// Local-use NAT64 (RFC 8215). Only the /96 layout is decoded (IPv4 in
	// the last 32 bits, as in 64:ff9b::/96); the shorter RFC 6052 layouts
	// put it at other offsets and are not decoded.
	nat64LocalPrefix = netip.MustParsePrefix("64:ff9b:1::/48")
	// IPv4-compatible IPv6 (::a.b.c.d, deprecated by RFC 4291). Checked
	// too, so that "::127.0.0.1" cannot pass as a plain IPv6 address.
	v4CompatPrefix = netip.MustParsePrefix("::/96")
	// SIIT IPv4-translated (::ffff:0:a.b.c.d, RFC 2765), that is
	// 0:0:0:0:ffff:0:a.b.c.d. The prefix is written in full: "::ffff:0:0"
	// would parse as the IPv4-mapped ::ffff:0.0.0.0, which Unmap already
	// handles.
	siitPrefix = netip.MustParsePrefix("::ffff:0:0:0/96")
	// 0.0.0.0/8: "this network"; Linux connects 0.0.0.0 to the local host.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")

	limitedBroadcast = netip.MustParseAddr("255.255.255.255")

	// Cloud instance metadata services.
	metadataAddrs = []netip.Addr{
		netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, most others
		netip.MustParseAddr("fd00:ec2::254"),   // AWS (IPv6)
		netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
		netip.MustParseAddr("192.0.0.192"),     // Oracle Cloud (legacy)
	}
)

// DeniedIP reports whether the probe must refuse to connect to ip, and why.
// It checks loopback, link-local, cloud metadata (AWS, GCP, Azure, Alibaba,
// Oracle), unspecified (0.0.0.0/8 and ::), multicast, the limited broadcast
// address 255.255.255.255 (reason "broadcast") and the Kubernetes API
// service addresses in apiServer.
//
// IPv4-mapped (::ffff:a.b.c.d), SIIT IPv4-translated (::ffff:0:a.b.c.d),
// NAT64 (64:ff9b::/96, and 64:ff9b:1::/48 in its /96 layout) and
// IPv4-compatible (::a.b.c.d) addresses are also checked as the IPv4
// address they carry.
// An invalid ip is denied with reason "invalid".
func DeniedIP(ip netip.Addr, apiServer []netip.Addr) (reason string, denied bool) {
	if !ip.IsValid() {
		return ReasonInvalid, true
	}
	ip = ip.WithZone("").Unmap()
	if reason, denied := deniedAddr(ip, apiServer); denied {
		return reason, true
	}
	if v4, ok := embeddedV4(ip); ok {
		return deniedAddr(v4, apiServer)
	}
	return "", false
}

func deniedAddr(ip netip.Addr, apiServer []netip.Addr) (string, bool) {
	switch {
	case ip.IsUnspecified() || thisNetwork.Contains(ip):
		return ReasonUnspecified, true
	case ip.IsLoopback():
		return ReasonLoopback, true
	case isMetadata(ip):
		return ReasonMetadata, true
	case ip.IsLinkLocalUnicast():
		return ReasonLinkLocal, true
	case ip.IsMulticast():
		return ReasonMulticast, true
	case ip == limitedBroadcast:
		return ReasonBroadcast, true
	}
	for _, a := range apiServer {
		if a.IsValid() && a.WithZone("").Unmap() == ip {
			return ReasonKubernetesAPI, true
		}
	}
	return "", false
}

func isMetadata(ip netip.Addr) bool {
	for _, m := range metadataAddrs {
		if ip == m {
			return true
		}
	}
	return false
}

// embeddedV4 returns the IPv4 address in the last 32 bits of a NAT64
// (well-known or local-use), SIIT IPv4-translated or IPv4-compatible
// address. ip has already been unmapped.
func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() || !(nat64Prefix.Contains(ip) || nat64LocalPrefix.Contains(ip) ||
		siitPrefix.Contains(ip) || v4CompatPrefix.Contains(ip)) {
		return netip.Addr{}, false
	}
	b := ip.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}
