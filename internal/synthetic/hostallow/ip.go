package hostallow

import "net/netip"

const (
	reasonInvalid       = "invalid"
	reasonUnspecified   = "unspecified"
	reasonLoopback      = "loopback"
	reasonMetadata      = "metadata"
	reasonLinkLocal     = "link_local"
	reasonMulticast     = "multicast"
	reasonKubernetesAPI = "kubernetes_api"
)

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	// IPv4-compatible IPv6 (::a.b.c.d, deprecated by RFC 4291). Checked
	// too, so that "::127.0.0.1" cannot pass as a plain IPv6 address.
	v4CompatPrefix = netip.MustParsePrefix("::/96")
	// 0.0.0.0/8: "this network"; Linux connects 0.0.0.0 to the local host.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")

	metadataAddrs = []netip.Addr{
		netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("fd00:ec2::254"),
	}
)

// DeniedIP reports whether the probe must refuse to connect to ip, and why.
// It checks loopback, link-local, cloud metadata, unspecified (0.0.0.0/8 and
// ::), multicast and the Kubernetes API service addresses in apiServer.
//
// IPv4-mapped (::ffff:a.b.c.d), NAT64 (64:ff9b::/96) and IPv4-compatible
// (::a.b.c.d) addresses are also checked as the IPv4 address they carry.
// An invalid ip is denied with reason "invalid".
func DeniedIP(ip netip.Addr, apiServer []netip.Addr) (reason string, denied bool) {
	if !ip.IsValid() {
		return reasonInvalid, true
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
		return reasonUnspecified, true
	case ip.IsLoopback():
		return reasonLoopback, true
	case isMetadata(ip):
		return reasonMetadata, true
	case ip.IsLinkLocalUnicast():
		return reasonLinkLocal, true
	case ip.IsMulticast():
		return reasonMulticast, true
	}
	for _, a := range apiServer {
		if a.IsValid() && a.WithZone("").Unmap() == ip {
			return reasonKubernetesAPI, true
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

// embeddedV4 returns the IPv4 address in the last 32 bits of a NAT64 or
// IPv4-compatible address. ip has already been unmapped.
func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() || !(nat64Prefix.Contains(ip) || v4CompatPrefix.Contains(ip)) {
		return netip.Addr{}, false
	}
	b := ip.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}
