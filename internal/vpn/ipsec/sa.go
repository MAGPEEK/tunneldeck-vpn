package ipsec

import (
	"net"
	"net/netip"
	"strings"
)

// ikeSA is what the driver reads of an IKE SA in VICI's list-sa,
// ike-updown and child-updown messages.
type ikeSA struct {
	name       string
	state      string
	remoteHost string
	remotePort string
	localVIPs  []string
	transforms transforms
	prf        string
	// version is "IKEv1" or "IKEv2" as charon reports it.
	version  string
	children []childSA
}

// childSA is what the driver reads of a CHILD_SA.
type childSA struct {
	uniqueID    string
	state       string
	transforms  transforms
	bytesIn     uint64
	bytesOut    uint64
	installTime uint64 // seconds since it was installed
}

// transforms are the negotiated transforms of an SA as charon names them.
type transforms struct {
	encryption, keySize, integrity, keyExchange string
}

// SA states of interest.
const (
	stateEstablished = "ESTABLISHED"
	stateInstalled   = "INSTALLED"
)

// parseIKESAs reads the IKE SA sections of m, one per SA, keyed by the
// connection name.
func parseIKESAs(m *message) []ikeSA {
	var out []ikeSA
	for _, e := range m.sections() {
		out = append(out, parseIKESA(e.key, e.section))
	}
	return out
}

func parseIKESA(name string, m *message) ikeSA {
	sa := ikeSA{
		name: name, state: m.get("state"),
		remoteHost: m.get("remote-host"), remotePort: m.get("remote-port"),
		localVIPs: m.items("local-vips"), transforms: parseTransforms(m), prf: m.get("prf-alg"),
		version: m.get("version"),
	}
	for _, e := range m.section("child-sas").sections() {
		child := e.section
		sa.children = append(sa.children, childSA{
			uniqueID: child.get("uniqueid"), state: child.get("state"), transforms: parseTransforms(child),
			bytesIn: child.getUint("bytes-in"), bytesOut: child.getUint("bytes-out"),
			installTime: child.getUint("install-time"),
		})
	}
	return sa
}

func parseTransforms(m *message) transforms {
	return transforms{
		encryption: m.get("encr-alg"), keySize: m.get("encr-keysize"),
		integrity: m.get("integ-alg"), keyExchange: m.get("dh-group"),
	}
}

// cipher names the encryption with its key size and, for classic ciphers,
// the integrity algorithm, as swanctl prints it: "AES_GCM_16-256" or
// "AES_CBC-256/HMAC_SHA2_256_128".
func (a transforms) cipher() string {
	name := a.encryption
	if a.keySize != "" && a.keySize != "0" {
		name += "-" + a.keySize
	}
	if a.integrity != "" {
		name += "/" + a.integrity
	}
	return name
}

// controlChannel describes the IKE SA's version and proposal, e.g.
// "IKEv2 AES_GCM_16-256/PRF_HMAC_SHA2_384/CURVE_25519"; IKEv2 when charon
// reports no version.
func (sa ikeSA) controlChannel() string {
	parts := []string{sa.transforms.cipher()}
	for _, part := range []string{sa.prf, sa.transforms.keyExchange} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	version := ikeVersionName(sa.version)
	return version + " " + strings.Join(parts, "/")
}

// remote is the gateway's address and port.
func (sa ikeSA) remote() string { return net.JoinHostPort(sa.remoteHost, sa.remotePort) }

// remoteAddr is the gateway's address, invalid when charon reported none.
func (sa ikeSA) remoteAddr() netip.Addr {
	addr, err := netip.ParseAddr(sa.remoteHost)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// virtualIP is the first IPv4 virtual IP the gateway assigned.
func (sa ikeSA) virtualIP() (netip.Addr, bool) {
	for _, vip := range sa.localVIPs {
		if addr, err := netip.ParseAddr(vip); err == nil && addr.Is4() {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// installedChild returns the CHILD_SA that carries traffic: the installed
// one installed last.
func (sa ikeSA) installedChild() (childSA, bool) {
	var newest childSA
	found := false
	for _, child := range sa.children {
		if child.state == stateInstalled && (!found || child.installTime < newest.installTime) {
			newest, found = child, true
		}
	}
	return newest, found
}

// trafficCounter sums the bytes of a tunnel's CHILD_SAs over rekeyings: a
// rekeyed CHILD_SA starts at zero, so the bytes of the ones that are gone
// are kept.
type trafficCounter struct {
	goneIn, goneOut uint64
	current         map[string]childSA // by unique ID
}

// update takes the CHILD_SAs charon lists now and returns the totals.
func (c *trafficCounter) update(children []childSA) (in, out uint64) {
	next := make(map[string]childSA, len(children))
	for _, child := range children {
		next[child.uniqueID] = child
	}
	for id, child := range c.current {
		if _, ok := next[id]; !ok {
			c.goneIn += child.bytesIn
			c.goneOut += child.bytesOut
		}
	}
	c.current = next
	in, out = c.goneIn, c.goneOut
	for _, child := range next {
		in += child.bytesIn
		out += child.bytesOut
	}
	return in, out
}

// ikeVersionName turns charon's version field into "IKEv1" or "IKEv2":
// VICI reports the bare number ("1", "2"); an empty value means IKEv2.
func ikeVersionName(version string) string {
	switch version {
	case "1", "IKEv1":
		return "IKEv1"
	default:
		return "IKEv2"
	}
}
