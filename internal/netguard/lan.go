package netguard

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"tunneldeck/internal/domain"
)

// lanAddress is an IPv4 address of the host on a LAN interface.
type lanAddress struct {
	iface  string
	prefix netip.Prefix // the address with its prefix length, e.g. 192.168.2.10/24
}

// subnet is the network the address lies in.
func (a lanAddress) subnet() netip.Prefix { return a.prefix.Masked() }

// nonLANPrefixes are interface name prefixes that never carry the LAN:
// tunnels, Docker's bridges and their veth ends.
var nonLANPrefixes = []string{"tun", "tap", "wg", "docker", "br-", "veth"}

// LANSubnets returns the IPv4 subnets of the host's LAN interfaces: every
// interface except loopback, the tunnel and Docker's bridges. Inbound rules
// to other devices must target an address inside one of them.
func (g *Guard) LANSubnets(ctx context.Context) ([]netip.Prefix, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	addrs, err := g.detectLAN(ctx)
	if err != nil {
		return nil, err
	}
	return subnets(addrs), nil
}

// HostNetwork returns the host's first LAN address, its LAN subnets and
// whether IPv4 forwarding is on. An unreadable ip_forward counts as off.
func (g *Guard) HostNetwork(ctx context.Context) (domain.HostNetwork, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	addrs, err := g.detectLAN(ctx)
	if err != nil {
		return domain.HostNetwork{}, err
	}
	forward, _ := g.ipForwardValue()
	network := domain.HostNetwork{Subnets: subnets(addrs), IPForward: forward == "1"}
	if len(addrs) > 0 {
		network.Address = addrs[0].prefix.Addr()
	}
	return network, nil
}

// detectLAN lists the host's LAN addresses with "ip -4 -o addr show".
func (g *Guard) detectLAN(ctx context.Context) ([]lanAddress, error) {
	out, err := g.ip(ctx, "-4", "-o", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("detect LAN subnets: %w", err)
	}
	return parseLANAddresses(out), nil
}

// parseLANAddresses reads lines like
// "2: eth0    inet 192.168.2.10/24 brd 192.168.2.255 scope global eth0\ ...".
// Host- and link-scoped addresses are skipped, and so is any link-local
// address (169.254.0.0/16, RFC 3927): an interface without DHCP assigns
// one itself, and it is no LAN.
func parseLANAddresses(out string) []lanAddress {
	var addrs []lanAddress
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "inet" {
			continue
		}
		if scope := valueAfter(fields, "scope"); scope == "host" || scope == "link" {
			continue
		}
		iface, _, _ := strings.Cut(fields[1], "@")
		prefix, err := netip.ParsePrefix(fields[3])
		if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsLinkLocalUnicast() || !isLANInterface(iface) {
			continue
		}
		addrs = append(addrs, lanAddress{iface: iface, prefix: prefix})
	}
	return addrs
}

func isLANInterface(iface string) bool {
	if iface == "lo" || iface == DeviceName {
		return false
	}
	for _, prefix := range nonLANPrefixes {
		if strings.HasPrefix(iface, prefix) {
			return false
		}
	}
	return true
}

// subnets returns the distinct subnets of addrs in detection order.
func subnets(addrs []lanAddress) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range addrs {
		out = appendPrefix(out, a.subnet())
	}
	return out
}

func describeLAN(addrs []lanAddress) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.subnet().String()+" ("+a.iface+")")
	}
	return strings.Join(parts, ", ")
}

func valueAfter(fields []string, key string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key {
			return fields[i+1]
		}
	}
	return ""
}
