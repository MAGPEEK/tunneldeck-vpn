package netguard

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"tunneldeck/internal/domain"
)

// usableNeighbourStates are the neighbour states of an entry with a known
// link-layer address; FAILED, INCOMPLETE and NONE entries are skipped.
var usableNeighbourStates = []string{"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}

// LANNeighbours lists the host's IPv4 neighbours on its LAN interfaces
// with "ip -4 neigh show", in listing order and once per address. Names
// are left empty; OnLAN tells whether the address lies inside a LAN
// subnet of the host.
func (g *Guard) LANNeighbours(ctx context.Context) ([]domain.LANDevice, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	lan, err := g.detectLAN(ctx)
	if err != nil {
		return nil, err
	}
	out, err := g.ip(ctx, "-4", "neigh", "show")
	if err != nil {
		return nil, fmt.Errorf("list LAN neighbours: %w", err)
	}
	return parseNeighbours(out, lan), nil
}

// parseNeighbours reads lines like
// "192.168.2.1 dev eth0 lladdr 3c:a6:2f:00:00:01 router REACHABLE" and
// keeps the entries on an interface of lan with a link-layer address and
// a usable state, the last field.
func parseNeighbours(out string, lan []lanAddress) []domain.LANDevice {
	var devices []domain.LANDevice
	seen := make(map[netip.Addr]bool)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		state := fields[len(fields)-1]
		mac := valueAfter(fields, "lladdr")
		if err != nil || !addr.Is4() || seen[addr] || mac == "" || !slices.Contains(usableNeighbourStates, state) ||
			!onLANInterface(lan, valueAfter(fields, "dev")) {
			continue
		}
		seen[addr] = true
		devices = append(devices, domain.LANDevice{
			Address: addr, MAC: strings.ToLower(mac), State: state, OnLAN: inSubnets(lan, addr),
		})
	}
	return devices
}

func onLANInterface(lan []lanAddress, iface string) bool {
	return slices.ContainsFunc(lan, func(a lanAddress) bool { return a.iface == iface })
}

func inSubnets(lan []lanAddress, addr netip.Addr) bool {
	return slices.ContainsFunc(lan, func(a lanAddress) bool { return a.subnet().Contains(addr) })
}
