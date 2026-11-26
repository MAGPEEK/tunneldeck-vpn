package domain

import "net/netip"

// LANDevice is a neighbour of the host on a LAN interface, as the device
// picker of the firewall editor offers it (SPEC §16.4). Name is the
// reverse-DNS name, empty when none resolved; State is the kernel's
// neighbour state (REACHABLE, STALE, DELAY, PROBE or PERMANENT); OnLAN
// reports whether Address lies inside a LAN subnet of the host, as port
// forwards require.
type LANDevice struct {
	Address netip.Addr
	MAC     string
	Name    string
	State   string
	OnLAN   bool
}

// RuleCounters are the hits of one firewall rule since its chain was last
// rebuilt (SPEC §16.4): Packets counts the new connections the rule
// matched (their first packets; later ones are accepted as established),
// Bytes the bytes of those packets.
type RuleCounters struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}
