package domain

import (
	"fmt"
	"net/netip"
)

// FirewallDirection says on which side of the tunnel a rule's traffic
// starts (SPEC §16.1).
type FirewallDirection string

// Firewall directions.
const (
	// DirectionInbound is traffic from the VPN side to the host or the LAN.
	DirectionInbound FirewallDirection = "inbound"
	// DirectionOutbound is traffic from the LAN to the VPN side.
	DirectionOutbound FirewallDirection = "outbound"
)

// FirewallAction is what happens to traffic a rule matches (SPEC §16.1a).
type FirewallAction string

// Firewall actions. An empty action means ActionAccept.
const (
	ActionAccept FirewallAction = "accept"
	ActionDrop   FirewallAction = "drop"
	// ActionReject answers TCP with a reset and everything else with ICMP
	// port-unreachable.
	ActionReject FirewallAction = "reject"
)

// FirewallProtocol is the IP protocol a firewall rule matches.
type FirewallProtocol string

// Firewall protocols. ProtocolTCPUDP matches both TCP and UDP.
const (
	ProtocolTCP    FirewallProtocol = "tcp"
	ProtocolUDP    FirewallProtocol = "udp"
	ProtocolTCPUDP FirewallProtocol = "tcp+udp"
	ProtocolICMP   FirewallProtocol = "icmp"
	ProtocolESP    FirewallProtocol = "esp"
	ProtocolGRE    FirewallProtocol = "gre"
	ProtocolAny    FirewallProtocol = "any"
)

// HasPorts reports whether rules of protocol p can match ports.
func (p FirewallProtocol) HasPorts() bool {
	return p == ProtocolTCP || p == ProtocolUDP || p == ProtocolTCPUDP
}

// Protocols expands ProtocolTCPUDP into TCP and UDP; every other protocol
// stands for itself.
func (p FirewallProtocol) Protocols() []FirewallProtocol {
	if p == ProtocolTCPUDP {
		return []FirewallProtocol{ProtocolTCP, ProtocolUDP}
	}
	return []FirewallProtocol{p}
}

func (p FirewallProtocol) valid() bool {
	switch p {
	case ProtocolTCP, ProtocolUDP, ProtocolTCPUDP, ProtocolICMP, ProtocolESP, ProtocolGRE, ProtocolAny:
		return true
	}
	return false
}

// DestinationKind distinguishes the host itself from an explicit address.
type DestinationKind string

// Destination kinds.
const (
	// DestinationHost is "This device": the host's own LAN address,
	// whatever it currently is.
	DestinationHost DestinationKind = "host"
	// DestinationAddress is an IPv4 address or network in CIDR.
	DestinationAddress DestinationKind = "address"
)

// FirewallDestination is where a rule's traffic goes. CIDR is set only for
// DestinationAddress; a bare IPv4 address means a single host.
type FirewallDestination struct {
	Kind DestinationKind `json:"kind"`
	CIDR string          `json:"cidr,omitempty"`
}

// Port range bounds.
const (
	MinPort = 1
	MaxPort = 65535
	// MaxPortRangeLength is the largest number of ports one range covers.
	MaxPortRangeLength = 1000
)

// PortRange is a single port (To zero or equal to From) or the inclusive
// range From–To. The zero value means "no port".
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to,omitempty"`
}

// SinglePort returns the range holding only port.
func SinglePort(port int) PortRange { return PortRange{From: port} }

// IsZero reports whether no port is set.
func (p PortRange) IsZero() bool { return p.From == 0 && p.To == 0 }

// Last returns the last port of the range.
func (p PortRange) Last() int {
	if p.To == 0 {
		return p.From
	}
	return p.To
}

// IsSingle reports whether the range holds exactly one port.
func (p PortRange) IsSingle() bool { return p.From == p.Last() }

// Len returns the number of ports in the range.
func (p PortRange) Len() int { return p.Last() - p.From + 1 }

// Contains reports whether port lies in the range.
func (p PortRange) Contains(port int) bool { return !p.IsZero() && port >= p.From && port <= p.Last() }

// Overlaps reports whether both ranges share a port.
func (p PortRange) Overlaps(o PortRange) bool {
	return !p.IsZero() && !o.IsZero() && p.From <= o.Last() && o.From <= p.Last()
}

// Equal compares ranges by the ports they hold, so {22} equals {22, 22}.
func (p PortRange) Equal(o PortRange) bool { return p.From == o.From && p.Last() == o.Last() }

// problem returns why a set range is unusable, or "".
func (p PortRange) problem() string {
	switch {
	case p.From < MinPort || p.From > MaxPort || p.Last() < MinPort || p.Last() > MaxPort:
		return "ports must be between 1 and 65535"
	case p.Last() < p.From:
		return "the range must not end before it starts"
	case p.Len() > MaxPortRangeLength:
		return fmt.Sprintf("a range covers at most %d ports", MaxPortRangeLength)
	}
	return ""
}

func (p PortRange) String() string {
	if p.IsSingle() {
		return fmt.Sprint(p.From)
	}
	return fmt.Sprintf("%d-%d", p.From, p.Last())
}

// FirewallRule is one line of the two-direction firewall (SPEC §16.1,
// §16.1a). An empty Source matches any source; an empty Action means
// accept; a zero PublicPort means "same as DestinationPort".
type FirewallRule struct {
	ID                string              `json:"id"`
	Name              string              `json:"name"`
	Direction         FirewallDirection   `json:"direction"`
	Action            FirewallAction      `json:"action"`
	Protocol          FirewallProtocol    `json:"protocol"`
	ICMPType          string              `json:"icmpType,omitempty"`
	Source            string              `json:"source"`
	SourcePort        PortRange           `json:"sourcePort,omitzero"`
	Destination       FirewallDestination `json:"destination"`
	DestinationPort   PortRange           `json:"destinationPort,omitzero"`
	PublicPort        PortRange           `json:"publicPort,omitzero"`
	KeepSourceAddress bool                `json:"keepSourceAddress"`
	Enabled           bool                `json:"enabled"`
	Comment           string              `json:"comment"`
}

// EffectiveAction returns the action, ActionAccept when none is set.
func (r FirewallRule) EffectiveAction() FirewallAction {
	if r.Action == "" {
		return ActionAccept
	}
	return r.Action
}

// IsPortForward reports whether r forwards inbound traffic to another LAN
// device (DNAT) rather than to the host.
func (r FirewallRule) IsPortForward() bool {
	return r.Direction == DirectionInbound && r.Destination.Kind == DestinationAddress
}

// PublicPorts returns the ports on the shared public address an inbound
// rule occupies: PublicPort, or DestinationPort when PublicPort is unset.
func (r FirewallRule) PublicPorts() PortRange {
	if r.PublicPort.IsZero() {
		return r.DestinationPort
	}
	return r.PublicPort
}

// Firewall is the whole firewall configuration: the global settings and
// the rules in evaluation order.
type Firewall struct {
	FirewallSettings
	Rules []FirewallRule `json:"rules"`
}

// FirewallSettings are the global protections of SPEC §16.1a.
type FirewallSettings struct {
	// DropInvalid drops conntrack-INVALID packets on the tunnel.
	DropInvalid bool `json:"dropInvalid"`
	// MSSClamp clamps the TCP MSS to the path MTU for traffic forwarded
	// through the tunnel.
	MSSClamp bool `json:"mssClamp"`
	// SYNFloodProtection limits new TCP connections from the tunnel per
	// source address.
	SYNFloodProtection bool `json:"synFloodProtection"`
	// PingLimit limits ICMP echo requests from the tunnel.
	PingLimit bool `json:"pingLimit"`
}

// DefaultFirewallSettings has every protection on.
func DefaultFirewallSettings() FirewallSettings {
	return FirewallSettings{DropInvalid: true, MSSClamp: true, SYNFloodProtection: true, PingLimit: true}
}

// ParseIPv4Prefix parses an IPv4 network in CIDR notation or a bare IPv4
// address, which stands for that single address (/32). Host bits must not
// be set.
func ParseIPv4Prefix(s string) (netip.Prefix, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		if !addr.Is4() {
			return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 address", s)
		}
		return netip.PrefixFrom(addr, 32), nil
	}
	prefix, err := netip.ParsePrefix(s)
	switch {
	case err != nil || !prefix.Addr().Is4():
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 address or network", s)
	case prefix != prefix.Masked():
		return netip.Prefix{}, fmt.Errorf("%q has host bits set", s)
	}
	return prefix, nil
}
