package domain

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
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

// problem returns why a set range is unusable, or an empty message.
func (p PortRange) problem() (FieldIssue, string) {
	switch {
	case p.From < MinPort || p.From > MaxPort || p.Last() < MinPort || p.Last() > MaxPort:
		return Issue("port_out_of_range"), "ports must be between 1 and 65535"
	case p.Last() < p.From:
		return Issue("port_range_reversed"), "the range must not end before it starts"
	case p.Len() > MaxPortRangeLength:
		return Issue("port_range_too_long", "max", strconv.Itoa(MaxPortRangeLength)),
			fmt.Sprintf("a range covers at most %d ports", MaxPortRangeLength)
	}
	return FieldIssue{}, ""
}

func (p PortRange) String() string {
	if p.IsSingle() {
		return fmt.Sprint(p.From)
	}
	return fmt.Sprintf("%d-%d", p.From, p.Last())
}

// FirewallRule is one line of the two-direction firewall (SPEC §16.1,
// §16.1a). Destination is one IPv4 address in the local LAN for inbound
// rules and an IPv4 address or network in CIDR for outbound rules. An
// empty Source matches any source; an empty Action means accept; a zero
// SourcePort or DestinationPort matches any port; a zero PublicPort means
// "same as DestinationPort".
type FirewallRule struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Direction         FirewallDirection `json:"direction"`
	Action            FirewallAction    `json:"action"`
	Protocol          FirewallProtocol  `json:"protocol"`
	ICMPType          string            `json:"icmpType,omitempty"`
	Source            string            `json:"source"`
	SourcePort        PortRange         `json:"sourcePort,omitzero"`
	Destination       string            `json:"destination"`
	DestinationPort   PortRange         `json:"destinationPort,omitzero"`
	PublicPort        PortRange         `json:"publicPort,omitzero"`
	KeepSourceAddress bool              `json:"keepSourceAddress"`
	Enabled           bool              `json:"enabled"`
	Comment           string            `json:"comment"`
	// legacyHost marks an inbound rule that settings schema 2 stored with
	// the destination "the host itself" and no address; Destination is then
	// empty. Only the store creates such rules (LegacyHostRule).
	legacyHost bool
}

// EffectiveAction returns the action, ActionAccept when none is set.
func (r FirewallRule) EffectiveAction() FirewallAction {
	if r.Action == "" {
		return ActionAccept
	}
	return r.Action
}

// LegacyHostRule returns r as an inbound rule to the host itself without
// an address, as settings schema 2 stored it. Such a rule keeps working
// until the next change of the firewall stores a plain address.
func LegacyHostRule(r FirewallRule) FirewallRule {
	r.Direction, r.Destination, r.legacyHost = DirectionInbound, "", true
	return r
}

// IsLegacyHost reports whether r was created by LegacyHostRule.
func (r FirewallRule) IsLegacyHost() bool { return r.legacyHost }

// WithHostAddress returns a legacy host rule as a plain rule to address,
// the host's current LAN address; without a valid address the destination
// stays empty. Other rules are returned unchanged.
func (r FirewallRule) WithHostAddress(address netip.Addr) FirewallRule {
	if !r.legacyHost {
		return r
	}
	r.legacyHost, r.Destination = false, ""
	if address.IsValid() {
		r.Destination = address.String()
	}
	return r
}

// TargetsHost reports whether r is an inbound rule to the host itself: a
// legacy host rule, or one whose destination is one of host, the host's
// own LAN addresses as detected now.
func (r FirewallRule) TargetsHost(host []netip.Addr) bool {
	if r.Direction != DirectionInbound {
		return false
	}
	if r.legacyHost {
		return true
	}
	addr, err := netip.ParseAddr(r.Destination)
	return err == nil && slices.Contains(host, addr)
}

// IsPortForward reports whether r forwards inbound traffic to another LAN
// device (DNAT) rather than to the host, whose own LAN addresses are host.
func (r FirewallRule) IsPortForward(host []netip.Addr) bool {
	return r.Direction == DirectionInbound && !r.TargetsHost(host)
}

// isAnyPortForward reports whether r forwards every port of its tcp/udp
// protocol to another LAN device.
func (r FirewallRule) isAnyPortForward(host []netip.Addr) bool {
	return r.IsPortForward(host) && r.Protocol.HasPorts() && r.DestinationPort.IsZero()
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

// ProtectionLevel is how far the host's kernel supports a global
// protection: minimal kernels lack some iptables modules.
type ProtectionLevel string

// Protection levels.
const (
	// ProtectionFull works as SPEC §16.1a describes it.
	ProtectionFull ProtectionLevel = "full"
	// ProtectionGlobal enforces one shared rate instead of one per source.
	ProtectionGlobal ProtectionLevel = "global"
	// ProtectionNone is not installed at all.
	ProtectionNone ProtectionLevel = "none"
)

// ProtectionSupport tells which global protections, and whether the hit
// counters, work on the host's kernel. The settings stay as stored; a
// protection the kernel cannot provide is left out of the firewall.
type ProtectionSupport struct {
	SYNFlood ProtectionLevel `json:"synFlood"`
	// Ping is never ProtectionGlobal: the ping limit is one global rate
	// anyway. MSSClamp is never ProtectionGlobal either.
	Ping         ProtectionLevel `json:"ping"`
	MSSClamp     ProtectionLevel `json:"mssClamp"`
	RuleCounters bool            `json:"ruleCounters"`
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
