package domain

import (
	"fmt"
	"net/netip"
)

// TransportProtocol is the IP protocol a host-access rule matches.
type TransportProtocol string

// Transport protocols a host-access rule can match.
const (
	TransportTCP TransportProtocol = "tcp"
	TransportUDP TransportProtocol = "udp"
)

// HostAccessRule opens one host port to traffic arriving through the tunnel
// (SPEC §6). An empty SourceCIDR matches any source. It is the shape of the
// stage-1 API (/api/host-access); the firewall stores FirewallRule, and a
// host-access rule is an inbound accepting rule to this device.
type HostAccessRule struct {
	ID         string            `json:"id"`
	Protocol   TransportProtocol `json:"protocol"`
	Port       int               `json:"port"`
	SourceCIDR string            `json:"sourceCidr"`
	Enabled    bool              `json:"enabled"`
	Comment    string            `json:"comment"`
}

// Validate checks protocol, port and source of a single rule. Field names
// are relative to the rule ("protocol", "port", "sourceCidr").
func (r HostAccessRule) Validate() error {
	v := &ValidationError{}
	if r.Protocol != TransportTCP && r.Protocol != TransportUDP {
		v.Add("protocol", "must be tcp or udp")
	}
	if r.Port < MinPort || r.Port > MaxPort {
		v.Add("port", "must be between 1 and 65535")
	}
	if msg := sourceCIDRProblem(r.SourceCIDR); msg != "" {
		v.Add("sourceCidr", msg)
	}
	return v.OrNil()
}

// matchKey identifies what traffic a rule matches; two rules with the same
// key are duplicates.
func (r HostAccessRule) matchKey() string {
	return fmt.Sprintf("%s/%d/%s", r.Protocol, r.Port, r.SourceCIDR)
}

// ValidateHostAccessRules validates every rule and rejects duplicate IDs and
// rules matching the same protocol, port and source. Field names have the
// form "rules[i].field".
func ValidateHostAccessRules(rules []HostAccessRule) error {
	v := &ValidationError{}
	seenMatch := make(map[string]int, len(rules))
	seenID := make(map[string]bool, len(rules))
	for i, rule := range rules {
		prefix := fmt.Sprintf("rules[%d].", i)
		v.Merge(prefix, asValidationError(rule.Validate()))
		if first, dup := seenMatch[rule.matchKey()]; dup {
			v.Add(prefix+"port", fmt.Sprintf("duplicates rule %d (same protocol, port and source)", first))
		} else {
			seenMatch[rule.matchKey()] = i
		}
		if rule.ID != "" && seenID[rule.ID] {
			v.Add(prefix+"id", "is used by another rule")
		}
		seenID[rule.ID] = true
	}
	return v.OrNil()
}

// HostPortRuleName is the generated name of a rule converted from a
// host-access rule, e.g. "Host port 5001/tcp".
func HostPortRuleName(protocol TransportProtocol, port int) string {
	return fmt.Sprintf("Host port %d/%s", port, protocol)
}

// FirewallRule converts r into the equivalent inbound rule to this device,
// named by HostPortRuleName.
func (r HostAccessRule) FirewallRule() FirewallRule {
	return FirewallRule{
		ID:              r.ID,
		Name:            HostPortRuleName(r.Protocol, r.Port),
		Direction:       DirectionInbound,
		Action:          ActionAccept,
		Protocol:        FirewallProtocol(r.Protocol),
		Source:          r.SourceCIDR,
		Destination:     FirewallDestination{Kind: DestinationHost},
		DestinationPort: SinglePort(r.Port),
		Enabled:         r.Enabled,
		Comment:         r.Comment,
	}
}

// HostAccessRule converts r back into a host-access rule. ok is false for
// rules the host-access shape cannot express: anything but an inbound
// accepting tcp or udp rule to this device on a single port without a
// source port.
func (r FirewallRule) HostAccessRule() (rule HostAccessRule, ok bool) {
	if r.Direction != DirectionInbound || r.Destination.Kind != DestinationHost ||
		r.EffectiveAction() != ActionAccept || (r.Protocol != ProtocolTCP && r.Protocol != ProtocolUDP) ||
		!r.DestinationPort.IsSingle() || r.DestinationPort.IsZero() || !r.SourcePort.IsZero() ||
		!r.PublicPorts().Equal(r.DestinationPort) || sourceCIDRProblem(r.Source) != "" {
		return HostAccessRule{}, false
	}
	return HostAccessRule{
		ID:         r.ID,
		Protocol:   TransportProtocol(r.Protocol),
		Port:       r.DestinationPort.From,
		SourceCIDR: r.Source,
		Enabled:    r.Enabled,
		Comment:    r.Comment,
	}, true
}

// sourceCIDRProblem returns why s is not an acceptable source, or "".
func sourceCIDRProblem(s string) string {
	if s == "" {
		return ""
	}
	prefix, err := netip.ParsePrefix(s)
	switch {
	case err != nil || !prefix.Addr().Is4():
		return "must be an IPv4 network in CIDR notation, e.g. 192.168.1.0/24"
	case prefix != prefix.Masked():
		return "must be the network address of the range (no host bits set)"
	}
	return ""
}
