package domain

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxFirewallRuleNameLength is the longest rule name in characters.
const MaxFirewallRuleNameLength = 64

// icmpTypeNames are the ICMP type names iptables understands that make
// sense in a rule; numeric "type" or "type/code" is accepted as well.
var icmpTypeNames = map[string]bool{
	"echo-reply": true, "destination-unreachable": true, "source-quench": true, "redirect": true,
	"echo-request": true, "router-advertisement": true, "router-solicitation": true, "time-exceeded": true,
	"parameter-problem": true, "timestamp-request": true, "timestamp-reply": true,
	"address-mask-request": true, "address-mask-reply": true,
}

var numericICMPType = regexp.MustCompile(`^([0-9]{1,3})(/([0-9]{1,3}))?$`)

// Validate checks one rule on its own. Field names are relative to the rule
// ("name", "protocol", "destinationPort", ...). Checks that need other rules
// or the host are in ValidateFirewallRules, CheckReservedPorts and
// CheckLANDestinations.
func (r FirewallRule) Validate() error {
	v := &ValidationError{}
	r.validateName(v)
	if r.Direction != DirectionInbound && r.Direction != DirectionOutbound {
		v.Add("direction", "must be inbound or outbound")
		return v
	}
	r.validateAction(v)
	protocolOK := r.validateProtocol(v)
	r.validateSource(v)
	r.validateDestination(v)
	if protocolOK {
		r.validatePorts(v)
	}
	if r.KeepSourceAddress && !r.IsPortForward() {
		v.Add("keepSourceAddress", "applies only to inbound rules to another device")
	}
	return v.OrNil()
}

func (r FirewallRule) validateName(v *ValidationError) {
	name := strings.TrimSpace(r.Name)
	switch {
	case name == "":
		v.Add("name", "is required")
	case utf8.RuneCountInString(r.Name) > MaxFirewallRuleNameLength:
		v.Add("name", fmt.Sprintf("must be at most %d characters", MaxFirewallRuleNameLength))
	}
}

func (r FirewallRule) validateAction(v *ValidationError) {
	switch r.Action {
	case "", ActionAccept:
	case ActionDrop, ActionReject:
		if r.IsPortForward() {
			v.Add("action", "rules to another device always accept")
		}
	default:
		v.Add("action", "must be accept, drop or reject")
	}
}

// validateProtocol reports whether the protocol is known, so the ports
// can be checked against it.
func (r FirewallRule) validateProtocol(v *ValidationError) bool {
	if !r.Protocol.valid() {
		v.Add("protocol", "must be tcp, udp, tcp+udp, icmp, esp, gre or any")
		return false
	}
	switch {
	case r.IsPortForward() && (r.Protocol == ProtocolAny || r.Protocol == ProtocolICMP):
		v.Add("protocol", "rules to another device forward tcp, udp, tcp+udp, esp or gre")
	case r.Direction == DirectionInbound && r.Protocol == ProtocolAny && r.EffectiveAction() == ActionAccept:
		v.Add("protocol", "accepting any protocol would open every port of this device; choose a protocol")
	}
	switch {
	case r.ICMPType == "":
	case r.Protocol != ProtocolICMP:
		v.Add("icmpType", "applies only to protocol icmp")
	case !validICMPType(r.ICMPType):
		v.Add("icmpType", "must be an ICMP type name such as echo-request, or a number with an optional /code")
	}
	return true
}

func validICMPType(s string) bool {
	if icmpTypeNames[s] {
		return true
	}
	m := numericICMPType.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	for _, part := range []string{m[1], m[3]} {
		if n, err := strconv.Atoi(part); part != "" && (err != nil || n > 255) {
			return false
		}
	}
	return true
}

func (r FirewallRule) validateSource(v *ValidationError) {
	if r.Source == "" {
		if r.Direction == DirectionOutbound {
			v.Add("source", "is required: the LAN device or subnet whose traffic goes through the tunnel")
		}
		return
	}
	prefix, err := ParseIPv4Prefix(r.Source)
	switch {
	case err != nil:
		v.Add("source", "must be an IPv4 address or a network in CIDR notation without host bits, e.g. 192.168.1.0/24")
	case r.Direction == DirectionOutbound && prefix.Bits() == 0:
		v.Add("source", "must be a LAN device or subnet, not every address")
	}
}

func (r FirewallRule) validateDestination(v *ValidationError) {
	d := r.Destination
	switch {
	case d.Kind == DestinationHost && r.Direction == DirectionOutbound:
		v.Add("destination", "outbound rules go to an address or network behind the VPN")
	case d.Kind == DestinationHost && d.CIDR != "":
		v.Add("destination", "this device takes no address")
	case d.Kind == DestinationHost:
	case d.Kind != DestinationAddress:
		v.Add("destination", "kind must be host or address")
	default:
		r.validateDestinationAddress(v)
	}
}

func (r FirewallRule) validateDestinationAddress(v *ValidationError) {
	prefix, err := ParseIPv4Prefix(r.Destination.CIDR)
	switch {
	case err != nil:
		v.Add("destination", "must be an IPv4 address or a network in CIDR notation without host bits, e.g. 10.0.0.0/8")
	case r.Direction == DirectionInbound && prefix.Bits() != 32:
		v.Add("destination", "must be a single IPv4 address for inbound rules")
	}
}

func (r FirewallRule) validatePorts(v *ValidationError) {
	ports := map[string]PortRange{
		"sourcePort": r.SourcePort, "destinationPort": r.DestinationPort, "publicPort": r.PublicPort,
	}
	if !r.Protocol.HasPorts() {
		for field, p := range ports {
			if !p.IsZero() {
				v.Add(field, "applies only to tcp, udp and tcp+udp")
			}
		}
		return
	}
	for field, p := range ports {
		if !p.IsZero() {
			if msg := p.problem(); msg != "" {
				v.Add(field, msg)
			}
		}
	}
	if r.DestinationPort.IsZero() && r.Direction == DirectionInbound && r.EffectiveAction() == ActionAccept {
		v.Add("destinationPort", "is required for inbound tcp and udp rules that accept")
	}
	r.validatePublicPort(v)
}

func (r FirewallRule) validatePublicPort(v *ValidationError) {
	if r.PublicPort.IsZero() {
		return
	}
	switch {
	case r.Direction != DirectionInbound:
		v.Add("publicPort", "applies only to inbound rules")
	case r.Destination.Kind == DestinationHost && !r.PublicPort.Equal(r.DestinationPort):
		v.Add("publicPort", "must equal the destination port for rules to this device")
	case !r.DestinationPort.IsZero() && r.PublicPort.Len() != r.DestinationPort.Len():
		v.Add("publicPort", "must cover as many ports as the destination port")
	}
}

// ValidateFirewallRules validates every rule, rejects duplicate IDs and
// duplicate matches, and keeps the shared public address unambiguous: an
// accepting port forward must not share a public port (or, for esp and
// gre, the protocol) with another accepting inbound rule that goes
// elsewhere. Field names have the form "rules[i].field".
func ValidateFirewallRules(rules []FirewallRule) error {
	v := &ValidationError{}
	seenID := make(map[string]bool, len(rules))
	seenMatch := make(map[string]int, len(rules))
	for i, rule := range rules {
		prefix := fmt.Sprintf("rules[%d].", i)
		ruleErr := asValidationError(rule.Validate())
		v.Merge(prefix, ruleErr)
		if rule.ID != "" && seenID[rule.ID] {
			v.Add(prefix+"id", "is used by another rule")
		}
		seenID[rule.ID] = true
		if ruleErr != nil {
			continue
		}
		key := rule.matchKey()
		if first, dup := seenMatch[key]; dup {
			v.Add(prefix+"name", fmt.Sprintf("duplicates rule %d (same direction, protocol, addresses and ports)", first))
			continue
		}
		seenMatch[key] = i
		for j := range i {
			if rules[j].Validate() == nil && publicAddressConflict(rules[j], rule) {
				v.Add(prefix+conflictField(rule), fmt.Sprintf("conflicts with rule %d on the shared public address", j))
				break
			}
		}
	}
	return v.OrNil()
}

// matchKey identifies the traffic a rule matches; equal keys are
// duplicates whatever their actions.
func (r FirewallRule) matchKey() string {
	return strings.Join([]string{
		string(r.Direction), string(r.Protocol), r.ICMPType, canonicalPrefix(r.Source),
		r.SourcePort.String(), string(r.Destination.Kind), canonicalPrefix(r.Destination.CIDR),
		r.DestinationPort.String(), r.PublicPorts().String(),
	}, "|")
}

func canonicalPrefix(s string) string {
	if s == "" {
		return ""
	}
	if prefix, err := ParseIPv4Prefix(s); err == nil {
		return prefix.String()
	}
	return s
}

// publicAddressConflict reports whether two inbound accepting rules claim
// the same traffic on the public address for different targets. At least
// one must be a port forward: overlapping rules to this device only
// accept, which never conflicts.
func publicAddressConflict(a, b FirewallRule) bool {
	if a.Direction != DirectionInbound || b.Direction != DirectionInbound ||
		a.EffectiveAction() != ActionAccept || b.EffectiveAction() != ActionAccept ||
		(!a.IsPortForward() && !b.IsPortForward()) || !sharesProtocol(a.Protocol, b.Protocol) {
		return false
	}
	sameTarget := a.Destination.Kind == b.Destination.Kind &&
		canonicalPrefix(a.Destination.CIDR) == canonicalPrefix(b.Destination.CIDR)
	if !a.Protocol.HasPorts() {
		return !sameTarget
	}
	sameMapping := sameTarget && a.DestinationPort.Equal(b.DestinationPort) && a.PublicPorts().Equal(b.PublicPorts())
	return a.PublicPorts().Overlaps(b.PublicPorts()) && !sameMapping
}

func sharesProtocol(a, b FirewallProtocol) bool {
	for _, pa := range a.Protocols() {
		for _, pb := range b.Protocols() {
			if pa == pb {
				return true
			}
		}
	}
	return false
}

func conflictField(r FirewallRule) string {
	if !r.Protocol.HasPorts() {
		return "protocol"
	}
	return publicPortField(r)
}

// publicPortField names the field holding a rule's public ports.
func publicPortField(r FirewallRule) string {
	if r.PublicPort.IsZero() {
		return "destinationPort"
	}
	return "publicPort"
}

// CheckReservedPorts rejects inbound accepting tcp/udp rules whose public
// ports include the web UI port (any rule, SPEC §6) or, when
// remoteAccessPort is not 0, enabled TCP rules including the port of remote
// access (SPEC §8.1). A port of 0 is not checked.
func CheckReservedPorts(rules []FirewallRule, uiPort, remoteAccessPort int) error {
	v := &ValidationError{}
	for i, rule := range rules {
		if rule.Direction != DirectionInbound || rule.EffectiveAction() != ActionAccept || !rule.Protocol.HasPorts() {
			continue
		}
		field := fmt.Sprintf("rules[%d].%s", i, publicPortField(rule))
		public := rule.PublicPorts()
		if uiPort != 0 && public.Contains(uiPort) {
			v.Add(field, "must not include the web UI port")
		}
		if remoteAccessPort != 0 && rule.Enabled && rule.Protocol != ProtocolUDP && public.Contains(remoteAccessPort) {
			v.Add(field, "must not include the port of remote access")
		}
	}
	return v.OrNil()
}

// CheckLANDestinations requires the destination of every enabled port
// forward to lie inside one of lan, the host's LAN subnets. Disabled rules
// install nothing and are not checked, so a rule left behind by a changed
// LAN can be disabled instead of blocking the others.
func CheckLANDestinations(rules []FirewallRule, lan []netip.Prefix) error {
	v := &ValidationError{}
	for i, rule := range rules {
		if !rule.Enabled || !rule.IsPortForward() {
			continue
		}
		prefix, err := ParseIPv4Prefix(rule.Destination.CIDR)
		if err != nil || !insideAny(prefix.Addr(), lan) {
			v.Add(fmt.Sprintf("rules[%d].destination", i), "must be inside a LAN subnet of this device ("+describePrefixes(lan)+")")
		}
	}
	return v.OrNil()
}

func insideAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func describePrefixes(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return "none detected"
	}
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}
