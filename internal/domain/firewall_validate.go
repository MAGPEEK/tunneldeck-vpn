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

// ruleIDPattern limits rule IDs to what an iptables comment tag carries
// unquoted and unambiguously (SPEC §16.4); generated IDs are 32 hex digits.
var ruleIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// icmpTypeNames are the ICMP type names iptables understands that make
// sense in a rule; numeric "type" or "type/code" is accepted as well.
var icmpTypeNames = map[string]bool{
	"echo-reply": true, "destination-unreachable": true, "source-quench": true, "redirect": true,
	"echo-request": true, "router-advertisement": true, "router-solicitation": true, "time-exceeded": true,
	"parameter-problem": true, "timestamp-request": true, "timestamp-reply": true,
	"address-mask-request": true, "address-mask-reply": true,
}

var numericICMPType = regexp.MustCompile(`^([0-9]{1,3})(/([0-9]{1,3}))?$`)

// Examples named by the address messages.
const (
	exampleLANNetwork    = "192.168.1.0/24"
	exampleRemoteNetwork = "10.0.0.0/8"
)

// Validate checks one rule on its own. Field names are relative to the rule
// ("name", "protocol", "destinationPort", ...). Checks that need other rules
// or the host are in ValidateFirewallRules, CheckReservedPorts and
// CheckLANDestinations. An empty source or destination port matches any
// port.
func (r FirewallRule) Validate() error {
	v := &ValidationError{}
	r.validateName(v)
	if r.Direction != DirectionInbound && r.Direction != DirectionOutbound {
		v.AddIssue("direction", Issue("firewall_direction_invalid"), "must be inbound or outbound")
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
		v.AddIssue("keepSourceAddress", Issue("firewall_keep_source_forward_only"),
			"applies only to inbound rules to another device")
	}
	return v.OrNil()
}

func (r FirewallRule) validateName(v *ValidationError) {
	name := strings.TrimSpace(r.Name)
	switch {
	case name == "":
		v.AddIssue("name", Issue("required"), "is required")
	case utf8.RuneCountInString(r.Name) > MaxFirewallRuleNameLength:
		v.AddIssue("name", Issue("too_long", "max", strconv.Itoa(MaxFirewallRuleNameLength)),
			fmt.Sprintf("must be at most %d characters", MaxFirewallRuleNameLength))
	}
}

func (r FirewallRule) validateAction(v *ValidationError) {
	switch r.Action {
	case "", ActionAccept:
	case ActionDrop, ActionReject:
		if r.IsPortForward() {
			v.AddIssue("action", Issue("firewall_forward_accepts_only"), "rules to another device always accept")
		}
	default:
		v.AddIssue("action", Issue("firewall_action_invalid"), "must be accept, drop or reject")
	}
}

// validateProtocol reports whether the protocol is known, so the ports
// can be checked against it.
func (r FirewallRule) validateProtocol(v *ValidationError) bool {
	if !r.Protocol.valid() {
		v.AddIssue("protocol", Issue("firewall_protocol_invalid"), "must be tcp, udp, tcp+udp, icmp, esp, gre or any")
		return false
	}
	switch {
	case r.IsPortForward() && (r.Protocol == ProtocolAny || r.Protocol == ProtocolICMP):
		v.AddIssue("protocol", Issue("firewall_forward_protocol"), "rules to another device forward tcp, udp, tcp+udp, esp or gre")
	case r.Direction == DirectionInbound && r.Protocol == ProtocolAny && r.EffectiveAction() == ActionAccept:
		v.AddIssue("protocol", Issue("firewall_accept_any_protocol"),
			"accepting any protocol would open every port of the host; choose a protocol")
	}
	switch {
	case r.ICMPType == "":
	case r.Protocol != ProtocolICMP:
		v.AddIssue("icmpType", Issue("firewall_icmp_type_needs_icmp"), "applies only to protocol icmp")
	case !validICMPType(r.ICMPType):
		v.AddIssue("icmpType", Issue("firewall_icmp_type_invalid"),
			"must be an ICMP type name such as echo-request, or a number with an optional /code")
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
			v.AddIssue("source", Issue("firewall_outbound_source_required"),
				"is required: the LAN device or subnet whose traffic goes through the tunnel")
		}
		return
	}
	prefix, err := ParseIPv4Prefix(r.Source)
	switch {
	case err != nil:
		addPrefixIssue(v, "source", exampleLANNetwork)
	case r.Direction == DirectionOutbound && prefix.Bits() == 0:
		v.AddIssue("source", Issue("firewall_outbound_source_everything"), "must be a LAN device or subnet, not every address")
	}
}

// addPrefixIssue reports field as not an IPv4 address or network, naming
// example.
func addPrefixIssue(v *ValidationError, field, example string) {
	v.AddIssue(field, Issue("ipv4_prefix_invalid", "example", example),
		"must be an IPv4 address or a network in CIDR notation without host bits, e.g. "+example)
}

func (r FirewallRule) validateDestination(v *ValidationError) {
	d := r.Destination
	switch {
	case d.Kind == DestinationHost && r.Direction == DirectionOutbound:
		v.AddIssue("destination", Issue("firewall_outbound_to_host"), "outbound rules go to an address or network behind the VPN")
	case d.Kind == DestinationHost && d.CIDR != "":
		v.AddIssue("destination", Issue("firewall_host_takes_no_address"), "the host takes no address")
	case d.Kind == DestinationHost:
	case d.Kind != DestinationAddress:
		v.AddIssue("destination", Issue("firewall_destination_kind_invalid"), "kind must be host or address")
	default:
		r.validateDestinationAddress(v)
	}
}

func (r FirewallRule) validateDestinationAddress(v *ValidationError) {
	prefix, err := ParseIPv4Prefix(r.Destination.CIDR)
	switch {
	case err != nil:
		addPrefixIssue(v, "destination", exampleRemoteNetwork)
	case r.Direction == DirectionInbound && prefix.Bits() != 32:
		v.AddIssue("destination", Issue("firewall_inbound_single_address"), "must be a single IPv4 address for inbound rules")
	}
}

func (r FirewallRule) validatePorts(v *ValidationError) {
	ports := map[string]PortRange{
		"sourcePort": r.SourcePort, "destinationPort": r.DestinationPort, "publicPort": r.PublicPort,
	}
	if !r.Protocol.HasPorts() {
		for field, p := range ports {
			if !p.IsZero() {
				v.AddIssue(field, Issue("firewall_ports_need_tcp_udp"), "applies only to tcp, udp and tcp+udp")
			}
		}
		return
	}
	for field, p := range ports {
		if !p.IsZero() {
			if issue, msg := p.problem(); msg != "" {
				v.AddIssue(field, issue, msg)
			}
		}
	}
	r.validatePublicPort(v)
}

func (r FirewallRule) validatePublicPort(v *ValidationError) {
	if r.PublicPort.IsZero() {
		return
	}
	switch {
	case r.Direction != DirectionInbound:
		v.AddIssue("publicPort", Issue("firewall_public_port_inbound_only"), "applies only to inbound rules")
	case r.DestinationPort.IsZero():
		v.AddIssue("publicPort", Issue("firewall_public_port_needs_destination_port"),
			"must be empty while the destination port is empty (any port)")
	case r.Destination.Kind == DestinationHost && !r.PublicPort.Equal(r.DestinationPort):
		v.AddIssue("publicPort", Issue("firewall_public_port_host"), "must equal the destination port for rules to the host")
	case r.PublicPort.Len() != r.DestinationPort.Len():
		v.AddIssue("publicPort", Issue("firewall_public_port_length"), "must cover as many ports as the destination port")
	}
}

// ValidateFirewallRules validates every rule, rejects duplicate IDs and
// duplicate matches, and keeps the shared public address unambiguous: an
// accepting port forward must not share a public port (or, for esp and
// gre, the protocol) with another accepting inbound rule that goes
// elsewhere. A conflict with an any-port forward is reported on both
// rules. Field names have the form "rules[i].field".
func ValidateFirewallRules(rules []FirewallRule) error {
	v := &ValidationError{}
	seenID := make(map[string]bool, len(rules))
	seenMatch := make(map[string]int, len(rules))
	for i, rule := range rules {
		prefix := fmt.Sprintf("rules[%d].", i)
		ruleErr := asValidationError(rule.Validate())
		v.Merge(prefix, ruleErr)
		switch {
		case rule.ID != "" && !ruleIDPattern.MatchString(rule.ID):
			v.AddIssue(prefix+"id", Issue("firewall_id_invalid"), "must be 1 to 64 letters, digits, underscores or hyphens")
		case rule.ID != "" && seenID[rule.ID]:
			v.AddIssue(prefix+"id", Issue("firewall_duplicate_id"), "is used by another rule")
		}
		seenID[rule.ID] = true
		if ruleErr != nil {
			continue
		}
		key := rule.matchKey()
		if first, dup := seenMatch[key]; dup {
			v.AddIssue(prefix+"name", Issue("firewall_duplicate_rule", "rule", strconv.Itoa(first)),
				fmt.Sprintf("duplicates rule %d (same direction, protocol, addresses and ports)", first))
			continue
		}
		seenMatch[key] = i
		addPublicAddressConflict(v, rules, i)
	}
	return v.OrNil()
}

// addPublicAddressConflict reports the first valid earlier rule that
// conflicts with rules[i] on the shared public address.
func addPublicAddressConflict(v *ValidationError, rules []FirewallRule, i int) {
	rule := rules[i]
	for j, other := range rules[:i] {
		if other.Validate() != nil || !publicAddressConflict(other, rule) {
			continue
		}
		addConflict(v, i, rule, j)
		if rule.isAnyPortForward() || other.isAnyPortForward() {
			addConflict(v, j, other, i)
		}
		return
	}
}

func addConflict(v *ValidationError, index int, rule FirewallRule, with int) {
	v.AddIssue(fmt.Sprintf("rules[%d].%s", index, conflictField(rule)),
		Issue("firewall_public_address_conflict", "rule", strconv.Itoa(with)),
		fmt.Sprintf("conflicts with rule %d on the shared public address", with))
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
// one must be a port forward: overlapping rules to the host only accept,
// which never conflicts. An any-port forward claims every public port of
// its protocol, but only while both rules are enabled.
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
	if a.isAnyPortForward() || b.isAnyPortForward() {
		return a.Enabled && b.Enabled && !sameMapping
	}
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
// access (SPEC §8.1). A port of 0 is not checked. Rules without a port
// (any port) pass: netguard keeps both ports for the host (SPEC §16.1).
func CheckReservedPorts(rules []FirewallRule, uiPort, remoteAccessPort int) error {
	v := &ValidationError{}
	for i, rule := range rules {
		if rule.Direction != DirectionInbound || rule.EffectiveAction() != ActionAccept || !rule.Protocol.HasPorts() {
			continue
		}
		field := fmt.Sprintf("rules[%d].%s", i, publicPortField(rule))
		public := rule.PublicPorts()
		if uiPort != 0 && public.Contains(uiPort) {
			v.AddIssue(field, Issue("firewall_ui_port"), "must not include the web UI port")
		}
		if remoteAccessPort != 0 && rule.Enabled && rule.Protocol != ProtocolUDP && public.Contains(remoteAccessPort) {
			v.AddIssue(field, Issue("firewall_remote_access_port"), "must not include the port of remote access")
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
			v.AddIssue(fmt.Sprintf("rules[%d].destination", i), lanIssue(lan),
				"must be inside a LAN subnet of the host ("+describePrefixes(lan)+")")
		}
	}
	return v.OrNil()
}

func lanIssue(lan []netip.Prefix) FieldIssue {
	if len(lan) == 0 {
		return Issue("firewall_lan_not_detected")
	}
	return Issue("firewall_destination_outside_lan", "subnets", describePrefixes(lan))
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
