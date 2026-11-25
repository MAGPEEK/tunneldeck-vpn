package netguard

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"tunneldeck/internal/domain"
)

// Chain names owned by netguard.
const (
	inputChain       = "TUNNELDECK-INPUT"
	forwardChain     = "TUNNELDECK-FORWARD"
	preroutingChain  = "TUNNELDECK-PREROUTING"
	postroutingChain = "TUNNELDECK-POSTROUTING"
)

// Connection-tracking states used in rules.
const (
	ctEstablished = "ESTABLISHED,RELATED"
	ctInvalid     = "INVALID"
	ctDNAT        = "DNAT"
)

// Limits of the global protections (SPEC §16.1a). hashlimit names are at
// most 15 characters.
var (
	synFloodLimit = []string{"-m", "hashlimit", "--hashlimit-above", "25/sec", "--hashlimit-burst", "50",
		"--hashlimit-mode", "srcip"}
	pingLimit = []string{"-m", "hashlimit", "--hashlimit-above", "5/sec", "--hashlimit-burst", "10"}
)

// ipProtocolNumbers are the IANA numbers of the protocols a rule can name.
// iptables gets names for tcp, udp and icmp, whose port and type options
// need them, and numbers otherwise, which work without /etc/protocols.
var ipProtocolNumbers = map[domain.FirewallProtocol]int{
	domain.ProtocolTCP: 6, domain.ProtocolUDP: 17, domain.ProtocolICMP: 1,
	domain.ProtocolESP: 50, domain.ProtocolGRE: 47,
}

var (
	inputSpec = chainSpec{
		table: filterTable, name: inputChain, parent: "INPUT", sealed: true,
		jumps: [][]string{{"-i", DeviceName}},
	}
	preroutingSpec = chainSpec{
		table: natTable, name: preroutingChain, parent: "PREROUTING",
		jumps: [][]string{{"-i", DeviceName}},
	}
	postroutingSpec = chainSpec{
		table: natTable, name: postroutingChain, parent: "POSTROUTING",
		jumps: [][]string{{}},
	}
)

// forwardSpec jumps to TUNNELDECK-FORWARD for traffic in or out of the
// tunnel and, as the kill switch, for the traffic of every outbound rule,
// whichever interface it would leave by.
func forwardSpec(killSwitch [][]string) chainSpec {
	return chainSpec{
		table: filterTable, name: forwardChain, parent: "FORWARD", sealed: true,
		jumps: append([][]string{{"-i", DeviceName}, {"-o", DeviceName}}, killSwitch...),
	}
}

// allChainSpecs lists the chains in installation order, the FORWARD jumps
// for killSwitch.
func allChainSpecs(killSwitch [][]string) []chainSpec {
	return []chainSpec{inputSpec, forwardSpec(killSwitch), preroutingSpec, postroutingSpec}
}

// ruleset is the content of every chain for one firewall configuration.
type ruleset struct {
	input, forward, prerouting, postrouting [][]string
	// killSwitch holds the matches of the extra FORWARD jumps.
	killSwitch [][]string
}

// chainContent pairs each chain with its content, in installation order.
func (rs ruleset) chainContent() []struct {
	spec    chainSpec
	content [][]string
} {
	specs := allChainSpecs(rs.killSwitch)
	contents := [][][]string{rs.input, rs.forward, rs.prerouting, rs.postrouting}
	out := make([]struct {
		spec    chainSpec
		content [][]string
	}, len(specs))
	for i := range specs {
		out[i].spec, out[i].content = specs[i], contents[i]
	}
	return out
}

// buildRuleset renders the chains for firewall (SPEC §16.1, §16.1a). Only
// enabled rules install anything, in list order. remoteAccessPort is 0
// while remote access is off; lan are the host's LAN subnets.
func buildRuleset(firewall domain.Firewall, remoteAccessPort int, lan []netip.Prefix) ruleset {
	var enabled []parsedRule
	for _, rule := range firewall.Rules {
		if rule.Enabled {
			enabled = append(enabled, parseRule(rule))
		}
	}
	return ruleset{
		input:       inputContent(firewall.FirewallSettings, enabled, remoteAccessPort),
		forward:     forwardContent(firewall.FirewallSettings, enabled, lan),
		prerouting:  preroutingContent(enabled),
		postrouting: postroutingContent(enabled),
		killSwitch:  killSwitchJumps(enabled),
	}
}

// parsedRule is a validated rule with its addresses parsed.
type parsedRule struct {
	domain.FirewallRule
	source      netip.Prefix // zero for "any"
	destination netip.Prefix // zero for this device
}

func parseRule(rule domain.FirewallRule) parsedRule {
	p := parsedRule{FirewallRule: rule}
	if rule.Source != "" {
		p.source, _ = domain.ParseIPv4Prefix(rule.Source)
	}
	if rule.Destination.Kind == domain.DestinationAddress {
		p.destination, _ = domain.ParseIPv4Prefix(rule.Destination.CIDR)
	}
	return p
}

func (r parsedRule) isHostRule() bool {
	return r.Direction == domain.DirectionInbound && r.Destination.Kind == domain.DestinationHost
}

func (r parsedRule) isOutboundAccept() bool {
	return r.Direction == domain.DirectionOutbound && r.EffectiveAction() == domain.ActionAccept
}

func inputContent(settings domain.FirewallSettings, rules []parsedRule, remoteAccessPort int) [][]string {
	var out [][]string
	if settings.DropInvalid {
		out = append(out, ctRule(ctInvalid, "DROP"))
	}
	out = append(out, ctRule(ctEstablished, "ACCEPT"))
	out = append(out, floodRules(settings, nil, "in")...)
	for _, rule := range rules {
		if !rule.isHostRule() {
			continue
		}
		for _, proto := range rule.Protocol.Protocols() {
			match := slices.Concat(protocolMatch(rule, proto), portMatch("--dport", rule.DestinationPort),
				icmpMatch(rule), prefixMatch("-s", rule.source))
			out = append(out, append(match, actionTarget(rule.EffectiveAction(), proto)...))
		}
	}
	if remoteAccessPort != 0 {
		out = append(out, []string{"-p", "tcp", "--dport", strconv.Itoa(remoteAccessPort), "-j", "ACCEPT"})
	}
	return append(out, []string{"-j", "DROP"})
}

func forwardContent(settings domain.FirewallSettings, rules []parsedRule, lan []netip.Prefix) [][]string {
	out := lanReturns(rules, lan)
	out = append(out, []string{"!", "-i", DeviceName, "!", "-o", DeviceName, "-j", "DROP"})
	if settings.DropInvalid {
		out = append(out, ctRule(ctInvalid, "DROP"))
	}
	if settings.MSSClamp {
		out = append(out, []string{"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"})
	}
	out = append(out, ctRule(ctEstablished, "ACCEPT"))
	out = append(out, floodRules(settings, []string{"-i", DeviceName}, "fwd")...)
	for _, rule := range rules {
		switch {
		case rule.IsPortForward():
			out = append(out, portForwardAccepts(rule)...)
		case rule.Direction == domain.DirectionOutbound:
			out = append(out, outboundRules(rule)...)
		}
	}
	return append(out, []string{"-j", "DROP"})
}

// lanReturns hands LAN-to-LAN traffic of outbound sources back to the host's
// own rules: it reaches TUNNELDECK-FORWARD only through a kill-switch jump
// whose destination covers a LAN subnet.
func lanReturns(rules []parsedRule, lan []netip.Prefix) [][]string {
	var out [][]string
	for _, rule := range rules {
		if !rule.isOutboundAccept() {
			continue
		}
		for _, subnet := range lan {
			if !rule.destination.Overlaps(subnet) {
				continue
			}
			ret := []string{"!", "-i", DeviceName, "!", "-o", DeviceName, "-s", rule.source.String(), "-d", subnet.String(), "-j", "RETURN"}
			out = appendUnique(out, ret)
		}
	}
	return out
}

// floodRules are the SYN flood protection and the ping limit for traffic
// matching iface; name tells the hashlimit tables of each chain apart.
func floodRules(settings domain.FirewallSettings, iface []string, name string) [][]string {
	var out [][]string
	if settings.SYNFloodProtection {
		rule := slices.Concat(iface, []string{"-p", "tcp", "--syn"}, synFloodLimit,
			[]string{"--hashlimit-name", "td-syn-" + name, "-j", "DROP"})
		out = append(out, rule)
	}
	if settings.PingLimit {
		rule := slices.Concat(iface, []string{"-p", "icmp", "--icmp-type", "echo-request"}, pingLimit,
			[]string{"--hashlimit-name", "td-ping-" + name, "-j", "DROP"})
		out = append(out, rule)
	}
	return out
}

// portForwardAccepts accepts DNATed traffic to the target, matching the
// destination port after translation.
func portForwardAccepts(rule parsedRule) [][]string {
	var out [][]string
	for _, proto := range rule.Protocol.Protocols() {
		match := slices.Concat([]string{"-i", DeviceName, "-d", rule.destination.String()}, protocolMatch(rule, proto),
			portMatch("--dport", rule.DestinationPort), prefixMatch("-s", rule.source))
		out = append(out, slices.Concat(match, ctMatch(ctDNAT), []string{"-j", "ACCEPT"}))
	}
	return out
}

func outboundRules(rule parsedRule) [][]string {
	var out [][]string
	for _, proto := range rule.Protocol.Protocols() {
		match := slices.Concat([]string{"-o", DeviceName, "-s", rule.source.String()}, prefixMatch("-d", rule.destination),
			protocolMatch(rule, proto), portMatch("--dport", rule.DestinationPort), icmpMatch(rule))
		out = append(out, append(match, actionTarget(rule.EffectiveAction(), proto)...))
	}
	return out
}

func preroutingContent(rules []parsedRule) [][]string {
	var out [][]string
	for _, rule := range rules {
		if !rule.IsPortForward() {
			continue
		}
		for _, proto := range rule.Protocol.Protocols() {
			match := slices.Concat(protocolMatch(rule, proto), portMatch("--dport", rule.PublicPorts()),
				prefixMatch("-s", rule.source))
			out = append(out, append(match, "-j", "DNAT", "--to-destination", dnatTarget(rule)))
		}
	}
	return out
}

// dnatTarget is the --to-destination of a port forward: the address alone
// keeps the port; a range shifted to other ports names the base port of
// the public range, so each public port maps to its own destination port.
func dnatTarget(rule parsedRule) string {
	addr := rule.destination.Addr().String()
	public, dest := rule.PublicPorts(), rule.DestinationPort
	switch {
	case dest.IsZero() || public.Equal(dest):
		return addr
	case dest.IsSingle():
		return fmt.Sprintf("%s:%d", addr, dest.From)
	}
	return fmt.Sprintf("%s:%d-%d/%d", addr, dest.From, dest.Last(), public.From)
}

// postroutingContent masquerades port forwards on the LAN side unless they
// keep the source address, and outbound traffic on the tunnel.
func postroutingContent(rules []parsedRule) [][]string {
	var out [][]string
	for _, rule := range rules {
		switch {
		case rule.IsPortForward() && !rule.KeepSourceAddress:
			for _, proto := range rule.Protocol.Protocols() {
				match := slices.Concat([]string{"!", "-o", DeviceName, "-d", rule.destination.String()},
					protocolMatch(rule, proto), portMatch("--dport", rule.DestinationPort))
				out = append(out, slices.Concat(match, ctMatch(ctDNAT), []string{"-j", "MASQUERADE"}))
			}
		case rule.isOutboundAccept():
			masquerade := slices.Concat([]string{"-o", DeviceName, "-s", rule.source.String()},
				prefixMatch("-d", rule.destination), []string{"-j", "MASQUERADE"})
			out = appendUnique(out, masquerade)
		}
	}
	return out
}

// killSwitchJumps sends the traffic of every accepting outbound rule to
// TUNNELDECK-FORWARD, so it is dropped while it cannot leave through the
// tunnel. The matches are written as iptables -S prints them.
func killSwitchJumps(rules []parsedRule) [][]string {
	var out [][]string
	for _, rule := range rules {
		if rule.isOutboundAccept() {
			out = appendUnique(out, append([]string{"-s", rule.source.String()}, prefixMatch("-d", rule.destination)...))
		}
	}
	return out
}

func ctMatch(states string) []string { return []string{"-m", "conntrack", "--ctstate", states} }

func ctRule(states, target string) []string { return append(ctMatch(states), "-j", target) }

// protocolMatch is "-p" with proto, plus the source port; nothing for any.
func protocolMatch(rule parsedRule, proto domain.FirewallProtocol) []string {
	switch proto {
	case domain.ProtocolAny:
		return nil
	case domain.ProtocolTCP, domain.ProtocolUDP:
		return append([]string{"-p", string(proto)}, portMatch("--sport", rule.SourcePort)...)
	case domain.ProtocolICMP:
		return []string{"-p", string(proto)}
	}
	return []string{"-p", strconv.Itoa(ipProtocolNumbers[proto])}
}

func portMatch(option string, ports domain.PortRange) []string {
	if ports.IsZero() {
		return nil
	}
	if ports.IsSingle() {
		return []string{option, strconv.Itoa(ports.From)}
	}
	return []string{option, fmt.Sprintf("%d:%d", ports.From, ports.Last())}
}

func icmpMatch(rule parsedRule) []string {
	if rule.Protocol != domain.ProtocolICMP || rule.ICMPType == "" {
		return nil
	}
	return []string{"--icmp-type", rule.ICMPType}
}

// prefixMatch matches an address; nothing for "any" (zero or /0).
func prefixMatch(option string, prefix netip.Prefix) []string {
	if !prefix.IsValid() || prefix.Bits() == 0 {
		return nil
	}
	return []string{option, prefix.String()}
}

func actionTarget(action domain.FirewallAction, proto domain.FirewallProtocol) []string {
	switch {
	case action == domain.ActionDrop:
		return []string{"-j", "DROP"}
	case action == domain.ActionReject && proto == domain.ProtocolTCP:
		return []string{"-j", "REJECT", "--reject-with", "tcp-reset"}
	case action == domain.ActionReject:
		return []string{"-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	}
	return []string{"-j", "ACCEPT"}
}

func appendUnique(list [][]string, item []string) [][]string {
	for _, existing := range list {
		if slices.Equal(existing, item) {
			return list
		}
	}
	return append(list, item)
}
