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
	// limitChain drops SYNs and pings above their global rate while the
	// kernel has the limit match but not the hashlimit match.
	limitChain = "TUNNELDECK-LIMIT"
	// mangleChain marks the connections that come in through the tunnel
	// while the kernel has the CONNMARK target (replyByMark).
	mangleChain = "TUNNELDECK-MANGLE-PRE"
)

// replyMark is the connection mark of connections that came in through the
// tunnel, with the mask of the bits netguard owns; the upper 16 bits stay
// free for other software.
const (
	replyMarkMask = "0xffff"
	replyMark     = "0x7194/" + replyMarkMask
)

var (
	// replyMarkRule marks every connection that comes in through the
	// tunnel.
	replyMarkRule = []string{"-i", DeviceName, "-j", "CONNMARK", "--set-mark", replyMark}
	// replyRestoreRule copies that mark onto the packets of such a
	// connection that arrive by another interface: the replies of
	// port-forward targets, which the policy rule "fwmark" then routes
	// into the tunnel. Packets of other connections keep their mark.
	replyRestoreRule = []string{"!", "-i", DeviceName, "-m", "connmark", "--mark", replyMark,
		"-j", "CONNMARK", "--restore-mark", "--nfmask", replyMarkMask, "--ctmask", replyMarkMask}
)

// Connection-tracking states used in rules.
const (
	ctEstablished = "ESTABLISHED,RELATED"
	ctInvalid     = "INVALID"
	ctDNAT        = "DNAT"
)

// rateLimit is the rate of a global protection (SPEC §16.1a), counted per
// source address when perSource is set.
type rateLimit struct {
	rate, burst string
	perSource   bool
}

var (
	synFloodRate = rateLimit{rate: "25/sec", burst: "50", perSource: true}
	pingRate     = rateLimit{rate: "5/sec", burst: "10"}
)

// hashlimitAbove matches the packets above r; name (at most 15
// characters) tells its table apart from the other rules'.
func (r rateLimit) hashlimitAbove(name string) []string {
	match := []string{"-m", "hashlimit", "--hashlimit-above", r.rate, "--hashlimit-burst", r.burst}
	if r.perSource {
		match = append(match, "--hashlimit-mode", "srcip")
	}
	return append(match, "--hashlimit-name", name)
}

// limitWithin matches the packets within r, counted together whatever
// their source: the limit match cannot invert, count per source or be
// named.
func (r rateLimit) limitWithin() []string {
	return []string{"-m", "limit", "--limit", r.rate, "--limit-burst", r.burst}
}

// mssClampRule clamps the MSS of TCP SYNs to the path MTU.
var mssClampRule = []string{"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"}

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
	// limitSpec is reached only from the lines of TUNNELDECK-INPUT and
	// TUNNELDECK-FORWARD that send SYNs and pings to it (rateRules).
	limitSpec = chainSpec{table: filterTable, name: limitChain, sealed: true}
	// mangleSpec sees every packet: the replies it marks arrive by the LAN
	// interfaces. Its lines never decide a packet's fate.
	mangleSpec = chainSpec{
		table: mangleTable, name: mangleChain, parent: "PREROUTING",
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
	// limit is the content of TUNNELDECK-LIMIT, nil while no protection
	// needs it.
	limit [][]string
	// killSwitch holds the matches of the extra FORWARD jumps.
	killSwitch [][]string
	// marksReplies is set while the kernel has the CONNMARK target, so
	// TUNNELDECK-MANGLE-PRE exists with the content mangle.
	marksReplies bool
	mangle       [][]string
}

// chainContent pairs each chain with its content, in installation order:
// TUNNELDECK-LIMIT, when needed, before the chains that jump to it, and
// TUNNELDECK-MANGLE-PRE last while the kernel can mark replies.
func (rs ruleset) chainContent() []struct {
	spec    chainSpec
	content [][]string
} {
	specs := allChainSpecs(rs.killSwitch)
	contents := [][][]string{rs.input, rs.forward, rs.prerouting, rs.postrouting}
	if rs.limit != nil {
		specs = append([]chainSpec{limitSpec}, specs...)
		contents = append([][][]string{rs.limit}, contents...)
	}
	if rs.marksReplies {
		specs = append(specs, mangleSpec)
		contents = append(contents, rs.mangle)
	}
	out := make([]struct {
		spec    chainSpec
		content [][]string
	}, len(specs))
	for i := range specs {
		out[i].spec, out[i].content = specs[i], contents[i]
	}
	return out
}

// hostPorts are the TCP ports the host keeps for itself: the web UI port,
// never reachable from the tunnel, and the remote-access port, 0 while
// remote access is off.
type hostPorts struct {
	ui, remoteAccess int
}

// buildRuleset renders the chains for firewall (SPEC §16.1, §16.1a). Only
// enabled rules install anything, in list order. Each line is tagged with
// its rule or its fixed purpose. lan are the host's LAN addresses: an
// inbound rule to one of them is a rule to the host, any other a port
// forward. caps are the optional extensions of the kernel: a protection
// it cannot provide falls back or is left out, reject rules drop without
// the REJECT target, and without CONNMARK there is no mangle chain.
// localNetworks are the LAN subnets a routed tunnel carries with their own
// addresses; their traffic into the tunnel is never masqueraded.
func buildRuleset(firewall domain.Firewall, reserved hostPorts, lan []lanAddress, caps capabilities, localNetworks []netip.Prefix) ruleset {
	var enabled []parsedRule
	host := hostAddresses(lan)
	for _, rule := range firewall.Rules {
		if rule.Enabled {
			enabled = append(enabled, parseRule(rule, host))
		}
	}
	opts := renderOptions(firewall.FirewallSettings, caps)
	return ruleset{
		input:        inputContent(opts, enabled, reserved),
		forward:      forwardContent(opts, enabled, subnets(lan)),
		prerouting:   preroutingContent(enabled, reserved),
		postrouting:  postroutingContent(enabled, localNetworks),
		limit:        limitContent(opts),
		killSwitch:   killSwitchJumps(enabled),
		marksReplies: caps.replyRouting() == replyByMark,
		mangle:       mangleContent(enabled),
	}
}

// mangleContent marks the connections from the tunnel and restores that
// mark on their replies while a port forward exists; nothing otherwise,
// as only port forwards route by it (markedReplyRule).
func mangleContent(rules []parsedRule) [][]string {
	if !slices.ContainsFunc(rules, parsedRule.isPortForward) {
		return nil
	}
	return [][]string{fixedRule(fixedReplyMark, replyMarkRule), fixedRule(fixedReplyRestore, replyRestoreRule)}
}

// rateMatch is the match a rate-limited protection is rendered with.
type rateMatch int

const (
	notLimited    rateMatch = iota // off, or no module for it
	viaHashlimit                   // in place, per source where the rate says so
	viaLimitChain                  // through TUNNELDECK-LIMIT, one global rate
)

// options are the global protections to install, each as far as the
// kernel provides it, and whether reject rules can use REJECT.
type options struct {
	dropInvalid, mssClamp, reject bool
	synFlood, ping                rateMatch
}

func renderOptions(settings domain.FirewallSettings, caps capabilities) options {
	rate := func(on bool) rateMatch {
		switch {
		case !on:
			return notLimited
		case caps.has[extHashlimit]:
			return viaHashlimit
		case caps.has[extLimit]:
			return viaLimitChain
		}
		return notLimited
	}
	return options{
		dropInvalid: settings.DropInvalid,
		mssClamp:    settings.MSSClamp && caps.has[extTCPMSS],
		reject:      caps.has[extReject],
		synFlood:    rate(settings.SYNFloodProtection),
		ping:        rate(settings.PingLimit),
	}
}

// usesLimitChain reports whether the rate limits fall back to
// TUNNELDECK-LIMIT with caps, so that chain may exist.
func usesLimitChain(caps capabilities) bool {
	return !caps.has[extHashlimit] && caps.has[extLimit]
}

// parsedRule is a validated rule with its addresses parsed and its target
// classified against the host's current LAN addresses.
type parsedRule struct {
	domain.FirewallRule
	source      netip.Prefix // zero for "any"
	destination netip.Prefix // zero for a legacy host rule
	toHost      bool         // an inbound rule to the host itself
}

func parseRule(rule domain.FirewallRule, host []netip.Addr) parsedRule {
	p := parsedRule{FirewallRule: rule, toHost: rule.TargetsHost(host)}
	if rule.Source != "" {
		p.source, _ = domain.ParseIPv4Prefix(rule.Source)
	}
	if rule.Destination != "" {
		p.destination, _ = domain.ParseIPv4Prefix(rule.Destination)
	}
	return p
}

func (r parsedRule) isHostRule() bool { return r.toHost }

// isPortForward reports whether r forwards inbound traffic to another LAN
// device.
func (r parsedRule) isPortForward() bool { return r.Direction == domain.DirectionInbound && !r.toHost }

func (r parsedRule) isOutboundAccept() bool {
	return r.Direction == domain.DirectionOutbound && r.EffectiveAction() == domain.ActionAccept
}

// withTag tags a line of the rule with "tdrule:<id>".
func (r parsedRule) withTag(rule []string) []string { return tagged(ruleTagPrefix+r.ID, rule) }

// inputContent drops TCP to the web UI port before anything else, so no
// rule, not even one for every port, can open it to the tunnel.
func inputContent(p options, rules []parsedRule, reserved hostPorts) [][]string {
	var out [][]string
	if reserved.ui != 0 {
		out = append(out, fixedRule(fixedUIPort, tcpPortRule(reserved.ui, "DROP")))
	}
	if p.dropInvalid {
		out = append(out, fixedRule(fixedInvalid, ctRule(ctInvalid, "DROP")))
	}
	out = append(out, fixedRule(fixedEstablished, ctRule(ctEstablished, "ACCEPT")))
	out = append(out, floodRules(p, nil, "in")...)
	for _, rule := range rules {
		if !rule.isHostRule() {
			continue
		}
		for _, proto := range rule.Protocol.Protocols() {
			match := slices.Concat(protocolMatch(rule, proto), portMatch("--dport", rule.DestinationPort),
				icmpMatch(rule), prefixMatch("-s", rule.source))
			out = append(out, rule.withTag(append(match, actionTarget(rule.EffectiveAction(), proto, p.reject)...)))
		}
	}
	if reserved.remoteAccess != 0 {
		out = append(out, fixedRule(fixedRemoteAccess, tcpPortRule(reserved.remoteAccess, "ACCEPT")))
	}
	return append(out, []string{"-j", "DROP"})
}

func tcpPortRule(port int, target string) []string {
	return []string{"-p", "tcp", "--dport", strconv.Itoa(port), "-j", target}
}

func forwardContent(p options, rules []parsedRule, lan []netip.Prefix) [][]string {
	out := lanReturns(rules, lan)
	out = append(out, fixedRule(fixedKillSwitch, []string{"!", "-i", DeviceName, "!", "-o", DeviceName, "-j", "DROP"}))
	if p.dropInvalid {
		out = append(out, fixedRule(fixedInvalid, ctRule(ctInvalid, "DROP")))
	}
	if p.mssClamp {
		out = append(out, fixedRule(fixedMSSClamp, mssClampRule))
	}
	out = append(out, fixedRule(fixedEstablished, ctRule(ctEstablished, "ACCEPT")))
	out = append(out, floodRules(p, []string{"-i", DeviceName}, "fwd")...)
	for _, rule := range rules {
		switch {
		case rule.isPortForward():
			out = append(out, portForwardAccepts(rule)...)
		case rule.Direction == domain.DirectionOutbound:
			out = append(out, outboundRules(rule, p.reject)...)
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
			out = appendUnique(out, fixedRule(fixedLANReturn, ret))
		}
	}
	return out
}

// Matches of the packets the rate-limited protections count.
var (
	synMatch  = []string{"-p", "tcp", "--syn"}
	pingMatch = []string{"-p", "icmp", "--icmp-type", "echo-request"}
)

// floodRules are the SYN flood protection and the ping limit for traffic
// matching iface; name tells the hashlimit tables of each chain apart.
func floodRules(p options, iface []string, name string) [][]string {
	var out [][]string
	out = append(out, rateRules(p.synFlood, fixedSYNFlood, slices.Concat(iface, synMatch), synFloodRate, "td-syn-"+name)...)
	return append(out, rateRules(p.ping, fixedPingLimit, slices.Concat(iface, pingMatch), pingRate, "td-ping-"+name)...)
}

// rateRules drop the packets of match above rate: in place with the
// hashlimit match, or by sending them to TUNNELDECK-LIMIT, whose limit
// match counts the packets of both filter chains together. Nothing while
// omitted.
func rateRules(how rateMatch, purpose string, match []string, rate rateLimit, name string) [][]string {
	switch how {
	case viaHashlimit:
		return [][]string{fixedRule(purpose, slices.Concat(match, rate.hashlimitAbove(name), []string{"-j", "DROP"}))}
	case viaLimitChain:
		return [][]string{fixedRule(purpose, slices.Concat(match, []string{"-j", limitChain}))}
	}
	return nil
}

// limitContent lets the SYNs and pings within their global rate return to
// the chain that sent them and drops the rest; nil while no protection
// uses the limit match. Only SYNs and pings ever enter the chain.
func limitContent(p options) [][]string {
	var out [][]string
	if p.synFlood == viaLimitChain {
		out = append(out, fixedRule(fixedSYNFlood, slices.Concat([]string{"-p", "tcp"}, synFloodRate.limitWithin(), []string{"-j", "RETURN"})))
	}
	if p.ping == viaLimitChain {
		out = append(out, fixedRule(fixedPingLimit, slices.Concat([]string{"-p", "icmp"}, pingRate.limitWithin(), []string{"-j", "RETURN"})))
	}
	if out == nil {
		return nil
	}
	return append(out, []string{"-j", "DROP"})
}

// portForwardAccepts accepts DNATed traffic to the target, matching the
// destination port after translation.
func portForwardAccepts(rule parsedRule) [][]string {
	var out [][]string
	for _, proto := range rule.Protocol.Protocols() {
		match := slices.Concat([]string{"-i", DeviceName, "-d", rule.destination.String()}, protocolMatch(rule, proto),
			portMatch("--dport", rule.DestinationPort), prefixMatch("-s", rule.source))
		out = append(out, rule.withTag(slices.Concat(match, ctMatch(ctDNAT), []string{"-j", "ACCEPT"})))
	}
	return out
}

func outboundRules(rule parsedRule, reject bool) [][]string {
	var out [][]string
	for _, proto := range rule.Protocol.Protocols() {
		match := slices.Concat([]string{"-o", DeviceName, "-s", rule.source.String()}, prefixMatch("-d", rule.destination),
			protocolMatch(rule, proto), portMatch("--dport", rule.DestinationPort), icmpMatch(rule))
		out = append(out, rule.withTag(append(match, actionTarget(rule.EffectiveAction(), proto, reject)...)))
	}
	return out
}

// preroutingContent translates port forwards. While a forward covers every
// TCP port, the host's own ports return first, so they are never
// forwarded.
func preroutingContent(rules []parsedRule, reserved hostPorts) [][]string {
	var out [][]string
	if forwardsEveryTCPPort(rules) {
		for _, port := range []int{reserved.ui, reserved.remoteAccess} {
			if port != 0 {
				out = append(out, fixedRule(fixedHostPort, tcpPortRule(port, "RETURN")))
			}
		}
	}
	for _, rule := range rules {
		if !rule.isPortForward() {
			continue
		}
		for _, proto := range rule.Protocol.Protocols() {
			match := slices.Concat(protocolMatch(rule, proto), portMatch("--dport", rule.PublicPorts()),
				prefixMatch("-s", rule.source))
			out = append(out, rule.withTag(append(match, "-j", "DNAT", "--to-destination", dnatTarget(rule))))
		}
	}
	return out
}

func forwardsEveryTCPPort(rules []parsedRule) bool {
	return slices.ContainsFunc(rules, func(rule parsedRule) bool {
		return rule.isPortForward() && rule.DestinationPort.IsZero() &&
			slices.Contains(rule.Protocol.Protocols(), domain.ProtocolTCP)
	})
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
// keep the source address, and outbound traffic on the tunnel except the
// traffic of localNetworks, which keeps its addresses in the tunnel.
func postroutingContent(rules []parsedRule, localNetworks []netip.Prefix) [][]string {
	var out [][]string
	for _, network := range localNetworks {
		out = append(out, fixedRule(fixedLocalNetwork, []string{"-o", DeviceName, "-s", network.String(), "-j", "RETURN"}))
	}
	for _, rule := range rules {
		switch {
		case rule.isPortForward() && !rule.KeepSourceAddress:
			for _, proto := range rule.Protocol.Protocols() {
				match := slices.Concat([]string{"!", "-o", DeviceName, "-d", rule.destination.String()},
					protocolMatch(rule, proto), portMatch("--dport", rule.DestinationPort))
				out = append(out, rule.withTag(slices.Concat(match, ctMatch(ctDNAT), []string{"-j", "MASQUERADE"})))
			}
		case rule.isOutboundAccept():
			masquerade := slices.Concat([]string{"-o", DeviceName, "-s", rule.source.String()},
				prefixMatch("-d", rule.destination), []string{"-j", "MASQUERADE"})
			out = appendUnique(out, rule.withTag(masquerade))
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

// actionTarget is the target of action; reject is DROP without the REJECT
// target (reject false).
func actionTarget(action domain.FirewallAction, proto domain.FirewallProtocol, reject bool) []string {
	switch {
	case action == domain.ActionDrop, action == domain.ActionReject && !reject:
		return []string{"-j", "DROP"}
	case action == domain.ActionReject && proto == domain.ProtocolTCP:
		return []string{"-j", "REJECT", "--reject-with", "tcp-reset"}
	case action == domain.ActionReject:
		return []string{"-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	}
	return []string{"-j", "ACCEPT"}
}

// appendUnique appends item unless list holds the same line already; tags
// are ignored, so a line shared by several rules keeps the first tag.
func appendUnique(list [][]string, item []string) [][]string {
	for _, existing := range list {
		if slices.Equal(untagged(existing), untagged(item)) {
			return list
		}
	}
	return append(list, item)
}
