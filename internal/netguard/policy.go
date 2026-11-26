package netguard

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
)

// Policy rule priorities. TunnelDeck owns 7100–7194; lower numbers are
// evaluated first. All rules at one priority lead to the same table, so
// their order among each other does not matter.
const (
	// lanExclusionPriority keeps traffic of policy-routed sources to the
	// LAN, and traffic from the host's own addresses, in the main table.
	lanExclusionPriority = 7100
	// remoteNetworkPriority routes the host's traffic to the networks
	// behind the VPN that the profile names (SPEC §17): "to <network>
	// lookup 7194". Remote networks never overlap the LAN, so the
	// exclusions above need no exception for them.
	remoteNetworkPriority = 7180
	// outboundPriority routes outbound rules: "from <source> to
	// <destination> lookup 7194".
	outboundPriority = 7190
	// replyPriority routes replies of port-forward targets into the tunnel:
	// "from <target> ipproto <p> [sport <destination port>] lookup 7194".
	replyPriority = 7191
	// vpnReplyPriority routes replies from the VPN address: "from <vpn-ip>
	// lookup 7194".
	vpnReplyPriority = 7194
)

const mainTable = "main"

// ownedPriorities are the priorities whose rules syncPolicyRules manages.
var ownedPriorities = []int{lanExclusionPriority, remoteNetworkPriority, outboundPriority, replyPriority}

// ipProtocolNames maps the names ip rule show may print to numbers.
var ipProtocolNames = map[string]int{"tcp": 6, "udp": 17, "icmp": 1, "esp": 50, "gre": 47}

var anyAddress = netip.MustParsePrefix("0.0.0.0/0")

// policyRule is one "ip rule". It is comparable; sport is normalised so
// that equal rules compare equal.
type policyRule struct {
	priority int
	from, to netip.Prefix
	ipproto  int // 0 matches every protocol
	sport    domain.PortRange
	table    string
}

func newPolicyRule(priority int, from, to netip.Prefix, table string) policyRule {
	return policyRule{priority: priority, from: from, to: to, table: table}
}

func (r policyRule) addArgs() []string {
	args := []string{"rule", "add", "from", r.from.String(), "to", r.to.String()}
	if r.ipproto != 0 {
		args = append(args, "ipproto", strconv.Itoa(r.ipproto))
	}
	if !r.sport.IsZero() {
		args = append(args, "sport", r.sport.String())
	}
	return append(args, "lookup", r.table, "priority", strconv.Itoa(r.priority))
}

// listedRule is a policy rule as ip rule show printed it.
type listedRule struct {
	priority int
	tokens   []string // the selectors and action after "<priority>:"
}

// policyListing is the parsed output of "ip -4 rule show".
type policyListing struct {
	owned      []listedRule // rules at ownedPriorities
	vpnSources []string     // "from" of each rule at vpnReplyPriority
}

func (g *Guard) listPolicyRules(ctx context.Context) (policyListing, error) {
	out, err := g.ip(ctx, "-4", "rule", "show")
	if err != nil {
		return policyListing{}, err
	}
	return parsePolicyListing(out), nil
}

func parsePolicyListing(out string) policyListing {
	var listing policyListing
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		priority, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		switch {
		case err != nil:
		case priority == vpnReplyPriority:
			if source := valueAfter(fields, "from"); source != "" {
				listing.vpnSources = append(listing.vpnSources, source)
			}
		case slices.Contains(ownedPriorities, priority):
			listing.owned = append(listing.owned, listedRule{priority: priority, tokens: fields[1:]})
		}
	}
	return listing
}

// parse reads the selectors netguard writes; ok is false for anything
// else, which then never matches a wanted rule and is deleted.
func (l listedRule) parse() (policyRule, bool) {
	from, okFrom := parseRuleAddress(valueAfter(l.tokens, "from"))
	to, okTo := parseRuleAddress(valueAfter(l.tokens, "to"))
	table := valueAfter(l.tokens, "lookup")
	if table == "254" {
		table = mainTable
	}
	rule := policyRule{priority: l.priority, from: from, to: to, table: table}
	okProto, okPort := true, true
	if p := valueAfter(l.tokens, "ipproto"); p != "" {
		rule.ipproto, okProto = parseIPProtocol(p)
	}
	if s := valueAfter(l.tokens, "sport"); s != "" {
		rule.sport, okPort = parsePortRange(s)
	}
	return rule, okFrom && okTo && okProto && okPort && table != ""
}

// parseRuleAddress reads a from/to selector: absent and "all" are any.
func parseRuleAddress(s string) (netip.Prefix, bool) {
	if s == "" || s == "all" {
		return anyAddress, true
	}
	prefix, err := domain.ParseIPv4Prefix(s)
	return prefix, err == nil
}

func parseIPProtocol(s string) (int, bool) {
	if n, ok := ipProtocolNames[s]; ok {
		return n, true
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func parsePortRange(s string) (domain.PortRange, bool) {
	first, last, isRange := strings.Cut(s, "-")
	from, err := strconv.Atoi(first)
	if err != nil {
		return domain.PortRange{}, false
	}
	if !isRange {
		return normalisedPorts(domain.SinglePort(from)), true
	}
	to, err := strconv.Atoi(last)
	return normalisedPorts(domain.PortRange{From: from, To: to}), err == nil
}

func normalisedPorts(p domain.PortRange) domain.PortRange {
	return domain.PortRange{From: p.From, To: p.Last()}
}

// syncPolicyRules makes the rules at ownedPriorities equal to want: stale
// rules are deleted first, routing rules before LAN exclusions, then the
// missing ones are added in want order, exclusions first. Traffic is thus
// never sent into the tunnel without its exclusions, and while a rule is
// missing its traffic falls back to the main table, where the kill switch
// drops it.
func (g *Guard) syncPolicyRules(ctx context.Context, owned []listedRule, want []policyRule) error {
	present := make([]bool, len(want))
	var stale []listedRule
	for _, listed := range owned {
		rule, ok := listed.parse()
		i := indexOfMissing(want, present, rule)
		if !ok || i < 0 {
			stale = append(stale, listed)
			continue
		}
		present[i] = true
	}
	slices.SortStableFunc(stale, func(a, b listedRule) int { return b.priority - a.priority })
	for _, listed := range stale {
		args := append([]string{"rule", "del", "priority", strconv.Itoa(listed.priority)}, listed.tokens...)
		if _, err := g.ip(ctx, args...); err != nil && !isAbsent(err) {
			return err
		}
	}
	for i, rule := range want {
		if present[i] {
			continue
		}
		if _, err := g.ip(ctx, rule.addArgs()...); err != nil {
			return err
		}
	}
	return nil
}

func indexOfMissing(want []policyRule, present []bool, rule policyRule) int {
	for i := range want {
		if !present[i] && want[i] == rule {
			return i
		}
	}
	return -1
}

// mayNeedPolicyRules reports whether firewall may route traffic besides
// the replies from the VPN address: it has an enabled accepting outbound
// rule, or an enabled accepting inbound rule to an address, which is a
// port forward unless the address is the host's own (wantedPolicyRules
// decides with the LAN).
func mayNeedPolicyRules(firewall domain.Firewall) bool {
	for _, rule := range firewall.Rules {
		if rule.Enabled && rule.EffectiveAction() == domain.ActionAccept && !rule.IsLegacyHost() {
			return true
		}
	}
	return false
}

// wantedPolicyRules lists the policy rules of firewall (SPEC §16.1):
// outbound rules route their traffic into table 7194; replies of port
// forwards follow them, because the target answers with the source of
// the original destination port; LAN traffic of all these sources and
// traffic from the host's own addresses stays in the main table.
func wantedPolicyRules(firewall domain.Firewall, lan []lanAddress) []policyRule {
	var exclusions, routes []policyRule
	var sources []netip.Prefix
	host := hostAddresses(lan)
	for _, rule := range firewall.Rules {
		if !rule.Enabled {
			continue
		}
		parsed := parseRule(rule, host)
		switch {
		case parsed.isOutboundAccept():
			sources = appendPrefix(sources, parsed.source)
			routes = appendPolicyRule(routes, newPolicyRule(outboundPriority, parsed.source, parsed.destination, routingTable))
		case parsed.isPortForward():
			sources = appendPrefix(sources, parsed.destination)
			for _, rr := range replyRules(parsed) {
				routes = appendPolicyRule(routes, rr)
			}
		}
	}
	for _, addr := range lan {
		host := netip.PrefixFrom(addr.prefix.Addr(), 32)
		if coveredBy(host, sources) {
			exclusions = appendPolicyRule(exclusions, newPolicyRule(lanExclusionPriority, host, anyAddress, mainTable))
		}
	}
	for _, source := range sources {
		for _, subnet := range subnets(lan) {
			exclusions = appendPolicyRule(exclusions, newPolicyRule(lanExclusionPriority, source, subnet, mainTable))
		}
	}
	return append(exclusions, routes...)
}

// policyRulesFor lists every policy rule of a routed tunnel: those of
// firewall followed by one rule per remote network. A remote network that
// overlaps the LAN is refused, as routing it into the tunnel would cut the
// host off from that part of its LAN.
func policyRulesFor(firewall domain.Firewall, remoteNetworks []netip.Prefix, lan []lanAddress) ([]policyRule, error) {
	for i, network := range remoteNetworks {
		for _, addr := range lan {
			if network.Overlaps(addr.subnet()) {
				return nil, remoteNetworkError(i, "remote_network_overlaps_lan",
					"overlaps a LAN subnet of this device: "+describeLAN(lan), lan)
			}
		}
	}
	rules := wantedPolicyRules(firewall, lan)
	for _, network := range remoteNetworks {
		rules = appendPolicyRule(rules, newPolicyRule(remoteNetworkPriority, anyAddress, network, routingTable))
	}
	return rules, nil
}

// checkRemoteNetworks accepts IPv4 networks in canonical form that do not
// cover every address.
func checkRemoteNetworks(networks []netip.Prefix) error {
	for i, network := range networks {
		switch {
		case !network.Addr().Is4():
			return remoteNetworkError(i, "remote_network_not_cidr", "must be an IPv4 network", nil)
		case network != network.Masked():
			return remoteNetworkError(i, "remote_network_not_canonical", "must be written as the network address with its prefix length", nil)
		case network.Bits() == 0:
			return remoteNetworkError(i, "remote_network_everything", "must not cover every address", nil)
		}
	}
	return nil
}

// remoteNetworkError reports a problem of the remote network at index with
// the codes of the profile setting: the 1-based "entry" and, when lan is
// given, its "subnets".
func remoteNetworkError(index int, code, message string, lan []lanAddress) *domain.ValidationError {
	entry := strconv.Itoa(index + 1)
	issue := domain.Issue(code, "entry", entry)
	if len(lan) > 0 {
		listed := make([]string, 0, len(lan))
		for _, subnet := range subnets(lan) {
			listed = append(listed, subnet.String())
		}
		issue.Params["subnets"] = strings.Join(listed, ", ")
	}
	return domain.NewFieldError("remoteNetworks", issue, "entry "+entry+" "+message)
}

func replyRules(rule parsedRule) []policyRule {
	var out []policyRule
	for _, proto := range rule.Protocol.Protocols() {
		reply := newPolicyRule(replyPriority, rule.destination, anyAddress, routingTable)
		reply.ipproto = ipProtocolNumbers[proto]
		if proto.HasPorts() {
			reply.sport = normalisedPorts(rule.DestinationPort)
		}
		out = append(out, reply)
	}
	return out
}

func coveredBy(host netip.Prefix, sources []netip.Prefix) bool {
	for _, source := range sources {
		if source.Contains(host.Addr()) {
			return true
		}
	}
	return false
}

func appendPrefix(list []netip.Prefix, p netip.Prefix) []netip.Prefix {
	if slices.Contains(list, p) {
		return list
	}
	return append(list, p)
}

func appendPolicyRule(list []policyRule, r policyRule) []policyRule {
	if slices.Contains(list, r) {
		return list
	}
	return append(list, r)
}
