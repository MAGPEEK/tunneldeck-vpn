package netguard

import (
	"fmt"
	"slices"
	"strings"

	"tunneldeck/internal/domain"
)

const (
	legacy    = "iptables-legacy -w "
	natPrefix = "iptables-legacy -w -t nat "
	uiPort    = 8080
)

// testFirewall holds the stage-1 shaped rules: two enabled host rules and
// a disabled one; every global protection is off to keep sequences short.
var testFirewall = domain.Firewall{Rules: []domain.FirewallRule{
	hostAccess("ssh", domain.ProtocolTCP, 22, "", true),
	hostAccess("wg", domain.ProtocolUDP, 51820, "192.168.1.0/24", true),
	hostAccess("web", domain.ProtocolTCP, 80, "", false),
}}

// hostAccess returns an accepting inbound rule to the host on one port,
// shaped like a migrated stage-1 host-access rule.
func hostAccess(id string, proto domain.FirewallProtocol, port int, source string, enabled bool) domain.FirewallRule {
	return domain.FirewallRule{
		ID: id, Name: fmt.Sprintf("Host port %d/%s", port, proto), Direction: domain.DirectionInbound,
		Action: domain.ActionAccept, Protocol: proto, Source: source,
		Destination: domain.FirewallDestination{Kind: domain.DestinationHost}, DestinationPort: domain.SinglePort(port),
		Enabled: enabled,
	}
}

func rulesOnly(rules ...domain.FirewallRule) domain.Firewall {
	return domain.Firewall{Rules: rules}
}

// Rule builders; each returns a valid, enabled rule.
func hostRule(proto domain.FirewallProtocol, ports domain.PortRange) domain.FirewallRule {
	return domain.FirewallRule{
		Name: "host", Direction: domain.DirectionInbound, Protocol: proto,
		Destination: domain.FirewallDestination{Kind: domain.DestinationHost}, DestinationPort: ports, Enabled: true,
	}
}

func portForward(proto domain.FirewallProtocol, target string, ports domain.PortRange) domain.FirewallRule {
	return domain.FirewallRule{
		Name: "forward", Direction: domain.DirectionInbound, Protocol: proto,
		Destination:     domain.FirewallDestination{Kind: domain.DestinationAddress, CIDR: target},
		DestinationPort: ports, Enabled: true,
	}
}

func outboundRule(proto domain.FirewallProtocol, source, destination string) domain.FirewallRule {
	return domain.FirewallRule{
		Name: "outbound", Direction: domain.DirectionOutbound, Protocol: proto, Source: source,
		Destination: domain.FirewallDestination{Kind: domain.DestinationAddress, CIDR: destination}, Enabled: true,
	}
}

func changed(r domain.FirewallRule, change func(*domain.FirewallRule)) domain.FirewallRule {
	change(&r)
	return r
}

func ports(from, to int) domain.PortRange { return domain.PortRange{From: from, To: to} }

// Content lines as appended (without "-A <chain> ").
const (
	established    = "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
	invalidDrop    = "-m conntrack --ctstate INVALID -j DROP"
	killSwitchDrop = "! -i tdvpn0 ! -o tdvpn0 -j DROP"
	dropAll        = "-j DROP"
	// uiPortDrop keeps the web UI port (uiPort) closed to the tunnel.
	uiPortDrop = "-p tcp --dport 8080 -j DROP"
)

// inputWith is TUNNELDECK-INPUT with every protection off.
func inputWith(rules ...string) []string {
	return slices.Concat([]string{uiPortDrop, established}, rules, []string{dropAll})
}

// forwardWith is TUNNELDECK-FORWARD with every protection off and no LAN
// returns.
func forwardWith(rules ...string) []string {
	return slices.Concat([]string{killSwitchDrop, established}, rules, []string{dropAll})
}

// Content of the rules in testFirewall.
var (
	testInput   = inputWith("-p tcp --dport 22 -j ACCEPT", "-p udp --dport 51820 -s 192.168.1.0/24 -j ACCEPT")
	testForward = forwardWith()
)

// installedState describes the chains scriptState lists: how many old
// rules each chain holds (a sealed chain's last one is DROP) and the
// FORWARD jump lines after the two tunnel jumps.
type installedState struct {
	input, forward, prerouting, postrouting int
	forwardJumps                            []string
}

// scriptInstalled lists the state an installation of testFirewall leaves
// behind, with one rule per filter chain and empty nat chains.
func scriptInstalled(f *fakeRunner) { scriptState(f, installedState{input: 1, forward: 1}) }

func scriptState(f *fakeRunner, s installedState) {
	f.on(legacy+"-S TUNNELDECK-INPUT", ok(chainListing(inputChain, s.input, true))).
		on(legacy+"-S INPUT", ok("-P INPUT ACCEPT\n-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT\n-A INPUT -i lo -j ACCEPT\n")).
		on(legacy+"-S TUNNELDECK-FORWARD", ok(chainListing(forwardChain, s.forward, true))).
		on(legacy+"-S FORWARD", ok("-P FORWARD ACCEPT\n-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD\n"+
			"-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD\n"+lines(s.forwardJumps)+"-A FORWARD -j DOCKER-USER\n")).
		on(natPrefix+"-S TUNNELDECK-PREROUTING", ok(chainListing(preroutingChain, s.prerouting, false))).
		on(natPrefix+"-S PREROUTING", ok("-P PREROUTING ACCEPT\n-A PREROUTING -i tdvpn0 -j TUNNELDECK-PREROUTING\n")).
		on(natPrefix+"-S TUNNELDECK-POSTROUTING", ok(chainListing(postroutingChain, s.postrouting, false))).
		on(natPrefix+"-S POSTROUTING", ok("-P POSTROUTING ACCEPT\n-A POSTROUTING -j TUNNELDECK-POSTROUTING\n"))
}

func chainListing(chain string, rules int, sealed bool) string {
	listing := "-N " + chain + "\n"
	for i := range rules {
		if sealed && i == rules-1 {
			listing += "-A " + chain + " -j DROP\n"
		} else {
			listing += "-A " + chain + " -j RETURN\n"
		}
	}
	return listing
}

func lines(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return strings.Join(list, "\n") + "\n"
}

// scriptFresh lists a host without any of netguard's chains or jumps.
func scriptFresh(f *fakeRunner) {
	f.on(legacy+"-S TUNNELDECK-INPUT", fail(noChain)).
		on(legacy+"-S TUNNELDECK-FORWARD", fail(noChain)).
		on(legacy+"-S INPUT", ok("-P INPUT ACCEPT\n")).
		on(legacy+"-S FORWARD", ok("-P FORWARD ACCEPT\n")).
		on(legacy+"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", fail(noTarget)).
		on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(natPrefix+"-S TUNNELDECK-PREROUTING", fail(noChain)).
		on(natPrefix+"-S TUNNELDECK-POSTROUTING", fail(noChain)).
		on(natPrefix+"-S PREROUTING", ok("-P PREROUTING ACCEPT\n")).
		on(natPrefix+"-S POSTROUTING", ok("-P POSTROUTING ACCEPT\n")).
		on(natPrefix+"-C PREROUTING -i tdvpn0 -j TUNNELDECK-PREROUTING", fail(noTarget)).
		on(natPrefix+"-C POSTROUTING -j TUNNELDECK-POSTROUTING", fail(noTarget))
}

// freshCalls is a fresh installation with the given chain contents.
func freshCalls(input, forward, prerouting, postrouting []string) []string {
	return slices.Concat(detectLegacy, []string{addrShow},
		prefixed(legacy,
			"-S TUNNELDECK-INPUT",
			"-N TUNNELDECK-INPUT",
			"-A TUNNELDECK-INPUT -j DROP",
			"-S INPUT",
			"-I INPUT 1 -i tdvpn0 -j DROP",
			"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
			"-I INPUT 1 -i tdvpn0 -j TUNNELDECK-INPUT",
			"-D INPUT -i tdvpn0 -j DROP"),
		appends(legacy, inputChain, input),
		prefixed(legacy,
			"-D TUNNELDECK-INPUT 1",
			"-S TUNNELDECK-FORWARD",
			"-N TUNNELDECK-FORWARD",
			"-A TUNNELDECK-FORWARD -j DROP",
			"-S FORWARD",
			"-I FORWARD 1 -i tdvpn0 -j DROP",
			"-I FORWARD 1 -o tdvpn0 -j DROP",
			"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
			"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
			"-I FORWARD 1 -o tdvpn0 -j TUNNELDECK-FORWARD",
			"-I FORWARD 1 -i tdvpn0 -j TUNNELDECK-FORWARD",
			"-D FORWARD -i tdvpn0 -j DROP",
			"-D FORWARD -o tdvpn0 -j DROP"),
		appends(legacy, forwardChain, forward),
		prefixed(legacy, "-D TUNNELDECK-FORWARD 1"),
		prefixed(natPrefix,
			"-S TUNNELDECK-PREROUTING",
			"-N TUNNELDECK-PREROUTING",
			"-S PREROUTING",
			"-C PREROUTING -i tdvpn0 -j TUNNELDECK-PREROUTING",
			"-I PREROUTING 1 -i tdvpn0 -j TUNNELDECK-PREROUTING"),
		appends(natPrefix, preroutingChain, prerouting),
		prefixed(natPrefix,
			"-S TUNNELDECK-POSTROUTING",
			"-N TUNNELDECK-POSTROUTING",
			"-S POSTROUTING",
			"-C POSTROUTING -j TUNNELDECK-POSTROUTING",
			"-I POSTROUTING 1 -j TUNNELDECK-POSTROUTING"),
		appends(natPrefix, postroutingChain, postrouting),
	)
}

// refillCalls is the refill of a chain whose jumps are in place: listing,
// appends, then deleting the old rules.
func refillCalls(prefix, chain, parent string, old int, content []string) []string {
	calls := slices.Concat(prefixed(prefix, "-S "+chain, "-S "+parent), appends(prefix, chain, content))
	for range old {
		calls = append(calls, prefix+"-D "+chain+" 1")
	}
	return calls
}

// reinstallCalls is a re-installation over scriptState(s) by a Guard whose
// backend is known already.
func reinstallCalls(s installedState, input, forward, prerouting, postrouting []string) []string {
	return slices.Concat([]string{addrShow},
		refillCalls(legacy, inputChain, "INPUT", s.input, input),
		refillCalls(legacy, forwardChain, "FORWARD", s.forward, forward),
		refillCalls(natPrefix, preroutingChain, "PREROUTING", s.prerouting, prerouting),
		refillCalls(natPrefix, postroutingChain, "POSTROUTING", s.postrouting, postrouting))
}

func appends(prefix, chain string, content []string) []string {
	calls := make([]string, len(content))
	for i, rule := range content {
		calls[i] = prefix + "-A " + chain + " " + rule
	}
	return calls
}
