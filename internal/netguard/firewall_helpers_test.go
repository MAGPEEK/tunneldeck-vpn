package netguard

import (
	"fmt"
	"slices"
	"strings"

	"tunneldeck/internal/domain"
)

const (
	legacy       = "iptables-legacy -w "
	natPrefix    = "iptables-legacy -w -t nat "
	manglePrefix = "iptables-legacy -w -t mangle "
	uiPort       = 8080
	// testHostAddress is the host's LAN address in lanListing.
	testHostAddress = "192.168.2.10"
)

// testFirewall holds the stage-1 shaped rules: two enabled host rules and
// a disabled one; every global protection is off to keep sequences short.
var testFirewall = domain.Firewall{Rules: []domain.FirewallRule{
	hostAccess("ssh", domain.ProtocolTCP, 22, "", true),
	hostAccess("wg", domain.ProtocolUDP, 51820, "192.168.1.0/24", true),
	hostAccess("web", domain.ProtocolTCP, 80, "", false),
}}

// hostAccess returns an accepting inbound rule to the host on one port,
// shaped like a migrated stage-1 host-access rule: a legacy host rule
// without an address.
func hostAccess(id string, proto domain.FirewallProtocol, port int, source string, enabled bool) domain.FirewallRule {
	return domain.LegacyHostRule(domain.FirewallRule{
		ID: id, Name: fmt.Sprintf("Host port %d/%s", port, proto), Direction: domain.DirectionInbound,
		Action: domain.ActionAccept, Protocol: proto, Source: source,
		DestinationPort: domain.SinglePort(port), Enabled: enabled,
	})
}

// rulesOnly is a firewall with every protection off; rules without an ID
// get "r<position>", starting at r1, so their lines carry "tdrule:r<n>".
func rulesOnly(rules ...domain.FirewallRule) domain.Firewall {
	for i := range rules {
		if rules[i].ID == "" {
			rules[i].ID = fmt.Sprintf("r%d", i+1)
		}
	}
	return domain.Firewall{Rules: rules}
}

// tagLine inserts the comment match with tag before the target of line,
// as netguard renders it.
func tagLine(tag, line string) string {
	before, after, found := strings.Cut(line, "-j ")
	if !found {
		return line + " -m comment --comment " + tag
	}
	return before + "-m comment --comment " + tag + " -j " + after
}

// onRule tags line with "tdrule:r<n>", the rule at position n of rulesOnly.
func onRule(n int, line string) string { return tagLine(fmt.Sprintf("tdrule:r%d", n), line) }

// Rule builders; each returns a valid, enabled rule.
func hostRule(proto domain.FirewallProtocol, ports domain.PortRange) domain.FirewallRule {
	return domain.FirewallRule{
		Name: "host", Direction: domain.DirectionInbound, Protocol: proto,
		Destination: testHostAddress, DestinationPort: ports, Enabled: true,
	}
}

func portForward(proto domain.FirewallProtocol, target string, ports domain.PortRange) domain.FirewallRule {
	return domain.FirewallRule{
		Name: "forward", Direction: domain.DirectionInbound, Protocol: proto,
		Destination:     target,
		DestinationPort: ports, Enabled: true,
	}
}

func outboundRule(proto domain.FirewallProtocol, source, destination string) domain.FirewallRule {
	return domain.FirewallRule{
		Name: "outbound", Direction: domain.DirectionOutbound, Protocol: proto, Source: source,
		Destination: destination, Enabled: true,
	}
}

func changed(r domain.FirewallRule, change func(*domain.FirewallRule)) domain.FirewallRule {
	change(&r)
	return r
}

func ports(from, to int) domain.PortRange { return domain.PortRange{From: from, To: to} }

// Content lines as appended (without "-A <chain> ").
const (
	established    = "-m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment tdfixed:established -j ACCEPT"
	invalidDrop    = "-m conntrack --ctstate INVALID -m comment --comment tdfixed:invalid -j DROP"
	killSwitchDrop = "! -i tdvpn0 ! -o tdvpn0 -m comment --comment tdfixed:kill-switch -j DROP"
	dropAll        = "-j DROP"
	// uiPortDrop keeps the web UI port (uiPort) closed to the tunnel.
	uiPortDrop = "-p tcp --dport 8080 -m comment --comment tdfixed:ui-port -j DROP"
	// replyMarkLine and replyRestoreLine fill TUNNELDECK-MANGLE-PRE while a
	// port forward exists.
	replyMarkLine    = "-i tdvpn0 -m comment --comment tdfixed:reply-mark -j CONNMARK --set-mark 0x7194/0xffff"
	replyRestoreLine = "! -i tdvpn0 -m connmark --mark 0x7194/0xffff -m comment --comment tdfixed:reply-restore " +
		"-j CONNMARK --restore-mark --nfmask 0xffff --ctmask 0xffff"
)

// mangleFor is the content of TUNNELDECK-MANGLE-PRE next to the nat
// PREROUTING content prerouting: the reply marks while a port forward
// translates anything.
func mangleFor(prerouting []string) []string {
	if !slices.ContainsFunc(prerouting, func(line string) bool { return strings.Contains(line, "-j DNAT") }) {
		return nil
	}
	return []string{replyMarkLine, replyRestoreLine}
}

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
	testInput = inputWith("-p tcp --dport 22 -m comment --comment tdrule:ssh -j ACCEPT",
		"-p udp --dport 51820 -s 192.168.1.0/24 -m comment --comment tdrule:wg -j ACCEPT")
	testForward = forwardWith()
)

// installedState describes the chains scriptState lists: how many old
// rules each chain holds (a sealed chain's last one is DROP) and the
// FORWARD jump lines after the two tunnel jumps.
type installedState struct {
	input, forward, prerouting, postrouting, mangle int
	forwardJumps                                    []string
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
		on(natPrefix+"-S POSTROUTING", ok("-P POSTROUTING ACCEPT\n-A POSTROUTING -j TUNNELDECK-POSTROUTING\n")).
		on(manglePrefix+"-S TUNNELDECK-MANGLE-PRE", ok(chainListing(mangleChain, s.mangle, false))).
		on(manglePrefix+"-S PREROUTING", ok("-P PREROUTING ACCEPT\n-A PREROUTING -j TUNNELDECK-MANGLE-PRE\n"))
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
		on(natPrefix+"-C POSTROUTING -j TUNNELDECK-POSTROUTING", fail(noTarget)).
		on(manglePrefix+"-S TUNNELDECK-MANGLE-PRE", fail(noChain)).
		on(manglePrefix+"-S PREROUTING", ok("-P PREROUTING ACCEPT\n")).
		on(manglePrefix+"-C PREROUTING -j TUNNELDECK-MANGLE-PRE", fail(noTarget))
}

// freshCalls is a fresh installation with the given chain contents.
func freshCalls(input, forward, prerouting, postrouting []string) []string {
	return slices.Concat(detectInstall, []string{addrShow},
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
		freshMangleCalls(mangleFor(prerouting)),
	)
}

// freshMangleCalls create TUNNELDECK-MANGLE-PRE with its jump at the top
// of mangle PREROUTING, then fill it with content.
func freshMangleCalls(content []string) []string {
	return slices.Concat(
		prefixed(manglePrefix,
			"-S TUNNELDECK-MANGLE-PRE",
			"-N TUNNELDECK-MANGLE-PRE",
			"-S PREROUTING",
			"-C PREROUTING -j TUNNELDECK-MANGLE-PRE",
			"-I PREROUTING 1 -j TUNNELDECK-MANGLE-PRE"),
		appends(manglePrefix, mangleChain, content))
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
		refillCalls(natPrefix, postroutingChain, "POSTROUTING", s.postrouting, postrouting),
		refillCalls(manglePrefix, mangleChain, "PREROUTING", s.mangle, mangleFor(prerouting)))
}

func appends(prefix, chain string, content []string) []string {
	calls := make([]string, len(content))
	for i, rule := range content {
		calls[i] = prefix + "-A " + chain + " " + rule
	}
	return calls
}

func withDefaultSettings(f domain.Firewall) domain.Firewall {
	f.FirewallSettings = domain.DefaultFirewallSettings()
	return f
}

// capsWithout is a kernel with every optional extension but missing.
func capsWithout(missing ...extension) capabilities {
	has := make(map[extension]bool, len(extensionProbes))
	for _, probe := range extensionProbes {
		has[probe.ext] = !slices.Contains(missing, probe.ext)
	}
	return capabilities{backend: "iptables-legacy", has: has}
}

// fullSupport is a kernel with every optional extension; limitOnlySupport
// lacks hashlimit and TCPMSS (capsWithout(extHashlimit, extTCPMSS)).
var (
	fullSupport = domain.ProtectionSupport{
		SYNFlood: domain.ProtectionFull, Ping: domain.ProtectionFull, MSSClamp: domain.ProtectionFull, RuleCounters: true,
	}
	limitOnlySupport = domain.ProtectionSupport{
		SYNFlood: domain.ProtectionGlobal, Ping: domain.ProtectionFull, MSSClamp: domain.ProtectionNone, RuleCounters: true,
	}
)
