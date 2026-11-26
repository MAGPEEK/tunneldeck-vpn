//go:build integration && linux

// Integration test against real iptables and ip. It changes the firewall
// and routing of its network namespace, so run it only in a throwaway
// container with NET_ADMIN, from the repository root:
//
//	docker run --rm --cap-add NET_ADMIN -v "$PWD":/src -w /src golang:1.27 \
//	  sh -c 'apt-get update -qq && apt-get install -y -qq iptables iproute2 >/dev/null && go test -tags integration -run Integration -v ./internal/netguard/'

package netguard

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

func TestIntegrationFirewallAndRouting(t *testing.T) {
	ctx := context.Background()
	runner := ExecRunner{}
	mustRun(t, runner, "ip", "link", "add", DeviceName, "type", "dummy")
	t.Cleanup(func() { _, _ = runner.Run(ctx, "ip", "link", "del", DeviceName) })
	mustRun(t, runner, "ip", "link", "set", DeviceName, "up")
	mainBefore := mustRun(t, runner, "ip", "route", "show", "table", "main")
	rulesBefore := mustRun(t, runner, "ip", "-4", "rule", "show")

	g := New(runner)
	lan, err := g.LANSubnets(ctx)
	if err != nil || len(lan) == 0 {
		t.Fatalf("LANSubnets = %v, %v; want the container's network", lan, err)
	}
	neighbours, err := g.LANNeighbours(ctx)
	if err != nil {
		t.Fatalf("LANNeighbours: %v", err)
	}
	for _, device := range neighbours {
		if !device.Address.Is4() || device.MAC == "" || device.State == "" {
			t.Errorf("neighbour %+v lacks an address, MAC or state", device)
		}
	}
	target := lanTarget(t, lan[0])
	firewall := integrationFirewall(target)
	for range 2 {
		if err := g.InstallFirewall(ctx, firewall, 8080); err != nil {
			t.Fatalf("InstallFirewall: %v", err)
		}
	}
	assertJumpsOnTop(t, g, filterTable, "INPUT", "-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT")
	assertJumpsOnTop(t, g, filterTable, "FORWARD",
		"-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
		"-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
		"-A FORWARD -s "+target+"/32 -j TUNNELDECK-FORWARD")
	assertJumpsOnTop(t, g, natTable, "PREROUTING", "-A PREROUTING -i tdvpn0 -j TUNNELDECK-PREROUTING")
	assertJumpsOnTop(t, g, natTable, "POSTROUTING", "-A POSTROUTING -j TUNNELDECK-POSTROUTING")
	if g.replyRouting() != replyByMark {
		t.Fatalf("capabilities %+v: the integration host must have CONNMARK", g.caps)
	}
	assertJumpsOnTop(t, g, mangleTable, "PREROUTING", "-A PREROUTING -j TUNNELDECK-MANGLE-PRE")
	mangle := listRulesOrFail(t, g, mangleTable, mangleChain)
	if len(mangle) != 2 || lineTag(mangle[0]) != "tdfixed:reply-mark" || !strings.Contains(mangle[0], "-i tdvpn0") ||
		!strings.Contains(mangle[0], "CONNMARK --set-xmark 0x7194/0xffff") ||
		!strings.Contains(mangle[1], "! -i tdvpn0 -m connmark --mark 0x7194/0xffff") || !strings.Contains(mangle[1], "--restore-mark") {
		t.Errorf("TUNNELDECK-MANGLE-PRE = %q", mangle)
	}

	input := listRulesOrFail(t, g, filterTable, inputChain)
	if len(input) != 11 || !strings.Contains(input[5], "--dport 22") || lineTag(input[5]) != "tdrule:ssh" || input[len(input)-1] != "-A TUNNELDECK-INPUT -j DROP" {
		t.Errorf("TUNNELDECK-INPUT = %q", input)
	}
	forward := listRulesOrFail(t, g, filterTable, forwardChain)
	if forward[len(forward)-1] != "-A TUNNELDECK-FORWARD -j DROP" || !containsFragment(forward, "--ctstate DNAT") ||
		!containsFragment(forward, "TCPMSS") {
		t.Errorf("TUNNELDECK-FORWARD = %q", forward)
	}
	prerouting := listRulesOrFail(t, g, natTable, preroutingChain)
	if len(prerouting) != 2 || !containsFragment(prerouting, "--to-destination "+target+":9000-9010/8000") {
		t.Errorf("TUNNELDECK-PREROUTING = %q", prerouting)
	}
	postrouting := listRulesOrFail(t, g, natTable, postroutingChain)
	if len(postrouting) != 2 || !containsFragment(postrouting, "MASQUERADE") {
		t.Errorf("TUNNELDECK-POSTROUTING = %q", postrouting)
	}

	if err := g.InstallFirewall(ctx, domain.Firewall{Rules: firewall.Rules[:1]}, 8080); err != nil {
		t.Fatalf("InstallFirewall with changed rules: %v", err)
	}
	if chain := listRulesOrFail(t, g, filterTable, inputChain); len(chain) != 4 {
		t.Errorf("TUNNELDECK-INPUT after rule change = %q", chain)
	}
	assertJumpsOnTop(t, g, filterTable, "FORWARD",
		"-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", "-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD")
	if chain := listRulesOrFail(t, g, natTable, preroutingChain); len(chain) != 0 {
		t.Errorf("TUNNELDECK-PREROUTING after rule change = %q", chain)
	}
	if chain := listRulesOrFail(t, g, mangleTable, mangleChain); len(chain) != 0 {
		t.Errorf("TUNNELDECK-MANGLE-PRE without port forwards = %q", chain)
	}
	if err := g.InstallFirewall(ctx, firewall, 8080); err != nil {
		t.Fatalf("InstallFirewall again: %v", err)
	}

	// A remote network behind the VPN (TEST-NET-2, outside every LAN).
	remoteNetworks := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	for _, ip := range []string{"10.99.0.2", "10.99.0.2", "10.99.0.3"} {
		if err := g.RouteThroughTunnel(ctx, netip.MustParseAddr(ip), remoteNetworks, nil); err != nil {
			t.Fatalf("RouteThroughTunnel(%s): %v", ip, err)
		}
	}
	listing, err := g.listPolicyRules(ctx)
	if err != nil || len(listing.vpnSources) != 1 || listing.vpnSources[0] != "10.99.0.3" {
		t.Errorf("policy rules at 7194 = %v, %v; want only 10.99.0.3", listing.vpnSources, err)
	}
	// One LAN exclusion per LAN subnet, the outbound rule, the replies of
	// both forwards by connection mark and the remote network; every
	// listed rule must parse back into a wanted one, or the repeated calls
	// above would have churned.
	if want := len(lan) + 3; len(listing.owned) != want {
		t.Errorf("owned policy rules = %v, want %d", listing.owned, want)
	}
	for _, rule := range listing.owned {
		if _, ok := rule.parse(); !ok {
			t.Errorf("policy rule %v does not parse", rule.tokens)
		}
	}
	if rules := mustRun(t, runner, "ip", "-4", "rule", "show"); !strings.Contains(rules, "7191:\tfrom all fwmark 0x7194/0xffff lookup 7194") {
		t.Errorf("no reply rule by connection mark:\n%s", rules)
	}
	if routes := mustRun(t, runner, "ip", "route", "show", "table", routingTable); !strings.Contains(routes, "default dev tdvpn0") {
		t.Errorf("table 7194 = %q", routes)
	}

	for range 2 {
		if err := g.ClearTunnelRouting(ctx); err != nil {
			t.Fatalf("ClearTunnelRouting: %v", err)
		}
	}
	if mainAfter := mustRun(t, runner, "ip", "route", "show", "table", "main"); mainAfter != mainBefore {
		t.Errorf("main table changed:\nbefore %q\nafter  %q", mainBefore, mainAfter)
	}
	if rulesAfter := mustRun(t, runner, "ip", "-4", "rule", "show"); rulesAfter != rulesBefore {
		t.Errorf("policy rules left behind:\nbefore %q\nafter  %q", rulesBefore, rulesAfter)
	}
	assertJumpsOnTop(t, g, filterTable, "FORWARD", "-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
		"-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", "-A FORWARD -s "+target+"/32 -j TUNNELDECK-FORWARD")

	for range 2 {
		if err := g.RemoveFirewall(ctx); err != nil {
			t.Fatalf("RemoveFirewall: %v", err)
		}
	}
	for _, chain := range []struct {
		table table
		name  string
	}{{filterTable, inputChain}, {filterTable, forwardChain}, {natTable, preroutingChain}, {natTable, postroutingChain}, {mangleTable, mangleChain}} {
		if _, err := g.listRules(ctx, chain.table, chain.name); !isAbsent(err) {
			t.Errorf("%s still present: %v", chain.name, err)
		}
	}

	for _, r := range g.SelfCheck(ctx) {
		if r.ID != CheckTunDevice && r.ID != CheckIPForward && !r.OK {
			t.Errorf("self-check %s failed: %s", r.ID, r.Detail)
		}
	}
}

// TestIntegrationProtectionsOnMinimalKernels hides extensions from the
// probed capabilities, as on a kernel without their modules: without
// hashlimit the rate limits go through TUNNELDECK-LIMIT, without limit as
// well they and the chain are left out, without TCPMSS MSS clamping is;
// every installation succeeds.
func TestIntegrationProtectionsOnMinimalKernels(t *testing.T) {
	ctx := context.Background()
	runner := ExecRunner{}
	mustRun(t, runner, "ip", "link", "add", DeviceName, "type", "dummy")
	t.Cleanup(func() { _, _ = runner.Run(ctx, "ip", "link", "del", DeviceName) })
	g := New(runner)
	t.Cleanup(func() { _ = g.RemoveFirewall(ctx) })
	caps, err := g.detectCapabilities(ctx)
	if err != nil || !caps.has[extLimit] {
		t.Skipf("capabilities = %+v, %v; the limit match is needed", caps, err)
	}
	firewall := domain.Firewall{FirewallSettings: domain.DefaultFirewallSettings(),
		Rules: []domain.FirewallRule{hostAccess("ssh", domain.ProtocolTCP, 22, "", true)}}

	g.caps.has[extHashlimit] = false
	for range 2 {
		if err := g.InstallFirewall(ctx, firewall, 8080); err != nil {
			t.Fatalf("InstallFirewall without hashlimit: %v", err)
		}
	}
	limit := listRulesOrFail(t, g, filterTable, limitChain)
	if len(limit) != 3 || !containsFragment(limit, "-m limit --limit 25/sec") || limit[2] != "-A TUNNELDECK-LIMIT -j DROP" {
		t.Errorf("TUNNELDECK-LIMIT = %q", limit)
	}
	input := listRulesOrFail(t, g, filterTable, inputChain)
	forward := listRulesOrFail(t, g, filterTable, forwardChain)
	for name, chain := range map[string][]string{inputChain: input, forwardChain: forward} {
		if countJumps(chain, limitChain) != 2 || containsFragment(chain, "hashlimit") {
			t.Errorf("%s = %q, want the SYN and ping jumps to TUNNELDECK-LIMIT", name, chain)
		}
	}

	g.caps.has[extLimit], g.caps.has[extTCPMSS] = false, false
	if err := g.InstallFirewall(ctx, firewall, 8080); err != nil {
		t.Fatalf("InstallFirewall without rate limits and TCPMSS: %v", err)
	}
	forward = listRulesOrFail(t, g, filterTable, forwardChain)
	if containsFragment(forward, "TCPMSS") || countJumps(forward, limitChain) != 0 || forward[len(forward)-1] != "-A TUNNELDECK-FORWARD -j DROP" {
		t.Errorf("TUNNELDECK-FORWARD = %q, want neither MSS clamping nor rate limits", forward)
	}

	if err := g.RemoveFirewall(ctx); err != nil {
		t.Fatalf("RemoveFirewall: %v", err)
	}
	if _, err := g.listRules(ctx, filterTable, limitChain); !isAbsent(err) {
		t.Errorf("%s still present: %v", limitChain, err)
	}
}

// TestIntegrationRepliesBySourceWithoutCONNMARK hides CONNMARK from the
// probed capabilities, as on a kernel without xt_connmark: the mangle
// table stays untouched and the replies of a port forward are routed by
// the target's address, with Linux 4.4 selectors only.
func TestIntegrationRepliesBySourceWithoutCONNMARK(t *testing.T) {
	ctx := context.Background()
	runner := ExecRunner{}
	mustRun(t, runner, "ip", "link", "add", DeviceName, "type", "dummy")
	t.Cleanup(func() { _, _ = runner.Run(ctx, "ip", "link", "del", DeviceName) })
	mustRun(t, runner, "ip", "link", "set", DeviceName, "up")
	g := New(runner)
	t.Cleanup(func() { _ = g.ClearTunnelRouting(ctx); _ = g.RemoveFirewall(ctx) })
	if _, err := g.detectCapabilities(ctx); err != nil {
		t.Fatalf("detectCapabilities: %v", err)
	}
	g.caps.has[extConnmark] = false
	lan, err := g.LANSubnets(ctx)
	if err != nil || len(lan) == 0 {
		t.Fatalf("LANSubnets = %v, %v", lan, err)
	}
	target := lanTarget(t, lan[0])
	forward := domain.Firewall{Rules: []domain.FirewallRule{{ID: "web", Name: "Web", Direction: domain.DirectionInbound,
		Protocol: domain.ProtocolTCP, Destination: target, DestinationPort: domain.SinglePort(80), Enabled: true}}}
	if err := g.InstallFirewall(ctx, forward, 8080); err != nil {
		t.Fatalf("InstallFirewall: %v", err)
	}
	if _, err := g.listRules(ctx, mangleTable, mangleChain); !isAbsent(err) {
		t.Errorf("%s exists without CONNMARK: %v", mangleChain, err)
	}
	if err := g.RouteThroughTunnel(ctx, netip.MustParseAddr("10.99.0.2"), nil, nil); err != nil {
		t.Fatalf("RouteThroughTunnel: %v", err)
	}
	rules := mustRun(t, runner, "ip", "-4", "rule", "show")
	if !strings.Contains(rules, "7191:\tfrom "+target+" lookup 7194") || strings.Contains(rules, "fwmark") {
		t.Errorf("want the reply rule by source, no fwmark rule:\n%s", rules)
	}
}

// integrationFirewall covers every chain: host rules, a shifted TCP range
// and ESP forwarded to target, an outbound rule for target and every
// global protection.
func integrationFirewall(target string) domain.Firewall {
	destination := target
	return domain.Firewall{FirewallSettings: domain.DefaultFirewallSettings(), Rules: []domain.FirewallRule{
		hostAccess("ssh", domain.ProtocolTCP, 22, "", true),
		domain.LegacyHostRule(domain.FirewallRule{ID: "wg", Name: "WireGuard", Direction: domain.DirectionInbound, Protocol: domain.ProtocolUDP, Source: "192.168.1.0/24",
			DestinationPort: domain.SinglePort(51820), Enabled: true}),
		domain.LegacyHostRule(domain.FirewallRule{ID: "ping", Name: "Ping", Direction: domain.DirectionInbound, Protocol: domain.ProtocolICMP, ICMPType: "echo-request",
			Enabled: true}),
		{ID: "range", Name: "Range", Direction: domain.DirectionInbound, Protocol: domain.ProtocolTCP, Destination: destination,
			DestinationPort: domain.PortRange{From: 9000, To: 9010}, PublicPort: domain.PortRange{From: 8000, To: 8010}, Enabled: true},
		{ID: "esp", Name: "ESP", Direction: domain.DirectionInbound, Protocol: domain.ProtocolESP, Destination: destination,
			KeepSourceAddress: true, Enabled: true},
		{ID: "out", Name: "Out", Direction: domain.DirectionOutbound, Protocol: domain.ProtocolAny, Source: target,
			Destination: "0.0.0.0/0", Enabled: true},
		domain.LegacyHostRule(domain.FirewallRule{ID: "telnet", Name: "Reject telnet", Direction: domain.DirectionInbound, Action: domain.ActionReject, Protocol: domain.ProtocolTCPUDP,
			DestinationPort: domain.SinglePort(23), Enabled: true}),
	}}
}

// lanTarget picks an address inside subnet that is not the container's.
func lanTarget(t *testing.T, subnet netip.Prefix) string {
	t.Helper()
	addr := subnet.Addr().Next().Next().Next().Next().Next()
	if !subnet.Contains(addr) {
		t.Fatalf("subnet %s is too small for a target", subnet)
	}
	return addr.String()
}

func mustRun(t *testing.T, runner CommandRunner, name string, args ...string) string {
	t.Helper()
	out, err := runner.Run(context.Background(), name, args...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return out
}

func listRulesOrFail(t *testing.T, g *Guard, tbl table, chain string) []string {
	t.Helper()
	rules, err := g.listRules(context.Background(), tbl, chain)
	if err != nil {
		t.Fatalf("list %s: %v", chain, err)
	}
	return rules
}

func assertJumpsOnTop(t *testing.T, g *Guard, tbl table, chain string, jumps ...string) {
	t.Helper()
	rules := listRulesOrFail(t, g, tbl, chain)
	if len(rules) < len(jumps) {
		t.Fatalf("%s = %q, want the jumps %q on top", chain, rules, jumps)
	}
	for i, jump := range jumps {
		if rules[i] != jump || countOf(rules, jump) != 1 {
			t.Errorf("%s = %q, want exactly one %q at position %d", chain, rules, jump, i+1)
		}
	}
	if extra := countJumpsTo(rules, jumps); extra != len(jumps) {
		t.Errorf("%s = %q, want no other jump to TunnelDeck's chain", chain, rules)
	}
}

func countJumpsTo(rules, jumps []string) int {
	target := jumps[0][strings.LastIndex(jumps[0], " -j ")+4:]
	return countJumps(rules, target)
}

func countOf(lines []string, want string) int {
	return len(slices.DeleteFunc(slices.Clone(lines), func(line string) bool { return line != want }))
}

func containsFragment(lines []string, fragment string) bool {
	return slices.ContainsFunc(lines, func(line string) bool { return strings.Contains(line, fragment) })
}
