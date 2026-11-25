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

	g := New(runner)
	rules := []domain.HostAccessRule{
		{Protocol: domain.TransportTCP, Port: 22, Enabled: true},
		{Protocol: domain.TransportUDP, Port: 51820, SourceCIDR: "192.168.1.0/24", Enabled: true},
	}
	for range 2 {
		if err := g.InstallFirewall(ctx, rules, 8080); err != nil {
			t.Fatalf("InstallFirewall: %v", err)
		}
	}
	assertJumpsOnTop(t, g, "INPUT", "-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT")
	assertJumpsOnTop(t, g, "FORWARD",
		"-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
		"-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD")
	chain := listRulesOrFail(t, g, inputChain)
	if len(chain) != 4 || !strings.Contains(chain[1], "--dport 22") || chain[3] != "-A TUNNELDECK-INPUT -j DROP" {
		t.Errorf("TUNNELDECK-INPUT = %q", chain)
	}

	if err := g.InstallFirewall(ctx, rules[:1], 8080); err != nil {
		t.Fatalf("InstallFirewall with changed rules: %v", err)
	}
	if chain := listRulesOrFail(t, g, inputChain); len(chain) != 3 {
		t.Errorf("TUNNELDECK-INPUT after rule change = %q", chain)
	}

	for _, ip := range []string{"10.99.0.2", "10.99.0.2", "10.99.0.3"} {
		if err := g.RouteThroughTunnel(ctx, netip.MustParseAddr(ip)); err != nil {
			t.Fatalf("RouteThroughTunnel(%s): %v", ip, err)
		}
	}
	if sources, err := g.policyRuleSources(ctx); err != nil || len(sources) != 1 || sources[0] != "10.99.0.3" {
		t.Errorf("policy rules = %v, %v; want only 10.99.0.3", sources, err)
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

	for range 2 {
		if err := g.RemoveFirewall(ctx); err != nil {
			t.Fatalf("RemoveFirewall: %v", err)
		}
	}
	if _, err := g.listRules(ctx, inputChain); !isAbsent(err) {
		t.Errorf("TUNNELDECK-INPUT still present: %v", err)
	}

	for _, r := range g.SelfCheck(ctx) {
		if r.ID != CheckTunDevice && !r.OK {
			t.Errorf("self-check %s failed: %s", r.ID, r.Detail)
		}
	}
}

func mustRun(t *testing.T, runner CommandRunner, name string, args ...string) string {
	t.Helper()
	out, err := runner.Run(context.Background(), name, args...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return out
}

func listRulesOrFail(t *testing.T, g *Guard, chain string) []string {
	t.Helper()
	rules, err := g.listRules(context.Background(), chain)
	if err != nil {
		t.Fatalf("list %s: %v", chain, err)
	}
	return rules
}

func assertJumpsOnTop(t *testing.T, g *Guard, chain string, jumps ...string) {
	t.Helper()
	rules := listRulesOrFail(t, g, chain)
	if len(rules) < len(jumps) {
		t.Fatalf("%s = %q, want the jumps %q on top", chain, rules, jumps)
	}
	for i, jump := range jumps {
		if rules[i] != jump || countOf(rules, jump) != 1 {
			t.Errorf("%s = %q, want exactly one %q at position %d", chain, rules, jump, i+1)
		}
	}
}
