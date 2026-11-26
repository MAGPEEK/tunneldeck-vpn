package netguard

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

// lancomFirewall is the IPsec device of SPEC §16.2 with the IKE port only:
// an outbound rule for 192.168.2.2 plus UDP 500 and ESP forwarded to it.
var lancomFirewall = rulesOnly(
	portForward(domain.ProtocolUDP, "192.168.2.2", domain.SinglePort(500)),
	portForward(domain.ProtocolESP, "192.168.2.2", domain.PortRange{}),
	outboundRule(domain.ProtocolAny, "192.168.2.2", "0.0.0.0/0"),
)

// The policy rules of lancomFirewall on lanListing.
const (
	addLANExclusion = "ip rule add from 192.168.2.2/32 to 192.168.2.0/24 lookup main priority 7100"
	addIKEReplies   = "ip rule add from 192.168.2.2/32 to 0.0.0.0/0 ipproto 17 sport 500 lookup 7194 priority 7191"
	addESPReplies   = "ip rule add from 192.168.2.2/32 to 0.0.0.0/0 ipproto 50 lookup 7194 priority 7191"
	addOutbound     = "ip rule add from 192.168.2.2/32 to 0.0.0.0/0 lookup 7194 priority 7190"
)

func lancomGuard(t *testing.T, f *fakeRunner) *Guard {
	t.Helper()
	scriptState(f, installedState{input: 1, forward: 1, forwardJumps: []string{"-A FORWARD -s 192.168.2.2/32 -j TUNNELDECK-FORWARD"}})
	g := newLegacyGuard(f)
	if err := g.InstallFirewall(context.Background(), lancomFirewall, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	f.takeCalls()
	return g
}

func TestRouteThroughTunnelInstallsPolicyRules(t *testing.T) {
	tests := []struct {
		name    string
		listing string
		want    []string
	}{
		{
			name:    "nothing installed yet",
			listing: defaultRules,
			want: []string{routeReplace, ruleShow, "ip rule add from 10.8.0.2 lookup 7194 priority 7194", addrShow,
				addLANExclusion, addIKEReplies, addESPReplies, addOutbound},
		},
		{
			name: "present rules are kept, stale ones deleted routing first",
			listing: "0:\tfrom all lookup local\n" +
				"7100:\tfrom 192.168.9.9 to 192.168.2.0/24 lookup main\n" +
				"7100:\tfrom 192.168.2.2 to 192.168.2.0/24 lookup main\n" +
				"7190:\tfrom 192.168.2.2 lookup 7194\n" +
				"7190:\tfrom 192.168.9.9 lookup 7194\n" +
				"7191:\tfrom 192.168.2.2 ipproto udp sport 500 lookup 7194\n" +
				"7191:\tfrom 192.168.2.2 ipproto 50 lookup 7194\n" +
				"7191:\tfrom 192.168.2.2 iif eth9 weird\n" +
				"7194:\tfrom 10.8.0.2 lookup 7194\n" +
				"32766:\tfrom all lookup main\n",
			want: []string{routeReplace, ruleShow, addrShow,
				"ip rule del priority 7191 from 192.168.2.2 iif eth9 weird",
				"ip rule del priority 7190 from 192.168.9.9 lookup 7194",
				"ip rule del priority 7100 from 192.168.9.9 to 192.168.2.0/24 lookup main",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			g := lancomGuard(t, f)
			f.on(ruleShow, ok(tt.listing))
			if err := g.RouteThroughTunnel(context.Background(), vpnIP, nil); err != nil {
				t.Fatalf("RouteThroughTunnel: %v", err)
			}
			assertCalls(t, f.calls, tt.want)
		})
	}
}

func TestInstallFirewallWhileRoutedUpdatesThePolicyRules(t *testing.T) {
	f := newFakeRunner()
	g := lancomGuard(t, f)
	f.on(ruleShow, ok(defaultRules))
	if err := g.RouteThroughTunnel(context.Background(), vpnIP, nil); err != nil {
		t.Fatal(err)
	}
	f.takeCalls()

	scriptState(f, installedState{input: 1, forward: 1, forwardJumps: []string{"-A FORWARD -s 192.168.2.2/32 -j TUNNELDECK-FORWARD"}})
	f.on(ruleShow, ok("7100:\tfrom 192.168.2.2 to 192.168.2.0/24 lookup main\n"+
		"7190:\tfrom 192.168.2.2 lookup 7194\n"+
		"7191:\tfrom 192.168.2.2 ipproto 17 sport 500 lookup 7194\n"+
		"7191:\tfrom 192.168.2.2 ipproto 50 lookup 7194\n"))
	f.on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule))
	if err := g.InstallFirewall(context.Background(), rulesOnly(lancomFirewall.Rules[:2]...), uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	calls := f.takeCalls()
	assertCalls(t, calls[slices.Index(calls, ruleShow):], []string{ruleShow,
		"ip rule del priority 7190 from 192.168.2.2 lookup 7194"})
}

func TestKillSwitchWhileDisconnected(t *testing.T) {
	f := newFakeRunner()
	g := lancomGuard(t, f)
	f.on(ruleShow, ok("7100:\tfrom 192.168.2.2 to 192.168.2.0/24 lookup main\n"+
		"7190:\tfrom 192.168.2.2 lookup 7194\n"+
		"7191:\tfrom 192.168.2.2 ipproto 17 sport 500 lookup 7194\n"+
		"7194:\tfrom 10.8.0.2 lookup 7194\n"))
	if err := g.ClearTunnelRouting(context.Background()); err != nil {
		t.Fatalf("ClearTunnelRouting: %v", err)
	}
	assertCalls(t, f.takeCalls(), []string{ruleShow,
		"ip rule del priority 7191 from 192.168.2.2 ipproto 17 sport 500 lookup 7194",
		"ip rule del priority 7190 from 192.168.2.2 lookup 7194",
		"ip rule del priority 7100 from 192.168.2.2 to 192.168.2.0/24 lookup main",
		"ip rule del from 10.8.0.2 lookup 7194 priority 7194",
		routeDelete,
	})

	// While disconnected an installation keeps the kill-switch jump and the
	// final DROP of TUNNELDECK-FORWARD and adds no policy rule.
	state := installedState{input: 1, forward: 1, forwardJumps: []string{"-A FORWARD -s 192.168.2.2/32 -j TUNNELDECK-FORWARD"}}
	scriptState(f, state)
	if err := g.InstallFirewall(context.Background(), lancomFirewall, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	calls := f.takeCalls()
	for _, call := range calls {
		if strings.HasPrefix(call, "ip rule") || strings.Contains(call, "-D FORWARD") {
			t.Errorf("disconnected installation ran %q", call)
		}
	}
	for _, want := range []string{
		legacy + "-A TUNNELDECK-FORWARD " + killSwitchDrop,
		legacy + "-A TUNNELDECK-FORWARD -o tdvpn0 -s 192.168.2.2/32 -j ACCEPT",
		legacy + "-A TUNNELDECK-FORWARD -j DROP",
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("missing %q in %v", want, calls)
		}
	}
}

func TestPolicyRuleFailures(t *testing.T) {
	tests := []struct {
		name    string
		script  func(*fakeRunner)
		run     func(*Guard) error
		wantErr string
	}{
		{
			name:    "adding a policy rule fails",
			script:  func(f *fakeRunner) { f.on(addOutbound, fail(notPermitted)) },
			run:     routeThroughTunnel,
			wantErr: "Operation not permitted",
		},
		{
			name: "deleting a stale policy rule fails",
			script: func(f *fakeRunner) {
				f.on(ruleShow, ok("7190:\tfrom 192.168.9.9 lookup 7194\n")).
					on("ip rule del priority 7190 from 192.168.9.9 lookup 7194", fail(notPermitted))
			},
			run:     routeThroughTunnel,
			wantErr: "ip rule del",
		},
		{
			name:    "LAN detection fails",
			script:  func(f *fakeRunner) { f.on(addrShow, fail("exec: \"ip\": executable file not found in $PATH")) },
			run:     routeThroughTunnel,
			wantErr: "detect LAN subnets",
		},
		{
			name: "clear: deleting a policy rule fails",
			script: func(f *fakeRunner) {
				f.on(ruleShow, ok("7100:\tfrom 192.168.2.2 to 192.168.2.0/24 lookup main\n")).
					on("ip rule del priority 7100 from 192.168.2.2 to 192.168.2.0/24 lookup main", fail(notPermitted))
			},
			run:     clearTunnelRouting,
			wantErr: "Operation not permitted",
		},
		{
			name: "install while routed: listing fails",
			script: func(f *fakeRunner) {
				f.on(ruleShow, ok(defaultRules), fail(notPermitted))
				scriptInstalled(f)
				f.scripts[legacy+"-S FORWARD"] = []fakeResult{ok("-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD\n" +
					"-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD\n-A FORWARD -s 192.168.2.2/32 -j TUNNELDECK-FORWARD\n")}
			},
			run: func(g *Guard) error {
				if err := routeThroughTunnel(g); err != nil {
					return err
				}
				return g.InstallFirewall(context.Background(), lancomFirewall, uiPort)
			},
			wantErr: "update policy routing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			g := lancomGuard(t, f)
			tt.script(f)
			if err := tt.run(g); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestWantedPolicyRulesExcludeTheHostsOwnAddress(t *testing.T) {
	lan := parseLANAddresses(lanListing)
	firewall := rulesOnly(
		outboundRule(domain.ProtocolAny, "192.168.2.0/24", "10.0.0.0/8"),
		changed(outboundRule(domain.ProtocolAny, "192.168.2.0/24", "10.1.0.0/16"), func(r *domain.FirewallRule) { r.Action = domain.ActionDrop }),
		changed(outboundRule(domain.ProtocolAny, "192.168.2.7", "10.2.0.0/16"), func(r *domain.FirewallRule) { r.Enabled = false }),
		changed(portForward(domain.ProtocolTCPUDP, "192.168.2.3", ports(6000, 6010)), func(r *domain.FirewallRule) { r.KeepSourceAddress = true }),
	)
	var got []string
	for _, rule := range wantedPolicyRules(firewall, lan) {
		got = append(got, strings.Join(rule.addArgs(), " "))
	}
	assertCalls(t, got, []string{
		"rule add from 192.168.2.10/32 to 0.0.0.0/0 lookup main priority 7100",
		"rule add from 192.168.2.0/24 to 192.168.2.0/24 lookup main priority 7100",
		"rule add from 192.168.2.3/32 to 192.168.2.0/24 lookup main priority 7100",
		"rule add from 192.168.2.0/24 to 10.0.0.0/8 lookup 7194 priority 7190",
		"rule add from 192.168.2.3/32 to 0.0.0.0/0 ipproto 6 sport 6000-6010 lookup 7194 priority 7191",
		"rule add from 192.168.2.3/32 to 0.0.0.0/0 ipproto 17 sport 6000-6010 lookup 7194 priority 7191",
	})
	if needsPolicyRules(testFirewall) {
		t.Error("host rules need no policy rules")
	}
}

func TestWantedPolicyRulesForAnAnyPortForward(t *testing.T) {
	lan := parseLANAddresses(lanListing)
	firewall := rulesOnly(portForward(domain.ProtocolTCP, "192.168.2.5", domain.PortRange{}))
	var got []string
	for _, rule := range wantedPolicyRules(firewall, lan) {
		got = append(got, strings.Join(rule.addArgs(), " "))
	}
	assertCalls(t, got, []string{
		"rule add from 192.168.2.5/32 to 192.168.2.0/24 lookup main priority 7100",
		"rule add from 192.168.2.5/32 to 0.0.0.0/0 ipproto 6 lookup 7194 priority 7191",
	})
	listed := listedRule{priority: replyPriority, tokens: strings.Fields("from 192.168.2.5 ipproto tcp lookup 7194")}
	if rule, ok := listed.parse(); !ok || rule != wantedPolicyRules(firewall, lan)[1] {
		t.Errorf("listed rule %+v (ok %v) does not match the wanted reply rule", rule, ok)
	}
}

func TestParsePolicyListing(t *testing.T) {
	listing := parsePolicyListing("0:\tfrom all lookup local\n" +
		"7100:\tfrom all to 192.168.2.0/24 lookup 254\n" +
		"7191:\tfrom 192.168.2.3 ipproto tcp sport 6000-6010 lookup 7194 proto boot\n" +
		"7191:\tfrom 192.168.2.3 ipproto ipv9 lookup 7194\n" +
		"7191:\tfrom 192.168.2.3 sport x lookup 7194\n" +
		"7194:\tfrom 10.8.0.2 lookup 7194\n" +
		"garbage\n" +
		"x:\tfrom all lookup main\n")
	if !slices.Equal(listing.vpnSources, []string{"10.8.0.2"}) || len(listing.owned) != 4 {
		t.Fatalf("listing = %+v", listing)
	}
	want := []policyRule{
		{priority: 7100, from: anyAddress, to: netip.MustParsePrefix("192.168.2.0/24"), table: mainTable},
		{priority: 7191, from: netip.MustParsePrefix("192.168.2.3/32"), to: anyAddress, ipproto: 6,
			sport: domain.PortRange{From: 6000, To: 6010}, table: routingTable},
	}
	for i, w := range want {
		if got, ok := listing.owned[i].parse(); !ok || got != w {
			t.Errorf("rule %d = %+v, %v; want %+v", i, got, ok, w)
		}
	}
	for _, i := range []int{2, 3} {
		if _, ok := listing.owned[i].parse(); ok {
			t.Errorf("rule %d %v parsed, want it treated as foreign", i, listing.owned[i].tokens)
		}
	}
}

// remoteNetworks are networks behind the VPN outside lanListing's LAN.
var remoteNetworks = []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("172.30.0.0/16")}

const (
	addRemote99 = "ip rule add from 0.0.0.0/0 to 10.99.0.0/24 lookup 7194 priority 7180"
	addRemote30 = "ip rule add from 0.0.0.0/0 to 172.30.0.0/16 lookup 7194 priority 7180"
)

func TestRouteThroughTunnelRoutesRemoteNetworks(t *testing.T) {
	f := newFakeRunner()
	g := newLegacyGuard(f)
	f.on(ruleShow, ok(defaultRules))
	if err := g.RouteThroughTunnel(context.Background(), vpnIP, remoteNetworks); err != nil {
		t.Fatalf("RouteThroughTunnel: %v", err)
	}
	assertCalls(t, f.takeCalls(), []string{routeReplace, ruleShow,
		"ip rule add from 10.8.0.2 lookup 7194 priority 7194", addrShow, addRemote99, addRemote30})

	// A changed list: present rules stay, stale ones go.
	f.on(ruleShow, ok("7180:\tfrom all to 10.99.0.0/24 lookup 7194\n"+
		"7180:\tfrom all to 10.98.0.0/24 lookup 7194\n"+
		"7194:\tfrom 10.8.0.2 lookup 7194\n"))
	if err := g.RouteThroughTunnel(context.Background(), vpnIP, remoteNetworks); err != nil {
		t.Fatalf("RouteThroughTunnel again: %v", err)
	}
	assertCalls(t, f.takeCalls(), []string{routeReplace, ruleShow, addrShow,
		"ip rule del priority 7180 from all to 10.98.0.0/24 lookup 7194", addRemote30})

	f.on(ruleShow, ok("7180:\tfrom all to 10.99.0.0/24 lookup 7194\n7194:\tfrom 10.8.0.2 lookup 7194\n"))
	if err := g.ClearTunnelRouting(context.Background()); err != nil {
		t.Fatalf("ClearTunnelRouting: %v", err)
	}
	assertCalls(t, f.takeCalls(), []string{ruleShow,
		"ip rule del priority 7180 from all to 10.99.0.0/24 lookup 7194",
		"ip rule del from 10.8.0.2 lookup 7194 priority 7194", routeDelete})
}

func TestInstallFirewallWhileRoutedKeepsRemoteNetworks(t *testing.T) {
	f := newFakeRunner()
	g := lancomGuard(t, f)
	f.on(ruleShow, ok(defaultRules))
	if err := g.RouteThroughTunnel(context.Background(), vpnIP, remoteNetworks[:1]); err != nil {
		t.Fatal(err)
	}
	if calls := f.takeCalls(); !slices.Equal(calls[len(calls)-2:], []string{addOutbound, addRemote99}) {
		t.Fatalf("remote network not routed after the firewall's rules: %q", calls)
	}

	scriptState(f, installedState{input: 1, forward: 1, forwardJumps: []string{"-A FORWARD -s 192.168.2.2/32 -j TUNNELDECK-FORWARD"}})
	f.on(ruleShow, ok("7100:\tfrom 192.168.2.2 to 192.168.2.0/24 lookup main\n"+
		"7180:\tfrom all to 10.99.0.0/24 lookup 7194\n"+
		"7190:\tfrom 192.168.2.2 lookup 7194\n"+
		"7191:\tfrom 192.168.2.2 ipproto 17 sport 500 lookup 7194\n"+
		"7191:\tfrom 192.168.2.2 ipproto 50 lookup 7194\n"))
	f.on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule))
	if err := g.InstallFirewall(context.Background(), rulesOnly(lancomFirewall.Rules[:2]...), uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	calls := f.takeCalls()
	assertCalls(t, calls[slices.Index(calls, ruleShow):], []string{ruleShow,
		"ip rule del priority 7190 from 192.168.2.2 lookup 7194"})
}

func TestRouteThroughTunnelRefusesRemoteNetworks(t *testing.T) {
	tests := []struct {
		name    string
		network string
		// commands is true when the refusal needs the LAN, so the route and
		// the VPN rule were already in place.
		commands bool
	}{
		{name: "overlaps the LAN", network: "192.168.0.0/16", commands: true},
		{name: "inside the LAN", network: "192.168.2.128/25", commands: true},
		{name: "every address", network: "0.0.0.0/0"},
		{name: "host bits set", network: "10.99.0.1/24"},
		{name: "IPv6", network: "fd00::/64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			g := newLegacyGuard(f)
			f.on(ruleShow, ok(defaultRules))
			err := g.RouteThroughTunnel(context.Background(), vpnIP, []netip.Prefix{netip.MustParsePrefix(tt.network)})
			var v *domain.ValidationError
			if !errors.As(err, &v) || v.Fields["remoteNetworks"] == "" {
				t.Fatalf("err = %v, want a validation error on remoteNetworks", err)
			}
			if got := len(f.calls) > 0; got != tt.commands {
				t.Errorf("commands run = %q", f.calls)
			}
			for _, call := range f.calls {
				if strings.Contains(call, "priority 7180") {
					t.Errorf("refused network routed: %q", call)
				}
			}
		})
	}
}
