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

const (
	defaultRules = "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n"
	routeReplace = "ip route replace default dev tdvpn0 table 7194"
	ruleShow     = "ip -4 rule show"
	routeDelete  = "ip route del default table 7194"
)

var vpnIP = netip.MustParseAddr("10.8.0.2")

func rulesWith(sources ...string) string {
	listing := "0:\tfrom all lookup local\n"
	for _, source := range sources {
		listing += "7194:\tfrom " + source + " lookup 7194\n"
	}
	return listing + "32766:\tfrom all lookup main\n"
}

type routingCase struct {
	name   string
	script func(*fakeRunner)
	run    func(*Guard) error
	want   []string
}

func routeThroughTunnel(g *Guard) error {
	return g.RouteThroughTunnel(context.Background(), vpnIP, nil, nil)
}

func clearTunnelRouting(g *Guard) error {
	return g.ClearTunnelRouting(context.Background())
}

var routingCases = []routingCase{
	{
		name:   "route added",
		script: func(f *fakeRunner) { f.on(ruleShow, ok(defaultRules)) },
		run:    routeThroughTunnel,
		want:   []string{routeReplace, ruleShow, "ip rule add from 10.8.0.2 lookup 7194 priority 7194"},
	},
	{
		name:   "route replaced while the rule exists",
		script: func(f *fakeRunner) { f.on(ruleShow, ok(rulesWith("10.8.0.2"))) },
		run:    routeThroughTunnel,
		want:   []string{routeReplace, ruleShow},
	},
	{
		name: "stale and duplicate rules replaced",
		script: func(f *fakeRunner) {
			f.on(ruleShow, ok(rulesWith("10.8.0.9", "10.8.0.2", "10.8.0.2")))
		},
		run: routeThroughTunnel,
		want: []string{
			routeReplace, ruleShow,
			"ip rule del from 10.8.0.9 lookup 7194 priority 7194",
			"ip rule del from 10.8.0.2 lookup 7194 priority 7194",
		},
	},
	{
		name: "stale rule vanishing meanwhile is tolerated",
		script: func(f *fakeRunner) {
			f.on(ruleShow, ok(rulesWith("10.8.0.9"))).
				on("ip rule del from 10.8.0.9 lookup 7194 priority 7194", fail(noRule))
		},
		run: routeThroughTunnel,
		want: []string{
			routeReplace, ruleShow,
			"ip rule del from 10.8.0.9 lookup 7194 priority 7194",
			"ip rule add from 10.8.0.2 lookup 7194 priority 7194",
		},
	},
	{
		name:   "clear removes rule and route",
		script: func(f *fakeRunner) { f.on(ruleShow, ok(rulesWith("10.8.0.2"))) },
		run:    clearTunnelRouting,
		want:   []string{ruleShow, "ip rule del from 10.8.0.2 lookup 7194 priority 7194", routeDelete},
	},
	{
		name: "clear tolerates absence",
		script: func(f *fakeRunner) {
			f.on(ruleShow, ok(defaultRules)).on(routeDelete, fail(noRoute))
		},
		run:  clearTunnelRouting,
		want: []string{ruleShow, routeDelete},
	},
}

func TestRoutingSequences(t *testing.T) {
	for _, tt := range routingCases {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			if err := tt.run(New(f)); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertCalls(t, f.calls, tt.want)
		})
	}
}

func TestRoutingNeverTouchesTheMainTable(t *testing.T) {
	for _, tt := range routingCases {
		f := newFakeRunner()
		tt.script(f)
		_ = tt.run(New(f))
		for _, call := range f.calls {
			if strings.HasPrefix(call, "ip route") && !strings.HasSuffix(call, " table 7194") {
				t.Errorf("%s: %q does not target table 7194", tt.name, call)
			}
			if strings.HasPrefix(call, "ip rule ") && !strings.HasSuffix(call, " lookup 7194 priority 7194") {
				t.Errorf("%s: %q is not our policy rule", tt.name, call)
			}
		}
	}
}

func TestRouteThroughTunnelRejectsNonIPv4(t *testing.T) {
	for _, addr := range []netip.Addr{
		netip.MustParseAddr("fd00::2"),
		netip.MustParseAddr("::ffff:10.8.0.2"),
		{},
	} {
		f := newFakeRunner()
		err := New(f).RouteThroughTunnel(context.Background(), addr, nil, nil)
		var v *domain.ValidationError
		if !errors.As(err, &v) || v.Fields["vpnIp"] == "" || v.Issues["vpnIp"].Code != "vpn_address_invalid" {
			t.Errorf("%v: err = %v, want a validation error on vpnIp", addr, err)
		}
		if len(f.calls) != 0 {
			t.Errorf("%v: commands ran: %v", addr, f.calls)
		}
	}
}

func TestRoutingFailures(t *testing.T) {
	tests := []struct {
		name    string
		script  func(*fakeRunner)
		run     func(*Guard) error
		wantErr string
	}{
		{
			name:    "route replace fails",
			script:  func(f *fakeRunner) { f.on(routeReplace, fail("Cannot find device \"tdvpn0\"")) },
			run:     routeThroughTunnel,
			wantErr: "Cannot find device",
		},
		{
			name:    "rule listing fails",
			script:  func(f *fakeRunner) { f.on(ruleShow, fail(notPermitted)) },
			run:     routeThroughTunnel,
			wantErr: "Operation not permitted",
		},
		{
			name: "stale rule deletion fails",
			script: func(f *fakeRunner) {
				f.on(ruleShow, ok(rulesWith("10.8.0.9"))).
					on("ip rule del from 10.8.0.9 lookup 7194 priority 7194", fail(notPermitted))
			},
			run:     routeThroughTunnel,
			wantErr: "ip rule del",
		},
		{
			name: "rule add fails",
			script: func(f *fakeRunner) {
				f.on("ip rule add from 10.8.0.2 lookup 7194 priority 7194", fail(notPermitted))
			},
			run:     routeThroughTunnel,
			wantErr: "ip rule add",
		},
		{
			name:    "clear: rule listing fails",
			script:  func(f *fakeRunner) { f.on(ruleShow, fail(notPermitted)) },
			run:     clearTunnelRouting,
			wantErr: "Operation not permitted",
		},
		{
			name: "clear: rule deletion fails",
			script: func(f *fakeRunner) {
				f.on(ruleShow, ok(rulesWith("10.8.0.2"))).
					on("ip rule del from 10.8.0.2 lookup 7194 priority 7194", fail(notPermitted))
			},
			run:     clearTunnelRouting,
			wantErr: "Operation not permitted",
		},
		{
			name:    "clear: route deletion fails",
			script:  func(f *fakeRunner) { f.on(routeDelete, fail(notPermitted)) },
			run:     clearTunnelRouting,
			wantErr: "Operation not permitted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			err := tt.run(New(f))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestRoutingErrorNamesTheCommand: the manager logs the routing error as it
// is, so it must name the failing ip command line and its error output.
func TestRoutingErrorNamesTheCommand(t *testing.T) {
	const stderr = `Error: argument "ipproto" is wrong: Failed to parse rule type`
	f := newFakeRunner()
	f.on(ruleShow, ok(defaultRules)).on("ip rule add from 10.8.0.2 lookup 7194 priority 7194", fail(stderr))
	err := routeThroughTunnel(New(f))
	for _, want := range []string{"route through tunnel: ip rule add from 10.8.0.2 lookup 7194 priority 7194", stderr} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
}

// localNetwork is the LAN subnet of lanListing that a net-to-net tunnel
// carries with its own addresses.
var localNetwork = []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")}

// TestRouteThroughTunnelWithLocalNetworks: a tunnel without an address of
// its own gets no rule at 7194, the host's LAN address as the source of
// table 7194 and its remote networks ahead of the LAN exclusions (7099).
func TestRouteThroughTunnelWithLocalNetworks(t *testing.T) {
	f := newFakeRunner()
	g := newLegacyGuard(f)
	f.on(ruleShow, ok(rulesWith("10.8.0.2")))
	if err := g.RouteThroughTunnel(context.Background(), netip.Addr{}, remoteNetworks, localNetwork); err != nil {
		t.Fatalf("RouteThroughTunnel: %v", err)
	}
	assertCalls(t, f.takeCalls(), []string{
		addrShow, routeReplace + " src 192.168.2.10", ruleShow,
		"ip rule del from 10.8.0.2 lookup 7194 priority 7194",
		"ip rule add to 10.99.0.0/24 lookup 7194 priority 7099",
		"ip rule add to 172.30.0.0/16 lookup 7194 priority 7099",
	})

	f.on(ruleShow, ok("7099:\tfrom all to 10.99.0.0/24 lookup 7194\n"))
	if err := g.ClearTunnelRouting(context.Background()); err != nil {
		t.Fatalf("ClearTunnelRouting: %v", err)
	}
	assertCalls(t, f.takeCalls(), []string{ruleShow, "ip rule del priority 7099 from all to 10.99.0.0/24 lookup 7194", routeDelete})
}

// TestLocalNetworksAreNotMasqueraded: while a tunnel carries local
// networks, TUNNELDECK-POSTROUTING returns their traffic into the tunnel
// before any masquerade line; clearing the routing removes that again.
func TestLocalNetworksAreNotMasqueraded(t *testing.T) {
	const exempt = natPrefix + "-A TUNNELDECK-POSTROUTING -o tdvpn0 -s 192.168.2.0/24 -m comment --comment tdfixed:local-network -j RETURN"
	f := newFakeRunner()
	g := installedGuard(t, f)
	state := installedState{input: 1, forward: 1}
	scriptState(f, state)
	f.on(ruleShow, ok(defaultRules))
	if err := g.RouteThroughTunnel(context.Background(), netip.Addr{}, nil, localNetwork); err != nil {
		t.Fatalf("RouteThroughTunnel: %v", err)
	}
	if calls := f.takeCalls(); !slices.Contains(calls, exempt) {
		t.Errorf("no masquerade exemption for the local network in:\n  %s", strings.Join(calls, "\n  "))
	}

	scriptState(f, installedState{input: 1, forward: 1, postrouting: 1})
	f.on(ruleShow, ok(defaultRules))
	if err := g.ClearTunnelRouting(context.Background()); err != nil {
		t.Fatalf("ClearTunnelRouting: %v", err)
	}
	if calls := f.takeCalls(); slices.Contains(calls, exempt) || !slices.ContainsFunc(calls, func(c string) bool {
		return strings.HasPrefix(c, natPrefix+"-D TUNNELDECK-POSTROUTING")
	}) {
		t.Errorf("the exemption was not removed:\n  %s", strings.Join(calls, "\n  "))
	}
}

func TestPostroutingExemptsLocalNetworksFirst(t *testing.T) {
	rules := []parsedRule{parseRule(domain.FirewallRule{
		ID: "o", Direction: domain.DirectionOutbound, Action: domain.ActionAccept, Protocol: domain.ProtocolAny,
		Source: "192.168.2.0/24", Destination: "10.99.0.0/24", Enabled: true,
	}, nil)}
	got := postroutingContent(rules, localNetwork)
	want := [][]string{
		{"-o", "tdvpn0", "-s", "192.168.2.0/24", "-m", "comment", "--comment", "tdfixed:local-network", "-j", "RETURN"},
		{"-o", "tdvpn0", "-s", "192.168.2.0/24", "-d", "10.99.0.0/24", "-m", "comment", "--comment", "tdrule:o", "-j", "MASQUERADE"},
	}
	if len(got) != len(want) || !slices.Equal(got[0], want[0]) || !slices.Equal(got[1], want[1]) {
		t.Errorf("postrouting = %q, want %q", got, want)
	}
}

func TestRouteThroughTunnelChecksTheTunnelAddress(t *testing.T) {
	tests := []struct {
		name  string
		vpnIP netip.Addr
		local []netip.Prefix
	}{
		{name: "address and local networks", vpnIP: vpnIP, local: localNetwork},
		{name: "everything", local: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{name: "not canonical", local: []netip.Prefix{netip.MustParsePrefix("192.168.2.1/24")}},
		{name: "IPv6", local: []netip.Prefix{netip.MustParsePrefix("fd00::/64")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			err := New(f).RouteThroughTunnel(context.Background(), tt.vpnIP, nil, tt.local)
			if !errors.Is(err, domain.ErrValidation) {
				t.Errorf("err = %v, want a validation error", err)
			}
			if calls := f.takeCalls(); len(calls) != 0 {
				t.Errorf("commands run: %q", calls)
			}
		})
	}
}
