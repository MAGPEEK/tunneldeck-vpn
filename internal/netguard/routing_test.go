package netguard

import (
	"context"
	"errors"
	"net/netip"
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
	return g.RouteThroughTunnel(context.Background(), vpnIP)
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
		err := New(f).RouteThroughTunnel(context.Background(), addr)
		var v *domain.ValidationError
		if !errors.As(err, &v) || v.Fields["vpnIp"] == "" {
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
