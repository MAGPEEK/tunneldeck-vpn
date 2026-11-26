package domain

import (
	"net/netip"
	"strings"
	"testing"
)

func TestIPsecDeviceRules(t *testing.T) {
	device := netip.MustParseAddr("192.168.1.2")
	tests := []struct {
		name      string
		peers     []netip.Prefix
		wantRules int
		wantPeer  string // inbound source and outbound destination of the first five rules
	}{
		{name: "no peers", wantRules: 5, wantPeer: ""},
		{name: "one peer", peers: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}, wantRules: 5, wantPeer: "203.0.113.7/32"},
		{name: "two peers", peers: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("198.51.100.0/24")}, wantRules: 10, wantPeer: "203.0.113.7/32"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := IPsecDeviceRules("Router", device, tt.peers)
			if len(rules) != tt.wantRules {
				t.Fatalf("got %d rules, want %d: %+v", len(rules), tt.wantRules, rules)
			}
			if err := ValidateFirewallRules(rules); err != nil {
				t.Fatalf("template rules are invalid: %v", err)
			}
			if err := CheckInboundDestinations(rules, HostNetwork{Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}); err != nil {
				t.Fatalf("template rules leave the LAN: %v", err)
			}
			wantRemote := tt.wantPeer
			if wantRemote == "" {
				wantRemote = "0.0.0.0/0"
			}
			assertIPsecRules(t, rules[:5], tt.wantPeer, wantRemote)
		})
	}
}

func assertIPsecRules(t *testing.T, rules []FirewallRule, source, remote string) {
	t.Helper()
	inbound := []struct {
		protocol FirewallProtocol
		port     int
	}{{ProtocolUDP, 500}, {ProtocolUDP, 4500}, {ProtocolESP, 0}}
	for i, want := range inbound {
		r := rules[i]
		if r.Direction != DirectionInbound || r.Protocol != want.protocol || r.DestinationPort.From != want.port ||
			r.Destination != "192.168.1.2" || !r.KeepSourceAddress || r.Source != source || !r.Enabled || r.ID != "" {
			t.Errorf("rule %d = %+v", i, r)
		}
	}
	for i, protocol := range []FirewallProtocol{ProtocolUDP, ProtocolESP} {
		r := rules[3+i]
		if r.Direction != DirectionOutbound || r.Protocol != protocol || r.Source != "192.168.1.2" ||
			r.Destination != remote || !r.Enabled {
			t.Errorf("rule %d = %+v", 3+i, r)
		}
	}
	for _, r := range rules {
		if !strings.HasPrefix(r.Name, "Router: ") {
			t.Errorf("name %q lacks the template name", r.Name)
		}
	}
}

func TestIPsecTemplateNameFits(t *testing.T) {
	name := strings.Repeat("n", MaxIPsecTemplateNameLength)
	rules := IPsecDeviceRules(name, netip.MustParseAddr("192.168.1.2"), nil)
	if err := ValidateFirewallRules(rules); err != nil {
		t.Fatalf("longest template name yields invalid rules: %v", err)
	}
}
