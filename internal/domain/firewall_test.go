package domain

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// testHost is the host's own LAN address in testNetwork.
const testHost = "192.168.1.10"

// testNetwork is the host's LAN for the checks that need it: two
// addresses, one per subnet.
var testNetwork = HostNetwork{
	Addresses: []netip.Addr{netip.MustParseAddr(testHost), netip.MustParseAddr("10.10.0.1")},
	Subnets:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.10.0.0/16")},
}

// Rule builders for the tables below; each returns a valid rule.
func hostIn(proto FirewallProtocol, port int) FirewallRule {
	return FirewallRule{
		Name: "host", Direction: DirectionInbound, Protocol: proto,
		Destination: testHost, DestinationPort: SinglePort(port), Enabled: true,
	}
}

func forward(proto FirewallProtocol, target string, port int) FirewallRule {
	r := FirewallRule{
		Name: "forward", Direction: DirectionInbound, Protocol: proto,
		Destination: target, Enabled: true,
	}
	if proto.HasPorts() {
		r.DestinationPort = SinglePort(port)
	}
	return r
}

func outbound(source, destination string) FirewallRule {
	return FirewallRule{
		Name: "outbound", Direction: DirectionOutbound, Protocol: ProtocolAny, Source: source,
		Destination: destination, Enabled: true,
	}
}

func with(r FirewallRule, change func(*FirewallRule)) FirewallRule {
	change(&r)
	return r
}

func TestFirewallRuleValidate(t *testing.T) {
	tests := []struct {
		name       string
		rule       FirewallRule
		wantFields []string
	}{
		{"host tcp", hostIn(ProtocolTCP, 22), nil},
		{"host tcp+udp range from a source", with(hostIn(ProtocolTCPUDP, 1000), func(r *FirewallRule) {
			r.DestinationPort = PortRange{From: 1000, To: 1999}
			r.Source = "10.8.0.0/24"
		}), nil},
		{"host public port equal", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.PublicPort = SinglePort(22) }), nil},
		{"host ping", with(hostIn(ProtocolICMP, 0), func(r *FirewallRule) {
			r.DestinationPort = PortRange{}
			r.ICMPType = "echo-request"
		}), nil},
		{"host icmp numeric type", with(hostIn(ProtocolICMP, 0), func(r *FirewallRule) {
			r.DestinationPort, r.ICMPType = PortRange{}, "3/4"
		}), nil},
		{"host esp", with(hostIn(ProtocolESP, 0), func(r *FirewallRule) { r.DestinationPort = PortRange{} }), nil},
		{"host drop any from a source", with(hostIn(ProtocolAny, 0), func(r *FirewallRule) {
			r.DestinationPort, r.Action, r.Source = PortRange{}, ActionDrop, "203.0.113.0/24"
		}), nil},
		{"host reject tcp without port", with(hostIn(ProtocolTCP, 0), func(r *FirewallRule) {
			r.DestinationPort, r.Action = PortRange{}, ActionReject
		}), nil},
		{"host accept tcp on any port", with(hostIn(ProtocolTCP, 0), func(r *FirewallRule) { r.DestinationPort = PortRange{} }), nil},
		{"host accept tcp+udp on any port from a source", with(hostIn(ProtocolTCPUDP, 0), func(r *FirewallRule) {
			r.DestinationPort, r.Source = PortRange{}, "10.8.0.0/24"
		}), nil},
		{"host any destination port, fixed source port", with(hostIn(ProtocolUDP, 0), func(r *FirewallRule) {
			r.DestinationPort, r.SourcePort = PortRange{}, SinglePort(500)
		}), nil},
		{"host with source port", with(hostIn(ProtocolUDP, 500), func(r *FirewallRule) { r.SourcePort = SinglePort(500) }), nil},
		{"legacy host rule", LegacyHostRule(hostIn(ProtocolTCP, 22)), nil},
		{"forward udp", forward(ProtocolUDP, "192.168.1.2", 500), nil},
		{"forward shifted range", with(forward(ProtocolTCP, "192.168.1.2", 2000), func(r *FirewallRule) {
			r.DestinationPort = PortRange{From: 2000, To: 2010}
			r.PublicPort = PortRange{From: 1000, To: 1010}
			r.KeepSourceAddress = true
		}), nil},
		{"forward esp", forward(ProtocolESP, "192.168.1.2", 0), nil},
		{"forward tcp on any port", forward(ProtocolTCP, "192.168.1.2", 0), nil},
		{"forward tcp+udp on any port", forward(ProtocolTCPUDP, "192.168.1.2", 0), nil},
		{"forward gre", forward(ProtocolGRE, "192.168.1.2", 0), nil},
		{"outbound everything", outbound("192.168.1.2", "0.0.0.0/0"), nil},
		{"outbound tcp port", with(outbound("192.168.1.0/24", "10.0.0.0/8"), func(r *FirewallRule) {
			r.Protocol, r.DestinationPort = ProtocolTCP, SinglePort(443)
		}), nil},
		{"outbound drop", with(outbound("192.168.1.0/24", "10.1.0.0/16"), func(r *FirewallRule) { r.Action = ActionDrop }), nil},
		{"outbound udp on any port", with(outbound("192.168.1.0/24", "10.0.0.0/8"), func(r *FirewallRule) { r.Protocol = ProtocolUDP }), nil},
		{"outbound reject tcp on any port", with(outbound("192.168.1.0/24", "10.0.0.0/8"), func(r *FirewallRule) {
			r.Protocol, r.Action = ProtocolTCP, ActionReject
		}), nil},
		{"outbound to one address", outbound("192.168.1.2", "198.51.100.7"), nil},

		{"no name", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Name = "  " }), []string{"name"}},
		{"long name", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Name = strings.Repeat("ä", 65) }), []string{"name"}},
		{"bad direction", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Direction = "sideways" }), []string{"direction"}},
		{"bad action", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Action = "log" }), []string{"action"}},
		{"bad protocol", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Protocol = "sctp" }), []string{"protocol"}},
		{"host accept any", with(hostIn(ProtocolAny, 0), func(r *FirewallRule) { r.DestinationPort = PortRange{} }), []string{"protocol"}},
		{"icmp type on tcp", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.ICMPType = "echo-request" }), []string{"icmpType"}},
		{"unknown icmp type", with(hostIn(ProtocolICMP, 0), func(r *FirewallRule) {
			r.DestinationPort, r.ICMPType = PortRange{}, "ping"
		}), []string{"icmpType"}},
		{"icmp type too high", with(hostIn(ProtocolICMP, 0), func(r *FirewallRule) {
			r.DestinationPort, r.ICMPType = PortRange{}, "8/256"
		}), []string{"icmpType"}},
		{"bad source", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Source = "10.0.0.1/8" }), []string{"source"}},
		{"ipv6 source", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Source = "fd00::1" }), []string{"source"}},
		{"outbound without source", outbound("", "0.0.0.0/0"), []string{"source"}},
		{"outbound from everywhere", outbound("0.0.0.0/0", "10.0.0.0/8"), []string{"source"}},
		{"outbound without destination", outbound("192.168.1.2", ""), []string{"destination"}},
		{"outbound bad destination", outbound("192.168.1.2", "10.0.0.1/8"), []string{"destination"}},
		{"inbound without destination", forward(ProtocolUDP, "", 500), []string{"destination"}},
		{"bad destination", forward(ProtocolUDP, "192.168.1.300", 500), []string{"destination"}},
		{"ipv6 destination", forward(ProtocolUDP, "fd00::2", 500), []string{"destination"}},
		{"inbound /32", forward(ProtocolUDP, "192.168.1.2/32", 500), []string{"destination"}},
		{"inbound to a network", forward(ProtocolUDP, "192.168.1.0/24", 500), []string{"destination"}},
		{"port on esp", with(forward(ProtocolESP, "192.168.1.2", 0), func(r *FirewallRule) { r.DestinationPort = SinglePort(1) }), []string{"destinationPort"}},
		{"source port on icmp", with(hostIn(ProtocolICMP, 0), func(r *FirewallRule) {
			r.DestinationPort, r.SourcePort = PortRange{}, SinglePort(1)
		}), []string{"sourcePort"}},
		{"any-port forward with a public port", with(forward(ProtocolTCP, "192.168.1.2", 0), func(r *FirewallRule) {
			r.PublicPort = SinglePort(80)
		}), []string{"publicPort"}},
		{"any-port host rule with a public port", with(hostIn(ProtocolUDP, 0), func(r *FirewallRule) {
			r.DestinationPort, r.PublicPort = PortRange{}, SinglePort(53)
		}), []string{"publicPort"}},
		{"port zero range", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.DestinationPort = PortRange{From: 0, To: 5} }), []string{"destinationPort"}},
		{"port too high", hostIn(ProtocolTCP, 65536), []string{"destinationPort"}},
		{"reversed range", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.DestinationPort = PortRange{From: 30, To: 20} }), []string{"destinationPort"}},
		{"range too long", with(hostIn(ProtocolTCP, 1), func(r *FirewallRule) { r.DestinationPort = PortRange{From: 1, To: 1001} }), []string{"destinationPort"}},
		{"bad source port", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.SourcePort = SinglePort(70000) }), []string{"sourcePort"}},
		{"public port on outbound", with(outbound("192.168.1.2", "0.0.0.0/0"), func(r *FirewallRule) {
			r.Protocol, r.PublicPort = ProtocolTCP, SinglePort(1)
		}), []string{"publicPort"}},
		{"public range length differs", with(forward(ProtocolTCP, "192.168.1.2", 80), func(r *FirewallRule) {
			r.PublicPort = PortRange{From: 8080, To: 8081}
		}), []string{"publicPort"}},
		{"keep source on outbound rule", with(outbound("192.168.1.2", "0.0.0.0/0"), func(r *FirewallRule) { r.KeepSourceAddress = true }),
			[]string{"keepSourceAddress"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			assertFields(t, err, tt.wantFields)
			assertCoded(t, err)
		})
	}
}

func TestValidateFirewallRules(t *testing.T) {
	tests := []struct {
		name       string
		rules      []FirewallRule
		wantFields []string
	}{
		{"empty list", nil, nil},
		{"IPsec router", []FirewallRule{
			forward(ProtocolUDP, "192.168.1.2", 500), forward(ProtocolUDP, "192.168.1.2", 4500), forward(ProtocolESP, "192.168.1.2", 0),
			outbound("192.168.1.2", "0.0.0.0/0"),
		}, nil},
		{"duplicate id", []FirewallRule{
			with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.ID = "a" }),
			with(hostIn(ProtocolTCP, 23), func(r *FirewallRule) { r.ID = "a" }),
		}, []string{"rules[1].id"}},
		{"id with a colon", []FirewallRule{with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.ID = "tdrule:a" })}, []string{"rules[0].id"}},
		{"id with a space", []FirewallRule{with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.ID = "a b" })}, []string{"rules[0].id"}},
		{"id too long", []FirewallRule{with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.ID = strings.Repeat("a", 65) })}, []string{"rules[0].id"}},
		{"generated and readable ids", []FirewallRule{
			with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.ID = NewID() }),
			with(hostIn(ProtocolTCP, 23), func(r *FirewallRule) { r.ID = "web_2-B" }),
		}, nil},
		{"duplicate match", []FirewallRule{hostIn(ProtocolTCP, 22), with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) {
			r.Action, r.Enabled = ActionDrop, false
		})}, []string{"rules[1].name"}},
		{"duplicate legacy host rules", []FirewallRule{LegacyHostRule(hostIn(ProtocolTCP, 22)), LegacyHostRule(hostIn(ProtocolTCP, 22))},
			[]string{"rules[1].name"}},
		{"legacy host rule beside a rule to an address", []FirewallRule{LegacyHostRule(hostIn(ProtocolTCP, 22)), hostIn(ProtocolTCP, 22)}, nil},
		{"bare and /32 duplicate", []FirewallRule{outbound("192.168.1.2", "0.0.0.0/0"), outbound("192.168.1.2/32", "0.0.0.0/0")},
			[]string{"rules[1].name"}},
		{"invalid rule", []FirewallRule{hostIn(ProtocolTCP, 22), hostIn(ProtocolTCP, 70000)}, []string{"rules[1].destinationPort"}},
		{"conflicts need the host's LAN", []FirewallRule{forward(ProtocolUDP, "192.168.1.2", 500), forward(ProtocolUDP, "192.168.1.3", 500)}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFirewallRules(tt.rules)
			assertFields(t, err, tt.wantFields)
			assertCoded(t, err)
		})
	}
}

func TestCheckInboundDestinations(t *testing.T) {
	ike := forward(ProtocolUDP, "192.168.1.2", 500)
	tests := []struct {
		name       string
		rules      []FirewallRule
		wantFields []string
	}{
		{"rules to the host and to devices", []FirewallRule{
			hostIn(ProtocolTCP, 22), forward(ProtocolTCP, "10.10.4.5", 80), ike, outbound("172.16.0.0/12", "0.0.0.0/0"),
		}, nil},
		{"rule to the host's second address", []FirewallRule{with(forward(ProtocolAny, "10.10.0.1", 0), func(r *FirewallRule) {
			r.Action = ActionDrop
		})}, nil},
		{"host drop and reject", []FirewallRule{
			with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Action = ActionDrop }),
			with(hostIn(ProtocolICMP, 0), func(r *FirewallRule) { r.DestinationPort, r.Action = PortRange{}, ActionReject }),
		}, nil},
		{"host public port differs", []FirewallRule{with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) {
			r.PublicPort = SinglePort(2222)
		})}, []string{"rules[0].publicPort"}},
		{"keep source on a host rule", []FirewallRule{with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) {
			r.KeepSourceAddress = true
		})}, []string{"rules[0].keepSourceAddress"}},
		{"legacy host rule drops", []FirewallRule{with(LegacyHostRule(hostIn(ProtocolTCP, 22)), func(r *FirewallRule) {
			r.Action = ActionDrop
		})}, nil},
		{"forward drops", []FirewallRule{with(ike, func(r *FirewallRule) { r.Action = ActionDrop })}, []string{"rules[0].action"}},
		{"forward any", []FirewallRule{with(forward(ProtocolAny, "192.168.1.2", 0), func(r *FirewallRule) { r.Action = ActionReject })},
			[]string{"rules[0].action", "rules[0].protocol"}},
		{"forward icmp", []FirewallRule{forward(ProtocolICMP, "192.168.1.2", 0)}, []string{"rules[0].protocol"}},
		{"forward outside the LAN", []FirewallRule{forward(ProtocolTCP, "172.16.0.9", 81)}, []string{"rules[0].destination"}},
		{"disabled forward outside the LAN", []FirewallRule{with(forward(ProtocolTCP, "172.16.0.9", 82), func(r *FirewallRule) {
			r.Enabled = false
		})}, nil},
		{"invalid rules are skipped", []FirewallRule{with(forward(ProtocolTCP, "172.16.0.9", 82), func(r *FirewallRule) { r.Name = "" })}, nil},

		{"same forward from two sources", []FirewallRule{
			with(ike, func(r *FirewallRule) { r.Source = "198.51.100.1" }),
			with(ike, func(r *FirewallRule) { r.Source = "198.51.100.2" }),
		}, nil},
		{"overlapping host rules", []FirewallRule{
			hostIn(ProtocolTCP, 22),
			with(hostIn(ProtocolTCP, 20), func(r *FirewallRule) { r.DestinationPort.To, r.Source = 30, "10.0.0.0/8" }),
		}, nil},
		{"host rules to both host addresses", []FirewallRule{hostIn(ProtocolUDP, 500), forward(ProtocolUDP, "10.10.0.1", 500)}, nil},
		{"drop above a forward", []FirewallRule{
			with(hostIn(ProtocolUDP, 500), func(r *FirewallRule) { r.Action = ActionDrop }), ike,
		}, nil},
		{"same port, other protocol", []FirewallRule{ike, forward(ProtocolTCP, "192.168.1.3", 500)}, nil},
		{"forward clashes with host rule", []FirewallRule{hostIn(ProtocolUDP, 500), ike}, []string{"rules[1].destinationPort"}},
		{"forward clashes with legacy host rule", []FirewallRule{LegacyHostRule(hostIn(ProtocolUDP, 500)), ike},
			[]string{"rules[1].destinationPort"}},
		{"forwards to two devices", []FirewallRule{ike, forward(ProtocolUDP, "192.168.1.3", 500)}, []string{"rules[1].destinationPort"}},
		{"tcp+udp overlaps udp", []FirewallRule{ike, with(forward(ProtocolTCPUDP, "192.168.1.3", 400), func(r *FirewallRule) {
			r.DestinationPort = PortRange{From: 400, To: 600}
		})}, []string{"rules[1].destinationPort"}},
		{"public port range overlap", []FirewallRule{ike, with(forward(ProtocolUDP, "192.168.1.3", 9500), func(r *FirewallRule) {
			r.PublicPort = SinglePort(500)
		})}, []string{"rules[1].publicPort"}},
		{"second esp forward", []FirewallRule{forward(ProtocolESP, "192.168.1.2", 0), forward(ProtocolESP, "192.168.1.3", 0)},
			[]string{"rules[1].protocol"}},
		{"any-port forward clashes with a later forward", []FirewallRule{
			forward(ProtocolTCP, "192.168.1.2", 0), forward(ProtocolTCP, "192.168.1.3", 443),
		}, []string{"rules[0].destinationPort", "rules[1].destinationPort"}},
		{"any-port forward clashes with an earlier forward", []FirewallRule{
			with(forward(ProtocolUDP, "192.168.1.3", 9500), func(r *FirewallRule) { r.PublicPort = SinglePort(500) }),
			forward(ProtocolTCPUDP, "192.168.1.2", 0),
		}, []string{"rules[0].publicPort", "rules[1].destinationPort"}},
		{"any-port forward clashes with a host rule", []FirewallRule{
			hostIn(ProtocolTCP, 22), forward(ProtocolTCP, "192.168.1.2", 0),
		}, []string{"rules[0].destinationPort", "rules[1].destinationPort"}},
		{"two any-port forwards to different devices", []FirewallRule{
			forward(ProtocolTCP, "192.168.1.2", 0), forward(ProtocolTCP, "192.168.1.3", 0),
		}, []string{"rules[0].destinationPort", "rules[1].destinationPort"}},
		{"any-port forward to the same device from two sources", []FirewallRule{
			with(forward(ProtocolTCP, "192.168.1.2", 0), func(r *FirewallRule) { r.Source = "198.51.100.1" }),
			with(forward(ProtocolTCP, "192.168.1.2", 0), func(r *FirewallRule) { r.Source = "198.51.100.2" }),
		}, nil},
		{"any-port forward of another protocol", []FirewallRule{forward(ProtocolTCP, "192.168.1.2", 0), ike}, nil},
		{"disabled any-port forward", []FirewallRule{
			with(forward(ProtocolTCP, "192.168.1.2", 0), func(r *FirewallRule) { r.Enabled = false }),
			forward(ProtocolTCP, "192.168.1.3", 443),
		}, nil},
		{"any-port host rule beside a forward", []FirewallRule{
			with(hostIn(ProtocolTCP, 0), func(r *FirewallRule) { r.DestinationPort = PortRange{} }),
			forward(ProtocolTCP, "192.168.1.3", 443),
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckInboundDestinations(tt.rules, testNetwork)
			assertFields(t, err, tt.wantFields)
			assertCoded(t, err)
		})
	}
}

// TestCheckInboundDestinationsFollowsTheHost re-classifies a rule when the
// host's address changes: a drop rule to the former address is no longer
// a rule to the host.
func TestCheckInboundDestinationsFollowsTheHost(t *testing.T) {
	rules := []FirewallRule{with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.Action = ActionDrop })}
	if err := CheckInboundDestinations(rules, testNetwork); err != nil {
		t.Fatalf("drop to the host: %v", err)
	}
	moved := testNetwork
	moved.Addresses = []netip.Addr{netip.MustParseAddr("192.168.1.11")}
	assertFields(t, CheckInboundDestinations(rules, moved), []string{"rules[0].action"})
}

func TestCheckInboundDestinationsCodes(t *testing.T) {
	tests := []struct {
		name    string
		rule    FirewallRule
		network HostNetwork
		field   string
		want    FieldIssue
	}{
		{"outside the LAN", forward(ProtocolUDP, "172.16.0.9", 500),
			HostNetwork{Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
			"rules[0].destination", Issue("firewall_destination_not_in_lan", "subnets", "192.168.1.0/24")},
		{"no LAN", forward(ProtocolUDP, "192.168.1.2", 500), HostNetwork{}, "rules[0].destination", Issue("firewall_lan_not_detected")},
		{"public port to the host", with(hostIn(ProtocolTCP, 22), func(r *FirewallRule) { r.PublicPort = SinglePort(2222) }),
			testNetwork, "rules[0].publicPort", Issue("firewall_public_port_own_address")},
		{"forward drops", with(forward(ProtocolUDP, "192.168.1.2", 500), func(r *FirewallRule) { r.Action = ActionDrop }),
			testNetwork, "rules[0].action", Issue("firewall_forward_accepts_only")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v *ValidationError
			if !errors.As(CheckInboundDestinations([]FirewallRule{tt.rule}, tt.network), &v) {
				t.Fatal("want a validation error")
			}
			if got := v.Issues[tt.field]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("issue = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLegacyHostRule(t *testing.T) {
	rule := LegacyHostRule(hostIn(ProtocolTCP, 22))
	if !rule.IsLegacyHost() || rule.Destination != "" || !rule.TargetsHost(nil) || rule.IsPortForward(nil) {
		t.Fatalf("legacy rule = %+v", rule)
	}
	resolved := rule.WithHostAddress(netip.MustParseAddr(testHost))
	if resolved.IsLegacyHost() || resolved.Destination != testHost || !resolved.TargetsHost(testNetwork.Addresses) {
		t.Errorf("resolved = %+v", resolved)
	}
	if got := rule.WithHostAddress(netip.Addr{}); got.IsLegacyHost() || got.Destination != "" {
		t.Errorf("resolved without an address = %+v", got)
	}
	plain := forward(ProtocolUDP, "192.168.1.2", 500)
	if got := plain.WithHostAddress(netip.MustParseAddr(testHost)); !reflect.DeepEqual(got, plain) {
		t.Errorf("plain rule changed: %+v", got)
	}
	data, err := json.Marshal(rule)
	if err != nil || strings.Contains(string(data), "legacy") || strings.Contains(string(data), "kind") {
		t.Errorf("legacy rule JSON = %s, %v; want no legacy marker", data, err)
	}
}

func TestTargetsHost(t *testing.T) {
	tests := []struct {
		name string
		rule FirewallRule
		want bool
	}{
		{"host address", hostIn(ProtocolTCP, 22), true},
		{"second host address", forward(ProtocolTCP, "10.10.0.1", 22), true},
		{"other device", forward(ProtocolTCP, "192.168.1.2", 22), false},
		{"outbound to the host address", outbound("192.168.1.2", testHost), false},
		{"legacy", LegacyHostRule(forward(ProtocolTCP, "", 22)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.TargetsHost(testNetwork.Addresses); got != tt.want {
				t.Errorf("TargetsHost = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckReservedPorts(t *testing.T) {
	const ui, remote = 8194, 8443
	tests := []struct {
		name       string
		rules      []FirewallRule
		wantFields []string
	}{
		{"unrelated", []FirewallRule{hostIn(ProtocolTCP, 22), outbound("192.168.1.2", "0.0.0.0/0")}, nil},
		{"UI port", []FirewallRule{hostIn(ProtocolTCP, ui)}, []string{"rules[0].destinationPort"}},
		{"UI port in a disabled udp range", []FirewallRule{with(hostIn(ProtocolUDP, 8000), func(r *FirewallRule) {
			r.DestinationPort.To, r.Enabled = 8999, false
		})}, []string{"rules[0].destinationPort"}},
		{"UI port as public port", []FirewallRule{with(forward(ProtocolTCP, "192.168.1.2", 80), func(r *FirewallRule) {
			r.PublicPort = SinglePort(ui)
		})}, []string{"rules[0].publicPort"}},
		{"UI port closed by a drop rule", []FirewallRule{with(hostIn(ProtocolTCP, ui), func(r *FirewallRule) { r.Action = ActionDrop })}, nil},
		{"remote access port", []FirewallRule{hostIn(ProtocolTCPUDP, remote)}, []string{"rules[0].destinationPort"}},
		{"remote access port on udp", []FirewallRule{hostIn(ProtocolUDP, remote)}, nil},
		{"remote access port disabled", []FirewallRule{with(hostIn(ProtocolTCP, remote), func(r *FirewallRule) { r.Enabled = false })}, nil},
		{"any-port host rule", []FirewallRule{with(hostIn(ProtocolTCP, 0), func(r *FirewallRule) { r.DestinationPort = PortRange{} })}, nil},
		{"any-port forward", []FirewallRule{forward(ProtocolTCPUDP, "192.168.1.2", 0)}, nil},
		{"outbound to the UI port", []FirewallRule{with(outbound("192.168.1.2", "0.0.0.0/0"), func(r *FirewallRule) {
			r.Protocol, r.DestinationPort = ProtocolTCP, SinglePort(ui)
		})}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckReservedPorts(tt.rules, ui, remote)
			assertFields(t, err, tt.wantFields)
			assertCoded(t, err)
		})
	}
	if err := CheckReservedPorts([]FirewallRule{hostIn(ProtocolTCP, ui)}, 0, 0); err != nil {
		t.Errorf("ports 0 must not be checked: %v", err)
	}
}

func TestHostNetworkAddress(t *testing.T) {
	if got := testNetwork.Address(); got.String() != testHost {
		t.Errorf("Address = %v, want %s", got, testHost)
	}
	if got := (HostNetwork{}).Address(); got.IsValid() {
		t.Errorf("Address without addresses = %v, want none", got)
	}
}

// assertCoded fails unless every field message of err has an issue code.
func assertCoded(t *testing.T, err error) {
	t.Helper()
	var v *ValidationError
	if !errors.As(err, &v) {
		return
	}
	for field := range v.Fields {
		if v.Issues[field].Code == "" {
			t.Errorf("field %q has no issue code", field)
		}
	}
}

func TestPortRange(t *testing.T) {
	single, rng := SinglePort(22), PortRange{From: 20, To: 30}
	if !single.Equal(PortRange{From: 22, To: 22}) || single.String() != "22" || rng.String() != "20-30" || rng.Len() != 11 {
		t.Errorf("single %v, range %v", single, rng)
	}
	if !rng.Overlaps(single) || rng.Overlaps(SinglePort(31)) || rng.Overlaps(PortRange{}) || (PortRange{}).Contains(0) {
		t.Error("overlap or containment is wrong")
	}
}

func TestParseIPv4Prefix(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.1": "10.0.0.1/32", "10.0.0.0/8": "10.0.0.0/8", "0.0.0.0/0": "0.0.0.0/0"} {
		if got, err := ParseIPv4Prefix(in); err != nil || got.String() != want {
			t.Errorf("ParseIPv4Prefix(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"", "fd00::1", "fd00::/8", "10.0.0.1/8", "nope"} {
		if _, err := ParseIPv4Prefix(in); err == nil {
			t.Errorf("ParseIPv4Prefix(%q) succeeded", in)
		}
	}
}

func TestFirewallJSON(t *testing.T) {
	firewall := Firewall{FirewallSettings: DefaultFirewallSettings(), Rules: []FirewallRule{forward(ProtocolESP, "192.168.1.2", 0)}}
	data, err := json.Marshal(firewall)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"dropInvalid":true`, `"rules":[`, `"destination":"192.168.1.2"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("JSON %s lacks %s", data, want)
		}
	}
	if strings.Contains(string(data), "Port") {
		t.Errorf("unset port ranges are not omitted: %s", data)
	}
}
