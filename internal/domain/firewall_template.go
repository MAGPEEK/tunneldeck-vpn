package domain

import (
	"net/netip"
)

// HostNetwork is the host's LAN as detected at run time: the address the
// UI shows as "This device", the LAN subnets port forwards must target,
// and whether IPv4 forwarding is on (SPEC §16.1). Zero values mean "not
// detected".
type HostNetwork struct {
	Address   netip.Addr
	Subnets   []netip.Prefix
	IPForward bool
}

// IPsec ports of the "IPsec device" template (SPEC §16.2).
const (
	portIKE  = 500
	portNATT = 4500
)

// ipsecRuleSuffixes are appended to the template name; the longest one
// bounds the name's length.
const (
	suffixIKE         = ": IKE"
	suffixNATT        = ": NAT-T"
	suffixESP         = ": ESP"
	suffixOutboundUDP = ": outbound UDP"
	suffixOutboundESP = ": outbound ESP"
)

// MaxIPsecTemplateNameLength is the longest name IPsecDeviceRules accepts,
// so every generated rule name stays within MaxFirewallRuleNameLength.
const MaxIPsecTemplateNameLength = MaxFirewallRuleNameLength - len(suffixOutboundUDP)

// IPsecDeviceRules returns the rules of the "IPsec device" template (SPEC
// §16.2) for a LAN device that terminates IPsec using the tunnel's public
// address: inbound UDP 500, UDP 4500 and ESP forwarded to device with the
// source address kept, and outbound UDP and ESP from device into the
// tunnel. Without peers the inbound rules accept any source and the
// outbound rules go to 0.0.0.0/0; with peers the five rules are repeated
// for each peer, which becomes the inbound source and the outbound
// destination. The rules are enabled and carry no IDs. The caller
// validates name, device and peers.
func IPsecDeviceRules(name string, device netip.Addr, peers []netip.Prefix) []FirewallRule {
	if len(peers) == 0 {
		return ipsecRulesForPeer(name, device, "", "0.0.0.0/0")
	}
	rules := make([]FirewallRule, 0, 5*len(peers))
	for _, peer := range peers {
		rules = append(rules, ipsecRulesForPeer(name, device, peer.String(), peer.String())...)
	}
	return rules
}

func ipsecRulesForPeer(name string, device netip.Addr, source, remote string) []FirewallRule {
	target := FirewallDestination{Kind: DestinationAddress, CIDR: device.String()}
	inbound := func(suffix string, protocol FirewallProtocol, port int) FirewallRule {
		rule := FirewallRule{
			Name: name + suffix, Direction: DirectionInbound, Action: ActionAccept, Protocol: protocol,
			Source: source, Destination: target, KeepSourceAddress: true, Enabled: true,
		}
		if port != 0 {
			rule.DestinationPort = SinglePort(port)
		}
		return rule
	}
	outbound := func(suffix string, protocol FirewallProtocol) FirewallRule {
		return FirewallRule{
			Name: name + suffix, Direction: DirectionOutbound, Action: ActionAccept, Protocol: protocol,
			Source: device.String(), Destination: FirewallDestination{Kind: DestinationAddress, CIDR: remote}, Enabled: true,
		}
	}
	return []FirewallRule{
		inbound(suffixIKE, ProtocolUDP, portIKE),
		inbound(suffixNATT, ProtocolUDP, portNATT),
		inbound(suffixESP, ProtocolESP, 0),
		outbound(suffixOutboundUDP, ProtocolUDP),
		outbound(suffixOutboundESP, ProtocolESP),
	}
}
