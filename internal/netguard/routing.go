package netguard

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"tunneldeck/internal/domain"
)

// RouteThroughTunnel routes through the tunnel: a default route via
// DeviceName in table 7194 and, for a tunnel with an address of its own, a
// policy rule "from vpnIP lookup 7194" at priority 7194 that makes replies
// from vpnIP leave through the tunnel; a rule at that priority for another
// source is replaced. It also installs the policy rules of the installed
// firewall's outbound rules and port forwards (wantedPolicyRules) and one
// rule "to <network> lookup 7194" per remote network, so the host reaches
// the networks behind the VPN; all of them exist only while the tunnel is
// up. Remote networks that overlap the LAN are refused with a
// *domain.ValidationError. Call it on every connected state, as the VPN IP
// can change. The main routing table is never touched. IPv4 only.
//
// localNetworks are LAN subnets the tunnel carries with their own
// addresses (IPsec net-to-net, SPEC §19); vpnIP is then the zero Addr.
// Traffic from them into the tunnel is not masqueraded (a RETURN ahead of
// the masquerade lines of TUNNELDECK-POSTROUTING), the default route of
// table 7194 names the host's LAN address inside them as the source of the
// host's own traffic, no rule exists at 7194, and the remote networks are
// routed at 7099 instead of 7180: ahead of the LAN exclusions at 7100,
// which keep traffic from the host's own addresses in the main table.
func (g *Guard) RouteThroughTunnel(ctx context.Context, vpnIP netip.Addr, remoteNetworks, localNetworks []netip.Prefix) error {
	if err := checkTunnelAddress(vpnIP, localNetworks); err != nil {
		return err
	}
	if err := checkRemoteNetworks(remoteNetworks); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.route(ctx, vpnIP, remoteNetworks, localNetworks); err != nil {
		return fmt.Errorf("route through tunnel: %w", err)
	}
	g.routed = true
	g.remoteNetworks = slices.Clone(remoteNetworks)
	return nil
}

// route applies the routing of RouteThroughTunnel; the caller holds g.mu.
// The LAN is detected first only for a tunnel with local networks, which
// needs it for the source address and the masquerade exemption.
func (g *Guard) route(ctx context.Context, vpnIP netip.Addr, remoteNetworks, localNetworks []netip.Prefix) error {
	var lan []lanAddress
	if len(localNetworks) > 0 {
		detected, err := g.detectLAN(ctx)
		if err != nil {
			return err
		}
		lan = detected
	}
	if err := g.carryLocalNetworks(ctx, localNetworks, lan); err != nil {
		return err
	}
	if _, err := g.ip(ctx, defaultRouteArgs(lan, localNetworks)...); err != nil {
		return err
	}
	listing, err := g.listPolicyRules(ctx)
	if err != nil {
		return err
	}
	if err := g.routeVPNReplies(ctx, vpnIP, listing.vpnSources); err != nil {
		return err
	}
	want, err := g.routedPolicyRules(ctx, remoteNetworks, localNetworks, lan)
	if err != nil {
		return err
	}
	return g.syncPolicyRules(ctx, listing.owned, want)
}

// checkTunnelAddress accepts an IPv4 VPN address without local networks,
// or local networks (IPv4 networks in canonical form that do not cover
// every address) without a VPN address.
func checkTunnelAddress(vpnIP netip.Addr, localNetworks []netip.Prefix) error {
	if len(localNetworks) == 0 {
		if !vpnIP.Is4() {
			return domain.NewFieldError("vpnIp", domain.Issue("vpn_address_invalid"), "must be an IPv4 address")
		}
		return nil
	}
	if vpnIP.IsValid() {
		return domain.NewFieldError("vpnIp", domain.Issue("vpn_address_with_local_networks"),
			"must be empty for a tunnel that carries local networks")
	}
	for i, network := range localNetworks {
		if !network.Addr().Is4() || network != network.Masked() || network.Bits() == 0 {
			entry := strconv.Itoa(i + 1)
			return domain.NewFieldError("localNetworks", domain.Issue("local_network_invalid", "entry", entry),
				"entry "+entry+" must be an IPv4 network in canonical form that does not cover every address")
		}
	}
	return nil
}

// defaultRouteArgs replaces the default route of table 7194. With local
// networks, the host's LAN address inside them is the source hint, so the
// host's own traffic into the tunnel carries an address the other side
// routes back; without such an address the kernel picks one.
func defaultRouteArgs(lan []lanAddress, localNetworks []netip.Prefix) []string {
	args := []string{"route", "replace", "default", "dev", DeviceName, "table", routingTable}
	if source, ok := hostAddressIn(lan, localNetworks); ok {
		args = append(args, "src", source.String())
	}
	return args
}

// hostAddressIn returns the first of the host's LAN addresses that lies in
// one of networks.
func hostAddressIn(lan []lanAddress, networks []netip.Prefix) (netip.Addr, bool) {
	for _, addr := range lan {
		if slices.ContainsFunc(networks, func(n netip.Prefix) bool { return n.Contains(addr.prefix.Addr()) }) {
			return addr.prefix.Addr(), true
		}
	}
	return netip.Addr{}, false
}

// carryLocalNetworks remembers the local networks of the tunnel and, when
// they changed and the firewall is installed, refills the chains: only
// TUNNELDECK-POSTROUTING's content depends on them, and installChain leaves
// every unchanged chain untouched. They are remembered only once the chains
// hold them; after a failed refill the chains are refilled on the next
// call whatever it carries, as the refill may have changed some of them.
// The caller holds g.mu; lan are the host's LAN addresses, detected here
// when not given.
func (g *Guard) carryLocalNetworks(ctx context.Context, localNetworks []netip.Prefix, lan []lanAddress) error {
	if slices.Equal(g.localNetworks, localNetworks) && !g.localNetworksStale {
		return nil
	}
	if g.installed == nil {
		g.localNetworks, g.localNetworksStale = slices.Clone(localNetworks), false
		return nil
	}
	if err := g.installLocalNetworks(ctx, localNetworks, lan); err != nil {
		g.localNetworksStale = true
		return err
	}
	g.localNetworks, g.localNetworksStale = slices.Clone(localNetworks), false
	return nil
}

// installLocalNetworks refills the chains of the installed firewall with
// localNetworks.
func (g *Guard) installLocalNetworks(ctx context.Context, localNetworks []netip.Prefix, lan []lanAddress) error {
	if lan == nil {
		detected, err := g.detectLAN(ctx)
		if err != nil {
			return err
		}
		lan = detected
	}
	caps, err := g.detectCapabilities(ctx)
	if err != nil {
		return err
	}
	reserved := hostPorts{ui: g.installed.uiPort, remoteAccess: g.remoteAccessPort}
	return g.installRuleset(ctx, buildRuleset(g.installed.firewall, reserved, lan, caps, localNetworks), caps)
}

// routeVPNReplies leaves exactly one rule "from vpnIP" at priority 7194, or
// none for a tunnel without a VPN address.
func (g *Guard) routeVPNReplies(ctx context.Context, vpnIP netip.Addr, sources []string) error {
	present := false
	for _, source := range sources {
		if vpnIP.IsValid() && source == vpnIP.String() && !present {
			present = true
			continue
		}
		if err := g.deleteVPNReplyRule(ctx, source); err != nil {
			return err
		}
	}
	if present || !vpnIP.IsValid() {
		return nil
	}
	_, err := g.ip(ctx, "rule", "add", "from", vpnIP.String(), "lookup", routingTable, "priority", strconv.Itoa(vpnReplyPriority))
	return err
}

// routedPolicyRules returns the policy rules of the installed firewall and
// of remoteNetworks. lan is given for a tunnel with local networks;
// otherwise the LAN is detected only when there are any rules.
func (g *Guard) routedPolicyRules(ctx context.Context, remoteNetworks, localNetworks []netip.Prefix, lan []lanAddress) ([]policyRule, error) {
	firewall := g.installedFirewall()
	if len(remoteNetworks) == 0 && !mayNeedPolicyRules(firewall) {
		return nil, nil
	}
	if len(localNetworks) == 0 {
		detected, err := g.detectLAN(ctx)
		if err != nil {
			return nil, err
		}
		lan = detected
	}
	return policyRulesFor(firewall, remoteNetworks, lan, g.replyRouting(), remoteNetworkPriorityFor(localNetworks))
}

// remoteNetworkPriorityFor is the priority of the remote network rules: a
// tunnel with local networks routes the host's own LAN address into the
// tunnel, so its remote networks go ahead of the LAN exclusions.
func remoteNetworkPriorityFor(localNetworks []netip.Prefix) int {
	if len(localNetworks) > 0 {
		return localRemoteNetworkPriority
	}
	return remoteNetworkPriority
}

// installedFirewall returns the installed firewall, or none.
func (g *Guard) installedFirewall() domain.Firewall {
	if g.installed == nil {
		return domain.Firewall{}
	}
	return g.installed.firewall
}

// ClearTunnelRouting removes every policy rule netguard owns (priorities
// 7099–7194, remote networks included) and the default route of table
// 7194, and ends the masquerade exemption of local networks. Already
// absent entries are skipped. The firewall chains stay, so outbound
// traffic is dropped instead of leaving through the normal internet
// connection (kill switch).
func (g *Guard) ClearTunnelRouting(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routed, g.remoteNetworks = false, nil
	listing, err := g.listPolicyRules(ctx)
	if err != nil {
		return fmt.Errorf("clear tunnel routing: %w", err)
	}
	if err := g.syncPolicyRules(ctx, listing.owned, nil); err != nil {
		return fmt.Errorf("clear tunnel routing: %w", err)
	}
	for _, source := range listing.vpnSources {
		if err := g.deleteVPNReplyRule(ctx, source); err != nil {
			return fmt.Errorf("clear tunnel routing: %w", err)
		}
	}
	if _, err := g.ip(ctx, "route", "del", "default", "table", routingTable); err != nil && !isAbsent(err) {
		return fmt.Errorf("clear tunnel routing: %w", err)
	}
	if err := g.carryLocalNetworks(ctx, nil, nil); err != nil {
		return fmt.Errorf("clear tunnel routing: %w", err)
	}
	return nil
}

func (g *Guard) deleteVPNReplyRule(ctx context.Context, source string) error {
	_, err := g.ip(ctx, "rule", "del", "from", source, "lookup", routingTable, "priority", strconv.Itoa(vpnReplyPriority))
	if err != nil && !isAbsent(err) {
		return err
	}
	return nil
}
