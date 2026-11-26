package netguard

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"tunneldeck/internal/domain"
)

// RouteThroughTunnel makes replies from vpnIP leave through the tunnel: a
// default route via DeviceName in table 7194 and a policy rule "from vpnIP
// lookup 7194" at priority 7194. A rule at that priority for another source
// is replaced. It also installs the policy rules of the installed
// firewall's outbound rules and port forwards (wantedPolicyRules) and one
// rule "to <network> lookup 7194" at priority 7180 per remote network, so
// the host reaches the networks behind the VPN; all of them exist only
// while the tunnel is up. Remote networks that overlap the LAN are refused
// with a *domain.ValidationError. Call it on every connected state, as the
// VPN IP can change. The main routing table is never touched. IPv4 only.
func (g *Guard) RouteThroughTunnel(ctx context.Context, vpnIP netip.Addr, remoteNetworks []netip.Prefix) error {
	if !vpnIP.Is4() {
		return domain.NewFieldError("vpnIp", domain.Issue("vpn_address_invalid"), "must be an IPv4 address")
	}
	if err := checkRemoteNetworks(remoteNetworks); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, err := g.ip(ctx, "route", "replace", "default", "dev", DeviceName, "table", routingTable); err != nil {
		return fmt.Errorf("route through tunnel: %w", err)
	}
	listing, err := g.listPolicyRules(ctx)
	if err != nil {
		return fmt.Errorf("route through tunnel: %w", err)
	}
	if err := g.routeVPNReplies(ctx, vpnIP, listing.vpnSources); err != nil {
		return fmt.Errorf("route through tunnel: %w", err)
	}
	want, err := g.routedPolicyRules(ctx, remoteNetworks)
	if err == nil {
		err = g.syncPolicyRules(ctx, listing.owned, want)
	}
	if err != nil {
		return fmt.Errorf("route through tunnel: %w", err)
	}
	g.routed = true
	g.remoteNetworks = slices.Clone(remoteNetworks)
	return nil
}

// routeVPNReplies leaves exactly one rule "from vpnIP" at priority 7194.
func (g *Guard) routeVPNReplies(ctx context.Context, vpnIP netip.Addr, sources []string) error {
	present := false
	for _, source := range sources {
		if source == vpnIP.String() && !present {
			present = true
			continue
		}
		if err := g.deleteVPNReplyRule(ctx, source); err != nil {
			return err
		}
	}
	if present {
		return nil
	}
	_, err := g.ip(ctx, "rule", "add", "from", vpnIP.String(), "lookup", routingTable, "priority", strconv.Itoa(vpnReplyPriority))
	return err
}

// routedPolicyRules returns the policy rules of the installed firewall and
// of remoteNetworks, detecting the LAN only when there are any.
func (g *Guard) routedPolicyRules(ctx context.Context, remoteNetworks []netip.Prefix) ([]policyRule, error) {
	firewall := g.installedFirewall()
	if len(remoteNetworks) == 0 && !mayNeedPolicyRules(firewall) {
		return nil, nil
	}
	lan, err := g.detectLAN(ctx)
	if err != nil {
		return nil, err
	}
	return policyRulesFor(firewall, remoteNetworks, lan, g.replyRouting())
}

// installedFirewall returns the installed firewall, or none.
func (g *Guard) installedFirewall() domain.Firewall {
	if g.installed == nil {
		return domain.Firewall{}
	}
	return g.installed.firewall
}

// ClearTunnelRouting removes every policy rule netguard owns (priorities
// 7100–7194, remote networks included) and the default route of table
// 7194. Already absent entries are skipped. The firewall chains stay, so
// outbound traffic is dropped instead of leaving through the normal
// internet connection (kill switch).
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
	return nil
}

func (g *Guard) deleteVPNReplyRule(ctx context.Context, source string) error {
	_, err := g.ip(ctx, "rule", "del", "from", source, "lookup", routingTable, "priority", strconv.Itoa(vpnReplyPriority))
	if err != nil && !isAbsent(err) {
		return err
	}
	return nil
}
