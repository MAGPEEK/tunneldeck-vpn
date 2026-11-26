package netguard

import (
	"context"
	"errors"
	"fmt"

	"tunneldeck/internal/domain"
)

// InstallFirewall creates or updates the four chains of SPEC §16 and puts
// their jumps at position 1 of the built-in chains: TUNNELDECK-INPUT
// (filter INPUT, -i tdvpn0) drops TCP to uiPort, then accepts inbound
// rules to the host;
// TUNNELDECK-FORWARD (filter FORWARD, -i/-o tdvpn0 plus one kill-switch
// jump per outbound source and destination) accepts port forwards and
// outbound rules and drops outbound traffic that would bypass the tunnel;
// TUNNELDECK-PREROUTING (nat PREROUTING, -i tdvpn0) translates port
// forwards, except uiPort and the remote-access port when a forward covers
// every TCP port; TUNNELDECK-POSTROUTING (nat POSTROUTING) masquerades port
// forwards on the LAN side and outbound traffic on the tunnel. While the
// kernel has the CONNMARK target, TUNNELDECK-MANGLE-PRE (mangle
// PREROUTING, every packet) marks the connections from the tunnel and
// restores that mark on their replies, as long as a port forward exists;
// the policy rule at 7191 routes those replies (replyByMark). The global
// settings add their rules at the top of the filter chains (buildRuleset).
// A protection whose kernel module is missing never fails the
// installation (capabilities.go): the rate limits fall back from hashlimit
// to one global limit in TUNNELDECK-LIMIT, which the filter chains' SYN
// and ping lines jump to, or are left out like MSS clamping; without
// CONNMARK the mangle table is never touched and replies are routed by
// source address (replyBySource).
// Rules are installed in list order. Every content line carries a comment
// tag (tags.go). Calling it again with the same configuration yields the
// same state and leaves every chain whose content is unchanged untouched,
// so its counters persist (RuleCounters).
//
// Refill strategy ("append, then trim", installChain): every filter chain
// always ends with DROP before its jumps exist, and misplaced jumps are
// moved behind temporary DROP guards, so a failure leaves DROP in place;
// the other chains are still attempted and all errors are returned.
//
// The LAN is detected anew on every call: an inbound rule to one of the
// host's own LAN addresses opens a service on the host, any other one is
// a port forward, whose target must lie in a LAN subnet while enabled
// (domain.CheckInboundDestinations). While a remote-access port is set
// (SetRemoteAccessPort), TUNNELDECK-INPUT also accepts TCP to that port.
// While the tunnel is routed (RouteThroughTunnel), the policy rules follow
// the new rules at once.
func (g *Guard) InstallFirewall(ctx context.Context, firewall domain.Firewall, uiPort int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := validateFirewall(firewall.Rules, uiPort, g.remoteAccessPort); err != nil {
		return err
	}
	return g.install(ctx, firewall, uiPort)
}

// SetRemoteAccessPort sets the TCP port of the HTTPS listener that tunnel
// traffic may reach (SPEC §8.1); 0 closes it. An installed firewall is
// re-installed at once with the configuration of its last installation.
// Otherwise the port is opened by the next InstallFirewall, which precedes
// every tunnel. The port must never be the web UI port nor a public port
// of an enabled inbound TCP rule.
func (g *Guard) SetRemoteAccessPort(ctx context.Context, port int) error {
	if port != 0 && (port < domain.MinPort || port > domain.MaxPort) {
		return domain.NewFieldError("remoteAccess.port", domain.Issue("port_invalid"), "must be between 1 and 65535")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.installed == nil {
		g.remoteAccessPort = port
		return nil
	}
	if port != 0 && port == g.installed.uiPort {
		return uiPortConflict()
	}
	if err := domain.CheckReservedPorts(g.installed.firewall.Rules, 0, port); err != nil {
		return err
	}
	g.remoteAccessPort = port
	return g.install(ctx, g.installed.firewall, g.installed.uiPort)
}

// validateFirewall applies the checks that need no command: the rules on
// their own and the reserved ports.
func validateFirewall(rules []domain.FirewallRule, uiPort, remoteAccessPort int) error {
	v := &domain.ValidationError{}
	for _, err := range []error{
		domain.ValidateFirewallRules(rules),
		domain.CheckReservedPorts(rules, uiPort, remoteAccessPort),
	} {
		var fields *domain.ValidationError
		switch {
		case errors.As(err, &fields):
			v.Merge("", fields)
		case err != nil:
			return err
		}
	}
	return v.OrNil()
}

// install fills all chains and remembers the configuration on success. The
// caller holds g.mu and has validated the rules.
func (g *Guard) install(ctx context.Context, firewall domain.Firewall, uiPort int) error {
	if g.remoteAccessPort != 0 && g.remoteAccessPort == uiPort {
		return uiPortConflict()
	}
	caps, err := g.detectCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("install firewall: %w", err)
	}
	lan, err := g.detectLAN(ctx)
	if err != nil {
		return fmt.Errorf("install firewall: %w", err)
	}
	if err := domain.CheckInboundDestinations(firewall.Rules, hostNetwork(lan)); err != nil {
		return err
	}
	if err := g.installRuleset(ctx, buildRuleset(firewall, hostPorts{ui: uiPort, remoteAccess: g.remoteAccessPort}, lan, caps, g.localNetworks), caps); err != nil {
		return err
	}
	g.installed = &installation{firewall: cloneFirewall(firewall), uiPort: uiPort}
	if !g.routed {
		return nil
	}
	if err := g.syncInstalledPolicy(ctx, lan); err != nil {
		return fmt.Errorf("install firewall: update policy routing: %w", err)
	}
	return nil
}

// installRuleset installs every chain of rs, untagged without the comment
// match, and then removes TUNNELDECK-LIMIT when the kernel would use it
// but rs no longer does; its jumps are gone by then. All chains are
// attempted; the errors are joined.
func (g *Guard) installRuleset(ctx context.Context, rs ruleset, caps capabilities) error {
	tagged := caps.has[extComment]
	var errs []error
	for _, chain := range rs.chainContent() {
		content := chain.content
		if !tagged {
			content = untaggedContent(content)
		}
		errs = append(errs, g.installChain(ctx, chain.spec, content, tagged))
	}
	if rs.limit == nil && usesLimitChain(caps) {
		if err := g.removeChain(ctx, limitSpec.table, limitSpec.name); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", limitSpec.name, err))
		}
	}
	return errors.Join(errs...)
}

// syncInstalledPolicy brings the policy rules of a routed tunnel in line
// with the newly installed firewall; the remote networks stay.
func (g *Guard) syncInstalledPolicy(ctx context.Context, lan []lanAddress) error {
	want, err := policyRulesFor(g.installed.firewall, g.remoteNetworks, lan, g.replyRouting(), remoteNetworkPriorityFor(g.localNetworks))
	if err != nil {
		return err
	}
	listing, err := g.listPolicyRules(ctx)
	if err != nil {
		return err
	}
	return g.syncPolicyRules(ctx, listing.owned, want)
}

// RemoveFirewall deletes every jump to the four chains, then the chains,
// TUNNELDECK-LIMIT, which their lines may reach, and, while the kernel can
// mark replies, TUNNELDECK-MANGLE-PRE. Objects that are already absent are
// skipped.
func (g *Guard) RemoveFirewall(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.installed = nil
	specs := append(allChainSpecs(nil), limitSpec)
	if g.replyRouting() == replyByMark {
		specs = append(specs, mangleSpec)
	}
	for _, spec := range specs {
		if err := g.removeChainAndJumps(ctx, spec); err != nil {
			return fmt.Errorf("remove firewall: %w", err)
		}
	}
	return nil
}

func cloneFirewall(f domain.Firewall) domain.Firewall {
	f.Rules = append([]domain.FirewallRule(nil), f.Rules...)
	return f
}

// uiPortConflict reports a remote-access port equal to the web UI port.
func uiPortConflict() error {
	return domain.NewFieldError("remoteAccess.port", domain.Issue("remote_access_ui_port"), "must not be the web UI port")
}
