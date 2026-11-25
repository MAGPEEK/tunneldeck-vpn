package netguard

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"tunneldeck/internal/domain"
)

// RouteThroughTunnel makes replies from vpnIP leave through the tunnel: a
// default route via DeviceName in table 7194 and a policy rule "from vpnIP
// lookup 7194" at priority 7194. A rule at that priority for another source
// is replaced. The main routing table is never touched. IPv4 only.
func (g *Guard) RouteThroughTunnel(ctx context.Context, vpnIP netip.Addr) error {
	if !vpnIP.Is4() {
		return domain.NewValidationError("vpnIp", "must be an IPv4 address")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, err := g.ip(ctx, "route", "replace", "default", "dev", DeviceName, "table", routingTable); err != nil {
		return fmt.Errorf("route through tunnel: %w", err)
	}
	sources, err := g.policyRuleSources(ctx)
	if err != nil {
		return fmt.Errorf("route through tunnel: %w", err)
	}
	present := false
	for _, source := range sources {
		if source == vpnIP.String() && !present {
			present = true
			continue
		}
		if err := g.deletePolicyRule(ctx, source); err != nil {
			return fmt.Errorf("route through tunnel: %w", err)
		}
	}
	if present {
		return nil
	}
	if _, err := g.ip(ctx, "rule", "add", "from", vpnIP.String(), "lookup", routingTable, "priority", rulePriority); err != nil {
		return fmt.Errorf("route through tunnel: %w", err)
	}
	return nil
}

// ClearTunnelRouting removes the policy rules at priority 7194 and the
// default route of table 7194. Already absent entries are skipped.
func (g *Guard) ClearTunnelRouting(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	sources, err := g.policyRuleSources(ctx)
	if err != nil {
		return fmt.Errorf("clear tunnel routing: %w", err)
	}
	for _, source := range sources {
		if err := g.deletePolicyRule(ctx, source); err != nil {
			return fmt.Errorf("clear tunnel routing: %w", err)
		}
	}
	if _, err := g.ip(ctx, "route", "del", "default", "table", routingTable); err != nil && !isAbsent(err) {
		return fmt.Errorf("clear tunnel routing: %w", err)
	}
	return nil
}

// policyRuleSources returns the "from" selector of every IPv4 policy rule at
// our priority, in listing order.
func (g *Guard) policyRuleSources(ctx context.Context) ([]string, error) {
	out, err := g.ip(ctx, "-4", "rule", "show")
	if err != nil {
		return nil, err
	}
	var sources []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != rulePriority+":" {
			continue
		}
		if source := valueAfter(fields, "from"); source != "" {
			sources = append(sources, source)
		}
	}
	return sources, nil
}

func (g *Guard) deletePolicyRule(ctx context.Context, source string) error {
	_, err := g.ip(ctx, "rule", "del", "from", source, "lookup", routingTable, "priority", rulePriority)
	if err != nil && !isAbsent(err) {
		return err
	}
	return nil
}

func valueAfter(fields []string, key string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key {
			return fields[i+1]
		}
	}
	return ""
}
