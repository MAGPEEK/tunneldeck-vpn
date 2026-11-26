package netguard

import (
	"context"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"sync"

	"tunneldeck/internal/domain"
)

// DeviceName is the tunnel interface every VPN driver must create.
const DeviceName = "tdvpn0"

// routingTable is the policy routing table whose default route is the
// tunnel. The main table is never modified.
const routingTable = "7194"

// Guard installs the firewall chains and the tunnel policy routing. All
// methods are safe for concurrent use; calls are serialised.
type Guard struct {
	runner     CommandRunner
	root       fs.FS // file system the self-check reads /dev and /proc from
	preference BackendPreference

	mu sync.Mutex
	// backend is the detected iptables backend, used for the process
	// lifetime; nil until detected.
	backend *Backend
	ct      ctMatchKind // detected connection-tracking match
	// caps are the optional extensions of the backend, nil until probed.
	caps *capabilities
	// remoteAccessPort is the TCP port of the HTTPS listener that tunnel
	// traffic may reach, 0 while remote access is off.
	remoteAccessPort int
	// installed holds the arguments of the last successful InstallFirewall,
	// nil while the firewall is not installed.
	installed *installation
	// routed is true between a successful RouteThroughTunnel and the next
	// ClearTunnelRouting: the policy rules of the firewall are in place.
	routed bool
	// remoteNetworks are the networks behind the VPN routed through the
	// tunnel while routed is true.
	remoteNetworks []netip.Prefix
}

type installation struct {
	firewall domain.Firewall
	uiPort   int
}

// New returns a Guard that runs every command through runner.
func New(runner CommandRunner, opts ...Option) *Guard {
	g := &Guard{runner: runner, root: os.DirFS("/"), preference: BackendAuto}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// iptables runs the detected iptables binary with -w (wait for the xtables
// lock), the table unless it is filter, and args.
func (g *Guard) iptables(ctx context.Context, t table, args ...string) (string, error) {
	backend, err := g.detectBackend(ctx)
	if err != nil {
		return "", err
	}
	prefix := []string{"-w"}
	if t != filterTable {
		prefix = append(prefix, "-t", string(t))
	}
	return g.runner.Run(ctx, backend.Binary, append(prefix, args...)...)
}

// listRules returns the "-A ..." lines of iptables -S for chain.
func (g *Guard) listRules(ctx context.Context, t table, chain string) ([]string, error) {
	out, err := g.iptables(ctx, t, "-S", chain)
	if err != nil {
		return nil, err
	}
	var rules []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules, nil
}

// ip runs the ip tool with args.
func (g *Guard) ip(ctx context.Context, args ...string) (string, error) {
	return g.runner.Run(ctx, "ip", args...)
}
