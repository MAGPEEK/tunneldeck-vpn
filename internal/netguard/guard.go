package netguard

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"sync"

	"tunneldeck/internal/domain"
)

// DeviceName is the tunnel interface every VPN driver must create.
const DeviceName = "tdvpn0"

const (
	routingTable = "7194"
	rulePriority = "7194"
)

// Guard installs the host-protection chains and the tunnel policy routing.
// All methods are safe for concurrent use; calls are serialised.
type Guard struct {
	runner     CommandRunner
	root       fs.FS // file system the self-check looks for the TUN device in
	preference BackendPreference

	mu sync.Mutex
	// backend is the detected iptables backend, used for the process
	// lifetime; nil until detected.
	backend    *Backend
	stateMatch []string // detected match for ESTABLISHED,RELATED, nil until detected
	// remoteAccessPort is the TCP port of the HTTPS listener that tunnel
	// traffic may reach, 0 while remote access is off.
	remoteAccessPort int
	// installed holds the arguments of the last successful InstallFirewall,
	// nil while the firewall is not installed.
	installed *installation
}

type installation struct {
	rules  []domain.HostAccessRule
	uiPort int
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
// lock) and args.
func (g *Guard) iptables(ctx context.Context, args ...string) (string, error) {
	backend, err := g.detectBackend(ctx)
	if err != nil {
		return "", err
	}
	return g.runner.Run(ctx, backend.Binary, append([]string{"-w"}, args...)...)
}

// listRules returns the "-A ..." lines of iptables -S for chain.
func (g *Guard) listRules(ctx context.Context, chain string) ([]string, error) {
	out, err := g.iptables(ctx, "-S", chain)
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
