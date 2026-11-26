package netguard

import (
	"context"
	"fmt"
	"slices"

	"tunneldeck/internal/domain"
)

// extension is an optional iptables match or target: a kernel module
// (xt_<name> for iptables-legacy) that minimal kernels, such as those of
// some NAS systems, may lack. An optional protection never keeps the
// firewall from installing; it falls back or is left out (SPEC §16.1a),
// and without REJECT reject rules drop instead.
// Connection tracking has its own fallback (appendRule).
type extension string

const (
	extComment   extension = "comment"
	extHashlimit extension = "hashlimit"
	extLimit     extension = "limit"
	extTCPMSS    extension = "TCPMSS"
	extReject    extension = "REJECT"
)

// extensionProbeChain is created, given one line per extension and
// deleted to probe the extensions.
const extensionProbeChain = "TUNNELDECK-EXT-PROBE"

// extensionProbe is a line that needs ext, written as netguard uses it.
type extensionProbe struct {
	ext  extension
	rule []string
}

var extensionProbes = []extensionProbe{
	{extComment, fixedRule("probe", []string{"-j", "RETURN"})},
	{extHashlimit, slices.Concat(synFloodRate.hashlimitAbove("td-probe"), []string{"-j", "RETURN"})},
	{extLimit, slices.Concat(synFloodRate.limitWithin(), []string{"-j", "RETURN"})},
	{extTCPMSS, mssClampRule},
	{extReject, []string{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"}},
}

// capabilities are the extensions the backend binary has.
type capabilities struct {
	backend string
	has     map[extension]bool
}

// support tells how the global protections and the counters work with c.
// The ping limit is one global rate either way, so the limit match
// provides it fully; the SYN flood protection loses its per-source rate.
func (c capabilities) support() domain.ProtectionSupport {
	synFlood, ping := domain.ProtectionNone, domain.ProtectionNone
	switch {
	case c.has[extHashlimit]:
		synFlood, ping = domain.ProtectionFull, domain.ProtectionFull
	case c.has[extLimit]:
		synFlood, ping = domain.ProtectionGlobal, domain.ProtectionFull
	}
	mssClamp := domain.ProtectionNone
	if c.has[extTCPMSS] {
		mssClamp = domain.ProtectionFull
	}
	return domain.ProtectionSupport{
		SYNFlood: synFlood, Ping: ping, MSSClamp: mssClamp, RuleCounters: c.has[extComment],
	}
}

// detectCapabilities probes the extensions once per backend, on a
// temporary chain. A probe chain left over from a crash is reused and
// deleted. Only a failing probe line counts as "missing"; failing to
// create or delete the chain is an error, and nothing is cached.
func (g *Guard) detectCapabilities(ctx context.Context) (capabilities, error) {
	backend, err := g.detectBackend(ctx)
	if err != nil {
		return capabilities{}, err
	}
	if g.caps != nil && g.caps.backend == backend.Binary {
		return *g.caps, nil
	}
	has, err := g.probeExtensions(ctx)
	if err != nil {
		return capabilities{}, fmt.Errorf("probe the iptables extensions: %w", err)
	}
	g.caps = &capabilities{backend: backend.Binary, has: has}
	return *g.caps, nil
}

func (g *Guard) probeExtensions(ctx context.Context) (map[extension]bool, error) {
	if _, err := g.iptables(ctx, filterTable, "-N", extensionProbeChain); err != nil && !isAlreadyExists(err) {
		return nil, err
	}
	has := make(map[extension]bool, len(extensionProbes))
	for _, probe := range extensionProbes {
		has[probe.ext] = g.appendRaw(ctx, filterTable, extensionProbeChain, probe.rule) == nil
	}
	if err := g.removeChain(ctx, filterTable, extensionProbeChain); err != nil {
		return nil, err
	}
	return has, nil
}

// ProtectionSupport tells which global protections, and whether the hit
// counters, work on the host's kernel (SPEC §16.1a).
func (g *Guard) ProtectionSupport(ctx context.Context) (domain.ProtectionSupport, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	caps, err := g.detectCapabilities(ctx)
	if err != nil {
		return domain.ProtectionSupport{}, err
	}
	return caps.support(), nil
}
