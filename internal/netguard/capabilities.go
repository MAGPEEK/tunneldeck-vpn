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
	// extConnmark is the CONNMARK target with the connmark match in the
	// mangle table (iptable_mangle, xt_connmark). Without it the replies of
	// port forwards are routed by source address (replyBySource).
	extConnmark extension = "CONNMARK"
)

// extensionProbeChain is created, given the probe lines of its table and
// deleted to probe the extensions.
const extensionProbeChain = "TUNNELDECK-EXT-PROBE"

// extensionProbe is a line that needs ext, written as netguard uses it in
// table. An extension with several lines is present when all of them
// work.
type extensionProbe struct {
	ext   extension
	table table
	rule  []string
}

var extensionProbes = []extensionProbe{
	{extComment, filterTable, fixedRule("probe", []string{"-j", "RETURN"})},
	{extHashlimit, filterTable, slices.Concat(synFloodRate.hashlimitAbove("td-probe"), []string{"-j", "RETURN"})},
	{extLimit, filterTable, slices.Concat(synFloodRate.limitWithin(), []string{"-j", "RETURN"})},
	{extTCPMSS, filterTable, mssClampRule},
	{extReject, filterTable, []string{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"}},
	{extConnmark, mangleTable, replyMarkRule},
	{extConnmark, mangleTable, replyRestoreRule},
}

// probeTables are the tables of extensionProbes in probing order. The
// filter table must work; a kernel may lack the mangle table.
var probeTables = []table{filterTable, mangleTable}

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

// replyRouting tells how the replies of port forwards find the tunnel
// with c.
func (c capabilities) replyRouting() replyRouting {
	if c.has[extConnmark] {
		return replyByMark
	}
	return replyBySource
}

// replyRouting tells how the replies of port forwards find the tunnel with
// the probed capabilities; by source until they are probed, which every
// firewall installation does first.
func (g *Guard) replyRouting() replyRouting {
	if g.caps == nil {
		return replyBySource
	}
	return g.caps.replyRouting()
}

// detectCapabilities probes the extensions once per backend, on a
// temporary chain per table. A probe chain left over from a crash is
// reused and deleted. Only a failing probe line, or a mangle table that
// cannot hold the probe chain, counts as "missing"; failing to create the
// filter probe chain or to delete a probe chain is an error, and nothing
// is cached.
func (g *Guard) detectCapabilities(ctx context.Context) (capabilities, error) {
	backend, err := g.detectBackend(ctx)
	if err != nil {
		return capabilities{}, err
	}
	if g.caps != nil && g.caps.backend == backend.Binary {
		return *g.caps, nil
	}
	has := make(map[extension]bool, len(extensionProbes))
	for _, t := range probeTables {
		if err := g.probeExtensions(ctx, t, has); err != nil {
			return capabilities{}, fmt.Errorf("probe the iptables extensions: %w", err)
		}
	}
	g.caps = &capabilities{backend: backend.Binary, has: has}
	return *g.caps, nil
}

// probeExtensions records in has which extensions of table t work.
func (g *Guard) probeExtensions(ctx context.Context, t table, has map[extension]bool) error {
	probes := slices.DeleteFunc(slices.Clone(extensionProbes), func(p extensionProbe) bool { return p.table != t })
	if _, err := g.iptables(ctx, t, "-N", extensionProbeChain); err != nil && !isAlreadyExists(err) {
		if t == filterTable {
			return err
		}
		for _, probe := range probes {
			has[probe.ext] = false
		}
		return nil
	}
	for _, probe := range probes {
		works := g.appendRaw(ctx, t, extensionProbeChain, probe.rule) == nil
		previous, probed := has[probe.ext]
		has[probe.ext] = works && (previous || !probed)
	}
	return g.removeChain(ctx, t, extensionProbeChain)
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
