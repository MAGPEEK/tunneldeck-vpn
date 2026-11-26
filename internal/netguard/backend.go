package netguard

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// BackendPreference selects the iptables backend: detected from the host's
// existing rules (BackendAuto, the default) or forced.
type BackendPreference string

// Backend preferences, matching the values of TUNNELDECK_IPTABLES.
const (
	BackendAuto   BackendPreference = "auto"
	BackendNft    BackendPreference = "nft"
	BackendLegacy BackendPreference = "legacy"
)

// Backend is the iptables binary netguard uses and why it was chosen.
type Backend struct {
	Binary string
	// Reason explains the choice in English, for the self-check and the log.
	Reason string
	// Mixed is true when both backends hold host rules: the rules of the
	// backend not chosen keep filtering traffic as well.
	Mixed bool
	// choice is Reason as a self-check detail code with its parameters.
	choice backendChoice
}

// backendChoice is why a backend was chosen: a self-check detail code and
// the values its text needs.
type backendChoice struct {
	code        string
	kind        xtablesKind
	nftRules    int
	legacyRules int
}

// newBackend is binary, chosen for c.
func newBackend(binary string, c backendChoice) Backend {
	return Backend{Binary: binary, Reason: c.reason(), Mixed: c.code == detailIptablesMixed, choice: c}
}

// with is c for code, choosing kind.
func (c backendChoice) with(code string, kind xtablesKind) backendChoice {
	c.code, c.kind = code, kind
	return c
}

// reason explains c in English.
func (c backendChoice) reason() string {
	switch c.code {
	case detailIptablesForced:
		return fmt.Sprintf("forced to %s by configuration", c.kind)
	case detailIptablesOnlyNft:
		return "only the nf_tables backend works"
	case detailIptablesOnlyLegacy:
		return "only the legacy backend works"
	case detailIptablesMixed:
		return fmt.Sprintf("host rules in both backends (nf_tables %d, legacy %d), chose %s; the other backend's rules still apply",
			c.nftRules, c.legacyRules, c.kind)
	case detailIptablesRulesLegacy:
		return fmt.Sprintf("host rules only in legacy (%d)", c.legacyRules)
	case detailIptablesRulesNft:
		return fmt.Sprintf("host rules only in nf_tables (%d)", c.nftRules)
	}
	return "no host rules in either backend, nf_tables preferred"
}

// params are the values of c's detail text; binary is the chosen binary.
func (c backendChoice) params(binary string) map[string]string {
	return map[string]string{
		"binary":      binary,
		"backend":     string(c.kind),
		"nftRules":    strconv.Itoa(c.nftRules),
		"legacyRules": strconv.Itoa(c.legacyRules),
	}
}

// xtablesKind is an iptables backend as "iptables -V" names it.
type xtablesKind string

const (
	kindNft    xtablesKind = "nf_tables"
	kindLegacy xtablesKind = "legacy"
)

// dedicatedBinary is each backend's own binary. plainBinary may be either
// backend, depending on how the image links it.
var dedicatedBinary = map[xtablesKind]string{
	kindNft:    "iptables-nft",
	kindLegacy: "iptables-legacy",
}

const plainBinary = "iptables"

// ownChainPrefix marks TunnelDeck's chains and the jumps to them, which do
// not count as host rules.
const ownChainPrefix = "TUNNELDECK-"

// probe is a working binary of one backend and the number of host rules it
// lists.
type probe struct {
	binary string
	kind   xtablesKind
	rules  int
}

// Option configures a Guard.
type Option func(*Guard)

// WithBackend sets the backend preference; the default is BackendAuto.
func WithBackend(preference BackendPreference) Option {
	return func(g *Guard) { g.preference = preference }
}

// Backend returns the detected backend; ok is false until a detection has
// succeeded.
func (g *Guard) Backend() (backend Backend, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.backend == nil {
		return Backend{}, false
	}
	return *g.backend, true
}

// detectBackend returns the cached backend or chooses one. Only success is
// cached, so a host fixed while TunnelDeck runs is picked up by the next
// call.
func (g *Guard) detectBackend(ctx context.Context) (Backend, error) {
	if g.backend != nil {
		return *g.backend, nil
	}
	backend, err := g.chooseBackend(ctx)
	if err != nil {
		return Backend{}, err
	}
	g.backend = &backend
	return backend, nil
}

func (g *Guard) chooseBackend(ctx context.Context) (Backend, error) {
	switch g.preference {
	case BackendNft:
		return g.forcedBackend(ctx, kindNft)
	case BackendLegacy:
		return g.forcedBackend(ctx, kindLegacy)
	}
	return g.autoBackend(ctx)
}

// forcedBackend uses kind if any binary of it works.
func (g *Guard) forcedBackend(ctx context.Context, kind xtablesKind) (Backend, error) {
	found, attempts := g.probeKinds(ctx, []xtablesKind{kind})
	if len(found) == 0 {
		return Backend{}, &NoBackendError{Attempts: attempts}
	}
	return newBackend(found[0].binary, backendChoice{code: detailIptablesForced, kind: kind}), nil
}

// autoBackend shares the backend with the host's firewall: the one that
// already holds host rules wins, the one with more if both do. Without any
// host rules nf_tables is preferred and legacy covers old kernels.
func (g *Guard) autoBackend(ctx context.Context) (Backend, error) {
	found, attempts := g.probeKinds(ctx, []xtablesKind{kindNft, kindLegacy})
	if len(found) == 0 {
		return Backend{}, &NoBackendError{Attempts: attempts}
	}
	nft, hasNft := probeOf(found, kindNft)
	legacy, hasLegacy := probeOf(found, kindLegacy)
	counts := backendChoice{nftRules: nft.rules, legacyRules: legacy.rules}
	switch {
	case !hasLegacy:
		return newBackend(nft.binary, counts.with(detailIptablesOnlyNft, kindNft)), nil
	case !hasNft:
		return newBackend(legacy.binary, counts.with(detailIptablesOnlyLegacy, kindLegacy)), nil
	case nft.rules > 0 && legacy.rules > 0:
		return mixedBackend(nft, legacy, counts), nil
	case legacy.rules > 0:
		return newBackend(legacy.binary, counts.with(detailIptablesRulesLegacy, kindLegacy)), nil
	case nft.rules > 0:
		return newBackend(nft.binary, counts.with(detailIptablesRulesNft, kindNft)), nil
	}
	return newBackend(nft.binary, counts.with(detailIptablesNoRules, kindNft)), nil
}

// mixedBackend picks the backend with more host rules, nf_tables on a tie.
func mixedBackend(nft, legacy probe, counts backendChoice) Backend {
	chosen := nft
	if legacy.rules > nft.rules {
		chosen = legacy
	}
	return newBackend(chosen.binary, counts.with(detailIptablesMixed, chosen.kind))
}

// probeKinds finds a working binary for each of kinds: the backend's own
// binary first, plain iptables when "iptables -V" names a backend still
// missing. It returns the working binaries and the errors of the others.
func (g *Guard) probeKinds(ctx context.Context, kinds []xtablesKind) ([]probe, []error) {
	var found []probe
	var attempts []error
	var missing []xtablesKind
	for _, kind := range kinds {
		p, err := g.probeBinary(ctx, dedicatedBinary[kind], kind)
		if err != nil {
			attempts = append(attempts, err)
			missing = append(missing, kind)
			continue
		}
		found = append(found, p)
	}
	if len(missing) == 0 {
		return found, attempts
	}
	kind, err := g.plainBinaryKind(ctx)
	if err != nil {
		return found, append(attempts, err)
	}
	if !slices.Contains(missing, kind) {
		return found, attempts
	}
	p, err := g.probeBinary(ctx, plainBinary, kind)
	if err != nil {
		return found, append(attempts, err)
	}
	return append(found, p), attempts
}

// probeBinary proves that binary can list the filter table and counts the
// host rules in the filter and nat tables. A nat table that cannot be
// listed holds no rules: old kernels may lack it.
func (g *Guard) probeBinary(ctx context.Context, binary string, kind xtablesKind) (probe, error) {
	filter, err := g.runner.Run(ctx, binary, "-w", "-t", "filter", "-S")
	if err != nil {
		return probe{}, err
	}
	nat, err := g.runner.Run(ctx, binary, "-w", "-t", "nat", "-S")
	if err != nil {
		nat = ""
	}
	return probe{binary: binary, kind: kind, rules: countHostRules(filter) + countHostRules(nat)}, nil
}

// plainBinaryKind asks plain iptables which backend it is.
func (g *Guard) plainBinaryKind(ctx context.Context) (xtablesKind, error) {
	out, err := g.runner.Run(ctx, plainBinary, "-V")
	if err != nil {
		return "", err
	}
	kind, err := parseVersionKind(out)
	if err != nil {
		return "", fmt.Errorf("%s -V: %w", plainBinary, err)
	}
	return kind, nil
}

// parseVersionKind reads the backend from "iptables v1.8.13 (nf_tables)".
// Versions before 1.8 print no backend; they only have the legacy one.
func parseVersionKind(out string) (xtablesKind, error) {
	version, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	version = strings.TrimSpace(version)
	switch {
	case strings.HasSuffix(version, "("+string(kindNft)+")"):
		return kindNft, nil
	case strings.HasSuffix(version, "("+string(kindLegacy)+")"):
		return kindLegacy, nil
	case strings.HasPrefix(version, plainBinary+" v") && !strings.Contains(version, "("):
		return kindLegacy, nil
	}
	return "", fmt.Errorf("unknown backend in %q", version)
}

// countHostRules counts the rules of an iptables -S listing that the host
// configured: appended rules and policies other than ACCEPT, without
// TunnelDeck's own chains and jumps.
func countHostRules(listing string) int {
	count := 0
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ownChainPrefix) {
			continue
		}
		if strings.HasPrefix(line, "-A ") || (strings.HasPrefix(line, "-P ") && !strings.HasSuffix(line, " ACCEPT")) {
			count++
		}
	}
	return count
}

func probeOf(found []probe, kind xtablesKind) (probe, bool) {
	for _, p := range found {
		if p.kind == kind {
			return p, true
		}
	}
	return probe{}, false
}
