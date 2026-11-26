package netguard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// table is an iptables table.
type table string

const (
	filterTable table = "filter"
	natTable    table = "nat"
)

// maxDuplicateRules bounds the delete loop for duplicate rules so a
// misbehaving iptables cannot spin forever.
const maxDuplicateRules = 64

// chainSpec describes one of our chains and the jumps leading to it.
type chainSpec struct {
	table  table
	name   string
	parent string     // built-in chain holding the jumps
	jumps  [][]string // match of each jump, in order from position 1
	// sealed chains end with DROP at all times, and their jumps are moved
	// behind DROP guards. Only filter chains can be sealed: the nat table
	// does not filter.
	sealed bool
}

// ctMatchKind is the match netguard uses for connection-tracking states.
type ctMatchKind int

const (
	ctUnknown   ctMatchKind = iota // not detected yet
	ctConntrack                    // -m conntrack --ctstate
	ctState                        // -m state --state, for kernels without xt_conntrack
)

// installChain brings spec's chain to content. With keepCurrent, a chain
// that holds exactly content already is left alone (chainCurrent), so its
// counters survive; only its jumps are checked. Without it (no comment
// match, so no tags and no counters to keep) and for any other chain, the
// chain is refilled ("append, then trim"): the new content is appended
// behind the old one, then the old rules are deleted from the top. A sealed
// chain ends with DROP before its jumps exist, and its old trailing DROP
// shadows the new rules until it is deleted, so tunnel traffic is never
// accepted by a partial chain.
func (g *Guard) installChain(ctx context.Context, spec chainSpec, content [][]string, keepCurrent bool) error {
	listing, err := g.listRules(ctx, spec.table, spec.name)
	exists := err == nil
	if isAbsent(err) {
		err = nil
	}
	switch {
	case err != nil:
	case keepCurrent && exists && g.chainCurrent(ctx, spec, listing, content):
		err = g.ensureJumps(ctx, spec)
	default:
		err = g.refillChain(ctx, spec, exists, listing, content)
	}
	if err != nil {
		return fmt.Errorf("install %s: %w", spec.name, err)
	}
	return nil
}

func (g *Guard) refillChain(ctx context.Context, spec chainSpec, exists bool, listing []string, content [][]string) error {
	oldCount, err := g.ensureChain(ctx, spec, exists, listing)
	if err == nil {
		err = g.ensureJumps(ctx, spec)
	}
	for _, rule := range content {
		if err != nil {
			return err
		}
		err = g.appendRule(ctx, spec.table, spec.name, rule)
	}
	if err != nil {
		return err
	}
	return g.deleteLeadingRules(ctx, spec.table, spec.name, oldCount)
}

// chainCurrent reports whether listing, the -S lines of spec's chain,
// holds exactly content: the same tags in the same order, and every line
// of content present (iptables -C, which compares rules as the kernel
// holds them and so ignores how -S prints them). With as many lines as
// content and no line of content twice, every listed line is one of
// content. Lines of one rule are not checked for their order among each
// other; netguard always renders them in the same order.
func (g *Guard) chainCurrent(ctx context.Context, spec chainSpec, listing []string, content [][]string) bool {
	if len(listing) != len(content) {
		return false
	}
	for i, rule := range content {
		if lineTag(listing[i]) != ruleTag(rule) {
			return false
		}
	}
	for _, rule := range content {
		if !g.ruleExists(ctx, spec.table, spec.name, rule) {
			return false
		}
	}
	return true
}

// ruleExists reports whether chain holds rule, in the connection-tracking
// match appendRule would use. While that match is unknown, both are tried,
// and the one found becomes the detected match.
func (g *Guard) ruleExists(ctx context.Context, t table, chain string, rule []string) bool {
	if !usesConntrack(rule) {
		return g.check(ctx, t, chain, rule)
	}
	switch g.ct {
	case ctConntrack:
		return g.check(ctx, t, chain, rule)
	case ctState:
		return g.check(ctx, t, chain, stateVariant(rule))
	}
	if g.check(ctx, t, chain, rule) {
		g.ct = ctConntrack
		return true
	}
	if g.check(ctx, t, chain, stateVariant(rule)) {
		g.ct = ctState
		return true
	}
	return false
}

// check runs iptables -C; any failure counts as "not there", since the
// refill that follows reports real errors.
func (g *Guard) check(ctx context.Context, t table, chain string, rule []string) bool {
	_, err := g.iptables(ctx, t, append([]string{"-C", chain}, rule...)...)
	return err == nil
}

// ensureChain creates the chain unless it exists; a sealed chain also gets
// a trailing DROP if it lacks one. listing holds the -S lines of an
// existing chain. It returns the number of rules now in the chain.
func (g *Guard) ensureChain(ctx context.Context, spec chainSpec, exists bool, listing []string) (int, error) {
	if !exists {
		if _, err := g.iptables(ctx, spec.table, "-N", spec.name); err != nil {
			return 0, err
		}
	}
	if !spec.sealed || (len(listing) > 0 && listing[len(listing)-1] == "-A "+spec.name+" -j DROP") {
		return len(listing), nil
	}
	if err := g.appendRaw(ctx, spec.table, spec.name, []string{"-j", "DROP"}); err != nil {
		return 0, err
	}
	return len(listing) + 1, nil
}

// ensureJumps leaves exactly the spec's jumps, once each, at the top of the
// parent chain, in spec order, and removes any other jump to the chain.
// For sealed chains guard rules drop the jumps' traffic while they move.
func (g *Guard) ensureJumps(ctx context.Context, spec chainSpec) error {
	rules, err := g.listRules(ctx, spec.table, spec.parent)
	if err != nil {
		return err
	}
	if jumpsInPlace(rules, spec) {
		return nil
	}
	if spec.sealed {
		for _, match := range spec.jumps {
			if err := g.insertFirst(ctx, spec.table, spec.parent, guardRule(match)); err != nil {
				return err
			}
		}
	}
	for _, match := range spec.jumps {
		if err := g.deleteAll(ctx, spec.table, spec.parent, jumpRule(match, spec.name)); err != nil {
			return err
		}
	}
	if err := g.deleteListedJumps(ctx, spec, rules, desiredJumpLines(spec)); err != nil {
		return err
	}
	for i := len(spec.jumps) - 1; i >= 0; i-- {
		if err := g.insertFirst(ctx, spec.table, spec.parent, jumpRule(spec.jumps[i], spec.name)); err != nil {
			return err
		}
	}
	if spec.sealed {
		for _, match := range spec.jumps {
			if _, err := g.iptables(ctx, spec.table, append([]string{"-D", spec.parent}, guardRule(match)...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

// jumpsInPlace reports whether the parent chain starts with the jumps in
// order and holds no further jump to the chain.
func jumpsInPlace(rules []string, spec chainSpec) bool {
	if len(rules) < len(spec.jumps) || countJumps(rules, spec.name) != len(spec.jumps) {
		return false
	}
	for i, want := range desiredJumpLines(spec) {
		if rules[i] != want {
			return false
		}
	}
	return true
}

func desiredJumpLines(spec chainSpec) []string {
	lines := make([]string, len(spec.jumps))
	for i, match := range spec.jumps {
		lines[i] = ruleLine(spec.parent, jumpRule(match, spec.name))
	}
	return lines
}

func countJumps(rules []string, chain string) int {
	n := 0
	for _, line := range rules {
		if jumpsTo(line, chain) {
			n++
		}
	}
	return n
}

func jumpsTo(line, chain string) bool { return strings.HasSuffix(line, " -j "+chain) }

// deleteListedJumps deletes the jumps to spec's chain that a listing of
// the parent showed, except the lines in keep. Jumps already gone are
// skipped.
func (g *Guard) deleteListedJumps(ctx context.Context, spec chainSpec, listing, keep []string) error {
	prefix := "-A " + spec.parent + " "
	for _, line := range listing {
		if !jumpsTo(line, spec.name) || slices.Contains(keep, line) || !strings.HasPrefix(line, prefix) {
			continue
		}
		args := append([]string{"-D", spec.parent}, strings.Fields(strings.TrimPrefix(line, prefix))...)
		if _, err := g.iptables(ctx, spec.table, args...); err != nil && !isAbsent(err) {
			return err
		}
	}
	return nil
}

// removeChainAndJumps deletes every jump to spec's chain, then the chain.
// Objects that are already absent are skipped.
func (g *Guard) removeChainAndJumps(ctx context.Context, spec chainSpec) error {
	listing, err := g.listRules(ctx, spec.table, spec.parent)
	if err != nil {
		return err
	}
	if err := g.deleteListedJumps(ctx, spec, listing, nil); err != nil {
		return err
	}
	return g.removeChain(ctx, spec.table, spec.name)
}

// appendRule appends rule to chain. A rule written with the conntrack match
// ("-m conntrack --ctstate S") is tried as written first; when that fails,
// the state match is used from then on (stateVariant).
func (g *Guard) appendRule(ctx context.Context, t table, chain string, rule []string) error {
	if !usesConntrack(rule) || g.ct == ctConntrack {
		return g.appendRaw(ctx, t, chain, rule)
	}
	if g.ct == ctState {
		return g.appendRaw(ctx, t, chain, stateVariant(rule))
	}
	conntrackErr := g.appendRaw(ctx, t, chain, rule)
	if conntrackErr == nil {
		g.ct = ctConntrack
		return nil
	}
	if err := g.appendRaw(ctx, t, chain, stateVariant(rule)); err != nil {
		return errors.Join(conntrackErr, err)
	}
	g.ct = ctState
	return nil
}

func usesConntrack(rule []string) bool { return slices.Contains(rule, "conntrack") }

// stateVariant rewrites the conntrack match of rule into the older state
// match. The state match cannot express DNAT; that condition is dropped.
func stateVariant(rule []string) []string {
	i := slices.Index(rule, "conntrack")
	if i < 1 || i+2 >= len(rule) {
		return rule
	}
	states := rule[i+2]
	out := slices.Clone(rule[:i-1])
	if states != ctDNAT {
		out = append(out, "-m", "state", "--state", states)
	}
	return append(out, rule[i+3:]...)
}

func (g *Guard) appendRaw(ctx context.Context, t table, chain string, rule []string) error {
	_, err := g.iptables(ctx, t, append([]string{"-A", chain}, rule...)...)
	return err
}

func (g *Guard) insertFirst(ctx context.Context, t table, chain string, rule []string) error {
	_, err := g.iptables(ctx, t, append([]string{"-I", chain, "1"}, rule...)...)
	return err
}

func (g *Guard) deleteLeadingRules(ctx context.Context, t table, chain string, count int) error {
	for range count {
		if _, err := g.iptables(ctx, t, "-D", chain, "1"); err != nil {
			return err
		}
	}
	return nil
}

// deleteAll deletes every copy of rule from chain; a missing rule or chain
// is not an error.
func (g *Guard) deleteAll(ctx context.Context, t table, chain string, rule []string) error {
	for range maxDuplicateRules {
		_, err := g.iptables(ctx, t, append([]string{"-C", chain}, rule...)...)
		if isAbsent(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := g.iptables(ctx, t, append([]string{"-D", chain}, rule...)...); err != nil {
			return err
		}
	}
	return fmt.Errorf("%s still holds %q after %d deletions", chain, ruleLine(chain, rule), maxDuplicateRules)
}

// removeChain flushes and deletes chain; a missing chain is not an error.
func (g *Guard) removeChain(ctx context.Context, t table, chain string) error {
	_, err := g.iptables(ctx, t, "-F", chain)
	if isAbsent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = g.iptables(ctx, t, "-X", chain)
	return err
}

func jumpRule(match []string, chain string) []string {
	return append(slices.Clone(match), "-j", chain)
}

func guardRule(match []string) []string {
	return append(slices.Clone(match), "-j", "DROP")
}

// ruleLine renders rule the way iptables -S prints it.
func ruleLine(chain string, rule []string) string {
	return strings.Join(append([]string{"-A", chain}, rule...), " ")
}
