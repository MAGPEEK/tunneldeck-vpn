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

// installChain refills spec's chain with content ("append, then trim"):
// the new content is appended behind the old one, then the old rules are
// deleted from the top. A sealed chain ends with DROP before its jumps
// exist, and its old trailing DROP shadows the new rules until it is
// deleted, so tunnel traffic is never accepted by a partial chain.
func (g *Guard) installChain(ctx context.Context, spec chainSpec, content [][]string) error {
	oldCount, err := g.ensureChain(ctx, spec)
	if err == nil {
		err = g.ensureJumps(ctx, spec)
	}
	for _, rule := range content {
		if err != nil {
			break
		}
		err = g.appendRule(ctx, spec.table, spec.name, rule)
	}
	if err == nil {
		err = g.deleteLeadingRules(ctx, spec.table, spec.name, oldCount)
	}
	if err != nil {
		return fmt.Errorf("install %s: %w", spec.name, err)
	}
	return nil
}

// ensureChain creates the chain if missing; a sealed chain also gets a
// trailing DROP if it lacks one. It returns the number of rules now in the
// chain.
func (g *Guard) ensureChain(ctx context.Context, spec chainSpec) (int, error) {
	rules, err := g.listRules(ctx, spec.table, spec.name)
	if isAbsent(err) {
		if _, err := g.iptables(ctx, spec.table, "-N", spec.name); err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	if !spec.sealed || (len(rules) > 0 && rules[len(rules)-1] == "-A "+spec.name+" -j DROP") {
		return len(rules), nil
	}
	if err := g.appendRaw(ctx, spec.table, spec.name, []string{"-j", "DROP"}); err != nil {
		return 0, err
	}
	return len(rules) + 1, nil
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
