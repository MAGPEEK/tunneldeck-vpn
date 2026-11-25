package netguard

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
)

// Chain names owned by netguard.
const (
	inputChain   = "TUNNELDECK-INPUT"
	forwardChain = "TUNNELDECK-FORWARD"
)

// maxDuplicateRules bounds the delete loop for duplicate rules so a
// misbehaving iptables cannot spin forever.
const maxDuplicateRules = 64

// chainSpec describes one of our chains and the jumps leading to it.
type chainSpec struct {
	name   string
	parent string     // built-in chain holding the jumps
	jumps  [][]string // match of each jump, in order from position 1
}

var (
	inputSpec = chainSpec{
		name:   inputChain,
		parent: "INPUT",
		jumps:  [][]string{{"-i", DeviceName}},
	}
	forwardSpec = chainSpec{
		name:   forwardChain,
		parent: "FORWARD",
		jumps:  [][]string{{"-i", DeviceName}, {"-o", DeviceName}},
	}
)

// Matches for "established or related" traffic: conntrack is preferred, the
// older state match is the fallback for kernels without xt_conntrack.
var (
	conntrackMatch = []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"}
	stateMatch     = []string{"-m", "state", "--state", "ESTABLISHED,RELATED"}
)

// InstallFirewall creates or updates TUNNELDECK-INPUT and TUNNELDECK-FORWARD
// and puts their jumps at the top of INPUT and FORWARD (SPEC §6). Calling it
// again with the same rules yields the same state.
//
// Refill strategy ("append, then trim"): every chain always ends with DROP
// before its jump exists. New content is appended behind the old content and
// the old rules are then deleted from the top. Until the old trailing DROP is
// deleted it shadows the new rules, and its deletion switches atomically to
// the complete new content, so tunnel traffic is never accepted by a partial
// chain. Misplaced jumps are moved behind a temporary "-i/-o tdvpn0 -j DROP"
// guard in the parent chain. A failure therefore leaves DROP in place and is
// returned; FORWARD is still attempted when INPUT fails.
func (g *Guard) InstallFirewall(ctx context.Context, rules []domain.HostAccessRule, uiPort int) error {
	if err := validateRules(rules, uiPort); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, err := g.detectBackend(ctx); err != nil {
		return fmt.Errorf("install firewall: %w", err)
	}
	inputErr := g.installChain(ctx, inputSpec, func(ctx context.Context) error {
		return g.appendInputContent(ctx, rules)
	})
	forwardErr := g.installChain(ctx, forwardSpec, func(ctx context.Context) error {
		return g.appendRule(ctx, forwardChain, "-j", "DROP")
	})
	return errors.Join(inputErr, forwardErr)
}

// RemoveFirewall deletes the jumps and both chains. Objects that are
// already absent are skipped.
func (g *Guard) RemoveFirewall(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	specs := []chainSpec{inputSpec, forwardSpec}
	for _, spec := range specs {
		for _, match := range spec.jumps {
			if err := g.deleteAll(ctx, spec.parent, jumpRule(match, spec.name)); err != nil {
				return fmt.Errorf("remove firewall: %w", err)
			}
		}
	}
	for _, spec := range specs {
		if err := g.removeChain(ctx, spec.name); err != nil {
			return fmt.Errorf("remove firewall: %w", err)
		}
	}
	return nil
}

// validateRules applies the domain rules plus the ban on the UI port.
func validateRules(rules []domain.HostAccessRule, uiPort int) error {
	v := &domain.ValidationError{}
	if err := domain.ValidateHostAccessRules(rules); err != nil {
		var ruleErrs *domain.ValidationError
		if !errors.As(err, &ruleErrs) {
			return err
		}
		v.Merge("", ruleErrs)
	}
	for i, rule := range rules {
		if rule.Port == uiPort {
			v.Add(fmt.Sprintf("rules[%d].port", i), "must not be the web UI port")
		}
	}
	return v.OrNil()
}

func (g *Guard) installChain(ctx context.Context, spec chainSpec, appendContent func(context.Context) error) error {
	oldCount, err := g.ensureSealedChain(ctx, spec.name)
	if err == nil {
		err = g.ensureJumps(ctx, spec)
	}
	if err == nil {
		err = appendContent(ctx)
	}
	if err == nil {
		err = g.deleteLeadingRules(ctx, spec.name, oldCount)
	}
	if err != nil {
		return fmt.Errorf("install %s: %w", spec.name, err)
	}
	return nil
}

// ensureSealedChain creates chain if missing and makes sure its last rule is
// DROP. It returns the number of rules now in the chain.
func (g *Guard) ensureSealedChain(ctx context.Context, chain string) (int, error) {
	rules, err := g.listRules(ctx, chain)
	if isAbsent(err) {
		if _, err := g.iptables(ctx, "-N", chain); err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	if len(rules) > 0 && rules[len(rules)-1] == "-A "+chain+" -j DROP" {
		return len(rules), nil
	}
	if err := g.appendRule(ctx, chain, "-j", "DROP"); err != nil {
		return 0, err
	}
	return len(rules) + 1, nil
}

// ensureJumps leaves exactly one copy of each jump at the top of the parent
// chain, in spec order. When they are misplaced, guard rules drop tunnel
// traffic while the jumps are moved.
func (g *Guard) ensureJumps(ctx context.Context, spec chainSpec) error {
	rules, err := g.listRules(ctx, spec.parent)
	if err != nil {
		return err
	}
	if jumpsInPlace(rules, spec) {
		return nil
	}
	for _, match := range spec.jumps {
		if err := g.insertFirst(ctx, spec.parent, guardRule(match)); err != nil {
			return err
		}
	}
	for _, match := range spec.jumps {
		if err := g.deleteAll(ctx, spec.parent, jumpRule(match, spec.name)); err != nil {
			return err
		}
	}
	for i := len(spec.jumps) - 1; i >= 0; i-- {
		if err := g.insertFirst(ctx, spec.parent, jumpRule(spec.jumps[i], spec.name)); err != nil {
			return err
		}
	}
	for _, match := range spec.jumps {
		if _, err := g.iptables(ctx, append([]string{"-D", spec.parent}, guardRule(match)...)...); err != nil {
			return err
		}
	}
	return nil
}

// jumpsInPlace reports whether the parent chain starts with the jumps in
// order and holds no further copy of them.
func jumpsInPlace(rules []string, spec chainSpec) bool {
	if len(rules) < len(spec.jumps) {
		return false
	}
	for i, match := range spec.jumps {
		want := ruleLine(spec.parent, jumpRule(match, spec.name))
		if rules[i] != want || countOf(rules, want) != 1 {
			return false
		}
	}
	return true
}

func (g *Guard) appendInputContent(ctx context.Context, rules []domain.HostAccessRule) error {
	if err := g.appendEstablishedAccept(ctx); err != nil {
		return err
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if err := g.appendRule(ctx, inputChain, acceptRule(rule)...); err != nil {
			return err
		}
	}
	return g.appendRule(ctx, inputChain, "-j", "DROP")
}

// appendEstablishedAccept appends the ESTABLISHED,RELATED accept, detecting
// on first use whether the conntrack match works or state is needed.
func (g *Guard) appendEstablishedAccept(ctx context.Context) error {
	if g.stateMatch != nil {
		return g.appendRule(ctx, inputChain, accept(g.stateMatch)...)
	}
	var errs []error
	for _, match := range [][]string{conntrackMatch, stateMatch} {
		err := g.appendRule(ctx, inputChain, accept(match)...)
		if err == nil {
			g.stateMatch = match
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (g *Guard) deleteLeadingRules(ctx context.Context, chain string, count int) error {
	for range count {
		if _, err := g.iptables(ctx, "-D", chain, "1"); err != nil {
			return err
		}
	}
	return nil
}

// deleteAll deletes every copy of rule from chain; a missing rule or chain
// is not an error.
func (g *Guard) deleteAll(ctx context.Context, chain string, rule []string) error {
	for range maxDuplicateRules {
		_, err := g.iptables(ctx, append([]string{"-C", chain}, rule...)...)
		if isAbsent(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := g.iptables(ctx, append([]string{"-D", chain}, rule...)...); err != nil {
			return err
		}
	}
	return fmt.Errorf("%s still holds %q after %d deletions", chain, ruleLine(chain, rule), maxDuplicateRules)
}

// removeChain flushes and deletes chain; a missing chain is not an error.
func (g *Guard) removeChain(ctx context.Context, chain string) error {
	_, err := g.iptables(ctx, "-F", chain)
	if isAbsent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = g.iptables(ctx, "-X", chain)
	return err
}

func (g *Guard) appendRule(ctx context.Context, chain string, rule ...string) error {
	_, err := g.iptables(ctx, append([]string{"-A", chain}, rule...)...)
	return err
}

func (g *Guard) insertFirst(ctx context.Context, chain string, rule []string) error {
	_, err := g.iptables(ctx, append([]string{"-I", chain, "1"}, rule...)...)
	return err
}

func acceptRule(rule domain.HostAccessRule) []string {
	args := []string{"-p", string(rule.Protocol), "--dport", strconv.Itoa(rule.Port)}
	if rule.SourceCIDR != "" {
		args = append(args, "-s", rule.SourceCIDR)
	}
	return accept(args)
}

func accept(match []string) []string {
	return append(append([]string{}, match...), "-j", "ACCEPT")
}

func jumpRule(match []string, chain string) []string {
	return append(append([]string{}, match...), "-j", chain)
}

func guardRule(match []string) []string {
	return append(append([]string{}, match...), "-j", "DROP")
}

// ruleLine renders rule the way iptables -S prints it.
func ruleLine(chain string, rule []string) string {
	return "-A " + chain + " " + strings.Join(rule, " ")
}

func countOf(lines []string, want string) int {
	n := 0
	for _, line := range lines {
		if line == want {
			n++
		}
	}
	return n
}
