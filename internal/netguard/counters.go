package netguard

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
)

// RuleCounters returns the hits of every firewall rule with installed
// lines, keyed by rule ID (SPEC §16.4): the new connections the rule
// matched. They are read from the rule's lines in the filter chains only
// (TUNNELDECK-INPUT for rules to the host, TUNNELDECK-FORWARD for port
// forwards and outbound rules); each connection meets exactly one of
// them, after "ESTABLISHED,RELATED" has accepted its later packets. The
// DNAT and masquerade lines in nat carry the same tag but are not summed,
// or a port forward would count every connection three times. available
// is false, and nothing is read, when the backend lacks the comment match
// that tags the lines. Chains that do not exist contribute nothing.
func (g *Guard) RuleCounters(ctx context.Context) (counters map[string]domain.RuleCounters, available bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	caps, err := g.detectCapabilities(ctx)
	if err != nil || !caps.has[extComment] {
		return nil, false, err
	}
	counters = make(map[string]domain.RuleCounters)
	for _, spec := range []chainSpec{inputSpec, forwardSpec(nil)} {
		out, err := g.iptables(ctx, spec.table, "-L", spec.name, "-v", "-x", "-n")
		if isAbsent(err) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("read counters of %s: %w", spec.name, err)
		}
		addRuleCounters(counters, out)
	}
	return counters, true, nil
}

// addRuleCounters adds the counters of the tagged rule lines of an
// iptables -L -v -x -n listing, whose lines both backends print as
// "<packets> <bytes> <target> ... /* tdrule:<id> */". Header lines and
// lines without a rule tag are skipped.
func addRuleCounters(counters map[string]domain.RuleCounters, listing string) {
	for _, line := range strings.Split(listing, "\n") {
		m := commentInListing.FindStringSubmatch(line)
		if m == nil || !strings.HasPrefix(m[1], ruleTagPrefix) {
			continue
		}
		id := strings.TrimPrefix(m[1], ruleTagPrefix)
		fields := strings.Fields(line)
		if id == "" || len(fields) < 2 {
			continue
		}
		packets, errPackets := strconv.ParseUint(fields[0], 10, 64)
		bytes, errBytes := strconv.ParseUint(fields[1], 10, 64)
		if errPackets != nil || errBytes != nil {
			continue
		}
		sum := counters[id]
		sum.Packets += packets
		sum.Bytes += bytes
		counters[id] = sum
	}
}
