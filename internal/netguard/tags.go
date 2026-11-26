package netguard

import (
	"context"
	"fmt"
	"regexp"
	"slices"
)

// Comment tags name the origin of every content line of netguard's
// chains: "tdrule:<id>" for the lines of a firewall rule, "tdfixed:<purpose>"
// for the lines netguard adds on its own. The trailing DROP of a sealed
// chain carries no tag: it is the seal ensureChain looks for.
const (
	ruleTagPrefix  = "tdrule:"
	fixedTagPrefix = "tdfixed:"
)

// Purposes of the fixed lines.
const (
	fixedUIPort       = "ui-port"
	fixedInvalid      = "invalid"
	fixedEstablished  = "established"
	fixedSYNFlood     = "syn-flood"
	fixedPingLimit    = "ping-limit"
	fixedRemoteAccess = "remote-access"
	fixedLANReturn    = "lan-return"
	fixedKillSwitch   = "kill-switch"
	fixedMSSClamp     = "mss-clamp"
	fixedHostPort     = "host-port"
)

// commentMatch finds the comment of a line as iptables -S prints it
// (quoted when it holds a colon) and as iptables -L prints it (/* ... */).
var (
	commentInRule    = regexp.MustCompile(`-m comment --comment "?([^"\s]+)"?`)
	commentInListing = regexp.MustCompile(`/\* (\S+) \*/`)
)

// tagged inserts the comment match with tag right before the target, so
// the line reads the same in both backends: iptables-nft prints a comment
// behind every other match.
func tagged(tag string, rule []string) []string {
	at := slices.Index(rule, "-j")
	if at < 0 {
		at = len(rule)
	}
	return slices.Concat(rule[:at], []string{"-m", "comment", "--comment", tag}, rule[at:])
}

func fixedRule(purpose string, rule []string) []string { return tagged(fixedTagPrefix+purpose, rule) }

// ruleTag is the tag of a content line as netguard renders it, "" for an
// untagged one.
func ruleTag(rule []string) string {
	for i := 0; i+3 < len(rule); i++ {
		if rule[i] == "-m" && rule[i+1] == "comment" && rule[i+2] == "--comment" {
			return rule[i+3]
		}
	}
	return ""
}

// untagged returns rule without its comment match.
func untagged(rule []string) []string {
	for i := 0; i+3 < len(rule); i++ {
		if rule[i] == "-m" && rule[i+1] == "comment" && rule[i+2] == "--comment" {
			return slices.Concat(rule[:i], rule[i+4:])
		}
	}
	return rule
}

// lineTag is the tag of a line of iptables -S, "" for an untagged one.
func lineTag(line string) string {
	if m := commentInRule.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// commentSupport is whether the backend has the comment match (xt_comment
// for iptables-legacy).
type commentSupport int

const (
	commentsUnknown commentSupport = iota // not probed yet
	commentsAvailable
	commentsMissing
)

// commentProbeChain is created, given one tagged rule and deleted to probe
// the comment match.
const commentProbeChain = "TUNNELDECK-COMMENT-PROBE"

// detectComments probes the comment match once per backend: on a
// temporary chain, like the connection-tracking detection. A probe chain
// left over from a crash is reused and deleted. Only a failing tagged rule
// counts as "missing"; failing to create or delete the chain is an error.
func (g *Guard) detectComments(ctx context.Context) (bool, error) {
	switch g.comments {
	case commentsAvailable:
		return true, nil
	case commentsMissing:
		return false, nil
	}
	if _, err := g.iptables(ctx, filterTable, "-N", commentProbeChain); err != nil && !isAlreadyExists(err) {
		return false, fmt.Errorf("probe the comment match: %w", err)
	}
	probe := fixedRule("probe", []string{"-j", "RETURN"})
	_, appendErr := g.iptables(ctx, filterTable, append([]string{"-A", commentProbeChain}, probe...)...)
	if err := g.removeChain(ctx, filterTable, commentProbeChain); err != nil {
		return false, fmt.Errorf("probe the comment match: %w", err)
	}
	if appendErr != nil {
		g.comments = commentsMissing
		return false, nil
	}
	g.comments = commentsAvailable
	return true, nil
}

// untaggedContent returns content without comment matches, for a backend
// without the comment match.
func untaggedContent(content [][]string) [][]string {
	out := make([][]string, len(content))
	for i, rule := range content {
		out[i] = untagged(rule)
	}
	return out
}
