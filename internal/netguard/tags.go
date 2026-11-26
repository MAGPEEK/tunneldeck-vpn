package netguard

import (
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

// untaggedContent returns content without comment matches, for a backend
// without the comment match.
func untaggedContent(content [][]string) [][]string {
	out := make([][]string, len(content))
	for i, rule := range content {
		out[i] = untagged(rule)
	}
	return out
}
