package netguard

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

// listingOf prints content as iptables-legacy -S prints the chain: tags
// with a colon are quoted.
func listingOf(chain string, content []string) string {
	listing := "-N " + chain + "\n"
	for _, line := range content {
		if tag := ruleTag(strings.Fields(line)); tag != "" {
			line = strings.Replace(line, "--comment "+tag, `--comment "`+tag+`"`, 1)
		}
		listing += "-A " + chain + " " + line + "\n"
	}
	return listing
}

// scriptCurrent lists chains that hold input, forward, prerouting and
// postrouting, with their jumps in place.
func scriptCurrent(f *fakeRunner, input, forward, prerouting, postrouting []string) {
	scriptState(f, installedState{})
	f.scripts[legacy+"-S TUNNELDECK-INPUT"] = []fakeResult{ok(listingOf(inputChain, input))}
	f.scripts[legacy+"-S TUNNELDECK-FORWARD"] = []fakeResult{ok(listingOf(forwardChain, forward))}
	f.scripts[natPrefix+"-S TUNNELDECK-PREROUTING"] = []fakeResult{ok(listingOf(preroutingChain, prerouting))}
	f.scripts[natPrefix+"-S TUNNELDECK-POSTROUTING"] = []fakeResult{ok(listingOf(postroutingChain, postrouting))}
}

// checks are the iptables -C calls that confirm content in chain.
func checks(prefix, chain string, content []string) []string {
	calls := make([]string, len(content))
	for i, rule := range content {
		calls[i] = prefix + "-C " + chain + " " + rule
	}
	return calls
}

// keptCalls is the installation of a chain that holds content already:
// listing, confirming every line, then the jumps.
func keptCalls(prefix, chain, parent string, content []string) []string {
	return slices.Concat([]string{prefix + "-S " + chain}, checks(prefix, chain, content), []string{prefix + "-S " + parent})
}

func TestUnchangedChainsAreLeftAlone(t *testing.T) {
	ike := rulesOnly(portForward(domain.ProtocolUDP, "192.168.2.2", domain.SinglePort(500)))
	ikeForward := forwardWith(onRule(1, "-i tdvpn0 -d 192.168.2.2/32 -p udp --dport 500 -m conntrack --ctstate DNAT -j ACCEPT"))
	ikeDNAT := []string{onRule(1, "-p udp --dport 500 -j DNAT --to-destination 192.168.2.2")}
	ikeMasq := []string{onRule(1, "! -o tdvpn0 -d 192.168.2.2/32 -p udp --dport 500 -m conntrack --ctstate DNAT -j MASQUERADE")}
	tests := []struct {
		name                                    string
		firewall                                domain.Firewall
		input, forward, prerouting, postrouting []string
	}{
		{name: "host rules", firewall: testFirewall, input: testInput, forward: testForward},
		{name: "port forward in every chain", firewall: ike, input: inputWith(), forward: ikeForward,
			prerouting: ikeDNAT, postrouting: ikeMasq},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			g := newLegacyGuard(f)
			for run := range 2 {
				scriptCurrent(f, tt.input, tt.forward, tt.prerouting, tt.postrouting)
				if err := g.InstallFirewall(context.Background(), tt.firewall, uiPort); err != nil {
					t.Fatalf("install %d: %v", run, err)
				}
				want := slices.Concat([]string{addrShow},
					keptCalls(legacy, inputChain, "INPUT", tt.input),
					keptCalls(legacy, forwardChain, "FORWARD", tt.forward),
					keptCalls(natPrefix, preroutingChain, "PREROUTING", tt.prerouting),
					keptCalls(natPrefix, postroutingChain, "POSTROUTING", tt.postrouting))
				if run == 0 {
					want = slices.Concat(detectInstall, want)
				}
				calls := f.takeCalls()
				assertCalls(t, calls, want)
				assertNoChange(t, calls)
			}
		})
	}
}

func assertNoChange(t *testing.T, calls []string) {
	t.Helper()
	for _, call := range calls {
		if strings.Contains(call, commentProbeChain) {
			continue
		}
		for _, change := range []string{" -A ", " -D ", " -I ", " -N ", " -F ", " -X "} {
			if strings.Contains(call, change) {
				t.Errorf("an unchanged installation ran %q", call)
			}
		}
	}
}

func TestChangedChainIsRebuiltAlone(t *testing.T) {
	const oldSSH = "-p tcp --dport 22 -m comment --comment tdrule:ssh -j ACCEPT"
	moved := testFirewall
	moved.Rules = slices.Clone(testFirewall.Rules)
	moved.Rules[0].DestinationPort = domain.SinglePort(2222)
	newInput := slices.Clone(testInput)
	newInput[2] = "-p tcp --dport 2222 -m comment --comment tdrule:ssh -j ACCEPT"
	swapped := testFirewall
	swapped.Rules = []domain.FirewallRule{testFirewall.Rules[1], testFirewall.Rules[0]}
	tests := []struct {
		name     string
		firewall domain.Firewall
		listed   []string // content of TUNNELDECK-INPUT before
		script   func(*fakeRunner)
		input    []string // content wanted
		checked  []string // lines confirmed before the refill
	}{
		{
			name:     "a rule's line changed: tags agree, iptables -C misses the new line",
			firewall: moved, listed: testInput, input: newInput,
			script:  func(f *fakeRunner) { f.on(legacy+"-C TUNNELDECK-INPUT "+newInput[2], fail(badRule)) },
			checked: newInput[:3],
		},
		{
			name:     "rules swapped: the tags differ",
			firewall: swapped, listed: testInput,
			input: inputWith(testInput[3], testInput[2]),
		},
		{
			name:     "a rule removed: the length differs",
			firewall: rulesOnly(testFirewall.Rules[1]), listed: testInput,
			input: inputWith(testInput[3]),
		},
		{
			name:     "an untagged line from an older version",
			firewall: testFirewall, listed: inputWith(strings.Replace(oldSSH, "-m comment --comment tdrule:ssh ", "", 1), testInput[3]),
			input: testInput,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			scriptCurrent(f, tt.listed, testForward, nil, nil)
			if tt.script != nil {
				tt.script(f)
			}
			if err := newLegacyGuard(f).InstallFirewall(context.Background(), tt.firewall, uiPort); err != nil {
				t.Fatalf("InstallFirewall: %v", err)
			}
			refill := slices.Concat(prefixed(legacy, "-S TUNNELDECK-INPUT"), checks(legacy, inputChain, tt.checked),
				prefixed(legacy, "-S INPUT"), appends(legacy, inputChain, tt.input))
			for range tt.listed {
				refill = append(refill, legacy+"-D TUNNELDECK-INPUT 1")
			}
			assertCalls(t, f.calls, slices.Concat(detectInstall, []string{addrShow}, refill,
				keptCalls(legacy, forwardChain, "FORWARD", testForward),
				keptCalls(natPrefix, preroutingChain, "PREROUTING", nil),
				keptCalls(natPrefix, postroutingChain, "POSTROUTING", nil)))
		})
	}
}

func TestUnchangedChainDetectsTheStateMatch(t *testing.T) {
	stateEstablished := "-m state --state ESTABLISHED,RELATED -m comment --comment tdfixed:established -j ACCEPT"
	input := slices.Clone(testInput)
	input[1] = stateEstablished
	forward := forwardWith()
	forward[1] = stateEstablished
	f := newFakeRunner()
	scriptCurrent(f, input, forward, nil, nil)
	f.on(legacy+"-C TUNNELDECK-INPUT "+established, fail("iptables v1.8.7 (legacy): Couldn't load match `conntrack'"))
	g := newLegacyGuard(f)
	if err := g.InstallFirewall(context.Background(), testFirewall, uiPort); err != nil {
		t.Fatalf("InstallFirewall: %v", err)
	}
	calls := f.takeCalls()
	assertNoChange(t, calls)
	if g.ct != ctState {
		t.Errorf("connection-tracking match = %v, want the state match", g.ct)
	}
	if !slices.Contains(calls, legacy+"-C TUNNELDECK-FORWARD "+stateEstablished) ||
		slices.Contains(calls, legacy+"-C TUNNELDECK-FORWARD "+established) {
		t.Errorf("the detected state match must be checked directly: %v", calls)
	}
}

func TestEveryContentLineIsTagged(t *testing.T) {
	firewall := domain.Firewall{FirewallSettings: domain.DefaultFirewallSettings(), Rules: []domain.FirewallRule{
		changed(hostRule(domain.ProtocolTCP, domain.SinglePort(22)), func(r *domain.FirewallRule) { r.ID = "ssh" }),
		changed(portForward(domain.ProtocolTCPUDP, "192.168.2.5", domain.PortRange{}), func(r *domain.FirewallRule) { r.ID = "all" }),
		changed(outboundRule(domain.ProtocolAny, "192.168.2.2", "0.0.0.0/0"), func(r *domain.FirewallRule) { r.ID = "out" }),
	}}
	rs := buildRuleset(firewall, hostPorts{ui: uiPort, remoteAccess: 8443}, []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")})
	for _, chain := range rs.chainContent() {
		for i, rule := range chain.content {
			tag := ruleTag(rule)
			last := i == len(chain.content)-1
			switch {
			case chain.spec.sealed && last:
				if tag != "" {
					t.Errorf("%s: the sealing DROP carries %q", chain.spec.name, tag)
				}
			case !strings.HasPrefix(tag, ruleTagPrefix) && !strings.HasPrefix(tag, fixedTagPrefix):
				t.Errorf("%s: line %q has no tag", chain.spec.name, strings.Join(rule, " "))
			}
			if at := slices.Index(rule, "comment"); tag != "" && rule[at+3] != "-j" {
				t.Errorf("%s: the comment of %q is not right before the target", chain.spec.name, strings.Join(rule, " "))
			}
		}
	}
	for _, id := range []string{"ssh", "all", "out"} {
		if !slices.ContainsFunc(rs.input, hasTag(id)) && !slices.ContainsFunc(rs.forward, hasTag(id)) {
			t.Errorf("no filter line of rule %q", id)
		}
	}
}

func hasTag(id string) func([]string) bool {
	return func(rule []string) bool { return ruleTag(rule) == ruleTagPrefix+id }
}

func TestTags(t *testing.T) {
	rule := tagged("tdrule:a1", []string{"-p", "tcp", "--dport", "22", "-j", "ACCEPT"})
	if got := strings.Join(rule, " "); got != "-p tcp --dport 22 -m comment --comment tdrule:a1 -j ACCEPT" {
		t.Errorf("tagged = %q", got)
	}
	if got := strings.Join(untagged(rule), " "); got != "-p tcp --dport 22 -j ACCEPT" {
		t.Errorf("untagged = %q", got)
	}
	lines := map[string]string{
		`-A TUNNELDECK-INPUT -p tcp -m tcp --dport 22 -m comment --comment "tdrule:a1" -j ACCEPT`: "tdrule:a1",
		`-A TUNNELDECK-INPUT -p tcp -m tcp --dport 22 -m comment --comment tdfixed -j ACCEPT`:     "tdfixed",
		`-A TUNNELDECK-INPUT -j DROP`: "",
	}
	for line, want := range lines {
		if got := lineTag(line); got != want {
			t.Errorf("lineTag(%q) = %q, want %q", line, got, want)
		}
	}
}

// untagLines drops the comment match from every line.
func untagLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = strings.Join(untagged(strings.Fields(line)), " ")
	}
	return out
}

func TestWithoutTheCommentMatchEveryChainIsRefilledUntagged(t *testing.T) {
	input, forward := untagLines(testInput), untagLines(testForward)
	f := newFakeRunner()
	f.on(probeTagged, fail(commentMissing))
	g := newLegacyGuard(f)
	for run := range 2 {
		// Even chains that already hold the content are refilled, as
		// before rules were tagged.
		scriptCurrent(f, input, forward, nil, nil)
		if err := g.InstallFirewall(context.Background(), testFirewall, uiPort); err != nil {
			t.Fatalf("install %d: %v", run, err)
		}
		want := slices.Concat([]string{addrShow},
			refillCalls(legacy, inputChain, "INPUT", len(input), input),
			refillCalls(legacy, forwardChain, "FORWARD", len(forward), forward),
			refillCalls(natPrefix, preroutingChain, "PREROUTING", 0, nil),
			refillCalls(natPrefix, postroutingChain, "POSTROUTING", 0, nil))
		if run == 0 {
			want = slices.Concat(detectInstall, want)
		}
		calls := f.takeCalls()
		assertCalls(t, calls, want)
		for _, call := range calls {
			if strings.Contains(call, "--comment") && !strings.Contains(call, commentProbeChain) {
				t.Errorf("a tagged rule was installed without the comment match: %q", call)
			}
		}
	}
}
