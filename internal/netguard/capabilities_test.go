package netguard

import (
	"context"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

// extensionMissing is how iptables-legacy 1.8.13 fails a line whose
// extension the kernel lacks (here xt_hashlimit on a DSM 7.2 kernel).
const extensionMissing = "Warning: Extension hashlimit revision 0 not supported, missing kernel module?\n" +
	"iptables v1.8.13 (legacy): unknown option \"--hashlimit-above\""

// Lines of the global protections, as appended.
const (
	synHashlimitIn   = "-p tcp --syn -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-name td-syn-in -m comment --comment tdfixed:syn-flood -j DROP"
	pingHashlimitIn  = "-p icmp --icmp-type echo-request -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-name td-ping-in -m comment --comment tdfixed:ping-limit -j DROP"
	synHashlimitFwd  = "-i tdvpn0 -p tcp --syn -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-name td-syn-fwd -m comment --comment tdfixed:syn-flood -j DROP"
	pingHashlimitFwd = "-i tdvpn0 -p icmp --icmp-type echo-request -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-name td-ping-fwd -m comment --comment tdfixed:ping-limit -j DROP"
	synToLimitIn     = "-p tcp --syn -m comment --comment tdfixed:syn-flood -j TUNNELDECK-LIMIT"
	pingToLimitIn    = "-p icmp --icmp-type echo-request -m comment --comment tdfixed:ping-limit -j TUNNELDECK-LIMIT"
	synToLimitFwd    = "-i tdvpn0 -p tcp --syn -m comment --comment tdfixed:syn-flood -j TUNNELDECK-LIMIT"
	pingToLimitFwd   = "-i tdvpn0 -p icmp --icmp-type echo-request -m comment --comment tdfixed:ping-limit -j TUNNELDECK-LIMIT"
	synWithinLimit   = "-p tcp -m limit --limit 25/sec --limit-burst 50 -m comment --comment tdfixed:syn-flood -j RETURN"
	pingWithinLimit  = "-p icmp -m limit --limit 5/sec --limit-burst 10 -m comment --comment tdfixed:ping-limit -j RETURN"
	mssClamp         = "-p tcp --tcp-flags SYN,RST SYN -m comment --comment tdfixed:mss-clamp -j TCPMSS --clamp-mss-to-pmtu"
	sshAccept        = "-p tcp --dport 22 -m comment --comment tdrule:r1 -j ACCEPT"
)

// freshLimitCalls create TUNNELDECK-LIMIT sealed, then fill it with
// content; it has no jumps from a built-in chain.
func freshLimitCalls(content ...string) []string {
	return slices.Concat(
		prefixed(legacy, "-S TUNNELDECK-LIMIT", "-N TUNNELDECK-LIMIT", "-A TUNNELDECK-LIMIT -j DROP"),
		appends(legacy, limitChain, content),
		prefixed(legacy, "-D TUNNELDECK-LIMIT 1"))
}

// TestInstallWithoutOptionalExtensions installs every protection on
// kernels that lack some of the optional extensions: the installation
// always succeeds, the rate limits fall back to the limit match or are
// left out, and MSS clamping is left out without TCPMSS.
func TestInstallWithoutOptionalExtensions(t *testing.T) {
	protected := withDefaultSettings(rulesOnly(hostRule(domain.ProtocolTCP, domain.SinglePort(22))))
	unprotected := rulesOnly(hostRule(domain.ProtocolTCP, domain.SinglePort(22)))
	tests := []struct {
		name     string
		missing  []string
		firewall domain.Firewall
		// limitCalls run between the LAN detection and TUNNELDECK-INPUT;
		// tailCalls after the nat chains.
		limitCalls, tailCalls []string
		input, forward        []string
	}{
		{
			name:     "every extension",
			firewall: protected,
			input:    []string{uiPortDrop, invalidDrop, established, synHashlimitIn, pingHashlimitIn, sshAccept, dropAll},
			forward:  []string{killSwitchDrop, invalidDrop, mssClamp, established, synHashlimitFwd, pingHashlimitFwd, dropAll},
		},
		{
			name:       "no hashlimit: one global limit",
			missing:    []string{probeHashlimit},
			firewall:   protected,
			limitCalls: freshLimitCalls(synWithinLimit, pingWithinLimit, dropAll),
			input:      []string{uiPortDrop, invalidDrop, established, synToLimitIn, pingToLimitIn, sshAccept, dropAll},
			forward:    []string{killSwitchDrop, invalidDrop, mssClamp, established, synToLimitFwd, pingToLimitFwd, dropAll},
		},
		{
			name:     "neither hashlimit nor limit: rate limits left out",
			missing:  []string{probeHashlimit, probeLimit},
			firewall: protected,
			input:    []string{uiPortDrop, invalidDrop, established, sshAccept, dropAll},
			forward:  []string{killSwitchDrop, invalidDrop, mssClamp, established, dropAll},
		},
		{
			name:     "no TCPMSS: MSS clamping left out",
			missing:  []string{probeTCPMSS},
			firewall: protected,
			input:    []string{uiPortDrop, invalidDrop, established, synHashlimitIn, pingHashlimitIn, sshAccept, dropAll},
			forward:  []string{killSwitchDrop, invalidDrop, established, synHashlimitFwd, pingHashlimitFwd, dropAll},
		},
		{
			name:      "no hashlimit, protections off: the limit chain is removed last",
			missing:   []string{probeHashlimit},
			firewall:  unprotected,
			tailCalls: prefixed(legacy, "-F TUNNELDECK-LIMIT", "-X TUNNELDECK-LIMIT"),
			input:     inputWith(sshAccept),
			forward:   forwardWith(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := installedState{input: 1, forward: 1}
			f := newFakeRunner()
			scriptState(f, state)
			f.on(legacy+"-S TUNNELDECK-LIMIT", fail(noChain))
			for _, probe := range tt.missing {
				f.on(probe, fail(extensionMissing))
			}
			if err := newLegacyGuard(f).InstallFirewall(context.Background(), tt.firewall, uiPort); err != nil {
				t.Fatalf("InstallFirewall: %v", err)
			}
			chains := reinstallCalls(state, tt.input, tt.forward, nil, nil)
			assertCalls(t, f.calls, slices.Concat(detectInstall, chains[:1], tt.limitCalls, chains[1:], tt.tailCalls))
		})
	}
}

func TestProtectionSupport(t *testing.T) {
	tests := []struct {
		name    string
		missing []string
		want    domain.ProtectionSupport
	}{
		{name: "every extension", want: fullSupport},
		{name: "no hashlimit, no TCPMSS", missing: []string{probeHashlimit, probeTCPMSS}, want: limitOnlySupport},
		{
			name: "limit without hashlimit: a global SYN rate, the ping limit in full", missing: []string{probeHashlimit},
			want: domain.ProtectionSupport{SYNFlood: domain.ProtectionGlobal, Ping: domain.ProtectionFull, MSSClamp: domain.ProtectionFull, RuleCounters: true},
		},
		{
			name: "nothing optional", missing: []string{probeComment, probeHashlimit, probeLimit, probeTCPMSS},
			want: domain.ProtectionSupport{SYNFlood: domain.ProtectionNone, Ping: domain.ProtectionNone, MSSClamp: domain.ProtectionNone},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			for _, probe := range tt.missing {
				f.on(probe, fail(extensionMissing))
			}
			got, err := newLegacyGuard(f).ProtectionSupport(context.Background())
			if err != nil || got != tt.want {
				t.Fatalf("ProtectionSupport = %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestProtectionSupportFailsWithoutAProbeChain(t *testing.T) {
	f := newFakeRunner()
	f.on(legacy+"-N TUNNELDECK-EXT-PROBE", fail(noPermission))
	g := newLegacyGuard(f)
	if _, err := g.ProtectionSupport(context.Background()); err == nil || !strings.Contains(err.Error(), "probe the iptables extensions") {
		t.Fatalf("err = %v, want the probe error", err)
	}
	if g.caps != nil {
		t.Errorf("a failed probe was cached: %+v", g.caps)
	}
}

// TestExtensionsAreProbedOncePerBackend probes once for an installation,
// counters, the self-check and the support, and again only for another
// backend binary.
func TestExtensionsAreProbedOncePerBackend(t *testing.T) {
	f := newFakeRunner()
	f.on(probeHashlimit, fail(extensionMissing))
	g := newLegacyGuard(f)
	g.root = withTun(charDevice)
	ctx := context.Background()
	scriptInstalled(f)
	if err := g.InstallFirewall(ctx, withDefaultSettings(testFirewall), uiPort); err != nil {
		t.Fatalf("InstallFirewall: %v", err)
	}
	if _, _, err := g.RuleCounters(ctx); err != nil {
		t.Fatalf("RuleCounters: %v", err)
	}
	g.SelfCheck(ctx)
	if support, err := g.ProtectionSupport(ctx); err != nil || support.SYNFlood != domain.ProtectionGlobal {
		t.Fatalf("ProtectionSupport = %+v, %v", support, err)
	}
	if n := countOfCall(f.calls, " -w -N TUNNELDECK-EXT-PROBE"); n != 1 {
		t.Errorf("probed %d times, want once", n)
	}
	g.backend = &Backend{Binary: plainBinary}
	if _, err := g.ProtectionSupport(ctx); err != nil {
		t.Fatalf("ProtectionSupport: %v", err)
	}
	if n := countOfCall(f.calls, " -w -N TUNNELDECK-EXT-PROBE"); n != 2 || !slices.Contains(f.calls, "iptables -w -N TUNNELDECK-EXT-PROBE") {
		t.Errorf("probed %d times, want again with the new backend", n)
	}
}

func countOfCall(calls []string, suffix string) int {
	n := 0
	for _, call := range calls {
		if strings.HasSuffix(call, suffix) {
			n++
		}
	}
	return n
}

func TestSelfCheckReportsMissingExtensions(t *testing.T) {
	everyCheckPasses := map[string]string{CheckCounters: "", CheckSYNFlood: "", CheckPingLimit: "", CheckMSSClamp: "", CheckReject: "", CheckReplyRouting: ""}
	tests := []struct {
		name    string
		missing []string
		// want maps each extension check to the detail it must contain;
		// "" for a passing check.
		want map[string]string
	}{
		{name: "every extension", want: everyCheckPasses},
		{
			name:    "no hashlimit: only the SYN flood protection is reduced",
			missing: []string{probeHashlimit},
			want: map[string]string{
				CheckCounters: "", CheckMSSClamp: "", CheckPingLimit: "", CheckReject: "", CheckReplyRouting: "",
				CheckSYNFlood: "falls back to the limit match: one global rate",
			},
		},
		{
			name:    "no rate limit, no TCPMSS, no REJECT",
			missing: []string{probeHashlimit, probeLimit, probeTCPMSS, probeReject},
			want: map[string]string{
				CheckCounters:     "",
				CheckSYNFlood:     "SYN flood protection is left out",
				CheckPingLimit:    "the ping limit is left out",
				CheckMSSClamp:     "xt_TCPMSS",
				CheckReject:       "the action reject drop instead",
				CheckReplyRouting: "",
			},
		},
		{
			name:    "no mangle table: replies by address",
			missing: []string{probeMangleChain},
			want: map[string]string{
				CheckCounters: "", CheckSYNFlood: "", CheckPingLimit: "", CheckMSSClamp: "", CheckReject: "",
				CheckReplyRouting: "routed by the target's address",
			},
		},
		{
			name:    "no connmark match: replies by address",
			missing: []string{probeReplyRestore},
			want: map[string]string{
				CheckCounters: "", CheckSYNFlood: "", CheckPingLimit: "", CheckMSSClamp: "", CheckReject: "",
				CheckReplyRouting: "routed by the target's address",
			},
		},
	}
	hints := map[string]string{CheckCounters: hintCounters, CheckSYNFlood: hintRateLimit, CheckPingLimit: hintRateLimit,
		CheckMSSClamp: hintMSSClamp, CheckReject: hintReject, CheckReplyRouting: hintReplyRouting}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			for _, probe := range tt.missing {
				f.on(probe, fail(extensionMissing))
			}
			g := newLegacyGuard(f)
			g.root = withTun(charDevice)
			seen := 0
			for _, r := range g.SelfCheck(context.Background()) {
				detail, checked := tt.want[r.ID]
				if !checked {
					continue
				}
				seen++
				switch {
				case detail == "" && (!r.OK || r.Warning):
					t.Errorf("%s = %+v, want passed", r.ID, r)
				case detail != "" && (r.OK || !r.Warning || r.Hint != hints[r.ID] || !strings.Contains(r.Detail, detail)):
					t.Errorf("%s = %+v, want a warning with %q", r.ID, r, detail)
				}
			}
			if seen != len(tt.want) {
				t.Errorf("saw %d extension checks, want %d", seen, len(tt.want))
			}
		})
	}
}

// extensionChecks are the self-checks of optional extensions, which only
// warn.
var extensionChecks = []string{CheckCounters, CheckSYNFlood, CheckPingLimit, CheckMSSClamp, CheckReject, CheckReplyRouting}

// mangleMissing is how iptables-legacy fails on a kernel without the
// mangle table.
const mangleMissing = "iptables v1.8.13 (legacy): can't initialize iptables table `mangle': Table does not exist (do you need to insmod?)"

// TestProbeWithoutCONNMARK: a kernel without the mangle table or without
// the connmark module routes replies by source and never gets a mangle
// chain; a failing probe line still has its probe chain removed.
func TestProbeWithoutCONNMARK(t *testing.T) {
	filterProbe := probeCalls[:8]
	tests := []struct {
		name   string
		script func(*fakeRunner)
		probes []string
	}{
		{
			name:   "no mangle table: nothing more is tried in it",
			script: func(f *fakeRunner) { f.on(probeMangleChain, fail(mangleMissing)) },
			probes: slices.Concat(filterProbe, []string{probeMangleChain}),
		},
		{
			name:   "no CONNMARK target",
			script: func(f *fakeRunner) { f.on(probeReplyMark, fail(extensionMissing)) },
			probes: probeCalls,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			scriptFresh(f)
			g := newLegacyGuard(f)
			ike := rulesOnly(portForward(domain.ProtocolUDP, "192.168.2.2", domain.SinglePort(500)))
			if err := g.InstallFirewall(context.Background(), ike, uiPort); err != nil {
				t.Fatalf("InstallFirewall: %v", err)
			}
			calls := f.takeCalls()
			assertCalls(t, calls[:len(detectLegacy)+len(tt.probes)], slices.Concat(detectLegacy, tt.probes))
			for _, call := range calls[len(detectLegacy)+len(tt.probes):] {
				if strings.Contains(call, "mangle") {
					t.Errorf("installation without CONNMARK ran %q", call)
				}
			}
			if g.replyRouting() != replyBySource {
				t.Errorf("reply routing = %v, want by source", g.replyRouting())
			}

			f.on(ruleShow, ok(defaultRules))
			if err := g.RouteThroughTunnel(context.Background(), vpnIP, nil); err != nil {
				t.Fatalf("RouteThroughTunnel: %v", err)
			}
			assertCalls(t, f.takeCalls(), []string{routeReplace, ruleShow, "ip rule add from 10.8.0.2 lookup 7194 priority 7194", addrShow,
				"ip rule add from 192.168.2.2/32 to 192.168.2.0/24 lookup main priority 7100",
				"ip rule add from 192.168.2.2/32 lookup 7194 priority 7191"})

			if err := g.RemoveFirewall(context.Background()); err != nil {
				t.Fatalf("RemoveFirewall: %v", err)
			}
			for _, call := range f.takeCalls() {
				if strings.Contains(call, "mangle") {
					t.Errorf("removal without CONNMARK ran %q", call)
				}
			}
		})
	}
}

// TestRepliesByConnectionMark: with CONNMARK a port forward fills
// TUNNELDECK-MANGLE-PRE, the tunnel routes its replies by the mark, and the
// removal deletes the chain and its jump.
func TestRepliesByConnectionMark(t *testing.T) {
	f := newFakeRunner()
	scriptFresh(f)
	g := newLegacyGuard(f)
	ike := rulesOnly(portForward(domain.ProtocolUDP, "192.168.2.2", domain.SinglePort(500)))
	if err := g.InstallFirewall(context.Background(), ike, uiPort); err != nil {
		t.Fatalf("InstallFirewall: %v", err)
	}
	calls := f.takeCalls()
	if want := freshMangleCalls([]string{replyMarkLine, replyRestoreLine}); !slices.Equal(calls[len(calls)-len(want):], want) {
		t.Errorf("installation ends with\n%s\nwant\n%s", strings.Join(calls[len(calls)-len(want):], "\n"), strings.Join(want, "\n"))
	}

	f.on(ruleShow, ok(defaultRules))
	if err := g.RouteThroughTunnel(context.Background(), vpnIP, nil); err != nil {
		t.Fatalf("RouteThroughTunnel: %v", err)
	}
	assertCalls(t, f.takeCalls(), []string{routeReplace, ruleShow, "ip rule add from 10.8.0.2 lookup 7194 priority 7194", addrShow,
		addMarkedReply})

	f.on(manglePrefix+"-S PREROUTING", ok("-P PREROUTING ACCEPT\n-A PREROUTING -j TUNNELDECK-MANGLE-PRE\n"))
	if err := g.RemoveFirewall(context.Background()); err != nil {
		t.Fatalf("RemoveFirewall: %v", err)
	}
	calls = f.takeCalls()
	assertCalls(t, calls[len(calls)-4:], prefixed(manglePrefix,
		"-S PREROUTING", "-D PREROUTING -j TUNNELDECK-MANGLE-PRE", "-F TUNNELDECK-MANGLE-PRE", "-X TUNNELDECK-MANGLE-PRE"))
}

// TestRejectRulesWithoutTheRejectTarget installs reject rules as DROP when
// the kernel lacks the REJECT target.
func TestRejectRulesWithoutTheRejectTarget(t *testing.T) {
	reject := func(r domain.FirewallRule) domain.FirewallRule {
		return changed(r, func(r *domain.FirewallRule) { r.Action = domain.ActionReject })
	}
	firewall := rulesOnly(
		reject(hostRule(domain.ProtocolTCP, domain.SinglePort(23))),
		reject(outboundRule(domain.ProtocolUDP, "192.168.2.2", "10.0.0.0/8")),
	)
	tests := []struct {
		name           string
		missing        []string
		input, forward []string
	}{
		{
			name:  "REJECT available",
			input: inputWith("-p tcp --dport 23 -m comment --comment tdrule:r1 -j REJECT --reject-with tcp-reset"),
			forward: forwardWith("-o tdvpn0 -s 192.168.2.2/32 -d 10.0.0.0/8 -p udp -m comment --comment tdrule:r2 " +
				"-j REJECT --reject-with icmp-port-unreachable"),
		},
		{
			name:    "REJECT missing: DROP",
			missing: []string{probeReject},
			input:   inputWith("-p tcp --dport 23 -m comment --comment tdrule:r1 -j DROP"),
			forward: forwardWith("-o tdvpn0 -s 192.168.2.2/32 -d 10.0.0.0/8 -p udp -m comment --comment tdrule:r2 -j DROP"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := installedState{input: 1, forward: 1}
			f := newFakeRunner()
			scriptState(f, state)
			for _, probe := range tt.missing {
				f.on(probe, fail(extensionMissing))
			}
			if err := newLegacyGuard(f).InstallFirewall(context.Background(), firewall, uiPort); err != nil {
				t.Fatalf("InstallFirewall: %v", err)
			}
			assertCalls(t, f.calls, slices.Concat(detectInstall, reinstallCalls(state, tt.input, tt.forward, nil, nil)))
		})
	}
}
