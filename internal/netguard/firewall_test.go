package netguard

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

func TestInstallFirewallSequences(t *testing.T) {
	changedState := installedState{input: 4, forward: 1, prerouting: 2, postrouting: 1}
	tests := []struct {
		name     string
		script   func(*fakeRunner)
		firewall domain.Firewall
		want     []string
	}{
		{
			name:     "fresh install",
			script:   scriptFresh,
			firewall: testFirewall,
			want:     freshCalls(testInput, testForward, nil, nil),
		},
		{
			name:     "rule change appends new content and trims the old in every chain",
			script:   func(f *fakeRunner) { scriptState(f, changedState) },
			firewall: rulesOnly(changed(hostRule(domain.ProtocolTCP, domain.SinglePort(443)), func(r *domain.FirewallRule) { r.Source = "10.0.0.0/8" })),
			want: slices.Concat(detectInstall, reinstallCalls(changedState,
				inputWith(onRule(1, "-p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT")), testForward, nil, nil)),
		},
		{
			name: "existing chain without trailing DROP is sealed first",
			script: func(f *fakeRunner) {
				scriptInstalled(f)
				f.scripts[legacy+"-S TUNNELDECK-INPUT"] = []fakeResult{ok("-N TUNNELDECK-INPUT\n")}
			},
			firewall: domain.Firewall{},
			want: slices.Concat(detectInstall, []string{addrShow}, prefixed(legacy,
				"-S TUNNELDECK-INPUT",
				"-A TUNNELDECK-INPUT -j DROP",
				"-S INPUT",
				"-A TUNNELDECK-INPUT "+uiPortDrop,
				"-A TUNNELDECK-INPUT "+established,
				"-A TUNNELDECK-INPUT -j DROP",
				"-D TUNNELDECK-INPUT 1",
			), refillCalls(legacy, forwardChain, "FORWARD", 1, testForward),
				refillCalls(natPrefix, preroutingChain, "PREROUTING", 0, nil),
				refillCalls(natPrefix, postroutingChain, "POSTROUTING", 0, nil)),
		},
		{
			name: "duplicate and displaced jumps are moved behind guards",
			script: func(f *fakeRunner) {
				scriptInstalled(f)
				f.scripts[legacy+"-S INPUT"] = []fakeResult{ok("-P INPUT ACCEPT\n" +
					"-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT\n" +
					"-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT\n")}
				f.scripts[legacy+"-S FORWARD"] = []fakeResult{ok("-P FORWARD DROP\n" +
					"-A FORWARD -j DOCKER-USER\n" +
					"-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD\n" +
					"-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD\n")}
				f.scripts[natPrefix+"-S POSTROUTING"] = []fakeResult{ok("-P POSTROUTING ACCEPT\n" +
					"-A POSTROUTING -j DOCKER_POSTROUTING\n" +
					"-A POSTROUTING -j TUNNELDECK-POSTROUTING\n")}
				f.on(legacy+"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", ok(""), ok(""), fail(badRule)).
					on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", ok(""), fail(badRule)).
					on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", ok(""), fail(badRule)).
					on(natPrefix+"-C POSTROUTING -j TUNNELDECK-POSTROUTING", ok(""), fail(badRule))
			},
			firewall: domain.Firewall{},
			want: slices.Concat(detectInstall, []string{addrShow}, prefixed(legacy,
				"-S TUNNELDECK-INPUT",
				"-S INPUT",
				"-I INPUT 1 -i tdvpn0 -j DROP",
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-D INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-D INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-I INPUT 1 -i tdvpn0 -j TUNNELDECK-INPUT",
				"-D INPUT -i tdvpn0 -j DROP",
				"-A TUNNELDECK-INPUT "+uiPortDrop,
				"-A TUNNELDECK-INPUT "+established,
				"-A TUNNELDECK-INPUT -j DROP",
				"-D TUNNELDECK-INPUT 1",
				"-S TUNNELDECK-FORWARD",
				"-S FORWARD",
				"-I FORWARD 1 -i tdvpn0 -j DROP",
				"-I FORWARD 1 -o tdvpn0 -j DROP",
				"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-I FORWARD 1 -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-I FORWARD 1 -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -i tdvpn0 -j DROP",
				"-D FORWARD -o tdvpn0 -j DROP",
			), appends(legacy, forwardChain, testForward), prefixed(legacy, "-D TUNNELDECK-FORWARD 1"),
				refillCalls(natPrefix, preroutingChain, "PREROUTING", 0, nil),
				prefixed(natPrefix,
					"-S TUNNELDECK-POSTROUTING",
					"-S POSTROUTING",
					"-C POSTROUTING -j TUNNELDECK-POSTROUTING",
					"-D POSTROUTING -j TUNNELDECK-POSTROUTING",
					"-C POSTROUTING -j TUNNELDECK-POSTROUTING",
					"-I POSTROUTING 1 -j TUNNELDECK-POSTROUTING",
				)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			if err := newLegacyGuard(f).InstallFirewall(context.Background(), tt.firewall, uiPort); err != nil {
				t.Fatalf("InstallFirewall: %v", err)
			}
			assertCalls(t, f.calls, tt.want)
		})
	}
}

// TestRuleShapes installs one rule shape each over an installed state and
// checks every chain's new content.
func TestRuleShapes(t *testing.T) {
	const (
		ikeForward  = "-i tdvpn0 -d 192.168.2.2/32 -p udp --dport 500 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT"
		ikeDNAT     = "-p udp --dport 500 -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.2"
		ikeMasq     = "! -o tdvpn0 -d 192.168.2.2/32 -p udp --dport 500 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j MASQUERADE"
		routerJump  = "-A FORWARD -s 192.168.2.2/32 -j TUNNELDECK-FORWARD"
		officeJump  = "-A FORWARD -s 192.168.2.0/24 -d 10.0.0.0/8 -j TUNNELDECK-FORWARD"
		routerLocal = "! -i tdvpn0 ! -o tdvpn0 -s 192.168.2.2/32 -d 192.168.2.0/24 -m comment --comment tdfixed:lan-return -j RETURN"
	)
	ike := portForward(domain.ProtocolUDP, "192.168.2.2", domain.SinglePort(500))
	tests := []struct {
		name                                    string
		firewall                                domain.Firewall
		forwardJumps                            []string
		input, forward, prerouting, postrouting []string
	}{
		{
			name: "inbound host rules: range with source port, icmp, drop and reject",
			firewall: rulesOnly(
				changed(hostRule(domain.ProtocolTCP, ports(5000, 5010)), func(r *domain.FirewallRule) {
					r.Source, r.SourcePort = "203.0.113.0/24", ports(1024, 1100)
				}),
				changed(hostRule(domain.ProtocolICMP, domain.PortRange{}), func(r *domain.FirewallRule) { r.ICMPType = "echo-request" }),
				changed(hostRule(domain.ProtocolAny, domain.PortRange{}), func(r *domain.FirewallRule) {
					r.Action, r.Source = domain.ActionDrop, "198.51.100.7"
				}),
				changed(hostRule(domain.ProtocolTCPUDP, domain.SinglePort(23)), func(r *domain.FirewallRule) { r.Action = domain.ActionReject }),
				hostRule(domain.ProtocolESP, domain.PortRange{}),
				changed(hostRule(domain.ProtocolTCP, domain.SinglePort(25)), func(r *domain.FirewallRule) { r.Enabled = false }),
			),
			input: inputWith(
				"-p tcp --sport 1024:1100 --dport 5000:5010 -s 203.0.113.0/24 -m comment --comment tdrule:r1 -j ACCEPT",
				"-p icmp --icmp-type echo-request -m comment --comment tdrule:r2 -j ACCEPT",
				"-s 198.51.100.7/32 -m comment --comment tdrule:r3 -j DROP",
				"-p tcp --dport 23 -m comment --comment tdrule:r4 -j REJECT --reject-with tcp-reset",
				"-p udp --dport 23 -m comment --comment tdrule:r4 -j REJECT --reject-with icmp-port-unreachable",
				"-p 50 -m comment --comment tdrule:r5 -j ACCEPT",
			),
			forward: testForward,
		},
		{
			name:        "inbound DNAT to a LAN target with masquerade",
			firewall:    rulesOnly(ike),
			input:       inputWith(),
			forward:     forwardWith(ikeForward),
			prerouting:  []string{ikeDNAT},
			postrouting: []string{ikeMasq},
		},
		{
			name: "inbound DNAT keeping the source address, from one peer",
			firewall: rulesOnly(changed(ike, func(r *domain.FirewallRule) {
				r.KeepSourceAddress, r.Source = true, "198.51.100.0/24"
			})),
			input:      inputWith(),
			forward:    forwardWith("-i tdvpn0 -d 192.168.2.2/32 -p udp --dport 500 -s 198.51.100.0/24 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT"),
			prerouting: []string{"-p udp --dport 500 -s 198.51.100.0/24 -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.2"},
		},
		{
			name: "port range shifted to other ports",
			firewall: rulesOnly(changed(portForward(domain.ProtocolTCP, "192.168.2.3", ports(9000, 9010)), func(r *domain.FirewallRule) {
				r.PublicPort = ports(8000, 8010)
			})),
			input:       inputWith(),
			forward:     forwardWith("-i tdvpn0 -d 192.168.2.3/32 -p tcp --dport 9000:9010 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT"),
			prerouting:  []string{"-p tcp --dport 8000:8010 -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.3:9000-9010/8000"},
			postrouting: []string{"! -o tdvpn0 -d 192.168.2.3/32 -p tcp --dport 9000:9010 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j MASQUERADE"},
		},
		{
			name: "public port differs from the destination port, tcp+udp",
			firewall: rulesOnly(changed(portForward(domain.ProtocolTCPUDP, "192.168.2.3", domain.SinglePort(22)), func(r *domain.FirewallRule) {
				r.PublicPort = domain.SinglePort(2222)
			})),
			input: inputWith(),
			forward: forwardWith(
				"-i tdvpn0 -d 192.168.2.3/32 -p tcp --dport 22 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT",
				"-i tdvpn0 -d 192.168.2.3/32 -p udp --dport 22 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT"),
			prerouting: []string{
				"-p tcp --dport 2222 -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.3:22",
				"-p udp --dport 2222 -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.3:22"},
			postrouting: []string{
				"! -o tdvpn0 -d 192.168.2.3/32 -p tcp --dport 22 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j MASQUERADE",
				"! -o tdvpn0 -d 192.168.2.3/32 -p udp --dport 22 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j MASQUERADE"},
		},
		{
			name: "inbound host rules on any port: tcp+udp from a source, drop udp",
			firewall: rulesOnly(
				changed(hostRule(domain.ProtocolTCPUDP, domain.PortRange{}), func(r *domain.FirewallRule) { r.Source = "10.8.0.0/24" }),
				changed(hostRule(domain.ProtocolUDP, domain.PortRange{}), func(r *domain.FirewallRule) { r.Action = domain.ActionDrop }),
			),
			input: inputWith(
				"-p tcp -s 10.8.0.0/24 -m comment --comment tdrule:r1 -j ACCEPT",
				"-p udp -s 10.8.0.0/24 -m comment --comment tdrule:r1 -j ACCEPT",
				"-p udp -m comment --comment tdrule:r2 -j DROP",
			),
			forward: testForward,
		},
		{
			name:     "forward on any port keeps the web UI port for the host",
			firewall: rulesOnly(portForward(domain.ProtocolTCPUDP, "192.168.2.5", domain.PortRange{})),
			input:    inputWith(),
			forward: forwardWith(
				"-i tdvpn0 -d 192.168.2.5/32 -p tcp -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT",
				"-i tdvpn0 -d 192.168.2.5/32 -p udp -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT"),
			prerouting: []string{
				"-p tcp --dport 8080 -m comment --comment tdfixed:host-port -j RETURN",
				"-p tcp -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.5",
				"-p udp -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.5"},
			postrouting: []string{
				"! -o tdvpn0 -d 192.168.2.5/32 -p tcp -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j MASQUERADE",
				"! -o tdvpn0 -d 192.168.2.5/32 -p udp -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j MASQUERADE"},
		},
		{
			name:       "udp forward on any port needs no exclusions",
			firewall:   rulesOnly(changed(portForward(domain.ProtocolUDP, "192.168.2.5", domain.PortRange{}), func(r *domain.FirewallRule) { r.KeepSourceAddress = true })),
			input:      inputWith(),
			forward:    forwardWith("-i tdvpn0 -d 192.168.2.5/32 -p udp -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT"),
			prerouting: []string{"-p udp -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.5"},
		},
		{
			name:         "outbound udp on any port",
			firewall:     rulesOnly(outboundRule(domain.ProtocolUDP, "192.168.2.0/24", "10.0.0.0/8")),
			forwardJumps: []string{officeJump},
			input:        inputWith(),
			forward:      forwardWith("-o tdvpn0 -s 192.168.2.0/24 -d 10.0.0.0/8 -p udp -m comment --comment tdrule:r1 -j ACCEPT"),
			postrouting:  []string{"-o tdvpn0 -s 192.168.2.0/24 -d 10.0.0.0/8 -m comment --comment tdrule:r1 -j MASQUERADE"},
		},
		{
			name: "ESP and GRE forwarding",
			firewall: rulesOnly(
				changed(portForward(domain.ProtocolESP, "192.168.2.2", domain.PortRange{}), func(r *domain.FirewallRule) { r.KeepSourceAddress = true }),
				portForward(domain.ProtocolGRE, "192.168.2.4", domain.PortRange{}),
			),
			input: inputWith(),
			forward: forwardWith(
				"-i tdvpn0 -d 192.168.2.2/32 -p 50 -m conntrack --ctstate DNAT -m comment --comment tdrule:r1 -j ACCEPT",
				"-i tdvpn0 -d 192.168.2.4/32 -p 47 -m conntrack --ctstate DNAT -m comment --comment tdrule:r2 -j ACCEPT"),
			prerouting:  []string{"-p 50 -m comment --comment tdrule:r1 -j DNAT --to-destination 192.168.2.2", "-p 47 -m comment --comment tdrule:r2 -j DNAT --to-destination 192.168.2.4"},
			postrouting: []string{"! -o tdvpn0 -d 192.168.2.4/32 -p 47 -m conntrack --ctstate DNAT -m comment --comment tdrule:r2 -j MASQUERADE"},
		},
		{
			name: "outbound to a network, tcp 443",
			firewall: rulesOnly(changed(outboundRule(domain.ProtocolTCP, "192.168.2.0/24", "10.0.0.0/8"), func(r *domain.FirewallRule) {
				r.DestinationPort = domain.SinglePort(443)
			})),
			forwardJumps: []string{officeJump},
			input:        inputWith(),
			forward:      forwardWith("-o tdvpn0 -s 192.168.2.0/24 -d 10.0.0.0/8 -p tcp --dport 443 -m comment --comment tdrule:r1 -j ACCEPT"),
			postrouting:  []string{"-o tdvpn0 -s 192.168.2.0/24 -d 10.0.0.0/8 -m comment --comment tdrule:r1 -j MASQUERADE"},
		},
		{
			name: "outbound to everything keeps the LAN out, with a drop rule above",
			firewall: rulesOnly(
				changed(outboundRule(domain.ProtocolAny, "192.168.2.2", "10.66.0.0/16"), func(r *domain.FirewallRule) { r.Action = domain.ActionDrop }),
				outboundRule(domain.ProtocolAny, "192.168.2.2", "0.0.0.0/0"),
			),
			forwardJumps: []string{routerJump},
			input:        inputWith(),
			forward: slices.Concat([]string{routerLocal}, forwardWith(
				"-o tdvpn0 -s 192.168.2.2/32 -d 10.66.0.0/16 -m comment --comment tdrule:r1 -j DROP",
				"-o tdvpn0 -s 192.168.2.2/32 -m comment --comment tdrule:r2 -j ACCEPT")),
			postrouting: []string{"-o tdvpn0 -s 192.168.2.2/32 -m comment --comment tdrule:r2 -j MASQUERADE"},
		},
		{
			name:     "global protections",
			firewall: withDefaultSettings(rulesOnly(hostRule(domain.ProtocolTCP, domain.SinglePort(22)))),
			input: []string{
				uiPortDrop, invalidDrop, established,
				"-p tcp --syn -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-name td-syn-in -m comment --comment tdfixed:syn-flood -j DROP",
				"-p icmp --icmp-type echo-request -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-name td-ping-in -m comment --comment tdfixed:ping-limit -j DROP",
				"-p tcp --dport 22 -m comment --comment tdrule:r1 -j ACCEPT",
				dropAll,
			},
			forward: []string{
				killSwitchDrop, invalidDrop,
				"-p tcp --tcp-flags SYN,RST SYN -m comment --comment tdfixed:mss-clamp -j TCPMSS --clamp-mss-to-pmtu",
				established,
				"-i tdvpn0 -p tcp --syn -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-name td-syn-fwd -m comment --comment tdfixed:syn-flood -j DROP",
				"-i tdvpn0 -p icmp --icmp-type echo-request -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-name td-ping-fwd -m comment --comment tdfixed:ping-limit -j DROP",
				dropAll,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := installedState{input: 1, forward: 1, forwardJumps: tt.forwardJumps}
			f := newFakeRunner()
			scriptState(f, state)
			if err := newLegacyGuard(f).InstallFirewall(context.Background(), tt.firewall, uiPort); err != nil {
				t.Fatalf("InstallFirewall: %v", err)
			}
			assertCalls(t, f.calls, slices.Concat(detectInstall,
				reinstallCalls(state, tt.input, tt.forward, tt.prerouting, tt.postrouting)))
		})
	}
}

func TestKillSwitchJumpsFollowTheOutboundRules(t *testing.T) {
	const stale = "-A FORWARD -s 192.168.9.9/32 -j TUNNELDECK-FORWARD"
	f := newFakeRunner()
	scriptState(f, installedState{input: 1, forward: 1, forwardJumps: []string{stale}})
	f.on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", ok(""), fail(badRule)).
		on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", ok(""), fail(badRule)).
		on(legacy+"-C FORWARD -s 192.168.2.2/32 -d 198.51.100.0/24 -j TUNNELDECK-FORWARD", fail(badRule))
	firewall := rulesOnly(outboundRule(domain.ProtocolAny, "192.168.2.2", "198.51.100.0/24"))
	if err := newLegacyGuard(f).InstallFirewall(context.Background(), firewall, uiPort); err != nil {
		t.Fatalf("InstallFirewall: %v", err)
	}
	start := slices.Index(f.calls, legacy+"-S FORWARD")
	end := slices.Index(f.calls, legacy+"-A TUNNELDECK-FORWARD "+killSwitchDrop)
	assertCalls(t, f.calls[start:end], prefixed(legacy,
		"-S FORWARD",
		"-I FORWARD 1 -i tdvpn0 -j DROP",
		"-I FORWARD 1 -o tdvpn0 -j DROP",
		"-I FORWARD 1 -s 192.168.2.2/32 -d 198.51.100.0/24 -j DROP",
		"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
		"-D FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
		"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
		"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
		"-D FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
		"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
		"-C FORWARD -s 192.168.2.2/32 -d 198.51.100.0/24 -j TUNNELDECK-FORWARD",
		"-D FORWARD -s 192.168.9.9/32 -j TUNNELDECK-FORWARD",
		"-I FORWARD 1 -s 192.168.2.2/32 -d 198.51.100.0/24 -j TUNNELDECK-FORWARD",
		"-I FORWARD 1 -o tdvpn0 -j TUNNELDECK-FORWARD",
		"-I FORWARD 1 -i tdvpn0 -j TUNNELDECK-FORWARD",
		"-D FORWARD -i tdvpn0 -j DROP",
		"-D FORWARD -o tdvpn0 -j DROP",
		"-D FORWARD -s 192.168.2.2/32 -d 198.51.100.0/24 -j DROP",
	))
}

func TestInstallFirewallIsIdempotent(t *testing.T) {
	f := newFakeRunner()
	scriptFresh(f)
	g := newLegacyGuard(f)
	if err := g.InstallFirewall(context.Background(), testFirewall, uiPort); err != nil {
		t.Fatalf("first install: %v", err)
	}
	f.takeCalls()

	state := installedState{input: 4, forward: 3}
	want := reinstallCalls(state, testInput, testForward, nil, nil)
	for run := range 2 {
		scriptState(f, state)
		if err := g.InstallFirewall(context.Background(), testFirewall, uiPort); err != nil {
			t.Fatalf("re-install %d: %v", run, err)
		}
		calls := f.takeCalls()
		assertCalls(t, calls, want)
		for _, call := range calls {
			if strings.Contains(call, " -I ") || strings.Contains(call, " -N ") || strings.HasPrefix(call, "ip rule") {
				t.Errorf("re-install %d ran %q; jumps, chains and policy rules must not be added again", run, call)
			}
		}
	}
}

func TestInstallFirewallRejectsInvalidRulesBeforeAnyCommand(t *testing.T) {
	tests := []struct {
		name     string
		firewall domain.Firewall
		field    string
	}{
		{
			name:     "enabled rule on the UI port",
			firewall: rulesOnly(hostRule(domain.ProtocolTCP, domain.SinglePort(uiPort))),
			field:    "rules[0].destinationPort",
		},
		{
			name: "disabled rule on the UI port",
			firewall: rulesOnly(hostRule(domain.ProtocolTCP, domain.SinglePort(22)),
				changed(hostRule(domain.ProtocolUDP, ports(8000, 8100)), func(r *domain.FirewallRule) { r.Enabled = false })),
			field: "rules[1].destinationPort",
		},
		{
			name: "port forward with the UI port as public port",
			firewall: rulesOnly(changed(portForward(domain.ProtocolTCP, "192.168.2.2", domain.SinglePort(80)), func(r *domain.FirewallRule) {
				r.PublicPort = domain.SinglePort(uiPort)
			})),
			field: "rules[0].publicPort",
		},
		{
			name:     "invalid protocol",
			firewall: rulesOnly(changed(hostRule(domain.ProtocolTCP, domain.SinglePort(1)), func(r *domain.FirewallRule) { r.Protocol = "sctp" })),
			field:    "rules[0].protocol",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			err := newLegacyGuard(f).InstallFirewall(context.Background(), tt.firewall, uiPort)
			assertValidationField(t, err, tt.field)
			if len(f.calls) != 0 {
				t.Errorf("commands ran before validation: %v", f.calls)
			}
		})
	}
}

// TestInboundRulesFollowTheHostAddress classifies inbound rules by the
// host's addresses at build time: its own address and a legacy host rule
// go to TUNNELDECK-INPUT, any other address is forwarded.
func TestInboundRulesFollowTheHostAddress(t *testing.T) {
	ssh := hostRule(domain.ProtocolTCP, domain.SinglePort(22))
	firewall := rulesOnly(ssh, hostAccess("", domain.ProtocolUDP, 161, "", true))
	at := func(listing string) ruleset {
		return buildRuleset(firewall, hostPorts{}, parseLANAddresses(listing), capsWithout())
	}
	rs := at(lanListing)
	if !slices.ContainsFunc(rs.input, hasTag("r1")) || !slices.ContainsFunc(rs.input, hasTag("r2")) || len(rs.prerouting) != 0 {
		t.Fatalf("rules to the host: input %v, prerouting %v", rs.input, rs.prerouting)
	}
	moved := strings.Replace(lanListing, testHostAddress+"/24", "192.168.2.11/24", 1)
	rs = at(moved)
	if slices.ContainsFunc(rs.input, hasTag("r1")) || !slices.ContainsFunc(rs.prerouting, hasTag("r1")) ||
		!slices.ContainsFunc(rs.input, hasTag("r2")) {
		t.Fatalf("after the host moved: input %v, prerouting %v", rs.input, rs.prerouting)
	}
}

func TestInstallFirewallRejectsDropToAnotherDevice(t *testing.T) {
	drop := rulesOnly(changed(portForward(domain.ProtocolTCP, "192.168.2.5", domain.SinglePort(22)), func(r *domain.FirewallRule) {
		r.Action = domain.ActionDrop
	}))
	f := newFakeRunner()
	err := newLegacyGuard(f).InstallFirewall(context.Background(), drop, uiPort)
	assertValidationField(t, err, "rules[0].action")
}

func TestInstallFirewallChecksTheLAN(t *testing.T) {
	outside := rulesOnly(portForward(domain.ProtocolUDP, "10.20.30.40", domain.SinglePort(500)))
	f := newFakeRunner()
	err := newLegacyGuard(f).InstallFirewall(context.Background(), outside, uiPort)
	assertValidationField(t, err, "rules[0].destination")
	assertCalls(t, f.calls, slices.Concat(detectInstall, []string{addrShow}))

	disabled := rulesOnly(changed(outside.Rules[0], func(r *domain.FirewallRule) { r.Enabled = false }))
	f = newFakeRunner()
	scriptInstalled(f)
	if err := newLegacyGuard(f).InstallFirewall(context.Background(), disabled, uiPort); err != nil {
		t.Errorf("a disabled rule outside the LAN blocked the installation: %v", err)
	}

	f = newFakeRunner()
	g := New(f, WithBackend(BackendLegacy))
	f.always(addrShow, fail("exec: \"ip\": executable file not found in $PATH"))
	if err := g.InstallFirewall(context.Background(), testFirewall, uiPort); err == nil || !strings.Contains(err.Error(), "detect LAN subnets") {
		t.Fatalf("err = %v, want the LAN detection failure", err)
	}
	if slices.ContainsFunc(f.calls, func(c string) bool {
		return strings.Contains(c, "TUNNELDECK") && !strings.Contains(c, extensionProbeChain)
	}) {
		t.Errorf("chains touched without LAN subnets: %v", f.calls)
	}
}

func TestConntrackFallsBackToStateMatch(t *testing.T) {
	const conntrackRule = legacy + "-A TUNNELDECK-INPUT " + established
	const stateRule = legacy + "-A TUNNELDECK-INPUT -m state --state ESTABLISHED,RELATED -m comment --comment tdfixed:established -j ACCEPT"
	f := newFakeRunner()
	scriptInstalled(f)
	f.on(conntrackRule, fail("iptables v1.8.7 (legacy): Couldn't load match `conntrack':No such file or directory"))
	g := newLegacyGuard(f)
	firewall := rulesOnly(portForward(domain.ProtocolUDP, "192.168.2.2", domain.SinglePort(500)))
	if err := g.InstallFirewall(context.Background(), firewall, uiPort); err != nil {
		t.Fatalf("first install: %v", err)
	}
	calls := f.takeCalls()
	afterListings := len(detectInstall) + 3
	assertCalls(t, calls[afterListings:afterListings+4], []string{
		legacy + "-A TUNNELDECK-INPUT " + uiPortDrop, conntrackRule, stateRule, legacy + "-A TUNNELDECK-INPUT -j DROP",
	})
	for _, want := range []string{
		legacy + "-A TUNNELDECK-FORWARD -i tdvpn0 -d 192.168.2.2/32 -p udp --dport 500 -m comment --comment tdrule:r1 -j ACCEPT",
		natPrefix + "-A TUNNELDECK-POSTROUTING ! -o tdvpn0 -d 192.168.2.2/32 -p udp --dport 500 -m comment --comment tdrule:r1 -j MASQUERADE",
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("the state match cannot express DNAT; want %q in %v", want, calls)
		}
	}

	scriptInstalled(f)
	if err := g.InstallFirewall(context.Background(), firewall, uiPort); err != nil {
		t.Fatalf("second install: %v", err)
	}
	calls = f.takeCalls()
	if slices.Contains(calls, conntrackRule) || !slices.Contains(calls, stateRule) {
		t.Errorf("second install must use the detected state match directly: %v", calls)
	}
}

func TestConntrackAndStateBothFail(t *testing.T) {
	f := newFakeRunner()
	scriptInstalled(f)
	f.on(legacy+"-A TUNNELDECK-INPUT "+established, fail("no conntrack")).
		on(legacy+"-A TUNNELDECK-INPUT -m state --state ESTABLISHED,RELATED -m comment --comment tdfixed:established -j ACCEPT", fail("no state"))
	err := newLegacyGuard(f).InstallFirewall(context.Background(), domain.Firewall{}, uiPort)
	if err == nil || !strings.Contains(err.Error(), "no conntrack") || !strings.Contains(err.Error(), "no state") {
		t.Fatalf("err = %v, want both match failures", err)
	}
	if slices.Contains(f.calls, legacy+"-D TUNNELDECK-INPUT 1") {
		t.Error("old content was trimmed although the new content is incomplete")
	}
}

func TestInstallFirewallFailureLeavesDropInPlace(t *testing.T) {
	const failing = legacy + "-A TUNNELDECK-INPUT -p tcp --dport 22 -m comment --comment tdrule:ssh -j ACCEPT"
	f := newFakeRunner()
	scriptFresh(f)
	f.on(failing, fail("iptables: Resource temporarily unavailable."))

	err := newLegacyGuard(f).InstallFirewall(context.Background(), testFirewall, uiPort)
	if err == nil {
		t.Fatal("InstallFirewall succeeded despite a failing command")
	}
	for _, part := range []string{"TUNNELDECK-INPUT", "--dport 22", "Resource temporarily unavailable"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("err = %q, want it to contain %q", err, part)
		}
	}
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Errorf("err = %v, want it to wrap *CommandError", err)
	}
	failedAt := slices.Index(f.calls, failing)
	sealedAt := slices.Index(f.calls, legacy+"-A TUNNELDECK-INPUT -j DROP")
	jumpAt := slices.Index(f.calls, legacy+"-I INPUT 1 -i tdvpn0 -j TUNNELDECK-INPUT")
	if sealedAt < 0 || jumpAt < sealedAt || failedAt < jumpAt {
		t.Errorf("chain must end with DROP before its jump exists: %v", f.calls)
	}
	if slices.Contains(f.calls, legacy+"-D TUNNELDECK-INPUT 1") {
		t.Error("the sealing DROP was deleted after a failure")
	}
	forwardAt := slices.Index(f.calls, legacy+"-S TUNNELDECK-FORWARD")
	natAt := slices.Index(f.calls, natPrefix+"-S TUNNELDECK-POSTROUTING")
	if forwardAt < failedAt || natAt < forwardAt {
		t.Errorf("the other chains must still be installed after a failure: %v", f.calls)
	}
}

func TestInstallFirewallEarlyFailures(t *testing.T) {
	tests := []struct {
		name      string
		failing   string
		stderr    string
		forbidden string
	}{
		{"listing the chain", legacy + "-S TUNNELDECK-INPUT", noPermission, legacy + "-S INPUT"},
		{"creating the chain", legacy + "-N TUNNELDECK-INPUT", "iptables: Chain already exists.", legacy + "-I INPUT 1 -i tdvpn0 -j DROP"},
		{"sealing the chain", legacy + "-A TUNNELDECK-INPUT -j DROP", "iptables: Index of insertion too big.", legacy + "-S INPUT"},
		{"listing the parent", legacy + "-S INPUT", noPermission, legacy + "-I INPUT 1 -i tdvpn0 -j DROP"},
		{"inserting the guard", legacy + "-I INPUT 1 -i tdvpn0 -j DROP", noPermission, legacy + "-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT"},
		{"checking a jump", legacy + "-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", noPermission, legacy + "-D INPUT -i tdvpn0 -j DROP"},
		{"inserting the jump", legacy + "-I INPUT 1 -i tdvpn0 -j TUNNELDECK-INPUT", noPermission, legacy + "-D INPUT -i tdvpn0 -j DROP"},
		{"removing the guard", legacy + "-D INPUT -i tdvpn0 -j DROP", noPermission, legacy + "-D TUNNELDECK-INPUT 1"},
		{"trimming old content", legacy + "-D TUNNELDECK-INPUT 1", noPermission, ""},
		{"creating a nat chain", natPrefix + "-N TUNNELDECK-PREROUTING", "can't initialize iptables table `nat'", natPrefix + "-S PREROUTING"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			scriptFresh(f)
			f.scripts[tt.failing] = []fakeResult{fail(tt.stderr)}
			err := newLegacyGuard(f).InstallFirewall(context.Background(), testFirewall, uiPort)
			if err == nil || !strings.Contains(err.Error(), tt.stderr) {
				t.Fatalf("err = %v, want the stderr %q", err, tt.stderr)
			}
			if tt.forbidden != "" && slices.Contains(f.calls, tt.forbidden) {
				t.Errorf("%q ran after the failure", tt.forbidden)
			}
		})
	}
}

func TestStaleJumpThatVanishedIsTolerated(t *testing.T) {
	f := newFakeRunner()
	scriptState(f, installedState{input: 1, forward: 1, forwardJumps: []string{"-A FORWARD -s 10.9.9.9/32 -j TUNNELDECK-FORWARD"}})
	f.on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-D FORWARD -s 10.9.9.9/32 -j TUNNELDECK-FORWARD", fail(badRule))
	if err := newLegacyGuard(f).InstallFirewall(context.Background(), domain.Firewall{}, uiPort); err != nil {
		t.Fatalf("InstallFirewall: %v", err)
	}
	f = newFakeRunner()
	scriptState(f, installedState{input: 1, forward: 1, forwardJumps: []string{"-A FORWARD -s 10.9.9.9/32 -j TUNNELDECK-FORWARD"}})
	f.on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-D FORWARD -s 10.9.9.9/32 -j TUNNELDECK-FORWARD", fail(noPermission))
	if err := newLegacyGuard(f).InstallFirewall(context.Background(), domain.Firewall{}, uiPort); err == nil {
		t.Fatal("a failing stale-jump deletion was ignored")
	}
}

func TestRemoveFirewall(t *testing.T) {
	tests := []struct {
		name   string
		script func(*fakeRunner)
		want   []string
	}{
		{
			name: "installed state with a kill-switch jump",
			script: func(f *fakeRunner) {
				scriptState(f, installedState{forwardJumps: []string{"-A FORWARD -s 192.168.2.2/32 -j TUNNELDECK-FORWARD"}})
			},
			want: slices.Concat(detectLegacy, prefixed(legacy,
				"-S INPUT",
				"-D INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-F TUNNELDECK-INPUT",
				"-X TUNNELDECK-INPUT",
				"-S FORWARD",
				"-D FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -s 192.168.2.2/32 -j TUNNELDECK-FORWARD",
				"-F TUNNELDECK-FORWARD",
				"-X TUNNELDECK-FORWARD",
			), prefixed(natPrefix,
				"-S PREROUTING",
				"-D PREROUTING -i tdvpn0 -j TUNNELDECK-PREROUTING",
				"-F TUNNELDECK-PREROUTING",
				"-X TUNNELDECK-PREROUTING",
				"-S POSTROUTING",
				"-D POSTROUTING -j TUNNELDECK-POSTROUTING",
				"-F TUNNELDECK-POSTROUTING",
				"-X TUNNELDECK-POSTROUTING",
			), prefixed(legacy, "-F TUNNELDECK-LIMIT", "-X TUNNELDECK-LIMIT")),
		},
		{
			name: "already absent",
			script: func(f *fakeRunner) {
				f.on(legacy+"-F TUNNELDECK-INPUT", fail(noChain)).
					on(legacy+"-F TUNNELDECK-FORWARD", fail(noChain)).
					on(natPrefix+"-F TUNNELDECK-PREROUTING", fail(noChain)).
					on(natPrefix+"-F TUNNELDECK-POSTROUTING", fail(noChain)).
					on(legacy+"-F TUNNELDECK-LIMIT", fail(noChain))
			},
			want: slices.Concat(detectLegacy,
				prefixed(legacy, "-S INPUT", "-F TUNNELDECK-INPUT", "-S FORWARD", "-F TUNNELDECK-FORWARD"),
				prefixed(natPrefix, "-S PREROUTING", "-F TUNNELDECK-PREROUTING", "-S POSTROUTING", "-F TUNNELDECK-POSTROUTING"),
				prefixed(legacy, "-F TUNNELDECK-LIMIT")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			if err := newLegacyGuard(f).RemoveFirewall(context.Background()); err != nil {
				t.Fatalf("RemoveFirewall: %v", err)
			}
			assertCalls(t, f.calls, tt.want)
		})
	}
}

func TestRemoveFirewallFailures(t *testing.T) {
	tests := []struct {
		name    string
		script  func(*fakeRunner)
		wantErr string
	}{
		{
			name:    "listing a parent fails",
			script:  func(f *fakeRunner) { f.on(legacy+"-S INPUT", fail(noPermission)) },
			wantErr: "Permission denied",
		},
		{
			name: "deleting a jump fails",
			script: func(f *fakeRunner) {
				scriptInstalled(f)
				f.on(legacy+"-D INPUT -i tdvpn0 -j TUNNELDECK-INPUT", fail(noPermission))
			},
			wantErr: "-D INPUT",
		},
		{
			name: "permission denied on flush is not mistaken for absence",
			script: func(f *fakeRunner) {
				f.on(legacy+"-F TUNNELDECK-INPUT", fail(noPermission))
			},
			wantErr: "Permission denied",
		},
		{
			name:    "deleting a chain fails",
			script:  func(f *fakeRunner) { f.on(legacy+"-X TUNNELDECK-INPUT", fail("iptables: Too many links.")) },
			wantErr: "Too many links",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			err := newLegacyGuard(f).RemoveFirewall(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestDeleteAllGivesUpOnARuleThatNeverDisappears(t *testing.T) {
	f := newFakeRunner()
	scriptInstalled(f)
	f.scripts[legacy+"-S INPUT"] = []fakeResult{ok("-P INPUT ACCEPT\n")}
	err := newLegacyGuard(f).InstallFirewall(context.Background(), domain.Firewall{}, uiPort)
	if err == nil || !strings.Contains(err.Error(), "after 64 deletions") {
		t.Fatalf("err = %v, want the bounded delete loop to give up", err)
	}
}

func TestStateVariant(t *testing.T) {
	tests := map[string]string{
		"-m conntrack --ctstate INVALID -j DROP":                         "-m state --state INVALID -j DROP",
		"-i tdvpn0 -d 10.0.0.1/32 -m conntrack --ctstate DNAT -j ACCEPT": "-i tdvpn0 -d 10.0.0.1/32 -j ACCEPT",
		"-p tcp -j ACCEPT": "-p tcp -j ACCEPT",
	}
	for in, want := range tests {
		if got := strings.Join(stateVariant(strings.Fields(in)), " "); got != want {
			t.Errorf("stateVariant(%q) = %q, want %q", in, got, want)
		}
	}
}

func assertValidationField(t *testing.T, err error, field string) {
	t.Helper()
	var v *domain.ValidationError
	if !errors.As(err, &v) || !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v, want *domain.ValidationError", err)
	}
	if _, found := v.Fields[field]; !found {
		t.Errorf("fields = %v, want %q", v.Fields, field)
	}
}
