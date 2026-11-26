//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Addresses of the firewall topology (compose.yml, README.md).
var (
	lanSubnet       = netip.MustParsePrefix("10.95.0.0/24")
	lanWebAddress   = netip.MustParseAddr("10.95.0.10")
	lanIPsecAddress = netip.MustParseAddr("10.95.0.20")
	// foreignSource is a network neither the probe nor the IPsec peer is in.
	foreignSource = netip.MustParsePrefix("203.0.113.0/24")
)

const (
	lanWebService    = "lan-web"
	lanIPsecService  = "lan-ipsec"
	peerIPsecService = "peer-ipsec"
	// publicHTTPPort on the tunnel address is forwarded to lanWebPort.
	publicHTTPPort = 8080
	lanWebPort     = 80
	// openVPNPort is the port of the test servers, blocked to drop the
	// tunnel.
	openVPNPort = "1194"
	// reconnectTimeout covers the reconnect backoff after a dropped tunnel.
	reconnectTimeout = 2 * time.Minute
)

// lanHost is a TunnelDeck with a second interface on the LAN network.
type lanHost struct {
	backend    backend
	lanAddress netip.Addr
	// marksReplies is false on the host whose iptables lacks CONNMARK
	// (compose.yml): replies of port forwards are then routed by the
	// target's address.
	marksReplies bool
}

var lanHosts = []lanHost{
	{
		backend: backend{
			name: "lan-nft", service: "tunneldeck-lan-nft", iptables: "iptables-nft",
			selfCheckPrefix: "using iptables-nft: only the nf_tables backend works",
		},
		lanAddress: netip.MustParseAddr("10.95.0.2"),
	},
	{
		backend: backend{
			name: "lan-legacy", service: "tunneldeck-lan-legacy", iptables: "iptables-legacy",
			selfCheckPrefix: "using iptables-legacy: only the legacy backend works",
		},
		lanAddress:   netip.MustParseAddr("10.95.0.3"),
		marksReplies: true,
	},
}

// lanScenario drives the firewall cases of one LAN host against server-a.
type lanScenario struct {
	*scenario
	host  lanHost
	vpnIP netip.Addr
}

// runLANScenario runs every firewall case; each case is a subtest so its
// result and duration show on its own. The cases share the tunnel and run
// in order.
func runLANScenario(t *testing.T, s stack, host lanHost) {
	td := attachTunnelDeck(t, s, host.backend)
	v := variants[0] // A: password, UDP, server-a with the network behind it
	sc := &lanScenario{scenario: &scenario{stack: s, td: td, variant: v, pki: v.readPKI(t, s)}, host: host}
	sc.useHostAsGateway(t)

	t.Run("self-checks", sc.checkLANSelfChecks)
	t.Run("migration-v1", sc.checkMigration)

	id := td.createProfile(t, sc.profile())
	t.Cleanup(func() { sc.cleanUp(t, id) })
	sc.vpnIP = sc.connect(t, id)

	t.Run("port-forward-masquerade", sc.checkPortForwardMasquerade)
	t.Run("port-forward-keep-source", sc.checkPortForwardKeepSource)
	t.Run("port-forward-source-restriction", sc.checkPortForwardSourceRestriction)
	t.Run("port-forward-any-port", sc.checkAnyPortForward)
	t.Run("outbound-policy-routing", sc.checkOutboundRouting)
	t.Run("ipsec-nat-t", sc.checkIPsec)
	t.Run("esp-forwarding", sc.checkESPForwarding)
	t.Run("kill-switch", sc.checkKillSwitch)
	t.Run("outbound-policy-routing-wireguard", sc.checkOutboundRoutingOverWireGuard)
}

// profile is variant A without remote networks, so only the outbound
// rules' policy routing (priority 7190) sends LAN traffic into the tunnel.
func (sc *lanScenario) profile() profileRequest {
	req := sc.variant.profile(sc.pki, vpnPassword)
	req.Name = "e2e firewall"
	delete(req.Settings, "remoteNetworks")
	return req
}

// useHostAsGateway points the default route of the LAN devices to the
// TunnelDeck under test, as a LAN whose router (or DHCP) names the host as
// gateway.
func (sc *lanScenario) useHostAsGateway(t *testing.T) {
	t.Helper()
	for _, service := range []string{lanWebService, lanIPsecService} {
		sc.stack.exec(t, service, "ip", "route", "replace", "default", "via", sc.host.lanAddress.String())
	}
}

// checkLANSelfChecks: every self-check passes, ip_forward included, but
// reply-routing on the host without CONNMARK, and the LAN network is among
// the detected LAN subnets.
func (sc *lanScenario) checkLANSelfChecks(t *testing.T) {
	var warnings []string
	if !sc.host.marksReplies {
		warnings = append(warnings, "reply-routing")
	}
	checkSelfChecks(t, sc.td, warnings...)
	for _, check := range sc.td.selfChecks(t) {
		if check.ID == "lan-subnets" && !strings.Contains(check.Detail, lanSubnet.String()) {
			t.Errorf("lan-subnets self-check = %q, want it to name %s", check.Detail, lanSubnet)
		}
	}
	state := sc.firewall(t)
	if !slices.Contains(state.LANSubnets, lanSubnet.String()) || !state.IPForward {
		t.Errorf("GET /api/firewall: lanSubnets %q, ipForward %v; want %s and true", state.LANSubnets, state.IPForward, lanSubnet)
	}
}

// checkMigration: the container started with the version 1 settings.json
// of testdata/. Its two host-access rules are inbound rules to the host
// with generated names, shown with the host's LAN address; the file itself
// is rewritten as version 3 only by the first change, here saving the
// migrated rules unchanged, which stores that address.
func (sc *lanScenario) checkMigration(t *testing.T) {
	if version, _ := sc.settingsDocument(t); version != 1 {
		t.Errorf("settings.json schemaVersion before any change = %d, want 1 (written only on the next change)", version)
	}
	state := sc.firewall(t)
	want := []firewallRule{
		{
			ID: "r-dsm", Name: "Host port 5001/tcp", Direction: "inbound", Action: "accept", Protocol: "tcp",
			Destination: state.HostAddress, DestinationPort: portRange{From: 5001}, Enabled: true,
			Comment: "DSM over HTTPS",
		},
		{
			ID: "r-snmp", Name: "Host port 161/udp", Direction: "inbound", Action: "accept", Protocol: "udp",
			Source: "10.8.0.0/24", Destination: state.HostAddress, DestinationPort: portRange{From: 161},
		},
	}
	if state.HostAddress == "" || !slices.Equal(state.Rules, want) {
		t.Fatalf("migrated rules = %+v, want %+v", state.Rules, want)
	}
	for _, setting := range []string{"dropInvalid", "mssClamp", "synFloodProtection", "pingLimit"} {
		if !state.Settings[setting] {
			t.Errorf("migrated firewall setting %s = false, want true", setting)
		}
	}

	sc.td.must(t, sc.td.setFirewallRules(state.Rules), "save the migrated rules")
	version, keys := sc.settingsDocument(t)
	if version < 3 || slices.Contains(keys, "hostAccessRules") || !slices.Contains(keys, "firewall") {
		t.Errorf("settings.json after the first change: schemaVersion %d, keys %q; want 3 or later with firewall and without hostAccessRules", version, keys)
	}
	if again := sc.firewall(t); !slices.Equal(again.Rules, want) {
		t.Errorf("rules after saving them unchanged = %+v, want %+v", again.Rules, want)
	}
}

// settingsDocument returns schemaVersion and the top-level keys of
// /data/settings.json.
func (sc *lanScenario) settingsDocument(t *testing.T) (int, []string) {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(sc.td.exec(t, "cat", "/data/settings.json")), &doc); err != nil {
		t.Fatalf("decode settings.json: %v", err)
	}
	var version int
	_ = json.Unmarshal(doc["schemaVersion"], &version)
	keys := make([]string, 0, len(doc))
	for key := range doc {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return version, keys
}

func (sc *lanScenario) firewall(t *testing.T) firewallState {
	t.Helper()
	var state firewallState
	sc.td.must(t, sc.td.api.get("/api/firewall", &state), "read the firewall")
	return state
}

// webForward forwards publicHTTPPort on the tunnel address to lan-web.
func webForward(keepSource bool, source string) firewallRule {
	return firewallRule{
		Name: "Web server", Direction: "inbound", Action: "accept", Protocol: "tcp", Source: source,
		Destination:     lanWebAddress.String(),
		DestinationPort: portRange{From: lanWebPort}, PublicPort: portRange{From: publicHTTPPort},
		KeepSourceAddress: keepSource, Enabled: true,
	}
}

// webOutbound routes lan-web's traffic to the network behind server-a
// into the tunnel.
func webOutbound() firewallRule {
	return firewallRule{
		Name: "lan-web to the remote network", Direction: "outbound", Action: "accept", Protocol: "any",
		Source: lanWebAddress.String(), Destination: remoteNetwork.String(),
		Enabled: true,
	}
}

// checkPortForwardMasquerade: the probe reaches lan-web through the public
// port, and lan-web sees TunnelDeck's LAN address as the client.
func (sc *lanScenario) checkPortForwardMasquerade(t *testing.T) {
	sc.td.must(t, sc.td.setFirewallRules([]firewallRule{webForward(false, "")}), "forward the web port")
	sc.expectWebClient(t, sc.host.lanAddress.String())
	sc.expectReplyRule(t)
}

// checkPortForwardKeepSource: with keepSourceAddress lan-web sees the
// probe's own address and answers it through TunnelDeck, its gateway.
func (sc *lanScenario) checkPortForwardKeepSource(t *testing.T) {
	sc.td.must(t, sc.td.setFirewallRules([]firewallRule{webForward(true, "")}), "forward the web port keeping the source")
	sc.expectWebClient(t, probeSource)
	sc.expectReplyRule(t)
}

// expectReplyRule: the replies of the web forward reach the probe only
// through policy rule 7191, by connection mark or, without CONNMARK, by
// lan-web's address; no rule uses a selector Linux 4.4 lacks, which
// linux44-ip.sh would have refused anyway.
func (sc *lanScenario) expectReplyRule(t *testing.T) {
	t.Helper()
	want := "7191: from all fwmark 0x7194/0xffff lookup 7194"
	if !sc.host.marksReplies {
		want = fmt.Sprintf("7191: from %s lookup 7194", lanWebAddress)
	}
	rules := readRouting(t, sc.td).rules
	if !slices.Contains(rules, want) {
		t.Errorf("ip rule has no %q: %q", want, rules)
	}
	for _, rule := range rules {
		if strings.Contains(rule, "ipproto") || strings.Contains(rule, "sport") || strings.Contains(rule, "dport") {
			t.Errorf("policy rule %q uses a selector of Linux 4.17", rule)
		}
	}
}

// checkPortForwardSourceRestriction: a forward limited to a network the
// probe is not in does not answer the probe.
func (sc *lanScenario) checkPortForwardSourceRestriction(t *testing.T) {
	sc.td.must(t, sc.td.setFirewallRules([]firewallRule{webForward(false, foreignSource.String())}),
		"forward the web port for another source")
	if body, err := sc.fetchWebClient(); err == nil {
		t.Errorf("port forward restricted to %s answered the probe from %s with %q, want no answer", foreignSource, probeSource, body)
	}
}

// checkAnyPortForward: a TCP forward without a port sends public port 80
// to lan-web's port 80, while the web UI port stays with TunnelDeck and
// closed to the tunnel, although lan-web listens on it too.
func (sc *lanScenario) checkAnyPortForward(t *testing.T) {
	listener := "0.0.0.0:" + strconv.Itoa(uiPort)
	sc.stack.exec(t, lanWebService, "httpd", "-p", listener, "-h", "/www")
	t.Cleanup(func() { _, _ = sc.stack.tryExec(lanWebService, "pkill", "-f", "httpd -p "+listener) })
	forward := firewallRule{
		Name: "Everything to lan-web", Direction: "inbound", Action: "accept", Protocol: "tcp",
		Destination: lanWebAddress.String(), Enabled: true,
	}
	sc.td.must(t, sc.td.setFirewallRules([]firewallRule{forward}), "forward every TCP port to lan-web")
	sc.expectWebClientOn(t, lanWebPort, sc.host.lanAddress.String())
	sc.expectReachable(t, sc.vpnIP, uiPort, false)
}

// expectWebClient fetches lan-web's client address through the public
// HTTP port of the tunnel address.
func (sc *lanScenario) expectWebClient(t *testing.T, want string) {
	t.Helper()
	sc.expectWebClientOn(t, publicHTTPPort, want)
}

// expectWebClientOn fetches lan-web's client address through port of the
// tunnel address.
func (sc *lanScenario) expectWebClientOn(t *testing.T, port int, want string) {
	t.Helper()
	body, err := sc.fetchWebClientOn(port)
	if err != nil {
		t.Fatalf("GET through %s:%d from the probe failed, want lan-web's answer: %v\n%s", sc.vpnIP, port, err, body)
	}
	if got := strings.TrimSpace(body); got != want {
		t.Errorf("lan-web saw client %q, want %q", got, want)
	}
}

// fetchWebClient asks lan-web, through the public HTTP port of the tunnel
// address, which client address it sees.
func (sc *lanScenario) fetchWebClient() (string, error) { return sc.fetchWebClientOn(publicHTTPPort) }

// fetchWebClientOn asks lan-web, through port of the tunnel address, which
// client address it sees. The probe runs on the VPN side.
func (sc *lanScenario) fetchWebClientOn(port int) (string, error) {
	url := fmt.Sprintf("http://%s:%d/cgi-bin/source", sc.vpnIP, port)
	return sc.stack.tryExec(sc.variant.service, "curl", "--silent", "--show-error", "--fail",
		"--max-time", "5", "--interface", probeSource, url)
}

// checkOutboundRouting: an outbound rule for lan-web adds the policy rule
// 7190 and lets lan-web reach the network behind the server; lan-ipsec,
// without a rule, does not get there.
func (sc *lanScenario) checkOutboundRouting(t *testing.T) {
	sc.td.must(t, sc.td.setFirewallRules([]firewallRule{webOutbound()}), "route lan-web into the tunnel")
	rule := fmt.Sprintf("7190: from %s to %s lookup 7194", lanWebAddress, remoteNetwork)
	if rules := readRouting(t, sc.td).rules; !slices.Contains(rules, rule) {
		t.Errorf("ip rule has no %q: %q", rule, rules)
	}
	if err := sc.ping(lanWebService, sc.variant.remoteHost); err != nil {
		t.Errorf("lan-web with an outbound rule cannot reach %s behind the server: %v", sc.variant.remoteHost, err)
	}
	if err := sc.ping(lanIPsecService, sc.variant.remoteHost); err == nil {
		t.Errorf("lan-ipsec without an outbound rule reached %s behind the server", sc.variant.remoteHost)
	}
}

// ping sends three pings from a container; options go before the target.
func (sc *lanScenario) ping(service string, target netip.Addr, options ...string) error {
	args := slices.Concat([]string{"ping", "-c", "3", "-W", "2"}, options, []string{target.String()})
	_, err := sc.stack.tryExec(service, args...)
	return err
}

// checkKillSwitch: while lan-web's outbound rule exists, its traffic to the
// remote network never leaves by the host's own route to that network,
// neither while the tunnel is down after a drop nor after a disconnect;
// the port forward stops answering too. Without the rule the same traffic
// does take that route and is counted, which proves both the route and the
// leak counter work.
func (sc *lanScenario) checkKillSwitch(t *testing.T) {
	sc.td.must(t, sc.td.setFirewallRules([]firewallRule{webOutbound(), webForward(false, "")}), "route lan-web and forward its port")
	sc.addLeakPath(t)
	if err := sc.ping(lanWebService, sc.variant.remoteHost); err != nil {
		t.Fatalf("lan-web cannot reach %s while connected: %v", sc.variant.remoteHost, err)
	}

	sc.dropTunnel(t)
	sc.expectKillSwitch(t, "while the tunnel is down")
	if body, err := sc.fetchWebClient(); err == nil {
		t.Errorf("port forward answered while the tunnel is down: %q", body)
	}

	sc.restoreTunnel(t)
	if err := sc.ping(lanWebService, sc.variant.remoteHost); err != nil {
		t.Errorf("lan-web cannot reach %s after the tunnel came back: %v", sc.variant.remoteHost, err)
	}
	sc.expectWebClient(t, sc.host.lanAddress.String())

	sc.td.disconnect(t)
	sc.expectKillSwitch(t, "after disconnect")

	sc.td.must(t, sc.td.setFirewallRules(nil), "remove the rules")
	before := sc.leakedPackets(t)
	if err := sc.ping(lanWebService, sc.variant.remoteHost); err != nil {
		t.Errorf("control: without an outbound rule lan-web cannot reach %s by the host's route either: %v", sc.variant.remoteHost, err)
	}
	if leaked := sc.leakedPackets(t) - before; leaked < 3 {
		t.Errorf("control: the leak counter saw %d of lan-web's 3 pings leave outside the tunnel, want 3", leaked)
	}
}

// expectKillSwitch: lan-web's pings to the remote network get no answer
// and not one of them leaves the host.
func (sc *lanScenario) expectKillSwitch(t *testing.T, when string) {
	t.Helper()
	before := sc.leakedPackets(t)
	if err := sc.ping(lanWebService, sc.variant.remoteHost); err == nil {
		t.Errorf("%s: lan-web reached %s by the host's own route (kill switch leak)", when, sc.variant.remoteHost)
	}
	if leaked := sc.leakedPackets(t) - before; leaked != 0 {
		t.Errorf("%s: %d of lan-web's packets to %s left the host outside the tunnel, want 0", when, leaked, remoteNetwork)
	}
}

// leakRule counts, in mangle POSTROUTING, a chain TunnelDeck never touches,
// every packet from lan-web to the remote network that leaves the host by
// another interface than the tunnel.
func leakRule() []string {
	return []string{"POSTROUTING", "-s", lanWebAddress.String() + "/32", "-d", remoteNetwork.String(), "!", "-o", "tdvpn0"}
}

// addLeakPath gives the host its own route to the remote network, via
// server-a outside the tunnel, and server-a a route back to the LAN: the
// path traffic would leak by without the kill switch. The leak counter
// watches that path.
func (sc *lanScenario) addLeakPath(t *testing.T) {
	t.Helper()
	server := sc.resolve(t, sc.host.backend.service, sc.variant.service)
	host := sc.resolve(t, sc.variant.service, sc.host.backend.service)
	iptables := sc.host.backend.iptables
	t.Cleanup(func() {
		_, _ = sc.stack.tryExec(sc.host.backend.service, append([]string{iptables, "-w", "-t", "mangle", "-D"}, leakRule()...)...)
		_, _ = sc.stack.tryExec(sc.host.backend.service, "ip", "route", "del", remoteNetwork.String())
		_, _ = sc.stack.tryExec(sc.variant.service, "ip", "route", "del", lanSubnet.String())
	})
	sc.td.exec(t, append([]string{iptables, "-w", "-t", "mangle", "-A"}, leakRule()...)...)
	sc.td.exec(t, "ip", "route", "replace", remoteNetwork.String(), "via", server)
	sc.stack.exec(t, sc.variant.service, "ip", "route", "replace", lanSubnet.String(), "via", host)
}

// leakedPackets reads the packet counter of the leak rule.
func (sc *lanScenario) leakedPackets(t *testing.T) int {
	t.Helper()
	listing := sc.td.exec(t, sc.host.backend.iptables, "-w", "-t", "mangle", "-v", "-S", "POSTROUTING")
	match := strings.Join(leakRule()[1:], " ")
	for _, line := range lines(listing) {
		if !strings.Contains(line, match) {
			continue
		}
		fields := strings.Fields(line)
		if i := slices.Index(fields, "-c"); i >= 0 && i+1 < len(fields) {
			if packets, err := strconv.Atoi(fields[i+1]); err == nil {
				return packets
			}
		}
	}
	t.Fatalf("no leak counter %q in mangle POSTROUTING:\n%s", match, listing)
	return 0
}

// resolve returns the address of name as seen from service.
func (sc *lanScenario) resolve(t *testing.T, service, name string) string {
	t.Helper()
	fields := strings.Fields(sc.stack.exec(t, service, "getent", "hosts", name))
	if len(fields) == 0 {
		t.Fatalf("%s cannot resolve %s", service, name)
	}
	return fields[0]
}

// dropTunnel blocks OpenVPN's traffic to the server and kills the OpenVPN
// process, like a tunnel that breaks down: the connection leaves the
// connected state and tdvpn0 disappears, while TunnelDeck keeps trying to
// reconnect.
func (sc *lanScenario) dropTunnel(t *testing.T) {
	t.Helper()
	block := []string{"OUTPUT", "-p", "udp", "--dport", openVPNPort, "-j", "DROP"}
	iptables := sc.host.backend.iptables
	sc.td.exec(t, append([]string{iptables, "-w", "-I"}, block...)...)
	t.Cleanup(func() {
		_, _ = sc.stack.tryExec(sc.host.backend.service, append([]string{iptables, "-w", "-D"}, block...)...)
	})
	sc.td.exec(t, "pkill", "-KILL", "-x", "openvpn")
	sc.td.waitFor(t, "the tunnel to drop", 30*time.Second, func(s connectionStatus) bool { return s.State != "connected" })
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := sc.stack.tryExec(sc.host.backend.service, "ip", "link", "show", "tdvpn0"); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tdvpn0 still exists 30 s after OpenVPN was killed")
		}
		time.Sleep(pollInterval)
	}
}

// restoreTunnel lifts the block and waits for the reconnect.
func (sc *lanScenario) restoreTunnel(t *testing.T) {
	t.Helper()
	sc.td.exec(t, sc.host.backend.iptables, "-w", "-D", "OUTPUT", "-p", "udp", "--dport", openVPNPort, "-j", "DROP")
	status := sc.td.waitForState(t, "connected", reconnectTimeout)
	vpnIP, err := netip.ParseAddr(status.VPNIP)
	if err != nil || !sc.variant.pool.Contains(vpnIP) {
		t.Fatalf("VPN IP after the reconnect %q is not a client address of %s", status.VPNIP, sc.variant.pool)
	}
	sc.vpnIP = vpnIP
}
