//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// probeSource is the server-side address the probes connect from
	// (entrypoint.sh). It lies outside the VPN pool, so TunnelDeck's replies
	// reach it only through policy routing table 7194.
	probeSource = "198.18.0.1"
	// uiPort is TunnelDeck's plain-HTTP UI port; never reachable from the
	// tunnel.
	uiPort = 8194
	// listenerPort is a dummy TCP service on the "host" that a host-access
	// rule opens.
	listenerPort = 9000
	// remoteAccessPort is the HTTPS listener of SPEC §8.1.
	remoteAccessPort = 8443

	connectTimeout = 60 * time.Second
	// noRetryWindow is how long a rejected login must stay unretried.
	noRetryWindow = 10 * time.Second
)

// TestEndToEnd runs every server variant against TunnelDeck on both
// iptables backends.
func TestEndToEnd(t *testing.T) {
	s := startStack(t)
	for _, v := range variants {
		if v.password {
			v.writeCredentials(t, s)
		}
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			td := attachTunnelDeck(t, s, b)
			checkSelfChecks(t, td)
			for _, v := range variants {
				t.Run(v.name, func(t *testing.T) {
					sc := &scenario{stack: s, td: td, variant: v, pki: v.readPKI(t, s)}
					sc.run(t)
				})
			}
		})
	}
}

func checkSelfChecks(t *testing.T, td *tunnelDeck) {
	t.Helper()
	for _, check := range td.selfChecks(t) {
		if !check.OK {
			t.Errorf("self-check %s failed: %s", check.ID, check.Detail)
		}
		if check.ID == "iptables" && !strings.HasPrefix(check.Detail, td.backend.selfCheckPrefix) {
			t.Errorf("iptables self-check = %q, want it to start with %q", check.Detail, td.backend.selfCheckPrefix)
		}
	}
}

// scenario is one variant on one backend.
type scenario struct {
	stack   stack
	td      *tunnelDeck
	variant variant
	pki     pki
	// before is the routing state of TunnelDeck's namespace before any
	// tunnel of this scenario existed.
	before routing
}

func (sc *scenario) run(t *testing.T) {
	sc.before = readRouting(t, sc.td)
	if sc.variant.password {
		sc.checkRejectedPasswordIsNotRetried(t)
	}
	id := sc.td.createProfile(t, sc.variant.profile(sc.pki, vpnPassword))
	t.Cleanup(func() { sc.cleanUp(t, id) })

	vpnIP := sc.connect(t, id)
	sc.checkTraffic(t)
	sc.checkRouting(t, vpnIP)
	sc.checkHostProtection(t, vpnIP)
	sc.checkRemoteAccess(t, vpnIP)

	sc.td.disconnect(t)
	sc.checkRoutingRestored(t)

	sc.connect(t, id)
	sc.td.restart(t)
	vpnIP = sc.waitConnected(t)
	sc.checkRouting(t, vpnIP)
	sc.checkFirewallInstalled(t)
}

// cleanUp leaves TunnelDeck disconnected and without profile, rules or
// remote access for the next scenario.
func (sc *scenario) cleanUp(t *testing.T, profileID string) {
	td := sc.td
	_ = td.api.call(http.MethodPost, "/api/connection/disconnect", nil, nil)
	_ = td.setHostAccess(nil)
	_ = td.api.call(http.MethodPut, "/api/remote-access", remoteAccess{Port: remoteAccessPort, CertificateSource: "selfSigned"}, nil)
	_ = td.api.call(http.MethodDelete, "/api/profiles/"+profileID, nil, nil)
	if !t.Failed() {
		td.waitForState(t, "disconnected", 30*time.Second)
	}
}

func (sc *scenario) connect(t *testing.T, profileID string) netip.Addr {
	t.Helper()
	sc.td.connect(t, profileID)
	return sc.waitConnected(t)
}

// waitConnected waits for the tunnel and checks the VPN address is from
// the server's pool.
func (sc *scenario) waitConnected(t *testing.T) netip.Addr {
	t.Helper()
	status := sc.td.waitForState(t, "connected", connectTimeout)
	vpnIP, err := netip.ParseAddr(status.VPNIP)
	if err != nil || !sc.variant.pool.Contains(vpnIP) || vpnIP == sc.variant.gateway {
		t.Fatalf("VPN IP %q is not a client address of %s", status.VPNIP, sc.variant.pool)
	}
	return vpnIP
}

// checkRejectedPasswordIsNotRetried connects with a wrong password: the
// state must become error/auth_failed and the server must see exactly one
// attempt, also after noRetryWindow (SPEC §4.2).
func (sc *scenario) checkRejectedPasswordIsNotRetried(t *testing.T) {
	t.Helper()
	sc.stack.exec(t, sc.variant.service, "sh", "-c", ": >/run/e2e/auth-attempts.log")
	id := sc.td.createProfile(t, sc.variant.profile(sc.pki, vpnWrongPassword))
	sc.td.connect(t, id)
	status := sc.td.waitForState(t, "error", connectTimeout)
	if status.LastError == nil || status.LastError.Code != "auth_failed" {
		t.Fatalf("last error = %+v, want code auth_failed", status.LastError)
	}
	if got := sc.authAttempts(t); got != 1 {
		t.Errorf("server saw %d login attempts right after the rejection, want 1", got)
	}
	time.Sleep(noRetryWindow)
	if status := sc.td.status(t); status.State != "error" {
		t.Errorf("state %s after %s, want error (no retry)", status.State, noRetryWindow)
	}
	if got := sc.authAttempts(t); got != 1 {
		t.Errorf("server saw %d login attempts within %s, want 1 (no retry)", got, noRetryWindow)
	}
	// The active profile in state error is disconnected by the delete.
	sc.td.deleteProfile(t, id)
	sc.td.waitForState(t, "disconnected", 30*time.Second)
}

func (sc *scenario) authAttempts(t *testing.T) int {
	t.Helper()
	return len(lines(sc.stack.exec(t, sc.variant.service, "cat", "/run/e2e/auth-attempts.log")))
}

// checkTraffic pings the server's tunnel address from the host side and
// expects the byte counters to grow by at least the ping payload.
func (sc *scenario) checkTraffic(t *testing.T) {
	t.Helper()
	const count, size = 5, 1000
	before := sc.td.status(t)
	sc.td.exec(t, "ping", "-c", strconv.Itoa(count), "-s", strconv.Itoa(size), "-W", "2", sc.variant.gateway.String())
	minimum := uint64(count * size)
	sc.td.waitFor(t, "byte counters to grow", 20*time.Second, func(s connectionStatus) bool {
		return s.BytesIn >= before.BytesIn+minimum && s.BytesOut >= before.BytesOut+minimum
	})
}

// routing is the IPv4 routing state of TunnelDeck's namespace, one
// whitespace-normalised line per entry.
type routing struct {
	main  []string
	rules []string
}

func readRouting(t *testing.T, td *tunnelDeck) routing {
	t.Helper()
	return routing{
		main:  lines(td.exec(t, "ip", "-4", "route", "show", "table", "main")),
		rules: lines(td.exec(t, "ip", "-4", "rule", "show")),
	}
}

// checkRouting: the main table differs from before only by the kernel's
// connected route of the tunnel subnet (SPEC §6); rule 7194 sends traffic
// from the VPN IP to table 7194, whose default route is the tunnel.
func (sc *scenario) checkRouting(t *testing.T, vpnIP netip.Addr) {
	t.Helper()
	now := readRouting(t, sc.td)
	kernelRoute := fmt.Sprintf("%s dev tdvpn0 proto kernel scope link src %s", sc.variant.pool, vpnIP)
	added, removed := difference(now.main, sc.before.main), difference(sc.before.main, now.main)
	if len(removed) > 0 || !slices.Equal(added, []string{kernelRoute}) {
		t.Errorf("main table changed: added %q, removed %q; want only %q added", added, removed, kernelRoute)
	}
	rule := fmt.Sprintf("7194: from %s lookup 7194", vpnIP)
	if !slices.ContainsFunc(now.rules, func(line string) bool { return strings.HasPrefix(line, rule) }) {
		t.Errorf("ip rule has no %q: %q", rule, now.rules)
	}
	table := lines(sc.td.exec(t, "ip", "-4", "route", "show", "table", "7194"))
	if len(table) != 1 || !strings.HasPrefix(table[0], "default dev tdvpn0") {
		t.Errorf("table 7194 = %q, want only the default route via tdvpn0", table)
	}
}

// checkRoutingRestored: after disconnect the main table and the rules are
// exactly as before the tunnel.
func (sc *scenario) checkRoutingRestored(t *testing.T) {
	t.Helper()
	now := readRouting(t, sc.td)
	if !slices.Equal(now.main, sc.before.main) {
		t.Errorf("main table after disconnect = %q, want %q", now.main, sc.before.main)
	}
	if !slices.Equal(now.rules, sc.before.rules) {
		t.Errorf("ip rules after disconnect = %q, want %q", now.rules, sc.before.rules)
	}
}

// checkFirewallInstalled: INPUT jumps to TUNNELDECK-INPUT first, and that
// chain ends with DROP, in the chosen backend's tables; the other backend
// holds none of TunnelDeck's rules.
func (sc *scenario) checkFirewallInstalled(t *testing.T) {
	t.Helper()
	iptables := sc.td.backend.iptables
	input := appendRules(sc.td.exec(t, iptables, "-w", "-S", "INPUT"))
	if len(input) == 0 || input[0] != "-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT" {
		t.Errorf("%s INPUT = %q, want the TUNNELDECK-INPUT jump first", iptables, input)
	}
	chain := appendRules(sc.td.exec(t, iptables, "-w", "-S", "TUNNELDECK-INPUT"))
	if len(chain) == 0 || chain[len(chain)-1] != "-A TUNNELDECK-INPUT -j DROP" {
		t.Errorf("%s TUNNELDECK-INPUT = %q, want DROP last", iptables, chain)
	}
	if unused := sc.td.backend.unusedIptables; unused != "" {
		if listing := sc.td.exec(t, unused, "-w", "-S"); strings.Contains(listing, "TUNNELDECK-") {
			t.Errorf("%s holds TunnelDeck's rules:\n%s", unused, listing)
		}
	}
}

// checkHostProtection: from the tunnel side neither the UI port nor a
// listening host service answers until a host-access rule opens the
// service; a rule for the UI port is refused.
func (sc *scenario) checkHostProtection(t *testing.T, vpnIP netip.Addr) {
	t.Helper()
	sc.checkFirewallInstalled(t)
	sc.stack.compose(t, commandTimeout, "exec", "-d", "-T", sc.td.backend.service,
		"nc", "-lk", "-p", strconv.Itoa(listenerPort), "-e", "/bin/true")
	sc.expectReachable(t, vpnIP, uiPort, false)
	sc.expectReachable(t, vpnIP, listenerPort, false)

	uiRule := []hostAccessRule{{Protocol: "tcp", Port: uiPort, Enabled: true}}
	if err := sc.td.setHostAccess(uiRule); !isValidationError(err) {
		t.Errorf("host-access rule for the UI port: error %v, want validation_failed", err)
	}
	open := []hostAccessRule{{Protocol: "tcp", Port: listenerPort, Enabled: true, Comment: "e2e"}}
	sc.td.must(t, sc.td.setHostAccess(open), "open the listener port")
	sc.expectReachable(t, vpnIP, listenerPort, true)
	sc.expectReachable(t, vpnIP, uiPort, false)

	sc.td.must(t, sc.td.setHostAccess(nil), "remove the host-access rules")
	sc.expectReachable(t, vpnIP, listenerPort, false)
}

// expectReachable probes a TCP port of the VPN IP from the server side of
// the tunnel.
func (sc *scenario) expectReachable(t *testing.T, vpnIP netip.Addr, port int, want bool) {
	t.Helper()
	_, err := sc.stack.tryExec(sc.variant.service,
		"nc", "-z", "-w", "3", "-s", probeSource, vpnIP.String(), strconv.Itoa(port))
	if got := err == nil; got != want {
		t.Errorf("TCP %s:%d reachable through the tunnel = %v, want %v", vpnIP, port, got, want)
	}
}

// checkRemoteAccess enables the HTTPS listener: it answers through the
// tunnel with HSTS while the plain UI port stays closed; disabling closes
// it again.
func (sc *scenario) checkRemoteAccess(t *testing.T, vpnIP netip.Addr) {
	t.Helper()
	sc.td.setRemoteAccess(t, true, remoteAccessPort)
	url := fmt.Sprintf("https://%s:%d/api/session", vpnIP, remoteAccessPort)
	headers := sc.stack.exec(t, sc.variant.service, "curl", "--insecure", "--silent", "--show-error",
		"--max-time", "5", "--interface", probeSource, "--output", "/dev/null", "--dump-header", "-", url)
	if status := firstLine(headers); !strings.Contains(status, " 200") {
		t.Errorf("GET %s: status line %q, want 200", url, status)
	}
	if !strings.Contains(strings.ToLower(headers), "strict-transport-security: max-age=31536000") {
		t.Errorf("GET %s: no HSTS header in\n%s", url, headers)
	}
	sc.expectReachable(t, vpnIP, uiPort, false)

	sc.td.setRemoteAccess(t, false, remoteAccessPort)
	sc.expectReachable(t, vpnIP, remoteAccessPort, false)
}

// lines splits command output into non-empty lines with single spaces.
func lines(out string) []string {
	var result []string
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			result = append(result, strings.Join(fields, " "))
		}
	}
	return result
}

// appendRules returns the "-A ..." lines of iptables -S output.
func appendRules(out string) []string {
	return slices.DeleteFunc(lines(out), func(line string) bool { return !strings.HasPrefix(line, "-A ") })
}

// difference returns the lines of a that are not in b.
func difference(a, b []string) []string {
	return slices.DeleteFunc(slices.Clone(a), func(line string) bool { return slices.Contains(b, line) })
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	return strings.TrimSpace(line)
}
