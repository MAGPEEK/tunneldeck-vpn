//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// IPsec test gateway (variant E, ipsecgw/). The throwaway credentials are
// those of ipsecgw/swanctl.conf and ipsecgw/entrypoint.sh.
const (
	ipsecGatewayService = "server-ipsec"
	// ipsecGatewayID is the identity in the gateway's certificate.
	ipsecGatewayID      = "ipsec-gw.e2e"
	ipsecGatewayPSK     = "e2e IPsec pre-shared key of 32+ chars"
	ipsecWrongPSK       = "not the pre-shared key of the gateway"
	ipsecUserPassword   = "e2e ipsec pass word;#1"
	ipsecPKCS12Password = "e2e PKCS#12 password"
	// ipsecGatewayLog is charon's log file on the gateway; ipsecAuthRequest
	// starts the line charon writes for every IKE_AUTH request it parses,
	// one per authentication attempt with a pre-shared key.
	ipsecGatewayLog  = "/run/e2e/charon.log"
	ipsecAuthRequest = "parsed IKE_AUTH request"
	// noInternetNote is part of the log line that replaces the public IP
	// detection for a tunnel without the internet (SPEC §6.1).
	noInternetNote = "not the internet; the public IP is not detected"
	// ipsecDataCipher is what the gateway's first ESP proposal negotiates.
	ipsecDataCipher = "AES_GCM_16-256"
)

// The net-to-net connection carries the LAN of the firewall topology to
// netToNetRemote behind the gateway, where netToNetWeb answers with the
// client address it sees.
var (
	netToNetRemote = netip.MustParsePrefix("10.98.0.0/24")
	netToNetWeb    = netip.MustParseAddr("10.98.0.1")
)

// ipsecCredentials are what the gateway's throwaway PKI hands to clients:
// the CA certificate and the client's PKCS#12 bundle in base64.
type ipsecCredentials struct {
	ca, pkcs12 string
}

func readIPsecCredentials(t *testing.T, s stack) ipsecCredentials {
	t.Helper()
	return ipsecCredentials{
		ca:     s.exec(t, ipsecGatewayService, "cat", "/run/e2e/client/ca.crt"),
		pkcs12: strings.TrimSpace(s.exec(t, ipsecGatewayService, "openssl", "base64", "-A", "-in", "/run/e2e/client/client.p12")),
	}
}

// ipsecVariant is one sign-in method of the gateway in virtual IP mode.
// Every gateway connection has its own pool; .1 of the pool's network is
// the gateway's address unless the connection carries only the network
// behind the gateway.
type ipsecVariant struct {
	variant
	// ikeVersion starts the control channel: "IKEv2" or "IKEv1".
	ikeVersion string
	// noInternet is true when the negotiated traffic selectors do not
	// cover 0.0.0.0/0, so the public IP is not detected (SPEC §6.1).
	noInternet bool
	profile    func(c ipsecCredentials) profileRequest
}

func newIPsecVariant(name, pool, gateway string) variant {
	return variant{
		name: name, service: ipsecGatewayService,
		pool: netip.MustParsePrefix(pool), gateway: netip.MustParseAddr(gateway),
		remoteHost: netip.MustParseAddr("10.99.0.1"), dataCipher: ipsecDataCipher, hostAddress: true,
	}
}

// ipsecProfile is a virtual IP profile for the gateway with the given
// settings on top of the gateway address.
func ipsecProfile(name string, settings map[string]any, secrets map[string]string) profileRequest {
	all := map[string]any{"gateway": ipsecGatewayService, "mode": "virtualIp"}
	for key, value := range settings {
		all[key] = value
	}
	return profileRequest{Name: "e2e " + name, Protocol: "ipsec", Settings: all, Secrets: secrets}
}

// withInternet are the remote subnets of a full tunnel with the network
// behind the gateway as remote network.
var withInternet = []string{everything, remoteNetwork.String()}

// pskVariant leaves the gateway identity empty (any identity is
// accepted with a pre-shared key).
var pskVariant = ipsecVariant{
	variant:    newIPsecVariant("E-ipsec-psk", "10.94.5.0/24", "10.94.5.1"),
	ikeVersion: "IKEv2",
	profile: func(ipsecCredentials) profileRequest {
		return ipsecProfile("E-ipsec-psk", map[string]any{
			"authMethod": "psk", "localId": "psk.client.e2e", "remoteSubnets": withInternet,
		}, map[string]string{"psk": ipsecGatewayPSK})
	},
}

var ipsecVariants = []ipsecVariant{
	pskVariant,
	{
		// The gateway narrows 0.0.0.0/0 to its address and the network
		// behind it.
		variant:    newIPsecVariant("E-ipsec-certificate", "10.94.6.0/24", "10.94.6.1"),
		ikeVersion: "IKEv2",
		noInternet: true,
		profile: func(c ipsecCredentials) profileRequest {
			return ipsecProfile("E-ipsec-certificate", map[string]any{
				"authMethod": "certificate", "localId": "client.ipsec.e2e", "remoteId": ipsecGatewayID,
				"caCert": c.ca, "remoteSubnets": withInternet,
			}, map[string]string{"pkcs12": c.pkcs12, "pkcs12Password": ipsecPKCS12Password})
		},
	},
	{
		variant:    newIPsecVariant("E-ipsec-eap-mschapv2", "10.94.7.0/24", "10.94.7.1"),
		ikeVersion: "IKEv2",
		profile: func(c ipsecCredentials) profileRequest {
			return ipsecProfile("E-ipsec-eap-mschapv2", map[string]any{
				"authMethod": "eapMschapv2", "username": vpnUsername, "remoteId": ipsecGatewayID,
				"caCert": c.ca, "remoteSubnets": withInternet,
			}, map[string]string{"eapPassword": ipsecUserPassword})
		},
	},
	{
		// Like the FRITZ!Box user access: only the network behind the
		// gateway, no gateway identity.
		variant:    newIPsecVariant("E-ipsec-ikev1-xauth", "10.94.8.0/24", "10.99.0.1"),
		ikeVersion: "IKEv1",
		noInternet: true,
		profile: func(ipsecCredentials) profileRequest {
			return ipsecProfile("E-ipsec-ikev1-xauth", map[string]any{
				"template": "fritzboxUser", "ikeVersion": "ikev1", "authMethod": "psk", "localId": "xauth.client.e2e",
				"xauthUsername": vpnUsername, "remoteSubnets": []string{remoteNetwork.String()},
			}, map[string]string{"psk": ipsecGatewayPSK, "xauthPassword": ipsecUserPassword})
		},
	},
}

// ipsecVariantsFor returns every sign-in method for the first backend and
// the pre-shared key for the others: the iptables backend matters only for
// the routing and the firewall, which all methods share.
func ipsecVariantsFor(b backend) []ipsecVariant {
	if b.name == backends[0].name {
		return ipsecVariants
	}
	return []ipsecVariant{pskVariant}
}

// runIPsecVariants runs the IPsec variants of td's backend; the failure
// cases depend on the gateway only and run on the first backend.
func runIPsecVariants(t *testing.T, s stack, td *tunnelDeck) {
	credentials := readIPsecCredentials(t, s)
	for _, v := range ipsecVariantsFor(td.backend) {
		t.Run(v.name, newIPsecScenario(s, td, v, credentials).run)
	}
	if td.backend.name == backends[0].name {
		t.Run(pskVariant.name+"-wrong-key", newIPsecScenario(s, td, pskVariant, credentials).checkWrongPSK)
		t.Run(pskVariant.name+"-proposal-mismatch", newIPsecScenario(s, td, pskVariant, credentials).checkProposalMismatch)
	}
}

// ipsecScenario is one IPsec variant on one backend.
type ipsecScenario struct {
	*scenario
	ipsec       ipsecVariant
	credentials ipsecCredentials
	// connectedAfter is the time of the newest log line before the
	// connect: the connection log keeps the lines of earlier tunnels.
	connectedAfter time.Time
}

func newIPsecScenario(s stack, td *tunnelDeck, v ipsecVariant, c ipsecCredentials) *ipsecScenario {
	return &ipsecScenario{scenario: &scenario{stack: s, td: td, variant: v.variant}, ipsec: v, credentials: c}
}

// run connects, checks the tunnel like the other protocols, disconnects
// and checks that nothing is left and no secret leaked.
func (sc *ipsecScenario) run(t *testing.T) {
	sc.before = readRouting(t, sc.td)
	req := sc.ipsec.profile(sc.credentials)
	id := sc.td.createProfile(t, req)
	t.Cleanup(func() { sc.cleanUp(t, id) })
	sc.checkStoredSecrets(t, id, req.Secrets)

	sc.connectedAfter = sc.newestLogTime(t)
	vpnIP := sc.connect(t, id)
	sc.checkChannel(t)
	sc.checkTraffic(t)
	sc.checkRouting(t, vpnIP)
	sc.checkRemoteNetwork(t, true)
	sc.checkPublicIPDetection(t)

	sc.td.disconnect(t)
	sc.checkTornDown(t)
	sc.checkCharonStopped(t)
	sc.checkRemoteNetwork(t, false)
	sc.checkSecretsNotLogged(t, req.Secrets)
}

// checkStoredSecrets: the stored profile shows every secret only as
// present, in the single profile and in the list.
func (sc *ipsecScenario) checkStoredSecrets(t *testing.T, id string, secrets map[string]string) {
	t.Helper()
	var raw json.RawMessage
	sc.td.must(t, sc.td.api.get("/api/profiles/"+id, &raw), "read the profile")
	var list json.RawMessage
	sc.td.must(t, sc.td.api.get("/api/profiles", &list), "list the profiles")
	for key, value := range secrets {
		for path, body := range map[string]json.RawMessage{"/api/profiles/" + id: raw, "/api/profiles": list} {
			if strings.Contains(string(body), value) {
				t.Errorf("GET %s returns the secret %s", path, key)
			}
		}
	}
	var profile struct {
		Secrets map[string]struct {
			HasValue bool `json:"hasValue"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatalf("decode the profile: %v", err)
	}
	for key := range secrets {
		if !profile.Secrets[key].HasValue {
			t.Errorf("profile secret %s: hasValue false, want true (%+v)", key, profile.Secrets)
		}
	}
}

// checkChannel: the status names the negotiated ESP algorithm and the IKE
// version with its proposal, and the routing applied without a warning.
func (sc *ipsecScenario) checkChannel(t *testing.T) {
	t.Helper()
	status := sc.td.status(t)
	if status.DataCipher != ipsecDataCipher || !strings.HasPrefix(status.ControlChannel, sc.ipsec.ikeVersion+" ") {
		t.Errorf("data cipher %q, control channel %q; want %q and %s with its proposal",
			status.DataCipher, status.ControlChannel, ipsecDataCipher, sc.ipsec.ikeVersion)
	}
	if status.RoutingWarning != nil || status.MessageCode != "" {
		t.Errorf("routing warning %+v, message code %q; want neither", status.RoutingWarning, status.MessageCode)
	}
}

// checkPublicIPDetection: a tunnel without the internet logs why the
// public IP is not detected, never a failed detection, and the public IP
// stays unknown; a full tunnel never logs that note.
func (sc *ipsecScenario) checkPublicIPDetection(t *testing.T) {
	t.Helper()
	noted := false
	for _, line := range sc.logsSinceConnect(t) {
		noted = noted || strings.Contains(line.Text, noInternetNote)
		if sc.ipsec.noInternet && strings.Contains(line.Text, "detecting the public IP") {
			t.Errorf("log line %q for a tunnel without the internet", line.Text)
		}
	}
	if noted != sc.ipsec.noInternet {
		t.Errorf("log notes a tunnel without the internet = %v, want %v", noted, sc.ipsec.noInternet)
	}
	if status := sc.td.status(t); sc.ipsec.noInternet && status.PublicIP != "" {
		t.Errorf("public IP %q through a tunnel without the internet, want none", status.PublicIP)
	}
}

// checkCharonStopped: no charon process outlives the tunnel.
func (sc *ipsecScenario) checkCharonStopped(t *testing.T) {
	t.Helper()
	if out, err := sc.stack.tryExec(sc.td.backend.service, "pidof", "charon"); err == nil {
		t.Errorf("charon still runs after disconnect: pid %s", strings.TrimSpace(out))
	}
}

// checkSecretsNotLogged: neither the connection log nor the container's
// output (log level debug) holds a secret of the profile.
func (sc *ipsecScenario) checkSecretsNotLogged(t *testing.T, secrets map[string]string) {
	t.Helper()
	output := sc.stack.compose(t, commandTimeout, "logs", "--no-color", sc.td.backend.service)
	logs := sc.td.logs(t)
	for key, value := range secrets {
		if strings.Contains(output, value) {
			t.Errorf("the output of %s holds the secret %s", sc.td.backend.service, key)
		}
		if slices.ContainsFunc(logs, func(line logLine) bool { return strings.Contains(line.Text, value) }) {
			t.Errorf("a connection log line holds the secret %s", key)
		}
	}
}

// checkWrongPSK connects with a wrong pre-shared key: the state becomes
// error with auth_failed and the gateway sees exactly one authentication,
// also after noRetryWindow (SPEC §19, no retry storm).
func (sc *ipsecScenario) checkWrongPSK(t *testing.T) {
	sc.stack.exec(t, ipsecGatewayService, "sh", "-c", ": >"+ipsecGatewayLog)
	req := sc.ipsec.profile(sc.credentials)
	req.Name += " wrong key"
	req.Secrets = map[string]string{"psk": ipsecWrongPSK}
	sc.expectFailure(t, req, "auth_failed", func() {
		if got := sc.authAttempts(t); got != 1 {
			t.Errorf("gateway saw %d authentications, want 1", got)
		}
	})
}

// checkProposalMismatch offers only AES-128, which the gateway does not
// accept: the state becomes error with proposal_mismatch and stays there.
func (sc *ipsecScenario) checkProposalMismatch(t *testing.T) {
	req := sc.ipsec.profile(sc.credentials)
	req.Name += " AES-128 only"
	req.Settings["ikeProposals"] = []string{"aes128-sha256-modp2048"}
	sc.expectFailure(t, req, "proposal_mismatch", func() {})
}

// expectFailure connects req, expects state error with code, runs check
// right then and after noRetryWindow, during which the state must stay
// error, and deletes the profile.
func (sc *ipsecScenario) expectFailure(t *testing.T, req profileRequest, code string, check func()) {
	t.Helper()
	id := sc.td.createProfile(t, req)
	sc.td.connect(t, id)
	status := sc.td.waitForState(t, "error", connectTimeout)
	if status.LastError == nil || status.LastError.Code != code {
		t.Fatalf("last error = %+v, want code %s\n%s", status.LastError, code, sc.td.logTail())
	}
	check()
	time.Sleep(noRetryWindow)
	if status := sc.td.status(t); status.State != "error" {
		t.Errorf("state %s after %s, want error (no retry)", status.State, noRetryWindow)
	}
	check()
	sc.td.deleteProfile(t, id)
	sc.td.waitForState(t, "disconnected", 30*time.Second)
	sc.checkCharonStopped(t)
}

func (sc *ipsecScenario) authAttempts(t *testing.T) int {
	t.Helper()
	count := 0
	for _, line := range strings.Split(sc.stack.exec(t, ipsecGatewayService, "cat", ipsecGatewayLog), "\n") {
		if strings.Contains(line, ipsecAuthRequest) {
			count++
		}
	}
	return count
}

// checkIPsecNetToNet connects the LAN to netToNetRemote behind the
// gateway without a VPN address: an outbound rule lets lan-web in, and
// the gateway's web server sees lan-web's own address and the host's LAN
// address, nothing is masqueraded. The remote network is routed at 7099,
// ahead of the LAN exclusions; no rule names a VPN IP.
func (sc *lanScenario) checkIPsecNetToNet(t *testing.T) {
	req := profileRequest{
		Name: "e2e E-ipsec-net-to-net", Protocol: "ipsec",
		Settings: map[string]any{
			"gateway": ipsecGatewayService, "mode": "netToNet", "authMethod": "psk", "localId": "net.client.e2e",
			"localSubnets": []string{lanSubnet.String()}, "remoteSubnets": []string{netToNetRemote.String()},
		},
		Secrets: map[string]string{"psk": ipsecGatewayPSK},
	}
	id := sc.td.createProfile(t, req)
	t.Cleanup(func() {
		_ = sc.td.api.call(http.MethodPost, "/api/connection/disconnect", nil, nil)
		_ = sc.td.setFirewallRules(nil)
		_ = sc.td.api.call(http.MethodDelete, "/api/profiles/"+id, nil, nil)
	})
	outbound := firewallRule{
		Name: "lan-web to the net-to-net network", Direction: "outbound", Action: "accept", Protocol: "any",
		Source: lanWebAddress.String(), Destination: netToNetRemote.String(), Enabled: true,
	}
	sc.td.must(t, sc.td.setFirewallRules([]firewallRule{outbound}), "route lan-web into the tunnel")
	sc.td.connect(t, id)
	if status := sc.td.waitForState(t, "connected", connectTimeout); status.VPNIP != "" {
		t.Errorf("net-to-net VPN IP %q, want none", status.VPNIP)
	}
	rules := readRouting(t, sc.td).rules
	if rule := fmt.Sprintf("7099: from all to %s lookup 7194", netToNetRemote); !slices.Contains(rules, rule) {
		t.Errorf("ip rule has no %q: %q", rule, rules)
	}
	if slices.ContainsFunc(rules, func(line string) bool { return strings.HasPrefix(line, "7194:") }) {
		t.Errorf("ip rule names a VPN IP: %q", rules)
	}
	url := fmt.Sprintf("http://%s/cgi-bin/source", netToNetWeb)
	for service, want := range map[string]netip.Addr{lanWebService: lanWebAddress, sc.td.backend.service: sc.host.lanAddress} {
		out, err := sc.stack.tryExec(service, "wget", "-q", "-T", "5", "-O", "-", url)
		if got := strings.TrimSpace(out); err != nil || got != want.String() {
			t.Errorf("%s → %s: the gateway saw %q (%v), want %s", service, url, got, err, want)
		}
	}
	sc.td.disconnect(t)
	if _, err := sc.stack.tryExec(sc.td.backend.service, "ip", "link", "show", "tdvpn0"); err == nil {
		t.Error("tdvpn0 still exists after disconnect")
	}
	if rules := readRouting(t, sc.td).rules; slices.ContainsFunc(rules, func(line string) bool { return strings.HasPrefix(line, "7099:") }) {
		t.Errorf("net-to-net rules left after disconnect: %q", rules)
	}
}

// newestLogTime returns the time of the newest connection log line, zero
// when the log is empty.
func (sc *ipsecScenario) newestLogTime(t *testing.T) time.Time {
	t.Helper()
	logs := sc.td.logs(t)
	if len(logs) == 0 {
		return time.Time{}
	}
	return logs[len(logs)-1].Time
}

// logsSinceConnect returns the connection log lines of this scenario's
// tunnel.
func (sc *ipsecScenario) logsSinceConnect(t *testing.T) []logLine {
	t.Helper()
	return slices.DeleteFunc(sc.td.logs(t), func(line logLine) bool { return !line.Time.After(sc.connectedAfter) })
}
