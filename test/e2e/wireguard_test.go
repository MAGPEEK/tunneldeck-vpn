//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// WireGuard test server (variant D, wgserver/).
const (
	wireGuardService = "server-wg"
	wireGuardPort    = "51820"
	// wireGuardAddress is the interface address the server accepts from its
	// only peer (wgserver/peer.sh); its network is the tunnel subnet.
	wireGuardAddress = "10.94.4.2/24"
	// The status names a missing first handshake after 30 s (SPEC §18).
	// Measured from the test it may come a little earlier: the clock of
	// Docker Desktop's VM runs a few percent fast (2026-11-26: 30 s in the
	// container took 28.5–29 s on the Windows host), so the test only
	// checks that it does not come early. noHandshakeTimeout adds the
	// driver's 2 s checks and some slack.
	minNoAnswerDelay   = 25 * time.Second
	noHandshakeTimeout = 45 * time.Second
)

// everything is the allowed IP that sends all traffic to the server; the
// host keeps its default route anyway (SPEC §18).
const everything = "0.0.0.0/0"

// wireGuardVariant describes server-wg for the checks shared with the
// OpenVPN variants. Its profiles are built by wireGuardScenario.
var wireGuardVariant = variant{
	name:        "D-wireguard",
	service:     wireGuardService,
	pool:        netip.MustParsePrefix("10.94.4.0/24"),
	gateway:     netip.MustParseAddr("10.94.4.1"),
	remoteHost:  netip.MustParseAddr("10.99.0.1"),
	dataCipher:  "ChaCha20-Poly1305",
	hostAddress: true,
}

// keyPair is a WireGuard key pair from POST /api/drivers/wireguard/keypair.
type keyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

// importDraft is the response of POST /api/profiles/import.
type importDraft struct {
	Settings map[string]any    `json:"settings"`
	Secrets  map[string]string `json:"secrets"`
	Warnings []struct {
		Code     string `json:"code"`
		Severity string `json:"severity"`
	} `json:"warnings"`
	Missing []string `json:"missing"`
}

// wireGuardScenario is variant D on one backend.
type wireGuardScenario struct {
	*scenario
}

func newWireGuardScenario(s stack, td *tunnelDeck) *wireGuardScenario {
	return &wireGuardScenario{scenario: &scenario{stack: s, td: td, variant: wireGuardVariant}}
}

// run creates the profile from form fields, checks the tunnel like an
// OpenVPN one, then connects a profile imported from a .conf file and
// restarts the container.
func (sc *wireGuardScenario) run(t *testing.T) {
	sc.before = readRouting(t, sc.td)
	keys := sc.newPeer(t)
	id := sc.td.createProfile(t, sc.formProfile(keys, sc.serverPublicKey(t), everything, remoteNetwork.String()))
	t.Cleanup(func() { sc.cleanUp(t, id) })
	sc.checkStoredKeys(t, id, keys)

	vpnIP := sc.connect(t, id)
	sc.checkChannel(t, keys)
	sc.checkTraffic(t)
	sc.checkRouting(t, vpnIP)
	sc.checkRemoteNetwork(t, true)
	sc.checkHostProtection(t, vpnIP)
	sc.checkRemoteAccess(t, vpnIP)

	sc.td.disconnect(t)
	sc.checkTornDown(t)
	sc.checkRemoteNetwork(t, false)

	imported := sc.td.createProfile(t, sc.importedProfile(t, keys))
	t.Cleanup(func() { sc.cleanUp(t, imported) })
	sc.connect(t, imported)
	sc.td.restart(t)
	vpnIP = sc.waitConnected(t)
	sc.checkRouting(t, vpnIP)
	sc.checkFirewallInstalled(t)
}

// checkNoHandshake connects with a wrong peer public key: the server never
// answers, the state stays connecting and after 30 s the status carries
// the message code wireguard_no_handshake.
func (sc *wireGuardScenario) checkNoHandshake(t *testing.T) {
	keys := sc.newPeer(t)
	wrongPeer := sc.keyPair(t).PublicKey
	id := sc.td.createProfile(t, sc.formProfile(keys, wrongPeer, everything))
	t.Cleanup(func() { sc.cleanUp(t, id) })
	connected := time.Now()
	sc.td.connect(t, id)
	status := sc.td.waitFor(t, "message code wireguard_no_handshake", noHandshakeTimeout, func(s connectionStatus) bool {
		return s.MessageCode == "wireguard_no_handshake" || s.State == "connected" || s.State == "error"
	})
	if status.State != "connecting" || status.MessageCode != "wireguard_no_handshake" {
		t.Errorf("status %+v, want state connecting with message code wireguard_no_handshake", status)
	}
	if elapsed := time.Since(connected); elapsed < minNoAnswerDelay {
		t.Errorf("message code after %s, want it only after about 30 s\n%s", elapsed.Round(time.Second), sc.td.logTail())
	}
}

// keyPair asks TunnelDeck for a fresh key pair; nothing is stored.
func (sc *wireGuardScenario) keyPair(t *testing.T) keyPair {
	t.Helper()
	var keys keyPair
	sc.td.must(t, sc.td.api.call(http.MethodPost, "/api/drivers/wireguard/keypair", nil, &keys), "generate a key pair")
	if keys.PrivateKey == "" || keys.PublicKey == "" {
		t.Fatalf("key pair %+v, want both keys", keys)
	}
	return keys
}

// newPeer generates a key pair through the API and makes its public key
// the server's only peer, as the owner enters it on the server.
func (sc *wireGuardScenario) newPeer(t *testing.T) keyPair {
	t.Helper()
	keys := sc.keyPair(t)
	sc.stack.exec(t, wireGuardService, "e2e-wgserver-peer", keys.PublicKey)
	return keys
}

// serverPublicKey reads the key the server generated at its start.
func (sc *wireGuardScenario) serverPublicKey(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(sc.stack.exec(t, wireGuardService, "cat", "/run/e2e/server.pub"))
}

// formProfile is a profile as the form sends it.
func (sc *wireGuardScenario) formProfile(keys keyPair, peerPublicKey string, allowedIPs ...string) profileRequest {
	return profileRequest{
		Name:     "e2e " + sc.variant.name,
		Protocol: "wireguard",
		Settings: map[string]any{
			"address": wireGuardAddress, "mtu": 1420,
			"peerPublicKey": peerPublicKey, "endpoint": wireGuardService + ":" + wireGuardPort,
			"allowedIps": allowedIPs, "persistentKeepalive": 25,
		},
		Secrets: map[string]string{"privateKey": keys.PrivateKey},
	}
}

// checkStoredKeys: the stored profile shows the private key only as
// present and the public key derived from it, never the key itself.
func (sc *wireGuardScenario) checkStoredKeys(t *testing.T, id string, keys keyPair) {
	t.Helper()
	var raw json.RawMessage
	sc.td.must(t, sc.td.api.get("/api/profiles/"+id, &raw), "read the profile")
	if strings.Contains(string(raw), keys.PrivateKey) {
		t.Errorf("GET /api/profiles/%s returns the private key", id)
	}
	var profile struct {
		Secrets map[string]struct {
			HasValue bool `json:"hasValue"`
		} `json:"secrets"`
		Derived map[string]string `json:"derived"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatalf("decode the profile: %v", err)
	}
	if !profile.Secrets["privateKey"].HasValue || profile.Derived["publicKey"] != keys.PublicKey {
		t.Errorf("profile secrets %+v, derived %+v; want privateKey present and publicKey %s",
			profile.Secrets, profile.Derived, keys.PublicKey)
	}
}

// checkChannel: the status names WireGuard's fixed cipher and no control
// channel, the routing applied without a warning, and no log line holds
// the private key.
func (sc *wireGuardScenario) checkChannel(t *testing.T, keys keyPair) {
	t.Helper()
	status := sc.td.status(t)
	if status.DataCipher != sc.variant.dataCipher || status.ControlChannel != "" {
		t.Errorf("data cipher %q, control channel %q; want %q and none", status.DataCipher, status.ControlChannel, sc.variant.dataCipher)
	}
	if status.RoutingWarning != nil || status.MessageCode != "" {
		t.Errorf("routing warning %+v, message code %q; want neither", status.RoutingWarning, status.MessageCode)
	}
	for _, line := range sc.td.logs(t) {
		if strings.Contains(line.Text, keys.PrivateKey) {
			t.Errorf("log line holds the private key: %q", line.Level)
		}
	}
}

// importedProfile imports a wg-quick file with the same keys and checks
// the draft: DNS, the IPv6 entries and the missing keepalive are noted,
// nothing is rejected or missing.
func (sc *wireGuardScenario) importedProfile(t *testing.T, keys keyPair) profileRequest {
	t.Helper()
	conf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + keys.PrivateKey,
		"Address = " + wireGuardAddress + ", fd00:94:4::2/64",
		"DNS = 192.0.2.53",
		"",
		"[Peer]",
		"PublicKey = " + sc.serverPublicKey(t),
		"Endpoint = " + wireGuardService + ":" + wireGuardPort,
		"AllowedIPs = " + everything + ", ::/0, " + remoteNetwork.String(),
		"",
	}, "\n")
	var draft importDraft
	body := map[string]string{"protocol": "wireguard", "text": conf}
	sc.td.must(t, sc.td.api.call(http.MethodPost, "/api/profiles/import", body, &draft), "import the .conf file")

	var codes []string
	for _, w := range draft.Warnings {
		if w.Severity == "rejected" {
			t.Errorf("import rejected a line: %+v", w)
		}
		codes = append(codes, w.Code)
	}
	for _, want := range []string{"dns_ignored", "ipv6_ignored", "keepalive_default"} {
		if !slices.Contains(codes, want) {
			t.Errorf("import warnings %q, want %s among them", codes, want)
		}
	}
	if len(draft.Missing) > 0 || draft.Secrets["privateKey"] != keys.PrivateKey ||
		draft.Settings["address"] != wireGuardAddress || draft.Settings["persistentKeepalive"] != float64(25) {
		t.Errorf("import draft settings %v, missing %q; want the file's values, keepalive 25 and nothing missing",
			draft.Settings, draft.Missing)
	}
	return profileRequest{
		Name: "e2e " + sc.variant.name + " imported", Protocol: "wireguard",
		Settings: draft.Settings, Secrets: draft.Secrets,
	}
}

// checkOutboundRoutingOverWireGuard repeats outbound-policy-routing with a
// WireGuard tunnel whose only allowed IP is 0.0.0.0/0: only lan-web's
// outbound rule sends its traffic to the network behind server-wg.
func (sc *lanScenario) checkOutboundRoutingOverWireGuard(t *testing.T) {
	wg := newWireGuardScenario(sc.stack, sc.td)
	keys := wg.newPeer(t)
	id := sc.td.createProfile(t, wg.formProfile(keys, wg.serverPublicKey(t), everything))
	t.Cleanup(func() {
		_ = sc.td.api.call(http.MethodPost, "/api/connection/disconnect", nil, nil)
		_ = sc.td.setFirewallRules(nil)
		_ = sc.td.api.call(http.MethodDelete, "/api/profiles/"+id, nil, nil)
	})
	wg.connect(t, id)
	(&lanScenario{scenario: wg.scenario, host: sc.host}).checkOutboundRouting(t)
}
