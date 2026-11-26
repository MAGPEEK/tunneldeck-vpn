//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ipsecGatewayPSKConnection is the gateway's connection for the pre-shared
// key clients (ipsecgw/swanctl.conf).
const ipsecGatewayPSKConnection = "psk"

// lostSATimeout bounds the wait for the reconnecting state after the
// gateway deleted the SA.
const lostSATimeout = 30 * time.Second

// foreignCA returns a self-signed CA certificate (PEM) that issued nothing
// the gateway holds.
func foreignCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the foreign CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Foreign e2e CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the foreign CA certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// checkWrongCA connects a certificate profile whose CA did not issue the
// gateway's certificate: the state becomes error with auth_failed and a
// message about the gateway's certificate (the driver's mapping of
// charon's certificate alert), and the gateway sees exactly one
// authentication, also after noRetryWindow.
func (sc *ipsecScenario) checkWrongCA(t *testing.T) {
	sc.stack.exec(t, ipsecGatewayService, "sh", "-c", ": >"+ipsecGatewayLog)
	req := sc.ipsec.profile(sc.credentials)
	req.Name += " wrong CA"
	req.Settings["caCert"] = foreignCA(t)
	sc.expectFailure(t, req, "auth_failed", func() {
		if got := sc.authAttempts(t); got != 1 {
			t.Errorf("gateway saw %d authentications, want 1", got)
		}
		if last := sc.td.status(t).LastError; last == nil || !strings.HasPrefix(last.Message, "the gateway's certificate ") {
			t.Errorf("last error %+v, want a message about the gateway's certificate", last)
		}
	})
}

// checkRestart restarts the container under a connected tunnel: the
// tunnel comes back by itself with the routing and the firewall, nothing
// of the tunnel before the restart is left twice, and after a disconnect
// nothing is left at all.
func (sc *ipsecScenario) checkRestart(t *testing.T) {
	sc.before = readRouting(t, sc.td)
	id := sc.td.createProfile(t, sc.ipsec.profile(sc.credentials))
	t.Cleanup(func() { sc.cleanUp(t, id) })
	sc.connect(t, id)

	sc.td.restart(t)
	vpnIP := sc.waitConnected(t)
	sc.checkRouting(t, vpnIP)
	sc.checkNoDuplicates(t)
	sc.checkFirewallInstalled(t)
	sc.checkTraffic(t)

	sc.td.disconnect(t)
	sc.checkTornDown(t)
	sc.checkCharonStopped(t)
}

// checkNoDuplicates: one charon, every policy rule and TunnelDeck's INPUT
// jump once.
func (sc *ipsecScenario) checkNoDuplicates(t *testing.T) {
	t.Helper()
	if pids := strings.Fields(sc.td.exec(t, "pidof", "charon")); len(pids) != 1 {
		t.Errorf("charon processes %q, want exactly one", pids)
	}
	rules := readRouting(t, sc.td).rules
	input := appendRules(sc.td.exec(t, sc.td.backend.iptables, "-w", "-S", "INPUT"))
	for name, listing := range map[string][]string{"ip rule": rules, "INPUT": input} {
		seen := map[string]bool{}
		for _, line := range listing {
			if seen[line] {
				t.Errorf("%s lists %q twice: %q", name, line, listing)
			}
			seen[line] = true
		}
	}
}

// checkLostSA has the gateway delete the IKE SA while the client cannot
// answer or reach it: charon learns of the loss from the gateway's DELETE,
// the state becomes reconnecting, and once the gateway is reachable again
// charon restores the tunnel (close_action = start; the driver initiates
// again otherwise) with the routing as before. A gateway that vanishes
// without a DELETE is found by DPD (30 s) plus charon's retransmissions,
// about three minutes, which this case does not wait for.
func (sc *ipsecScenario) checkLostSA(t *testing.T) {
	sc.before = readRouting(t, sc.td)
	id := sc.td.createProfile(t, sc.ipsec.profile(sc.credentials))
	t.Cleanup(func() { sc.cleanUp(t, id) })
	sc.connect(t, id)

	unblock := sc.blockGateway(t)
	sc.stack.exec(t, ipsecGatewayService, "swanctl", "--terminate", "--ike", ipsecGatewayPSKConnection, "--force")
	sc.td.waitForState(t, "reconnecting", lostSATimeout)
	unblock()

	vpnIP := sc.waitConnected(t)
	sc.checkRouting(t, vpnIP)
	sc.checkTraffic(t)
	sas := sc.stack.exec(t, ipsecGatewayService, "swanctl", "--list-sas", "--ike", ipsecGatewayPSKConnection)
	if got := strings.Count(sas, "ESTABLISHED"); got != 1 {
		t.Errorf("the gateway lists %d established IKE SAs after the reconnect, want 1:\n%s", got, sas)
	}
	sc.td.disconnect(t)
	sc.checkTornDown(t)
}

// blockGateway drops every UDP packet from TunnelDeck to the gateway (IKE
// and the UDP-encapsulated ESP) and returns the function that lifts the
// block; the test's cleanup lifts it too.
func (sc *ipsecScenario) blockGateway(t *testing.T) func() {
	t.Helper()
	fields := strings.Fields(sc.td.exec(t, "getent", "hosts", ipsecGatewayService))
	if len(fields) == 0 {
		t.Fatalf("%s cannot resolve %s", sc.td.backend.service, ipsecGatewayService)
	}
	rule := []string{"OUTPUT", "-d", fields[0], "-p", "udp", "-j", "DROP"}
	iptables := sc.td.backend.iptables
	sc.td.exec(t, append([]string{iptables, "-w", "-I"}, rule...)...)
	lifted := false
	unblock := func() {
		if !lifted {
			lifted = true
			_, _ = sc.stack.tryExec(sc.td.backend.service, append([]string{iptables, "-w", "-D"}, rule...)...)
		}
	}
	t.Cleanup(unblock)
	return unblock
}
