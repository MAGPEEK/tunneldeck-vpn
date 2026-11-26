//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// IPsec part of the firewall topology (compose.yml): lan-ipsec in the LAN
// and peer-ipsec on the VPN side, each with an inner network behind it.
var (
	// ipsecPeerAddress is peer-ipsec's IKE address on the VPN side.
	ipsecPeerAddress = netip.MustParseAddr("198.18.0.2")
	lanInner         = netip.MustParsePrefix("10.96.1.0/24")
	lanInnerHost     = netip.MustParseAddr("10.96.1.1")
	peerInner        = netip.MustParsePrefix("10.96.2.0/24")
	peerInnerHost    = netip.MustParseAddr("10.96.2.1")
	// The manually keyed ESP check uses its own inner networks, so its
	// policies never meet those of the IKE SAs.
	lanManualInner    = netip.MustParsePrefix("10.97.1.0/24")
	lanManualAddress  = netip.MustParsePrefix("10.97.1.1/24")
	peerManualInner   = netip.MustParsePrefix("10.97.2.0/24")
	peerManualAddress = netip.MustParsePrefix("10.97.2.1/24")
)

const (
	// ipsecConnection names the swanctl connection and its child on both
	// sides.
	ipsecConnection   = "e2e"
	ipsecLANID        = "lan-ipsec.e2e"
	ipsecPeerID       = "peer-ipsec.e2e"
	ipsecPSK          = "e2e throwaway pre-shared key"
	swanctlFile       = "/etc/swanctl/conf.d/e2e.conf"
	ipsecTemplateName = "LANCOM stand-in"
)

// ipsecEndpoint is one side of the IPsec tunnel.
type ipsecEndpoint struct {
	service   string
	local     netip.Addr
	remote    netip.Addr
	localID   string
	remoteID  string
	localNet  netip.Prefix
	remoteNet netip.Prefix
	innerHost netip.Addr
}

// swanctlConfig is an IKEv2 connection with a pre-shared key and current
// proposals (AES-GCM, ECP-256), started only on request.
func (e ipsecEndpoint) swanctlConfig() string {
	return fmt.Sprintf(`connections {
  %[1]s {
    version = 2
    local_addrs = %[2]s
    remote_addrs = %[3]s
    proposals = aes256gcm16-prfsha256-ecp256
    local {
      auth = psk
      id = %[4]s
    }
    remote {
      auth = psk
      id = %[5]s
    }
    children {
      %[1]s {
        local_ts = %[6]s
        remote_ts = %[7]s
        esp_proposals = aes256gcm16-ecp256
        start_action = none
      }
    }
  }
}
secrets {
  ike-%[1]s {
    id-local = %[4]s
    id-remote = %[5]s
    secret = "%[8]s"
  }
}
`, ipsecConnection, e.local, e.remote, e.localID, e.remoteID, e.localNet, e.remoteNet, ipsecPSK)
}

// ipsecEndpoints returns lan-ipsec and peer-ipsec; the peer reaches the
// LAN device only by the tunnel address.
func (sc *lanScenario) ipsecEndpoints() (lan, peer ipsecEndpoint) {
	lan = ipsecEndpoint{
		service: lanIPsecService, local: lanIPsecAddress, remote: ipsecPeerAddress,
		localID: ipsecLANID, remoteID: ipsecPeerID, localNet: lanInner, remoteNet: peerInner, innerHost: lanInnerHost,
	}
	peer = ipsecEndpoint{
		service: peerIPsecService, local: ipsecPeerAddress, remote: sc.vpnIP,
		localID: ipsecPeerID, remoteID: ipsecLANID, localNet: peerInner, remoteNet: lanInner, innerHost: peerInnerHost,
	}
	return lan, peer
}

// checkIPsec applies the "IPsec device" template for lan-ipsec with
// peer-ipsec as the only peer and establishes IKEv2 in both directions.
// TunnelDeck masquerades the LAN device behind the tunnel address, so both
// sides detect NAT and move IKE and ESP to UDP 4500 (NAT-T).
func (sc *lanScenario) checkIPsec(t *testing.T) {
	sc.applyIPsecTemplate(t)
	lan, peer := sc.ipsecEndpoints()
	for _, e := range []ipsecEndpoint{lan, peer} {
		sc.stack.execInput(t, e.service, e.swanctlConfig(), "sh", "-c", "cat >"+swanctlFile)
		sc.stack.exec(t, e.service, "swanctl", "--load-all")
	}
	t.Run("peer-initiates", func(t *testing.T) { sc.checkIPsecInitiation(t, peer, lan) })
	t.Run("lan-initiates", func(t *testing.T) { sc.checkIPsecInitiation(t, lan, peer) })
}

// applyIPsecTemplate fetches the template rules, checks their shape and
// saves them as the whole firewall.
func (sc *lanScenario) applyIPsecTemplate(t *testing.T) {
	t.Helper()
	request := map[string]any{
		"name": ipsecTemplateName, "deviceAddress": lanIPsecAddress.String(), "peers": []string{ipsecPeerAddress.String()},
	}
	var template struct {
		Rules []firewallRule `json:"rules"`
	}
	sc.td.must(t, sc.td.api.call(http.MethodPost, "/api/firewall/templates/ipsec", request, &template), "get the IPsec template")
	if len(template.Rules) != 5 {
		t.Fatalf("IPsec template returned %d rules, want 5: %+v", len(template.Rules), template.Rules)
	}
	for _, rule := range template.Rules {
		if rule.Direction == "inbound" && (!rule.KeepSourceAddress || rule.Destination.CIDR != lanIPsecAddress.String()) {
			t.Errorf("template rule %q: keepSourceAddress %v, destination %q; want true and %s",
				rule.Name, rule.KeepSourceAddress, rule.Destination.CIDR, lanIPsecAddress)
		}
	}
	sc.td.must(t, sc.td.setFirewallRules(template.Rules), "save the IPsec template rules")
}

// checkIPsecInitiation: the initiator establishes the SA, both sides list
// it as established and UDP-encapsulated, and the inner networks ping
// each other through it in both directions. The SA is closed afterwards.
func (sc *lanScenario) checkIPsecInitiation(t *testing.T, initiator, responder ipsecEndpoint) {
	t.Cleanup(func() { sc.terminateIPsec(initiator, responder) })
	out, err := sc.stack.tryExec(initiator.service, "swanctl", "--initiate", "--child", ipsecConnection, "--timeout", "30")
	if err != nil {
		t.Fatalf("%s could not establish IKEv2 with %s: %v\n%s", initiator.service, initiator.remote, err, out)
	}
	for _, e := range []ipsecEndpoint{initiator, responder} {
		sas := sc.stack.exec(t, e.service, "swanctl", "--list-sas", "--ike", ipsecConnection)
		for _, want := range []string{"ESTABLISHED", "INSTALLED", "TUNNEL-in-UDP"} {
			if !strings.Contains(sas, want) {
				t.Errorf("%s: swanctl --list-sas has no %q:\n%s", e.service, want, sas)
			}
		}
	}
	for _, from := range []ipsecEndpoint{initiator, responder} {
		to := responder
		if from.service == responder.service {
			to = initiator
		}
		if err := sc.ping(from.service, to.innerHost, "-I", from.innerHost.String()); err != nil {
			t.Errorf("ping %s → %s through IPsec failed: %v", from.innerHost, to.innerHost, err)
		}
	}
}

// terminateIPsec closes the IKE SA and waits until the responder has
// deleted its side too, so the next initiation starts clean.
func (sc *lanScenario) terminateIPsec(initiator, responder ipsecEndpoint) {
	_, _ = sc.stack.tryExec(initiator.service, "swanctl", "--terminate", "--ike", ipsecConnection, "--timeout", "10")
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out, err := sc.stack.tryExec(responder.service, "swanctl", "--list-sas", "--ike", ipsecConnection)
		if err == nil && !strings.Contains(out, "ESTABLISHED") {
			return
		}
		time.Sleep(pollInterval)
	}
}

// checkESPForwarding sends plain ESP (IP protocol 50, no UDP) through the
// template's ESP forward with manually keyed SAs: IKE always detects the
// NAT and encapsulates, so only manual keys exercise the ESP rule itself.
// The peer pings lan-ipsec's inner address; the answer proves ESP reached
// lan-ipsec with the peer's own source address and the reply ESP went back
// through the tunnel.
func (sc *lanScenario) checkESPForwarding(t *testing.T) {
	sc.applyIPsecTemplate(t)
	lan := manualSA{
		service: lanIPsecService, local: lanIPsecAddress, remote: ipsecPeerAddress,
		localNet: lanManualInner, remoteNet: peerManualInner, inner: lanManualAddress,
		inSPI: "0xe2e00001", outSPI: "0xe2e00002",
	}
	peer := manualSA{
		service: peerIPsecService, local: ipsecPeerAddress, remote: sc.vpnIP,
		localNet: peerManualInner, remoteNet: lanManualInner, inner: peerManualAddress,
		inSPI: "0xe2e00002", outSPI: "0xe2e00001",
	}
	for _, sa := range []manualSA{lan, peer} {
		sa.install(t, sc.stack)
	}
	err := sc.ping(peer.service, lanManualAddress.Addr(), "-I", peerManualAddress.Addr().String())
	if err != nil {
		t.Errorf("ping %s → %s through manually keyed ESP failed: %v", peerManualAddress.Addr(), lanManualAddress.Addr(), err)
	}
}

// Throwaway AES-GCM keys (16 key bytes and 4 salt bytes) of the manual SAs,
// one per direction: peer → LAN and LAN → peer.
var manualKeys = map[string]string{
	"0xe2e00001": "0x00112233445566778899aabbccddeeff01020304",
	"0xe2e00002": "0xffeeddccbbaa99887766554433221100a0b0c0d0",
}

// manualSA is one side of a manually keyed ESP tunnel.
type manualSA struct {
	service             string
	local, remote       netip.Addr
	localNet, remoteNet netip.Prefix
	inner               netip.Prefix // address/prefix put on inner0
	inSPI, outSPI       string
}

// install adds the inner address, both states and both policies, and
// registers their removal.
func (sa manualSA) install(t *testing.T, s stack) {
	t.Helper()
	inState := sa.state(sa.remote, sa.local, sa.inSPI)
	outState := sa.state(sa.local, sa.remote, sa.outSPI)
	outPolicy := sa.policy(sa.localNet, sa.remoteNet, "out", sa.local, sa.remote)
	inPolicy := sa.policy(sa.remoteNet, sa.localNet, "in", sa.remote, sa.local)
	t.Cleanup(func() {
		for _, del := range [][]string{
			{"ip", "xfrm", "policy", "delete", "src", sa.localNet.String(), "dst", sa.remoteNet.String(), "dir", "out"},
			{"ip", "xfrm", "policy", "delete", "src", sa.remoteNet.String(), "dst", sa.localNet.String(), "dir", "in"},
			{"ip", "xfrm", "state", "delete", "src", sa.remote.String(), "dst", sa.local.String(), "proto", "esp", "spi", sa.inSPI},
			{"ip", "xfrm", "state", "delete", "src", sa.local.String(), "dst", sa.remote.String(), "proto", "esp", "spi", sa.outSPI},
			{"ip", "addr", "del", sa.inner.String(), "dev", "inner0"},
		} {
			_, _ = s.tryExec(sa.service, del...)
		}
	})
	s.exec(t, sa.service, "ip", "addr", "replace", sa.inner.String(), "dev", "inner0")
	for _, args := range [][]string{inState, outState, outPolicy, inPolicy} {
		s.exec(t, sa.service, args...)
	}
}

func (sa manualSA) state(src, dst netip.Addr, spi string) []string {
	return []string{"ip", "xfrm", "state", "add", "src", src.String(), "dst", dst.String(), "proto", "esp", "spi", spi,
		"mode", "tunnel", "aead", "rfc4106(gcm(aes))", manualKeys[spi], "128"}
}

func (sa manualSA) policy(src, dst netip.Prefix, dir string, outerSrc, outerDst netip.Addr) []string {
	return []string{"ip", "xfrm", "policy", "add", "src", src.String(), "dst", dst.String(), "dir", dir,
		"tmpl", "src", outerSrc.String(), "dst", outerDst.String(), "proto", "esp", "mode", "tunnel"}
}
