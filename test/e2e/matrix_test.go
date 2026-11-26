//go:build e2e

package e2e

import (
	"net/netip"
	"testing"
)

// Test credentials of the throwaway servers. The password contains the
// characters the management protocol has to escape (docs/openvpn-notes.md).
const (
	vpnUsername      = "e2e-user"
	vpnPassword      = `e2e p"a\ss'w#rd;$x`
	vpnWrongPassword = "not-the-password"
)

// backend is a TunnelDeck container and the iptables backend its automatic
// detection must choose (compose.yml sets up each host).
type backend struct {
	name    string
	service string
	// iptables is the binary that lists the chosen backend's chains.
	iptables string
	// unusedIptables lists the backend that must stay free of TunnelDeck's
	// chains; empty when its binaries were removed.
	unusedIptables string
	// selfCheckPrefix is the expected start of the "iptables" self-check
	// detail; the rule count after it depends on Docker's own rules.
	selfCheckPrefix string
}

var backends = []backend{
	{
		name: "only-legacy", service: "tunneldeck-legacy", iptables: "iptables-legacy",
		selfCheckPrefix: "using iptables-legacy: only the legacy backend works",
	},
	{
		name: "only-nft", service: "tunneldeck-nft", iptables: "iptables-nft",
		selfCheckPrefix: "using iptables-nft: only the nf_tables backend works",
	},
	{
		name: "both-nft-has-host-rules", service: "tunneldeck-shared", iptables: "iptables-nft", unusedIptables: "iptables-legacy",
		selfCheckPrefix: "using iptables-nft: host rules only in nf_tables (",
	},
}

// pki is the throwaway PKI of one test server, read from its container.
type pki struct {
	ca, clientCert, clientKey, tlsCryptKey string
}

// variant is one OpenVPN test server and the profile that reaches it.
type variant struct {
	name    string
	service string       // compose service of the server
	pool    netip.Prefix // address pool the server assigns from
	gateway netip.Addr   // the server's own tunnel address
	// password is true when the server checks username and password.
	password bool
	// remoteHost, when valid, is an address on the network behind the
	// server that the profile names in remoteNetworks.
	remoteHost netip.Addr
	// dataCipher is the data-channel cipher the status must report.
	dataCipher string
	// hostAddress is true when the driver puts the VPN IP on tdvpn0 as a
	// host address (/32, WireGuard): the main table gets no connected
	// route, and the host reaches the server's tunnel address only from the
	// VPN IP, through table 7194.
	hostAddress bool
	settings    func(pki) map[string]any
	secrets     func(p pki, password string) map[string]string
}

var variants = []variant{
	{
		name:       "A-userpass-aes-gcm",
		service:    "server-a",
		pool:       netip.MustParsePrefix("10.94.1.0/24"),
		gateway:    netip.MustParseAddr("10.94.1.1"),
		password:   true,
		remoteHost: netip.MustParseAddr("10.99.0.1"),
		dataCipher: "AES-256-GCM",
		settings: func(p pki) map[string]any {
			return map[string]any{
				"remoteHost": "server-a", "port": 1194, "proto": "udp",
				"authMode": "password", "username": vpnUsername, "caCert": p.ca,
				"remoteNetworks": []string{remoteNetwork.String()},
			}
		},
		secrets: passwordSecrets,
	},
	{
		name:       "B-userpass-cipher-none",
		service:    "server-b",
		pool:       netip.MustParsePrefix("10.94.2.0/24"),
		gateway:    netip.MustParseAddr("10.94.2.1"),
		password:   true,
		dataCipher: "none",
		settings: func(p pki) map[string]any {
			return map[string]any{
				"remoteHost": "server-b", "port": 1194, "proto": "udp",
				"authMode": "password", "username": vpnUsername, "caCert": p.ca,
				"cipher": "none", "authDigest": "none",
				"extraOptions": []string{"tun-mtu 1500", "fragment 1448", "mssfix", "reneg-sec 86400"},
			}
		},
		secrets: passwordSecrets,
	},
	{
		name:       "C-certificate-tls-crypt-tcp",
		service:    "server-c",
		pool:       netip.MustParsePrefix("10.94.3.0/24"),
		gateway:    netip.MustParseAddr("10.94.3.1"),
		dataCipher: "AES-256-GCM",
		settings: func(p pki) map[string]any {
			return map[string]any{
				"remoteHost": "server-c", "port": 1194, "proto": "tcp",
				"authMode": "certificate", "caCert": p.ca, "clientCert": p.clientCert,
			}
		},
		secrets: func(p pki, _ string) map[string]string {
			return map[string]string{"clientKey": p.clientKey, "tlsCryptKey": p.tlsCryptKey}
		},
	},
}

// remoteNetwork is the network behind every test server (entrypoint.sh).
var remoteNetwork = netip.MustParsePrefix("10.99.0.0/24")

func passwordSecrets(_ pki, password string) map[string]string {
	return map[string]string{"password": password}
}

// profile is the create request for this variant with the given password.
func (v variant) profile(p pki, password string) profileRequest {
	return profileRequest{
		Name:     "e2e " + v.name,
		Protocol: "openvpn",
		Settings: v.settings(p),
		Secrets:  v.secrets(p, password),
	}
}

// readPKI fetches the server's CA and the client material from its
// container.
func (v variant) readPKI(t *testing.T, s stack) pki {
	t.Helper()
	read := func(name string) string { return s.exec(t, v.service, "cat", "/etc/openvpn/pki/"+name) }
	return pki{
		ca:          read("ca.crt"),
		clientCert:  read("client.crt"),
		clientKey:   read("client.key"),
		tlsCryptKey: read("tc.key"),
	}
}

// writeCredentials gives the server's verify script the expected login.
func (v variant) writeCredentials(t *testing.T, s stack) {
	t.Helper()
	s.execInput(t, v.service, vpnUsername+"\n"+vpnPassword+"\n", "sh", "-c", "cat >/run/e2e/credentials")
}
