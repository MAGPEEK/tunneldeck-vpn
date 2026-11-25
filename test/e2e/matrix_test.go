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

// backend is a TunnelDeck container that sees only one working iptables
// backend (compose.yml removes the other one's binaries).
type backend struct {
	name    string
	service string
	// iptables is the binary that lists this backend's chains.
	iptables string
	// selfCheck is the expected detail of the "iptables" self-check.
	selfCheck string
}

var backends = []backend{
	{name: "iptables-legacy", service: "tunneldeck-legacy", iptables: "iptables-legacy", selfCheck: "using iptables-legacy"},
	{name: "iptables-nft", service: "tunneldeck-nft", iptables: "iptables-nft", selfCheck: "using iptables"},
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
	settings func(pki) map[string]any
	secrets  func(p pki, password string) map[string]string
}

var variants = []variant{
	{
		name:     "A-userpass-aes-gcm",
		service:  "server-a",
		pool:     netip.MustParsePrefix("10.94.1.0/24"),
		gateway:  netip.MustParseAddr("10.94.1.1"),
		password: true,
		settings: func(p pki) map[string]any {
			return map[string]any{
				"remoteHost": "server-a", "port": 1194, "proto": "udp",
				"authMode": "password", "username": vpnUsername, "caCert": p.ca,
			}
		},
		secrets: passwordSecrets,
	},
	{
		name:     "B-userpass-cipher-none",
		service:  "server-b",
		pool:     netip.MustParsePrefix("10.94.2.0/24"),
		gateway:  netip.MustParseAddr("10.94.2.1"),
		password: true,
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
		name:    "C-certificate-tls-crypt-tcp",
		service: "server-c",
		pool:    netip.MustParsePrefix("10.94.3.0/24"),
		gateway: netip.MustParseAddr("10.94.3.1"),
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
