package ipsec

import (
	"net/netip"
	"strings"
)

// connName names the connection and its CHILD_SA in charon.
const connName = "tunneldeck"

// plugins are the charon plugins TunnelDeck loads, in load order.
// kernel-libipsec comes before kernel-netlink, because the first plugin
// that provides IPsec wins: ESP then runs in user space on a TUN device and
// no XFRM state or policy is installed in the host. The "!" makes it
// critical: without its TUN device charon refuses to start instead of
// falling back to kernel IPsec. openssl provides the
// algorithms (its legacy provider MD4 and DES for EAP-MSCHAPv2), curl
// fetches CRLs and OCSP answers for the revocation checks, xauth-generic
// answers the IKEv1 XAuth round with the loaded username and password.
var plugins = []string{
	"kernel-libipsec!", "kernel-netlink", "socket-default", "vici", "openssl", "pem", "x509", "pkcs1",
	"pkcs8", "pubkey", "constraints", "revocation", "curl", "nonce", "random", "kdf",
	"eap-identity", "eap-mschapv2", "xauth-generic",
}

// renderStrongswanConf returns charon's configuration (strongswan.conf(5))
// with the VICI socket at socketPath. It holds no secrets: they reach
// charon over VICI only. charon picks random local IKE ports, so it
// collides neither with an IPsec server on the host nor with port forwards
// of UDP 500/4500 (SPEC §19); it installs no routes and no virtual IP
// (TunnelDeck does, on the tunnel device) and adds no routing rule; it
// logs to stderr only, which the driver reads.
func renderStrongswanConf(socketPath string) string {
	lines := []string{
		"# Rendered by TunnelDeck-VPN for one IPsec tunnel (SPEC §19); removed when it stops.",
		"charon {",
		"\tport = 0",
		"\tport_nat_t = 0",
		"\tinstall_routes = no",
		"\tinstall_virtual_ip = no",
		"\trouting_table = 0",
		"\tload = " + strings.Join(plugins, " "),
		"\tplugins {",
		"\t\tvici {",
		"\t\t\tsocket = " + quoteSetting("unix://"+socketPath),
		"\t\t}",
		"\t\topenssl {",
		"\t\t\tload_legacy = yes",
		"\t\t}",
		"\t}",
		"\tfilelog {",
		"\t\tstderr {",
		"\t\t\tdefault = 1",
		"\t\t}",
		"\t}",
		"}",
	}
	return strings.Join(lines, "\n") + "\n"
}

// quoteSetting quotes a strongswan.conf value.
func quoteSetting(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

// Timing of the connection (SPEC §19.1): rekeying instead of
// reauthentication keeps traffic flowing.
const (
	dpdDelay       = "30s"
	ikeRekeyTime   = "4h"
	childRekeyTime = "1h"
)

// connectionMessage is the load-conn request for c: UDP encapsulation,
// fragmentation, DPD every 30 s, retries until the gateway answers. IKEv2
// rekeys without reauthentication and without MOBIKE; the IKEv1 fallback
// uses Aggressive Mode with an XAuth round after the pre-shared key and
// reauthenticates instead, as IKEv1 cannot rekey. The gateway's certificate
// is checked against the CA certificates (relaxed revocation: only a
// certificate known to be revoked fails). A lost IKE or CHILD SA is
// restarted by charon.
func connectionMessage(c profileConfig) *message {
	m := newMessage()
	conn := m.setSection(connName)
	if c.version == IKEv1 {
		conn.set("version", "1").set("aggressive", "yes")
	} else {
		conn.set("version", "2")
	}
	conn.setList("remote_addrs", c.gateway).
		setList("proposals", c.ikeProposals...)
	if c.mode == ModeVirtualIP {
		conn.setList("vips", "0.0.0.0")
	}
	conn.set("encap", "yes").
		set("fragmentation", "yes").
		set("dpd_delay", dpdDelay)
	if c.version == IKEv1 {
		conn.set("rekey_time", "0").set("reauth_time", ikeRekeyTime)
	} else {
		conn.set("mobike", "no").set("rekey_time", ikeRekeyTime).set("reauth_time", "0")
	}
	conn.set("keyingtries", "0")
	localAuth(conn.setSection("local"), c)
	if c.version == IKEv1 {
		conn.setSection("local-xauth").set("auth", "xauth").set("xauth_id", c.xauthUser)
	}
	remoteAuth(conn.setSection("remote"), c)
	child := conn.setSection("children").setSection(connName)
	child.setList("local_ts", localTrafficSelectors(c)...).
		setList("remote_ts", subnetStrings(c.remoteSubnets)...).
		setList("esp_proposals", c.espProposals...).
		set("rekey_time", childRekeyTime).
		set("dpd_action", "restart").
		set("close_action", "start").
		set("start_action", "none")
	return m
}

func localAuth(local *message, c profileConfig) {
	switch c.auth {
	case AuthPSK:
		local.set("auth", "psk")
	case AuthCertificate:
		local.set("auth", "pubkey").setList("certs", certificatePEM(c.client.certificate))
	case AuthEAPMSCHAPv2:
		local.set("auth", "eap-mschapv2").set("eap_id", c.username)
	}
	switch {
	case c.localID != "":
		local.set("id", c.localID)
	case c.auth == AuthEAPMSCHAPv2:
		local.set("id", c.username)
	}
}

func remoteAuth(remote *message, c profileConfig) {
	if c.auth == AuthPSK {
		remote.set("auth", "psk").set("id", identityOrAny(c.remoteID))
		return
	}
	cacerts := make([]string, len(c.caCerts))
	for i, cert := range c.caCerts {
		cacerts[i] = certificatePEM(cert)
	}
	remote.set("auth", "pubkey").
		set("id", c.remoteID).
		setList("cacerts", cacerts...).
		set("revocation", "relaxed")
}

// identityOrAny is id, or %any for a gateway whose identity is not
// configured (pre-shared key only).
func identityOrAny(id string) string {
	if id == "" {
		return "%any"
	}
	return id
}

// localTrafficSelectors are the virtual IP ("dynamic") or the local
// subnets.
func localTrafficSelectors(c profileConfig) []string {
	if c.mode == ModeNetToNet {
		return subnetStrings(c.localSubnets)
	}
	return []string{"dynamic"}
}

func subnetStrings(subnets []netip.Prefix) []string {
	out := make([]string, len(subnets))
	for i, s := range subnets {
		out[i] = s.String()
	}
	return out
}

// viciRequest is one VICI command with its message.
type viciRequest struct {
	command string
	message *message
}

// credentialRequests hand c's secrets and certificates to charon before
// the connection is loaded, so no secret is ever written to a file: the
// pre-shared key (with the XAuth password for the XAuth user in IKEv1),
// the EAP password for the EAP identity, or the private key with the
// certificates of the client certificate's chain.
func credentialRequests(c profileConfig) []viciRequest {
	switch c.auth {
	case AuthPSK:
		psk := viciRequest{"load-shared", newMessage().set("type", "IKE").set("data", c.psk)}
		if c.version == IKEv1 {
			return []viciRequest{psk, {"load-shared",
				newMessage().set("type", "XAUTH").set("data", c.xauthPassword).setList("owners", c.xauthUser)}}
		}
		return []viciRequest{psk}
	case AuthEAPMSCHAPv2:
		return []viciRequest{{"load-shared", newMessage().set("type", "EAP").set("data", c.eapPassword).setList("owners", c.username)}}
	}
	requests := []viciRequest{{"load-key", newMessage().set("type", "any").set("data", c.client.keyPEM)}}
	for _, cert := range c.client.chain {
		requests = append(requests, viciRequest{"load-cert",
			newMessage().set("type", "X509").set("flag", "NONE").set("data", certificatePEM(cert))})
	}
	return requests
}
