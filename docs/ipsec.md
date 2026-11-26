# IPsec/IKEv2 gateways

[Deutsch](ipsec.de.md)

TunnelDeck-VPN connects to company and router gateways over IPsec: IKEv2 by default, IKEv1 only as a legacy fallback for the FRITZ!Box user access and similar gateways. This guide says what to set up on the gateway and how its values map to the profile form. Specification: [SPEC §19](SPEC.md#19-ipsecikev2-driver-owner-approved-2026-11-26).

## 1. How TunnelDeck-VPN talks to the gateway

- **TunnelDeck-VPN always starts the connection.** It is a client: the gateway must accept a peer whose address it does not know in advance (a "dynamic peer", "road warrior" or "mobile client"). Nothing has to be opened on the TunnelDeck host or on your own internet router.
- **Ports:** the gateway must accept UDP 500 and UDP 4500. TunnelDeck-VPN uses random local ports on its side, so it collides neither with an IPsec server on the same host (such as the DSM VPN server) nor with port forwards of UDP 500/4500 to a LAN device.
- **NAT traversal is always on.** ESP runs in user space inside the container and is always sent in UDP 4500, so the gateway always reports "remote host is behind NAT". This is expected; plain ESP (IP protocol 50) never leaves TunnelDeck-VPN.
- **No kernel IPsec on the host.** The host needs no IPsec kernel modules and gets no IPsec policies; only the TUN device of the [Linux](linux.md) and [Synology](synology.md) guides is required.
- **Liveness and rekeying:** dead peer detection every 30 s; the IKE SA is rekeyed every 4 h, the CHILD SA every hour, without reauthentication (IKEv1 reauthenticates every 4 h). MOBIKE is off.

## 2. The profile form

| Field | Meaning |
|---|---|
| Gateway type | Pre-fills the IKE version and the proposals for LANCOM, FRITZ!Box, OPNsense/pfSense/strongSwan or the generic defaults. |
| Gateway address | Host name (also a dynamic DNS name, resolved at every attempt) or IPv4 address of the gateway. |
| IKE version | IKEv2. IKEv1 means Aggressive Mode with pre-shared key and XAuth only; the form marks it as a security risk. |
| Mode | **Virtual IP**: the gateway assigns an address, which becomes this device's VPN IP; LAN devices are masqueraded to it. **Net-to-net**: local LAN subnets keep their addresses in the tunnel (section 6). |
| Remote subnets | Networks behind the gateway. In virtual IP mode the default `0.0.0.0/0` asks for everything; the host keeps its own default route, every other entry is routed through the tunnel like a remote network. |
| Sign-in method | Pre-shared key; certificate (PEM certificate and key, or a PKCS#12 file with its password); username and password (EAP-MSCHAPv2). |
| Local identity | The identity this side sends (FQDN, IP address, email or DN). Empty: the certificate's subject, the EAP username, or the own IP address with a pre-shared key. |
| Gateway identity | Required with certificate and EAP: it must match the gateway certificate's subject alternative name. With a pre-shared key it may stay empty, then any gateway identity is accepted. |
| CA certificate of the gateway | Required with certificate and EAP; the system CA store is not used. |
| IKE and ESP proposals | strongSwan syntax, one proposal per line. Empty means the RFC 8247/8221 defaults: AES-GCM and AES-CBC with SHA-2, Curve25519, ECP-384/256, MODP-3072/2048, ESP with perfect forward secrecy. |

Traffic selectors: the gateway may narrow the requested subnets; TunnelDeck-VPN accepts that. If no negotiated remote subnet covers `0.0.0.0/0` (for example the FRITZ!Box, which offers only its LAN), the tunnel does not carry internet traffic, so TunnelDeck-VPN does not detect a public IP through it (SPEC §6.1): the dashboard shows no public IP and the log says why.

## 3. LANCOM

Template **LANCOM**. In LANconfig under **VPN → IKEv2/IPSec**:

1. **Connection** for TunnelDeck-VPN with an empty remote gateway (TunnelDeck-VPN connects, its address may change), IKEv2, and the authentication: pre-shared key with an identity on each side (for example the type FQDN), or certificates.
2. **Proposals:** IKE AES-GCM-256 with PRF SHA-256 and DH group 19 (ECP-256) or 14 (MODP-2048); IPsec AES-GCM-256 with PFS group 19 or 14. These are the template's values; if the router uses others, enter its proposals in the form.
3. **Virtual IP:** give the connection an IKE-CFG address pool (IKE-CFG mode "server"); the remote subnets in TunnelDeck-VPN are the router's networks (or `0.0.0.0/0` when it routes everything).
4. **Net-to-net:** the router's IPv4 rules name its own network as local and the TunnelDeck LAN subnet as remote; in TunnelDeck-VPN the same networks the other way round.

Profile: gateway address = the router's public address or DNS name, local identity = the router's remote identity, gateway identity = the router's local identity (or empty with a pre-shared key), pre-shared key as on the router.

*Unverified:* the menu names differ between LCOS versions; no real LANCOM was tested, only a strongSwan gateway with the template's proposals.

## 4. FRITZ!Box

### User access (IKEv1 XAuth)

FRITZ!OS offers single users only "IPSec Xauth PSK", i.e. IKEv1 Aggressive Mode. Template **FRITZ!Box user access (IKEv1 XAuth)**.

1. On the FRITZ!Box create or open a user under **System → FRITZ!Box Users**, allow **VPN** and open the **VPN settings**. The "VPN-Daten" (VPN data) for "IPSec Xauth PSK" show the values below.
2. Map them to the form:

| FRITZ!Box "VPN-Daten" | Form field |
|---|---|
| Server address (MyFRITZ! name or IP) | Gateway address |
| IPSec-ID | Local identity |
| Shared secret | Pre-shared key |
| Account name | XAuth username |
| Password | XAuth password |
| – | Gateway identity: leave empty. The FRITZ!Box identifies itself with its internet IP address, not with the MyFRITZ! name. |

3. Mode virtual IP; remote subnets: the FRITZ!Box LAN, for example `192.168.178.0/24`. The FRITZ!Box assigns an address from its LAN (for example `192.168.178.202`), which becomes the VPN IP.

The template's proposals start with MODP-2048 and fall back to MODP-1024, which FRITZ!OS still uses; the form shows a warning for it. Field test 2026-11-26: connected, the FRITZ!Box LAN and its web interface reachable through the tunnel, the host's main routing table unchanged. Since the FRITZ!Box carries only its LAN, no public IP is shown.

### LAN-to-LAN (IKEv2)

Template **FRITZ!Box (LAN-to-LAN, IKEv2)**, mode net-to-net. On the FRITZ!Box under **Internet → Permit Access → VPN (IPSec)** add a connection to another network: the remote network is the TunnelDeck LAN subnet (the local subnets in TunnelDeck-VPN), the pre-shared key the same on both sides. In TunnelDeck-VPN the remote subnets are the FRITZ!Box LAN. The LAN router of the TunnelDeck side needs the static route of section 6.

*Unverified:* LAN-to-LAN with a real FRITZ!Box; whether FRITZ!OS offers IKEv2 for it depends on the version.

## 5. OPNsense, pfSense and strongSwan

Template **OPNsense / pfSense / strongSwan** (the IKEv2 defaults).

- **OPNsense** (VPN → IPsec → Connections): a connection with version IKEv2, local and remote authentication (pre-shared key, public key, or EAP-MSCHAPv2 for the remote side), a pool for virtual IPs, and a child with the local networks.
- **pfSense** (VPN → IPsec): for virtual IP mode the **Mobile Clients** tab with a virtual address pool and a mobile phase 1 (IKEv2, mutual PSK, EAP-MSCHAPv2 or certificates); for net-to-net a phase 1 with the TunnelDeck side as peer and a phase 2 with the local network and the TunnelDeck LAN subnet as remote network.
- **strongSwan** (`swanctl.conf`), as in the end-to-end test (`test/e2e/ipsecgw/swanctl.conf`):

```
connections {
  tunneldeck {
    version = 2
    proposals = aes256gcm16-prfsha384-curve25519-ecp384-ecp256-modp3072, aes256-sha256-modp2048
    pools = tunneldeck
    local  { auth = psk  id = gateway.example.com }
    remote { auth = psk  id = tunneldeck.example.com }
    children {
      tunneldeck {
        local_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16-curve25519-ecp256-modp3072, aes256-sha256-modp2048
      }
    }
  }
}
pools {
  tunneldeck { addrs = 10.10.10.10-10.10.10.99 }
}
secrets {
  ike-tunneldeck { id = tunneldeck.example.com  secret = "a long random pre-shared key" }
}
```

For net-to-net drop `pools` and set `local_ts` to the gateway's networks and `remote_ts` to the TunnelDeck LAN subnet. The profile: gateway identity `gateway.example.com` (or empty), local identity `tunneldeck.example.com`.

## 6. Net-to-net: static route on the LAN router

In net-to-net mode the LAN devices keep their own addresses in the tunnel, so the gateway side sees them as they are. This needs three things on the TunnelDeck side:

1. **Static route on the LAN router:** destination = each remote subnet, next hop = the LAN address of the TunnelDeck host. Example: remote subnet `10.20.0.0/24`, TunnelDeck host `192.168.1.10` → route `10.20.0.0/24 via 192.168.1.10`. Without it, the LAN devices send traffic for the remote subnets to their default gateway, the internet router. The form shows this hint with the host's LAN address.
2. **IP forwarding** on the host and an **outbound rule** for each LAN device (or the whole LAN) to the remote subnets, as for every LAN device that uses the tunnel ([Linux](linux.md#10-firewall-rules), [Synology](synology.md#10-firewall-rules-and-ipsec)).
3. The host itself reaches the remote subnets from its LAN address in the local subnets, no further setting needed.

Connections from the remote subnets to LAN devices that are not answers still need an inbound firewall rule.

## 7. Troubleshooting

| Status message | Cause and fix |
|---|---|
| The server rejected the credentials | Wrong pre-shared key, XAuth or EAP password, or identities the gateway does not know. TunnelDeck-VPN does not retry, so the account is not locked; fix the profile and connect again. |
| The gateway accepted none of the proposals | Compare the IKE and ESP proposals with the gateway, or choose the gateway type again. |
| The gateway refused the subnets of the tunnel | Local or remote subnets do not match the gateway's configuration (IKEv2 TS_UNACCEPTABLE). |
| The gateway assigned no virtual IP | Virtual IP mode needs an address pool on the gateway; retried automatically. |
| The server address lies in a network routed through the tunnel | The gateway address is inside a remote subnet; remove that subnet or use another address. |

The log of the dashboard shows charon's messages. The end-to-end test (`test/e2e/`, variant E) runs a strongSwan gateway with a pre-shared key, a certificate, EAP-MSCHAPv2 and IKEv1 XAuth, and net-to-net for a LAN. *Unverified:* real LANCOM, OPNsense, pfSense and Sophos gateways, and arm64.
