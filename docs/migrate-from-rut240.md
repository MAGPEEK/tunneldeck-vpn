# Moving an mdex connection from a Teltonika RUT240 to TunnelDeck-VPN

[Deutsch](migrate-from-rut240.de.md)

This guide moves an OpenVPN client instance (Services > VPN > OpenVPN on the RUT240) to a TunnelDeck-VPN profile, using an mdex public.IP level-20 connection as the example. The facts behind it are in [`openvpn-notes.md`](openvpn-notes.md). The configuration was tested against emulated mdex servers in a lab, not against the real mdex server.

## Before the first connect

- **Disconnect the router first.** Switch the RUT240's OpenVPN instance off (or unplug the router) before you connect TunnelDeck-VPN. mdex most likely allows one session per account (*check with mdex*); two clients with the same account would keep pushing each other off.
- Have the account's username and password and the CA certificate `mdexCA20.crt` ready (from mdex's download page or the RUT240's certificate files).

## Field mapping

Create a profile with **Profiles > New profile > OpenVPN**, or import an `.ovpn` exported from the router and check the warnings it lists.

| RUT240 field | TunnelDeck-VPN profile field | Note |
|---|---|---|
| TUN/TAP | – | Always TUN. TAP is not supported; an imported `dev tap` is rejected. |
| Protocol | Transport | UDP or TCP. |
| Port | Port | mdex: `1194`. |
| LZO | Compression | mdex level 20: **Off**. Any `comp-lzo` against a server without compression connects but carries no traffic. |
| Authentication | Sign-in method | Password → "Username and password"; TLS → "Certificate"; TLS/Password → "Certificate and password". |
| Encryption | Data channel cipher | None → `none` (see below). |
| Remote host/IP address | Server address | `publicip20.mdex.de` |
| Resolve retry | Retry name resolution | `infinite` (default). |
| Keep alive | Keepalive | Two numbers, interval and timeout, for example `10 120`. Empty: TunnelDeck-VPN sets none. |
| Remote network IP / netmask | – | Not in stage 1. TunnelDeck-VPN never adds routes; it answers connections that arrive through the tunnel. LAN gateway functions are planned for 0.2.0. |
| Authentication algorithm | Authentication digest | None → `none`. Must match the server. |
| User name / Password | Username / Password | The password is stored encrypted and reaches OpenVPN over the management socket, never in a file. |
| Certificate files (CA) | CA certificate | Required in every sign-in method. Paste the PEM text of `mdexCA20.crt`. |
| Extra options | Extra options | One directive per line; see the next table. |

## Extra options of the RUT240

What happens to each line when you paste it into **Extra options** or import it (`internal/vpn/openvpn/classify.go`, `render.go`):

| Line | Result | Why |
|---|---|---|
| `tun-mtu 1500` | kept | Passed to OpenVPN; 1500 is the default anyway. |
| `fragment 1448` | kept | Works in 2.7; shown as an advisory (legacy MTU workaround). Disables data-channel offload. |
| `mssfix` | kept | Takes its value from `fragment`. |
| `float` | kept | |
| `nobind` | dropped with a warning | TunnelDeck-VPN always renders it. |
| `reneg-sec 86400` | kept | |
| `remote-cert-tls server` | dropped with a warning | Set by the profile field "Check that the server certificate is issued for a server" (on by default). |
| `tls-version-min 1.2` | kept | TunnelDeck-VPN renders `tls-version-min 1.2` anyway when no extra option sets a TLS version. |
| `explicit-exit-notify 2` | kept for UDP | Dropped with a warning when the transport is TCP, because OpenVPN ignores it there. |
| `fast-io` | dropped with a warning | Deprecated; OpenVPN 2.7 ignores it. |
| `redirect-gateway def1` | dropped with a warning | Routing is handled by TunnelDeck-VPN; this device keeps its own default route. |

Lines that run scripts or touch files (`up`, `script-security`, `log`, ...) are rejected; the form names the line.

## Why `cipher none` becomes `data-ciphers`

OpenVPN 2.7 ignores `cipher` when it negotiates the data channel. The RUT240's "Encryption: None" pasted as `cipher none` therefore fails against a server that only offers `none` (`AUTH_FAILED ... no shared cipher`). When the profile's cipher is `none`, TunnelDeck-VPN renders

```
data-ciphers none:CHACHA20-POLY1305
data-ciphers-fallback none
```

The tunnel is then unencrypted when the server allows it, and falls back to ChaCha20-Poly1305 when it does not. The dashboard and the form show an advisory that traffic is not encrypted. A `cipher` line in the extra options is dropped with a pointer to the profile field.

## Reaching this device from outside

On the RUT240, the router's web UI was reachable over the tunnel. In TunnelDeck-VPN that is replaced by **remote access over HTTPS** (System > Remote access, default port 8443): TunnelDeck-VPN's own UI on `https://<VPN-address>:8443` with a self-signed or uploaded certificate. See [`synology.md`](synology.md#6-remote-access-over-the-tunnel). Other ports of this device become reachable from the tunnel only through an inbound rule on the **Firewall** page to this device's own LAN address (for example `192.168.1.10`); other devices in the local LAN through an inbound rule to their address (for example `192.168.1.20`), which is a port forward. Everything else stays blocked.

## Recommendation: move to level 30

mdex marks level 20 as no longer to be used. Level 30 needs these changes to the profile:

- Server address `publicip30.mdex.de`.
- CA certificate `mdexCA30.crt`.
- Extra option `tls-version-min 1.3`.
- Remove `tun-mtu`, `fragment`, `mssfix` and `reneg-sec`, which mdex does not list for level 30.
- Cipher `none` and digest `none` stay.

Ask mdex whether your account is enabled for level 30. This variant follows mdex's documentation and has not been tested against the real server.
