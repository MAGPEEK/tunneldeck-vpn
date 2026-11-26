# TunnelDeck-VPN

**A self-hosted VPN client with a web UI, packaged as one Docker container.** Runs on any Linux Docker host, amd64 or arm64: a server, a mini PC or a Raspberry Pi.

[Deutsch](README.de.md) · License: MIT · Status: **0.2.3**, field-tested on a Synology DS723+ with mdex

## What it does

- **Manage VPN profiles in the browser**: create them in a form or import an `.ovpn` file. Several profiles can be stored; one is active at a time.
- **Dashboard**: connection state, VPN address, traffic, and a live log.
- **Stays connected**: reconnects automatically after network errors, stops immediately when credentials are rejected, and reconnects after a container restart.
- **Optional daily reconnect** at a time you choose, per profile.
- **Firewall between VPN and LAN**: everything is blocked unless a rule allows it. Inbound rules open ports on this device or forward them to any other device in the local LAN (also ESP/GRE, e.g. for an IPsec router); outbound rules let chosen LAN devices reach networks behind the VPN, with a kill switch. This device keeps its own default route.
- **Flags outdated settings**: an unencrypted data channel, weak ciphers, compression and similar settings are shown as advisories.
- **Secure by default**: sign-in required, credentials encrypted at rest, web UI on the LAN only. Optional remote access over HTTPS.
- **German and English** UI, light and dark theme.

## Supported VPN methods

| Method | Status |
|---|---|
| OpenVPN (2.7) | available |
| WireGuard | planned |
| IPsec / IKEv2 | planned |

## Quick start

```yaml
services:
  tunneldeck:
    image: magpeek/tunneldeck-vpn:0.2.3
    container_name: tunneldeck
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes: ["./data:/data"]
    environment: { TZ: Europe/Berlin }
    restart: unless-stopped
```

Open `http://<host-ip>:8194` and create the admin account. If you forget the password, run `docker exec tunneldeck tunneldeck reset-admin` (see [Lost admin password](docs/reset-admin.md)).

## Ports

| Port | Protocol | Reachable from | Purpose |
|---|---|---|---|
| 8194 | HTTP | LAN only, never through the tunnel | Web UI. Change it with `TUNNELDECK_LISTEN=<lan-ip>:<port>`, e.g. `192.168.1.10:9000`. |
| 8443 (default, free to choose) | HTTPS | LAN and the VPN tunnel | Optional remote access to the web UI. Off by default; turn it on under **System → Remote access**. Remote access over the VPN is HTTPS only, never plain HTTP. |

All other traffic between the VPN and the LAN is blocked unless you allow it on the **Firewall** page.

## Documentation

- [Linux Docker host setup](docs/linux.md): TUN device, firewall tools (ufw, firewalld), HTTPS, backup, update
- [Synology setup](docs/synology.md): TUN module, Container Manager, firewall, HTTPS, backup, update
- [System page checks explained](docs/system-checks.md): what each self-check entry means and how to fix it on Linux and DSM
- [Lost admin password](docs/reset-admin.md): reset the admin account by command or environment variable, what is kept
- [Moving from a Teltonika RUT240](docs/migrate-from-rut240.md): field mapping and extra options, mdex example
- [Releasing](docs/RELEASING.md): version tags, image build and publishing
- [Specification](docs/SPEC.md) and [OpenVPN notes](docs/openvpn-notes.md)

## Roadmap

- **0.1.0**: OpenVPN client, dashboard, host protection, daily reconnect, HTTPS remote access
- **0.2.0**: firewall with port forwarding to LAN devices, outbound rules and kill switch, IPsec template, remote networks, PKCS#12
- **0.3.0**: WireGuard

## Development

Go backend with an embedded React/TypeScript frontend. Commands are in [`CLAUDE.md`](CLAUDE.md), and the design is in [`docs/SPEC.md`](docs/SPEC.md).
