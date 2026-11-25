# TunnelDeck

**A self-hosted VPN client with a web UI, packaged as one Docker container.** Built for NAS devices such as a Synology DS723+, and usable on any Linux Docker host.

[Deutsch](README.de.md) · License: MIT · Status: **work in progress (0.1.0-dev)**, not yet released

## What it does

- **Manage VPN profiles in the browser**: create them in a form or import an `.ovpn` file. Several profiles can be stored; one is active at a time.
- **Dashboard**: connection state, VPN address, traffic, and a live log.
- **Stays connected**: reconnects automatically after network errors, stops immediately when credentials are rejected, and reconnects after a container restart.
- **Optional daily reconnect** at a time you choose, per profile.
- **Protects the host**: everything arriving through the tunnel is blocked except the ports you allow. The host keeps its own default route.
- **Flags outdated settings**: an unencrypted data channel, weak ciphers, compression and similar settings are shown as advisories.
- **Secure by default**: sign-in required, credentials encrypted at rest, web UI on the LAN only. Optional remote access over HTTPS.
- **German and English** UI, light and dark theme.

## Supported VPN methods

| Method | Status |
|---|---|
| OpenVPN (2.7) | in development |
| WireGuard | planned |
| IPsec / IKEv2 | planned |

## Quick start

```yaml
services:
  tunneldeck:
    image: magpeek/tunneldeck:0.1.0-dev
    container_name: tunneldeck
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes: ["./data:/data"]
    environment: { TZ: Europe/Berlin }
    restart: unless-stopped
```

Open `http://<host-ip>:8194` and create the admin account. If you forget the password, run `docker exec tunneldeck tunneldeck reset-admin`.

## Roadmap

- **0.1.0**: OpenVPN client, dashboard, host protection, daily reconnect, HTTPS remote access
- **0.2.0**: LAN gateway with device allow-list, kill switch, port forwarding, traffic chart
- **0.3.0**: WireGuard

## Development

Go backend with an embedded React/TypeScript frontend. Commands are in [`CLAUDE.md`](CLAUDE.md), and the design is in [`docs/SPEC.md`](docs/SPEC.md).
