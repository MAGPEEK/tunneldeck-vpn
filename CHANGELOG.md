# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `settings.json` schema version 2. The host-access rules become firewall rules (SPEC §16): each one is migrated on start to an inbound rule to "This device" named like "Host port 5001/tcp", and the global firewall protections are switched on. The migrated file is written on the next settings change; older TunnelDeck-VPN versions refuse to start with it, so keep a copy of `/data` before upgrading if you may roll back.
- The firewall now has two directions and four chains: `TUNNELDECK-INPUT` and `TUNNELDECK-FORWARD` (filter), `TUNNELDECK-PREROUTING` and `TUNNELDECK-POSTROUTING` (nat), each jumped to from position 1 of its built-in chain. The firewall page follows in the next change.
- OpenVPN profile form: client certificate and client key are no longer required on their own (a PKCS#12 file can replace them; saving still requires one of the two forms). The keep-alive field shows the placeholder `10 120`.
- **Breaking (API):** `GET`/`PUT /api/host-access` are removed and answer `410 Gone` (problem code `gone`) with a pointer to `/api/firewall`.

### Added

- Firewall rules (backend): inbound rules to this device (accept, drop or reject; tcp, udp, tcp+udp, icmp with optional type, esp, gre; port ranges, source address and source port), port forwards to other LAN devices (DNAT with optional public port or shifted port range, masquerade unless the source address is kept, esp and gre forwarding), and outbound rules that route LAN devices through the tunnel (policy rules at priorities 7100–7191, masquerade on `tdvpn0`) with a kill switch that drops their traffic while the tunnel is down.
- Global firewall protections, all on by default: drop invalid packets, clamp the TCP MSS to the path MTU, limit new TCP connections from the tunnel (25/s, burst 50 per source) and pings from the tunnel (5/s, burst 10).
- Firewall API: `GET /api/firewall` returns `{rules, settings, hostAddress, lanSubnets, ipForward}` (the last three describe the host's LAN for the UI and are empty when detection fails); `PUT /api/firewall` with `{rules, settings}` validates every rule (field errors as `rules[i].<field>` and `settings.<field>`; all four settings are required), keeps the web UI port and the remote-access port closed, requires port-forward targets inside a LAN subnet, stores and applies the firewall, and restores and re-applies the previous configuration when applying fails (`500 firewall_failed`). `POST /api/firewall/templates/ipsec` with `{name, deviceAddress, peers?}` returns the "IPsec device" rules (inbound UDP 500, UDP 4500 and ESP to the device with the source address kept, outbound UDP and ESP from the device; per peer when peers are given) without storing them.
- Self-checks `ip-forward` (reads `net.ipv4.ip_forward`, never changes it) and `lan-subnets` (the host's LAN subnets, which port-forward targets must lie in).
- OpenVPN profile setting `remoteNetworks`: up to 32 IPv4 networks behind the VPN (canonical CIDR, not overlapping a LAN subnet of the host, not containing the server address). While connected the host routes them through the tunnel (`ip rule … to <net> lookup 7194`, priority 7180), removed on disconnect; pushed routes stay ignored. Outbound firewall rules can use them as destinations.
- OpenVPN PKCS#12: the secret `pkcs12` (base64 of a `.p12`/`.pfx` file) replaces client certificate and key in the certificate sign-in methods and is rendered as an inline `<pkcs12>` block; its passphrase is the key passphrase, sent over management. The `.ovpn` import maps `<pkcs12>` blocks; a `pkcs12` file reference is still rejected.
- `.ovpn` import and extra options reject static-key mode (`secret`, `<secret>`) with the warning code `static_key_unsupported`.

## [0.1.0-alpha.1] - 2026-11-25

### Added

- Project skeleton: Go backend serving `/api/system` and the embedded React app, Docker image definition, CI workflow.
- Web UI shell: setup and sign-in pages, sidebar navigation, light and dark theme, German and English.
- Web UI pages: dashboard with connection card (state, server, VPN address, connected-since, connect/disconnect/reconnect, error details, advisories), traffic metrics, host protection summary and live log with level and text filters; profile list with edit, duplicate and delete; profile form generated from the driver schema with secret handling, daily reconnect schedule and server-side validation errors; `.ovpn` import with grouped warnings; host-access rule editor; system page with version, server time, self-check hints and remote access settings. Live updates over server-sent events.
- Profile advisories: profiles and the connection status report findings such as an unencrypted data channel, weak ciphers or digests, compression, TLS below 1.2, tls-auth instead of tls-crypt, a disabled server certificate check, `fragment` and missing data-channel offload. They never block saving or connecting.
- OpenVPN profiles without their own TLS version bound are rendered with `tls-version-min 1.2`.
- HTTP API (`/api/*`): session, setup, login and logout; drivers; profile list, create, read, update, delete and `.ovpn` import; connection status and control; log tail; live events over server-sent events; host-access rules; system status with self-check, listen address, server time and time zone. Errors are RFC 9457 problem details.
- Configuration through `TUNNELDECK_LISTEN`, `TUNNELDECK_DATA_DIR`, `TUNNELDECK_SECRET_KEY`, `TUNNELDECK_LOG_LEVEL`, `TUNNELDECK_RESET_ADMIN` and `TZ`; the UI listens on the address of the default-route interface, port 8194, unless `TUNNELDECK_LISTEN` is set.
- `tunneldeck reset-admin` removes the admin account through the running server, or directly in the data directory when no server runs.
- Remote access over the tunnel (off by default): a second, HTTPS-only listener on `0.0.0.0:<port>` (default 8443, TLS 1.2 minimum) with a self-signed ECDSA P-256 certificate that is renewed 30 days before expiry, or an uploaded PEM certificate and key; the firewall opens the port on the tunnel device while it is on. Session cookies get `Secure` and responses `Strict-Transport-Security` there, and logins from non-private addresses on it are limited to 3 failures per minute. API: `GET`/`PUT /api/remote-access`, `POST /api/remote-access/certificate`; changes apply without a restart.
- Driver form schemas can show a field only while a secret field has a value (`visibleWhen: {secret: "<key>"}`).
- `tunneldeck healthcheck` probes `/api/session` on the configured listen address; the image's `HEALTHCHECK` uses it, so the container health reflects the process, not the tunnel.
- Image: OpenVPN pinned to the 2.7 series, `tzdata` for `TZ`, version and revision from git as build arguments, OCI labels (title, description, version, revision, source, licenses). `scripts/build-image.sh` builds `magpeek/tunneldeck:<version>`, `scripts/export-image.sh` writes a `docker save` archive for Synology Container Manager.
- Compose files for local use and for Synology (`deploy/synology/docker-compose.yml`, data in `/volume1/docker/tunneldeck`) with the optional environment variables as comments.
- Documentation: Synology DS723+ guide, migration guide from a Teltonika RUT240 (mdex example), release steps; each guide in English and German.
- Documentation: Linux Docker host guide (TUN device, iptables backends next to ufw, firewalld and Docker's chains, reverse proxy, remote access, backup, update, `reset-admin`) in English and German.
- End-to-end test (`test/e2e/`, build tag `e2e`) against throwaway OpenVPN servers (username/password, `cipher none`, client certificate with tls-crypt) on both iptables backends; CI job `e2e`.

### Changed

- Display name is now TunnelDeck-VPN (UI title, i18n, docs, image labels, rendered-config header, warnings, LICENSE). Repository moved to `https://github.com/MAGPEEK/tunneldeck-vpn`, image renamed to `magpeek/tunneldeck-vpn`. Technical identifiers (binary, module, `TUNNELDECK_*` variables, chains, `tdvpn0`, container name) are unchanged.
- Compose files, READMEs and install guides document how the web UI is reached: LAN address port 8194 (change with `TUNNELDECK_LISTEN`, e.g. `192.168.1.10:9000`), never through the tunnel; remote access over the VPN is HTTPS only.

### Fixed

- Profile form: "Key direction" is shown only while a TLS auth key is set, and is no longer sent without one.
- iptables backend: TunnelDeck now uses the backend that the host's firewall (ufw, firewalld, Docker) already uses instead of always preferring `iptables-legacy`; on modern hosts its chains no longer live in a second, parallel rule set where the host's nftables rules still dropped ports opened under host access. Without host rules nf_tables is preferred, old kernels keep legacy. The System page and the start log name the backend and the reason, and warn when the host mixes both. `TUNNELDECK_IPTABLES=auto|nft|legacy` overrides the detection.
- Deleting the active profile while it is in state `error` (or disconnected) no longer fails with 409: it is disconnected first, then deleted. Deletion is still refused while the tunnel is connecting, connected, reconnecting or disconnecting.
