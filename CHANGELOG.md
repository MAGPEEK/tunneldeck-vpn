# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
