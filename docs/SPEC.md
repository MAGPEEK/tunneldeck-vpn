# TunnelDeck — Specification

Working name: **TunnelDeck** (binary `tunneldeck`). A self-hosted VPN client gateway in a Docker container with a modern web UI. License: MIT.

## 1. Goals

- Run a VPN client on **any Linux Docker host** (amd64 and arm64: servers, mini PCs, Raspberry Pi, NAS) and manage it entirely from a web UI: profiles, connect/disconnect, status, live log. Nothing may depend on a particular distribution or vendor; vendor-specific steps live only in `docs/` guides. The oldest supported environment is the first test device, a Synology DS723+ (DSM 7.2, Linux 4.4, iptables-legacy, no DCO), so every feature must also work on an old kernel without nftables.
- Act as a gateway between the LAN and the VPN (stage 2) while never breaking the host's own connectivity.
- Support several VPN methods through one driver interface. **OpenVPN is the first and, for now, only driver.** WireGuard and IPsec/IKEv2 must be addable without touching API, store or UI pages.
- Reference use case: mdex public.IP (`publicipNN.mdex.de`, UDP 1194, username/password, `cipher none`, extra options as on a Teltonika RUT240).

## 2. Non-goals (stage 1)

- LAN forwarding, allow-list of LAN devices, kill switch, port forwards (DNAT), traffic chart → stage 2.
- IPv6 (IPv4 only), DNS handling for LAN clients, TAP devices, multiple simultaneous tunnels.
- HTTPS termination (use a reverse proxy), OIDC, multi-user.
- VPN *server* functionality.

## 3. Stack

- Backend: Go 1.27, standard library `net/http` (Go 1.22+ pattern routing), `golang.org/x/crypto` (argon2id). No web framework, no cgo.
- Frontend: React 19 + TypeScript (strict) + Vite, react-router, TanStack Query, react-i18next, lucide-react. Styling: CSS modules + CSS custom properties (design tokens). No UI component library.
- Tests: `go test`, Vitest + Testing Library.
- Lint: `golangci-lint`, ESLint + Prettier.
- Image: multi-stage build → Alpine runtime with `openvpn`, `iptables` + `iptables-legacy`, `iproute2`. Target `linux/amd64` (required) and `linux/arm64`.

## 4. Architecture

Dependency rule: `domain` imports nothing internal; everything else may import `domain`; only `cmd/tunneldeck` wires concrete types together. Packages talk through small interfaces defined by the consumer.

| Package | Responsibility |
|---|---|
| `cmd/tunneldeck` | Parse config, build dependencies, start HTTP server, graceful shutdown |
| `internal/config` | Environment variables → typed config |
| `internal/domain` | `Profile`, `ConnectionState`, `HostAccessRule`, `Event`, sentinel errors |
| `internal/vpn` | `Driver` interface, driver registry, `ConnectionManager` (desired state, one active tunnel, auto-reconnect) |
| `internal/vpn/openvpn` | Config renderer, `.ovpn` importer, process supervisor, management-interface client |
| `internal/netguard` | iptables chains (host protection) and policy routing, behind a `CommandRunner` interface |
| `internal/store` | JSON persistence with atomic writes |
| `internal/secret` | AES-256-GCM encryption of secret fields, key file handling |
| `internal/auth` | Admin account, argon2id, sessions, login rate limit |
| `internal/api` | REST handlers, SSE stream, middleware (auth, CSRF, JSON errors) |
| `internal/web` | `go:embed` of `web/dist`, SPA fallback |
| `web/` | React app |

### 4.1 Driver interface

```go
type Driver interface {
    Protocol() domain.Protocol                 // "openvpn"
    Describe() FormSchema                      // fields for the profile form
    Validate(p domain.Profile) error
    Start(ctx context.Context, p domain.Profile, s Secrets) error
    Stop(ctx context.Context) error
    Events() <-chan domain.Event               // state, traffic, log
}
```

`FormSchema` is a list of sections and fields (`key`, `type`: text | number | select | secret | textarea | stringList | bool, `required`, `options`, i18n label key, `visibleWhen`). The frontend renders the profile form from it; a new driver needs no new page.

`ConnectionManager` owns the single active driver instance, persists the desired state (`activeProfileId`, `wantConnected`) and reconnects after a container restart. It calls `netguard` before starting and after stopping a tunnel.

### 4.2 Connection states

`disconnected → connecting → connected → (reconnecting ↔ connected) → disconnecting → disconnected`, plus `error` (with message; user action or auto-retry leaves it). Auto-retry uses exponential backoff 2 s … 60 s and never gives up on network errors. An authentication failure (credentials rejected by the server) stops retrying immediately and enters `error` until the user reconnects or edits the profile, so the account is not locked by the provider.

### 4.3 Scheduled daily reconnect

Every profile (driver-independent, part of `domain.Profile`) has `dailyReconnect { enabled bool, time "HH:MM" }`, default off, default time `04:00`. While that profile is connected, `ConnectionManager` disconnects and immediately reconnects once per day at that local time (container time zone from `TZ`, image ships `tzdata`). It is skipped when the tunnel is not connected at that moment, never fires twice for the same day, and is rescheduled when the profile or the time changes. The clock is injected for tests. The log gets a line naming the reason ("scheduled daily reconnect"). The profile form shows a switch "Reconnect once a day" with a time field in a "Schedule" section; the System page shows the server's current time and time zone.

## 5. OpenVPN driver

- OpenVPN runs as a child process with a rendered config file under `/run/tunneldeck/` (tmpfs, mode 0600), removed on stop.
- Control via the management interface on a unix socket: state changes, byte counts, log lines, and credentials (`management-query-passwords`), so passwords never land in a file. Exact directives are fixed in `docs/openvpn-notes.md` (task 2).
- Fixed tunnel device name `tdvpn0`, `dev-type tun`.
- `docs/openvpn-notes.md` is binding for this driver (OpenVPN 2.7.x from Alpine): the always-emitted directives, the `cipher` → `data-ciphers` mapping (`none` → `data-ciphers none:CHACHA20-POLY1305` + `data-ciphers-fallback none`), compression rules, importer drops and the management dialogue. Decisions on its open points: OpenVPN configures the interface itself (no `ifconfig-noexec`); pushed IPv6 is ignored; `remote-cert-tls server` is emitted unless the profile setting `verifyServerCertUsage` is switched off (default on); client key and tls-auth/tls-crypt key are written inline into the rendered config in the tmpfs runtime directory (0700 dir, 0600 file, deleted on stop) because OpenVPN offers no other channel — passwords and key passphrases go over management only.
- Routes: OpenVPN must not touch the main routing table (`route-noexec`; pushed and configured `redirect-gateway` is neutralised). See 6.
- Profile fields (OpenVPN settings): `remoteHost`, `port`, `proto` (udp|tcp), `compression` (none|lzo), `authMode` (password | certificate | certificate+password), `username`, `password`*, `caCert`, `clientCert`, `clientKey`*, `tlsAuthKey`* / `tlsCryptKey`* + `keyDirection`, `cipher` (free text incl. `none`), `authDigest`, `resolveRetry`, `keepalive`, `extraOptions` (list of raw lines). `*` = secret.
- **Current-practice defaults and advisories.** New profiles default to what OpenVPN 2.7 considers current: AEAD data ciphers negotiated (`cipher` empty → OpenVPN default `AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305`), `authDigest` empty (irrelevant for AEAD), no compression, `tls-version-min 1.2` rendered when the profile sets nothing (TLS 1.3 is used when the server offers it), `tls-crypt` preferred over `tls-auth`. Legacy settings stay possible because the server dictates them, but `Advisories(profile)` returns stable-coded findings that the form and the dashboard show: `unencrypted_data_channel` (cipher `none`, severity danger), `weak_cipher` (BF-CBC, DES, 3DES, RC2, CAST5, any CBC without AEAD → warning), `weak_digest` (MD5, SHA1, `none` with a non-AEAD cipher), `compression_enabled` (deprecated, VORACLE), `tls_below_1_2`, `tls_auth_instead_of_crypt` (info), `server_usage_check_disabled`, `fragment_in_use` (info: legacy MTU workaround), `no_dco` (info: kernel 4.4 has no data-channel offload, expect lower throughput). Advisories never block saving or connecting.
- `caCert` is required for every `authMode`, including `password` (the server must always be verified; mdex issues a CA certificate).
- `extraOptions` are validated: one directive per line, and a denylist rejects anything that runs code or fights the app: `up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`, `auth-user-pass-verify`, `client-connect`, `client-disconnect`, `learn-address`, `plugin`, `script-security`, `management*`, `daemon`, `log`, `log-append`, `status`, `writepid`, `config`, `cd`, `chroot`, `dev`, `dev-type`, `dev-node`, `iproute`, `route-noexec`, `auth-user-pass`. `redirect-gateway` is accepted but dropped with a visible warning ("handled by TunnelDeck").
- `.ovpn` import maps known directives to fields, inline blocks (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`) to cert/secret fields, everything else to `extraOptions` (subject to the denylist; rejected lines are reported, not silently dropped).

## 6. Networking (stage 1)

Container runs with `network_mode: host`, `cap_add: NET_ADMIN`, device `/dev/net/tun`.

- **Routing:** routing table `7194`. On connect: `ip route replace default dev tdvpn0 table 7194`, `ip rule add from <vpn-ip> lookup 7194 priority 7194`. On disconnect both are removed. TunnelDeck and OpenVPN never add routes to the main table (`route-noexec`, `route-nopull`), so the host keeps its default route; the only entry that appears there is the kernel's own connected route for the tunnel subnet. Routing is re-applied on every `CONNECTED` state because the VPN IP can change. Effect: replies to connections arriving at the VPN IP leave through the tunnel.
- **Host protection:** chain `TUNNELDECK-INPUT`, jumped to from `INPUT` (position 1) for `-i tdvpn0`: accept `ESTABLISHED,RELATED`; accept each enabled `HostAccessRule` (proto tcp|udp, port, optional source CIDR); drop the rest. Chain `TUNNELDECK-FORWARD` from `FORWARD` (position 1): drop everything in or out of `tdvpn0` (stage 1 forwards nothing).
- Rules are installed at application start (before any tunnel) and re-applied idempotently whenever host-access rules change; removed on graceful shutdown.
- The UI port can never be opened through a host-access rule (validation error).
- iptables backend: detect at start whether `iptables-legacy` or `iptables` (nft) works on the host kernel and use that binary for the process lifetime.
- Startup self-check reports: `/dev/net/tun` present, `NET_ADMIN` effective, iptables usable. Failures are shown in the UI (System status), not just logged.

## 7. Persistence and secrets

Data directory `/data` (volume):

- `settings.json` — admin account (argon2id hash), language default, host-access rules, desired connection state.
- `profiles.json` — profiles; secret fields stored as `enc:v1:<base64 nonce+ciphertext>`.
- `secret.key` — 32 random bytes, mode 0600, created on first start. Overridden by env `TUNNELDECK_SECRET_KEY` (base64).

Writes are atomic (temp file + rename) and serialised by a mutex. The API never returns secret values; it returns `hasValue: true|false` per secret field. Sending an empty secret on update keeps the stored value.

## 8. Auth

- First start: no admin exists → UI shows setup (username, password ≥ 12 chars). `POST /api/setup` works only while no admin exists.
- Login → random 256-bit session token in an `HttpOnly`, `SameSite=Strict` cookie; sessions kept in memory (hashed), 12 h idle timeout.
- All `/api/*` except `setup`, `login`, `session` require a session. Mutating requests also require header `X-TunnelDeck-Request: 1` and a matching `Origin`/`Host` (CSRF).
- Lost password: `tunneldeck reset-admin` (run via `docker exec`) removes the admin account and all sessions; alternatively env `TUNNELDECK_RESET_ADMIN=1` does the same at start and logs a warning on every start until it is removed. Profiles and settings are kept; the UI shows setup again.
- Login rate limit: 5 failures per IP per minute, then lockout with backoff. Constant-time comparison.

### 8.1 Remote access to the UI over the tunnel (HTTPS only)

Off by default. Setting `remoteAccess { enabled bool, port int (default 8443), certificateSource "selfSigned" | "uploaded" }` in `settings.json`.

- When enabled, a second listener serves the same app over **HTTPS only** on `0.0.0.0:<port>` (so it is reachable on the VPN address and, as a bonus, on the LAN). TLS 1.2 minimum, TLS 1.3 preferred, Go's default cipher suites. The plain-HTTP listener stays LAN-only and is never reachable from the tunnel.
- Certificate: `selfSigned` — ECDSA P-256 certificate generated on first enable, valid 2 years, renewed automatically 30 days before expiry, stored in `/data` with the key encrypted like other secrets; its SHA-256 fingerprint is shown in the UI so the user can verify the browser warning. `uploaded` — PEM certificate chain and key (RFC 7468) validated on upload (key matches, not expired); the key is a secret.
- `netguard` adds an accept for TCP `<port>` on the tunnel device while enabled. This is the only way the UI becomes reachable from the tunnel; a host-access rule for the HTTP port stays forbidden.
- On the HTTPS listener: session cookie with `Secure`, `Strict-Transport-Security: max-age=31536000`, same CSRF and rate-limit rules. Login attempts from tunnel addresses use a stricter limit (3 failures per minute).
- Changing the setting applies without a container restart. The port must not collide with the HTTP port or an enabled host-access rule.
- API: `GET/PUT /api/remote-access` (state, port, source, certificate subject, expiry, fingerprint; never the key), `POST /api/remote-access/certificate` (upload). UI: section "Remote access" on the System page with a clear warning that the login becomes reachable from the internet.

## 9. HTTP API

JSON; errors as RFC 9457 problem details (`Content-Type: application/problem+json`): `{ "type": "about:blank", "title": "...", "status": 400, "detail": "...", "code": "validation_failed", "fields": { "name": "..." } }` — `code` (stable machine-readable string) and `fields` are extension members. 429 responses carry `Retry-After` (seconds).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/session` | `{ setupRequired, authenticated, username }` |
| POST | `/api/setup`, `/api/login`, `/api/logout` | Account and session |
| GET | `/api/drivers` | Protocols with their `FormSchema` |
| GET/POST | `/api/profiles` | List / create |
| GET/PUT/DELETE | `/api/profiles/{id}` | Read / update / delete (delete refused while active and connected) |
| POST | `/api/profiles/import` | Parse `.ovpn` text → draft profile + warnings (not saved). The draft echoes the secrets contained in the uploaded text back to the same client so the form can submit them with the create request — the only response that carries secret values, and never from storage |
| GET | `/api/connection` | State, active profile, VPN IP, remote, since, bytes in/out, rates |
| POST | `/api/connection/connect` `{profileId}`, `/disconnect`, `/reconnect` | Control |
| GET | `/api/logs?tail=N` | Last N lines of the in-memory ring buffer (2000 lines) |
| GET | `/api/events` | SSE: `state`, `traffic` (every 2 s), `log` |
| GET/PUT | `/api/host-access` | Host-access rules |
| GET | `/api/system` | Version, self-check results, UI listen address |

## 10. Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELDECK_LISTEN` | address of the interface holding the default route, port `8194` | UI listen address; never the tunnel device |
| `TUNNELDECK_DATA_DIR` | `/data` | Data directory |
| `TUNNELDECK_SECRET_KEY` | – | Base64 key instead of `secret.key` |
| `TUNNELDECK_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `TUNNELDECK_RESET_ADMIN` | – | `1` removes the admin account at start (see §8) |
| `TZ` | `UTC` | Time zone for the daily reconnect and log timestamps |

Backup in stage 1 = copying `/data` including `secret.key`; an export/import UI is not part of stage 1.

## 11. UI design

Tone: calm, technical, uncluttered. Sentence case, no exclamation marks, verbs on buttons. German and English from day one (browser language default, switch in the user menu). Light and dark theme from `prefers-color-scheme` with a manual toggle.

**Tokens** (CSS custom properties in `web/src/styles/tokens.css`): neutral gray scale for surfaces/text, one accent (blue) for links, focus and primary action, semantic green/amber/red for connection state only. Radius 8 px (controls) / 12 px (cards). Spacing scale 4/8/12/16/24/32. Font: system UI stack; monospace for IPs and log. Two weights (400/500). One primary button per view.

**Layout:** fixed left sidebar (240 px; collapses to a top bar below 800 px) with product name, nav — Dashboard, Profiles, Host access, System — and at the bottom language, theme and sign-out. Content column max 960 px.

**Dashboard**
- Connection card: state pill (gray disconnected, amber connecting/reconnecting, green connected, red error), profile name, protocol badge, remote host:port, VPN IP, connected-since duration. Actions: `Connect` (primary when disconnected) / `Disconnect` + `Reconnect`. A profile select sits next to `Connect` when more than one profile exists. Error state shows the last error line and `Try again`.
- Metric row: received, sent (totals), download rate, upload rate.
- Host protection card: "NAS shielded from tunnel", count of open ports, link to Host access.
- Live log card: monospace, auto-scroll with pause-on-scroll, level filter, text filter, `Copy`.
- Empty state (no profile): headline "Add your first VPN profile", one line of body, button `Create profile`.

**Profiles:** list rows (name, protocol, remote, active marker) with `Edit`, `Duplicate`, `Delete`. `New profile` → choose protocol (only OpenVPN enabled; WireGuard and IPsec shown as "planned", disabled) → form generated from `FormSchema`, sections: Server, Authentication, Encryption, Advanced (extra options as an add/remove list like on the RUT240). `Import .ovpn` fills the form and lists warnings. Secret fields show "Stored" with `Replace`.

**Host access:** explanation line, table of rules (protocol, port, source, enabled) with add/remove, `Save changes`.

**System:** version, self-check list with pass/fail and fix hints, listen address.

**Setup / Login:** centered card, product name, fields, one button.

## 12. Definition of done (stage 1)

- `docker compose up` on a Linux host with `/dev/net/tun`: setup → create OpenVPN profile → connect → dashboard shows connected, VPN IP, byte counters and live log.
- Host's default route unchanged while connected; replies to tunnel-originated connections leave via the tunnel.
- From the VPN side only explicitly allowed host ports answer.
- Container restart reconnects the previously connected profile without user action.
- `go test ./...`, `golangci-lint run`, `npm run lint`, `npm test`, `npm run build` all pass.
- README (de/en) with Synology DS723+ instructions.
- Docker `HEALTHCHECK` reflects process health (UI reachable), not tunnel state.

## 13. Versioning, review and testing

**Versioning**
- Semantic Versioning 2.0.0. Stage 1 ships as `0.1.0`; stage 2 as `0.2.0`; WireGuard as `0.3.0`; `1.0.0` once the data format and API are declared stable. While `0.y.z`, breaking changes bump the minor version and are called out in the changelog.
- The single source of truth is the git tag `vX.Y.Z`. The binary gets its version through `-ldflags -X` from `git describe --tags --always --dirty` (untagged builds look like `0.1.0-dev+<sha>`); `GET /api/system` and the System page show it. The frontend `package.json` version mirrors the release version.
- Docker image tags: `X.Y.Z`, `X.Y` and `latest` for releases only; OCI labels `org.opencontainers.image.version`, `.revision`, `.source`, `.licenses`.
- `settings.json` and `profiles.json` carry `schemaVersion` (integer). On start the store migrates older versions step by step and refuses to start on a newer one with a clear message.
- Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:`, `ci:`, `chore:`; `!` for breaking). `CHANGELOG.md` follows Keep a Changelog with an `Unreleased` section updated in the same commit as the change.

**Review**
- Every task is reviewed by the orchestrator against its brief and this spec before it is committed: read the diff, check scope, edge cases, error paths and security rules (§5 denylist, §7 secrets, §8 auth), re-run the checks. Defects go back to the worker; nothing unreviewed is committed.
- Before a release: a full code review and a security review of the whole diff since the last tag.

**Testing**
- Unit tests next to the code for every package; table-driven; fakes instead of real processes, sockets, clocks and `iptables`. Race detector in CI (`go test -race ./...`).
- Target line coverage ≥ 80 % for `domain`, `store`, `secret`, `auth`, `vpn`, `vpn/openvpn`, `netguard`, `api`; coverage is reported in CI.
- Frontend: component tests for shared components, the schema form renderer, connection card states and the log filter.
- Integration: `netguard` against real `iptables`/`ip` in a privileged Linux container (build tag `integration`).
- End-to-end: compose stack with a throwaway OpenVPN server (task 12).
- Field test on the DS723+ with the real mdex profile is the release gate for `0.1.0`.

## 14. Standards

Where an RFC covers something, follow it instead of inventing a format:

| Area | Standard |
|---|---|
| HTTP semantics, methods, status codes, `Retry-After` | RFC 9110; 429 per RFC 6585 |
| HTTP caching headers | RFC 9111 |
| API errors | RFC 9457 (problem details) |
| JSON | RFC 8259 |
| Timestamps in API and files | RFC 3339, UTC |
| Cookies (`HttpOnly`, `SameSite`, `Secure` when behind HTTPS) | RFC 6265 / 6265bis |
| Origin check for CSRF | RFC 6454 |
| Password hashing | Argon2id, RFC 9106 parameters |
| Secret encryption | AES-GCM as AEAD, RFC 5116 |
| Certificates and keys in profiles | PEM, RFC 7468; X.509, RFC 5280 |
| IPv4 CIDR notation, private ranges | RFC 4632, RFC 1918 |
| Language tags (`de`, `en`) | RFC 5646 |
| TLS minimum for VPN control channels | TLS 1.2+ (RFC 5246 / 8446) |
| Later: IKEv2 | RFC 7296 |

Not RFCs but binding here: Server-Sent Events (WHATWG HTML), Semantic Versioning, Conventional Commits. OpenVPN and WireGuard have no RFC; their official documentation is the reference.

## 15. Roadmap and release

1. Stage 1 (this spec). Public from the start (owner's decision, 2026-11-25): code at `github.com/MAGPEEK/tunneldeck`, image at `magpeek/tunneldeck` on Docker Hub. Development builds are tagged `0.1.0-dev`; `latest` and plain version tags only for releases. Field test on the DS723+ pulls the image from Docker Hub (or imports a `docker save` export).
2. After a successful field test: tag `v0.1.0` and publish the release image.
3. Stage 2: gateway functions (LAN allow-list, kill switch, port forwards, traffic chart). Port forwards include a freely chosen external port mapped to a host service (e.g. tunnel port 4444 → DSM 5001), as the RUT240 offered for its own web UI.
4. WireGuard driver (userspace `wireguard-go`, because the DS723+ kernel has no WireGuard module), then IPsec/IKEv2.
5. Notifications (webhook) — not before stage 2.
