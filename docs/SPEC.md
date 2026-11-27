# TunnelDeck-VPN — Specification

Working name: **TunnelDeck-VPN** (binary `tunneldeck`). A self-hosted VPN client gateway in a Docker container with a modern web UI. License: MIT.

## 1. Goals

**End result (owner, 2026-11-26):** a user sets up and establishes a VPN connection in the web UI and controls the traffic between the VPN and the internal LAN with a firewall (both directions, to the host and to any LAN device). Every task is judged against this.

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
- `extraOptions` are validated: one directive per line, and a denylist rejects anything that runs code or fights the app: `up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`, `auth-user-pass-verify`, `client-connect`, `client-disconnect`, `learn-address`, `plugin`, `script-security`, `management*`, `daemon`, `log`, `log-append`, `status`, `writepid`, `config`, `cd`, `chroot`, `dev`, `dev-type`, `dev-node`, `iproute`, `route-noexec`, `auth-user-pass`. `redirect-gateway` is accepted but dropped with a visible warning ("handled by TunnelDeck-VPN").
- `.ovpn` import maps known directives to fields, inline blocks (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`) to cert/secret fields, everything else to `extraOptions` (subject to the denylist; rejected lines are reported, not silently dropped).

## 6. Networking (stage 1)

Container runs with `network_mode: host`, `cap_add: NET_ADMIN`, device `/dev/net/tun`.

- **Routing:** routing table `7194`. On connect: `ip route replace default dev tdvpn0 table 7194`, `ip rule add from <vpn-ip> lookup 7194 priority 7194`. On disconnect both are removed. TunnelDeck-VPN and OpenVPN never add routes to the main table (`route-noexec`; pushed routes, gateway redirects, DNS options, `route-delay` and `ifconfig-ipv6` are dropped with `pull-filter ignore`), so the host keeps its default route; the only entry that appears there is the kernel's own connected route for the tunnel subnet (with a point-to-point address, the host route to the peer). Routing is re-applied on every `CONNECTED` state because the VPN IP can change; when applying it fails, the tunnel stays up, the status carries `routingWarning` (code `routing_failed`) and the routing is retried with the backoff of §4.2. Effect: replies to connections arriving at the VPN IP leave through the tunnel.
- **Host protection:** chain `TUNNELDECK-INPUT`, jumped to from `INPUT` (position 1) for `-i tdvpn0`: accept `ESTABLISHED,RELATED`; accept each enabled `HostAccessRule` (proto tcp|udp, port, optional source CIDR); drop the rest. Chain `TUNNELDECK-FORWARD` from `FORWARD` (position 1): drop everything in or out of `tdvpn0` (stage 1 forwards nothing).
- Rules are installed at application start (before any tunnel) and re-applied idempotently whenever host-access rules change; removed on graceful shutdown.
- The UI port can never be opened through a host-access rule (validation error).
- iptables backend: share the host firewall's backend. At start, count the host rules (filter and nat tables, without TunnelDeck-VPN's own chains and `ACCEPT` policies) that `iptables-nft` and `iptables-legacy` (or plain `iptables`, per `iptables -V`) list; use the backend that holds rules, the one with more if both do (with a warning), nf_tables if neither does, and the only working one on old kernels. The binary is kept for the process lifetime; the self-check and the start log name it and the reason. `TUNNELDECK_IPTABLES` can force one.
- Startup self-check reports: `/dev/net/tun` present, `NET_ADMIN` effective, iptables usable. Failures are shown in the UI (System status), not just logged.

### 6.1 Public IP detection

Setting `publicIpLookup { enabled bool (default true), url string (default "https://api.ipify.org") }` in `settings.json` (schema 5; the migration from 4 adds the defaults). `url` must be an absolute `http` or `https` URL with a host and without user name or password (field codes `required`, `too_long` (2048), `public_ip_url_invalid`, `url_credentials_not_allowed`).

- While enabled, the connection manager asks the service once whenever the tunnel reaches `connected` with its routing applied (after every connect and reconnect, after a routing retry that succeeds, and at once when the setting is saved while connected): one `GET` with `User-Agent: TunnelDeck-VPN`, from a TCP socket bound to the VPN IP over IPv4, without proxy. The policy rule `from <vpn-ip> lookup 7194` routes such host-originated traffic through `tdvpn0`, so the answer is the address the internet sees for the tunnel, not the host's own. Name resolution uses the host resolver as usual.
- Each attempt is bounded by 10 s, at most three attempts with 2 s and 5 s pauses; leaving `connected` cancels it. Redirects are not followed (a redirect could point at another host, plain HTTP or a host or LAN address). Only a `200` answer of at most 64 bytes that is, trimmed, an IPv4 address is accepted. The service name is resolved with the host's resolver, not through the tunnel.
- A tunnel that carries no internet traffic is not asked: the driver says so with the connected state (`domain.StateEvent.NoInternet`, never in the API). IPsec reports it when no negotiated remote traffic selector covers `0.0.0.0/0`, e.g. a FRITZ!Box user access that offers only its LAN (§19.2); OpenVPN and WireGuard never do. Instead of a lookup the tunnel log gets one `info` line saying why, there is no warning, and `publicIp` stays unknown. A tunnel without a VPN IP (net-to-net) is not asked either.
- The result is logged to the tunnel log (`info` with the address, `warn` on failure; errors name the service's host only) and exposed as `publicIp` of the status; it is cleared when the tunnel leaves `connected` (also while reconnecting, because the next server may have another address), when the routing fails, on a failed detection and when the detection is switched off.
- Precedence in the UI: the profile's public address (`publicAddress`) always wins, then the detected `publicIp`, then (for the remote-access URL only) the VPN IP. UI: Dashboard "Connection details" ("Public IP") and connection line, System page remote-access URL (with the note "detected"), and the System page card "Public IP detection".

## 7. Persistence and secrets

Data directory `/data` (volume):

- `settings.json` — admin account (argon2id hash), language default, host-access rules, desired connection state, remembered sessions (token hashes only, §8), remote access (§8.1), public IP detection (§6.1).
- `profiles.json` — profiles; secret fields stored as `enc:v1:<base64 nonce+ciphertext>`.
- `audit-log.json` — audit log of sign-ins and security events (§8.2); no secrets.
- `secret.key` — 32 random bytes, mode 0600, created on first start. Overridden by env `TUNNELDECK_SECRET_KEY` (base64).

Writes are atomic (temp file + rename) and serialised by a mutex. The API never returns secret values; it returns `hasValue: true|false` per secret field. Sending an empty secret on update keeps the stored value.

## 8. Auth

- First start: no admin exists → UI shows setup (username, password ≥ 12 chars). `POST /api/setup` works only while no admin exists.
- Login → random 256-bit session token in an `HttpOnly`, `SameSite=Strict` cookie; sessions kept in memory (hashed), 12 h idle timeout.
- All `/api/*` except `setup`, `login`, `session` require a session. Mutating requests also require header `X-TunnelDeck-Request: 1` and a matching `Origin`/`Host` (CSRF).
- "Stay signed in" (`POST /api/login {username, password, remember?}`), offered only on the LAN HTTP listener (`GET /api/session` → `rememberAvailable`); the HTTPS listener (§8.1) hides it and ignores the flag. A remembered session has a 30-day idle timeout and a 90-day absolute lifetime, and its cookie gets `Max-Age` (90 days; still `HttpOnly`, `SameSite=Strict`, `Path=/`). Remembered sessions survive a restart: `settings.json` (`rememberedSessions`, schema 4, max 10, oldest dropped) keeps only the SHA-256 token hash, username, created/last-used time (RFC 3339 UTC, last-used written at most once per hour) and the client IP at login — never the token. Logout removes the session from the store too; `DELETE /api/sessions` ("Sign out everywhere" on the System page) ends every session; `reset-admin` and a new admin account drop all remembered sessions.
- Lost password: `tunneldeck reset-admin` (run via `docker exec`) removes the admin account and all sessions; alternatively env `TUNNELDECK_RESET_ADMIN=1` does the same at start and logs a warning on every start until it is removed. Profiles and settings are kept; the UI shows setup again.
- Login rate limit (owner-approved 2026-11-27), per client IP (peer address only, never forwarding headers) on both listeners, one record per IP shared by them: after failure n the client must wait 10 s × 2^(n−1), capped at 15 min (10 s, 20 s, 40 s, … 640 s, then 900 s). The failed login already answers `401 invalid_credentials` with `Retry-After` and the extension member `retryAfterSeconds` (the wait it started), so the UI counts down at once. Attempts during the wait get `429 rate_limited` (RFC 6585) with `Retry-After` and `retryAfterSeconds`, without checking the password and without extending the wait or counting a failure. An attempt counts from its start: while one attempt of an IP is being checked, further attempts of that IP get 429 with the wait that follows if it fails. A successful login clears the record; a record is forgotten 30 min after its last failure; at most 10,000 IPs are tracked (least recently seen evicted). Each failure logs a warning with IP, failure count and wait (app log; never the username or password). The login page shows a live countdown and disables "Sign in" until it ends; a hidden polite live region announces only the start and the end. Constant-time comparison.
- Security headers (owner-approved 2026-11-27, 0.4.3) on every response of both listeners — API, SPA and error responses — set by one middleware around the shared router: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`; every `/api/*` response carries `Cache-Control: no-store`. The SPA must therefore have no inline scripts, `<style>` elements, style attributes in markup or inline event handlers (React `style` props go through the CSSOM, which `style-src` does not restrict); a Go test checks the built `index.html`.

### 8.1 Remote access to the UI over the tunnel (HTTPS only)

Off by default. Setting `remoteAccess { enabled bool, port int (default 8443), certificateSource "selfSigned" | "uploaded" }` in `settings.json`.

- When enabled, a second listener serves the same app over **HTTPS only** on `0.0.0.0:<port>` (so it is reachable on the VPN address and, as a bonus, on the LAN). TLS 1.2 minimum, TLS 1.3 preferred, Go's default cipher suites. The plain-HTTP listener stays LAN-only and is never reachable from the tunnel.
- Certificate: `selfSigned` — ECDSA P-256 certificate generated on first enable, valid 2 years, renewed automatically 30 days before expiry, stored in `/data` with the key encrypted like other secrets; its SHA-256 fingerprint is shown in the UI so the user can verify the browser warning. `uploaded` — PEM certificate chain and key (RFC 7468) validated on upload (key matches, not expired); the key is a secret.
- `netguard` adds an accept for TCP `<port>` on the tunnel device while enabled. This is the only way the UI becomes reachable from the tunnel; a host-access rule for the HTTP port stays forbidden.
- On the HTTPS listener: session cookie with `Secure`, `Strict-Transport-Security: max-age=31536000` in addition to the security headers of §8, same CSRF rules and the per-IP login rate limit of §8. Additionally, across all client IPs: 10 failed logins on the HTTPS listener within 10 min lock it for every client for 1 min, doubling on each further lock up to 15 min; the doubling resets 30 min after the last failure there. Every login on the HTTPS listener counts, whatever the client address; attempts in progress count towards the 10, so parallel attempts cannot exceed it. During the lock every login there gets `429 rate_limited_remote` with `Retry-After` (the longer of the lock and the client's own wait), and the UI says that remote sign-in is temporarily blocked for everyone. The lock start is logged as a warning; start and end are audited (§8.2). The LAN HTTP listener is never affected by this lock.
- Changing the setting applies without a container restart. The port must not collide with the HTTP port or an enabled host-access rule.
- API: `GET/PUT /api/remote-access` (state, port, source, certificate subject, expiry, fingerprint; never the key), `POST /api/remote-access/certificate` (upload). UI: section "Remote access" on the System page with a clear warning that the login becomes reachable from the internet.

### 8.2 Audit log (owner-approved 2026-11-27, 0.4.3)

Records sign-ins and security events so the user can tell an attack from normal use. Each entry: RFC 3339 UTC time, type, severity (derived from the type), client IP (peer address, as the rate limit uses), access `lan` | `remote` (the listener), count, and the username for sign-ins and sign-outs only. Never attempted usernames, passwords, request bodies or secrets.

| Type | Severity | Recorded when |
|---|---|---|
| `signedIn` | info | Login succeeded |
| `wrongCredentials` | notice | Login with wrong username or password |
| `signedOut`, `signedOutEverywhere` | info | `POST /api/logout`, `DELETE /api/sessions` |
| `rateLimited` | warning | Login rejected during the client's cooldown (429) |
| `remoteLocked` | warning | Login rejected during the remote lock (429 `rate_limited_remote`) |
| `remoteLockStarted`, `remoteLockEnded` | warning, info | The remote lock (§8.1) starts (IP of the failure that started it) and ends (no IP) |
| `csrfRejected` | warning | 403 from the CSRF check: missing or wrong `X-TunnelDeck-Request`, or foreign `Origin` |
| `bodyTooLarge`, `invalidBody` | warning, notice | 400 for a JSON body over 1 MiB, or not one valid JSON value of the expected shape |
| `possibleScan` | warning | ≥ 10 requests for unknown `/api/*` paths (404 of the fallback route) from one IP within 1 min; reported once with count 10, then counted per request |

Types marked as repeated (`rateLimited`, `remoteLocked`, `csrfRejected`, `bodyTooLarge`, `invalidBody`, `possibleScan`) are merged: an event of the same type, IP and access within 10 min of the entry's last occurrence increments its `count`, sets `time` to the latest and `firstTime` to the first occurrence, and moves the entry to the newest position (new ID). Storage: `/data/audit-log.json` (own file, `schemaVersion` 1, atomic writes, not in `settings.json` because attackers control its write rate), written at most 2 s after an entry and at shutdown. Two classes with their own cap of 500 entries each — sign-ins/sign-outs/wrong credentials, and security events — so a burst of attack events from many addresses never pushes the sign-in history out; the oldest entry of the full class is dropped. App log: sign-ins and sign-outs at info, wrong credentials at warning, security events at debug (the rate limit already warns when a cooldown or lock starts), always with client IP and access, never the username.

API: `GET /api/audit?limit=1..500 (default 50)&before=<id>&filter=failures|security` → `{ entries: [{ id, time, firstTime?, type, severity, clientIp, access, username?, count }], hasMore, recentWarnings, newRemoteSignIn? }`, newest first; `before` pages to entries with a smaller ID. `failures` = `wrongCredentials`, `rateLimited`, `remoteLocked`; `security` = every type except sign-ins, sign-outs and wrong credentials. `recentWarnings` sums the counts of warning-level entries of the last 24 h (any filter). `newRemoteSignIn` is the latest `signedIn` when its access is `remote` and no earlier `signedIn` in the log has the same IP.

UI: System page card "Sign-ins" / "Anmeldungen": table time (server time zone, like the other times), event (pill coloured by severity, green for sign-in, "(N×)" for counts), IP, access (LAN / Remote); radio filter all / only failed sign-ins / only security events; "Show older entries" loads the next page; a red banner "N blocked attempts in the last 24 hours" when `recentWarnings` > 0; a yellow notice for `newRemoteSignIn`. Help section `sign-ins`.

## 9. HTTP API

JSON; errors as RFC 9457 problem details (`Content-Type: application/problem+json`): `{ "type": "about:blank", "title": "...", "status": 400, "detail": "...", "code": "validation_failed", "fields": { "name": "..." } }` — `code` (stable machine-readable string) and `fields` are extension members. Validation problems also carry `fieldCodes`, an extension member with a stable code and optional string params per field, e.g. `{ "rules[0].destinationPort": { "code": "port_range_too_long", "params": { "max": "1000" } } }`; the UI translates known codes (`fieldError.<code>`) and shows the English `fields` message for any other field. 429 responses carry `Retry-After` (seconds).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/session` | `{ setupRequired, authenticated, username, rememberAvailable }` |
| POST | `/api/setup`, `/api/login`, `/api/logout` | Account and session |
| DELETE | `/api/sessions` | Sign out everywhere: ends every session, remembered ones included |
| GET | `/api/drivers` | Protocols with their `FormSchema` |
| GET/POST | `/api/profiles` | List / create |
| GET/PUT/DELETE | `/api/profiles/{id}` | Read / update / delete (delete is always possible: an active profile in any state other than `disconnected` is disconnected first and deleted once the manager reports `disconnected`; if the tunnel does not stop within 15 s the profile is kept and `503 unavailable` is returned) |
| POST | `/api/profiles/import` | Parse `.ovpn` text → draft profile + warnings (not saved). The draft echoes the secrets contained in the uploaded text back to the same client so the form can submit them with the create request — the only response that carries secret values, and never from storage |
| GET | `/api/connection` | State, active profile, VPN IP, remote, since, bytes in/out, rates, `dataCipher`, `controlChannel`, `routingWarning`, `publicIp` (§6.1, omitted when unknown) |
| POST | `/api/connection/connect` `{profileId}`, `/disconnect`, `/reconnect` | Control |
| GET | `/api/logs?tail=N` | Last N lines of the in-memory ring buffer (2000 lines) |
| GET | `/api/events` | SSE: `state`, `traffic` (every 2 s), `log`, `channel` (`dataCipher`/`controlChannel`; an empty field keeps the known value), `publicIp` (`{ "publicIp": "<ipv4>" }`, `""` when it became unknown) |
| GET/PUT | `/api/firewall` | Firewall rules and settings (§16); `/api/host-access` answers 410 Gone |
| POST | `/api/firewall/templates/ipsec` | Returns the rule set for an IPsec device (§16.2), not stored |
| GET | `/api/system` | Version, self-check results, UI listen address |
| GET/PUT | `/api/public-ip-lookup` | Public IP detection setting `{ enabled, url }` (§6.1); PUT validates (422 with `fieldCodes`) and applies to a connected tunnel at once |
| GET | `/api/audit` | Audit log of sign-ins and security events, newest first (§8.2): `limit`, `before`, `filter` |

## 10. Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELDECK_LISTEN` | address of the interface holding the default route, port `8194` | UI listen address; never the tunnel device |
| `TUNNELDECK_DATA_DIR` | `/data` | Data directory |
| `TUNNELDECK_SECRET_KEY` | – | Base64 key instead of `secret.key` |
| `TUNNELDECK_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `TUNNELDECK_RESET_ADMIN` | – | `1` removes the admin account at start (see §8) |
| `TUNNELDECK_IPTABLES` | `auto` | iptables backend: `auto` (share the host firewall's backend, see §6) \| `nft` \| `legacy` |
| `TZ` | `UTC` | Time zone for the daily reconnect and log timestamps |

Backup in stage 1 = copying `/data` including `secret.key`; an export/import UI is not part of stage 1.

## 11. UI design

Tone: calm, technical, uncluttered. Sentence case, no exclamation marks, verbs on buttons. German and English from day one (browser language default, switch in the user menu). Light and dark theme from `prefers-color-scheme` with a manual toggle.

**Tokens** (CSS custom properties in `web/src/styles/tokens.css`): neutral gray scale for surfaces/text, one accent (blue) for links, focus and primary action, semantic green/amber/red for connection state only. Radius 8 px (controls) / 12 px (cards). Spacing scale 4/8/12/16/24/32. Font: system UI stack; monospace for IPs and log. Two weights (400/500). One primary button per view.

**Layout:** fixed left sidebar (240 px; collapses to a top bar below 800 px) with product name, nav — Dashboard, Profiles, Firewall, System — and at the bottom language, theme and sign-out. Content column max 960 px.

**Dashboard**
- Connection card: state pill (gray disconnected, amber connecting/reconnecting, green connected, red error), profile name, protocol badge, remote host:port, VPN IP, connected-since duration. Actions: `Connect` (primary when disconnected) / `Disconnect` + `Reconnect`. A profile select sits next to `Connect` when more than one profile exists. Error state shows the last error line and `Try again`.
- Metric row: received, sent (totals), download rate, upload rate.
- Host protection card: "NAS shielded from tunnel", count of open ports, link to Firewall (§16.4).
- Live log card: monospace, auto-scroll with pause-on-scroll, level filter, text filter, `Copy`.
- Empty state (no profile): headline "Add your first VPN profile", one line of body, button `Create profile`.

**Profiles:** list rows (name, protocol, remote, active marker) with `Edit`, `Duplicate`, `Delete`. `New profile` → choose protocol (only OpenVPN enabled; WireGuard and IPsec shown as "planned", disabled) → form generated from `FormSchema`, sections: Server, Authentication, Encryption, Advanced (extra options as an add/remove list like on the RUT240). `Import .ovpn` fills the form and lists warnings. Secret fields show "Stored" with `Replace`.

**Firewall:** see §16.4 (replaced the former "Host access" page in 0.2.0).

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
| Security headers | CSP Level 3 (W3C); `X-Frame-Options` RFC 7034; HSTS RFC 6797; `Referrer-Policy`, `Permissions-Policy`, COOP/CORP per their W3C/WHATWG specs |

Not RFCs but binding here: Server-Sent Events (WHATWG HTML), Semantic Versioning, Conventional Commits. OpenVPN and WireGuard have no RFC; their official documentation is the reference.

## 16. Firewall (0.2.0, replaces "Host access")

Built before the 0.1.0 field test (owner decided 2026-11-25). Owner's decisions of 2026-11-25. The single "Host access" list becomes a two-direction firewall that can target this device or any other device in the local LAN, always by IPv4 address.

### 16.1 Rule model

`FirewallRule { id, direction: inbound | outbound, protocol: tcp | udp | esp | gre | any, source: CIDR (optional = any), destination: string (inbound: one IPv4 address; outbound: CIDR), destinationPort: port or range (tcp/udp only; empty = any port), publicPort: port or range (inbound tcp/udp only, default = destinationPort; must be empty while destinationPort is), keepSourceAddress: bool (inbound to other devices, default false), enabled, comment }`. Default policy: everything not allowed by a rule is dropped in both directions. Rules are evaluated in list order; the UI allows reordering.

- **Inbound** (VPN side → LAN): `source` = allowed remote addresses (default any, e.g. `203.0.113.0/24`). `destination` = exactly one IPv4 address inside a LAN subnet of the host (e.g. `192.168.1.10`). Whether it is the host's own address is re-evaluated on every apply, because the host's LAN address can change.
  - Destination = one of the host's own LAN addresses → accept / drop / reject in `TUNNELDECK-INPUT`; `publicPort` must be empty or equal `destinationPort`. This replaces the 0.1 host-access rule. An empty `destinationPort` accepts the protocol on every port. `TUNNELDECK-INPUT` drops TCP to the HTTP UI port before any rule, so no rule can open it to the tunnel; the remote-access HTTPS port keeps its own accept.
  - Destination = any other LAN address (e.g. `192.168.1.20`) → port forward (always accept): DNAT `tdvpn0:publicPort → destination:destinationPort` in a `TUNNELDECK-PREROUTING` nat chain, accept in `TUNNELDECK-FORWARD`, and unless `keepSourceAddress` is set, MASQUERADE on the LAN interface so the target answers the host without route changes. With `keepSourceAddress` the target needs a route back via the host (typically an outbound rule for the same device, see below); the UI says so.
  - An empty `destinationPort` (and `publicPort`) forwards every port of the protocol to the destination. Its DNAT returns early for TCP to the HTTP UI port and, while remote access is on, to the remote-access port, so the host keeps both. Such a forward conflicts with every other enabled accepting inbound rule of an overlapping protocol that goes elsewhere (reported on both rules).
  - `esp`/`gre` have no ports: they forward the whole protocol to one destination (only one such rule per protocol, since the public address is shared).
- **Outbound** (LAN → VPN side): `source` = LAN device or subnet (required), `destination` = remote address or network behind the VPN (CIDR, `0.0.0.0/0` = everything). Matching traffic is policy-routed into table 7194 (`ip rule from <source> to <destination> lookup 7194`, with a higher-priority rule that keeps LAN-to-LAN traffic in the main table), accepted in `TUNNELDECK-FORWARD`, and MASQUERADEd on `tdvpn0`. LAN devices must send this traffic to the host (host as gateway, or a static route in the LAN router for the destination network); the UI shows that hint. When the tunnel is down, matching traffic is dropped, never sent out via the normal internet connection (kill switch).
- Replies to established connections are always allowed in both directions (conntrack).
- An empty `sourcePort` or `destinationPort` means any port in every direction and for every action (accept, drop, reject); netguard then omits `--sport`/`--dport`.
- Validation: one inbound rule per (protocol, publicPort) on the shared public address; the HTTP UI port can never be a public port; the remote-access HTTPS port is reserved; `destination` of inbound rules must be inside a LAN subnet of the host; ranges ≤ 1000 ports.
- Requires `net.ipv4.ip_forward=1` on the host; the self-check reports it (Docker hosts normally have it on) and the docs explain how to enable it. Coexists with Docker's own `FORWARD`/`DOCKER-USER` chains by inserting the jump at position 1.

Implementation notes (task 16, task 20): `ip rule` priorities 7100 (LAN exclusion, `lookup main`), 7180 (a profile's remote networks while connected, `from all to <net> lookup 7194`; remote networks never overlap a LAN subnet), 7190 (outbound rules), 7191 (replies of port-forward targets, masqueraded or not: after the reverse NAT their destination is the original sender on the VPN side, which the main table would route elsewhere), 7194 (VPN source address). Only selectors Linux 4.4 knows are used (`from`, `to`, `fwmark`; `ipproto`/`sport`/`dport` need Linux 4.17). Reply routing (task 25): while the kernel has the CONNMARK target and the mangle table, chain `TUNNELDECK-MANGLE-PRE` (jump at position 1 of mangle `PREROUTING`, tagged `tdfixed:reply-mark`/`tdfixed:reply-restore`, filled only while a port forward exists, removed with the firewall) sets connmark `0x7194/0xffff` on every connection arriving on `tdvpn0` and restores it onto the packets of such connections arriving by another interface, and 7191 holds one rule `fwmark 0x7194/0xffff lookup 7194`; without them 7191 holds `from <target> lookup 7194` per forward target (with its LAN exclusion at 7100), which also sends other traffic the host routes for that target into the tunnel, and the self-check `reply-routing` warns. Drop/reject rules currently act on traffic to the host only (INPUT); exceptions for port forwards are expressed by the forward rule's `source`. Inbound `any` protocol only with drop/reject. The `nat` table is required.

### 16.1a Adopted from the Teltonika RUT240 firewall

Compared with the RUT240 firewall (General settings, Port forwards, Traffic rules, NAT, Attack prevention), the following is adopted:

- Every rule gets a `name` (required, 1–64 chars); `comment` stays optional.
- `action: accept | drop | reject` per rule (default accept; reject answers TCP RST / ICMP port-unreachable). Port-forward rules (inbound to another device) are always accept. Drop/reject rules let a user carve exceptions above broader accept rules, since order matters.
- Protocol adds `tcp+udp` (default for new inbound rules, as on the RUT240) and `icmp` (optional ICMP type, e.g. echo-request for ping to the host).
- Optional `sourcePort` (port or range).
- Global firewall settings (`settings.firewall`): `dropInvalid` (default on: drop conntrack INVALID on the tunnel), `mssClamp` (default on: clamp TCP MSS to PMTU for traffic forwarded through `tdvpn0`), `synFloodProtection` (default on: limit new TCP connections from the tunnel to 25/s burst 50 per source), `pingLimit` (default on: ICMP echo from the tunnel limited to 5/s burst 10).
- Not adopted, with reason: raw custom iptables rules (security, clean code), DMZ / forward-everything (unsafe default), source-MAC matching (no MACs exist on a TUN tunnel), conntrack helpers (IPsec with NAT-T needs none; PPTP/SIP later if asked), NAT loopback (LAN clients reach mdex addresses over the internet anyway), per-zone logging (kernel log is not readable from the container). Planned later: time restrictions per rule, hit counters per rule, port-scan prevention.

### 16.2 Reference use case: an IPsec router in the local LAN using the VPN address

An IPsec router in the local LAN (example `192.168.1.2`) establishes IPsec tunnels to peers (e.g. `198.51.100.7`) using the tunnel's public address:
- Inbound: UDP 500 → `192.168.1.2:500`, UDP 4500 → `192.168.1.2:4500`, ESP → `192.168.1.2`, each with `keepSourceAddress` on (IKE identifies peers by address).
- Outbound: source `192.168.1.2/32` → destination `0.0.0.0/0` (or the peers' addresses), so the router's own IKE/ESP traffic and its replies leave through the tunnel with the public address. The router's default gateway (or a route for the peers) points to the host.
- The UI offers this as a template ("IPsec router") that creates the five rules.

### 16.3 Migration and API

- `settings.json` schemaVersion 1 → 2: every host-access rule becomes an inbound rule to the host (0.2.0-alpha stored a host destination kind).
- schemaVersion 2 → 3: destinations become plain strings. Legacy host-kind rules are kept privately by the store; `GET /api/firewall` returns them with the host's detected address (`hostAddress`), and the next PUT stores plain addresses. Until then netguard keeps handling legacy rules.
- `GET/PUT /api/firewall` replaces `/api/host-access` (the old endpoint answers 410 Gone with a pointer).
- Breaking change → release 0.2.0.

### 16.4 UI (redesign, owner-approved 2026-11-26)

Amended 2026-11-26 (task 24): there is no "Host" destination; destinations are IP addresses in the "Local LAN" (example 192.168.1.0/24), the flow strip reads `VPN → Local LAN device` / `Local LAN device → VPN`, and all texts are generic (no brand or device-type names).

Based on a comparison of pfSense, OPNsense, OpenWrt LuCI, Teltonika RutOS, UniFi, MikroTik, Firewalla, Fritz!Box and Synology DSM. The rule model (§16.1) is unchanged; only the presentation changes.

- **Rule list** (one list, both directions, in evaluation order): per row an enable switch, a flow strip of chips `Source → (Host) → Target` with the endpoint the rule is about highlighted (accent), a second line with name, service/ports in plain words and notable options ("sender kept", "all ports", "off"), a hit counter, and row actions Edit / Duplicate / Delete; up/down buttons for order. Filter chips: All / Inbound / Outbound.
- **Add rule = intent first.** Cards: "Make a LAN device reachable from the VPN" (port forward), "Open a service on the host", "Let a LAN device into the VPN" (outbound), "IPsec router" (template, §16.2), "Block something" (drop/reject), "Custom rule" (full form). Each card presets direction, action and destination kind and shows only its fields.
- **Editor**: the same flow strip on top (live); numbered steps: 1 device (picker), 2 service (presets HTTP 80/tcp, HTTPS 443/tcp, SSH 22/tcp, RDP 3389/tcp, SMB 445/tcp, DNS 53/tcp+udp, "All ports", "Custom" with protocol + port fields), 3 name (prefilled from device + service, editable). A plain-language summary generated from the same model as the rules, e.g. "Connections from any sender to <VPN address>:443 go to Webserver 192.168.2.30:443 (TCP). The webserver sees the host as sender." Collapsible "Restrict and advanced": sender (source CIDR + source port), different port on the VPN address, "Sender seen by the target: Host / Original" (= keepSourceAddress, with one-line explanation), comment. Collapsible "What this rule creates" listing the technical entries (filter accept, DNAT, masquerade, policy route) read-only. Empty fields always mean "any".
- **Device picker**: LAN neighbours of the host (IP, MAC, hostname when resolvable via reverse DNS or DHCP leases visible to the host) from `GET /api/firewall/devices`; free IP/CIDR entry always possible; a hint when a chosen device's address may change ("Reserve this address in your router").
- **Hit counters**: `GET /api/firewall` returns per-rule packet/byte counters read from iptables (`-L -v -x`) through `CommandRunner`; counters must survive re-applying unchanged rules (rules are matched by a comment tag `tdrule:<id>` and only changed rules are replaced; counters reset only when a rule changes). Shown as "N hits"; "–" while disabled. Hits = new connections matched: each rule is counted once, from its filter line (INPUT accept or drop/reject for rules to the host, the FORWARD line for port forwards and outbound rules); its DNAT and masquerade lines keep their tags but are not summed. Without the iptables comment match (`xt_comment`) rules are installed untagged and rebuilt on every apply as before, `GET /api/firewall` returns `counters: null` with `countersAvailable: false`, and the self-check `rule-counters` warns. Granularity is the chain: a chain whose lines (tags in order, each line confirmed with `iptables -C`) already match is left untouched, and a changed chain is refilled with the DROP-safe append-then-trim, which resets the counters of every rule in that chain only.
- Not done (anti-patterns found): implicit bidirectional rules, auto-generated extra rows in the list, a separate NAT tab.

## 17. Compared with the Teltonika RUT240 VPN features

Reviewed 2026-11-25 against the RUT240 VPN manual (OpenVPN client/server, GRE, IPsec, PPTP, SSTP, Stunnel, DMVPN, L2TP, L2TPv3, ZeroTier, WireGuard, Tinc).

**Adopt for the OpenVPN client (0.2.0):**
- `remoteNetworks` (list of IPv4 CIDRs, the RUT240's "Remote network IP address/netmask"): networks behind the VPN. While connected, the host itself routes them through table 7194 (`ip rule to <net> lookup 7194`), and outbound firewall rules (§16) can use them as destinations. Pushed routes stay ignored.
- Inline PKCS#12 (`<pkcs12>` base64 block in `.ovpn`, or an upload field) as an alternative to separate certificate and key; stored as a secret.
- Keep-alive placeholder `10 120` in the form (no default value, the server usually pushes it).

**Not adopted, with reason:** "Static key" authentication (deprecated in OpenVPN 2.6/2.7 and insecure; the importer rejects `secret` and the advisories explain), TAP mode (bridging is out of scope), provider presets such as NordVPN/ExpressVPN (third-party brands, no maintenance), OpenVPN server mode (TunnelDeck-VPN is a client), legacy encryption defaults (the RUT240 defaults to AES-256-CBC with SHA1; TunnelDeck-VPN negotiates AEAD ciphers, §5), UDP6/TCP6 (IPv6 is a non-goal for now).

**Roadmap for other methods**, in this order:
1. WireGuard (0.3.0): interface private key (generate button), addresses, MTU 1280–1420, DNS; peers with public key, allowed IPs, optional pre-shared key, endpoint host:port (default 51820), persistent keepalive (default 25 behind NAT). Userspace `wireguard-go`.
2. IPsec/IKEv2 client via strongSwan: IKEv2 only by default (IKEv1 opt-in for old peers), PSK or X.509, local/remote subnets, DPD, modern proposals by default (AES-GCM, SHA-256+, ECP256/MODP2048+). The RUT240's IPsec defaults (3DES, MD5, MODP768) count as insecure and only produce advisories if a peer requires them.
3. GRE (alone or over IPsec), L2TP/IPsec client.

Rejected: PPTP (broken encryption), SSTP, ZeroTier, Tinc, DMVPN, Stunnel, L2TPv3 (niche or covered by the above).

## 15. Roadmap and release

1. Stage 1 (this spec). Public from the start (owner's decision, 2026-11-25): code at `github.com/MAGPEEK/tunneldeck-vpn`, image at `magpeek/tunneldeck-vpn` on Docker Hub. Development builds are tagged `0.1.0-dev`; `latest` and plain version tags only for releases. Field test on the DS723+ pulls the image from Docker Hub (or imports a `docker save` export).
2. After a successful field test: tag `v0.1.0` and publish the release image.
3. Stage 2: gateway functions (LAN allow-list, kill switch, port forwards, traffic chart). Port forwards include a freely chosen external port mapped to a host service (e.g. tunnel port 4444 → DSM 5001), as the RUT240 offered for its own web UI.
4. WireGuard driver (userspace `wireguard-go`, because the DS723+ kernel has no WireGuard module), then IPsec/IKEv2.
5. Notifications (webhook) — not before stage 2.

## 18. WireGuard driver (0.3.0, owner-approved 2026-11-26)

Decisions from the owner interview. No concrete counterpart yet: built generically and tested against a WireGuard server in the e2e stack.

- **Implementation:** `golang.zx2c4.com/wireguard` (wireguard-go) embedded as a library in the TunnelDeck binary; no extra process, no kernel module (the DS723+ kernel 4.4 has none). Linux only, behind build tags; the device is the fixed tunnel device `tdvpn0`. Everything WireGuard-specific lives in `internal/vpn/wireguard`; other code sees only `vpn.Driver`.
- **Profile (one peer, the server):** interface private key (secret), addresses (IPv4 CIDR, e.g. `10.66.0.2/32`), MTU (default 1420, 1280–1420); peer public key, optional pre-shared key (secret), endpoint `host:port` (default port 51820), allowed IPs (CIDR list), persistent keepalive (default 25 s, 0 = off). Plus the generic profile fields (name, public address, daily disconnect, kill switch).
- **Keys:** "Generate key pair" creates a Curve25519 private key on the server; the private key and the PSK are stored encrypted and never returned (`hasValue`); the public key derived from the private key is shown with a Copy button so the owner can enter it on the server.
- **Import:** `.conf` in wg-quick format (file or pasted). `[Interface]` PrivateKey, Address, MTU; `[Peer]` PublicKey, PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive fill the form. Dropped with an info note: `DNS` (the host's DNS is not changed), `Table`, `FwMark`, `ListenPort`, `SaveConfig`, IPv6 addresses and IPv6 allowed IPs (IPv4 only), further peers ("only the first peer is used"). Rejected: `PreUp`, `PostUp`, `PreDown`, `PostDown` (scripts). Unknown keys: rejected like unknown OpenVPN directives. A further `[Interface]` section is merged into the first with a warning (`additional_interface`). At most 50 warnings are listed; one more warning (`warnings_limited`, its `count` field holds the number) stands for the rest, so a file of junk lines cannot flood the response.
- **Routing (same as OpenVPN, §6):** the host keeps its default route; the main table is never modified. The interface address is the VPN IP (policy rule from the VPN IP, table 7194). Allowed IPs other than `0.0.0.0/0` become remote networks (§16); which LAN devices may use the tunnel is decided by the firewall's outbound rules and kill switch. WireGuard's cryptokey routing still enforces the allowed IPs.
- **State (§4.2):** `connecting` until the first handshake; `connected` after it (since = handshake time); no handshake for 180 s → `reconnecting`, the endpoint host name is resolved again (DynDNS) and the peer re-set; 30 s after start without a first handshake the status message says "No answer from the server – check the keys and the endpoint" (state stays `connecting`, retrying). Traffic counters from the device's rx/tx bytes. Log lines from wireguard-go at info level (no keys).
- **Data channel:** the encryption row shows `ChaCha20-Poly1305` (WireGuard's fixed cipher); no control-channel value.
- **Unchanged features:** daily disconnect, firewall, kill switch, remote access, public IP detection work for WireGuard profiles exactly as for OpenVPN.
- **Tests:** unit tests for schema, validation, renderer, importer (fixtures incl. provider-style files), key generation, state machine with a fake device; e2e matrix case "D-wireguard" against a WireGuard server container on both iptables backends.

Implementation decisions (task 25):

- **Address:** one IPv4 address with prefix length (setting `address`; a plain address means /32), not a list: only the VPN IP gets the policy routing. The driver puts it on `tdvpn0` as /32, so unlike OpenVPN (§6) not even a connected route appears in the main table; the server's tunnel subnet is reached from the VPN IP through table 7194. The address must lie outside the host's LAN. The importer takes the first IPv4 address and drops further ones with a warning.
- **Key pair API:** `POST /api/drivers/{protocol}/keypair` returns a fresh `{ privateKey, publicKey }` to the requesting client and stores nothing, like the import draft; the form sends the private key with the profile as a typed-in secret. A stored private key is never returned; profile responses carry `derived.publicKey`, computed from it. The API keeps derived values and secret-dependent advisories (such as IPsec's weak pre-shared key) in memory per profile revision, so listing profiles and reading the connection status do not decrypt secrets; saving or deleting a profile drops its entry, and a restart computes each profile again on its first read. The cache holds only these results, never a secret.
- **Endpoint inside a remote network:** after every resolution (at start and when resolving again), an endpoint address inside one of the allowed IPs other than `0.0.0.0/0` ends the attempt with error code `endpoint_in_tunnel` (retried with backoff, as the name may resolve elsewhere later): rule 7180 would route the tunnel's own UDP packets into the tunnel. A literal endpoint address is already refused by validation (`remote_network_contains_server`).
- **Start:** `Start` only checks the profile; resolving the endpoint, creating the device, the `ip` commands and the configuration run in the background, so the connection manager stays responsive. Their failures arrive as an `error` state (`start_failed`, `endpoint_in_tunnel`). Name resolution never holds the lock that `Stop` needs, and `Stop` cancels it.
- **Status note:** status and state events carry `messageCode` next to `message`; the 30 s note is `wireguard_no_handshake` (UI text `connection.messageCode.<code>`).
- **Liveness:** the device is polled every 2 s (traffic events at the OpenVPN cadence). A connected tunnel counts as lost only when the last handshake is 180 s old (counted on the monotonic clock from the check that first saw it, so a step of the wall clock does not age it; any change of the reported handshake time counts as a new handshake) and the device has sent something since, on two checks in a row, so an idle tunnel without keepalive stays `connected`. While no handshake is current, a keepalive is sent on every check (wireguard-go limits initiations to one per 5 s and would otherwise give up after 90 s) and the endpoint is resolved again every 180 s (IPv4 preferred, IPv6 if the name has none). `since` of `connected` is the handshake time: the manager takes a driver's connect time when it reports one.
- **Import:** a file without `PersistentKeepalive` gets 25 s with an info note.
- **Log:** wireguard-go's keepalive and worker-start lines are dropped (every 25 s / every start), its handshake and UAPI lines are `debug`, other lines `info`, errors `error`; hex keys in a line are replaced by `(hidden)`.

### 18.1 Standards compliance (review, 2026-11-26)

WireGuard has no RFC; the protocol is defined by the WireGuard whitepaper (Donenfeld, NDSS 2017) on the Noise framework (Noise_IKpsk2). Its primitives are fixed and standardised: X25519 (RFC 7748), ChaCha20-Poly1305 AEAD (RFC 8439), BLAKE2s (RFC 7693), HKDF (RFC 5869). There is no cipher negotiation, so no weak configuration exists and no algorithm advisories are needed. TunnelDeck uses the reference implementation wireguard-go and implements no protocol logic itself.

| Area | Basis | Requirement for TunnelDeck |
|---|---|---|
| Keys | RFC 7748 | Private keys are 32 random bytes from `crypto/rand`, clamped per RFC 7748 §5; public key derived with X25519; base64 (RFC 4648 §4) with exactly 32 decoded bytes, otherwise a field error. |
| Pre-shared key | Whitepaper §5.2 (Noise psk2) | Optional, 32 bytes base64; recommended as post-quantum hardening, no advisory when missing. |
| Configuration format | wg(8) / wg-quick(8), de facto | Import accepts the wg-quick INI format (case-insensitive keys, comma lists, `#` comments); scripts are rejected (§18). |
| Endpoint | RFC 3986 host, RFC 5952 / 4291 for IPv6 literals | `host:port`, IPv6 literals in brackets; IPv6 endpoints are rejected while TunnelDeck is IPv4-only. |
| Addresses / allowed IPs | RFC 4632 (CIDR) | Canonical CIDR; host bits in allowed IPs are rejected or normalised with a note. |
| MTU | RFC 791 / RFC 8200 minimum | 1280–1420 (1420 = 1500 minus the 80-byte IPv6 + UDP + WireGuard overhead). |
| Keepalive and handshake | Whitepaper §6 (REKEY_AFTER_TIME 120 s, REJECT_AFTER_TIME 180 s) | 180 s without a handshake = tunnel lost (§18); keepalive 25 s default behind NAT. |
| Verify | — | Key clamping, base64 length check and CIDR normalisation are covered by unit tests in `internal/vpn/wireguard`. |

## 19. IPsec/IKEv2 driver (owner-approved 2026-11-26)

Decisions from the owner interview. Counterparts: company and router gateways (LANCOM, FRITZ!Box, OPNsense/pfSense, Sophos, strongSwan). One active profile as before: an IPsec profile replaces the active one on connect.

- **Implementation:** strongSwan `charon` (Alpine package) driven over VICI from Go (`internal/vpn/ipsec`, the only package that knows IPsec), with the `kernel-libipsec` plugin: ESP runs in user space over a TUN device (`tdvpn0`), so no kernel IPsec modules are needed and no XFRM policies are installed on the host; routing, firewall and kill switch work exactly as for OpenVPN and WireGuard (table 7194, §6, §16). charon's own route installation is off (`install_routes = no`, `install_virtual_ip` handled by TunnelDeck on `tdvpn0`). charon runs with random local IKE ports (`port = 0`, `port_nat_t = 0`) so it neither collides with the DSM VPN server nor with port forwards of UDP 500/4500 to a LAN device (§16.2). The charon process is supervised like OpenVPN (start, stop, restart with backoff), its config is rendered into the tmpfs runtime dir.
- **IKE version:** IKEv2 (RFC 7296) by default. Owner decision 2026-11-26 (after testing a FRITZ!Box user VPN, which offers only "IPSec Xauth PSK"): IKEv1 is offered as a legacy fallback, limited to Aggressive Mode with PSK plus XAuth username/password (the FRITZ!Box user access and older gateways), with a danger advisory (§19.1). Template "FRITZ!Box user access (IKEv1 XAuth)" pre-fills it; the FRITZ!Box LAN-to-LAN template stays IKEv2 where FRITZ!OS supports it.
- **Authentication:** pre-shared key; certificate (PKCS#12 upload with password, or PEM certificate + key) with CA certificate for the server; EAP-MSCHAPv2 (username/password) with the server authenticated by certificate (CA upload or system CA store). Local/remote identities (FQDN, IP, email, DN) as fields with sensible defaults. All secrets encrypted, `hasValue` in responses.
- **Modes:** "Virtual IP" (request an address via configuration payload; that address is the VPN IP; LAN devices are masqueraded like with OpenVPN) or "Net-to-net" (local traffic selector = one or more local LAN subnets, remote traffic selectors = remote subnets; no masquerade for those subnets; the LAN router needs a static route for the remote subnets via the TunnelDeck host — documented). In net-to-net the host's own LAN address is the source for host-originated traffic into the tunnel. Remote subnets become remote networks (§16).
- **Proposals:** defaults IKE `aes256gcm16-prfsha384-curve25519-ecp384-ecp256-modp3072`, ESP `aes256gcm16-curve25519-ecp256-modp3072` (PFS) plus a plain-CBC fallback list for older gateways; fields to override. Advisories (like §5) for weak choices: 3DES, DES, MD5, SHA-1 PRF/integrity, MODP-768/1024/1536, no PFS.
- **Templates:** "LANCOM", "FRITZ!Box", "OPNsense/pfSense/strongSwan", "Generic" pre-fill proposals, identities and mode hints; each with a short guide in docs (what to configure on the gateway side).
- **State (§4.2):** `connecting` until IKE_SA and the first CHILD_SA are up; `connected` then (since = CHILD_SA install time); DPD (`dpd_delay = 30s`) and charon's retries; IKE_SA down → `reconnecting`, re-initiate; authentication failure → `error` with code `auth_failed` (no retry storm, like OpenVPN AUTH_FAILED). Traffic counters from the CHILD_SA (VICI `list-sas` bytes). Encryption row: negotiated ESP algorithm, control channel = IKE proposal.
- **Not in scope:** IKEv1 Main Mode with certificates, L2TP, several simultaneous tunnels, import of vendor files.
- **Tests:** unit tests for schema, validation, config rendering, VICI message handling with a fake, state machine; e2e: a strongSwan gateway container (`test/e2e/ipsecgw`, separate from the LAN IPsec router of §16.2) with PSK, certificate, EAP-MSCHAPv2 and IKEv1 XAuth in virtual IP mode on every iptables backend, and net-to-net with a LAN behind TunnelDeck (README of `test/e2e`).

### 19.1 Standards compliance (RFC analysis, 2026-11-26)

Binding for the IPsec driver. "Verify" marks points to confirm against strongSwan's behaviour in the e2e test.

| Area | Standard | Requirement for TunnelDeck |
|---|---|---|
| Protocol | RFC 7296 (IKEv2), RFC 9395 (IKEv1 deprecated), RFC 2409 (IKEv1), RFC 3947 (IKEv1 NAT-T), XAuth (draft-beaulieu-ike-xauth-02, never standardised) | IKEv2 by default. IKEv1 only as explicit legacy fallback (Aggressive Mode + PSK + XAuth) with a **danger** advisory: RFC 9395 deprecates IKEv1, and Aggressive Mode sends the identity in clear and allows an offline dictionary attack on the PSK. IKEv1 proposals follow the same algorithm advisories (MODP-1024 → warning). |
| IKE algorithms | RFC 8247 | Default IKE proposal must include the MUST/SHOULD set: AES-GCM-16 and AES-CBC, PRF HMAC-SHA2-256/384, DH groups 31 (Curve25519, RFC 8031), 19/20 (ECP, RFC 5903) **and 14 (MODP-2048, MUST implement)** for interoperability. Advisories: DES, MD5, MODP-768 (MUST NOT) → danger; 3DES, SHA-1 PRF/integrity, MODP-1024/1536, groups 22–24 → warning. |
| ESP algorithms | RFC 8221, RFC 4303, RFC 4106, RFC 7634 | Default ESP: AES-GCM-16 (MUST), ChaCha20-Poly1305 (SHOULD), AES-CBC + HMAC-SHA2-256-128 as fallback; PFS group in the ESP proposal. NULL encryption and DES never allowed; 3DES → warning. |
| Authentication | RFC 7296 §2.15/§2.16, RFC 7427, RFC 4945, RFC 5280 | With certificate or EAP the gateway is always authenticated by certificate (RFC 7296 §2.16): CA certificate and **remote identity are mandatory**, and the identity must match the gateway certificate (SAN). Signature authentication per RFC 7427 (RSA-PSS/ECDSA) allowed. PSK: warning below 20 characters (RFC 7296 §2.15: PSK must have high entropy). |
| EAP | RFC 7296 §2.16, RFC 3748 | EAP-MSCHAPv2 is not an IETF standard and is cryptographically weak: offered for compatibility, with a warning advisory recommending certificates. |
| NAT traversal | RFC 7296 §2.23, RFC 3948 | NAT detection and UDP encapsulation on; random local ports (§19). Verified: IKE_SA_INIT from a random port to 500, then IKE and ESP from a second random port to 4500 with the non-ESP marker. kernel-libipsec needs UDP encapsulation, so charon deliberately fakes a NAT (forced encapsulation, permitted by RFC 3948 and RFC 7296 §2.23); NAT-D therefore always reports NAT. |
| Fragmentation | RFC 7383 | IKEv2 fragmentation on (certificate exchanges exceed path MTU). |
| Liveness | RFC 7296 §2.4 | DPD 30 s; dead peer → `reconnecting`, re-initiate. |
| Rekeying | RFC 7296 §2.8 | Rekey, not reauthenticate (no traffic gap): IKE SA ~4 h, CHILD SA ~1 h with jitter; reauthentication off by default. |
| Traffic selectors | RFC 7296 §2.9, RFC 4301 | Accept narrowing by the gateway; `TS_UNACCEPTABLE` → error `ts_unacceptable` with a hint to compare subnets. |
| Configuration payload | RFC 7296 §3.15 | Virtual IP from INTERNAL_IP4_ADDRESS; INTERNAL_IP4_DNS is ignored (host DNS unchanged, as §6); `INTERNAL_ADDRESS_FAILURE` → error `no_virtual_ip`. |
| Error mapping | RFC 7296 §3.10.1 | AUTHENTICATION_FAILED → `auth_failed` (no retry storm); NO_PROPOSAL_CHOSEN → `proposal_mismatch`; others → generic with the notify name in the log. |
| Mobility | RFC 4555 (MOBIKE) | Off: TunnelDeck is a fixed gateway; avoids address changes that bypass its routing. |
| Revocation | RFC 5280, RFC 4806 | CRL/OCSP checks from strongSwan in relaxed mode (fail open only when unreachable). |
| Not covered (later, optional) | RFC 8229 (IKE/ESP over TCP), RFC 9370 (multiple key exchanges, post-quantum ML-KEM hybrid), RFC 8784 (PPK) | Not in the first version; candidates once gateways support them. |

### 19.2 Implementation decisions (task 28)

- **charon from source:** Alpine's `strongswan` package has no kernel-libipsec, so the image builds strongSwan 6.0.7 (the release Alpine 3.24 ships, checksum from its APKBUILD) in a build stage with only the plugins the driver loads, IKEv2 plus IKEv1 (for the XAuth fallback); the PID file lives in `/run/tunneldeck/ipsec`. kernel-libipsec installs a route through its TUN device for every policy regardless of `install_routes` – into the main table with `routing_table = 0`, otherwise with a routing rule of its own – so the build applies a small patch (`build/strongswan/`) that makes it honour `install_routes = no`. kernel-libipsec is loaded first and as critical (`kernel-libipsec!`): without its TUN device charon refuses to start instead of falling back to kernel IPsec. `routing_table = 0` keeps kernel-netlink from adding its routing rule. charon is built with `--with-user=ipsec --with-group=ipsec` (system user and group created in the image): it loads its plugins as root – TUN device, IKE sockets, VICI socket and PID file are opened then – and drops to `ipsec` with only `CAP_NET_ADMIN` (kept by kernel-netlink) before it starts working; nothing in `/data` or the root-only runtime directory is readable for it afterwards. Dropping to `ipsec` needs the capabilities `SETUID` and `SETGID`, which Docker grants by default; a container started with `cap_drop: ALL` must add them back next to `NET_ADMIN` (Linux and Synology guides, section 12). The driver starts charon with `STRONGSWAN_CONF` as its whole environment, so no `TUNNELDECK_*` variable (such as the secret key) reaches it.
- **Tunnel device:** kernel-libipsec creates `ipsec%d`; the driver reads the name from charon's log ("created TUN device") and renames it to `tdvpn0` before anything is loaded. The virtual IP is put on `tdvpn0` as /32 by the driver (`install_virtual_ip = no`).
- **VICI:** a small client in the package (encoding per strongSwan's VICI README, tested against its encoding example), because the protocol is small and a fake charon on a pipe tests the driver like OpenVPN's management socket. Credentials are loaded over VICI (`load-shared`, `load-key`, `load-cert`), the connection with `load-conn`; nothing secret is written to a file, so no swanctl.conf exists; strongswan.conf (no secrets) is the only rendered file. PKCS#12 bundles are decoded in Go (`software.sslmate.com/src/go-pkcs12`, which reads the AES/PBES2 bundles of OpenSSL 3 that `golang.org/x/crypto/pkcs12` cannot); a PEM key must be unencrypted. With certificate or EAP authentication the CA certificate and the gateway identity are required (§19.1), and the identity must name exactly one gateway: the forms charon reads as "any" (`%any`, `*`, `0.0.0.0`, `::`, `0::0`, `{0}:`), `*` wildcards, subnets and ranges (also as `ipv4net:` etc.) and the numeric type form `{n}:` are refused (`ipsec_identity_wildcard`), because charon would accept any certificate of the CA that matches them; the system CA store is not used.
- **State:** charon keeps the tunnel up itself (`keyingtries = 0`, `dpd_action = restart`, `close_action = start`); the driver reports `connected` on the installed CHILD_SA (from `child-updown`, or from `list-sas` if the event was missed), `reconnecting` when an IKE or CHILD SA goes down and `list-sas` shows no other established IKE SA of the tunnel with an installed CHILD_SA (IKEv1 reauthenticates make-before-break and moves the CHILD_SAs to the new IKE SA before the old one goes down; a new IKE SA with another virtual IP goes through `reconnecting` to `connected` with the new address), and initiates again when no attempt has been under way for 10 s (doubling up to 60 s), e.g. after a name that did not resolve. Failures come from VICI `alert` events: local/peer authentication alerts → `auth_failed`; certificate alerts (`cert-*`) only name the cause of a following `peer-auth-failed` of the same attempt (the same IKE SA `uniqueid`; charon's own retries use new IKE SAs), because charon raises them also for checks that succeed (a rejected chain may be followed by a trusted one); `cert-validation-failed` is ignored, as it only says that no CRL or OCSP answer was available, which relaxed revocation accepts, proposal mismatches → `proposal_mismatch`, `ts-mismatch` → `ts_unacceptable`, `vip-failure` (or an SA without IPv4 virtual IP) → `no_virtual_ip`. IKEv1 raises no alert for a received AUTHENTICATION_FAILED or NO_PROPOSAL_CHOSEN notify nor for refused XAuth credentials, so these come from charon's log lines. `proposal_mismatch` and `ts_unacceptable` wait for the user like `auth_failed`; `no_virtual_ip` is retried. A gateway address inside a remote subnet ends the attempt with `endpoint_in_tunnel` when the SA comes up (charon resolves the name itself at every attempt). Traffic is the sum of the CHILD_SAs' bytes, kept across rekeyings. The connected event carries `NoInternet` when none of the installed CHILD_SA's negotiated remote traffic selectors (VICI `remote-ts`) covers `0.0.0.0/0`, as a prefix or a range; without reported selectors the tunnel counts as carrying the internet (§6.1). Stop deletes the IKE SA over VICI, then SIGTERM, SIGKILL after 10 s.
- **NAT traversal:** kernel-libipsec needs UDP encapsulation, so charon fakes NAT detection ("faking NAT situation to enforce UDP encapsulation"); the gateway therefore always sees "remote host is behind NAT". Verified with a strongSwan gateway: IKE_SA_INIT from a random port to 500, then IKE and ESP on a second random port to 4500 with the non-ESP marker; ESP never goes out unencapsulated.
- **Net-to-net (generic netguard hook):** drivers may implement `vpn.LocalNetworker`; a tunnel with local networks reports no VPN IP. netguard then adds a `RETURN` for each local network ahead of the masquerade lines of `TUNNELDECK-POSTROUTING` (tag `tdfixed:local-network`), gives the default route of table 7194 the host's LAN address in the local networks as `src`, adds no rule at 7194 and routes the remote networks at priority 7099 – ahead of the LAN exclusions at 7100, which would keep traffic from the host's LAN address in the main table. Public IP detection is skipped without a VPN IP. Traffic from the remote subnets to LAN devices that is not a reply still needs a firewall rule; the inbound rule model (§16) has no un-NATed forward yet.
- **Templates and defaults:** a select option may carry `presets` (field key → value) in the form schema; the IPsec templates pre-fill the IKE version and the proposals (the FRITZ!Box user access also the pre-shared key and virtual IP mode). Empty proposals mean the defaults of the IKE version; IKEv1 has its own defaults without AEAD and Curve25519 in phase 1. The IKEv2 ESP defaults end with the same proposals without key exchange: IKEv2 creates the first CHILD_SA without one, so a gateway without PFS would otherwise refuse only the first rekey (~1 h); a gateway with PFS picks a PFS proposal first. IKEv1 keeps PFS-only ESP defaults, as Quick Mode negotiates PFS with the first CHILD_SA and a mismatch shows at once. The `ipsec_no_pfs` advisory is raised only when none of the ESP proposals has a key exchange. In virtual IP mode the remote subnets default to `0.0.0.0/0`; net-to-net requires them. The PSK-length advisory needs the secret, so the API asks drivers that implement `AdviseSecrets` with the stored profile; only the finding leaves the driver.
- **IKEv1 fallback:** `ikeVersion = ikev1` means Aggressive Mode with the pre-shared key and an XAuth round (`xauthUsername`, `xauthPassword`); other sign-in methods are rejected. IKEv1 reauthenticates every 4 h instead of rekeying (IKEv1 cannot rekey an IKE SA).
