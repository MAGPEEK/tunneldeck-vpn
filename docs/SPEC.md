# TunnelDeck — Specification

Working name: **TunnelDeck** (binary `tunneldeck`). A self-hosted VPN client gateway in a Docker container with a modern web UI. License: MIT.

## 1. Goals

- Run a VPN client on a Docker host (reference host: Synology DS723+, x86-64, DSM 7.2, Linux 4.4) and manage it entirely from a web UI: profiles, connect/disconnect, status, live log.
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

`disconnected → connecting → connected → (reconnecting ↔ connected) → disconnecting → disconnected`, plus `error` (with message; user action or auto-retry leaves it). Auto-retry uses exponential backoff 2 s … 60 s.

## 5. OpenVPN driver

- OpenVPN runs as a child process with a rendered config file under `/run/tunneldeck/` (tmpfs, mode 0600), removed on stop.
- Control via the management interface on a unix socket: state changes, byte counts, log lines, and credentials (`management-query-passwords`), so passwords never land in a file. Exact directives are fixed in `docs/openvpn-notes.md` (task 2).
- Fixed tunnel device name `tdvpn0`, `dev-type tun`.
- Routes: OpenVPN must not touch the main routing table (`route-noexec`; pushed and configured `redirect-gateway` is neutralised). See 6.
- Profile fields (OpenVPN settings): `remoteHost`, `port`, `proto` (udp|tcp), `compression` (none|lzo), `authMode` (password | certificate | certificate+password), `username`, `password`*, `caCert`, `clientCert`, `clientKey`*, `tlsAuthKey`* / `tlsCryptKey`* + `keyDirection`, `cipher` (free text incl. `none`), `authDigest`, `resolveRetry`, `keepalive`, `extraOptions` (list of raw lines). `*` = secret.
- `extraOptions` are validated: one directive per line, and a denylist rejects anything that runs code or fights the app: `up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`, `auth-user-pass-verify`, `client-connect`, `client-disconnect`, `learn-address`, `plugin`, `script-security`, `management*`, `daemon`, `log`, `log-append`, `status`, `writepid`, `config`, `cd`, `chroot`, `dev`, `dev-type`, `dev-node`, `iproute`, `route-noexec`, `auth-user-pass`. `redirect-gateway` is accepted but dropped with a visible warning ("handled by TunnelDeck").
- `.ovpn` import maps known directives to fields, inline blocks (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`) to cert/secret fields, everything else to `extraOptions` (subject to the denylist; rejected lines are reported, not silently dropped).

## 6. Networking (stage 1)

Container runs with `network_mode: host`, `cap_add: NET_ADMIN`, device `/dev/net/tun`.

- **Routing:** routing table `7194`. On connect: `ip route replace default dev tdvpn0 table 7194`, `ip rule add from <vpn-ip> lookup 7194 priority 7194`. On disconnect both are removed. The main table is never modified, so the host keeps its default route. Effect: replies to connections arriving at the VPN IP leave through the tunnel.
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
- Login rate limit: 5 failures per IP per minute, then lockout with backoff. Constant-time comparison.

## 9. HTTP API

JSON; errors as `{ "error": { "code": "...", "message": "...", "fields": {…} } }`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/session` | `{ setupRequired, authenticated, username }` |
| POST | `/api/setup`, `/api/login`, `/api/logout` | Account and session |
| GET | `/api/drivers` | Protocols with their `FormSchema` |
| GET/POST | `/api/profiles` | List / create |
| GET/PUT/DELETE | `/api/profiles/{id}` | Read / update / delete (delete refused while active and connected) |
| POST | `/api/profiles/import` | Parse `.ovpn` text → draft profile + warnings (not saved) |
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
