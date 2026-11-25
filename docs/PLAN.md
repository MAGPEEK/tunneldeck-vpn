# TunnelDeck — Plan (stage 1)

Status legend: `[ ]` open, `[x]` accepted. Spec: `docs/SPEC.md`. Every task: update `filemap.md` for added/moved files, keep all checks in CLAUDE.md green, do not commit (the orchestrator commits after review).

## [x] 1. Scaffold project — medium — after: –

Create the repository skeleton per SPEC §3–4: Go module `tunneldeck` (Go 1.27) with `cmd/tunneldeck/main.go` serving `/api/system` (version only) and the embedded SPA; empty packages with `doc.go` for every package in SPEC §4; `web/` Vite + React 19 + TypeScript strict app with a placeholder page, ESLint, Prettier, Vitest; `internal/web` embedding `web/dist` with SPA fallback (build must work when `web/dist` holds only a placeholder); `.golangci.yml`; multi-stage `Dockerfile` (node build → go build → Alpine runtime with openvpn, iptables, iptables-legacy, iproute2); `docker-compose.yml` (host network, NET_ADMIN, /dev/net/tun, `./data:/data`); move the existing root `docker-compose.yml` to `docs/reference/original-compose.yml` first; `LICENSE` (MIT); GitHub Actions workflow running all checks; `.dockerignore`. Verify: every command in CLAUDE.md passes locally (Docker build only if the daemon is running — report if not).

## [x] 2. Verify OpenVPN facts — heavy — after: 1

Research only, output `docs/openvpn-notes.md`. Determine for the OpenVPN version shipped by the Alpine release pinned in the Dockerfile: (a) how to run with no data-channel encryption against a server configured `cipher none` / `auth none` (mdex public.IP; RUT240 settings: UDP 1194, TUN, no LZO, user/pass auth, `tun-mtu 1500`, `fragment 1448`, `mssfix`, `float`, `nobind`, `reneg-sec 86400`, `remote-cert-tls server`, `tls-version-min 1.2`, `explicit-exit-notify 2`, `fast-io`, `redirect-gateway def1`) — exact directives, deprecations, whether a different OpenVPN version must be pinned; (b) whether `fragment` and `comp-lzo` are still compiled in; (c) management interface over a unix socket: directives, how to supply username/password, real-time `state`, `bytecount`, `log` message formats, clean shutdown signal; (d) `route-noexec` + neutralising pushed `redirect-gateway`, and whether `ifconfig` still applies; (e) whether a CA is mandatory with user/pass auth and how mdex distributes it. Use official OpenVPN docs/source and Alpine package data; verify in a container if Docker is running. Mark each claim VERIFIED (how) or UNVERIFIED. End with a ready-to-use reference config for the mdex case.

## [x] 3. Domain, store, secret — careful — after: 1

Implement `internal/domain` (types and errors from SPEC §4, §5 fields, §6 `HostAccessRule`, validation helpers), `internal/secret` (AES-256-GCM, `enc:v1:` format, key file creation 0600, env override) and `internal/store` (SPEC §7: `settings.json`, `profiles.json`, atomic write, mutex, secrets encrypted at rest, `schemaVersion` with a migration hook (SPEC §13), never-return-secret read model with `hasValue`, empty-secret-keeps-value update rule). Table-driven tests incl. corrupted files, wrong key, concurrent writes.

## [x] 4. Auth and sessions — careful — after: 3

Implement `internal/auth` per SPEC §8: setup-once admin creation, argon2id hashing with stored parameters, in-memory sessions (hashed tokens, idle timeout, logout), login rate limiter with injected clock, admin reset (function used by the `reset-admin` subcommand and `TUNNELDECK_RESET_ADMIN`; the CLI/env wiring itself lands in task 8). No HTTP here except small helpers for cookie read/write. Tests for every rule in §8.

## [x] 5. Driver interface and OpenVPN config — careful — after: 2, 3

Implement `internal/vpn` `Driver`, `FormSchema`, registry (SPEC §4.1) and in `internal/vpn/openvpn`: `Describe()` schema, `Validate`, config renderer (profile → config text, following `docs/openvpn-notes.md`), extra-option validation with the denylist (SPEC §5), `.ovpn` importer with warnings. Pure functions, golden-file tests incl. the mdex reference profile and hostile inputs (script directives, inline blocks, CRLF, comments, quoted args).

## [x] 6. OpenVPN supervisor and management — heavy — after: 5

Implement process supervision and the management client in `internal/vpn/openvpn` (`Start`, `Stop`, `Events`) and `vpn.ConnectionManager` (SPEC §4.1–4.2): state machine, credentials over management, byte counts → rates, log ring buffer feed, backoff retry with stop-on-auth-failure, scheduled daily reconnect (SPEC §4.3, injected clock), persisted desired state and reconnect on start, calls into a `netguard`-shaped interface on connect/disconnect: `InstallFirewall` is re-run before every connect (other software may have reordered the host chains) and a failure refuses the connect; `RouteThroughTunnel` after the VPN IP is known; `ClearTunnelRouting` on disconnect. Process and socket behind interfaces; tests with a fake management server and fake process covering races (stop during connect, process crash, double connect, shutdown).

## [x] 7. Netguard host protection — careful — after: 3

Implement `internal/netguard` per SPEC §6: backend detection, idempotent chain install/update/remove, policy routing add/remove, startup self-check. All commands through `CommandRunner`; tests assert exact command sequences and idempotency with a fake runner; one integration test (build tag `integration`) meant to run in a Linux container with NET_ADMIN.

## [x] 13. Profile advisories — medium — after: 6

Implement `Advisories(profile)` in `internal/vpn/openvpn` and the current-practice defaults per SPEC §5 ("Current-practice defaults and advisories"); expose advisories through the `Driver` interface (`Advise(profile) []Advisory`, driver-independent `Advisory{Code, Severity, Field}` in `internal/vpn`) so the API can return them with each profile and with the connection status. Table-driven tests for every code, including the mdex profile (must yield `unencrypted_data_channel`, `fragment_in_use`, `no_dco`).

## [x] 8. HTTP API and SSE — medium — after: 4, 6, 7, 13

Implement `internal/api` per SPEC §9 with middleware (session, CSRF, JSON errors, request logging), SSE hub, and wire everything in `cmd/tunneldeck` including config (SPEC §10), listen-address detection and graceful shutdown. `tunneldeck reset-admin` runs in a second process (`docker exec`), so it must ask the running server to call `auth.Service.ResetAdmin` over a root-only unix control socket (`/run/tunneldeck/control.sock`); if no server is running it edits the store directly. `TUNNELDECK_RESET_ADMIN=1` resets at start. The API also enforces that a host-access rule never opens the UI port. Handler tests with `httptest` and fakes for every endpoint and auth rule.

## [x] 14. Remote access over HTTPS — careful — after: 8

Implement SPEC §8.1: settings + store fields (schema stays v1 if additive with defaults, otherwise migration), self-signed certificate generation and renewal, upload validation, second HTTPS listener with live enable/disable/port change, `Secure` cookie and HSTS on that listener, stricter login limit for tunnel clients, netguard accept rule for the port, API endpoints. Tests: certificate generation/renewal with injected clock, upload validation (mismatched key, expired, garbage), listener lifecycle, cookie/HSTS headers, port-collision validation, netguard command sequence.

## [x] 9. Frontend shell and login — medium — after: 1

Implement in `web/`: design tokens and base styles, light/dark theme, app shell with sidebar (SPEC §11), routing, typed API client (CSRF header, error mapping), session handling, setup and login pages, i18n (de/en) scaffolding, shared components (Button, Card, Field, StatePill, EmptyState, Table). Component tests. Works against the API contract in SPEC §9 with mocked fetch.

## [x] 10. Frontend dashboard and profiles — medium — after: 8, 9, 13, 14

Implement Dashboard, Profiles (schema-driven form, import, secret fields), Host access and System pages per SPEC §11, the "Remote access" section (SPEC §8.1) on the System page, profile advisories (SPEC §5) in the form and on the dashboard, live updates via SSE. Tests for the schema form renderer, connection card states and log filter. Verify in a browser against the running backend.

## [x] 11. Image, compose, README — medium — after: 10

Finalise Dockerfile (pin the `openvpn` package to `~2.7`, non-root not possible → document why; healthcheck; labels; amd64 + arm64), compose example for Synology (`/volume1/docker/tunneldeck:/data`), `README.md` + `README.de.md`: what it is, quick start, DS723+ walkthrough (Container Manager, TUN module, DSM firewall notes, reverse proxy for HTTPS), mdex example written as a migration from a Teltonika RUT240 (which RUT240 fields map to which profile fields, which extra options are dropped or translated and why, disconnect the router before connecting because one mdex account allows one session, recommendation to move from level 20 to level 30), security model, roadmap (SPEC §15), versioning per SPEC §13 (version from `git describe` via build arg, OCI labels, release tagging steps in `docs/RELEASING.md`). Add a documented way to export the image as a `.tar` (`docker save`) for import in Synology Container Manager.

## [x] 12. End-to-end test — careful — after: 11

`test/e2e/`: compose file with a throwaway OpenVPN server (user/pass + cert variants, one `cipher none` variant) and TunnelDeck; script that drives the API: setup, create profile, connect, assert state/VPN IP/bytes, assert main routing table unchanged, assert host port closed then open after adding a rule, restart container and assert auto-reconnect. Document how to run it; run it if Docker is available. The stack runs on a generic Linux Docker host (not Synology-specific) and must pass with both the `iptables-nft` and `iptables-legacy` backends. Also write `docs/linux.md` + `docs/linux.de.md` (generic Linux host guide: `/dev/net/tun`, interplay with ufw/firewalld/Docker's own chains, reverse proxy for HTTPS, backup, update), linked first from the READMEs.
