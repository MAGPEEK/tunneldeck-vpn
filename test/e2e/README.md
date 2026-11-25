# End-to-end test

Drives a real TunnelDeck-VPN image through its HTTP API against throwaway OpenVPN servers in Docker. Nothing contacts a real VPN provider.

## Run

Requirements: Docker with Compose v2, Go (see `go.mod`), a Linux kernel with `/dev/net/tun` (Docker Desktop on Windows or macOS works: its Linux VM provides it).

```sh
go test -tags e2e -v -count=1 -timeout 30m ./test/e2e/
```

The test builds both images, starts the stack, runs the matrix and removes everything again: containers, the network, volumes and the two images it built (`tunneldeck-e2e:local`, `tunneldeck-e2e-server:local`). Base images and the build cache stay. Set `E2E_KEEP_STACK=1` to keep the stack for debugging; remove it afterwards with

```sh
docker compose -f test/e2e/compose.yml -p tunneldeck-e2e down -v --rmi all
```

Without the `e2e` tag, `go test ./...` skips this package.

Duration: about 7 minutes with a warm build cache (Docker Desktop on Windows, 2026-11-25, three backends); each scenario takes 35–47 s, most of it the deliberate 10 s no-retry wait, the three-second probe timeouts and the container restart. A cold build adds the image build time.

## Topology

```
                       Docker bridge network "e2e"
   ┌──────────────────────────────┐            ┌───────────────────────────────┐
   │ tunneldeck-legacy/nft/shared │  OpenVPN   │ server-a / server-b / server-c │
   │ (own network namespace =     │ ─────────▶ │ OpenVPN 2.7 server, tun0      │
   │  the "host" of SPEC §6)      │  UDP/TCP   │ 10.94.{1,2,3}.1               │
   │ tdvpn0 = 10.94.x.2           │            │ probe source 198.18.0.1 on lo │
   └──────────────┬───────────────┘            └───────────────────────────────┘
                  │ 127.0.0.1:<random> → 8194 (API for the Go driver)
```

- Each TunnelDeck-VPN container gets `NET_ADMIN` and `/dev/net/tun`, like the production compose file. In production it uses `network_mode: host`; here its own network namespace is the "host", so "main routing table unchanged" and "host protected" are checked inside that namespace (`docker compose exec … ip route`, `iptables -S`). This keeps the test independent of the developer's machine.
- The Go driver (`e2e_test.go`) talks to the real API through a published loopback port: setup, sign-in, then every request with the CSRF header and a matching `Origin`.
- The probe runs inside the server container, i.e. on the far side of the tunnel. It connects from `198.18.0.1`, an address outside the VPN pool, so TunnelDeck-VPN's replies reach it only through policy routing table 7194. A missing `ip rule` makes the reachability checks fail.

## Server variants

The servers generate a fresh PKI at start (`server/make-pki.sh`, ECDSA P-256, valid two days, never committed). All of them push `redirect-gateway def1`, which TunnelDeck-VPN must ignore.

| Variant | Server | Profile |
|---|---|---|
| A | username/password via `auth-user-pass-verify`, CA, data cipher negotiated (AES-256-GCM), UDP | `authMode password`, `remoteNetworks: ["10.99.0.0/24"]` |
| B | like mdex level 20: username/password, `data-ciphers none`, `auth none`, `fragment 1448`, `mssfix`, UDP | `cipher none`, `authDigest none`, extra options |
| C | client certificate required, `tls-crypt`, TCP | `authMode certificate`, client key and tls-crypt key as secrets |

Every server also has a dummy interface `remote0` with `10.99.0.1/24`, a network "behind" it that is pushed to nobody; only variant A's profile names it in `remoteNetworks`.

The test password contains a space, `"`, `\`, `'`, `#`, `;` and `$` to exercise the management escaping.

## iptables backends

TunnelDeck-VPN shares the backend of the host's firewall (SPEC §6): it counts the host rules each working backend lists and picks the one that holds rules, nf_tables when neither does. All three containers run the same image with the default `TUNNELDECK_IPTABLES=auto`; `compose.yml` overrides the entrypoint to shape each "host" before TunnelDeck-VPN starts:

| Service | Host it emulates | Expected self-check |
|---|---|---|
| `tunneldeck-legacy` | `xtables-nft-multi` deleted: a kernel without nftables, such as DSM 7.2 on kernel 4.4 | `using iptables-legacy: only the legacy backend works` |
| `tunneldeck-nft` | `xtables-legacy-multi` deleted: a modern host without the legacy `ip_tables` modules | `using iptables-nft: only the nf_tables backend works` |
| `tunneldeck-shared` | both binaries work; a host firewall on nf_tables already has `-A INPUT -i tdvpn0 -p tcp -j DROP`, like ufw's "deny incoming" | `using iptables-nft: host rules only in nf_tables (<n>)` |

`<n>` includes the nat rules Docker installs in every container namespace for its embedded DNS, so the test checks the detail up to the count. It lists TunnelDeck-VPN's chains with the chosen backend's own binary; for `tunneldeck-shared` it also checks that `iptables-legacy` holds none of them. The host's DROP rule makes the firewall and remote-access steps fail if TunnelDeck-VPN installed its chains in the other backend.

## Assertions per backend and variant

1. Self-checks pass; the iptables self-check names the expected backend and reason.
2. Variants A and B: a profile with a wrong password ends in state `error` with `lastError.code` `auth_failed`; the server's verify script sees exactly one attempt, also 10 s later (no retry). Deleting that profile while it is still in state `error` succeeds and leaves the connection `disconnected`.
3. Connect: state `connected` within 60 s; the VPN IP is a client address of the server's pool.
4. Traffic: five 1000-byte pings from the host side to the server's tunnel address succeed, and both byte counters grow by at least 5000.
5. Routing: the main table differs from before only by the kernel's connected route of the tunnel subnet (SPEC §6); `ip rule` has `7194: from <vpn-ip> lookup 7194` (variant A also `7180: from all to 10.99.0.0/24 lookup 7194`); table 7194 holds only `default dev tdvpn0`. Variant A: the host pings `10.99.0.1` behind the server.
6. Host protection: `INPUT` jumps to `TUNNELDECK-INPUT` first and that chain ends with `DROP` (and the unused backend holds no TunnelDeck-VPN rule). From the probe, the UI port 8194 and a listening dummy service (TCP 9000) are unreachable; an inbound firewall rule to this device for 8194 is refused (`validation_failed`); a rule for 9000 makes it reachable while 8194 stays closed; removing the rule closes it again.
7. Remote access: enabling HTTPS remote access (port 8443, self-signed) makes `https://<vpn-ip>:8443/api/session` answer 200 with `Strict-Transport-Security: max-age=31536000` from the probe, while 8194 stays closed; disabling closes 8443 again.
8. Disconnect: main table and rules are exactly as before; variant A: `10.99.0.1` is no longer reachable.
9. Restart: connect, `docker compose restart` the TunnelDeck-VPN container, sign in again; the tunnel comes back by itself, routing is as in step 5 and the firewall is installed.

## Not covered

- The daily reconnect (SPEC §4.3).
- A real `network_mode: host` deployment on a physical host, and interplay with ufw, firewalld or Docker's own chains (ufw was checked once by hand in a container lab; see `docs/linux.md`).
- arm64 (the test runs on the build machine's architecture only).
- Uploaded remote-access certificates, `.ovpn` import and the web UI itself.
- Wrong CA, unreachable server and backoff timing.
