# End-to-end test

Drives a real TunnelDeck-VPN image through its HTTP API against throwaway OpenVPN and WireGuard servers and an IPsec gateway in Docker. Nothing contacts a real VPN provider.

## Run

Requirements: Docker with Compose v2, Go (see `go.mod`), a Linux kernel with `/dev/net/tun` (Docker Desktop on Windows or macOS works: its Linux VM provides it).

```sh
go test -tags e2e -v -count=1 -timeout 60m ./test/e2e/
```

The test builds the five images, starts the stack, runs the matrix and the firewall cases and removes everything again: containers, the networks, volumes and the images it built (`tunneldeck-e2e:local`, `tunneldeck-e2e-server:local`, `tunneldeck-e2e-wgserver:local`, `tunneldeck-e2e-ipsecgw:local`, `tunneldeck-e2e-node:local`). Only the firewall cases: `-run 'TestEndToEnd/firewall'`. Base images and the build cache stay. Set `E2E_KEEP_STACK=1` to keep the stack for debugging; remove it afterwards with

```sh
docker compose -f test/e2e/compose.yml -p tunneldeck-e2e down -v --rmi all
```

Without the `e2e` tag, `go test ./...` skips this package.

Duration: about 16.5 minutes with a warm build cache (Docker Desktop on Windows, 2026-11-26): about 12 minutes for the matrix on three backends, where each scenario takes 33–52 s (WireGuard 44–46 s), most of it the deliberate 10 s no-retry wait, the three-second probe timeouts and the container restart, plus about 30 s once for `D-wireguard-no-handshake` and 18 s once for `D-wireguard-psk`. Each IPsec case takes about 14.5 s (failure cases 11–12 s, `-sa-lost` and `-restart` 14 s each), so variant E adds about 125 s on the first backend and 15 s on each other one. A cold build adds the image build time.

## Topology

```
                       Docker bridge network "e2e"
   ┌──────────────────────────────┐            ┌───────────────────────────────┐
   │ tunneldeck-legacy/nft/shared │  OpenVPN   │ server-a / server-b / server-c │
   │ (own network namespace =     │ ─────────▶ │ OpenVPN 2.7 server, tun0      │
   │  the "host" of SPEC §6)      │  UDP/TCP   │ 10.94.{1,2,3}.1               │
   │ tdvpn0 = 10.94.x.2           │            │ probe source 198.18.0.1 on lo │
   │                              │            └───────────────────────────────┘
   │                              │ WireGuard  ┌───────────────────────────────┐
   │                              │ ─────────▶ │ server-wg: wireguard-go, wg0  │
   │                              │  UDP 51820 │ 10.94.4.1                     │
   │                              │            │ probe source 198.18.0.1 on lo │
   │                              │            └───────────────────────────────┘
   │                              │ IPsec      ┌───────────────────────────────┐
   │                              │ ─────────▶ │ server-ipsec: strongSwan,     │
   │                              │  UDP 500,  │ kernel IPsec, pools           │
   │                              │  4500      │ 10.94.{5,6,7,8}.0/24          │
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

### Variant D: WireGuard

`server-wg` (image `wgserver/`, Alpine with the userspace `wireguard-go` and `wg`, no kernel module needed) runs the device `wg0` with `10.94.4.1/24` on UDP 51820, the probe source `198.18.0.1` and `remote0` `10.99.0.1/24` like the OpenVPN servers. It generates its key pair at start (`/run/e2e/server.pub`, never committed); its healthcheck waits until the device listens. Each scenario asks TunnelDeck-VPN for a key pair (`POST /api/drivers/wireguard/keypair`) and makes the public key the server's only peer with allowed IP `10.94.4.2/32` (`wgserver/peer.sh`), as an owner would enter it on the server.

Profile: address `10.94.4.2/24`, the server's public key, endpoint `server-wg:51820`, allowed IPs `0.0.0.0/0` and `10.99.0.0/24`, keepalive 25. `0.0.0.0/0` lets the probe (198.18.0.1) through WireGuard's cryptokey routing; `10.99.0.0/24` is the remote network.

### Variant E: IPsec

`server-ipsec` (image `ipsecgw/`, Alpine with strongSwan's charon and kernel IPsec in its own namespace) is a separate gateway, not the LAN IPsec router of the firewall cases. It generates a throwaway PKI at start (`ipsecgw/make-pki.sh`, ECDSA P-256, two days): the CA, the gateway certificate for `ipsec-gw.e2e` and the client certificate for `client.ipsec.e2e`, which the test reads as PKCS#12 bundle (OpenSSL 3 defaults) with its CA. `ipsecgw/swanctl.conf` has one connection per sign-in method, picked by the client's identity, each with its own virtual IP pool; the dummy interface `gw0` carries the gateway's `.1` in each pool's network, `remote0` `10.99.0.1/24` and `net0` `10.98.0.1/24` with an httpd that answers `/cgi-bin/source` with the client address it sees. charon logs to `/run/e2e/charon.log` line by line, where the test counts the authentication attempts. IKEv2 offers TunnelDeck's default proposals and nothing with AES-128.

| Case | Gateway connection | Profile |
|---|---|---|
| `E-ipsec-psk` | IKEv2, pre-shared key, pool `10.94.5.0/24`, everything (`0.0.0.0/0`) | local identity `psk.client.e2e`, **no gateway identity**, remote subnets `0.0.0.0/0` and `10.99.0.0/24` |
| `E-ipsec-certificate` | IKEv2, certificates, pool `10.94.6.0/24`, narrows the client's subnets to `10.94.6.1/32` and `10.99.0.0/24` | PKCS#12 with its password, CA, gateway identity `ipsec-gw.e2e`, the same remote subnets |
| `E-ipsec-eap-mschapv2` | IKEv2, EAP-MSCHAPv2, gateway certificate, pool `10.94.7.0/24`, everything | username and password, CA, gateway identity |
| `E-ipsec-ikev1-xauth` | IKEv1 Aggressive Mode, pre-shared key and XAuth, pool `10.94.8.0/24`, only `10.99.0.0/24` (like the FRITZ!Box user access) | template `fritzboxUser`, local identity, XAuth username and password, no gateway identity, remote subnet `10.99.0.0/24` |
| net-to-net (firewall case 12) | IKEv2, pre-shared key, `10.98.0.0/24` ↔ `10.95.0.0/24`, no pool | mode net-to-net, local subnet `10.95.0.0/24`, remote subnet `10.98.0.0/24` |

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
   Negotiation: although every server pushes `redirect-gateway def1` and A and B also a `route` and a `dhcp-option`, the connection log has no `Options error` line (pull filters instead of `route-nopull`); the status names the data cipher (A and C `AES-256-GCM`, B `none`) and the control channel (`TLSv1.x <suite>`) and has no `routingWarning`.
4. Traffic: five 1000-byte pings from the host side to the server's tunnel address succeed, and both byte counters grow by at least 5000.
5. Routing: the main table differs from before only by the kernel's connected route of the tunnel subnet (SPEC §6); `ip rule` has `7194: from <vpn-ip> lookup 7194` (variant A also `7180: from all to 10.99.0.0/24 lookup 7194`); table 7194 holds only `default dev tdvpn0`. Variant A: the host pings `10.99.0.1` behind the server.
6. Host protection: `INPUT` jumps to `TUNNELDECK-INPUT` first and that chain ends with `DROP` (and the unused backend holds no TunnelDeck-VPN rule). From the probe, the UI port 8194 and a listening dummy service (TCP 9000) are unreachable; an inbound firewall rule to this device for 8194 is refused (`validation_failed`); a rule for 9000 makes it reachable while 8194 stays closed; removing the rule closes it again.
7. Remote access: enabling HTTPS remote access (port 8443, self-signed) makes `https://<vpn-ip>:8443/api/session` answer 200 with `Strict-Transport-Security: max-age=31536000` from the probe, while 8194 stays closed; disabling closes 8443 again. Login rate limits (SPEC §8, §8.1), in the first scenario only (variant A on the first backend; they depend on neither) and adding about 20 s: wrong logins on `https://<vpn-ip>:8443/api/login` from ten addresses `198.18.1.1`–`.10` added to the server's loopback each answer 401 with `Retry-After: 10`, the tenth with 60 (the remote lock starts); an eleventh address gets 429 `rate_limited_remote`. Meanwhile the LAN listener, reached from the server's own network address, answers a wrong login with 401 `Retry-After: 10` and the next attempt with 429 `rate_limited`; after the wait the next wrong login gets 401 `Retry-After: 20` and then 429 again. Audit log (SPEC §8.2): a login without `X-TunnelDeck-Request` on the LAN listener answers 403 with the security headers (CSP, `X-Frame-Options`, `nosniff`), and `GET /api/audit?filter=security` then lists `csrfRejected` and `rateLimited` on `lan` and `remoteLocked` and `remoteLockStarted` on `remote`, none with a username, with `recentWarnings` ≥ 4.
8. Disconnect: main table and rules are exactly as before; variant A: `10.99.0.1` is no longer reachable.
9. Restart: connect, `docker compose restart` the TunnelDeck-VPN container, sign in again; the tunnel comes back by itself, routing is as in step 5 and the firewall is installed.

Variant D (`D-wireguard`, on every backend) runs steps 3–9 with these differences:

- The profile is created from form fields; `GET /api/profiles/{id}` shows `secrets.privateKey.hasValue` and `derived.publicKey` equal to the generated public key, never the private key.
- Connect means the first handshake. The status names `ChaCha20-Poly1305` as data cipher, no control channel, no message code and no `routingWarning`; no log line holds the private key.
- Step 4 pings from the VPN IP (`ping -I`): the address sits on `tdvpn0` as /32, so the main table has no route to the tunnel subnet.
- Step 5: the main table does not change at all (no connected route, SPEC §18). The allowed IPs: `10.99.0.0/24` becomes `7180: from all to 10.99.0.0/24 lookup 7194`, `0.0.0.0/0` adds no rule.
- Step 8 also checks that `tdvpn0` is gone.
- Step 9 uses a second profile imported from a wg-quick `.conf` (`POST /api/profiles/import`) with the same keys plus `DNS`, an IPv6 address and `::/0`, without `PersistentKeepalive`: the draft has the notes `dns_ignored`, `ipv6_ignored` and `keepalive_default`, nothing rejected or missing, and connects.

`D-wireguard-no-handshake` (first backend only, as it waits about 30 s and does not depend on the iptables backend): a profile with a wrong server public key stays `connecting`, and the status gets `messageCode` `wireguard_no_handshake` no earlier than 25 s after the connect (30 s in the driver; Docker Desktop's VM clock runs a few percent fast against the host).

`D-wireguard-psk` (first backend only): `peer.sh` gives the server's peer a pre-shared key as well. A profile with another pre-shared key stays `connecting` without an error for 8 s (two handshake initiations) and the server reports no handshake (`wg show wg0 latest-handshakes`); a profile with the same key shows it only as `hasValue`, connects, carries the pings of step 4 and the server reports the handshake.

Variant E (`E-ipsec-*`) runs every sign-in method on the first backend and `E-ipsec-psk` on the others: the iptables backend matters only for the routing and the firewall, which all methods share. Each case:

- creates the profile from form fields; `GET /api/profiles/{id}` and `GET /api/profiles` show every secret only as `hasValue: true`, never its value;
- connects: state `connected` within 60 s, the VPN IP from the connection's pool; the status names `AES_GCM_16-256` as data cipher and the control channel starts with `IKEv2 ` or `IKEv1 `; no routing warning, no message code;
- pings the gateway's address from the VPN IP and expects both byte counters to grow by at least 5000;
- routing as variant D: the main table does not change at all (the virtual IP sits on `tdvpn0` as /32), `7194: from <vpn-ip> lookup 7194`, `7180: from all to 10.99.0.0/24 lookup 7194`, table 7194 only `default dev tdvpn0`; the host pings `10.99.0.1` behind the gateway;
- public IP (SPEC §6.1): where the negotiated remote subnets do not cover `0.0.0.0/0` (certificate, IKEv1), the log of this tunnel says that the public IP is not detected, has no line about a detection and the status has no public IP; the full tunnels never log that note;
- disconnects: `tdvpn0` is gone, the main table and the rules are exactly as before, no `charon` process is left and `10.99.0.1` is unreachable;
- neither the connection log nor the container's output (log level debug) holds a secret of the profile.

These cases depend on the gateway and the driver only and run on the first backend:

- `E-ipsec-psk-wrong-key`: a wrong pre-shared key ends in state `error` with `auth_failed`; the gateway logged exactly one IKE_AUTH request (fragments of a fragmented request not counted), also 10 s later, and the state stays `error` (no retry storm). Deleting the profile leaves the connection `disconnected` without `charon`.
- `E-ipsec-psk-proposal-mismatch`: only `aes128-sha256-modp2048` as IKE proposal ends in state `error` with `proposal_mismatch` and stays there.
- `E-ipsec-certificate-wrong-ca`: the certificate profile with a CA the test generates, which did not issue the gateway's certificate, ends in state `error` with `auth_failed` and a message about the gateway's certificate (the driver's mapping of charon's certificate alert, here "has no trusted issuer"); the gateway logged exactly one IKE_AUTH request, also 10 s later, and the state stays `error`.
- `E-ipsec-psk-sa-lost`: with the tunnel connected, TunnelDeck's UDP to the gateway is dropped (`OUTPUT`) and the gateway deletes the IKE SA (`swanctl --terminate --ike psk --force`); its DELETE still arrives, so the state becomes `reconnecting` within 30 s. After lifting the block the tunnel is `connected` again with a VPN IP of the pool, the routing of a connected tunnel, traffic through it, and the gateway lists exactly one established IKE SA; after the disconnect nothing is left.
- `E-ipsec-psk-restart`: `docker compose restart` under a connected tunnel; the tunnel comes back by itself with the routing and the firewall, one `charon`, no `ip rule` or `INPUT` jump twice, and traffic; after the disconnect `tdvpn0`, the rules and `charon` are gone.

## Firewall topology

The firewall cases (SPEC §16) add a LAN behind TunnelDeck-VPN. They use variant A without remote networks, so only the outbound rules' policy routing sends LAN traffic into the tunnel, and run on both backends: `tunneldeck-lan-nft` (only nf_tables) and `tunneldeck-lan-legacy` (only legacy).

```
   VPN side (server-a's namespace)              TunnelDeck "host"                 LAN 10.95.0.0/24
   ┌──────────────────────────────┐   tunnel   ┌────────────────────────┐   ┌──────────────────────────┐
   │ server-a  tun0 10.94.1.1     │ ◀────────▶ │ tunneldeck-lan-nft     │   │ lan-web    10.95.0.10    │
   │ probe     198.18.0.1 (lo)    │            │   LAN 10.95.0.2        │◀─▶│  HTTP :80, /cgi-bin/     │
   │ remote0   10.99.0.1/24       │            │ tunneldeck-lan-legacy  │   │  source = client address │
   │ peer-ipsec 198.18.0.2 (lo)   │            │   LAN 10.95.0.3        │   │ lan-ipsec  10.95.0.20    │
   │  inner0   10.96.2.1/24       │            │ ip_forward=1           │   │  inner0 10.96.1.1/24     │
   └──────────────────────────────┘            └────────────────────────┘   └──────────────────────────┘
```

- The LAN network is a Docker bridge with a fixed subnet. `lan-web` and `lan-ipsec` get their default route via the TunnelDeck-VPN under test (set by the test), as LAN devices that use the host as gateway. The test image `node/` (Alpine, busybox httpd, strongSwan 6.0, iproute2) serves all three nodes.
- `peer-ipsec` shares server-a's network namespace (`network_mode: service:server-a`): it sits on the VPN side like the probe and reaches the LAN router only through the tunnel's address, the "public address" the server sees.
- The two LAN TunnelDecks listen on `0.0.0.0:8194` (`TUNNELDECK_LISTEN`): with two networks the default-route address need not be the one Docker publishes the port to. The firewall keeps the UI port closed to the tunnel as before.
- Each starts with `testdata/settings-v1.json` (schema version 1, two host-access rules, the test admin's argon2id hash) copied to `/data` on the first start, so the migration runs against a real file.
- Both refuse the `ip rule` selectors `ipproto`, `sport` and `dport`, which Linux 4.4 (DSM 7.2) lacks: `testdata/linux44-ip.sh` is installed as `/usr/local/sbin/ip` in front of the real one. `tunneldeck-lan-nft` also lacks CONNMARK (`testdata/no-connmark-iptables.sh` in front of `iptables-nft`), so its port forwards route their replies by source address; `tunneldeck-lan-legacy` routes them by connection mark.

## Firewall assertions per backend

Each case is a subtest of `firewall-lan-nft` and `firewall-lan-legacy`:

1. `self-checks`: every self-check passes, `ip-forward` included, except `reply-routing`, which warns on `tunneldeck-lan-nft` (no CONNMARK), and `lan-subnets` names 10.95.0.0/24; `GET /api/firewall` reports the LAN and `ipForward: true`.
2. `migration-v1`: before any change `settings.json` still has `schemaVersion: 1`; `GET /api/firewall` lists the two host-access rules as inbound rules to the host (`Host port 5001/tcp`, `Host port 161/udp` with its source and disabled state, IDs and comments kept) with every protection on; saving them unchanged writes `schemaVersion: 2` with `firewall` and without `hostAccessRules`, and the rules read back the same.
3. `port-forward-masquerade`: public port 8080 → `lan-web:80`; the probe gets lan-web's answer through the tunnel address, and lan-web saw TunnelDeck's LAN address as client. The reply needs policy rule 7191 too: after the reverse NAT its destination is the probe. `ip rule` has `7191: from all fwmark 0x7194/0xffff lookup 7194` (lan-legacy) or `7191: from 10.95.0.10 lookup 7194` (lan-nft), and no rule uses `ipproto`/`sport`/`dport`.
4. `port-forward-keep-source`: the same rule with `keepSourceAddress`; lan-web saw the probe's address `198.18.0.1` and answered through TunnelDeck (policy rule 7191, checked as in 3).
5. `port-forward-source-restriction`: the rule with source 203.0.113.0/24 gives the probe no answer.
6. `port-forward-any-port`: a TCP forward to lan-web without a port; the probe gets lan-web's answer on port 80 of the tunnel address, while TCP 8194 (the web UI port, on which lan-web listens for this case) stays closed through the tunnel.
7. `outbound-policy-routing`: an outbound rule `10.95.0.10 → 10.99.0.0/24` (protocol any) adds `7190: from 10.95.0.10 to 10.99.0.0/24 lookup 7194`; lan-web pings 10.99.0.1 behind the server, lan-ipsec (no rule) does not.
8. `ipsec-nat-t`: `POST /api/firewall/templates/ipsec` for 10.95.0.20 with peer 198.18.0.2 returns five rules (inbound ones keep the source), which are saved as the firewall. Both strongSwan endpoints load an IKEv2 PSK connection (AES-GCM, ECP-256; IDs, not addresses, since the addresses differ by NAT). `peer-initiates`: peer-ipsec initiates to the tunnel address; `lan-initiates`: lan-ipsec initiates to 198.18.0.2 (outbound rules). Each time both sides list the SA as `ESTABLISHED`/`INSTALLED` and `TUNNEL-in-UDP`, and the inner networks 10.96.1.0/24 and 10.96.2.0/24 ping each other in both directions. TunnelDeck masquerades the LAN router behind the tunnel address, so IKE always detects NAT and uses NAT-T (UDP 4500); raw ESP never occurs with IKE in this setup.
9. `esp-forwarding`: the template's ESP forward with plain ESP (protocol 50): manually keyed tunnel-mode SAs (`ip xfrm`, AES-GCM) between 198.18.0.2 and the tunnel address on the peer and between 198.18.0.2 and 10.95.0.20 on lan-ipsec; the peer pings lan-ipsec's inner address 10.97.1.1 from 10.97.2.1. The answer proves the ESP packet reached lan-ipsec with the peer's own source and the reply ESP went back through the tunnel.
10. `kill-switch`: with lan-web's outbound rule and the port forward, the test gives the host its own route to 10.99.0.0/24 via server-a outside the tunnel (and server-a a route back), plus a counting rule in `mangle POSTROUTING` (a chain TunnelDeck never touches) for lan-web's packets to that network leaving by any interface but `tdvpn0`. Then the tunnel drops: OpenVPN's UDP is blocked in `OUTPUT` and the OpenVPN process is killed, so the state leaves `connected` and `tdvpn0` disappears while TunnelDeck keeps reconnecting. lan-web's pings get no answer and the counter stays at 0; the port forward does not answer. After lifting the block the tunnel comes back, lan-web reaches 10.99.0.1 and the forward answers again. After a disconnect the pings again get no answer with 0 leaked packets. Control: without the outbound rule the same pings take the host's route, get answers and are counted, which proves both the leak path and the counter work.
11. `outbound-policy-routing-wireguard`: case 7 over WireGuard. After the kill switch the host connects a WireGuard profile to `server-wg` with the only allowed IP `0.0.0.0/0` (no remote network); with lan-web's outbound rule, lan-web pings 10.99.0.1 behind `server-wg`, lan-ipsec does not.
12. `ipsec-net-to-net`: after the WireGuard case the host connects a net-to-net IPsec profile to `server-ipsec` (local subnet `10.95.0.0/24`, remote subnet `10.98.0.0/24`) with an outbound rule for lan-web to `10.98.0.0/24`. The status has no VPN IP, `ip rule` has `7099: from all to 10.98.0.0/24 lookup 7194` and no rule at 7194. The gateway's web server on `10.98.0.1` sees lan-web's own address `10.95.0.10` and, for a request from the host itself, the host's LAN address: nothing is masqueraded. After the disconnect `tdvpn0` and rule 7099 are gone.
13. `kill-switch-wireguard` (`firewall-lan-nft` only: the kill switch depends on the firewall backend, which case 10 covers on both hosts): case 10 over a WireGuard tunnel to `server-wg` (allowed IP `0.0.0.0/0`), with the leak path via `server-wg`. The driver counts a tunnel as lost only after 180 s without a handshake and keeps `tdvpn0` meanwhile (SPEC §18), so the case simulates the loss instead of waiting: first `server-wg` takes its `wg0` down; the state stays `connected`, lan-web's pings get no answer, nothing leaks and the forward does not answer. Then the test deletes TunnelDeck's `tdvpn0`: the driver reports the device's end, the state leaves `connected` and the manager starts the tunnel again, which stays `connecting` without the server, so table 7194 has no route and only the kill switch keeps lan-web's traffic from the host's route; again no answer, no leak. After `wg0` is up again the tunnel connects, lan-web reaches 10.99.0.1 and the forward answers; the disconnect and the control run as in case 10.

Duration of the firewall cases: 99 s on `firewall-lan-legacy` and 145 s on `firewall-lan-nft` (Docker Desktop on Windows, 2026-11-26), about 10 s of each the WireGuard case, 4 s the IPsec net-to-net case, 34 s the kill switch (reconnect backoff), and on `firewall-lan-nft` 42 s the WireGuard kill switch (case 13: the probes against the dead tunnel, the manager's retry and the handshake); most of the rest are the IPsec handshakes.

## Not covered

- A real Linux 4.4 kernel (DSM 7.2): the LAN TunnelDecks only emulate its missing `ip rule` selectors and, on `tunneldeck-lan-nft`, a missing CONNMARK target, on the build machine's kernel.
- The daily reconnect (SPEC §4.3).
- Firewall: a real LANCOM (or other vendor's) IPsec router, IKEv1, certificates for IPsec, GRE forwarding, port ranges and shifted public ports, drop/reject rules, ICMP rules, the global protections' limits (SYN flood, ping limit) under load, and the web UI's Firewall page.
- A real `network_mode: host` deployment on a physical host, and interplay with ufw, firewalld or Docker's own chains (ufw was checked once by hand in a container lab; see `docs/linux.md`).
- arm64 (the test runs on the build machine's architecture only).
- Uploaded remote-access certificates, `.ovpn` import and the web UI itself.
- OpenVPN: a wrong CA, an unreachable server and the backoff timing.
- WireGuard: the 180 s detection of a lost tunnel and the reconnect after it (case 13 simulates the loss by deleting `tdvpn0`), DynDNS re-resolution and real WireGuard providers.
- IPsec (variant E): real gateways (LANCOM, FRITZ!Box, OPNsense, pfSense, Sophos), a wrong gateway identity, `ts_unacceptable`, `no_virtual_ip`, a gateway that vanishes without a DELETE (found by DPD after 30 s plus charon's retransmissions, about three minutes; `E-ipsec-psk-sa-lost` lets the gateway delete the SA instead), rekeying, PEM client certificate and key (PKCS#12 only), and host protection and remote access over an IPsec tunnel (they depend only on `tdvpn0`, which the other variants cover). The FRITZ!Box user access was tested by hand (`docs/ipsec.md`, section 4).
