# OpenVPN notes (task 2)

Research results that the OpenVPN driver (`internal/vpn/openvpn`) must follow: config renderer, `.ovpn` importer, process supervisor and management client. Researched on 2026-11-25.

Every claim is tagged:

- **VERIFIED (how)**: checked in the shipped package, in its documentation or source, or in the container lab described below.
- **UNVERIFIED**: inferred or unchecked. Treat it as an assumption.

**Container lab.** Docker Desktop 29.9.3 (WSL2 kernel 6.18), user-defined bridge network. The client was `alpine:3.24.4` with `apk add openvpn` (2.7.9-r0), running with `NET_ADMIN` and `/dev/net/tun`. A small Python harness drove the management unix socket. Two lab servers emulated the mdex level-20 server: OpenVPN 2.7.9 (Alpine 3.24.4) and OpenVPN 2.4.12 (Alpine 3.12), each with `cipher none`/`data-ciphers none`, `auth none`, `tun-mtu 1500`, `fragment 1448`, `mssfix` and `reneg-sec 86400`. Each server checked username and password with `auth-user-pass-verify` and pushed `redirect-gateway def1`, a route and a DNS option. A throwaway openssl CA signed a server certificate with KU and EKU `serverAuth`. Tests that pass data used ping through the tunnel. The real mdex server was **not** contacted: it was not reachable for testing, and logging in to it with test values was not acceptable.

---

## 0. Version and build facts

| Fact | Status |
|---|---|
| Alpine 3.24 ships **OpenVPN 2.7.9** (package `openvpn-2.7.9-r0`, `main`, built 2026-11-24). | VERIFIED: pkgs.alpinelinux.org, plus `openvpn --version` in `alpine:3.24.4` → `OpenVPN 2.7.9 x86_64-alpine-linux-musl [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]`, OpenSSL 3.5.9, LZO 2.10 |
| The Dockerfile pins the base image only. `apk add openvpn` installs whatever 2.7.x is current in the 3.24 branch at build time. Everything here was checked against 2.7.9-r0. | VERIFIED: Dockerfile and package index |
| APKBUILD configure flags: `--enable-dco --enable-pkcs11 --disable-dns-updown-by-default`. LZO and LZ4 are not disabled. | VERIFIED: aports `3.24-stable/main/openvpn/APKBUILD` |
| Compile-time defines include `enable_fragment='yes' enable_lzo='yes' enable_lz4='yes' enable_comp_stub='no' enable_iproute2='no' enable_management='yes' enable_dco='yes' enable_dns_updown_by_default='no'`. | VERIFIED: `openvpn --version` |
| Runtime deps: `iproute2-minimal` (APKBUILD comment: "needs just /sbin/ip"), libnl-3/libnl-genl-3 (DCO), libcap-ng, lz4, lzo2, pkcs11-helper, OpenSSL 3. | VERIFIED: `apk info -R openvpn` |
| `openvpn-doc` ships `Changes.md`, `management-notes.txt` and the man page. All doc references below are to these 2.7.9 files. | VERIFIED: `apk info -L openvpn-doc` |

**No other OpenVPN version needs to be pinned.** 2.7.9 can do everything the mdex connection needs (section (a)). VERIFIED in the lab.

---

## (a) No data-channel encryption against a `cipher none` / `auth none` server

**Answer.** In 2.7.9, `cipher none` on the client does nothing for negotiation. Encryption is turned off by putting `none` into `data-ciphers` and setting `auth none`. Recommended directives:

```
data-ciphers none:CHACHA20-POLY1305
data-ciphers-fallback none
auth none
```

Details:

1. **`--cipher` is ignored in TLS mode for choosing the cipher.** The client prints `DEPRECATED OPTION: --cipher set to 'none' but missing in --data-ciphers (DEFAULT). OpenVPN ignores --cipher for cipher negotiations.` VERIFIED: man page `--cipher` ("Starting with 2.6.0, this option is always ignored in TLS mode"); `options.c` `options_postprocess_cipher()`; lab log.
2. **The RUT240 options pasted as they are fail against a server that offers only `none`.** The server answers `AUTH_FAILED,Data channel cipher negotiation failed (no shared cipher)`. The client announces `IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305` and so has no cipher in common with the server. VERIFIED: lab, 2.7.9 client with RUT240 options against a 2.7.9 server with `data-ciphers none`.
3. **`none` is allowed in `--data-ciphers`.** Every start prints the warning `WARNING: cipher 'none' specified for --data-ciphers. ... PLEASE DO RECONSIDER THIS SETTING!` (log flag `W`). After connecting, OpenVPN logs `Data Channel: cipher '[null-cipher]', auth '[null-digest]'`. VERIFIED: `ssl_ncp.c` `mutate_ncp_cipher_list()`; lab.
4. **How the cipher is chosen** (client side, `ssl_ncp.c` `check_pull_client_ncp()`, VERIFIED source):
   - If the server pushes `cipher X`, X must be in the client's `data-ciphers`.
   - Otherwise "poor man's NCP" applies. The server's OCC options string carries `cipher [null-cipher]` (mapped to `none` in `ssl.c`), and that cipher is used if it is in `data-ciphers`. The log shows `Using peer cipher 'none'`.
   - Otherwise `data-ciphers-fallback` is used. This matters only for 2.3-era servers built without OCC strings.
5. **Negotiation matrix** (all VERIFIED in the lab, with ping through the tunnel):

   | Server | Client `data-ciphers none` + fallback none | Client `data-ciphers none:CHACHA20-POLY1305` + fallback none | Client with RUT240 options (`cipher none`, default data-ciphers) |
   |---|---|---|---|
   | 2.7.9, `data-ciphers none` | none ✔ | none ✔ | AUTH_FAILED (no shared cipher) ✘ |
   | 2.7.9, `data-ciphers CHACHA20-POLY1305:AES-256-GCM` | AUTH_FAILED ✘ | CHACHA20-POLY1305 ✔ (encrypted) | (not tested) |
   | 2.4.12, `cipher none`, NCP on (default) | none ✔ | none ✔ | **AES-256-GCM** pushed by server ✔ (encrypted) |
   | 2.4.12, `cipher none`, `ncp-disable` | none ✔ | none ✔ | (not tested) |

   With `none:CHACHA20-POLY1305` the data channel is unencrypted whenever the server permits `none`. If the server does not permit it, the client falls back to ChaCha20. This list does not contain both AES-GCM ciphers, so the client does not send `IV_NCP=2`, and a 2.4 server does not push AES-GCM. VERIFIED: lab; `IV_NCP` rule in man page "OpenVPN 2.4 server" section.
6. **mdex's own guidance matches this.** The mdex FAQ lists public.IP level 20 (`publicip20.mdex.de`) as `cipher none (or CHACHA20-POLY1305)`, `auth none`. It marks level 20 "nicht mehr verwenden" (no longer to be used). Level 30 (`publicip30.mdex.de`) uses `data-ciphers none:CHACHA20-POLY1305`, `auth none`, `tls-version-min 1.3` and CA `mdexCA30.crt`. mdex's ready-made level-30 router `.ovpn` (release 1.1, 2025-09-22) contains exactly `data-ciphers none:CHACHA20-POLY1305` and `auth none`. VERIFIED: wiki.mdex.de pages and file listed in Sources.
7. **`auth` must match the server.** For non-AEAD data channels (`none`, CBC) the HMAC digest set by `--auth` is not negotiated. `auth` is not pushable (`VERIFY_PERMISSION(OPT_P_GENERAL)` in `options.c`), and the man page says protocol options "must be configured in a compatible way" on both sides. For AEAD ciphers `--auth` is ignored. VERIFIED: man page `--auth`, source. What happens on an `auth` mismatch (HMAC failures, no traffic) is UNVERIFIED in the lab.
8. **Side effect of `none`: renegotiation every 64 MB.** OpenVPN treats `none` as a small-block cipher and logs `WARNING: cipher with small block size in use, reducing reneg-bytes to 64MB to mitigate SWEET32 attacks.` The client therefore renegotiates TLS after every 64 MB, re-sending the cached credentials. An explicit `reneg-bytes 0` suppresses this, because only an unset value (-1) is lowered. VERIFIED: lab log; `ssl.c` `tls_limit_reneg_bytes()`. Whether mdex minds frequent renegotiation is UNVERIFIED. The safe default is not to set `reneg-bytes`, which behaves like any 2.4+ client.
9. **Is the RUT240 tunnel really unencrypted today?** UNVERIFIED. Row 3 of the matrix shows that a server which pushes a cipher overrides the client's "Encryption: None". The RUT240's OpenVPN log, or the old `alpine:3.20` container's log, would show the actual `Data Channel: cipher ...` line.
10. Deprecations around (a): `ncp-disable` was removed in 2.6, `--secret`/static-key mode is disabled by default in 2.7, `compat-mode` exists but is not needed here. VERIFIED: man page, section "UNSUPPORTED OPTIONS"; `Changes.md` 2.6/2.7.

---

## (b) `fragment` and `comp-lzo`: still compiled in?

| Item | Finding | Status |
|---|---|---|
| `fragment` | Compiled in (`enable_fragment='yes'`). `fragment 1448` with `tun-mtu 1500` and bare `mssfix` passes 3000-byte pings through the tunnel. The only cosmetic issue is the warning `WARNING: if you use --mssfix and --fragment, you should use the "mtu" flag for both or none of of them.` (flag `W`). Bare `mssfix` inherits `fragment`'s value (man `--mssfix`). `fragment` disables DCO (`Note: --fragment disables data channel offload.`). | VERIFIED: version defines, lab ping, man, `dco.c` |
| LZO/LZ4 | Compiled in (`[LZO] [LZ4]`, `enable_comp_stub='no'`). | VERIFIED |
| `comp-lzo` / `compress` | Still parsed, but **2.7 never compresses outgoing packets**. It only decompresses incoming ones. `comp-lzo` (= `yes`/`adaptive`) enables LZO framing and receive-side decompression; `comp-lzo no` gives stub framing only. A warning is logged: `WARNING: Compression for receiving enabled. ... deprecated`. `--allow-compression yes` maps to `asym` with a `DEPRECATED OPTION` warning. | VERIFIED: man `--comp-lzo`/`--compress`/`--allow-compression`; `Changes.md` 2.7 "Compression on send has been removed"; `options.c`; lab |
| Framing must match the server exactly | Against a server **without** compression (mdex level 20 unencrypted: "LZO nicht gesetzt"), both `comp-lzo` and `comp-lzo no` connect but carry **no traffic** (100 % ping loss): the handshake succeeds and the data path silently fails. Against a 2.4 server with `comp-lzo yes`, or with `comp-lzo no`, client `comp-lzo` works. Without any compression directive the client gets no traffic from either. Client `comp-lzo no` works only with a `comp-lzo no` server. | VERIFIED: lab, all four combinations, ping |

Consequence: profile `compression: none` must render **no** compression directive. Profile `lzo` renders `comp-lzo`, which covers both `comp-lzo yes` and `comp-lzo no` servers.

---

## (c) Management interface over a unix socket

### Directives

```
management /run/tunneldeck/mgmt.sock unix
management-hold
management-query-passwords
auth-user-pass
auth-retry none
```

- `auth-user-pass` with no file argument, together with `management-query-passwords`, makes OpenVPN ask for the credentials over management. No password file exists. VERIFIED: lab.
- `management-hold` makes OpenVPN wait for `hold release` before it does anything, at startup **and after every internal restart**. "The hold flag setting is persistent and will not be reset by restarts." VERIFIED: management-notes "COMMAND -- hold"; lab shows `>HOLD:` again after SIGUSR1, `tls-error`, `ping-restart` and `auth-failure`.
- The socket is created with mode **0777** (`srwxrwxrwx root root`) whatever the umask. Access control therefore comes from the directory: create `/run/tunneldeck` with mode 0700. `management-client-user`/`-group` only filter the peer UID/GID. With everything running as root in the container they add nothing; `management-client-user root` parses fine. A management password (`pw-file`) is not needed for unix sockets. VERIFIED: lab `ls -l`; man `--management`.
- A stale socket file left from a crash is replaced at startup, and the socket is deleted on a clean exit. VERIFIED: lab.
- Only one management client can be connected at a time. After `quit`, or a disconnect, OpenVPN keeps running and listens again. VERIFIED: management-notes "COMMAND -- exit, quit". Keeping the tunnel alive after the client goes away was not tested in the lab: UNVERIFIED.

### Wire format (VERIFIED: lab transcript, `manage.c`)

- Line-based, **every line from OpenVPN ends in `\r\n`**. Commands to OpenVPN end in `\n`.
- On connect: `>INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info`, then, if held, `>HOLD:Waiting for hold release:0`.
- Lines starting with `>` are real-time notifications (`>STATE:`, `>LOG:`, `>BYTECOUNT:`, `>HOLD:`, `>PASSWORD:`, `>FATAL:`, `>INFO:`, ...). All other lines answer the last command: `SUCCESS: ...`, `ERROR: ...`, or a block of lines ending with `END`. Real-time lines **interleave** with command replies. For example, `>LOG:...,D,MANAGEMENT: CMD 'bytecount 5'` arrives before that command's `SUCCESS:`. Route `>` lines to an event stream and match all other lines to pending commands in FIFO order. VERIFIED: lab.
- `state on all` / `log on all` reply with `SUCCESS: ...`, then **history lines without the `>STATE:`/`>LOG:` prefix**, then `END`. To keep the parser simple, send `state on` and `log on` (no history) while still held. Nothing tunnel-related has happened yet at that point. The startup banner and warnings also go to the child's stdout.

### Recommended dialogue (VERIFIED: lab, start to finish)

```
<- >INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info
<- >HOLD:Waiting for hold release:0
-> state on
-> log on
-> bytecount 5
-> hold release
<- SUCCESS: real-time state notification set to ON
<- SUCCESS: real-time log notification set to ON
<- SUCCESS: bytecount interval changed
<- SUCCESS: hold release succeeded
<- >PASSWORD:Need 'Auth' username/password
-> username "Auth" "<escaped user>"
-> password "Auth" "<escaped password>"
<- SUCCESS: 'Auth' username entered, but not yet verified
<- SUCCESS: 'Auth' password entered, but not yet verified
<- >STATE:1795632689,RESOLVE,,,,,,
<- >STATE:1795632689,WAIT,,,,,,
<- >STATE:1795632689,AUTH,,,,,,
<- >STATE:1795632689,ASSIGN_IP,,10.66.0.2,,,,
<- >STATE:1795632689,CONNECTED,SUCCESS,10.66.0.2,172.20.0.2,1194,,
<- >BYTECOUNT:4172,2327
...
-> signal SIGTERM
<- SUCCESS: signal SIGTERM thrown
<- >LOG:1795632694,I,SIGTERM received, sending exit notification to peer
<- >STATE:1795632697,EXITING,exit-with-notification,,,,,
   (socket closes, process exits with code 0)
```

### Credentials: quoting and escaping

VERIFIED: management-notes "Command Parsing"; `options_parse.c` `parse_line()`; lab password `p a"s\s'w#rd;$x` accepted by the server's verify script.

- Always send `username "Auth" "<v>"` and `password "Auth" "<v>"`. Inside the double quotes, escape `\` as `\\` and `"` as `\"`. Leave everything else as it is: spaces, `'`, `#`, `;`, `$` and UTF-8 bytes.
- Any other backslash sequence makes OpenVPN reject the whole line ("Bad backslash usage"). An unquoted token starting with `#` or `;` is treated as a comment, **even when backslash-escaped**. Never send unquoted values.
- Limits: each parameter can be at most **255 bytes** after unescaping (`OPTION_PARM_SIZE 256`, "Parameter ... is too long"). A management input line can be at most 1024 bytes (`command_line_new(1024)`). Newlines are impossible. Longer passwords (up to `USER_PASS_LEN` 4096) need the base64 multi-line form: the client must first send `version 5` or higher, and OpenVPN must be ≥ 2.7.2 (management version 6). VERIFIED: source and docs; the multi-line form was not lab-tested.
- An empty password is accepted (`""` is translated internally to a blank tag). VERIFIED: `manage.c` `man_query_password()`.
- OpenVPN logs the command as `MANAGEMENT: CMD 'password [...]'` (masked). The **username is logged in clear text** at verb 3 (`MANAGEMENT: CMD 'username "Auth" "tduser"'`). VERIFIED: lab.
- No `version` command is needed. With a client version ≥ 6, 2.7.9 may append ` UN:<base64-user>` to the prompt when a username is preset. TunnelDeck never presets one. VERIFIED: management-notes example 10; `Changes.md` 2.7.9.
- With an encrypted private key (certificate mode) `management-query-passwords` also prompts `>PASSWORD:Need 'Private Key' password`, answered with `password "Private Key" "..."`. VERIFIED: management-notes example 1; not lab-tested.
- A passphrase-protected PKCS#12 bundle (`<pkcs12>` inline, base64) uses the same prompt: OpenVPN first tries an empty password and then asks through the private-key password callback, i.e. `>PASSWORD:Need 'Private Key' password`. The driver answers it with the profile's `keyPassphrase`, as for a PEM key. The prompt comes after `hold release`, when the TLS context is set up, before any packet is sent. VERIFIED: lab 2026-11-26 (`alpine:3.24.4`, `openvpn~2.7`): an openssl-made `.p12` with passphrase, inline as `<pkcs12>` with `base64 -w 64` content, gave `>PASSWORD:Need 'Private Key' password`; after `password "Private Key" "..."` OpenVPN went on to the UDP link (no server was contacted).
- Static-key mode (`secret`, `<secret>`) is not supported (SPEC §17): the importer reports it as `static_key_unsupported` and extra options reject it.
- `tls-crypt-v2` client keys (Access Server, cloud VPN services) are accepted inline: `--tls-crypt-v2 keyfile` is a file option, and OpenVPN takes every file option as an inline `<tag>` block. The client key is the 2048-bit key plus the server-wrapped key (WKc, at most 1024 bytes), base64 between `-----BEGIN/END OpenVPN tls-crypt-v2 client key-----`. TunnelDeck stores it as the secret `tlsCryptV2Key`, renders it as `<tls-crypt-v2>` and rejects it together with tls-auth or tls-crypt. Only `tls-crypt-v2-verify` (server side, runs a script) stays forbidden. Source: OpenVPN reference manual and `doc/tls-crypt-v2.txt`; not lab-tested against a server.

### Rejected credentials

VERIFIED: lab; `push.c` `receive_auth_failed()`; `manage.c` `management_auth_failure()`.

- Wrong username or password: `>PASSWORD:Verification Failed: 'Auth'`. With `auth-retry none` the process then exits on its own after about 2 s, with **exit code 0** and state `EXITING,exit-with-notification`. There is **no `>FATAL:`**. The exit code cannot tell an auth failure from a normal stop; only the management line can.
- A server-provided reason adds ` ['<reason>']`, for example `>PASSWORD:Verification Failed: 'Auth' ['Data channel cipher negotiation failed (no shared cipher)']`. That is a **configuration** error, not a credential error, and it arrives through the same AUTH_FAILED path.
- `AUTH_FAILED,TEMP...` also produces `Verification Failed: 'Auth' ['TEMP...']`, but OpenVPN treats it as temporary and restarts (SIGUSR1) whatever `auth-retry` is set to. VERIFIED: source only.
- Classification for the app:
  - no reason → credentials rejected: stop retrying (SPEC §4.2);
  - reason starting with `TEMP` → transient;
  - any other reason → server-side rejection or configuration error: stop retrying and show the reason.

### Other real-time messages

| Message | Layout | Status |
|---|---|---|
| `>STATE:` | `>STATE:<unix-ts>,<state>,<detail>,<local tun IPv4>,<remote ip>,<remote port>,<local ip>,<local port>[,<local tun IPv6>]`. States: `CONNECTING WAIT AUTH GET_CONFIG ASSIGN_IP ADD_ROUTES CONNECTED RECONNECTING EXITING RESOLVE TCP_CONNECT AUTH_PENDING`. **Field 4 (index 3) is the VPN IPv4**, present on `ASSIGN_IP` and `CONNECTED`. `CONNECTED` detail is `SUCCESS`, `ERROR` or `ROUTE_ERROR`. `RECONNECTING`/`EXITING` detail is the reason (`SIGUSR1`, `ping-restart`, `tls-error`, `auth-failure`, `exit-with-notification`, ...). With `nobind` the local ip/port fields are empty. With `persist-tun`, `ASSIGN_IP` is not repeated on reconnect, but `CONNECTED` still carries the IP. | VERIFIED: management-notes "COMMAND -- state"; `manage.c` `log_entry_print()`; `init.c`; lab |
| `>BYTECOUNT:` | `>BYTECOUNT:<bytes_in>,<bytes_out>`, every N seconds after `bytecount N` (`bytecount 0` turns it off). Counts are **transport (link) bytes**, including OpenVPN overhead and control traffic, cumulative since process start and **preserved across internal restarts**. | VERIFIED: management-notes; `manage.c` (`man->persist.bytes_in/out`); lab |
| `>LOG:` | `>LOG:<unix-ts>,<flags>,<text>`. Flags are zero or more of `I` (info), `F` (fatal), `N` (non-fatal error), `W` (warning), `D` (debug), concatenated; often empty. **Split only on the first two commas**: the text contains commas. At `verb 3` it includes `PUSH: Received control message: 'PUSH_REPLY,...'` and echoes of state changes as `MANAGEMENT: >STATE:...`. | VERIFIED: `error.c` `msg_flags_string()`; lab |
| `>FATAL:` | `>FATAL:<text>` (no timestamp), sent just before exit, after a `>LOG:...,F,...` line. Example: `>FATAL:ERROR: Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)`; exit code 1. | VERIFIED: lab without `/dev/net/tun` |
| `>INFO:` | Banner on connect (see above). | VERIFIED |
| `>HOLD:` | `>HOLD:Waiting for hold release:<n>`, where n is the seconds OpenVPN would wait under its own connect-retry backoff (0 at start, 2 after soft restarts, 10 for `auth-retry nointeract`). | VERIFIED: lab |
| Errors before management exists | Option and parse errors (for example missing CA) happen **before** the socket exists. They go only to stdout/stderr, with exit code 1 (`Options error: You must define CA file ...`, `Exiting due to fatal error`). | VERIFIED: lab |

### Clean shutdown

- `signal SIGTERM` over management and `SIGTERM` to the PID behave the same. With `explicit-exit-notify` on UDP, OpenVPN sends `EXIT` over the control channel (`SENT CONTROL [...]: 'EXIT'`, protocol flag `cc-exit`). It exits after about 1.3–2.5 s with exit code 0. `tdvpn0` and its address are removed, even with `persist-tun`, and the socket is deleted. VERIFIED: lab.
- `SIGINT` has the same effect (man "SIGNALS"); not lab-tested.
- SIGTERM during hold exits immediately (`Signal received from management interface, exiting`). VERIFIED: lab.

---

## (d) `route-noexec`, pushed `redirect-gateway`, and `ifconfig`

- **`route-noexec` alone guarantees that OpenVPN installs no routes.** In `init.c` `do_route()`, `add_routes()` is skipped when `route_noexec` is set. `add_routes()` (`route.c`) is the only place that applies `redirect-gateway` (`redirect_default_route_to_vpn()`), `route` and `route-ipv6`. This covers both pushed and locally configured directives. `route-noexec` itself cannot be pushed: it carries the `OPT_P_SCRIPT` permission, which is not in `pull_permission_mask()`. VERIFIED: source; lab with local `redirect-gateway def1` + local `route` and pushed `redirect-gateway def1` + `route` + `dhcp-option`: main table unchanged apart from the kernel route below.
- **`route-nopull`** (rendered until task 25) additionally drops all pushed `OPT_P_ROUTE` and `OPT_P_DHCPDNS` options (`route*`, `redirect-*`, `dhcp-option`, `dns`) and keeps `ifconfig`, `topology`, `tun-mtu`, `ping*` and `cipher`. Each dropped option is logged as `>LOG:...,N,Options error: option 'redirect-gateway' cannot be used in this context ([PUSH-OPTIONS])`. These lines are **harmless** and must not be treated as fatal. VERIFIED: `init.c` `pull_permission_mask()`; lab.
- **Rendered combination (since task 25): `route-noexec` + `pull-filter ignore` instead of `route-nopull`.** In the field (mdex, OpenVPN 2.7 client) `route-nopull` filled the log with one `Options error ... ([PUSH-OPTIONS])` line per pushed `route` and `dhcp-option`. The renderer therefore drops the pushed options it does not want with `pull-filter ignore "route "`, `"route-ipv6"`, `"redirect-gateway"`, `"redirect-private"`, `"dhcp-option"`, `"dns "`, `"block-outside-dns"`, `"route-delay"` and `"ifconfig-ipv6"`, and keeps `route-noexec` as the safety net that stops routes of any origin (the man page warns that `pull-filter` "cannot be relied upon as a security measure"). `pull-filter` compares the start of each pushed option with its text (prefix match, man `--pull-filter`, which shows exactly this `"route "` example); the first matching filter wins, unmatched options are accepted. Hence `"route "` with its trailing space drops `route 10.0.0.0 255.0.0.0` but not `route-gateway`, `route-delay` or `route-ipv6` (which have their own filters, `route-gateway` none), and no filter matches `ifconfig <ip> <peer/mask>`, `topology`, `tun-mtu`, `ping*`, `peer-id` or `cipher`, so the tunnel address still applies. `"dns "` keeps the `dns` options of 2.6+ out, as `route-nopull` did. Ignored options are logged as `Pushed option removed by filter: '...'` at the push debug level, not as errors (source `options.c` `apply_pull_filter()`; UNVERIFIED in the lab). A pushed `route-delay` (mdex pushes `route-delay 6 6`) would only hold back `Initialization Sequence Completed` and the CONNECTED state, as no route is added (UNVERIFIED: inferred from man `--route-delay`). Extra options cannot add filters of their own: `pull-filter` and `route-nopull` are dropped from them (`routing_handled`). VERIFIED: man page; e2e (servers A and B push `redirect-gateway def1`, a `route` and a `dhcp-option`: no `Options error` line, main table unchanged apart from the kernel route); the prefix list is unit-tested (`TestIgnoredPushes`).
- **`ifconfig` still applies.** OpenVPN opens `tdvpn0`, sets the MTU, brings it up and adds the pushed address (`net_addr_v4_add: 10.66.0.2/24 dev tdvpn0`). VERIFIED: lab.
- **Caveat for "the main table is never modified".** Because the address is added with its prefix (`topology subnet`), **the kernel** adds a connected route to the main table: `10.66.0.0/24 dev tdvpn0 proto kernel scope link src 10.66.0.2`. It is removed when the address or device goes away. OpenVPN does not add it, and `route-noexec` cannot prevent it. With `topology net30`/`p2p` the kernel would add a host route to the peer instead (UNVERIFIED for net30; the lab used `subnet`). VERIFIED for `subnet`: lab `ip route` before, during and after. If even that route is unacceptable, the alternative is `ifconfig-noexec`: OpenVPN then leaves `tdvpn0` **DOWN and without an address**, `>STATE:...,CONNECTED,SUCCESS,<ip>,...` still reports the IP, and the app configures the interface itself:

  ```
  ip addr add <ip>/32 dev tdvpn0
  ip link set tdvpn0 up mtu 1500
  ip route replace default dev tdvpn0 table 7194
  ip rule add from <ip> lookup 7194 priority 7194
  ```

  With this the main table stays untouched and ping through the tunnel works. VERIFIED: lab. `noprefixroute` also works on kernel 6.18; on the DSM 4.4 kernel it is UNVERIFIED. Without scripts the app does not learn the netmask in this mode (only from the `PUSH_REPLY` log line), and does not need it for SPEC §6. This is a design decision for the orchestrator. The default recommended here keeps OpenVPN's `ifconfig` and accepts the kernel's connected route.
- **How the app learns the VPN IP and the gateway without scripts:**
  - VPN IP: field 4 of `>STATE:...,CONNECTED,...` (also on `ASSIGN_IP`).
  - Pushed gateway and netmask: only from the `>LOG:` line `PUSH: Received control message: 'PUSH_REPLY,...route-gateway 10.66.0.1,topology subnet,...ifconfig 10.66.0.2 255.255.255.0,...'` (verb ≥ 3, `D_PUSH`), or from `route_vpn_gateway`/`ifconfig_*` env vars in an `--up`/`--route-up` script. Scripts would need `script-security 2` and are not recommended.
  - SPEC §6 needs no gateway on a tun device (`ip route replace default dev tdvpn0 table 7194`), so **no script is needed**.

  VERIFIED: management-notes, man "Environmental Variables", `errlevel.h` (`D_PUSH` = verb 3), lab.
- `--route-table <id>` (new in 2.7) would let OpenVPN install `route`s into a user table. It does not cover `redirect-gateway`'s bypass route logic, and the app's policy routing is simpler with `route-noexec`. VERIFIED: man `--route-table`. Not recommended; noted for completeness.
- **IPv6:** a pushed `ifconfig-ipv6` is an `OPT_P_UP` option. Without a filter OpenVPN would configure it on `tdvpn0` (`route-nopull` never dropped it). Stage 1 has only IPv4 iptables host protection, so the renderer emits `pull-filter ignore "ifconfig-ipv6"`. VERIFIED (source): permission classes. Whether mdex pushes IPv6 is UNVERIFIED.

---

## (e) CA requirement with user/pass auth; mdex CA distribution

- **A CA is mandatory** in TLS client mode with `auth-user-pass`. Without `--ca`/`--capath`/`--peer-fingerprint`/`--pkcs12`, OpenVPN refuses to start: `Options error: You must define CA file (--ca) or CA path (--capath) and/or peer fingerprint verification (--peer-fingerprint)`, exit 1, before the management socket exists. VERIFIED: `options.c` `check_ca_required()`; lab.
- **Wrong CA:** the log shows `>LOG:...,N,VERIFY ERROR: depth=1, error=self-signed certificate in certificate chain ...`, then `TLS Error: TLS handshake failed`, `>STATE:...,RECONNECTING,tls-error`, then `>HOLD:` again: an endless retry loop. There is no `>PASSWORD:Verification Failed`. The app should show "server certificate not trusted" from the `VERIFY ERROR` line. VERIFIED: lab.
- `--peer-fingerprint` pins the **server leaf** certificate. It is no substitute for the mdex CA, because leaf certificates change. VERIFIED: man.
- **mdex distribution** (VERIFIED: wiki.mdex.de FAQ "Welche OpenVPN-Einstellungen sind für eine Verbindung zu mdex erforderlich?"; downloaded and inspected with `openssl x509`):
  - Level 20 (`publicip20.mdex.de`, `openvpn20.mdex.de`): **`mdexCA20.crt`**, PEM, public download `https://wiki.mdex.de/pub/Support/MdexDownloads/mdexCA20.crt`. RSA 4096, `sha512WithRSAEncryption`, self-signed. Subject `C=DE, ST=Schleswig-Holstein, L=Tangstedt, O=mdex AG, OU=mdex-ovpn20, CN=mdex AG CA`. Valid 2017-01-24 to **2037-01-19**. SHA-256 fingerprint `C8:77:C8:46:51:69:04:AC:96:39:1F:4B:F7:4E:C3:2F:69:CF:58:5A:66:7F:AD:74:69:E5:95:7C:4D:8C:FE:42`.
  - Level 30 (`publicip30.mdex.de`, `openvpn30.mdex.de`, since 08/2025): **`mdexCA30.crt`**, `https://wiki.mdex.de/pub/Support/MdexDownloads/mdexCA30.crt`. ECDSA P-384, `ecdsa-with-SHA384`. Subject `O=Wireless Logic mdex GmbH, OU=mdex-ovpn30, CN=Wireless Logic mdex GmbH`. Valid 2025-06-30 to 2045-06-25. SHA-256 fingerprint `42:B6:EF:DB:DC:0E:2C:C7:C6:EE:E1:41:0F:98:30:1C:D7:23:46:03:06:0D:7F:98:6C:A0:5A:6F:D6:CB:34:66`. Also embedded as `<ca>` in mdex's ready-made `mdex public.IP30 Router.ovpn`.
  - Credentials come from the customer's mdex account data. They are not in the `.ovpn`; it contains a commented-out `<auth-user-pass>` block.
  - Both CAs are strong enough for OpenSSL 3.5's default security level. Whether the mdex **server leaf** certificates pass OpenSSL 3.5 checks, and carry the KU/EKU that `remote-cert-tls server` needs, is **UNVERIFIED**. It is supported by the user's RUT240 working with `remote-cert-tls server`.
- `ns-cert-type server` (the mdex level-20 table lists it) still works in 2.7.9 but logs `WARNING: --ns-cert-type is DEPRECATED. Use --remote-cert-tls instead.` It is implemented as `X509_check_purpose(SSL_SERVER)`. VERIFIED: lab, `ssl_verify_openssl.c`. Prefer `remote-cert-tls server`, as on the RUT240.

---

## 1. Child process, rendered config, fixed device

- `dev tdvpn0` + `dev-type tun` works on Linux (arbitrary names are supported for tun). The log shows `TUN/TAP device tdvpn0 opened`. VERIFIED: lab, man `--dev`.
- `client` implies `pull` + `tls-client`; `nobind` is the default with `client`/`pull` since 2.6. VERIFIED: man `--client`, `Changes.md` 2.6.
- Config file lines may be at most 255 characters. At 256 OpenVPN fails with `Maximum option line length (256) exceeded`. A single parameter may be at most 255 characters. A UTF-8 BOM on line 1 is ignored. VERIFIED: `options_parse.c`, `options.h`. Inline blocks (`<ca>...</ca>`) avoid extra files; PEM lines are 64 characters. UNVERIFIED in the lab: the lab used file paths. Inline blocks are standard syntax (man "INLINE FILE SUPPORT").
- The child's stdout carries the full log with timestamps, including errors raised before management starts. Capture it. VERIFIED: lab.

## 2. Management client

All of section (c). Additions for the supervisor:

- Answer **every** `>PASSWORD:Need 'Auth' username/password` at any time, not only the first. With `auth-retry interact`, or after `forget-passwords`, it comes again. VERIFIED: lab with `interact`.
- Answer every `>HOLD:` with `hold release` (optionally after the app's own backoff delay). Otherwise OpenVPN never reconnects after an internal restart. VERIFIED: lab.
- Ignore `>LOG:` lines whose text starts with `MANAGEMENT: ` (they echo commands and states) Treat `N`-flagged `Options error: ... ([PUSH-OPTIONS])` lines as warnings: the pull filters keep the usual ones away, but a server may push other options a client does not accept. VERIFIED: lab.

## 3. Routing guarantee

See (d). Render `route-noexec` and the `pull-filter ignore` lines of (d) on every profile. Drop `redirect-gateway`, `redirect-private`, `route`, `route-ipv6` and `route-gateway` from imported or extra options with a warning; with `route-noexec` they would be inert anyway. VERIFIED: lab.

## 4. `script-security`, external binaries, sitnl

- Alpine's build uses **netlink (sitnl)**, not iproute2: `enable_iproute2='no'`, and the log shows `net_iface_mtu_set`, `net_iface_up`, `net_addr_v4_add` and `net_route_v4_add`. With `/sbin/ip` removed from the container, connect, ifconfig and data all still work. VERIFIED: version defines; lab with `/sbin/ip` renamed.
- `--iproute` does not exist in this build: `Unrecognized option or missing or extra parameter(s) ... iproute (2.7.9)`. VERIFIED: lab. (SPEC's denylist entry is harmless.)
- **No `script-security` directive is needed.** The default level 1 is enough, and no scripts or executables are invoked. Pushed DNS does not run `dns-updown`, because the Alpine build disables it by default, and `/etc/resolv.conf` stayed unchanged. VERIFIED: lab (no `script-security` in the config); APKBUILD flag.
- `iproute2-minimal` is still pulled in by the package dependency, and the Dockerfile installs full `iproute2` for `netguard`. VERIFIED: `apk info -R`.

## 5. Signals, reconnects, `persist-tun`, `explicit-exit-notify`, `auth-retry`

| Event | Behaviour (2.7.9) | Status |
|---|---|---|
| `SIGUSR1` (management `signal SIGUSR1` or kill) | Soft restart inside the same process: `>STATE:...,RECONNECTING,SIGUSR1`, `>HOLD:` (when `management-hold`), reconnect with cached credentials (no new `>PASSWORD:` unless `auth-nocache`), new `CONNECTED`. **Without `persist-tun`** `tdvpn0` is deleted and recreated (new ifindex), so all routes in table 7194 that reference it vanish and must be re-added. **With `persist-tun`** it logs `Preserving previous TUN/TAP instance: tdvpn0`; the interface keeps its ifindex, address and state while reconnecting. | VERIFIED: lab |
| `ping-restart` (server unreachable) | Same as `SIGUSR1` (`RECONNECTING,ping-restart`, then `>HOLD:`); repeats until the server answers; recovers by itself. | VERIFIED: lab (server paused for 22 s) |
| `SIGTERM` / `SIGINT` | Graceful exit with an exit notification (see (c)); exit code 0; interface removed. | VERIFIED: lab (SIGTERM) |
| `SIGHUP` | Restart that re-reads the config file. Not needed. | VERIFIED: man "SIGNALS" |
| `SIGKILL` | No exit notification; the server times out the session. The kernel removes the non-persistent `tdvpn0` when the fd closes. | UNVERIFIED (standard Linux tun behaviour) |
| `explicit-exit-notify 2` on UDP | Accepted. On exit the client sends `EXIT` over the control channel. In client mode `n` is the resend count, used only in data-channel mode. | VERIFIED: lab, man |
| `explicit-exit-notify` on TCP | Ignored with `NOTICE: --explicit-exit-notify ignored for --proto tcp`. | VERIFIED: `options.c` |
| `auth-retry none` (default) | After `Verification Failed: 'Auth'` the process exits (code 0). **Recommended.** | VERIFIED: lab |
| `auth-retry interact` | `RECONNECTING,auth-failure`, `>HOLD:`, then a fresh `>PASSWORD:Need 'Auth' ...`: the app could stop answering, but `none` is simpler. | VERIFIED: lab |
| `auth-retry nointeract` | Loops forever with the cached wrong credentials (`>HOLD:...:10` between attempts). Risks provider lockout. **Do not use.** | VERIFIED: lab |

Recommendations:
- `persist-tun`: the interface and policy routes survive reconnects, and traffic for the VPN IP blackholes instead of leaking during a reconnect.
- `auth-retry none`.
- Let OpenVPN reconnect internally on `RECONNECTING`, and use the `hold release` delay to apply SPEC §4.2's backoff.
- Kill and restart the process only after an exit.
- Allow at least 10 s between `signal SIGTERM` and `SIGKILL`.
- On Linux set `Pdeathsig` (Go: `SysProcAttr.Pdeathsig = syscall.SIGTERM`) so that OpenVPN does not outlive a crashed app. `--management-client` would achieve the same, because OpenVPN exits when the app's socket goes away, but it inverts the connection direction. Neither option was lab-tested.

## 6. DCO on the DSM/Synology kernel 4.4

- The binary is built with DCO (`[DCO]`, `enable_dco='yes'`, libnl). 2.7 supports only the new upstream `ovpn` module (Linux ≥ 6.16, or ovpn-backports). VERIFIED: version output; `Changes.md` 2.7; man `--disable-dco`.
- On a kernel without `ovpn` (the lab's WSL2 6.18 kernel has no module loaded; DSM 4.4 certainly has none) OpenVPN logs `Note: Kernel support for ovpn interfaces missing, disabling data channel offload. Use Linux 6.16.0 or newer with ovpn support or use ovpn-backports for interface support.` and falls back to tun. The mdex profile disables DCO anyway (`fragment`, cipher `none` not supported by Linux DCO, `data-ciphers-fallback none`, compression). VERIFIED: lab; `dco.c` `dco_check_option()`.
- **`disable-dco` is harmless and recommended.** It makes the interface type and behaviour (tun, `fragment`, bytecount source) identical on every host kernel, including modern test hosts where `ovpn` might be loaded. VERIFIED: parses in the lab; `options.c`.

---

## RUT240 options in OpenVPN 2.7.9

| RUT240 setting | 2.7.9 behaviour | Consequence if pasted | Status |
|---|---|---|---|
| UDP 1194, TUN | normal | ok (renderer emits `remote ... udp`; `dev`/`dev-type` are fixed by the app) | VERIFIED |
| Encryption: None (`cipher none`) | `--cipher` ignored for negotiation; `DEPRECATED OPTION` warning | **Connection fails** against a none-only NCP server (`AUTH_FAILED ... no shared cipher`), or ends up encrypted against a 2.4 NCP server. Must become `data-ciphers none:CHACHA20-POLY1305` + `data-ciphers-fallback none`. | VERIFIED: lab |
| Authentication algorithm: None (`auth none`) | supported; warning `'--auth none' was specified` | ok, must match the server | VERIFIED: lab |
| LZO: none (no directive) | ok | ok. **Any** `comp-lzo` directive against this server connects but passes no traffic. | VERIFIED: lab |
| Authentication: Password (`auth-user-pass`) | ok | Importer maps it to `authMode=password`; credentials go over management | VERIFIED: lab |
| `tun-mtu 1500` | ok (default) | ok | VERIFIED |
| `fragment 1448` | compiled in, works; disables DCO | ok; cosmetic `mssfix`/`fragment` "mtu flag" warning | VERIFIED: lab |
| `mssfix` | ok, inherits `fragment` value | ok | VERIFIED |
| `float` | ok | ok | VERIFIED: lab (parsed) |
| `nobind` | ok (default for clients) | ok | VERIFIED |
| `reneg-sec 86400` | ok (but `none` lowers `reneg-bytes` to 64 MB) | ok | VERIFIED: lab |
| `remote-cert-tls server` | ok | ok, needs server cert KU+EKU | VERIFIED: lab; mdex cert UNVERIFIED |
| `tls-version-min 1.2` | ok (already the default) | ok; level 30 uses 1.3, which also works | VERIFIED: lab |
| `explicit-exit-notify 2` | ok on UDP | ok | VERIFIED: lab |
| `fast-io` | **ignored**: `DEPRECATED OPTION: --fast-io option ignored.` | harmless warning; importer should drop it with a note | VERIFIED: lab |
| `redirect-gateway def1` | would replace the default route (0/1 + 128/1) | SPEC drops it; `route-noexec` makes it inert even if present | VERIFIED: lab |
| (mdex level 20 table) `ns-cert-type server` | deprecated, still works | prefer `remote-cert-tls server` | VERIFIED: lab |
| (common in RUT exports) `persist-key` | ignored: `DEPRECATED OPTION: --persist-key option ignored.` | harmless | VERIFIED: lab |
| `comp-lzo no` | stub framing | breaks data against a no-compression server | VERIFIED: lab |
| `allow-compression yes` | aliased to `asym` with a deprecation warning | harmless | VERIFIED: lab |

---

## Known directives

Imported directives and extra options must be on the allowlist `knownDirectives` (`internal/vpn/openvpn/known.go`); anything else is rejected as `unknown_directive` (import) or `extra_option_unknown` (validation). The denylist in `classify.go` is applied first and still decides which known directives are dropped or rejected.

- **Source.** The openvpn binary of the image, 2.7.9 (`alpine:3.24.4`, `apk add openvpn~2.7`), probed on 2026-11-26: for every option-like name from `openvpn --help` and from `strings /usr/sbin/openvpn`, `openvpn --<name> [1 [1 [1]]] --version` was run; a name counts as recognized when no argument count gives `Unrecognized option or missing or extra parameter(s)`. 287 names are recognized. `--help` alone is incomplete (it lacks e.g. `key-direction`, `persist-key`, `tls-groups`, `peer-fingerprint`, `data-ciphers-fallback`).
- **Left out** (recognized, but not for a client config): server-only options (`server`, `push`, `mode`, `ifconfig-pool`, `client-config-dir`, `duplicate-cn`, `verify-client-cert`, `tls-server`, `dh`, …), push-only and internal options (`peer-id`, `auth-token`, `key-derivation`, `protocol-flags`, `push-continuation`, …), stand-alone commands (`genkey`, `show-*`, `test-crypto`, `mktun`, `help`, `version`), the inline-only `connection` and `http-proxy-user-pass`, and options that make 2.7.9 exit (`no-replay`, `compat-names`, `no-name-remapping`, `client-cert-not-required`, `msg-channel`). Not recognized at all on Linux: `iproute`, `inetd`, `ncp-disable`. The Windows-only options (`block-outside-dns`, `register-dns`, `ip-win32`, `route-method`, `tap-sleep`, `dhcp-renew`, `dhcp-release`, `dhcp-pre-release`, `win-sys`, `show-net-up`, `allow-nonadmin`) are dropped with the info code `windows_only_ignored`, because providers ship them in files meant for every platform.
- **Credentials typed as lines.** Providers ship `<auth-user-pass>` commented out (`;<auth-user-pass>`, `;Username`, `;Password`, `;</auth-user-pass>`). Users who uncomment only the data lines turn the credentials into "directives" (`Options error: Unrecognized option ... <username>`). The importer takes uncommented lines between a commented opener or closer as username and password (`credentials_from_partial_block`) and refuses more than two (`openvpn_credentials_block_ambiguous`). Warnings and errors print a directive or file name that matches the stored username, password or key passphrase as `(hidden)`. Rendering a stored profile skips unknown extra options and logs only their line number.

---

## Sources

- Alpine package index, openvpn in v3.24: https://pkgs.alpinelinux.org/packages?name=openvpn&branch=v3.24&repo=&arch=x86_64 (2.7.9-r0)
- aports APKBUILD (GitHub mirror; gitlab.alpinelinux.org blocks automated access): https://github.com/alpinelinux/aports/blob/3.24-stable/main/openvpn/APKBUILD
- OpenVPN 2.7.9 docs as shipped in `openvpn-doc-2.7.9-r0`: `/usr/share/man/man8/openvpn.8.gz`, `/usr/share/doc/openvpn/Changes.md`, `/usr/share/doc/openvpn/management-notes.txt`
- OpenVPN source, tag v2.7.9: https://github.com/OpenVPN/openvpn/tree/v2.7.9/src/openvpn. Files used: `options.c`, `options.h`, `options_parse.c`, `ssl_ncp.c`, `ssl.c`, `push.c`, `init.c`, `route.c`, `manage.c`, `manage.h`, `dco.c`, `errlevel.h`, `error.c`, `ssl_verify_openssl.c`, `misc.h`
- mdex FAQ, required OpenVPN settings (levels 20/30): https://wiki.mdex.de/bin/view/Support/QNAOpenVPNEinstellungen
- mdex FAQ, server switch (levels 10/20/30, hostnames, dates): https://wiki.mdex.de/bin/view/Support/QNASwitchingOpenVPNServer
- mdex CA files: https://wiki.mdex.de/pub/Support/MdexDownloads/mdexCA20.crt, https://wiki.mdex.de/pub/Support/MdexDownloads/mdexCA30.crt
- mdex level-30 router profile: https://wiki.mdex.de/pub/Support/MdexDownloads/mdex%20public.IP30%20Router.ovpn

---

## Reference config (mdex public.IP level 20, as used by the RUT240)

Placeholders: `<HOST>` = `publicip20.mdex.de`; `<CA PEM>` = content of `mdexCA20.crt`. Credentials are never in the file; they are supplied over management.

VERIFIED: this exact block was run in the lab, with `<HOST>` = the emulated 2.7.9 server and `<CA PEM>` = the lab CA. Results:
- connected unencrypted: `Data Channel: cipher '[null-cipher]', auth '[null-digest]'`;
- 3000-byte pings passed;
- the main table gained only the kernel's connected route;
- exit code 0 after `signal SIGTERM`.

It is UNVERIFIED against the real mdex server.

Since task 25 the routing block holds the `pull-filter ignore` lines of (d) instead of `route-nopull`; that change was verified by the e2e test (see (d)), not in this lab run. The first real mdex connection (DS723+ on Linux 4.4) pushed `route` options, `dhcp-option DNS`, `route-delay 6 6`, a point-to-point `ifconfig` (VPN IP and peer), `cipher CHACHA20-POLY1305` and `tun-mtu 1500`, and negotiated `CHACHA20-POLY1305`, although the profile allowed `none`.

```
# rendered by TunnelDeck - do not edit
client
dev tdvpn0
dev-type tun
remote <HOST> 1194 udp
resolv-retry infinite
nobind
float
persist-tun
disable-dco

# data channel: no encryption, as configured on the server
data-ciphers none:CHACHA20-POLY1305
data-ciphers-fallback none
auth none

# link / MTU (from RUT240)
tun-mtu 1500
fragment 1448
mssfix
reneg-sec 86400
explicit-exit-notify 2

# server verification
remote-cert-tls server
tls-version-min 1.2
<ca>
<CA PEM>
</ca>

# authentication over management, no password file
auth-user-pass
auth-retry none

# routing is owned by TunnelDeck
route-noexec
pull-filter ignore "route "
pull-filter ignore "route-ipv6"
pull-filter ignore "redirect-gateway"
pull-filter ignore "redirect-private"
pull-filter ignore "dhcp-option"
pull-filter ignore "dns "
pull-filter ignore "block-outside-dns"
pull-filter ignore "route-delay"
pull-filter ignore "ifconfig-ipv6"

# management
management /run/tunneldeck/mgmt.sock unix
management-hold
management-query-passwords
verb 3
```

Level 30 variant (`publicip30.mdex.de`), per the mdex FAQ and mdex's `.ovpn`:

- CA becomes `mdexCA30.crt`;
- `tls-version-min 1.3`;
- drop `tun-mtu`/`fragment`/`mssfix`/`reneg-sec`, which mdex does not list for level 30.

Everything else is the same. Not lab-tested against the real server: UNVERIFIED.

## Directives the renderer always emits

1. `client`
2. `dev tdvpn0`
3. `dev-type tun`
4. `nobind`
5. `persist-tun`
6. `disable-dco`
7. `route-noexec`
8. `pull-filter ignore` for `"route "`, `"route-ipv6"`, `"redirect-gateway"`, `"redirect-private"`, `"dhcp-option"`, `"dns "`, `"block-outside-dns"`, `"route-delay"`
9. `pull-filter ignore "ifconfig-ipv6"` (until IPv6 host protection exists)
10. `management /run/tunneldeck/mgmt.sock unix`
11. `management-hold`
12. `management-query-passwords`
13. `auth-retry none`
14. `verb 3`
15. `remote-cert-tls server`: recommended always, because SPEC requires the server to be verified. It fails against servers whose certificate lacks the TLS-server KU/EKU. This is an orchestrator decision.
16. `<ca>` inline, always (CA is mandatory; see (e))
17. `auth-user-pass` (no argument), whenever `authMode` includes password

## Consequences for the implementation

**Config renderer / importer**

1. Map the profile `cipher` field to `data-ciphers` and **never** render a bare `cipher`.
   - `none` → `data-ciphers none:CHACHA20-POLY1305` + `data-ciphers-fallback none`.
   - Any other cipher X → `data-ciphers X` (plus `data-ciphers-fallback X` only for pre-2.4 servers).
   - Importer: `cipher X` → field `cipher=X` with a note. `data-ciphers` lines → the field, verbatim.
2. Render `auth <authDigest>` exactly; for mdex it is `none`. It must equal the server's value for non-AEAD ciphers.
3. Compression:
   - `none` → render nothing.
   - `lzo` → `comp-lzo`. In 2.7 this decompresses only; it works against both `comp-lzo yes` and `comp-lzo no` servers.
   - Never render `comp-lzo no`.
   - Importer: `comp-lzo`, `comp-lzo yes/adaptive/no` and `compress lzo` → `lzo` (with a hint that 2.7 never compresses). `compress lz4*`/`stub*` → keep as extra option with a warning.
4. Importer must drop with a visible note:
   - deprecated no-ops: `fast-io`, `persist-key`, `comp-noadapt`;
   - routing directives, covered by `route-noexec` anyway: `redirect-gateway`/`redirect-private`, `route*`;
   - `script-security` (mdex's own level-30 `.ovpn` contains `script-security 2`), `client`, `pull`, `tls-client`, `nobind`, `resolv-retry`.

   Map `dev tun` to nothing; reject `dev tap` as unsupported. Map `ns-cert-type server` to `remote-cert-tls server`. Map `auth-user-pass` (bare) to `authMode=password`. Map `<auth-user-pass>` inline credentials into the secret fields, never into the file.
5. Reject `extraOptions` lines of 255 characters or more. Do the same for parameters longer than 255. Remove CR (CRLF input). Never emit lines OpenVPN would treat as comments by accident: a token starting with `#`/`;` must be quoted.
6. Omit `explicit-exit-notify` when `proto` is `tcp` (otherwise OpenVPN prints a harmless NOTICE).
7. Expected warnings on every mdex start (flag `W`, not errors):
   - cipher none for `--data-ciphers`;
   - `--cipher none` / `--auth none` was specified;
   - mssfix/fragment "mtu" flag;
   - small block size / reneg-bytes 64 MB;
   - "may cache passwords in memory".

   The UI should not show these as failures. The log level of "may cache passwords in memory" is info (the credentials stay cached on purpose for renegotiation), and after the first warning about cipher `none` the driver logs a note that it comes from the profile setting; whether the data channel is really unencrypted is the `Data Channel: cipher '...'` line, which the driver reports as `dataCipher` (`none` for `[null-cipher]`). Against a server that does not permit `none` (field: the first mdex connection negotiated `CHACHA20-POLY1305`), the same warnings appear although the tunnel is encrypted.
8. **SPEC/CLAUDE.md conflict to resolve:** `clientKey`, `tlsAuthKey` and `tlsCryptKey` can only reach OpenVPN through the rendered file, which is tmpfs, 0600 and deleted on stop. CLAUDE.md says secrets never appear in files outside `/data`. Only the password and a private-key passphrase can avoid the file (management). The mdex profile has no file secrets.

**Management client / supervisor**

9. Create `/run/tunneldeck` with mode 0700 (the socket itself is 0777). Connect after spawn, retrying until the socket exists. Capture stdout/stderr from the start, because errors raised before management starts appear only there (exit code 1).
10. On `>HOLD:` send, once, `state on`, `log on`, `bytecount <n>`, then `hold release`. Send `hold release` again on every later `>HOLD:`; the backoff delay goes here.
11. Answer `>PASSWORD:Need 'Auth' username/password` with `username "Auth" "<v>"` / `password "Auth" "<v>"`, escaping `\` → `\\` and `"` → `\"`. Validate credentials: at most 255 bytes, no CR/LF/NUL. Answer `>PASSWORD:Need 'Private Key' password` analogously in certificate mode.
12. Treat `>PASSWORD:Verification Failed: 'Auth'` with **no** reason as rejected credentials: no automatic retry; the process exits by itself with code 0. With reason `TEMP...` treat it as transient. With any other `['reason']` treat it as a configuration or server rejection: show the reason, no retry.
13. Parsing:
    - Parse `>STATE:` by splitting on `,`; field 1 is the state, field 2 the detail, field 3 the VPN IPv4.
    - Mark the tunnel connected on `CONNECTED`; the detail can be `SUCCESS`, `ERROR` or `ROUTE_ERROR`.
    - Re-apply table-7194 routes and the rule on **every** `CONNECTED`, because the IP can change and, without `persist-tun`, the device is recreated.
    - Map `RECONNECTING,<reason>` to the `reconnecting` state.
    - Parse `>LOG:` by splitting only on the first two commas.
    - Treat `>FATAL:` as terminal (exit code 1 follows).
14. `>BYTECOUNT:in,out` values are transport bytes since process start (not since the last reconnect). For traffic rates, compute deltas.
15. Stop: send `signal SIGTERM` (or SIGTERM), wait for socket EOF or process exit (observed 1.3–2.5 s), then SIGKILL after 10 s. The daily reconnect (SPEC §4.3) can use `signal SIGUSR1`, which keeps the process, credentials and (with `persist-tun`) the interface, or a full stop/start.
16. Never rely on the exit code to tell apart auth failure and a normal stop: both are 0 (VERIFIED: lab). A server-pushed halt takes the same SIGTERM path (`push.c`); its exit code is UNVERIFIED. Use the last `>PASSWORD:`/`>STATE:`/`>FATAL:` seen; exit code 1 means a fatal or options error.
17. Use `Pdeathsig` (or `--management-client`) so that OpenVPN cannot outlive a crashed TunnelDeck process. UNVERIFIED design suggestion.

**Open points (UNVERIFIED, could change the implementation)**

- How the real `publicip20.mdex.de` negotiates (server version; whether `none` is in its `data-ciphers`; whether it pushes a cipher, `ifconfig-ipv6`, `topology net30`, or compression). The recommended `data-ciphers none:CHACHA20-POLY1305` + `data-ciphers-fallback none` worked against every emulated variant. The first real connection log (the `PUSH_REPLY` and `Data Channel:` lines) settles it.
- Whether the mdex level-20 server certificate has the KU/EKU that `remote-cert-tls server` needs (the RUT240 working with it suggests yes).
- mdex marks level 20 "no longer to be used". A move to level 30 (`publicip30.mdex.de`, `mdexCA30.crt`, `tls-version-min 1.3`) may become necessary.
- Whether the kernel's connected route for the tunnel subnet in the main table is acceptable under the "never modify the main table" rule, or the app should use `ifconfig-noexec` and configure `tdvpn0` itself (both paths verified in the lab; see (d)).
