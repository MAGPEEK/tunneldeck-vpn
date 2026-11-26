# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- WireGuard driver (backend): WireGuard profiles run on the embedded wireguard-go (no kernel module, no extra process) on the same tunnel device `tdvpn0`, so routing, firewall, kill switch, daily reconnect, remote access and public IP detection work as for OpenVPN. A profile holds the private key, the tunnel address, the MTU and one server (public key, optional pre-shared key, endpoint, allowed IPs, persistent keepalive); allowed IPs other than `0.0.0.0/0` are routed as remote networks. The state follows the handshakes: "connecting" until the first one (after 30 s the status says that the server does not answer), "connected" since the handshake, "reconnecting" after 3 minutes without one, when the endpoint's host name is resolved again. `POST /api/profiles/import` reads wg-quick `.conf` files for `"protocol": "wireguard"` (DNS, Table, FwMark, ListenPort, SaveConfig, IPv6 entries and further peers are dropped with a note, scripts are not imported), `POST /api/drivers/wireguard/keypair` generates a key pair without storing it, and profiles show the public key of their stored private key as `derived.publicKey`. The polished WireGuard form follows.
- WireGuard in the web interface: the profile editor offers WireGuard next to OpenVPN; "Generate key pair" fills in a new private key (after a confirmation when one is set) and shows the matching public key with Copy, also for a saved profile, to enter on the server. "Load profile file (.ovpn, .conf)", drag and drop and pasted text recognise wg-quick files and import them as WireGuard, with translated import notes. The Dashboard shows "WireGuard" and the endpoint host in the connection line, the note that the server does not answer while connecting, and ChaCha20-Poly1305 in the encryption row; the profile list shows the protocol and endpoint. The Help page has a WireGuard section.

## [0.2.4] - 2026-11-26

### Changed

- Dashboard: when the profile allows "cipher none" but the running tunnel negotiated a cipher, the advisory is a warning ("The profile allows an unencrypted data channel …; remove \"none\" from the Cipher field") instead of the red "Traffic is not encrypted"; the red notice stays while the tunnel really runs without a cipher.
- Import and extra options: Windows-only directives (`block-outside-dns`, `register-dns`, `ip-win32`, `route-method`, `tap-sleep`, `dhcp-renew`, `dhcp-release`, `dhcp-pre-release`, `win-sys`, `show-net-up`, `allow-nonadmin`) are dropped with an info note instead of being rejected as unknown options.

### Fixed

- Public IP detection: a reconnect, a failed routing and switching the detection off clear the old public IP at once, so the dashboard never shows the address of the previous server; the lookup no longer follows redirects. The privacy note says that the service name is resolved with the host's DNS server.
- Firewall page: the "How to turn it on" link for IP forwarding points at the guide of the installed version instead of `main`.

## [0.2.3] - 2026-11-26

### Added

- Public IP detection: after every connect TunnelDeck-VPN asks a "what is my IP" service through the tunnel (a connection bound to the VPN IP, so it uses the tunnel's routing) which public IPv4 address the internet sees, for example the fixed mdex address behind a VPN IP like 172.21.31.170. The Dashboard shows it as "Public IP" in "Connection details" and in the connection line below the VPN IP, and the System page uses it for the remote access URL (marked as detected); a public address entered in the profile always takes precedence. On by default with `https://api.ipify.org`; the System page card "Public IP detection" switches it off or changes the service URL. `GET /api/connection` returns `publicIp`, the event stream sends `publicIp` events, `GET/PUT /api/public-ip-lookup` reads and changes the setting, and `settings.json` moves to schema version 5 (migrated automatically).

## [0.2.2] - 2026-11-26

### Changed

- Dashboard: the advisories of the profile (for example "The data channel uses no cipher") moved from the connection card to a notice box at the very bottom, below "Connection details".
- System page, remote access: when the URL falls back to the VPN IP because the profile names no public address, the hint links to the profile ("Edit profile"), where the public address is set.

## [0.2.1] - 2026-11-26

### Changed

- Dashboard: Connect, Reconnect and Disconnect sit at the bottom of "Connection details". The "Remote access on" pill is gone; the remote access row shows only its state and port, without the URL. The "VPN address" row shows "VPN IP" and below it "Public IP" (the public address of the profile) instead of the server address, which the connection line already shows.

## [0.2.0] - 2026-11-26

First release of the 0.2 line, field-tested on a Synology DS723+ with mdex. It contains everything from 0.2.0-alpha.1 to 0.2.0-alpha.6 and the changes below.

### Changed

- The remote access address on the Dashboard and the System page is a plain link; the Copy button next to it is gone.
- The Dashboard connection card no longer repeats the state pill, the profile name and the protocol badge in its header; the state is still announced to screen readers, and the status list and connection line show the details.
- System page, Version card: "Container running for" replaces "TunnelDeck-VPN running for" and "Host running for". TunnelDeck-VPN is the container's main process, so its start is the container start. `GET /api/system` no longer returns `hostUptimeSeconds`.
- Dashboard: Connect, Reconnect and Disconnect sit below the connection line instead of in the header.
- Dashboard, Connection details: the "VPN tunnel" row is gone, because the connection line already shows the state and both rates; "Traffic total" is now the first row, in the list and in Customize.
- The log on the Log page fills the window height (at least 360px) instead of a fixed 360px box.
- Edit, Duplicate and Delete on the Profiles page stay on one line; on narrow screens the table scrolls sideways.

## [0.2.0-alpha.6] - 2026-11-27

### Added

- App icon (blue square, white shield with padlock) for browser tabs, desktop shortcuts and installed apps: favicon, Apple touch icon, maskable icon and a web app manifest, so "Install", "Create shortcut" and "Add to home screen" show the TunnelDeck-VPN icon.
- `GET /api/connection` returns `dataCipher` (the negotiated data-channel cipher, `none` when unencrypted) and `controlChannel` (TLS version and cipher suite, e.g. `TLSv1.3 TLS_CHACHA20_POLY1305_SHA256`), read from OpenVPN's `Data Channel:` and `Control Channel:` log lines and cleared when the tunnel goes down, and `routingWarning` (see Fixed). The event stream sends them as `channel` events.
- "Stay signed in" checkbox on the sign-in page, offered only on the LAN HTTP listener (hidden on the remote-access HTTPS listener, which ignores the flag; `GET /api/session` returns `rememberAvailable`). `POST /api/login` accepts `remember`; such a session has a 30-day idle timeout and a 90-day lifetime, its cookie gets `Max-Age`, and it survives a container restart. `settings.json` (schema version 4, migrated automatically) keeps at most 10 of them as SHA-256 token hash, username, created/last-used time and client IP, never the token. Logout removes the session from the store; `reset-admin` and a new admin account remove all remembered sessions.
- "Sign out everywhere" on the System page (with inline confirmation) ends every session, remembered ones included (`DELETE /api/sessions`).
- System page, Version card: "TunnelDeck-VPN running for" and "Host running for" (e.g. "5 days 4 h 12 min", months counted as 30 days, updated every minute, start time as tooltip). `GET /api/system` returns `startedAt` (RFC 3339 UTC) and `hostUptimeSeconds` (from `/proc/uptime`, omitted when unknown).
- Profiles have an optional `publicAddress` (IPv4 address or host name), edited in the new form section "Access": the address the provider assigns to the connection, which TunnelDeck-VPN cannot detect itself.
- Dashboard: while remote access is on and listening, the connection card shows the pill "Remote access on" and the "Remote access" row links `https://<public address or VPN IP>:<port>` with a Copy button (with a hint when it falls back to the VPN IP); the row shows the last error when the listener does not run. The System page shows the same URL in the Remote access card.

- Help page (`/help`, "Help" in the navigation below System): getting started, profiles, connecting, firewall, remote access (public address vs. VPN server address), one line per System check, troubleshooting, admin reset and About (installed version, MIT license), in German and English with a table of contents. Links to the guides on GitHub point at the installed release tag (`/blob/v<version>/…`, German guides in German) or at `main` for development builds, plus the release notes and "Report a problem"; they open in a new tab. Profiles, Firewall, System and Log have a "?" button in the page header that opens the matching help section.

### Changed

- Dashboard redesigned around real-time data. The connection card shows a connection line: VPN server (host, protocol) → this device (state, connected-for time) → local LAN (first subnet, device count), joined by links coloured by state (green connected, amber connecting/reconnecting, red error, dashed when disconnected; the firewall link turns amber when protections are limited or IP forwarding is off while forward rules exist) with received/sent rates, active rules and forwards; below it the VPN IP, the host's LAN address with the TunnelDeck-VPN version, and links "Show log" and "Open firewall". The row stacks vertically below 720 px. A new "Connection details" list shows VPN tunnel, VPN address (IPv4), encryption (data and control channel, when the server reports them; red for an unencrypted data channel), local LAN, firewall, remote access (only when available) and traffic totals, each with a status dot. "Customize" hides rows or the connection line per browser (stored in localStorage, "Reset" restores all); each row can also be hidden with its × button. The metric tiles and the host protection card are gone; their information moved into the line and the list.
- The live log moved from the Dashboard to its own page "Log" (`/log`) in the navigation between Firewall and System, with the same filters, copy and auto-scroll. In the error state the Dashboard links "Open log for details".

### Fixed

- System page: self-check entries no longer run title, detail and hint together. Each entry shows the status icon and title, the detail translated into the UI language, and the hint (muted, only for warnings and failures) on separate lines. `GET /api/system` check results carry a stable `detailCode` with `params`; `detail` stays as the English fallback.
- Dashboard: a `routingWarning` is shown in the connection card ("Routing for forwarded traffic could not be applied; retrying…" with a link to the log), and `channel` events update the Encryption row live.
- Port forwards on Linux 4.4 (e.g. Synology DSM 7.2): the policy rules no longer use the `ipproto`/`sport` selectors, which exist since Linux 4.17. Replies of port forwards, masqueraded or not, now follow a connection mark: the new chain `TUNNELDECK-MANGLE-PRE` (jump at position 1 of mangle `PREROUTING`, tagged lines) marks every connection arriving on `tdvpn0` (`CONNMARK --set-mark 0x7194/0xffff`) and copies that mark onto its packets from the LAN, and one policy rule `fwmark 0x7194/0xffff lookup 7194` (priority 7191) sends them into the tunnel. Without the CONNMARK target or the mangle table the firewall still installs: replies are routed by the target's address (`from <target> lookup 7194`), and the new self-check `reply-routing` warns that a forward target which uses this device as its gateway then sends all its traffic through the tunnel. Rules of older versions are replaced on the next connect. Every `ip rule` now names only the selectors it needs (`from`, `to`, `fwmark`).
- A failure to apply the tunnel routing after the tunnel came up no longer stops OpenVPN (on the reference device this ended a working connection with "SIGTERM received" and a reconnect). The tunnel stays connected, `GET /api/connection` carries `routingWarning` (`code: routing_failed`, message with the failing `ip` command and its error output, time), the log line names the same, and the routing is retried with the reconnect backoff (2 s doubling to 60 s) until it applies or the tunnel goes down.
- OpenVPN no longer logs "Options error: option 'route' cannot be used in this context ([PUSH-OPTIONS])" (and the same for `dhcp-option`) for every pushed option: `route-nopull` is replaced by `pull-filter ignore` for pushed routes, gateway redirects, DNS options, `route-delay` and `ifconfig-ipv6`; `route-noexec` stays as the safety net and the tunnel address still applies. A pushed `route-delay` no longer holds back the connected state.
- Log: "this configuration may cache passwords in memory" is logged as info, and after the first warning about cipher `none` the log notes that it comes from the profile's cipher setting and that the "Data Channel:" line names the cipher in use.

## [0.2.0-alpha.5] - 2026-11-27

### Fixed

- Profiles can always be deleted, also the active one while it connects, is connected or keeps retrying. `DELETE /api/profiles/{id}` disconnects the active profile first, waits up to 15 s for the tunnel to stop and then deletes it (`503 unavailable` if it does not stop in time) instead of answering `409`. The Delete button is no longer disabled; for the profile in use the confirmation reads "This profile is in use. It will be disconnected and deleted." with the button "Disconnect and delete".
- OpenVPN import: credentials could end up in extra options. When only the data lines of a provider's commented-out `<auth-user-pass>` template were uncommented, username and password were stored unencrypted as extra options, shown in the UI and written into the rendered config, where OpenVPN failed with "Unrecognized option". The uncommented lines between a commented opener or closer are now taken as username and password (note `credentials_from_partial_block`); more than two such lines fail the import (`openvpn_credentials_block_ambiguous`). Imported directives and extra options must be known OpenVPN 2.7 client options (the list comes from the image's openvpn 2.7.9): an unknown directive is not imported (`unknown_directive`, rejected), and an unknown extra option fails validation with `extra_option_unknown` ("Unknown OpenVPN option: …"), also for stored profiles when they are saved again; nothing is deleted automatically. Connecting a stored profile skips such entries and logs a warning with the line number only. Warnings and errors show a value that matches the stored username, password or key passphrase as "(hidden)".

## [0.2.0-alpha.4] - 2026-11-27

### Fixed

- OpenVPN import of provider files such as mdex fixed.IP level 30: `script-security` is dropped with the warning `script_security_dropped` instead of being reported as "not imported" (directives that run a script, such as `up`, stay rejected); `verb` is replaced by TunnelDeck-VPN's log level (`verb_replaced`, note); `client`, `pull`, `tls-client`, `nobind` and the other directives TunnelDeck-VPN renders itself are notes instead of warnings, with a corrected text ("is set by TunnelDeck-VPN itself"). A file without client certificate, key, PKCS#12 bundle or `auth-user-pass` selects the password sign-in, marks username and password as missing and adds the note `credentials_expected`; a commented-out `<auth-user-pass>` block only points the note at its line and is never read.
- The advisory `unencrypted_data_channel` ("Traffic is not encrypted") is only shown when the cipher list offers `none` without an AEAD alternative (for example `none` or `none:BF-CBC`), no longer for lists such as `AES-256-GCM:none`.
- Firewall on kernels without optional iptables modules (e.g. Synology DSM 7.2, Linux 4.4, no `xt_hashlimit`): the installation no longer fails. netguard probes `comment`, `hashlimit`, `limit`, `TCPMSS` and `REJECT` once per backend on a temporary chain (`TUNNELDECK-EXT-PROBE`). Without `hashlimit` the SYN flood protection falls back to one global rate with the same numbers and the ping limit, global anyway, keeps working (`limit` match, in the new chain `TUNNELDECK-LIMIT` that the SYN and ping lines of `TUNNELDECK-INPUT` and `TUNNELDECK-FORWARD` jump to); without `limit` as well both are left out; without `TCPMSS` MSS clamping is left out; without `REJECT` rules with the action reject are installed as `DROP`. The settings stay as stored. New self-checks `syn-flood-protection`, `ping-limit`, `mss-clamp` and `reject-target` warn (`warning: true`) with the missing module, the active fallback and a hint; `GET /api/firewall` returns `protectionsAvailable` (`synFlood`: `full`/`global`/`none`; `ping`, `mssClamp`: `full`/`none`; `ruleCounters`), and the Firewall page notes "Global limit only" or "Not available on this system" next to the affected switch.


### Changed

- Firewall editor suggestions follow the detected network: "Open a service on this device" and "Block something" prefill the host's first LAN address, address placeholders (device, outbound source, IPsec router) are built from the first detected LAN subnet (e.g. `192.168.2.x` for `192.168.2.0/24`), and "Let a LAN device into the VPN" offers "Whole local LAN (<subnet>)" in one click. Without a detected network the fields show a neutral hint instead of a fixed example address.

## [0.2.0-alpha.3] - 2026-11-26

Includes the changes released as 0.2.0-alpha.2 (empty ports mean any, translated field errors, LAN detection fix).

### Added

- Firewall rules with an empty port match any port: for TCP, UDP and TCP+UDP an empty source or destination port means every port, inbound and outbound, for allow, drop and reject. An inbound rule to the host with an empty destination port opens that protocol on all ports; `TUNNELDECK-INPUT` now drops TCP to the web UI port before any rule, so no rule can open it to the tunnel. A port forward with an empty destination port forwards every port of its protocol to the device (the port on the VPN address must be empty too); its DNAT skips the web UI port and, while remote access is on, the remote-access port, and it conflicts with every other enabled forward of an overlapping protocol (reported on both rules).
- Validation problems carry `fieldCodes` (RFC 9457 extension member): a stable code and optional params per field. The Firewall page and the profile forms show these errors in the UI language (German or English) and fall back to the server's message for unknown codes.
- `GET /api/firewall/devices` lists the host's LAN neighbours (address, MAC, reverse-DNS name when one resolves within a second, neighbour state, whether the address is inside a LAN subnet) for the device picker of the firewall editor.
- `GET /api/firewall` returns `counters`: the hits per rule ID (`packets` = new connections matched, `bytes` their first packets), each rule counted once from its filter line (DNAT and masquerade lines are not summed), and `countersAvailable`. Every generated iptables rule carries a comment tag (`tdrule:<id>` or `tdfixed:<purpose>`). Without the iptables comment match (`xt_comment`) the firewall works as before, untagged; `counters` is then `null`, `countersAvailable` is `false`, and the new self-check `rule-counters` reports a warning (`warning: true`) with a hint.
- All remaining validation messages (remote access, remote networks, setup, certificate upload) carry `fieldCodes` with German and English texts.
- Web UI: "Load .ovpn file" (de: ".ovpn-Datei laden") is the first, primary action on the Profiles page and in the empty dashboard; a `.ovpn`/`.conf` file can also be dropped onto the Profiles page (drop overlay). Pasting stays available as "Paste configuration". The new-profile form opens prefilled, named after the file (else the server address), lists the import warnings above the form and highlights only what the file lacks (username and password, CA, client certificate and key, key passphrase of an encrypted key, files the profile only references) until it is filled in. Files that are not UTF-8 are read as Windows-1252.
- OpenVPN: inline `<tls-crypt-v2>` client keys are imported and rendered (secret `tlsCryptV2Key`, form field "TLS crypt v2 client key"); it cannot be combined with tls-auth or tls-crypt.
- `POST /api/profiles/import` returns `missing` (setting and secret keys the file left empty, in form order), and `file_reference` warnings carry `file`, the referenced file name; the message says to embed it inline or paste it.

### Changed

- OpenVPN import: plain `setenv`/`setenv-safe` lines (Access Server profiles) are dropped with the warning `setenv_ignored` instead of being rejected; `setenv opt` is still rejected. Comment lines are ignored whatever their length or bytes. Empty files (`openvpn_file_empty`) and files without any OpenVPN directive or with binary content (`openvpn_not_a_profile`) fail with a specific, translated error. A file reference to `cert`, `key` or `pkcs12` selects a certificate sign-in. `tls-crypt-v2` in extra options is now "set through a profile field" instead of "not allowed".
- Web UI: the Firewall page is loaded on first visit, so the main bundle stays below 500 kB.
- Web UI: the Firewall page is redesigned (SPEC §16.4). One rule list in evaluation order with filter chips All / Inbound / Outbound replaces the direction tabs; each row shows an enable switch, a flow strip (`VPN · sender → Local LAN · device` inbound, `Local LAN · device → VPN · destination` outbound, the LAN device highlighted), a plain-language line (name, service, "all ports", "VPN port", "sender kept", "off"), the hit count ("N hits", "–" while off; hidden without counters), Edit / Duplicate / Delete and up/down. "Add rule" starts with intent cards: "Make a LAN device reachable from the VPN", "Open a service on this device", "Let a LAN device into the VPN", "IPsec router", "Block something" and "Custom rule". The inline step editor shows a live flow strip, a device picker (LAN neighbours with name, IP and MAC, free address entry, "This device’s address", "Reserve this address in your router"), service presets (HTTP, HTTPS, SSH, RDP, SMB, DNS, All ports, Custom), a prefilled name, a plain-language summary, a collapsible "Restrict and advanced" section (sender address and port, port on the VPN address, the sender the device sees, comment) and a read-only "What this rule creates". An empty outbound destination now means everything behind the VPN (`0.0.0.0/0`).
- **Breaking:** the firewall destination kind "Host" is gone. An inbound rule's `destination` is now a plain string holding one IPv4 address in the local LAN; an outbound rule's is an address or CIDR network (`"destination": "192.168.1.10"` instead of `{"kind": …, "cidr": …}`). On every apply, an inbound rule to one of the host's own LAN addresses opens a service on the host (allow, drop or reject; the port on the VPN address must be empty or equal to the destination port), and a rule to any other LAN address is a port forward (always allow). `GET /api/firewall` also returns `hostAddresses`, all of the host's LAN addresses. Validation codes: new `firewall_destination_not_in_lan`, `firewall_public_port_own_address` and `firewall_template_own_address` (the IPsec template refuses the host's own address); removed `firewall_outbound_to_host`, `firewall_host_takes_no_address`, `firewall_destination_kind_invalid`, `firewall_public_port_host` and `firewall_destination_outside_lan`; an empty destination is `required`.
- **Breaking:** `settings.json` schema version 3. Destinations are stored as plain strings. Rules saved with the destination "Host" keep working: the Firewall page shows them with the host's current LAN address, and the next save stores that address. Older TunnelDeck-VPN versions refuse to start with a version 3 file.
- Web UI: generic wording. The Firewall page shows "This device: 192.168.1.10 · Local LAN: 192.168.1.0/24" (de: "Dieses Gerät", "Lokales LAN"); the inbound destination is an address field "Destination (address in the local LAN)" with the one-click suggestion "This device’s address: 192.168.1.10"; the template is "IPsec router" (de: "IPsec-Router"); examples use 192.168.1.0/24, and no brand or device-type names appear (the dashboard card reads "This device shielded from tunnel"). The guides keep real-world specifics only in a marked "Example: LANCOM router with mdex" subsection.
- System page: a self-check that only turns a feature off (`warning: true`, such as `rule-counters`) shows a warning icon and tone instead of a failure.
- Re-applying the firewall leaves every chain whose content is unchanged untouched, so counters survive reconnects and unrelated rule changes; a changed chain is rebuilt with the existing DROP-safe refill and starts its counters at zero.
- Firewall rule IDs must be 1 to 64 letters, digits, underscores or hyphens (generated IDs always are).
- Web UI: port inputs show the placeholder "any" (de: "beliebig"), and the rule list shows "any" for an empty source or destination port. "Public port" is now "Port on the VPN address" (de: "Port auf der VPN-Adresse") with a clearer hint; it is disabled while the destination port is empty, and an any-port forward explains that every port except the web UI ports goes to the device.

### Fixed

- Web UI: a new firewall rule without a destination no longer shows the Action select disabled.
- LAN detection no longer lists link-local addresses (169.254.0.0/16, for example on an unplugged network port) as LAN subnets.

## [0.2.0-alpha.1] - 2026-11-26

### Changed

- **Breaking:** `settings.json` schema version 2. The host-access rules become firewall rules (SPEC §16): each one is migrated on start to an inbound rule to "This device" named like "Host port 5001/tcp", and the global firewall protections are switched on. The migrated file is written on the next settings change; older TunnelDeck-VPN versions refuse to start with it, so keep a copy of `/data` before upgrading if you may roll back.
- The firewall now has two directions and four chains: `TUNNELDECK-INPUT` and `TUNNELDECK-FORWARD` (filter), `TUNNELDECK-PREROUTING` and `TUNNELDECK-POSTROUTING` (nat), each jumped to from position 1 of its built-in chain.
- OpenVPN profile form: client certificate and client key are no longer required on their own (a PKCS#12 file can replace them; saving still requires one of the two forms). The keep-alive field shows the placeholder `10 120`.
- **Breaking (API):** `GET`/`PUT /api/host-access` are removed and answer `410 Gone` (problem code `gone`) with a pointer to `/api/firewall`.

### Fixed

- Both compose files had a broken `environment:` block (invalid YAML) in 0.1.0-alpha.1.

### Added

- Firewall rules (backend): inbound rules to this device (accept, drop or reject; tcp, udp, tcp+udp, icmp with optional type, esp, gre; port ranges, source address and source port), port forwards to other LAN devices (DNAT with optional public port or shifted port range, masquerade unless the source address is kept, esp and gre forwarding), and outbound rules that route LAN devices through the tunnel (policy rules at priorities 7100–7191, masquerade on `tdvpn0`) with a kill switch that drops their traffic while the tunnel is down.
- Global firewall protections, all on by default: drop invalid packets, clamp the TCP MSS to the path MTU, limit new TCP connections from the tunnel (25/s, burst 50 per source) and pings from the tunnel (5/s, burst 10).
- Firewall API: `GET /api/firewall` returns `{rules, settings, hostAddress, lanSubnets, ipForward}` (the last three describe the host's LAN for the UI and are empty when detection fails); `PUT /api/firewall` with `{rules, settings}` validates every rule (field errors as `rules[i].<field>` and `settings.<field>`; all four settings are required), keeps the web UI port and the remote-access port closed, requires port-forward targets inside a LAN subnet, stores and applies the firewall, and restores and re-applies the previous configuration when applying fails (`500 firewall_failed`). `POST /api/firewall/templates/ipsec` with `{name, deviceAddress, peers?}` returns the "IPsec device" rules (inbound UDP 500, UDP 4500 and ESP to the device with the source address kept, outbound UDP and ESP from the device; per peer when peers are given) without storing them.
- Self-checks `ip-forward` (reads `net.ipv4.ip_forward`, never changes it) and `lan-subnets` (the host's LAN subnets, which port-forward targets must lie in).
- OpenVPN profile setting `remoteNetworks`: up to 32 IPv4 networks behind the VPN (canonical CIDR, not overlapping a LAN subnet of the host, not containing the server address). While connected the host routes them through the tunnel (`ip rule … to <net> lookup 7194`, priority 7180), removed on disconnect; pushed routes stay ignored. Outbound firewall rules can use them as destinations.
- OpenVPN PKCS#12: the secret `pkcs12` (base64 of a `.p12`/`.pfx` file) replaces client certificate and key in the certificate sign-in methods and is rendered as an inline `<pkcs12>` block; its passphrase is the key passphrase, sent over management. The `.ovpn` import maps `<pkcs12>` blocks; a `pkcs12` file reference is still rejected.
- `.ovpn` import and extra options reject static-key mode (`secret`, `<secret>`) with the warning code `static_key_unsupported`.
- Web UI: the Firewall page replaces Host access (`/host-access` redirects to `/firewall`). Tabs "Inbound from VPN" and "Outbound to VPN" list the rules in evaluation order with move up/down, enable, edit, duplicate and delete (with confirmation). An inline editor covers name, action, protocol (TCP, UDP, TCP+UDP, ICMP with optional type, ESP, GRE, any), source and source port, destination "This device" or an address (LAN subnets as a hint), destination port, public port, keep source address and comment, and shows the server's validation errors on the matching rule, opening its editor. "Add IPsec device" inserts the template rules, marked until saved. Switches for the four protections; a line with this device's address, the LAN and IP forwarding (a warning with a docs link when off); `Save changes` and `Discard`; a danger notice with the detail when applying fails. The dashboard card counts inbound and outbound rules and warns when IP forwarding is off while port forwards or outbound rules exist.
- Docs: a "Firewall rules" section in the Linux and Synology guides (English and German): inbound and outbound rules, This device, port forwards, keep source address, the gateway requirement and the kill switch; how to check and enable IP forwarding (`docs/linux.md#ip-forwarding`, `docs/linux.de.md#ip-weiterleitung`, linked from the Firewall page); a worked example for an IPsec router in the LAN such as a LANCOM, with what was lab-tested with strongSwan and what was not.
- End-to-end test: firewall cases on both iptables backends with a LAN behind TunnelDeck-VPN: migration of a version 1 `settings.json`, port forwards with and without keep source address and with a source restriction, outbound policy routing for one LAN device, the IPsec template with strongSwan (IKEv2 with NAT-T initiated from both sides, plain ESP with manually keyed SAs) and the kill switch after a tunnel drop and after a disconnect.
- Web UI: OpenVPN profile form labels for remote networks and the PKCS#12 file, which can be pasted as base64 or loaded from a `.p12`/`.pfx` file (driven by the new driver-independent form schema attribute `encoding: "base64"` on multi-line secret fields); a translated import warning for static-key mode; System page names and hints for the `ip-forward` and `lan-subnets` self-checks.

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
