# System page checks explained

The System page shows the self-check TunnelDeck-VPN runs at start (`internal/netguard/selfcheck.go`). Each entry is one of three states:

- **OK**: the prerequisite or feature is in place.
- **Warning**: an optional iptables extension is missing. The firewall is installed anyway; only the named feature falls back or is left out.
- **Failure**: a prerequisite is missing. The tunnel or the firewall cannot work as intended until you fix it.

After loading a kernel module or changing the container, restart the container: the extensions are probed once per start.

German version: [system-checks.de.md](system-checks.de.md).

## Entry — what it means for you

| Entry (id) | Kind | What it means for you |
| --- | --- | --- |
| TUN device (`tun-device`) | required | Without it no tunnel can start. |
| iptables (`iptables`) | required | Without it there is no firewall and no kill switch. |
| ip tool (`ip`) | required | Without it no routing for the tunnel. |
| NET_ADMIN capability (`net-admin`) | required | Without it the container may not change firewall or routes. |
| IP forwarding (`ip-forward`) | required | Without it rules to other devices and outbound rules forward nothing. |
| LAN subnets (`lan-subnets`) | required | Without them inbound rules to other LAN devices have no target. |
| Hit counters (`rule-counters`) | optional | Off when the comment match is missing — the firewall still works. |
| SYN flood protection (`syn-flood-protection`) | optional | Global instead of per-sender rate, or left out — the firewall still works. |
| Ping limit (`ping-limit`) | optional | Left out only when both rate modules are missing — the firewall still works. |
| TCP MSS clamping (`mss-clamp`) | optional | Left out without TCPMSS — large transfers may stall. |
| REJECT target (`reject-target`) | optional | Reject rules drop silently instead. |
| Reply routing of port forwards (`reply-routing`) | optional | Without CONNMARK, a port-forward target that uses this host as gateway sends all its traffic through the tunnel. |

## Fixing missing kernel modules

**Generic Linux host:** load the module on the host, then restart the container:

```sh
sudo modprobe xt_comment          # name from the section below
echo xt_comment | sudo tee /etc/modules-load.d/tunneldeck.conf   # load at boot
```

If the module exists but iptables-legacy cannot use it, try the nft backend: set `TUNNELDECK_IPTABLES=nft` in the container environment (see [linux.md](linux.md#which-iptables-backend-tunneldeck-vpn-uses)).

**Synology DSM:** DSM has no `modprobe` path for every module, and some DSM kernels do not ship these modules at all. Check first, then load by path:

```sh
ls /lib/modules | grep -i -E 'comment|limit|tcpmss|reject|connmark|mangle'
sudo insmod /lib/modules/xt_comment.ko
```

To load it at every boot, add the line to the boot task from [synology.md](synology.md#tun-device) (Task Scheduler, user `root`, event Boot-up), for example `lsmod | grep -q '^xt_comment ' || insmod /lib/modules/xt_comment.ko`. If the module is not in `/lib/modules`, the warning stays; the firewall still protects the host, only that feature is reduced.

*Not verified on a real DS723+:* which of these modules DSM 7.2 ships, and whether `insmod` of them succeeds. Some modules depend on others (for example `xt_connmark` on `nf_conntrack`); load those first if `insmod` reports unknown symbols.

## tun-device

- **Checks:** `/dev/net/tun` exists in the container and is a character device.
- **OK:** the tunnel interface can be created.
- **Failure:** no VPN connection can start.
- **Module:** `tun`.
- **Fix:** pass the device into the container (`devices: - /dev/net/tun`). Linux: `sudo modprobe tun`. DSM: `insmod /lib/modules/tun.ko` and the boot task, see [synology.md](synology.md#tun-device).

## iptables

- **Checks:** a working iptables backend (legacy or nft) is found; the detail names the binary and why it was chosen.
- **OK:** the firewall and kill switch can be installed.
- **Failure:** no firewall, no kill switch.
- **Module:** `ip_tables` / `iptable_filter` (legacy) or `nf_tables` (nft).
- **Fix:** the image ships iptables; the host kernel must provide the filter table. Override the choice with `TUNNELDECK_IPTABLES=nft` or `legacy` (default `auto`). DSM 4.4 kernels have only legacy.

## ip

- **Checks:** `ip -4 rule show` runs.
- **OK:** policy routing for the tunnel works.
- **Failure:** routes and rules for the tunnel cannot be set.
- **Module:** none.
- **Fix:** iproute2 is part of the image; a failure points to a broken or custom image.

## net-admin

- **Checks:** creates and deletes the probe chain `TUNNELDECK-PROBE`.
- **OK:** the container may change firewall and routing.
- **Failure:** neither the firewall nor routes can be set. Also fails when iptables is missing.
- **Module:** none.
- **Fix:** `cap_add: - NET_ADMIN` in the compose file.

## ip-forward

- **Checks:** `net.ipv4.ip_forward` is `1`. TunnelDeck-VPN reads it and never changes it.
- **OK:** traffic between tunnel and LAN can be forwarded.
- **Failure:** rules to other devices and outbound rules forward nothing; access to this host itself still works.
- **Module:** none.
- **Fix:** Linux: `sudo sysctl -w net.ipv4.ip_forward=1`, persisted in `/etc/sysctl.conf` (Docker hosts normally have it on), see [linux.md](linux.md#ip-forwarding). DSM: boot task, see [synology.md](synology.md#ip-forwarding-on-dsm).

## lan-subnets

- **Checks:** at least one IPv4 address on a LAN interface; the detail lists the subnets.
- **OK:** inbound rules to other devices know their LAN.
- **Failure:** inbound rules to other LAN devices have no target.
- **Module:** none.
- **Fix:** run the container with `network_mode: host` on a host with an IPv4 address on its LAN interface.

## rule-counters

- **Checks:** the iptables `comment` match works.
- **OK:** the firewall page shows hit counts per rule.
- **Warning:** no hit counters — the firewall still works.
- **Module:** `xt_comment`.
- **Fix:** `modprobe xt_comment` or `TUNNELDECK_IPTABLES=nft`; DSM: see above.

## syn-flood-protection

- **Checks:** the `hashlimit` match, else the `limit` match.
- **OK:** SYN flood protection with one rate per sender (hashlimit).
- **Warning (limit only):** one global rate for all senders — one flooding sender can slow new connections of others.
- **Warning (neither):** SYN flood protection is left out — the firewall still works.
- **Module:** `xt_hashlimit` (preferred), fallback `xt_limit`.
- **Fix:** `modprobe xt_hashlimit`; DSM: see above.

## ping-limit

- **Checks:** the `hashlimit` or `limit` match. The ping limit is one global rate either way, so either is OK.
- **OK:** pings from the tunnel are rate-limited.
- **Warning:** both modules missing, the ping limit is left out — the firewall still works.
- **Module:** `xt_hashlimit` or `xt_limit`.
- **Fix:** `modprobe xt_limit` (or `xt_hashlimit`); DSM: see above.

## mss-clamp

- **Checks:** the `TCPMSS` target works.
- **OK:** the TCP MSS is clamped to the path MTU.
- **Warning:** MSS clamping is left out — large transfers through the tunnel may stall when the path MTU is small.
- **Module:** `xt_TCPMSS`.
- **Fix:** `modprobe xt_TCPMSS`; DSM: see above.

## reject-target

- **Checks:** the `REJECT` target works.
- **OK:** rules with the action reject answer with a TCP reset or ICMP port unreachable.
- **Warning:** reject rules drop silently instead; the sender waits for a timeout.
- **Module:** `ipt_REJECT` (nft backend: `nft_reject`).
- **Fix:** `modprobe ipt_REJECT`; DSM: see above.

## reply-routing

- **Checks:** the `CONNMARK` target and `connmark` match in the `mangle` table work.
- **OK:** replies of port forwards follow a connection mark back into the tunnel.
- **Warning:** replies are routed by the target's address: while the tunnel is up, everything this host routes for a port-forward target goes through the tunnel. Port forwards themselves still work.
- **Module:** `xt_connmark` and `iptable_mangle`.
- **Fix:** `modprobe xt_connmark iptable_mangle`; DSM: see above.
