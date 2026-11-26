# TunnelDeck-VPN on a Linux Docker host

[Deutsch](linux.de.md)

This guide runs TunnelDeck-VPN on any Linux host with Docker: a server, a mini PC, a Raspberry Pi. Nothing in it depends on a distribution. Connecting, routing and host protection were checked with the end-to-end test (`test/e2e/`) on both iptables backends, and the ufw notes in a container lab. Points marked *unverified* have not been tested.

## 1. Requirements

- **Docker Engine with Compose v2** (`docker compose version`).
- **CPU:** amd64 or arm64. The image is built for `linux/amd64` and `linux/arm64`; arm64 is *unverified* so far.
- **TUN device.** Check it:

  ```sh
  ls -l /dev/net/tun
  ```

  A line starting with `crw` means it exists. Otherwise load the module and make it permanent:

  ```sh
  sudo modprobe tun
  echo tun | sudo tee /etc/modules-load.d/tun.conf
  ```

- **iptables support in the kernel**: nftables (`nf_tables`, every current distribution) or the legacy `ip_tables`/`iptable_filter` modules (old kernels such as DSM's 4.4). The image ships both `iptables-legacy` and `iptables-nft`; TunnelDeck-VPN uses the one your host's firewall already uses (see section 4). The container cannot load kernel modules: if neither works, load one on the host, for example `sudo modprobe nf_tables` or `sudo modprobe -a ip_tables iptable_filter`.
- **Policy routing** (`ip rule`), part of every distribution kernel.

## 2. Start

Create a directory, for example `/opt/tunneldeck`, with this `docker-compose.yml`:

```yaml
services:
  tunneldeck:
    image: magpeek/tunneldeck-vpn:0.3.0
    container_name: tunneldeck
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes: ["./data:/data"]
    environment:
      TZ: Europe/Berlin
      # TUNNELDECK_LISTEN: "192.168.1.10:8194"  # default: default-route interface, port 8194
      # TUNNELDECK_IPTABLES: nft                # default auto: the host firewall's backend
    restart: unless-stopped
```

```sh
docker compose up -d
docker compose logs -f
```

`network_mode: host` is required: TunnelDeck-VPN manages the host's `tdvpn0` device, its policy routing and its firewall chains. `NET_ADMIN` and `/dev/net/tun` are all it needs; the container does not run privileged.

## 3. First sign-in

1. Open `http://<host-ip>:8194`. TunnelDeck-VPN listens on the address of the interface that holds the default route (the log shows `listening address=...`). Set `TUNNELDECK_LISTEN` to choose another address or port (example `192.168.1.10:9000`). The UI is never reachable through the VPN tunnel; remote access over the VPN is HTTPS only (System page, default port 8443, freely selectable).
2. Create the admin account (password of at least 12 characters).
3. Open **System** and check that every self-check passes: TUN device, iptables (it names the backend in use), `ip`, `NET_ADMIN`, IP forwarding (section 10) and the LAN subnets. Each failed check shows a hint.

The Docker health status shows whether the web server answers, not whether the tunnel is up.

## 4. Firewall: TunnelDeck-VPN, ufw, firewalld and Docker

What TunnelDeck-VPN changes on the host (SPEC §6, §16):

- Chain `TUNNELDECK-INPUT`, jumped to from position 1 of `INPUT` for traffic arriving on `tdvpn0`: accept established connections, drop TCP to the web UI port, apply the inbound firewall rules to this device's own LAN address (and accept the remote-access port while it is on), drop everything else.
- Chain `TUNNELDECK-FORWARD`, jumped to from position 1 of `FORWARD` for traffic in or out of `tdvpn0` and for the traffic of every outbound rule: accept port forwards and outbound rules, drop everything else. Without such rules nothing is forwarded.
- Chains `TUNNELDECK-PREROUTING` and `TUNNELDECK-POSTROUTING` in the `nat` table: the address translation of port forwards and outbound rules (section 10).
- Routing table `7194` with a default route via `tdvpn0`, and the rule `from <VPN address> lookup 7194`, so replies to connections that came in through the tunnel leave through it; while connected also the policy rules of the firewall (priorities 7100–7191). The main routing table is not touched; the only entry that appears there while connected is the kernel's own route for the tunnel subnet.
- The chains are installed at start, re-applied before every connect and whenever the firewall changes, and removed when the container stops.

Check the state with the backend TunnelDeck-VPN uses (the iptables self-check on the System page names it):

```sh
sudo iptables-nft -S INPUT | head -3        # backend "iptables-nft"
sudo iptables-legacy -S INPUT | head -3     # backend "iptables-legacy"
ip rule show; ip route show table 7194
```

### Which iptables backend TunnelDeck-VPN uses

`iptables-legacy` and `iptables-nft` keep separate rule sets, and the kernel applies both: a packet must pass the legacy chains *and* the nftables chains. An `ACCEPT` in one does not override a `DROP` in the other. TunnelDeck-VPN therefore shares the backend of the host's firewall. At start it lists the `filter` and `nat` tables with both binaries and counts the rules there, ignoring its own chains and `ACCEPT` policies:

- only one backend works: that one (old kernels such as DSM's 4.4 have only legacy),
- only one backend holds rules: that one,
- both hold rules: the one with more; the System page and the log warn that the host mixes backends, whose other rules still apply,
- neither holds rules: nf_tables.

What each System page entry means and which module fixes a warning: [System page checks explained](system-checks.md).

The iptables self-check on the System page and the start log (`iptables backend binary=... reason=...`) name the choice and the reason. To override it, set `TUNNELDECK_IPTABLES` to `nft` or `legacy` (default `auto`).

On a shared backend the rules still interact, in a fixed order: TunnelDeck-VPN inserts its jump at position 1 of `INPUT`, so for traffic arriving on `tdvpn0` its chain decides first and that decision wins. A port opened by an inbound rule to this device's own LAN address (or the remote-access port) is reachable even if the host firewall would drop it; everything else from the tunnel is dropped even if the host firewall allows it. Traffic on other interfaces never enters TunnelDeck-VPN's chains. Rules in another *table* (firewalld's own nftables table, or the other backend on a mixed host) are evaluated separately and can still drop what TunnelDeck-VPN accepts.

### ufw

With ufw's usual `default deny incoming`:

- Allow the UI port from your LAN, otherwise ufw blocks the browser: `sudo ufw allow from 192.168.1.0/24 to any port 8194 proto tcp`.
- **Same backend** (the normal case: ufw on nft, TunnelDeck-VPN shows `using iptables-nft`): TunnelDeck-VPN's jump sits before ufw's chains in `INPUT`, so TunnelDeck-VPN alone decides about tunnel traffic. An inbound rule to this device's own LAN address opens the port; ufw's own allow rules (for example `ufw allow 22`) open nothing on the tunnel. `ufw reload` keeps TunnelDeck-VPN's jump first.
- **Different backends** (only when `TUNNELDECK_IPTABLES` forces the other backend, or the host mixes both and the other one holds more rules): a TunnelDeck-VPN rule alone is not enough, because ufw still drops the port. Allow it in ufw too:

  ```sh
  sudo ufw allow in on tdvpn0 to any port 8443 proto tcp
  ```

  The rule can be added while `tdvpn0` does not exist. A port allowed only in ufw stays closed, because TunnelDeck-VPN drops it.

Both cases were verified in a container lab (Alpine, ufw 0.36.2 on iptables-nft, TunnelDeck-VPN connected to a test server, probes through the tunnel). The end-to-end test covers the shared case with automatic detection: a host rule in nf_tables that drops TCP from the tunnel, and inbound rules to the host's own LAN address that still open their port. Not verified on a full distribution install such as Ubuntu or Debian.

### firewalld

firewalld (nftables backend, the default since 0.6) filters in its own nftables table. An interface without a zone falls into the default zone (usually `public`, which allows only a few services), so a port opened in TunnelDeck-VPN stays closed until firewalld allows it too. Either let TunnelDeck-VPN alone decide:

```sh
sudo firewall-cmd --permanent --zone=trusted --add-interface=tdvpn0
sudo firewall-cmd --reload
```

or keep a stricter zone for `tdvpn0` and add the ports there (`--add-port=8443/tcp`). Allow the UI port from the LAN as well. *Unverified:* this follows from how the kernel applies several tables, as shown for ufw above, but was not tested with firewalld. Whether `firewall-cmd --reload` leaves TunnelDeck-VPN's chains alone is also *unverified*; restart the container after changing the firewall to be sure, since TunnelDeck-VPN installs its chains at start.

### Docker's own chains

Docker's chains (`DOCKER-USER`, `DOCKER-FORWARD`, the `nat` chains) sit in `FORWARD` and `nat`, not in `INPUT`, so they do not change what reaches the host through the tunnel. TunnelDeck-VPN runs with host networking and publishes no ports. Its `FORWARD` and `nat` jumps are inserted at position 1, before Docker's. *Unverified:* after a Docker daemon restart Docker may put its `FORWARD` jumps above TunnelDeck-VPN's until TunnelDeck-VPN re-installs its chains (next connect, next firewall change or container restart); Docker's chains only handle traffic of its own bridges, so port forwards and outbound rules between the tunnel and the LAN should not be affected.

## 5. HTTPS in the LAN with a reverse proxy

The UI on port 8194 is plain HTTP. For HTTPS in the LAN put a reverse proxy in front of it, for example Caddy:

```
tunneldeck.home.arpa {
    reverse_proxy 192.168.1.10:8194
}
```

or nginx:

```nginx
server {
    listen 443 ssl;
    server_name tunneldeck.home.arpa;
    # ssl_certificate ...; ssl_certificate_key ...;
    location / {
        proxy_pass http://192.168.1.10:8194;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
    }
}
```

- Proxy to the LAN address TunnelDeck-VPN listens on, not to `127.0.0.1` (unless `TUNNELDECK_LISTEN` says so).
- Keep the `Host` header: sign-in and every change check that the browser's `Origin` matches `Host`. Caddy keeps it by default.
- The live view uses server-sent events; TunnelDeck-VPN sends `X-Accel-Buffering: no`, which nginx honours.
- Behind a proxy all browsers share the proxy's address for the sign-in rate limit.

Both proxy examples are *unverified*.

## 6. Remote access over the tunnel

To reach the UI from the internet through the VPN address (SPEC §8.1), open **System > Remote access**, turn it on (default port `8443`), keep the self-signed certificate or upload your own, and compare the SHA-256 fingerprint shown there with the browser's warning on the first visit to `https://<VPN-address>:8443`. Only this HTTPS port opens on the tunnel; 8194 stays closed there (verified by the end-to-end test). The login page is then reachable from the internet: use a long admin password. With a host firewall see section 4.

## 7. Backup

Back up the data directory (`./data` next to the compose file):

- `settings.json`: admin account, firewall rules and settings, remote access, desired connection,
- `profiles.json`: profiles; secret fields encrypted,
- `secret.key`: the key for those secrets.

Without `secret.key` the stored passwords and keys cannot be decrypted. If you set `TUNNELDECK_SECRET_KEY`, keep that value with the backup instead. Keep the backup as protected as the host. For a consistent copy stop the container first:

```sh
docker compose stop && sudo tar czf tunneldeck-backup.tgz data && docker compose start
```

## 8. Update

1. Back up the data directory (section 7). A newer version may migrate the data files, and an older one refuses to start on migrated files.
2. Set the new tag in `image:`, then:

   ```sh
   docker compose pull && docker compose up -d
   ```

3. A tunnel that was connected reconnects by itself (verified for a container restart by the end-to-end test). Check the version on the **System** page.

## 9. Lost admin password

```sh
docker exec tunneldeck tunneldeck reset-admin
```

This removes the admin account and all sessions; profiles and settings stay. Open the UI and create the account again. Alternatively set `TUNNELDECK_RESET_ADMIN: "1"`, restart, sign up again and remove the variable; it resets at every start while it is set.

Details and expected output: [Lost admin password](reset-admin.md).

## 10. Firewall rules

The **Firewall** page controls what crosses the tunnel, in both directions, to this device and to any other device in the local LAN (SPEC §16). Everything no rule allows is dropped in both directions; replies to allowed connections always pass. Rules apply in list order, top to bottom.

### Concepts

- **Inbound** rules (tab "Inbound from VPN") match traffic that arrives through the tunnel at the tunnel's address, the *public address*. *Source* limits the remote addresses (empty = any).
- The **destination** of an inbound rule is exactly one IPv4 address in the local LAN (field "Destination (address in the local LAN)"). The Firewall page shows the addresses in its context line, e.g. "This device: 192.168.1.10 · Local LAN: 192.168.1.0/24 · IP forwarding: on", and the field offers the suggestion "This device's address: 192.168.1.10".
- An inbound rule to **this device's own LAN address** opens a port on this device, with allow, drop or reject; the *port on the VPN address* must be empty or equal to the destination port (this replaces the former "Host access" list). Any other LAN address makes the rule a port forward. This is decided again on every apply, because this device's address can change; reserve it in your router. The web UI port can never be opened, and the remote-access port is reserved.
- **Older settings:** `settings.json` of 0.1 and 0.2.0-alpha is migrated on start. Rules that 0.2.0-alpha stored with the destination "Host" keep working; the Firewall page shows them with this device's current LAN address, and the next save stores that address.
- **Empty port = any port.** For TCP, UDP and TCP+UDP an empty *source port* or *destination port* matches every port, in both directions and for allow, drop and reject. An inbound rule to this device's own address with an empty destination port opens every port of that protocol, except the web UI port: TCP to it from the tunnel is dropped before any rule.
- A **port forward** is an inbound rule to another LAN address: traffic to the *port on the VPN address* (public port) is translated (DNAT) to the destination address and *destination port*. The destination must lie in a LAN subnet of the host (the System page and the Firewall page list them; link-local addresses such as 169.254.x.x, Docker bridges, veth and tunnel interfaces are never counted as LAN). ESP and GRE forward the whole protocol to one device. A port forward with an empty destination port (the *port on the VPN address* stays empty too) forwards every port of its protocol to the device, except the web UI port and, while remote access is on, its port, which stay with the host; it cannot share its protocol with another forward.
- **Keep source address** off (default): TunnelDeck-VPN replaces the sender with its own LAN address (masquerade), so the device answers the host without any route change, but sees only the host as client. On: the device sees the real remote address and must send its replies back through the host, so the host must be its gateway (default route, or a route for the remote addresses). Needed where the remote address matters, for example IKE.
- **Outbound** rules (tab "Outbound to VPN") send traffic of a LAN device or subnet (*source*, required) to a destination behind the VPN (*destination*, `0.0.0.0/0` = everything) through the tunnel, translated to the tunnel address. LAN-to-LAN traffic of that source stays in the LAN.
- **Gateway requirement:** the host only sees traffic that is sent to it. A device with an outbound rule (or a port forward with keep source address) needs the host as its default gateway, or a static route for the destination network pointing to the host, set on the device or in the LAN router. The host itself needs IP forwarding.
- **Kill switch:** while the tunnel is down, traffic of outbound rules is dropped; it never leaves through the host's normal internet connection. Port forwards stop with the tunnel, since nothing arrives.

### IP forwarding

Port forwards and outbound rules need IPv4 forwarding on the host. Docker turns it on when it starts, so a Docker host normally has it. The **ip-forward** self-check on the System page and the line "IP forwarding: on/off" on the Firewall page show the current value. Check it on the host:

```sh
sysctl net.ipv4.ip_forward     # "net.ipv4.ip_forward = 1" means on
```

If it is `0`, switch it on and keep it on after a reboot:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/90-tunneldeck.conf
```

TunnelDeck-VPN reads the value but never changes it. Rules to this device's own address work without forwarding.

### An IPsec router in the local LAN

Reference case (SPEC §16.2): an IPsec router in the local LAN, for example at `192.168.1.2`, builds IPsec tunnels to remote peers using the tunnel's public address instead of its own internet connection. The remote peers connect to the public address; TunnelDeck-VPN forwards IKE and ESP to the router.

1. On the Firewall page choose **Add IPsec router**, enter a name, the router's address `192.168.1.2` and, optionally, the peers' public addresses. The template inserts five rules per peer (without peers once, for any source):

   | Direction | Protocol | Port | Source → destination | Keep source address |
   |---|---|---|---|---|
   | Inbound | UDP | 500 (IKE) | peer → `192.168.1.2` | on |
   | Inbound | UDP | 4500 (NAT-T) | peer → `192.168.1.2` | on |
   | Inbound | ESP | – | peer → `192.168.1.2` | on |
   | Outbound | UDP | – | `192.168.1.2` → peer (or `0.0.0.0/0`) | – |
   | Outbound | ESP | – | `192.168.1.2` → peer (or `0.0.0.0/0`) | – |

   Save the changes.
2. On the router, send the IPsec traffic to the host: a static route for each peer's public address (`/32`) with the host's LAN address as gateway, or the host as default gateway if the router has no other internet connection. The outbound rules carry the router's own IKE and ESP packets through the tunnel with the public address, which is what the peers expect.
3. On the router, configure the IPsec connection to each peer as usual, with these points:
   - IKEv2 with current proposals (for example AES-GCM, SHA-256, ECP-256).
   - NAT traversal must be allowed. The router's own address (`192.168.1.2`) differs from the public address the peer connects to, so both sides detect NAT and move IKE and ESP to UDP 4500.
   - Use an identity that is not the router's IP address (FQDN or e-mail type), on both sides, since the addresses differ because of the NAT.
4. On each peer, use the tunnel's public address as the router's address.

While the tunnel is down, the router's IPsec packets are dropped (kill switch) and its SAs fail over or expire as configured; they come back when the tunnel does.

What was tested and what was not:

- **Lab-tested** by the end-to-end test (`test/e2e/README.md`), on both iptables backends: strongSwan 6.0 as the LAN router and as the peer on the VPN side, PSK, IKEv2 with AES-GCM and ECP-256. The template rules are applied through the API, IKEv2 is established in both directions (peer to router and router to peer), both sides report NAT-T (`TUNNEL-in-UDP`), and the networks behind both ends ping each other through the SA. Plain ESP (protocol 50, without UDP encapsulation) through the ESP forward was tested with manually keyed SAs, because IKE always chooses NAT-T in this setup. Also tested: port forwards with and without keep source address, a source restriction, an outbound rule for one LAN device and the kill switch after a tunnel drop and after a disconnect.
- **Not tested:** a real IPsec router of any vendor, certificates instead of PSK, IKEv1, a real VPN provider's public address, and the MTU of IPsec inside the OpenVPN tunnel with large packets. If large transfers stall while small ones work, lower the MTU or the TCP MSS of the IPsec connection on the router.

#### Example: LANCOM router with mdex

With mdex public.IP the public address is the address of `publicipNN.mdex.de`. A LANCOM router at `192.168.1.2` is set up as described above: the template with the router's address, a static route for each peer's public address via the host (or the host as default gateway), IKEv2 with NAT traversal and an FQDN or e-mail identity, and `publicipNN.mdex.de` as the router's address on each peer. *Unverified:* neither a real LANCOM router nor a real mdex public.IP connection has been tested; the steps follow from the lab test with strongSwan.

## 11. WireGuard

TunnelDeck-VPN brings its own WireGuard: wireguard-go is built into the binary, so the host needs neither the `wireguard` kernel module nor `wireguard-tools`. It uses the same TUN device as OpenVPN (section 1) and the same firewall, kill switch and remote access.

1. **Keys:** in the profile form, **Generate key pair** creates a new private key. It is stored encrypted and never shown again; the form shows the matching **public key** with a Copy button.
2. **Server side:** add that public key on the WireGuard server as a peer, with the profile's tunnel address as the peer's allowed IP, for example `AllowedIPs = 10.66.0.2/32`. Enter the server's public key and its address (`host:port`) in the profile. Alternatively import the `.conf` file the server's administrator gave you; `DNS`, `Table`, IPv6 entries and further peers are dropped with a note, files with `PreUp`/`PostUp` scripts are refused.
3. **Ports:** the server must accept UDP on its listen port (51820 unless configured otherwise); open or forward that port in the server's firewall or router. TunnelDeck-VPN only connects outbound, so nothing has to be opened on this host. Persistent keepalive (default 25 s) keeps NAT mappings open, so the server can reach this side.
4. **Routing:** the allowed IP `0.0.0.0/0` does not change this host's default route; every other allowed IP is routed through the tunnel like a remote network. Which LAN devices may use the tunnel is set by outbound rules (section 10).
5. **State:** the dashboard shows "Connecting" until the first handshake. If it still shows "No answer from the server – check the keys and the endpoint" after 30 seconds, check both public keys, the server address and the server's UDP port.

The end-to-end test (`test/e2e/`) connects to a wireguard-go server on both iptables backends. *Unverified:* commercial WireGuard providers and arm64.
