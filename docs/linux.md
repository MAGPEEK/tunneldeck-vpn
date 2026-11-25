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
    image: magpeek/tunneldeck-vpn:0.1.0-dev
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
3. Open **System** and check that every self-check passes: TUN device, iptables (it names the backend in use), `ip`, `NET_ADMIN`. Each failed check shows a hint.

The Docker health status shows whether the web server answers, not whether the tunnel is up.

## 4. Firewall: TunnelDeck-VPN, ufw, firewalld and Docker

What TunnelDeck-VPN changes on the host (SPEC §6):

- Chain `TUNNELDECK-INPUT`, jumped to from position 1 of `INPUT` for traffic arriving on `tdvpn0`: accept established connections, accept the ports you allow under **Host access** (and the remote-access port while it is on), drop everything else.
- Chain `TUNNELDECK-FORWARD`, jumped to from position 1 of `FORWARD` for traffic in or out of `tdvpn0`: drop everything (nothing is forwarded in this version).
- Routing table `7194` with a default route via `tdvpn0`, and the rule `from <VPN address> lookup 7194`, so replies to connections that came in through the tunnel leave through it. The main routing table is not touched; the only entry that appears there while connected is the kernel's own route for the tunnel subnet.
- The chains are installed at start, re-applied before every connect and whenever host-access rules change, and removed when the container stops.

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

The iptables self-check on the System page and the start log (`iptables backend binary=... reason=...`) name the choice and the reason. To override it, set `TUNNELDECK_IPTABLES` to `nft` or `legacy` (default `auto`).

On a shared backend the rules still interact, in a fixed order: TunnelDeck-VPN inserts its jump at position 1 of `INPUT`, so for traffic arriving on `tdvpn0` its chain decides first and that decision wins. A port opened under **Host access** (or the remote-access port) is reachable even if the host firewall would drop it; everything else from the tunnel is dropped even if the host firewall allows it. Traffic on other interfaces never enters TunnelDeck-VPN's chains. Rules in another *table* (firewalld's own nftables table, or the other backend on a mixed host) are evaluated separately and can still drop what TunnelDeck-VPN accepts.

### ufw

With ufw's usual `default deny incoming`:

- Allow the UI port from your LAN, otherwise ufw blocks the browser: `sudo ufw allow from 192.168.1.0/24 to any port 8194 proto tcp`.
- **Same backend** (the normal case: ufw on nft, TunnelDeck-VPN shows `using iptables-nft`): TunnelDeck-VPN's jump sits before ufw's chains in `INPUT`, so TunnelDeck-VPN alone decides about tunnel traffic. A host-access rule opens the port; ufw's own allow rules (for example `ufw allow 22`) open nothing on the tunnel. `ufw reload` keeps TunnelDeck-VPN's jump first.
- **Different backends** (only when `TUNNELDECK_IPTABLES` forces the other backend, or the host mixes both and the other one holds more rules): a host-access rule alone is not enough, because ufw still drops the port. Allow it in ufw too:

  ```sh
  sudo ufw allow in on tdvpn0 to any port 8443 proto tcp
  ```

  The rule can be added while `tdvpn0` does not exist. A port allowed only in ufw stays closed, because TunnelDeck-VPN drops it.

Both cases were verified in a container lab (Alpine, ufw 0.36.2 on iptables-nft, TunnelDeck-VPN connected to a test server, probes through the tunnel). The end-to-end test covers the shared case with automatic detection: a host rule in nf_tables that drops TCP from the tunnel, and host-access rules that still open their port. Not verified on a full distribution install such as Ubuntu or Debian.

### firewalld

firewalld (nftables backend, the default since 0.6) filters in its own nftables table. An interface without a zone falls into the default zone (usually `public`, which allows only a few services), so a port opened in TunnelDeck-VPN stays closed until firewalld allows it too. Either let TunnelDeck-VPN alone decide:

```sh
sudo firewall-cmd --permanent --zone=trusted --add-interface=tdvpn0
sudo firewall-cmd --reload
```

or keep a stricter zone for `tdvpn0` and add the ports there (`--add-port=8443/tcp`). Allow the UI port from the LAN as well. *Unverified:* this follows from how the kernel applies several tables, as shown for ufw above, but was not tested with firewalld. Whether `firewall-cmd --reload` leaves TunnelDeck-VPN's chains alone is also *unverified*; restart the container after changing the firewall to be sure, since TunnelDeck-VPN installs its chains at start.

### Docker's own chains

Docker's chains (`DOCKER-USER`, `DOCKER-FORWARD`, the `nat` chains) sit in `FORWARD` and `nat`, not in `INPUT`, so they do not change what reaches the host through the tunnel. TunnelDeck-VPN runs with host networking and publishes no ports. *Unverified:* after a Docker daemon restart Docker may put its `FORWARD` jumps above TunnelDeck-VPN's until TunnelDeck-VPN re-installs its chains (next connect or container restart). This version forwards nothing, so this has no effect yet.

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

- `settings.json`: admin account, host-access rules, remote access, desired connection,
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
