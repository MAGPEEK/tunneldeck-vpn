# TunnelDeck-VPN on a Synology DS723+ (DSM 7.2)

[Deutsch](synology.de.md)

This guide runs TunnelDeck-VPN with Container Manager on DSM 7.2. The DS723+ is an x86-64 model, so it uses the `linux/amd64` image. Steps marked *check on your NAS* have not been verified on real DSM hardware yet.

## 1. Prerequisites

- DSM 7.2 with **Container Manager** installed from the Package Center.
- SSH enabled for the first check (Control Panel > Terminal & SNMP), or use a scheduled task instead.
- Two shared-folder paths under the `docker` share:
  - `docker/tunneldeck`: TunnelDeck-VPN's data (`/data` in the container),
  - `docker/tunneldeck-project`: the compose file for Container Manager.

### TUN device

OpenVPN needs `/dev/net/tun`. Check it over SSH:

```sh
ls -l /dev/net/tun
```

A line starting with `crw` means the device exists. If the file is missing, load the kernel module once by hand:

```sh
sudo insmod /lib/modules/tun.ko
```

To load it at every boot, create a task (Control Panel > Task Scheduler > Create > Triggered Task > User-defined script):

- General: user `root`, event `Boot-up`, enabled.
- Task Settings > Run command:

  ```sh
  lsmod | grep -q '^tun ' || insmod /lib/modules/tun.ko
  ```

Run the task once (select it, `Run`) and check `ls -l /dev/net/tun` again. Packages such as VPN Server may load the module already; the task does no harm then.

## 2. Create the project

1. Copy [`deploy/synology/docker-compose.yml`](../deploy/synology/docker-compose.yml) to `docker/tunneldeck-project` (File Station), or paste it in the next step.
2. Container Manager > Project > Create:
   - Project name: `tunneldeck`
   - Path: `/volume1/docker/tunneldeck-project`
   - Source: use the existing `docker-compose.yml`, or "Create docker-compose.yml" and paste the file.
3. Adjust `TZ` if needed, skip the web portal settings, and finish. Container Manager pulls `magpeek/tunneldeck-vpn` and starts the container.

The compose file gives the container host networking, `NET_ADMIN` and `/dev/net/tun`, and mounts `/volume1/docker/tunneldeck` as `/data`. Optional variables (listen address, log level, secret key, admin reset) are listed there as comments.

**Without internet access to Docker Hub:** build and export the image on another machine with `scripts/build-image.sh` and `scripts/export-image.sh`, then import `tunneldeck-<version>.tar` in Container Manager > Image > Add > Add from file. Set the `image:` line in the compose file to the imported tag.

## 3. First sign-in

1. Open `http://<NAS-IP>:8194`. TunnelDeck-VPN listens on the address of the interface that holds the default route; set `TUNNELDECK_LISTEN` to choose another address or port (example `192.168.1.10:9000`). The UI is never reachable through the VPN tunnel; remote access over the VPN is HTTPS only (System page, default port 8443, freely selectable).
2. Create the admin account (password of at least 12 characters).
3. Open **System** and check that every self-check passes: TUN device, iptables, `ip`, `NET_ADMIN`, IP forwarding and the LAN subnets (section 10). Each failed check shows a hint.

The container's health status in Container Manager shows whether the web server answers. It does not show whether the tunnel is up; the dashboard shows that.

## 4. DSM firewall

- If the DSM firewall is on (Control Panel > Security > Firewall), allow TCP `8194` from your LAN subnet only.
- If you use remote access (section 6), its port (default TCP `8443`) arrives through the tunnel device. TunnelDeck-VPN puts its own chain first in `INPUT` when it starts. DSM rebuilds its rules when you change firewall settings; restart the container afterwards so TunnelDeck-VPN's chain is first again. *Check on your NAS* with `sudo iptables -S INPUT | head -3`.
- Do not forward `8194` on your internet router. The plain-HTTP UI is meant for the LAN only.

## 5. HTTPS in the LAN with the DSM reverse proxy

Control Panel > Login Portal > Advanced > Reverse Proxy > Create:

- Source: protocol `HTTPS`, hostname of your choice (for example `tunneldeck.home.arpa`), port `8195`.
- Destination: protocol `HTTP`, hostname `<NAS-IP>` (not `localhost`, because TunnelDeck-VPN listens on the LAN address), port `8194`.
- Pick a certificate for the hostname under Control Panel > Security > Certificate > Settings.

The live view uses server-sent events; TunnelDeck-VPN sends `X-Accel-Buffering: no`, so the proxy passes them through without buffering. Sign-in checks that the browser's `Origin` matches the `Host` header. If sign-in fails behind the proxy, add a custom header `Host` = `$http_host` to the rule (*check on your NAS*). Behind the proxy, all browsers share the NAS address for the sign-in rate limit.

## 6. Remote access over the tunnel

To reach TunnelDeck-VPN from the internet through its VPN address (SPEC §8.1), open **System > Remote access**:

1. Turn it on and keep port `8443`, or choose a free port.
2. Keep the self-signed certificate, or upload your own certificate and key (PEM).
3. Note the SHA-256 fingerprint shown there and compare it with the browser's certificate warning on the first visit to `https://<VPN-address>:8443`.

The login page then becomes reachable from the internet. Use a long admin password. Only this HTTPS port is opened on the tunnel; the HTTP port 8194 stays closed there.

## 7. Backup

Back up the whole folder `docker/tunneldeck` (Hyper Backup or a copy):

- `settings.json`: admin account, firewall rules and settings, remote access, desired connection,
- `profiles.json`: profiles; secret fields encrypted,
- `secret.key`: the key for those secrets.

Without `secret.key` the stored passwords and keys cannot be decrypted. Keep the backup as protected as the NAS itself. If you set `TUNNELDECK_SECRET_KEY`, store that value with the backup instead.

## 8. Update

1. Back up `docker/tunneldeck` (section 7). A newer version may migrate the data files, and an older version refuses to start on migrated files.
2. Change the `image:` tag in the compose file to the new version (Container Manager > Project > tunneldeck > YAML configurations), or import the new `.tar` first.
3. Project > Action > Build. Container Manager pulls the image and recreates the container. A tunnel that was connected before reconnects by itself.
4. Check the version on the **System** page.

## 9. Lost admin password

Run `tunneldeck reset-admin` in the container: Container Manager > Container > tunneldeck > Terminal > Create > `tunneldeck reset-admin`, or over SSH:

```sh
sudo docker exec tunneldeck tunneldeck reset-admin
```

This removes the admin account and all sessions; profiles and settings stay. Open the UI and create the account again. Alternatively set `TUNNELDECK_RESET_ADMIN: "1"`, restart, sign up again, and remove the variable; it resets at every start while it is set.

## 10. Firewall rules and IPsec

The **Firewall** page controls what crosses the tunnel in both directions, to the NAS itself (**This device**) and to other devices in its LAN; everything no rule allows is dropped, replies always pass, rules apply top to bottom. The concepts (inbound and outbound rules, This device, port forwards, keep source address, the gateway requirement, the kill switch) are explained in [`linux.md`, section 10](linux.md#10-firewall-rules); they are the same on DSM. In short:

- An inbound rule to **This device** opens a port of the NAS on the tunnel address (for example DSM's `5001`). Host-access rules of 0.1 become such rules on the first start of 0.2.
- An inbound rule to another LAN address is a **port forward**. With **Keep source address** on, the device sees the real remote address and needs the NAS as its gateway.
- An **outbound** rule sends a LAN device's traffic through the tunnel. The device needs the NAS as gateway, or a route in the LAN router that points to the NAS. While the tunnel is down that traffic is dropped (kill switch).

### IP forwarding on DSM

Port forwards and outbound rules need IPv4 forwarding on the NAS. Container Manager (Docker) normally turns it on. The **ip-forward** self-check on the System page shows the value; over SSH:

```sh
cat /proc/sys/net/ipv4/ip_forward     # 1 means on
```

If it is `0`: Control Panel > Task Scheduler > Create > Triggered Task > User-defined script, user `root`, event **Boot-up**, script `sysctl -w net.ipv4.ip_forward=1`; run it once by hand. *Check on your NAS:* whether DSM keeps the value without the task. TunnelDeck-VPN never changes it.

### DSM firewall and forwarded traffic

The DSM firewall filters traffic to the NAS itself. TunnelDeck-VPN's chains are first in `INPUT` and `FORWARD` for tunnel traffic, so its rules decide there. *Check on your NAS:* that forwarded traffic between the tunnel and the LAN is not blocked by DSM's own rules (`sudo iptables -S FORWARD | head -5` should show the `TUNNELDECK-FORWARD` jumps first); restart the container after changing DSM firewall settings.

### Example: a LANCOM router in the LAN

Reference case (SPEC §16.2): an IPsec router in the LAN, here a LANCOM router at `192.168.2.2`, builds its IPsec tunnels through the tunnel's public address (mdex public.IP).

1. Firewall page > **Add IPsec device**: a name, device address `192.168.2.2`, optionally the peers' public addresses. The template inserts inbound UDP 500, UDP 4500 and ESP to `192.168.2.2` with keep source address on, and outbound UDP and ESP from `192.168.2.2` to the peers (or `0.0.0.0/0`). Save the changes.
2. In the router: a static route for each peer's public address (`/32`) via the NAS's LAN address, or the NAS as default gateway.
3. In the router's IPsec connection: IKEv2 with current proposals, NAT traversal allowed (the router's own address differs from the public address, so both sides move to UDP 4500), and on both sides an identity that is not an IP address (FQDN or e-mail type).
4. In each peer: the tunnel's public address as the router's address.

The table of the five rules and the full steps are in [`linux.md`, "Example: an IPsec router in the LAN"](linux.md#example-an-ipsec-router-in-the-lan). What was tested: the end-to-end test runs this case with strongSwan 6.0 on both sides (IKEv2 with PSK and NAT-T in both directions, plain ESP with manually keyed SAs) on both iptables backends, iptables-legacy included, but on a current Docker host kernel, not on DSM's kernel 4.4. *Not tested:* a real LANCOM router, DSM 7.2 itself, and a real mdex public.IP connection.
