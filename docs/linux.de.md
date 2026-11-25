# TunnelDeck-VPN auf einem Linux-Docker-Host

[English](linux.md)

Diese Anleitung betreibt TunnelDeck-VPN auf jedem Linux-Host mit Docker: Server, Mini-PC, Raspberry Pi. Nichts davon hängt von einer Distribution ab. Verbinden, Routing und Host-Schutz sind mit dem End-to-End-Test (`test/e2e/`) auf beiden iptables-Backends geprüft, die ufw-Hinweise in einem Container-Labor. Mit *ungeprüft* markierte Punkte sind nicht getestet.

## 1. Voraussetzungen

- **Docker Engine mit Compose v2** (`docker compose version`).
- **CPU:** amd64 oder arm64. Das Image wird für `linux/amd64` und `linux/arm64` gebaut; arm64 ist bisher *ungeprüft*.
- **TUN-Gerät.** Prüfen:

  ```sh
  ls -l /dev/net/tun
  ```

  Eine Zeile, die mit `crw` beginnt, heißt: Das Gerät ist da. Sonst das Modul laden und dauerhaft eintragen:

  ```sh
  sudo modprobe tun
  echo tun | sudo tee /etc/modules-load.d/tun.conf
  ```

- **iptables-Unterstützung im Kernel**: nftables (`nf_tables`, jede aktuelle Distribution) oder die alten Module `ip_tables`/`iptable_filter` (alte Kernel wie der 4.4 von DSM). Das Image enthält `iptables-legacy` und `iptables-nft`; TunnelDeck-VPN nimmt das, welches die Firewall des Hosts bereits nutzt (siehe Abschnitt 4). Der Container kann keine Kernelmodule laden: Funktioniert keins, eins auf dem Host laden, zum Beispiel `sudo modprobe nf_tables` oder `sudo modprobe -a ip_tables iptable_filter`.
- **Policy-Routing** (`ip rule`), in jedem Distributionskernel enthalten.

## 2. Starten

Ein Verzeichnis anlegen, zum Beispiel `/opt/tunneldeck`, mit dieser `docker-compose.yml`:

```yaml
services:
  tunneldeck:
    image: magpeek/tunneldeck-vpn:0.1.0-alpha.1
    container_name: tunneldeck
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes: ["./data:/data"]
    environment:
      TZ: Europe/Berlin
      # TUNNELDECK_LISTEN: "192.168.1.10:8194"  # Standard: Schnittstelle der Default-Route, Port 8194
      # TUNNELDECK_IPTABLES: nft                # Standard auto: Backend der Host-Firewall
    restart: unless-stopped
```

```sh
docker compose up -d
docker compose logs -f
```

`network_mode: host` ist nötig: TunnelDeck-VPN verwaltet das Gerät `tdvpn0` des Hosts, sein Policy-Routing und seine Firewall-Ketten. `NET_ADMIN` und `/dev/net/tun` genügen; der Container läuft nicht privilegiert.

## 3. Erste Anmeldung

1. `http://<Host-IP>:8194` öffnen. TunnelDeck-VPN lauscht auf der Adresse der Schnittstelle mit der Default-Route (das Log zeigt `listening address=...`). Mit `TUNNELDECK_LISTEN` lassen sich andere Adresse und Port wählen (Beispiel `192.168.1.10:9000`). Durch den VPN-Tunnel ist die Oberfläche nie erreichbar; Fernzugriff über das VPN gibt es nur per HTTPS (Seite System, Standardport 8443, frei wählbar).
2. Das Admin-Konto anlegen (Passwort mit mindestens 12 Zeichen).
3. **System** öffnen und prüfen, dass alle Selbsttests bestehen: TUN-Gerät, iptables (nennt das verwendete Backend), `ip`, `NET_ADMIN`. Jeder fehlgeschlagene Test zeigt einen Hinweis.

Der Docker-Gesundheitsstatus zeigt, ob der Webserver antwortet, nicht ob der Tunnel steht.

## 4. Firewall: TunnelDeck-VPN, ufw, firewalld und Docker

Was TunnelDeck-VPN auf dem Host ändert (SPEC §6):

- Kette `TUNNELDECK-INPUT`, angesprungen von Position 1 in `INPUT` für Verkehr, der über `tdvpn0` ankommt: bestehende Verbindungen annehmen, die unter **Host-Zugriff** freigegebenen Ports annehmen (und den Port des Fernzugriffs, solange er an ist), alles andere verwerfen.
- Kette `TUNNELDECK-FORWARD`, angesprungen von Position 1 in `FORWARD` für Verkehr von oder zu `tdvpn0`: alles verwerfen (diese Version leitet nichts weiter).
- Routingtabelle `7194` mit einer Default-Route über `tdvpn0` und die Regel `from <VPN-Adresse> lookup 7194`, damit Antworten auf Verbindungen, die durch den Tunnel kamen, auch durch ihn zurückgehen. Die Haupt-Routingtabelle bleibt unberührt; während der Verbindung erscheint dort nur die eigene Route des Kernels für das Tunnel-Subnetz.
- Die Ketten werden beim Start eingerichtet, vor jedem Verbinden und bei jeder Änderung der Host-Zugriffsregeln erneut angewendet und beim Stoppen des Containers entfernt.

Den Zustand mit dem Backend prüfen, das TunnelDeck-VPN verwendet (der iptables-Selbsttest auf der Seite System nennt es):

```sh
sudo iptables-nft -S INPUT | head -3        # Backend "iptables-nft"
sudo iptables-legacy -S INPUT | head -3     # Backend "iptables-legacy"
ip rule show; ip route show table 7194
```

### Welches iptables-Backend TunnelDeck-VPN nutzt

`iptables-legacy` und `iptables-nft` führen getrennte Regelwerke, und der Kernel wendet beide an: Ein Paket muss die Legacy-Ketten *und* die nftables-Ketten passieren. Ein `ACCEPT` im einen hebt ein `DROP` im anderen nicht auf. TunnelDeck-VPN teilt sich deshalb das Backend mit der Firewall des Hosts. Beim Start listet es mit beiden Programmen die Tabellen `filter` und `nat` und zählt die Regeln darin, ohne seine eigenen Ketten und ohne `ACCEPT`-Policies:

- nur ein Backend funktioniert: dieses (alte Kernel wie der 4.4 von DSM haben nur legacy),
- nur ein Backend enthält Regeln: dieses,
- beide enthalten Regeln: das mit mehr Regeln; die Seite System und das Log warnen, dass der Host beide Backends mischt und die Regeln des anderen weiter gelten,
- keins enthält Regeln: nf_tables.

Der iptables-Selbsttest auf der Seite System und das Start-Log (`iptables backend binary=... reason=...`) nennen die Wahl und den Grund. Wer sie übersteuern will, setzt `TUNNELDECK_IPTABLES` auf `nft` oder `legacy` (Standard `auto`).

Auch im gemeinsamen Backend wirken die Regeln zusammen, in fester Reihenfolge: TunnelDeck-VPN setzt seinen Sprung an Position 1 von `INPUT`, für Verkehr, der über `tdvpn0` ankommt, entscheidet also zuerst seine Kette, und diese Entscheidung gilt. Ein unter **Host-Zugriff** freigegebener Port (oder der Port des Fernzugriffs) ist erreichbar, auch wenn die Host-Firewall ihn verwerfen würde; alles andere aus dem Tunnel wird verworfen, auch wenn die Host-Firewall es erlaubt. Verkehr auf anderen Schnittstellen läuft nie durch die Ketten von TunnelDeck-VPN. Regeln in einer anderen *Tabelle* (die eigene nftables-Tabelle von firewalld oder das andere Backend auf einem gemischten Host) werden getrennt ausgewertet und können verwerfen, was TunnelDeck-VPN annimmt.

### ufw

Mit dem üblichen `default deny incoming` von ufw:

- Den UI-Port aus dem LAN erlauben, sonst sperrt ufw den Browser aus: `sudo ufw allow from 192.168.1.0/24 to any port 8194 proto tcp`.
- **Gleiches Backend** (der Normalfall: ufw auf nft, TunnelDeck-VPN zeigt `using iptables-nft`): Der Sprung von TunnelDeck-VPN steht in `INPUT` vor den Ketten von ufw, TunnelDeck-VPN entscheidet also allein über Tunnelverkehr. Eine Host-Zugriffsregel öffnet den Port; die eigenen Freigaben von ufw (zum Beispiel `ufw allow 22`) öffnen am Tunnel nichts. `ufw reload` lässt den Sprung von TunnelDeck-VPN an erster Stelle.
- **Verschiedene Backends** (nur wenn `TUNNELDECK_IPTABLES` das andere Backend erzwingt oder der Host beide mischt und das andere mehr Regeln enthält): Eine Host-Zugriffsregel allein reicht nicht, ufw verwirft den Port weiterhin. Ihn zusätzlich in ufw erlauben:

  ```sh
  sudo ufw allow in on tdvpn0 to any port 8443 proto tcp
  ```

  Die Regel lässt sich anlegen, auch wenn `tdvpn0` gerade nicht existiert. Ein nur in ufw erlaubter Port bleibt zu, weil TunnelDeck-VPN ihn verwirft.

Beide Fälle sind in einem Container-Labor geprüft (Alpine, ufw 0.36.2 auf iptables-nft, TunnelDeck-VPN mit einem Testserver verbunden, Proben durch den Tunnel). Der End-to-End-Test deckt den gemeinsamen Fall mit automatischer Erkennung ab: eine Host-Regel in nf_tables, die TCP aus dem Tunnel verwirft, und Host-Zugriffsregeln, die ihren Port trotzdem öffnen. Nicht geprüft auf einer vollständigen Distribution wie Ubuntu oder Debian.

### firewalld

firewalld (nftables-Backend, Standard seit 0.6) filtert in einer eigenen nftables-Tabelle. Eine Schnittstelle ohne Zone landet in der Standardzone (meist `public`, die nur wenige Dienste erlaubt); ein in TunnelDeck-VPN geöffneter Port bleibt also zu, bis firewalld ihn ebenfalls erlaubt. Entweder TunnelDeck-VPN allein entscheiden lassen:

```sh
sudo firewall-cmd --permanent --zone=trusted --add-interface=tdvpn0
sudo firewall-cmd --reload
```

oder `tdvpn0` in einer strengeren Zone lassen und die Ports dort freigeben (`--add-port=8443/tcp`). Den UI-Port aus dem LAN ebenfalls erlauben. *Ungeprüft:* Das folgt daraus, wie der Kernel mehrere Tabellen anwendet (wie oben für ufw gezeigt), wurde mit firewalld aber nicht getestet. Ob `firewall-cmd --reload` die Ketten von TunnelDeck-VPN in Ruhe lässt, ist ebenfalls *ungeprüft*; nach Firewall-Änderungen sicherheitshalber den Container neu starten, denn TunnelDeck-VPN richtet seine Ketten beim Start ein.

### Dockers eigene Ketten

Dockers Ketten (`DOCKER-USER`, `DOCKER-FORWARD`, die `nat`-Ketten) liegen in `FORWARD` und `nat`, nicht in `INPUT`; sie ändern also nicht, was den Host durch den Tunnel erreicht. TunnelDeck-VPN läuft im Host-Netz und veröffentlicht keine Ports. *Ungeprüft:* Nach einem Neustart des Docker-Daemons setzt Docker seine `FORWARD`-Sprünge eventuell vor die von TunnelDeck-VPN, bis TunnelDeck-VPN seine Ketten neu einrichtet (nächstes Verbinden oder Neustart des Containers). Diese Version leitet nichts weiter, daher hat das noch keine Wirkung.

## 5. HTTPS im LAN mit einem Reverse Proxy

Die Oberfläche auf Port 8194 spricht reines HTTP. Für HTTPS im LAN einen Reverse Proxy davorsetzen, zum Beispiel Caddy:

```
tunneldeck.home.arpa {
    reverse_proxy 192.168.1.10:8194
}
```

oder nginx:

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

- Auf die LAN-Adresse weiterleiten, auf der TunnelDeck-VPN lauscht, nicht auf `127.0.0.1` (außer `TUNNELDECK_LISTEN` sagt das).
- Den `Host`-Header erhalten: Anmeldung und jede Änderung prüfen, dass der `Origin` des Browsers zu `Host` passt. Caddy erhält ihn von selbst.
- Die Live-Ansicht nutzt Server-Sent Events; TunnelDeck-VPN sendet `X-Accel-Buffering: no`, was nginx beachtet.
- Hinter einem Proxy teilen sich alle Browser die Adresse des Proxys für die Begrenzung der Anmeldeversuche.

Beide Proxy-Beispiele sind *ungeprüft*.

## 6. Fernzugriff über den Tunnel

Um die Oberfläche aus dem Internet über die VPN-Adresse zu erreichen (SPEC §8.1), **System > Fernzugriff** öffnen, einschalten (Standardport `8443`), das selbstsignierte Zertifikat behalten oder ein eigenes hochladen und den dort angezeigten SHA-256-Fingerabdruck beim ersten Aufruf von `https://<VPN-Adresse>:8443` mit der Warnung des Browsers vergleichen. Nur dieser HTTPS-Port öffnet sich am Tunnel; 8194 bleibt dort zu (vom End-to-End-Test geprüft). Die Anmeldeseite ist dann aus dem Internet erreichbar: ein langes Admin-Passwort verwenden. Mit einer Host-Firewall siehe Abschnitt 4.

## 7. Sicherung

Das Datenverzeichnis sichern (`./data` neben der Compose-Datei):

- `settings.json`: Admin-Konto, Host-Zugriffsregeln, Fernzugriff, gewünschte Verbindung,
- `profiles.json`: Profile; geheime Felder verschlüsselt,
- `secret.key`: der Schlüssel für diese Geheimnisse.

Ohne `secret.key` lassen sich die gespeicherten Passwörter und Schlüssel nicht entschlüsseln. Ist `TUNNELDECK_SECRET_KEY` gesetzt, stattdessen diesen Wert mit der Sicherung aufbewahren. Die Sicherung so gut schützen wie den Host selbst. Für eine konsistente Kopie den Container vorher stoppen:

```sh
docker compose stop && sudo tar czf tunneldeck-backup.tgz data && docker compose start
```

## 8. Aktualisieren

1. Das Datenverzeichnis sichern (Abschnitt 7). Eine neuere Version migriert die Datendateien eventuell, und eine ältere startet mit migrierten Dateien nicht.
2. Das neue Tag in `image:` eintragen, dann:

   ```sh
   docker compose pull && docker compose up -d
   ```

3. Ein vorher verbundener Tunnel verbindet sich von selbst wieder (für einen Neustart des Containers vom End-to-End-Test geprüft). Die Version auf der Seite **System** prüfen.

## 9. Admin-Passwort vergessen

```sh
docker exec tunneldeck tunneldeck reset-admin
```

Das entfernt das Admin-Konto und alle Sitzungen; Profile und Einstellungen bleiben. Die Oberfläche öffnen und das Konto neu anlegen. Alternativ `TUNNELDECK_RESET_ADMIN: "1"` setzen, neu starten, das Konto neu anlegen und die Variable wieder entfernen; solange sie gesetzt ist, setzt sie bei jedem Start zurück.
