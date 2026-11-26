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
    image: magpeek/tunneldeck-vpn:0.2.0-alpha.6
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
3. **System** öffnen und prüfen, dass alle Selbsttests bestehen: TUN-Gerät, iptables (nennt das verwendete Backend), `ip`, `NET_ADMIN`, IP-Weiterleitung (Abschnitt 10) und die LAN-Subnetze. Jeder fehlgeschlagene Test zeigt einen Hinweis.

Der Docker-Gesundheitsstatus zeigt, ob der Webserver antwortet, nicht ob der Tunnel steht.

## 4. Firewall: TunnelDeck-VPN, ufw, firewalld und Docker

Was TunnelDeck-VPN auf dem Host ändert (SPEC §6, §16):

- Kette `TUNNELDECK-INPUT`, angesprungen von Position 1 in `INPUT` für Verkehr, der über `tdvpn0` ankommt: bestehende Verbindungen annehmen, TCP an den Port der Weboberfläche verwerfen, die eingehenden Firewall-Regeln an die eigene LAN-Adresse dieses Geräts anwenden (und den Port des Fernzugriffs annehmen, solange er an ist), alles andere verwerfen.
- Kette `TUNNELDECK-FORWARD`, angesprungen von Position 1 in `FORWARD` für Verkehr von oder zu `tdvpn0` und für den Verkehr jeder ausgehenden Regel: Portweiterleitungen und ausgehende Regeln annehmen, alles andere verwerfen. Ohne solche Regeln wird nichts weitergeleitet.
- Ketten `TUNNELDECK-PREROUTING` und `TUNNELDECK-POSTROUTING` in der Tabelle `nat`: die Adressumsetzung der Portweiterleitungen und ausgehenden Regeln (Abschnitt 10).
- Routingtabelle `7194` mit einer Default-Route über `tdvpn0` und die Regel `from <VPN-Adresse> lookup 7194`, damit Antworten auf Verbindungen, die durch den Tunnel kamen, auch durch ihn zurückgehen; während der Verbindung außerdem die Policy-Regeln der Firewall (Prioritäten 7100–7191). Die Haupt-Routingtabelle bleibt unberührt; während der Verbindung erscheint dort nur die eigene Route des Kernels für das Tunnel-Subnetz.
- Die Ketten werden beim Start eingerichtet, vor jedem Verbinden und bei jeder Änderung der Firewall erneut angewendet und beim Stoppen des Containers entfernt.

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

Was jeder Eintrag der Seite System bedeutet und welches Modul eine Warnung behebt: [Systemprüfungen erklärt](system-checks.de.md).

Der iptables-Selbsttest auf der Seite System und das Start-Log (`iptables backend binary=... reason=...`) nennen die Wahl und den Grund. Wer sie übersteuern will, setzt `TUNNELDECK_IPTABLES` auf `nft` oder `legacy` (Standard `auto`).

Auch im gemeinsamen Backend wirken die Regeln zusammen, in fester Reihenfolge: TunnelDeck-VPN setzt seinen Sprung an Position 1 von `INPUT`, für Verkehr, der über `tdvpn0` ankommt, entscheidet also zuerst seine Kette, und diese Entscheidung gilt. Ein mit einer eingehenden Regel an die eigene LAN-Adresse dieses Geräts geöffneter Port (oder der Port des Fernzugriffs) ist erreichbar, auch wenn die Host-Firewall ihn verwerfen würde; alles andere aus dem Tunnel wird verworfen, auch wenn die Host-Firewall es erlaubt. Verkehr auf anderen Schnittstellen läuft nie durch die Ketten von TunnelDeck-VPN. Regeln in einer anderen *Tabelle* (die eigene nftables-Tabelle von firewalld oder das andere Backend auf einem gemischten Host) werden getrennt ausgewertet und können verwerfen, was TunnelDeck-VPN annimmt.

### ufw

Mit dem üblichen `default deny incoming` von ufw:

- Den UI-Port aus dem LAN erlauben, sonst sperrt ufw den Browser aus: `sudo ufw allow from 192.168.1.0/24 to any port 8194 proto tcp`.
- **Gleiches Backend** (der Normalfall: ufw auf nft, TunnelDeck-VPN zeigt `using iptables-nft`): Der Sprung von TunnelDeck-VPN steht in `INPUT` vor den Ketten von ufw, TunnelDeck-VPN entscheidet also allein über Tunnelverkehr. Eine eingehende Regel an die eigene LAN-Adresse dieses Geräts öffnet den Port; die eigenen Freigaben von ufw (zum Beispiel `ufw allow 22`) öffnen am Tunnel nichts. `ufw reload` lässt den Sprung von TunnelDeck-VPN an erster Stelle.
- **Verschiedene Backends** (nur wenn `TUNNELDECK_IPTABLES` das andere Backend erzwingt oder der Host beide mischt und das andere mehr Regeln enthält): Eine Regel in TunnelDeck-VPN allein reicht nicht, ufw verwirft den Port weiterhin. Ihn zusätzlich in ufw erlauben:

  ```sh
  sudo ufw allow in on tdvpn0 to any port 8443 proto tcp
  ```

  Die Regel lässt sich anlegen, auch wenn `tdvpn0` gerade nicht existiert. Ein nur in ufw erlaubter Port bleibt zu, weil TunnelDeck-VPN ihn verwirft.

Beide Fälle sind in einem Container-Labor geprüft (Alpine, ufw 0.36.2 auf iptables-nft, TunnelDeck-VPN mit einem Testserver verbunden, Proben durch den Tunnel). Der End-to-End-Test deckt den gemeinsamen Fall mit automatischer Erkennung ab: eine Host-Regel in nf_tables, die TCP aus dem Tunnel verwirft, und eingehende Regeln an die eigene LAN-Adresse des Hosts, die ihren Port trotzdem öffnen. Nicht geprüft auf einer vollständigen Distribution wie Ubuntu oder Debian.

### firewalld

firewalld (nftables-Backend, Standard seit 0.6) filtert in einer eigenen nftables-Tabelle. Eine Schnittstelle ohne Zone landet in der Standardzone (meist `public`, die nur wenige Dienste erlaubt); ein in TunnelDeck-VPN geöffneter Port bleibt also zu, bis firewalld ihn ebenfalls erlaubt. Entweder TunnelDeck-VPN allein entscheiden lassen:

```sh
sudo firewall-cmd --permanent --zone=trusted --add-interface=tdvpn0
sudo firewall-cmd --reload
```

oder `tdvpn0` in einer strengeren Zone lassen und die Ports dort freigeben (`--add-port=8443/tcp`). Den UI-Port aus dem LAN ebenfalls erlauben. *Ungeprüft:* Das folgt daraus, wie der Kernel mehrere Tabellen anwendet (wie oben für ufw gezeigt), wurde mit firewalld aber nicht getestet. Ob `firewall-cmd --reload` die Ketten von TunnelDeck-VPN in Ruhe lässt, ist ebenfalls *ungeprüft*; nach Firewall-Änderungen sicherheitshalber den Container neu starten, denn TunnelDeck-VPN richtet seine Ketten beim Start ein.

### Dockers eigene Ketten

Dockers Ketten (`DOCKER-USER`, `DOCKER-FORWARD`, die `nat`-Ketten) liegen in `FORWARD` und `nat`, nicht in `INPUT`; sie ändern also nicht, was den Host durch den Tunnel erreicht. TunnelDeck-VPN läuft im Host-Netz und veröffentlicht keine Ports. Seine Sprünge in `FORWARD` und `nat` stehen an Position 1, vor denen von Docker. *Ungeprüft:* Nach einem Neustart des Docker-Daemons setzt Docker seine `FORWARD`-Sprünge eventuell vor die von TunnelDeck-VPN, bis TunnelDeck-VPN seine Ketten neu einrichtet (nächstes Verbinden, nächste Änderung der Firewall oder Neustart des Containers); Dockers Ketten behandeln nur den Verkehr seiner eigenen Bridges, Portweiterleitungen und ausgehende Regeln zwischen Tunnel und LAN sollten also nicht betroffen sein.

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

- `settings.json`: Admin-Konto, Firewall-Regeln und -Einstellungen, Fernzugriff, gewünschte Verbindung,
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

Details und erwartete Ausgabe: [Admin-Passwort verloren](reset-admin.de.md).

## 10. Firewall-Regeln

Die Seite **Firewall** regelt, was den Tunnel passiert, in beide Richtungen, zu diesem Gerät und zu jedem anderen Gerät im lokalen LAN (SPEC §16). Was keine Regel erlaubt, wird in beide Richtungen verworfen; Antworten auf erlaubte Verbindungen kommen immer durch. Die Regeln gelten in der Reihenfolge der Liste, von oben nach unten.

### Begriffe

- **Eingehende** Regeln (Reiter „Eingehend vom VPN“) betreffen Verkehr, der durch den Tunnel an der Adresse des Tunnels ankommt, der *öffentlichen Adresse*. *Quelle* beschränkt die entfernten Adressen (leer = beliebig).
- Das **Ziel** einer eingehenden Regel ist genau eine IPv4-Adresse im lokalen LAN (Feld „Ziel (Adresse im lokalen LAN)“). Die Seite Firewall zeigt die Adressen in ihrer Kontextzeile, z. B. „Dieses Gerät: 192.168.1.10 · Lokales LAN: 192.168.1.0/24 · IP-Weiterleitung: an“, und das Feld bietet den Vorschlag „Adresse dieses Geräts: 192.168.1.10“ an.
- Eine eingehende Regel an die **eigene LAN-Adresse dieses Geräts** öffnet einen Port auf diesem Gerät, mit Erlauben, Verwerfen oder Ablehnen; der *Port auf der VPN-Adresse* muss leer oder gleich dem Zielport sein (das ersetzt die frühere Liste „Host-Zugriff“). Jede andere LAN-Adresse macht die Regel zu einer Portweiterleitung. Das wird bei jedem Anwenden neu entschieden, weil sich die Adresse dieses Geräts ändern kann; sie daher im Router reservieren. Der Port der Weboberfläche lässt sich nie öffnen, der Port des Fernzugriffs ist reserviert.
- **Ältere Einstellungen:** Eine `settings.json` von 0.1 und 0.2.0-alpha wird beim Start migriert. Regeln, die 0.2.0-alpha mit dem Ziel „Host“ gespeichert hat, funktionieren weiter; die Seite Firewall zeigt sie mit der aktuellen LAN-Adresse dieses Geräts, und das nächste Speichern legt diese Adresse ab.
- **Leerer Port = beliebiger Port.** Bei TCP, UDP und TCP+UDP passt ein leerer *Quellport* oder *Zielport* auf jeden Port, in beiden Richtungen und für Erlauben, Verwerfen und Ablehnen. Eine eingehende Regel an die eigene Adresse dieses Geräts mit leerem Zielport öffnet jeden Port dieses Protokolls, außer dem Port der Weboberfläche: TCP an ihn aus dem Tunnel wird vor jeder Regel verworfen.
- Eine **Portweiterleitung** ist eine eingehende Regel an eine andere LAN-Adresse: Verkehr an den *Port auf der VPN-Adresse* wird auf Zieladresse und *Zielport* umgesetzt (DNAT). Das Ziel muss in einem LAN-Subnetz des Hosts liegen (die Seiten System und Firewall zeigen sie; link-lokale Adressen wie 169.254.x.x, Docker-Bridges, veth- und Tunnel-Schnittstellen zählen nie als LAN). ESP und GRE leiten das ganze Protokoll an ein Gerät weiter. Eine Portweiterleitung mit leerem Zielport (der *Port auf der VPN-Adresse* bleibt dann ebenfalls leer) leitet jeden Port ihres Protokolls an das Gerät weiter, außer dem Port der Weboberfläche und, solange der Fernzugriff an ist, dessen Port; beide bleiben beim Host. Sie kann ihr Protokoll mit keiner anderen Weiterleitung teilen.
- **Quelladresse behalten** aus (Standard): TunnelDeck-VPN ersetzt den Absender durch seine eigene LAN-Adresse (Masquerade), das Gerät antwortet dem Host also ohne Routenänderung, sieht aber nur den Host als Client. An: Das Gerät sieht die echte entfernte Adresse und muss seine Antworten über den Host zurückschicken; der Host muss also sein Gateway sein (Default-Route oder eine Route für die entfernten Adressen). Nötig, wo die entfernte Adresse zählt, zum Beispiel bei IKE.
- **Ausgehende** Regeln (Reiter „Ausgehend ins VPN“) schicken Verkehr eines LAN-Geräts oder Subnetzes (*Quelle*, Pflicht) an ein Ziel hinter dem VPN (*Ziel*, `0.0.0.0/0` = alles) durch den Tunnel, umgesetzt auf die Tunneladresse. Verkehr dieser Quelle innerhalb des LANs bleibt im LAN.
- **Gateway-Voraussetzung:** Der Host sieht nur Verkehr, der an ihn geschickt wird. Ein Gerät mit einer ausgehenden Regel (oder einer Portweiterleitung mit behaltener Quelladresse) braucht den Host als Default-Gateway oder eine statische Route für das Zielnetz über den Host, eingetragen im Gerät oder im LAN-Router. Der Host selbst braucht die IP-Weiterleitung.
- **Kill-Switch:** Solange der Tunnel nicht steht, wird der Verkehr ausgehender Regeln verworfen; er verlässt den Host nie über dessen normale Internetverbindung. Portweiterleitungen enden mit dem Tunnel, weil nichts mehr ankommt.

### IP-Weiterleitung

Portweiterleitungen und ausgehende Regeln brauchen die IPv4-Weiterleitung auf dem Host. Docker schaltet sie beim Start ein, ein Docker-Host hat sie also normalerweise. Der Selbsttest **ip-forward** auf der Seite System und die Zeile „IP-Weiterleitung: an/aus“ auf der Seite Firewall zeigen den aktuellen Wert. Auf dem Host prüfen:

```sh
sysctl net.ipv4.ip_forward     # "net.ipv4.ip_forward = 1" heißt an
```

Steht sie auf `0`, einschalten und über einen Neustart hinweg behalten:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/90-tunneldeck.conf
```

TunnelDeck-VPN liest den Wert, ändert ihn aber nie. Regeln an die eigene Adresse dieses Geräts funktionieren ohne Weiterleitung.

### Ein IPsec-Router im lokalen LAN

Referenzfall (SPEC §16.2): Ein IPsec-Router im lokalen LAN, zum Beispiel unter `192.168.1.2`, baut IPsec-Tunnel zu entfernten Gegenstellen über die öffentliche Adresse des Tunnels auf statt über seine eigene Internetverbindung. Die Gegenstellen verbinden sich mit der öffentlichen Adresse; TunnelDeck-VPN leitet IKE und ESP an den Router weiter.

1. Auf der Seite Firewall **IPsec-Router hinzufügen** wählen, einen Namen, die Adresse des Routers `192.168.1.2` und optional die öffentlichen Adressen der Gegenstellen eingeben. Die Vorlage fügt je Gegenstelle fünf Regeln ein (ohne Gegenstellen einmal, für jede Quelle):

   | Richtung | Protokoll | Port | Quelle → Ziel | Quelladresse behalten |
   |---|---|---|---|---|
   | Eingehend | UDP | 500 (IKE) | Gegenstelle → `192.168.1.2` | an |
   | Eingehend | UDP | 4500 (NAT-T) | Gegenstelle → `192.168.1.2` | an |
   | Eingehend | ESP | – | Gegenstelle → `192.168.1.2` | an |
   | Ausgehend | UDP | – | `192.168.1.2` → Gegenstelle (oder `0.0.0.0/0`) | – |
   | Ausgehend | ESP | – | `192.168.1.2` → Gegenstelle (oder `0.0.0.0/0`) | – |

   Die Änderungen speichern.
2. Im Router den IPsec-Verkehr zum Host schicken: eine statische Route für die öffentliche Adresse jeder Gegenstelle (`/32`) mit der LAN-Adresse des Hosts als Gateway, oder den Host als Default-Gateway, wenn der Router keine andere Internetverbindung hat. Die ausgehenden Regeln bringen die eigenen IKE- und ESP-Pakete des Routers mit der öffentlichen Adresse durch den Tunnel, wie es die Gegenstellen erwarten.
3. Im Router die IPsec-Verbindung zu jeder Gegenstelle wie gewohnt einrichten, mit diesen Punkten:
   - IKEv2 mit aktuellen Proposals (zum Beispiel AES-GCM, SHA-256, ECP-256).
   - NAT-Traversal muss erlaubt sein. Die eigene Adresse des Routers (`192.168.1.2`) unterscheidet sich von der öffentlichen Adresse, an die sich die Gegenstelle wendet; beide Seiten erkennen daher NAT und verlegen IKE und ESP auf UDP 4500.
   - Auf beiden Seiten eine Identität verwenden, die nicht die IP-Adresse des Routers ist (Typ FQDN oder E-Mail), weil sich die Adressen durch das NAT unterscheiden.
4. In jeder Gegenstelle die öffentliche Adresse des Tunnels als Adresse des Routers eintragen.

Solange der Tunnel nicht steht, werden die IPsec-Pakete des Routers verworfen (Kill-Switch), und seine SAs wechseln oder laufen ab, wie im Router eingestellt; sie kommen mit dem Tunnel zurück.

Was geprüft ist und was nicht:

- **Im Labor geprüft** vom End-to-End-Test (`test/e2e/README.md`), mit beiden iptables-Backends: strongSwan 6.0 als LAN-Router und als Gegenstelle auf der VPN-Seite, PSK, IKEv2 mit AES-GCM und ECP-256. Die Regeln der Vorlage werden über die API angewendet, IKEv2 wird in beide Richtungen aufgebaut (Gegenstelle zu Router und Router zu Gegenstelle), beide Seiten melden NAT-T (`TUNNEL-in-UDP`), und die Netze hinter beiden Enden pingen sich durch die SA an. Reines ESP (Protokoll 50, ohne UDP-Kapselung) durch die ESP-Weiterleitung wurde mit SAs mit manuell gesetzten Schlüsseln geprüft, weil IKE in diesem Aufbau immer NAT-T wählt. Ebenfalls geprüft: Portweiterleitungen mit und ohne behaltene Quelladresse, eine Quellbeschränkung, eine ausgehende Regel für ein LAN-Gerät und der Kill-Switch nach einem Tunnelabbruch und nach dem Trennen.
- **Nicht geprüft:** ein echter IPsec-Router eines beliebigen Herstellers, Zertifikate statt PSK, IKEv1, die öffentliche Adresse eines echten VPN-Anbieters und die MTU von IPsec im OpenVPN-Tunnel bei großen Paketen. Bleiben große Übertragungen hängen, während kleine funktionieren, MTU oder TCP-MSS der IPsec-Verbindung im Router senken.

#### Beispiel: LANCOM-Router mit mdex

Bei mdex public.IP ist die öffentliche Adresse die Adresse von `publicipNN.mdex.de`. Ein LANCOM-Router unter `192.168.1.2` wird wie oben beschrieben eingerichtet: die Vorlage mit der Adresse des Routers, eine statische Route für die öffentliche Adresse jeder Gegenstelle über den Host (oder der Host als Default-Gateway), IKEv2 mit NAT-Traversal und einer Identität vom Typ FQDN oder E-Mail, und in jeder Gegenstelle `publicipNN.mdex.de` als Adresse des Routers. *Ungeprüft:* Weder ein echter LANCOM-Router noch eine echte mdex-public.IP-Verbindung wurden getestet; die Schritte folgen aus dem Labortest mit strongSwan.
