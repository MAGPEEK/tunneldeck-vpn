# TunnelDeck-VPN auf einer Synology DS723+ (DSM 7.2)

[English](synology.md)

Diese Anleitung betreibt TunnelDeck-VPN mit dem Container Manager unter DSM 7.2. Die DS723+ ist ein x86-64-Modell und nutzt das Image für `linux/amd64`. Mit *auf der NAS prüfen* markierte Schritte sind auf echter DSM-Hardware noch nicht geprüft.

## 1. Voraussetzungen

- DSM 7.2 mit **Container Manager** aus dem Paket-Zentrum.
- SSH für die erste Prüfung (Systemsteuerung > Terminal & SNMP), oder stattdessen eine geplante Aufgabe.
- Zwei Ordner in der Freigabe `docker`:
  - `docker/tunneldeck`: die Daten von TunnelDeck-VPN (`/data` im Container),
  - `docker/tunneldeck-project`: die Compose-Datei für den Container Manager.

### TUN-Gerät

OpenVPN braucht `/dev/net/tun`. Per SSH prüfen:

```sh
ls -l /dev/net/tun
```

Eine Zeile, die mit `crw` beginnt, heißt: Das Gerät ist da. Fehlt die Datei, das Kernelmodul einmal von Hand laden:

```sh
sudo insmod /lib/modules/tun.ko
```

Damit es bei jedem Start geladen wird, eine Aufgabe anlegen (Systemsteuerung > Aufgabenplaner > Erstellen > Ausgelöste Aufgabe > Benutzerdefiniertes Skript):

- Allgemein: Benutzer `root`, Ereignis `Hochfahren`, aktiviert.
- Aufgabeneinstellungen > Befehl ausführen:

  ```sh
  lsmod | grep -q '^tun ' || insmod /lib/modules/tun.ko
  ```

Die Aufgabe einmal ausführen (auswählen, `Ausführen`) und `ls -l /dev/net/tun` erneut prüfen. Pakete wie der VPN Server laden das Modul unter Umständen schon; die Aufgabe schadet dann nicht.

## 2. Projekt anlegen

1. [`deploy/synology/docker-compose.yml`](../deploy/synology/docker-compose.yml) nach `docker/tunneldeck-project` kopieren (File Station) oder im nächsten Schritt einfügen.
2. Container Manager > Projekt > Erstellen:
   - Projektname: `tunneldeck`
   - Pfad: `/volume1/docker/tunneldeck-project`
   - Quelle: vorhandene `docker-compose.yml` verwenden, oder „docker-compose.yml erstellen“ und die Datei einfügen.
3. `TZ` bei Bedarf anpassen, die Webportal-Einstellungen überspringen und abschließen. Der Container Manager lädt `magpeek/tunneldeck-vpn` und startet den Container.

Die Compose-Datei gibt dem Container das Host-Netzwerk, `NET_ADMIN` und `/dev/net/tun` und bindet `/volume1/docker/tunneldeck` als `/data` ein. Optionale Variablen (Listen-Adresse, Log-Level, Geheimschlüssel, Admin-Reset) stehen dort als Kommentare.

**Ohne Internetzugang zu Docker Hub:** Das Image auf einem anderen Rechner mit `scripts/build-image.sh` bauen und mit `scripts/export-image.sh` exportieren, dann `tunneldeck-<version>.tar` im Container Manager unter Image > Hinzufügen > Aus Datei hinzufügen importieren. Die Zeile `image:` in der Compose-Datei auf das importierte Tag setzen.

## 3. Erste Anmeldung

1. `http://<NAS-IP>:8194` öffnen. TunnelDeck-VPN lauscht auf der Adresse der Schnittstelle mit der Standardroute; andere Adresse und Port setzt `TUNNELDECK_LISTEN` (Beispiel `192.168.1.10:9000`). Durch den VPN-Tunnel ist die Oberfläche nie erreichbar; Fernzugriff über das VPN gibt es nur per HTTPS (Seite System, Standardport 8443, frei wählbar).
2. Das Admin-Konto anlegen (Passwort mit mindestens 12 Zeichen).
3. **System** öffnen und prüfen, ob alle Selbsttests bestanden sind: TUN-Gerät, iptables, `ip`, `NET_ADMIN`, IP-Weiterleitung und die LAN-Subnetze (Abschnitt 10). Jeder fehlgeschlagene Test zeigt einen Hinweis. Warnungen zu fehlenden iptables-Modulen schränken nur eine Schutzfunktion ein (Abschnitt 10, „Schutzfunktionen, die dem DSM-Kernel fehlen können“).

Der Integritätsstatus im Container Manager zeigt, ob der Webserver antwortet. Ob der Tunnel steht, zeigt er nicht; das zeigt das Dashboard.

## 4. DSM-Firewall

- Ist die DSM-Firewall an (Systemsteuerung > Sicherheit > Firewall), TCP `8194` nur aus dem eigenen LAN-Subnetz erlauben.
- Mit Fernzugriff (Abschnitt 6) kommt dessen Port (Standard TCP `8443`) über das Tunnelgerät herein. TunnelDeck-VPN setzt seine eigene Kette beim Start an die erste Stelle von `INPUT`. DSM baut seine Regeln neu auf, wenn sich Firewall-Einstellungen ändern; danach den Container neu starten, damit die Kette von TunnelDeck-VPN wieder vorne steht. *Auf der NAS prüfen* mit `sudo iptables -S INPUT | head -3`.
- `8194` nicht am Internet-Router weiterleiten. Die Oberfläche über HTTP ist nur fürs LAN gedacht.

## 5. HTTPS im LAN über den DSM-Reverse-Proxy

Systemsteuerung > Anmeldeportal > Erweitert > Reverse Proxy > Erstellen:

- Quelle: Protokoll `HTTPS`, frei gewählter Hostname (zum Beispiel `tunneldeck.home.arpa`), Port `8195`.
- Ziel: Protokoll `HTTP`, Hostname `<NAS-IP>` (nicht `localhost`, weil TunnelDeck-VPN auf der LAN-Adresse lauscht), Port `8194`.
- Ein Zertifikat für den Hostnamen unter Systemsteuerung > Sicherheit > Zertifikat > Einstellungen zuordnen.

Die Live-Ansicht nutzt Server-Sent Events; TunnelDeck-VPN sendet `X-Accel-Buffering: no`, damit der Proxy sie ungepuffert durchreicht. Die Anmeldung prüft, ob der `Origin` des Browsers zum `Host`-Header passt. Scheitert die Anmeldung hinter dem Proxy, der Regel einen benutzerdefinierten Header `Host` = `$http_host` hinzufügen (*auf der NAS prüfen*). Hinter dem Proxy teilen sich alle Browser die NAS-Adresse für die Begrenzung der Anmeldeversuche.

## 6. Fernzugriff über den Tunnel

Um TunnelDeck-VPN aus dem Internet über seine VPN-Adresse zu erreichen (SPEC §8.1), **System > Fernzugriff** öffnen:

1. Einschalten und Port `8443` lassen oder einen freien Port wählen.
2. Das selbst signierte Zertifikat behalten oder ein eigenes Zertifikat mit Schlüssel (PEM) hochladen.
3. Den dort angezeigten SHA-256-Fingerabdruck notieren und beim ersten Aufruf von `https://<VPN-Adresse>:8443` mit der Zertifikatswarnung des Browsers vergleichen.

Die Anmeldeseite ist danach aus dem Internet erreichbar. Ein langes Admin-Passwort verwenden. Im Tunnel wird nur dieser HTTPS-Port geöffnet; der HTTP-Port 8194 bleibt dort zu.

## 7. Sicherung

Den ganzen Ordner `docker/tunneldeck` sichern (Hyper Backup oder Kopie):

- `settings.json`: Admin-Konto, Firewall-Regeln und -Einstellungen, Fernzugriff, gewünschte Verbindung,
- `profiles.json`: Profile; geheime Felder verschlüsselt,
- `secret.key`: der Schlüssel zu diesen Geheimnissen.

Ohne `secret.key` lassen sich die gespeicherten Passwörter und Schlüssel nicht entschlüsseln. Die Sicherung so gut schützen wie die NAS selbst. Wer `TUNNELDECK_SECRET_KEY` setzt, bewahrt stattdessen diesen Wert mit der Sicherung auf.

## 8. Aktualisieren

1. `docker/tunneldeck` sichern (Abschnitt 7). Eine neuere Version kann die Datendateien migrieren, und eine ältere Version startet mit migrierten Dateien nicht.
2. Das Tag in der Zeile `image:` der Compose-Datei auf die neue Version ändern (Container Manager > Projekt > tunneldeck > YAML-Konfigurationen) oder vorher das neue `.tar` importieren.
3. Projekt > Aktion > Erstellen. Der Container Manager lädt das Image und erstellt den Container neu. Ein vorher verbundener Tunnel verbindet sich von selbst wieder.
4. Die Version auf der Seite **System** prüfen.

## 9. Admin-Passwort vergessen

`tunneldeck reset-admin` im Container ausführen: Container Manager > Container > tunneldeck > Terminal > Erstellen > `tunneldeck reset-admin`, oder per SSH:

```sh
sudo docker exec tunneldeck tunneldeck reset-admin
```

Das entfernt das Admin-Konto und alle Sitzungen; Profile und Einstellungen bleiben. Danach die Oberfläche öffnen und das Konto neu anlegen. Alternativ `TUNNELDECK_RESET_ADMIN: "1"` setzen, neu starten, Konto anlegen und die Variable wieder entfernen; solange sie gesetzt ist, wird bei jedem Start zurückgesetzt.

Details, erwartete Ausgabe und die Schritte im Synology-Terminal: [Admin-Passwort verloren](reset-admin.de.md).

## 10. Firewall-Regeln und IPsec

Die Seite **Firewall** regelt, was den Tunnel in beide Richtungen passiert, zu diesem Gerät selbst und zu anderen Geräten im lokalen LAN; was keine Regel erlaubt, wird verworfen, Antworten kommen immer durch, die Regeln gelten von oben nach unten. Die Begriffe (eingehende und ausgehende Regeln, die Zieladresse, Portweiterleitungen, Quelladresse behalten, Gateway-Voraussetzung, Kill-Switch) erklärt [`linux.de.md`, Abschnitt 10](linux.de.md#10-firewall-regeln); auf DSM gelten sie genauso. Kurz:

- Das Ziel einer eingehenden Regel ist eine Adresse im lokalen LAN. Eine eingehende Regel an die **eigene LAN-Adresse dieses Geräts** (die Seite Firewall zeigt sie als „Dieses Gerät: 192.168.1.10“) öffnet einen Port von DSM an der Tunneladresse (zum Beispiel `5001` von DSM). Host-Zugriffsregeln von 0.1 werden beim ersten Start von 0.2 zu solchen Regeln; Regeln, die 0.2.0-alpha mit dem Ziel „Host“ gespeichert hat, funktionieren weiter und werden beim nächsten Speichern mit der Adresse dieses Geräts abgelegt.
- Eine eingehende Regel an eine andere LAN-Adresse ist eine **Portweiterleitung**. Mit **Quelladresse behalten** sieht das Gerät die echte entfernte Adresse und braucht die NAS als Gateway.
- Eine **ausgehende** Regel schickt den Verkehr eines LAN-Geräts durch den Tunnel. Das Gerät braucht die NAS als Gateway oder eine Route im LAN-Router, die auf die NAS zeigt. Solange der Tunnel nicht steht, wird dieser Verkehr verworfen (Kill-Switch).

### IP-Weiterleitung auf DSM

Portweiterleitungen und ausgehende Regeln brauchen die IPv4-Weiterleitung auf der NAS. Container Manager (Docker) schaltet sie normalerweise ein. Der Selbsttest **ip-forward** auf der Seite System zeigt den Wert; per SSH:

```sh
cat /proc/sys/net/ipv4/ip_forward     # 1 heißt an
```

Steht sie auf `0`: Systemsteuerung > Aufgabenplaner > Erstellen > Ausgelöste Aufgabe > Benutzerdefiniertes Skript, Benutzer `root`, Ereignis **Hochfahren**, Skript `sysctl -w net.ipv4.ip_forward=1`; einmal von Hand ausführen. *Auf der NAS prüfen:* ob DSM den Wert auch ohne die Aufgabe behält. TunnelDeck-VPN ändert ihn nie.

### DSM-Firewall und weitergeleiteter Verkehr

Die DSM-Firewall filtert Verkehr an die NAS selbst. Die Ketten von TunnelDeck-VPN stehen für Tunnelverkehr an erster Stelle in `INPUT` und `FORWARD`, dort entscheiden also seine Regeln. *Auf der NAS prüfen:* dass DSMs eigene Regeln weitergeleiteten Verkehr zwischen Tunnel und LAN nicht sperren (`sudo iptables -S FORWARD | head -5` sollte zuerst die Sprünge nach `TUNNELDECK-FORWARD` zeigen); nach Änderungen an der DSM-Firewall den Container neu starten.

### Schutzfunktionen, die dem DSM-Kernel fehlen können

DSM-Kernel (DSM 7.2 auf der DS723+ läuft mit Linux 4.4) enthalten nicht jedes iptables-Modul. TunnelDeck-VPN prüft die optionalen einmal beim Start und installiert die Firewall in jedem Fall; nur die betroffene Schutzfunktion wird eingeschränkt. Die Regeln selbst, der Kill-Switch und „alles andere wird verworfen“ funktionieren immer.

| Fehlendes Modul | Wirkung | Seite System | Seite Firewall |
| --- | --- | --- | --- |
| `xt_hashlimit` | Der Schutz vor SYN-Flut nutzt ein globales Limit mit denselben Werten (25/s) für alle Absender statt eines pro Absender; die Ping-Begrenzung (ohnehin global 5/s) funktioniert weiter | Warnung **syn-flood-protection** | „Nur globales Limit“ beim Schutz vor SYN-Flut |
| `xt_hashlimit` und `xt_limit` | Schutz vor SYN-Flut und Ping-Begrenzung entfallen | Warnungen **syn-flood-protection**, **ping-limit** | „Auf diesem System nicht verfügbar“ |
| `xt_TCPMSS` | Die MSS-Anpassung entfällt; große Übertragungen durch den Tunnel können bei kleiner Pfad-MTU hängen | Warnung **mss-clamp** | „Auf diesem System nicht verfügbar“ |
| `ipt_REJECT` | Regeln mit der Aktion **Ablehnen** verwerfen stattdessen und antworten nicht | Warnung **reject-target** | keine |
| `xt_comment` | Keine Trefferzähler | Warnung **rule-counters** | keine Trefferzahlen |

Die Schalter bleiben so, wie Sie sie gesetzt haben; die Schutzfunktion greift, sobald das Modul vorhanden ist. Jede Warnung nennt das fehlende Modul und den aktiven Ersatz. *Auf der NAS prüfen:* `sudo modprobe xt_hashlimit` (ebenso `xt_limit`, `xt_TCPMSS`, `ipt_REJECT`); gibt es das Modul auf DSM nicht, bleibt die Warnung, und die Firewall arbeitet ohne diese Schutzfunktion weiter. Nach dem Laden eines Moduls den Container neu starten.

Alle Einträge der Seite System, mit dem zu ladenden Modul und den Schritten für DSM: [Systemprüfungen erklärt](system-checks.de.md).

### Ein IPsec-Router im lokalen LAN

Referenzfall (SPEC §16.2): Ein IPsec-Router im lokalen LAN, zum Beispiel unter `192.168.1.2`, baut seine IPsec-Tunnel über die öffentliche Adresse des Tunnels auf.

1. Seite Firewall > **IPsec-Router hinzufügen**: ein Name, die Adresse des Routers `192.168.1.2`, optional die öffentlichen Adressen der Gegenstellen. Die Vorlage fügt eingehend UDP 500, UDP 4500 und ESP an `192.168.1.2` mit behaltener Quelladresse ein und ausgehend UDP und ESP von `192.168.1.2` an die Gegenstellen (oder `0.0.0.0/0`). Die Änderungen speichern.
2. Im Router: eine statische Route für die öffentliche Adresse jeder Gegenstelle (`/32`) über die LAN-Adresse der NAS, oder die NAS als Default-Gateway.
3. In der IPsec-Verbindung des Routers: IKEv2 mit aktuellen Proposals, NAT-Traversal erlaubt (die eigene Adresse des Routers unterscheidet sich von der öffentlichen Adresse, beide Seiten wechseln daher auf UDP 4500), und auf beiden Seiten eine Identität, die keine IP-Adresse ist (Typ FQDN oder E-Mail).
4. In jeder Gegenstelle: die öffentliche Adresse des Tunnels als Adresse des Routers.

Die Tabelle der fünf Regeln und die ausführlichen Schritte stehen in [`linux.de.md`, „Ein IPsec-Router im lokalen LAN“](linux.de.md#ein-ipsec-router-im-lokalen-lan). Geprüft: Der End-to-End-Test spielt diesen Fall mit strongSwan 6.0 auf beiden Seiten durch (IKEv2 mit PSK und NAT-T in beide Richtungen, reines ESP mit manuell gesetzten Schlüsseln), mit beiden iptables-Backends, iptables-legacy eingeschlossen, aber auf einem aktuellen Kernel eines Docker-Hosts, nicht auf dem Kernel 4.4 von DSM. *Nicht geprüft:* ein echter IPsec-Router und DSM 7.2 selbst.

#### Beispiel: LANCOM-Router mit mdex

Ein LANCOM-Router unter `192.168.1.2` nutzt eine mdex-public.IP-Verbindung auf der NAS: Die öffentliche Adresse ist die Adresse von `publicipNN.mdex.de`, die jede Gegenstelle als Adresse des Routers verwendet. Die Schritte sind die oben genannten. *Nicht geprüft:* ein echter LANCOM-Router und eine echte mdex-public.IP-Verbindung.
