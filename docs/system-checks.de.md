# Systemprüfungen erklärt

Die Seite System zeigt den Selbsttest, den TunnelDeck-VPN beim Start ausführt (`internal/netguard/selfcheck.go`). Jeder Eintrag hat einen von drei Zuständen:

- **OK**: Voraussetzung oder Funktion ist vorhanden.
- **Warnung**: Eine optionale iptables-Erweiterung fehlt. Die Firewall wird trotzdem installiert; nur die genannte Funktion fällt auf einen Ersatz zurück oder entfällt.
- **Fehler**: Eine Voraussetzung fehlt. Tunnel oder Firewall funktionieren erst, wenn Sie sie beheben.

Nach dem Laden eines Kernelmoduls oder einer Änderung am Container starten Sie den Container neu: Die Erweiterungen werden einmal pro Start geprüft.

Englische Fassung: [system-checks.md](system-checks.md).

## Eintrag — was er für Sie bedeutet

| Eintrag (ID) | Art | Was er für Sie bedeutet |
| --- | --- | --- |
| TUN-Gerät (`tun-device`) | nötig | Ohne es startet kein Tunnel. |
| iptables (`iptables`) | nötig | Ohne es keine Firewall und kein Kill-Switch. |
| ip-Werkzeug (`ip`) | nötig | Ohne es kein Routing für den Tunnel. |
| NET_ADMIN-Berechtigung (`net-admin`) | nötig | Ohne sie darf der Container weder Firewall noch Routen ändern. |
| IP-Weiterleitung (`ip-forward`) | nötig | Ohne sie leiten Regeln zu anderen Geräten und ausgehende Regeln nichts weiter. |
| LAN-Subnetze (`lan-subnets`) | nötig | Ohne sie haben eingehende Regeln zu anderen LAN-Geräten kein Ziel. |
| Trefferzähler (`rule-counters`) | optional | Aus, wenn das comment-Match fehlt — die Firewall funktioniert trotzdem. |
| Schutz vor SYN-Flut (`syn-flood-protection`) | optional | Globales statt Limit pro Absender, oder entfällt — die Firewall funktioniert trotzdem. |
| Ping-Begrenzung (`ping-limit`) | optional | Entfällt nur, wenn beide Limit-Module fehlen — die Firewall funktioniert trotzdem. |
| TCP-MSS-Anpassung (`mss-clamp`) | optional | Entfällt ohne TCPMSS — große Übertragungen können hängen. |
| REJECT-Ziel (`reject-target`) | optional | Ablehnen-Regeln verwerfen stattdessen still. |
| Antwort-Routing von Portweiterleitungen (`reply-routing`) | optional | Ohne CONNMARK schickt ein Portweiterleitungs-Ziel, das diesen Host als Gateway nutzt, seinen ganzen Verkehr durch den Tunnel. |

## Fehlende Kernelmodule laden

**Allgemeiner Linux-Host:** Laden Sie das Modul auf dem Host und starten Sie dann den Container neu:

```sh
sudo modprobe xt_comment          # Name aus dem jeweiligen Abschnitt
echo xt_comment | sudo tee /etc/modules-load.d/tunneldeck.conf   # beim Booten laden
```

Gibt es das Modul, kann iptables-legacy es aber nicht nutzen, probieren Sie das nft-Backend: Setzen Sie `TUNNELDECK_IPTABLES=nft` in der Umgebung des Containers (siehe [linux.de.md](linux.de.md#welches-iptables-backend-tunneldeck-vpn-nutzt)).

**Synology DSM:** Manche DSM-Kernel liefern diese Module gar nicht mit. Prüfen Sie zuerst und laden Sie dann per Pfad:

```sh
ls /lib/modules | grep -i -E 'comment|limit|tcpmss|reject|connmark|mangle'
sudo insmod /lib/modules/xt_comment.ko
```

Damit es bei jedem Start geladen wird, ergänzen Sie die Zeile in der Boot-Aufgabe aus [synology.de.md](synology.de.md#tun-gerät) (Aufgabenplaner, Benutzer `root`, Ereignis Hochfahren), zum Beispiel `lsmod | grep -q '^xt_comment ' || insmod /lib/modules/xt_comment.ko`. Liegt das Modul nicht in `/lib/modules`, bleibt die Warnung; die Firewall schützt den Host trotzdem, nur diese Funktion ist eingeschränkt.

*Nicht auf einer echten DS723+ geprüft:* welche dieser Module DSM 7.2 mitliefert und ob `insmod` sie lädt. Manche Module hängen von anderen ab (zum Beispiel `xt_connmark` von `nf_conntrack`); meldet `insmod` unbekannte Symbole, laden Sie diese zuerst.

## tun-device

- **Prüft:** `/dev/net/tun` existiert im Container und ist ein Zeichengerät.
- **OK:** Die Tunnel-Schnittstelle kann angelegt werden.
- **Fehler:** Keine VPN-Verbindung kann starten.
- **Modul:** `tun`.
- **Lösung:** Reichen Sie das Gerät in den Container durch (`devices: - /dev/net/tun`). Linux: `sudo modprobe tun`. DSM: `insmod /lib/modules/tun.ko` und Boot-Aufgabe, siehe [synology.de.md](synology.de.md#tun-gerät).

## iptables

- **Prüft:** Ein funktionierendes iptables-Backend (legacy oder nft) wird gefunden; das Detail nennt Programm und Grund der Wahl.
- **OK:** Firewall und Kill-Switch lassen sich installieren.
- **Fehler:** Keine Firewall, kein Kill-Switch.
- **Modul:** `ip_tables` / `iptable_filter` (legacy) oder `nf_tables` (nft).
- **Lösung:** Das Image enthält iptables; der Host-Kernel muss die filter-Tabelle bereitstellen. Die Wahl übersteuern Sie mit `TUNNELDECK_IPTABLES=nft` oder `legacy` (Standard `auto`). DSM-Kernel 4.4 haben nur legacy.

## ip

- **Prüft:** `ip -4 rule show` läuft.
- **OK:** Policy-Routing für den Tunnel funktioniert.
- **Fehler:** Routen und Regeln für den Tunnel lassen sich nicht setzen.
- **Modul:** keins.
- **Lösung:** iproute2 gehört zum Image; ein Fehler deutet auf ein defektes oder selbst gebautes Image.

## net-admin

- **Prüft:** Legt die Probe-Kette `TUNNELDECK-PROBE` an und löscht sie wieder.
- **OK:** Der Container darf Firewall und Routing ändern.
- **Fehler:** Weder Firewall noch Routen lassen sich setzen. Schlägt auch fehl, wenn iptables fehlt.
- **Modul:** keins.
- **Lösung:** `cap_add: - NET_ADMIN` in der Compose-Datei.

## ip-forward

- **Prüft:** `net.ipv4.ip_forward` ist `1`. TunnelDeck-VPN liest den Wert und ändert ihn nie.
- **OK:** Verkehr zwischen Tunnel und LAN kann weitergeleitet werden.
- **Fehler:** Regeln zu anderen Geräten und ausgehende Regeln leiten nichts weiter; der Zugriff auf diesen Host selbst funktioniert weiter.
- **Modul:** keins.
- **Lösung:** Linux: `sudo sysctl -w net.ipv4.ip_forward=1`, dauerhaft in `/etc/sysctl.conf` (auf Docker-Hosts meist schon an), siehe [linux.de.md](linux.de.md#ip-weiterleitung). DSM: Boot-Aufgabe, siehe [synology.de.md](synology.de.md#ip-weiterleitung-auf-dsm).

## lan-subnets

- **Prüft:** Mindestens eine IPv4-Adresse auf einer LAN-Schnittstelle; das Detail nennt die Subnetze.
- **OK:** Eingehende Regeln zu anderen Geräten kennen ihr LAN.
- **Fehler:** Eingehende Regeln zu anderen LAN-Geräten haben kein Ziel.
- **Modul:** keins.
- **Lösung:** Starten Sie den Container mit `network_mode: host` auf einem Host mit IPv4-Adresse auf der LAN-Schnittstelle.

## rule-counters

- **Prüft:** Das iptables-Match `comment` funktioniert.
- **OK:** Die Seite Firewall zeigt Trefferzahlen pro Regel.
- **Warnung:** Keine Trefferzähler — die Firewall funktioniert trotzdem.
- **Modul:** `xt_comment`.
- **Lösung:** `modprobe xt_comment` oder `TUNNELDECK_IPTABLES=nft`; DSM: siehe oben.

## syn-flood-protection

- **Prüft:** Das Match `hashlimit`, sonst das Match `limit`.
- **OK:** Schutz vor SYN-Flut mit einem Limit pro Absender (hashlimit).
- **Warnung (nur limit):** Ein globales Limit für alle Absender — ein flutender Absender kann neue Verbindungen anderer bremsen.
- **Warnung (keins):** Der Schutz vor SYN-Flut entfällt — die Firewall funktioniert trotzdem.
- **Modul:** `xt_hashlimit` (bevorzugt), Ersatz `xt_limit`.
- **Lösung:** `modprobe xt_hashlimit`; DSM: siehe oben.

## ping-limit

- **Prüft:** Das Match `hashlimit` oder `limit`. Die Ping-Begrenzung ist ohnehin ein globales Limit, daher reicht eins von beiden für OK.
- **OK:** Pings aus dem Tunnel werden begrenzt.
- **Warnung:** Beide Module fehlen, die Ping-Begrenzung entfällt — die Firewall funktioniert trotzdem.
- **Modul:** `xt_hashlimit` oder `xt_limit`.
- **Lösung:** `modprobe xt_limit` (oder `xt_hashlimit`); DSM: siehe oben.

## mss-clamp

- **Prüft:** Das Ziel `TCPMSS` funktioniert.
- **OK:** Die TCP-MSS wird an die Pfad-MTU angepasst.
- **Warnung:** Die MSS-Anpassung entfällt — große Übertragungen durch den Tunnel können bei kleiner Pfad-MTU hängen.
- **Modul:** `xt_TCPMSS`.
- **Lösung:** `modprobe xt_TCPMSS`; DSM: siehe oben.

## reject-target

- **Prüft:** Das Ziel `REJECT` funktioniert.
- **OK:** Regeln mit der Aktion Ablehnen antworten mit TCP-Reset oder ICMP „Port unreachable“.
- **Warnung:** Ablehnen-Regeln verwerfen stattdessen still; der Absender wartet auf einen Timeout.
- **Modul:** `ipt_REJECT` (nft-Backend: `nft_reject`).
- **Lösung:** `modprobe ipt_REJECT`; DSM: siehe oben.

## reply-routing

- **Prüft:** Das Ziel `CONNMARK` und das Match `connmark` in der Tabelle `mangle` funktionieren.
- **OK:** Antworten von Portweiterleitungen folgen einer Verbindungsmarke zurück in den Tunnel.
- **Warnung:** Antworten werden nach der Adresse des Ziels geroutet: Solange der Tunnel steht, geht alles, was dieser Host für ein Portweiterleitungs-Ziel routet, durch den Tunnel. Die Portweiterleitungen selbst funktionieren.
- **Modul:** `xt_connmark` und `iptable_mangle`.
- **Lösung:** `modprobe xt_connmark iptable_mangle`; DSM: siehe oben.
