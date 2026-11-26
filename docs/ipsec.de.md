# IPsec/IKEv2-Gateways

[English](ipsec.md)

TunnelDeck-VPN verbindet sich per IPsec mit Firmen- und Router-Gateways: standardmäßig mit IKEv2, IKEv1 nur als veralteter Rückfall für den FRITZ!Box-Benutzerzugang und ähnliche Gateways. Diese Anleitung beschreibt, was Sie auf dem Gateway einrichten und wie seine Werte den Feldern des Profilformulars entsprechen. Spezifikation: [SPEC §19](SPEC.md#19-ipsecikev2-driver-owner-approved-2026-11-26).

## 1. Wie TunnelDeck-VPN mit dem Gateway spricht

- **TunnelDeck-VPN baut die Verbindung immer selbst auf.** Es ist ein Client: Das Gateway muss eine Gegenstelle annehmen, deren Adresse es vorher nicht kennt („dynamischer Peer“, „Road Warrior“ oder „Mobile Client“). Auf dem TunnelDeck-Host und auf Ihrem eigenen Internet-Router müssen Sie nichts öffnen.
- **Ports:** Das Gateway muss UDP 500 und UDP 4500 annehmen. TunnelDeck-VPN nutzt auf seiner Seite zufällige lokale Ports und kommt daher weder einem IPsec-Server auf demselben Host (etwa dem DSM-VPN-Server) noch Portweiterleitungen von UDP 500/4500 an ein LAN-Gerät in die Quere.
- **NAT-Traversal ist immer aktiv.** ESP läuft im Container im Benutzermodus und wird immer in UDP 4500 verpackt, daher meldet das Gateway stets „remote host is behind NAT“. Das ist so gewollt; reines ESP (IP-Protokoll 50) verlässt TunnelDeck-VPN nie.
- **Kein Kernel-IPsec auf dem Host.** Der Host braucht keine IPsec-Kernelmodule und erhält keine IPsec-Policies; nötig ist nur das TUN-Gerät aus den Anleitungen für [Linux](linux.de.md) und [Synology](synology.de.md).
- **Lebenszeichen und Schlüsselwechsel:** Dead Peer Detection alle 30 s; die IKE-SA wird alle 4 h erneuert, die CHILD-SA stündlich, ohne erneute Anmeldung (IKEv1 meldet sich alle 4 h neu an). MOBIKE ist aus.

## 2. Das Profilformular

| Feld | Bedeutung |
|---|---|
| Gateway-Typ | Füllt die IKE-Version und die Proposals für LANCOM, FRITZ!Box, OPNsense/pfSense/strongSwan oder die allgemeinen Vorgaben vor. |
| Gateway-Adresse | Hostname (auch ein DynDNS-Name, der bei jedem Versuch neu aufgelöst wird) oder IPv4-Adresse des Gateways. |
| IKE-Version | IKEv2. IKEv1 bedeutet ausschließlich Aggressive Mode mit Pre-shared Key und XAuth; das Formular kennzeichnet es als Sicherheitsrisiko. |
| Modus | **Virtuelle IP**: Das Gateway vergibt eine Adresse, die zur VPN-IP dieses Geräts wird; LAN-Geräte werden auf sie maskiert. **Netz-zu-Netz**: Lokale LAN-Subnetze behalten im Tunnel ihre Adressen (Abschnitt 6). |
| Entfernte Subnetze | Netze hinter dem Gateway. Im Modus „Virtuelle IP“ fordert die Vorgabe `0.0.0.0/0` alles an; der Host behält trotzdem seine eigene Standardroute, jeder andere Eintrag wird wie ein Remote-Netz durch den Tunnel geleitet. |
| Anmeldeverfahren | Pre-shared Key; Zertifikat (PEM-Zertifikat und Schlüssel oder eine PKCS#12-Datei mit Passwort); Benutzername und Passwort (EAP-MSCHAPv2). |
| Lokale Identität | Die Identität, die diese Seite sendet (FQDN, IP-Adresse, E-Mail oder DN). Leer: der Inhaber des Zertifikats, der EAP-Benutzername bzw. bei Pre-shared Key die eigene IP-Adresse. |
| Identität des Gateways | Bei Zertifikat und EAP Pflicht: Sie muss zum Subject Alternative Name des Gateway-Zertifikats passen. Bei Pre-shared Key darf sie leer bleiben; dann wird jede Identität des Gateways angenommen. |
| CA-Zertifikat des Gateways | Bei Zertifikat und EAP Pflicht; der CA-Speicher des Systems wird nicht verwendet. |
| IKE- und ESP-Proposals | strongSwan-Schreibweise, ein Proposal pro Zeile. Leer bedeutet die Vorgaben nach RFC 8247/8221: AES-GCM und AES-CBC mit SHA-2, Curve25519, ECP-384/256, MODP-3072/2048, ESP mit Perfect Forward Secrecy. |

Traffic-Selektoren: Das Gateway darf die angeforderten Subnetze einschränken; TunnelDeck-VPN akzeptiert das. Deckt kein ausgehandeltes entferntes Subnetz `0.0.0.0/0` ab (etwa bei der FRITZ!Box, die nur ihr LAN anbietet), transportiert der Tunnel keinen Internetverkehr, und TunnelDeck-VPN ermittelt keine öffentliche IP über ihn (SPEC §6.1): Das Dashboard zeigt keine öffentliche IP, das Protokoll nennt den Grund.

## 3. LANCOM

Vorlage **LANCOM**. In LANconfig unter **VPN → IKEv2/IPSec**:

1. **Verbindung** für TunnelDeck-VPN mit leerem entfernten Gateway (TunnelDeck-VPN baut die Verbindung auf, seine Adresse kann wechseln), IKEv2 und der Authentifizierung: Pre-shared Key mit einer Identität je Seite (z. B. vom Typ FQDN) oder Zertifikate.
2. **Proposals:** IKE AES-GCM-256 mit PRF SHA-256 und DH-Gruppe 19 (ECP-256) oder 14 (MODP-2048); IPsec AES-GCM-256 mit PFS-Gruppe 19 oder 14. Das sind die Werte der Vorlage; nutzt der Router andere, tragen Sie seine Proposals im Formular ein.
3. **Virtuelle IP:** Geben Sie der Verbindung einen IKE-CFG-Adresspool (IKE-CFG-Modus „Server“); die entfernten Subnetze in TunnelDeck-VPN sind die Netze des Routers (oder `0.0.0.0/0`, wenn er alles routet).
4. **Netz-zu-Netz:** Die IPv4-Regeln des Routers nennen sein eigenes Netz als lokal und das TunnelDeck-LAN-Subnetz als entfernt; in TunnelDeck-VPN dieselben Netze umgekehrt.

Profil: Gateway-Adresse = öffentliche Adresse oder DNS-Name des Routers, lokale Identität = entfernte Identität im Router, Identität des Gateways = lokale Identität des Routers (bei Pre-shared Key auch leer), Pre-shared Key wie im Router.

*Nicht geprüft:* Die Menünamen unterscheiden sich je nach LCOS-Version; getestet wurde kein echter LANCOM, nur ein strongSwan-Gateway mit den Proposals der Vorlage.

## 4. FRITZ!Box

### Benutzerzugang (IKEv1 XAuth)

FRITZ!OS bietet einzelnen Benutzern nur „IPSec Xauth PSK“ an, also IKEv1 im Aggressive Mode. Vorlage **FRITZ!Box-Benutzerzugang (IKEv1 XAuth)**.

1. Legen Sie auf der FRITZ!Box unter **System → FRITZ!Box-Benutzer** einen Benutzer an oder öffnen Sie ihn, erlauben Sie **VPN** und öffnen Sie die **VPN-Einstellungen**. Die „VPN-Daten“ für „IPSec Xauth PSK“ zeigen die folgenden Werte.
2. Übertragen Sie sie so ins Formular:

| FRITZ!Box „VPN-Daten“ | Formularfeld |
|---|---|
| Serveradresse (MyFRITZ!-Name oder IP) | Gateway-Adresse |
| IPSec-ID | Lokale Identität |
| Shared Secret | Pre-shared Key |
| Kontoname | XAuth-Benutzername |
| Kennwort | XAuth-Passwort |
| – | Identität des Gateways: leer lassen. Die FRITZ!Box meldet sich mit ihrer Internet-IP-Adresse, nicht mit dem MyFRITZ!-Namen. |

3. Modus „Virtuelle IP“; entfernte Subnetze: das LAN der FRITZ!Box, z. B. `192.168.178.0/24`. Die FRITZ!Box vergibt eine Adresse aus ihrem LAN (z. B. `192.168.178.202`), die zur VPN-IP wird.

Die Proposals der Vorlage beginnen mit MODP-2048 und weichen auf MODP-1024 aus, das FRITZ!OS noch verwendet; das Formular zeigt dafür eine Warnung. Praxistest am 26.11.2026: verbunden, das FRITZ!Box-LAN und ihre Weboberfläche durch den Tunnel erreichbar, die Hauptroutingtabelle des Hosts unverändert. Da die FRITZ!Box nur ihr LAN transportiert, wird keine öffentliche IP angezeigt.

### LAN-zu-LAN (IKEv2)

Vorlage **FRITZ!Box (LAN-zu-LAN, IKEv2)**, Modus „Netz-zu-Netz“. Fügen Sie auf der FRITZ!Box unter **Internet → Freigaben → VPN (IPSec)** eine Verbindung mit einem anderen Netzwerk hinzu: Das entfernte Netzwerk ist das TunnelDeck-LAN-Subnetz (in TunnelDeck-VPN die lokalen Subnetze), der Pre-shared Key ist auf beiden Seiten gleich. In TunnelDeck-VPN sind die entfernten Subnetze das LAN der FRITZ!Box. Der LAN-Router auf der TunnelDeck-Seite braucht die statische Route aus Abschnitt 6.

*Nicht geprüft:* LAN-zu-LAN mit einer echten FRITZ!Box; ob FRITZ!OS dafür IKEv2 anbietet, hängt von der Version ab.

## 5. OPNsense, pfSense und strongSwan

Vorlage **OPNsense / pfSense / strongSwan** (die IKEv2-Vorgaben).

- **OPNsense** (VPN → IPsec → Connections): eine Verbindung mit Version IKEv2, lokaler und entfernter Authentifizierung (Pre-shared Key, Public Key oder EAP-MSCHAPv2 für die Gegenseite), einem Pool für virtuelle IPs und einem Child mit den lokalen Netzen.
- **pfSense** (VPN → IPsec): für den Modus „Virtuelle IP“ der Reiter **Mobile Clients** mit einem virtuellen Adresspool und einer mobilen Phase 1 (IKEv2, Mutual PSK, EAP-MSCHAPv2 oder Zertifikate); für Netz-zu-Netz eine Phase 1 mit der TunnelDeck-Seite als Peer und eine Phase 2 mit dem lokalen Netz und dem TunnelDeck-LAN-Subnetz als entferntem Netz.
- **strongSwan** (`swanctl.conf`), wie im End-to-End-Test (`test/e2e/ipsecgw/swanctl.conf`):

```
connections {
  tunneldeck {
    version = 2
    proposals = aes256gcm16-prfsha384-curve25519-ecp384-ecp256-modp3072, aes256-sha256-modp2048
    pools = tunneldeck
    local  { auth = psk  id = gateway.example.com }
    remote { auth = psk  id = tunneldeck.example.com }
    children {
      tunneldeck {
        local_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16-curve25519-ecp256-modp3072, aes256-sha256-modp2048
      }
    }
  }
}
pools {
  tunneldeck { addrs = 10.10.10.10-10.10.10.99 }
}
secrets {
  ike-tunneldeck { id = tunneldeck.example.com  secret = "ein langer zufälliger Pre-shared Key" }
}
```

Für Netz-zu-Netz lassen Sie `pools` weg und setzen `local_ts` auf die Netze des Gateways und `remote_ts` auf das TunnelDeck-LAN-Subnetz. Im Profil: Identität des Gateways `gateway.example.com` (oder leer), lokale Identität `tunneldeck.example.com`.

## 6. Netz-zu-Netz: statische Route im LAN-Router

Im Modus „Netz-zu-Netz“ behalten die LAN-Geräte im Tunnel ihre eigenen Adressen, die Gegenseite sieht sie also unverändert. Dafür braucht die TunnelDeck-Seite drei Dinge:

1. **Statische Route im LAN-Router:** Ziel = jedes entfernte Subnetz, nächster Hop = die LAN-Adresse des TunnelDeck-Hosts. Beispiel: entferntes Subnetz `10.20.0.0/24`, TunnelDeck-Host `192.168.1.10` → Route `10.20.0.0/24 über 192.168.1.10`. Ohne sie schicken die LAN-Geräte den Verkehr für die entfernten Subnetze an ihr Standard-Gateway, den Internet-Router. Das Formular zeigt diesen Hinweis mit der LAN-Adresse des Hosts.
2. **IP-Weiterleitung** auf dem Host und eine **Ausgangsregel** für jedes LAN-Gerät (oder das ganze LAN) zu den entfernten Subnetzen, wie für jedes LAN-Gerät, das den Tunnel nutzt ([Linux](linux.de.md#10-firewall-regeln), [Synology](synology.de.md#10-firewall-regeln-und-ipsec)).
3. Der Host selbst erreicht die entfernten Subnetze von seiner LAN-Adresse in den lokalen Subnetzen aus; dafür ist nichts weiter einzustellen.

Verbindungen aus den entfernten Subnetzen zu LAN-Geräten, die keine Antworten sind, brauchen weiterhin eine Eingangsregel in der Firewall.

## 7. Fehlersuche

| Statusmeldung | Ursache und Abhilfe |
|---|---|
| Der Server hat die Anmeldedaten abgelehnt | Falscher Pre-shared Key, falsches XAuth- oder EAP-Passwort oder Identitäten, die das Gateway nicht kennt. TunnelDeck-VPN versucht es nicht erneut, damit das Konto nicht gesperrt wird; korrigieren Sie das Profil und verbinden Sie erneut. |
| Das Gateway hat keinen der Vorschläge angenommen | Vergleichen Sie die IKE- und ESP-Proposals mit dem Gateway oder wählen Sie den Gateway-Typ erneut. |
| Das Gateway hat die Subnetze des Tunnels abgelehnt | Lokale oder entfernte Subnetze passen nicht zur Konfiguration des Gateways (IKEv2 TS_UNACCEPTABLE). |
| Das Gateway hat keine virtuelle IP vergeben | Der Modus „Virtuelle IP“ braucht auf dem Gateway einen Adresspool; der Versuch wird automatisch wiederholt. |
| Die Serveradresse liegt in einem Netz, das durch den Tunnel geroutet wird | Die Gateway-Adresse liegt in einem entfernten Subnetz; entfernen Sie dieses Subnetz oder verwenden Sie eine andere Adresse. |

Das Protokoll im Dashboard zeigt die Meldungen von charon. Der End-to-End-Test (`test/e2e/`, Variante E) betreibt ein strongSwan-Gateway mit Pre-shared Key, Zertifikat, EAP-MSCHAPv2 und IKEv1 XAuth sowie Netz-zu-Netz für ein LAN. *Nicht geprüft:* echte LANCOM-, OPNsense-, pfSense- und Sophos-Gateways sowie arm64.
