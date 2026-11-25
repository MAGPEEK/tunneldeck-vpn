# Eine mdex-Verbindung vom Teltonika RUT240 zu TunnelDeck umziehen

[English](migrate-from-rut240.md)

Diese Anleitung überträgt eine OpenVPN-Client-Instanz (Services > VPN > OpenVPN am RUT240) in ein TunnelDeck-Profil, am Beispiel einer mdex-public.IP-Verbindung der Stufe 20. Die Fakten dahinter stehen in [`openvpn-notes.md`](openvpn-notes.md). Die Konfiguration wurde im Labor gegen nachgebildete mdex-Server getestet, nicht gegen den echten mdex-Server.

## Vor dem ersten Verbinden

- **Zuerst den Router trennen.** Die OpenVPN-Instanz des RUT240 abschalten (oder den Router vom Strom nehmen), bevor TunnelDeck verbindet. mdex erlaubt sehr wahrscheinlich eine Sitzung pro Konto (*bei mdex nachfragen*); zwei Clients mit demselben Konto würden sich gegenseitig hinauswerfen.
- Benutzername und Passwort des Kontos sowie das CA-Zertifikat `mdexCA20.crt` bereithalten (von der Download-Seite von mdex oder aus den Zertifikatsdateien des RUT240).

## Felder im Vergleich

Ein Profil unter **Profile > Neues Profil > OpenVPN** anlegen, oder eine vom Router exportierte `.ovpn`-Datei importieren und die angezeigten Warnungen prüfen.

| Feld am RUT240 | Feld im TunnelDeck-Profil | Hinweis |
|---|---|---|
| TUN/TAP | – | Immer TUN. TAP wird nicht unterstützt; ein importiertes `dev tap` wird abgelehnt. |
| Protocol | Transport | UDP oder TCP. |
| Port | Port | mdex: `1194`. |
| LZO | Komprimierung | mdex Stufe 20: **Aus**. Jedes `comp-lzo` gegen einen Server ohne Komprimierung verbindet, überträgt aber keine Daten. |
| Authentication | Anmeldeverfahren | Password → „Benutzername und Passwort“; TLS → „Zertifikat“; TLS/Password → „Zertifikat und Passwort“. |
| Encryption | Verschlüsselung des Datenkanals | None → `none` (siehe unten). |
| Remote host/IP address | Serveradresse | `publicip20.mdex.de` |
| Resolve retry | Namensauflösung wiederholen | `infinite` (Standard). |
| Keep alive | Keepalive | Zwei Zahlen, Intervall und Timeout, zum Beispiel `10 120`. Leer: TunnelDeck setzt keins. |
| Remote network IP / netmask | – | Nicht in Stufe 1. TunnelDeck legt nie Routen an; es beantwortet Verbindungen, die durch den Tunnel ankommen. LAN-Gateway-Funktionen sind für 0.2.0 geplant. |
| Authentication algorithm | Authentifizierungs-Digest | None → `none`. Muss zum Server passen. |
| User name / Password | Benutzername / Passwort | Das Passwort wird verschlüsselt gespeichert und erreicht OpenVPN über den Management-Socket, nie über eine Datei. |
| Certificate files (CA) | CA-Zertifikat | Bei jedem Anmeldeverfahren nötig. Den PEM-Text von `mdexCA20.crt` einfügen. |
| Extra options | Zusätzliche Optionen | Eine Direktive pro Zeile; siehe nächste Tabelle. |

## Zusätzliche Optionen des RUT240

Was mit jeder Zeile passiert, wenn sie unter **Zusätzliche Optionen** eingefügt oder importiert wird (`internal/vpn/openvpn/classify.go`, `render.go`):

| Zeile | Ergebnis | Grund |
|---|---|---|
| `tun-mtu 1500` | bleibt | Geht an OpenVPN; 1500 ist ohnehin der Standard. |
| `fragment 1448` | bleibt | Funktioniert in 2.7; erscheint als Hinweis (veraltete MTU-Notlösung). Schaltet Data Channel Offload ab. |
| `mssfix` | bleibt | Übernimmt den Wert von `fragment`. |
| `float` | bleibt | |
| `nobind` | entfällt mit Warnung | TunnelDeck setzt es immer. |
| `reneg-sec 86400` | bleibt | |
| `remote-cert-tls server` | entfällt mit Warnung | Wird über das Profilfeld „Prüfen, ob das Serverzertifikat für einen Server ausgestellt ist“ gesetzt (standardmäßig an). |
| `tls-version-min 1.2` | bleibt | TunnelDeck setzt `tls-version-min 1.2` ohnehin, wenn keine zusätzliche Option eine TLS-Version festlegt. |
| `explicit-exit-notify 2` | bleibt bei UDP | Entfällt mit Warnung, wenn der Transport TCP ist, weil OpenVPN es dort ignoriert. |
| `fast-io` | entfällt mit Warnung | Veraltet; OpenVPN 2.7 ignoriert es. |
| `redirect-gateway def1` | entfällt mit Warnung | Das Routing übernimmt TunnelDeck; die NAS behält ihre eigene Standardroute. |

Zeilen, die Skripte starten oder Dateien anfassen (`up`, `script-security`, `log`, ...), werden abgelehnt; das Formular nennt die Zeile.

## Warum aus `cipher none` ein `data-ciphers` wird

OpenVPN 2.7 ignoriert `cipher`, wenn es den Datenkanal aushandelt. „Encryption: None“ des RUT240 als `cipher none` eingefügt scheitert daher an einem Server, der nur `none` anbietet (`AUTH_FAILED ... no shared cipher`). Steht im Profil die Verschlüsselung `none`, erzeugt TunnelDeck

```
data-ciphers none:CHACHA20-POLY1305
data-ciphers-fallback none
```

Der Tunnel ist dann unverschlüsselt, wenn der Server das erlaubt, und weicht sonst auf ChaCha20-Poly1305 aus. Dashboard und Formular zeigen einen Hinweis, dass der Datenverkehr nicht verschlüsselt ist. Eine `cipher`-Zeile in den zusätzlichen Optionen entfällt mit einem Verweis auf das Profilfeld.

## Die NAS von außen erreichen

Am RUT240 war die Weboberfläche des Routers über den Tunnel erreichbar. In TunnelDeck ersetzt das der **Fernzugriff per HTTPS** (System > Fernzugriff, Standardport 8443): die eigene Oberfläche von TunnelDeck unter `https://<VPN-Adresse>:8443` mit selbst signiertem oder hochgeladenem Zertifikat. Siehe [`synology.de.md`](synology.de.md#6-fernzugriff-über-den-tunnel). Andere Ports der NAS sind aus dem Tunnel nur über eine Regel auf der Seite **Host-Zugriff** erreichbar; alles andere bleibt gesperrt.

## Empfehlung: Wechsel auf Stufe 30

mdex kennzeichnet Stufe 20 als nicht mehr zu verwenden. Für Stufe 30 ändert sich im Profil:

- Serveradresse `publicip30.mdex.de`.
- CA-Zertifikat `mdexCA30.crt`.
- Zusätzliche Option `tls-version-min 1.3`.
- `tun-mtu`, `fragment`, `mssfix` und `reneg-sec` entfernen; mdex nennt sie für Stufe 30 nicht.
- Verschlüsselung `none` und Digest `none` bleiben.

Bei mdex nachfragen, ob das Konto für Stufe 30 freigeschaltet ist. Diese Variante folgt der Dokumentation von mdex und ist nicht gegen den echten Server getestet.
