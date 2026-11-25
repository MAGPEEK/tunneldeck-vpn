# TunnelDeck-VPN

**Selbst gehosteter VPN-Client mit Weboberfläche, als ein einziger Docker-Container.** Läuft auf jedem Linux-Docker-Host mit amd64 oder arm64: Server, Mini-PC, Raspberry Pi oder NAS.

[English](README.md) · Lizenz: MIT · Status: **Vorab-Version 0.1.0-alpha.1**, noch nicht im Praxistest bestätigt

## Was es kann

- **VPN-Profile im Browser verwalten**: per Formular anlegen oder als `.ovpn`-Datei importieren. Mehrere Profile lassen sich speichern; aktiv ist immer eines.
- **Dashboard**: Verbindungsstatus, VPN-Adresse, Datenverkehr und Live-Protokoll.
- **Bleibt verbunden**: verbindet nach Netzfehlern automatisch neu, stoppt sofort bei abgelehnten Zugangsdaten und verbindet nach einem Container-Neustart wieder.
- **Tägliche Trennung, wenn gewünscht**: einmal am Tag zur eingestellten Uhrzeit, je Profil.
- **Schützt den Host**: Alles, was durch den Tunnel ankommt, wird gesperrt, außer den freigegebenen Ports. Der Host behält seine eigene Standardroute.
- **Erkennt veraltete Einstellungen**: unverschlüsselter Datenkanal, schwache Verschlüsselung, Kompression und Ähnliches erscheinen als Hinweis.
- **Sicher voreingestellt**: Anmeldung nötig, Zugangsdaten verschlüsselt gespeichert, Oberfläche nur im LAN. Fernzugriff per HTTPS zuschaltbar.
- Oberfläche auf **Deutsch und Englisch**, helles und dunkles Design.

## Unterstützte VPN-Verfahren

| Verfahren | Status |
|---|---|
| OpenVPN (2.7) | in Entwicklung |
| WireGuard | geplant |
| IPsec / IKEv2 | geplant |

## Schnellstart

```yaml
services:
  tunneldeck:
    image: magpeek/tunneldeck-vpn:0.1.0-alpha.1
    container_name: tunneldeck
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes: ["./data:/data"]
    environment: { TZ: Europe/Berlin }
    restart: unless-stopped
```

`http://<host-ip>:8194` öffnen und das Admin-Konto anlegen. Passwort vergessen: `docker exec tunneldeck tunneldeck reset-admin`.

## Ports

| Port | Protokoll | Erreichbar aus | Zweck |
|---|---|---|---|
| 8194 | HTTP | nur LAN, nie durch den Tunnel | Weboberfläche. Ändern mit `TUNNELDECK_LISTEN=<LAN-IP>:<Port>`, z. B. `192.168.1.10:9000`. |
| 8443 (Vorgabe, frei wählbar) | HTTPS | LAN und VPN-Tunnel | Optionaler Fernzugriff auf die Weboberfläche. Standardmäßig aus; einschalten unter **System → Fernzugriff**. Fernzugriff über das VPN nur per HTTPS, nie per reinem HTTP. |

Alle anderen Ports des Hosts sind für den Tunnel gesperrt, außer du gibst sie unter **Host-Zugriff** frei.

## Dokumentation

- [Einrichtung auf einem Linux-Docker-Host](docs/linux.de.md): TUN-Gerät, Firewall-Werkzeuge (ufw, firewalld), HTTPS, Sicherung, Aktualisierung
- [Einrichtung auf einer Synology](docs/synology.de.md): TUN-Modul, Container Manager, Firewall, HTTPS, Sicherung, Aktualisierung
- [Umzug vom Teltonika RUT240](docs/migrate-from-rut240.de.md): Felder und zusätzliche Optionen, Beispiel mdex
- [Releases](docs/RELEASING.md) (englisch): Versions-Tags, Image bauen und veröffentlichen
- [Spezifikation](docs/SPEC.md) und [OpenVPN-Notizen](docs/openvpn-notes.md) (englisch)

## Fahrplan

- **0.1.0**: OpenVPN-Client, Dashboard, Host-Schutz, tägliche Trennung, Fernzugriff per HTTPS
- **0.2.0**: LAN-Gateway mit Gerätefreigabe, Kill-Switch, Portweiterleitung, Verkehrsdiagramm
- **0.3.0**: WireGuard

## Entwicklung

Go-Backend mit eingebettetem React/TypeScript-Frontend. Die Befehle stehen in [`CLAUDE.md`](CLAUDE.md), das Design in [`docs/SPEC.md`](docs/SPEC.md).
