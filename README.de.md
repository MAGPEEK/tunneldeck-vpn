# TunnelDeck

**Selbst gehosteter VPN-Client mit Weboberfläche, als ein einziger Docker-Container.** Gebaut für NAS-Geräte wie die Synology DS723+, läuft auf jedem Linux-Docker-Host.

[English](README.md) · Lizenz: MIT · Status: **in Entwicklung (0.1.0-dev)**, noch kein Release

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
    image: magpeek/tunneldeck:0.1.0-dev
    container_name: tunneldeck
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes: ["./data:/data"]
    environment: { TZ: Europe/Berlin }
    restart: unless-stopped
```

`http://<host-ip>:8194` öffnen und das Admin-Konto anlegen. Passwort vergessen: `docker exec tunneldeck tunneldeck reset-admin`.

## Fahrplan

- **0.1.0**: OpenVPN-Client, Dashboard, Host-Schutz, tägliche Trennung, Fernzugriff per HTTPS
- **0.2.0**: LAN-Gateway mit Gerätefreigabe, Kill-Switch, Portweiterleitung, Verkehrsdiagramm
- **0.3.0**: WireGuard

## Entwicklung

Go-Backend mit eingebettetem React/TypeScript-Frontend. Die Befehle stehen in [`CLAUDE.md`](CLAUDE.md), das Design in [`docs/SPEC.md`](docs/SPEC.md).
