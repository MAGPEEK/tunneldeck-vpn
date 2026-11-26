# Admin-Passwort verloren

TunnelDeck hat genau ein Admin-Konto. Haben Sie das Passwort verloren, setzen Sie das Konto zurück und legen ein neues an. Diese Anleitung erklärt, was ein Zurücksetzen ändert, und zeigt die zwei Wege dorthin.

## Was das Zurücksetzen bewirkt

Das Zurücksetzen:

- entfernt das Admin-Konto (Benutzername und Passwort-Hash),
- beendet alle Sitzungen, auch gemerkte „Angemeldet bleiben“-Sitzungen auf allen Geräten.

Alles andere bleibt erhalten: VPN-Profile mit ihren Geheimnissen, Firewall-Regeln, Einstellungen, Zertifikate und die Konfiguration des Fernzugriffs. Ein verbundener Tunnel bleibt verbunden.

Beim nächsten Aufruf zeigt die Oberfläche die Einrichtungsseite, auf der Sie ein neues Admin-Konto anlegen.

## Weg A: Befehl im Container

Führen Sie den Befehl im laufenden Container aus:

```sh
docker exec tunneldeck tunneldeck reset-admin
```

`tunneldeck` ist der Container-Name aus unseren Compose-Dateien (`docker-compose.yml`, `deploy/synology/docker-compose.yml`). Haben Sie den Container anders benannt, finden Sie ihn mit:

```sh
docker ps --format '{{.Names}}\t{{.Image}}'
```

### Auf einer Synology

- **Per SSH:** Melden Sie sich am NAS an und führen Sie `sudo docker exec tunneldeck tunneldeck reset-admin` aus.

### Erwartete Ausgabe

Läuft der Server, bittet der Befehl ihn über seinen lokalen Steuer-Socket um das Zurücksetzen, und die Logzeile lautet:

```
admin account removed by the running server; open the web UI to run setup again
```

Läuft kein Server (etwa in einem Container, der nur für diesen Befehl gestartet wurde), ändert der Befehl das Datenverzeichnis direkt:

```
admin account removed (no server was running); setup is offered at the next start
```

Jedes andere Ergebnis ist eine Fehlermeldung, die mit `reset admin:` beginnt.

## Weg B: Umgebungsvariable, ohne Shell

Nutzen Sie diesen Weg, wenn Sie keine Shell im Container öffnen können.

1. Ergänzen Sie die Variable in der Umgebung des Containers, in der Compose-Datei:

   ```yaml
   environment:
     TUNNELDECK_RESET_ADMIN: "1"
   ```

   (der Synology Container Manager funktioniert dabei wie jeder Docker-Host).
2. Erstellen Sie den Container neu (`docker compose up -d`).
3. Öffnen Sie die Oberfläche und legen Sie das neue Admin-Konto an.
4. **Entfernen Sie die Variable wieder** und erstellen Sie den Container erneut.

Solange die Variable gesetzt ist, entfernt der Server das Admin-Konto und alle Sitzungen **bei jedem Start** und schreibt jedes Mal diese Warnung ins Log:

```
TUNNELDECK_RESET_ADMIN is set: the admin account is removed at every start until the variable is removed
```

Vergessen Sie Schritt 4, löscht der nächste Neustart (ein Update, ein Neustart des NAS) das eben angelegte Konto, und die Einrichtungsseite steht wieder offen für jeden, der die Oberfläche zuerst erreicht.

## Danach

- Legen Sie auf der Einrichtungsseite das neue Admin-Konto an. Das Passwort muss mindestens 12 Zeichen lang sein.
- Nutzen Sie den Fernzugriff über HTTPS, prüfen Sie auf der Seite **System**, dass er noch funktioniert; Konfiguration und Zertifikat sind unverändert.
- „Überall abmelden“ ist nicht nötig: Das Zurücksetzen hat bereits alle Sitzungen auf allen Geräten beendet.

## Sicherheitshinweis

Wer Zugriff auf den Docker-Host (SSH, `docker`-Befehle, Container Manager) oder auf das Datenverzeichnis hat, kann das Admin-Konto zurücksetzen und die Oberfläche übernehmen. Schützen Sie SSH- und DSM-Zugänge mit starken Passwörtern und Zwei-Faktor-Authentifizierung und machen Sie sie nicht aus dem Internet erreichbar.
