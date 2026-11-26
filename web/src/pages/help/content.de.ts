import type { HelpContent } from './content';

export const HELP_CONTENT_DE: HelpContent = {
  'getting-started': [
    {
      type: 'paragraph',
      text: 'Öffnen Sie `http://<Host-Adresse>:8194` in einem Browser im lokalen LAN. Die Weboberfläche ist nur aus dem LAN erreichbar, nie durch den VPN-Tunnel. Adresse oder Port ändern Sie mit der Umgebungsvariablen `TUNNELDECK_LISTEN` (zum Beispiel `192.168.1.10:9000`); die System-Seite zeigt die verwendete Adresse.',
    },
    {
      type: 'list',
      items: [
        'Beim ersten Aufruf legen Sie das Administratorkonto an. Das Passwort braucht mindestens 12 Zeichen. Es gibt genau ein Administratorkonto.',
        'Melden Sie sich mit Benutzername und Passwort an. Nach fünf Fehlversuchen innerhalb einer Minute von einer Adresse wird die Anmeldung für eine Weile gesperrt.',
        '„Angemeldet bleiben“ hält diesen Browser bis zu 90 Tage angemeldet, auch über Neustarts des Containers hinweg; nach 30 Tagen ohne Nutzung endet die Sitzung. Die Option gibt es nur über die LAN-Adresse, nicht über den Fernzugriff.',
        '„Überall abmelden“ auf der System-Seite beendet alle Sitzungen, auch gemerkte.',
      ],
    },
    {
      type: 'paragraph',
      text: 'Prüfen Sie danach, dass auf der System-Seite alle Einträge bestanden sind, legen Sie unter Profile ein VPN-Profil an und verbinden Sie es in der Übersicht.',
    },
    { type: 'link', target: 'linux', text: 'Einrichtung auf einem Linux-Docker-Host' },
    { type: 'link', target: 'synology', text: 'Einrichtung auf Synology DSM' },
  ],
  profiles: [
    {
      type: 'paragraph',
      text: 'Ein Profil enthält alles, was eine VPN-Verbindung braucht. Sie können mehrere Profile speichern; aktiv ist immer eines.',
    },
    {
      type: 'terms',
      items: [
        {
          term: 'Profildatei laden',
          text: 'Verwenden Sie „Profildatei laden (.ovpn, .conf)“ für eine OpenVPN- oder WireGuard-Datei, ziehen Sie die Datei auf die Profil-Seite oder fügen Sie die Konfiguration ein. Das Formular öffnet sich ausgefüllt; gespeichert wird erst, wenn Sie speichern.',
        },
        {
          term: 'Fehlende Felder',
          text: 'Fehlt der Datei etwas, das die Verbindung braucht, zum Beispiel Benutzername und Passwort für `auth-user-pass` oder ein Zertifikat, auf das sie als eigene Datei verweist, hebt das Formular diese Felder hervor. Füllen Sie sie vor dem Speichern aus.',
        },
        {
          term: 'Import-Hinweise',
          text: 'Zeilen, die geändert oder nicht übernommen wurden, werden mit Grund aufgelistet. Unbekannte Direktiven werden nicht übernommen.',
        },
        {
          term: 'Empfehlungen',
          text: 'Veraltete oder schwache Einstellungen werden im Formular und in der Übersicht markiert: ein unverschlüsselter Datenkanal (`cipher none`), schwache Verschlüsselungs- oder Prüfsummenverfahren, Kompression, `fragment`. Sie verhindern die Verbindung nicht.',
        },
        {
          term: 'Zusätzliche Optionen',
          text: 'Eine OpenVPN-2.7-Client-Direktive pro Zeile, die an OpenVPN übergeben wird. Manche werden mit Hinweis verworfen, weil TunnelDeck-VPN sie selbst setzt oder weil sie das Routing dieses Geräts ändern würden: `nobind`, `remote-cert-tls` und `cipher` (nutzen Sie die Profilfelder), `redirect-gateway` (dieses Gerät behält seine eigene Standardroute) sowie veraltete wie `fast-io`. Zeilen, die Skripte ausführen oder Dateien schreiben (`up`, `script-security`, `log`, …), werden abgelehnt.',
        },
        {
          term: 'Geheimnisse',
          text: 'Passwörter und Schlüssel werden verschlüsselt gespeichert und nur als „Gespeichert“ angezeigt. Mit „Ersetzen“ ändern Sie sie.',
        },
        {
          term: 'Tägliche Neuverbindung',
          text: 'Abschnitt „Zeitplan“: „Einmal täglich neu verbinden“ zu einer Uhrzeit Ihrer Wahl, in der Zeitzone des Containers (`TZ`). Sie läuft nur, solange dieses Profil verbunden ist.',
        },
        {
          term: 'Öffentliche Adresse',
          text: 'Abschnitt „Zugriff“: die Adresse, die Ihr Anbieter dieser Verbindung zuweist, zum Beispiel eine feste öffentliche IP. Sie hat immer Vorrang vor der öffentlichen IP, die TunnelDeck-VPN nach jedem Verbindungsaufbau erkennt (System → Erkennung der öffentlichen IP). Sie wird für die Fernzugriffs-URL und für Portweiterleitungen verwendet. Lassen Sie das Feld leer, wenn die VPN-Adresse selbst aus dem Internet erreichbar ist.',
        },
      ],
    },
    { type: 'subheading', text: 'WireGuard' },
    {
      type: 'list',
      items: [
        'Legen Sie ein WireGuard-Profil mit dem Formular an (Protokoll „WireGuard“) oder laden Sie die `.conf`-Datei, die Ihr Server oder Anbieter bereitstellt; Einfügen des Textes geht ebenfalls.',
        '„Schlüsselpaar erzeugen“ erstellt einen neuen privaten Schlüssel für dieses Gerät und zeigt den passenden öffentlichen Schlüssel. Tragen Sie diesen öffentlichen Schlüssel auf dem Server als öffentlichen Schlüssel des Peers ein; der private Schlüssel verlässt TunnelDeck-VPN nicht und wird verschlüsselt gespeichert.',
        '`DNS` aus der Datei wird nicht übernommen, der Host behält seine eigenen DNS-Einstellungen; Skripte (`PreUp`, `PostUp`, `PreDown`, `PostDown`) werden nicht importiert. Verwendet werden nur der erste Peer und IPv4-Einträge.',
        '`AllowedIPs` außer `0.0.0.0/0` gelten als Netze hinter dem VPN und werden über den Tunnel geroutet. Welche LAN-Geräte den Tunnel nutzen dürfen, entscheiden wie bei OpenVPN die Firewall-Regeln und der Kill-Switch.',
        'Antwortet der Server beim Verbinden nicht, zeigt die Übersicht das nach 30 Sekunden an und versucht es weiter: Prüfen Sie die Schlüssel und den Endpunkt.',
      ],
    },
    { type: 'link', target: 'migrate-from-rut240', text: 'Umstieg von einem Teltonika RUT240' },
  ],
  connecting: [
    {
      type: 'paragraph',
      text: 'Verbinden Sie in der Übersicht. Bei mehreren Profilen wählen Sie das Profil neben „Verbinden“.',
    },
    {
      type: 'terms',
      items: [
        { term: 'Getrennt', text: 'Kein Tunnel. Die Firewall schützt dieses Gerät weiterhin.' },
        { term: 'Verbindet', text: 'OpenVPN erreicht den Server und meldet sich an.' },
        {
          term: 'Verbunden',
          text: 'Der Tunnel steht; die Übersicht zeigt VPN-Adresse und Datenverkehr.',
        },
        {
          term: 'Verbindet neu',
          text: 'Die Verbindung ging verloren oder wird erneuert, zum Beispiel durch die tägliche Neuverbindung.',
        },
        { term: 'Trennt', text: 'Der Tunnel wird geschlossen.' },
        {
          term: 'Fehler',
          text: 'Der letzte Versuch ist fehlgeschlagen. Die Übersicht zeigt den Grund und „Erneut versuchen“; Details stehen auf der Protokoll-Seite.',
        },
      ],
    },
    {
      type: 'list',
      items: [
        'Nach Netzwerkfehlern versucht TunnelDeck-VPN es selbst erneut: zuerst nach 2 Sekunden, dann mit doppeltem Abstand bis 60 Sekunden, ohne je aufzugeben.',
        'Lehnt der Server die Zugangsdaten ab, hören die Versuche sofort auf, damit der Anbieter das Konto nicht sperrt. Korrigieren Sie Benutzername oder Passwort im Profil und verbinden Sie erneut.',
        'Nach einem Neustart des Containers verbindet sich das zuvor verbundene Profil wieder.',
        'Ein Profil lässt sich immer löschen, auch das aktive: Es wird zuerst getrennt (bis zu 15 Sekunden) und dann gelöscht. Die Bestätigung weist darauf hin.',
        'Die Zeile „Verschlüsselung“ in der Übersicht zeigt das mit dem Server ausgehandelte Verfahren des Datenkanals; ein unverschlüsselter Kanal erscheint rot.',
      ],
    },
  ],
  firewall: [
    {
      type: 'paragraph',
      text: 'Alles zwischen VPN und lokalem LAN ist in beide Richtungen gesperrt, solange keine Regel es erlaubt. Antworten auf erlaubte Verbindungen kommen immer durch. Regeln gelten von oben nach unten; die Reihenfolge ändern Sie mit den Pfeiltasten. Änderungen wirken mit „Änderungen speichern“.',
    },
    {
      type: 'terms',
      items: [
        {
          term: 'Eingehend vom VPN',
          text: 'Verkehr, der an der VPN-Adresse ankommt. Ziel ist genau eine IPv4-Adresse im lokalen LAN.',
        },
        {
          term: 'Dieses Gerät oder Portweiterleitung',
          text: 'Die Zieladresse entscheidet: Die eigene LAN-Adresse dieses Geräts öffnet einen Port auf diesem Gerät (erlauben, verwerfen oder ablehnen); jede andere LAN-Adresse macht die Regel zu einer Portweiterleitung, die immer erlaubt. Das wird bei jedem Anwenden neu entschieden; reservieren Sie die Adresse dieses Geräts deshalb in Ihrem Router.',
        },
        {
          term: 'Ausgehend ins VPN',
          text: 'Lässt ein LAN-Gerät oder Subnetz Netze hinter dem VPN erreichen, mit der VPN-Adresse als Absender. Das Gerät muss dieses Gerät als Gateway nutzen oder eine Route zum Ziel über dieses Gerät haben. Kill-Switch: Solange der Tunnel getrennt ist, wird dieser Verkehr verworfen und geht nie über die normale Internetverbindung hinaus.',
        },
        {
          term: 'Absender, den das Gerät sieht',
          text: '„Dieses Gerät“ (Standard): Das Ziel sieht dieses Gerät als Absender und antwortet ihm ohne Routenänderung. „Ursprünglicher Absender“: Das Ziel sieht die echte entfernte Adresse und muss seine Antworten über dieses Gerät zurückschicken, zum Beispiel mit einer ausgehenden Regel. Nötig, wo die Adresse zählt, etwa bei IPsec.',
        },
        {
          term: 'IPsec-Router',
          text: 'Die Karte legt die Regeln für einen IPsec-Router im LAN an: IKE (UDP 500 und 4500) und ESP werden mit ursprünglichem Absender an den Router weitergeleitet, dazu eine ausgehende Regel für den Router. Sein Standard-Gateway muss dieses Gerät sein.',
        },
        {
          term: 'Beliebiger Port',
          text: 'Ein leeres Portfeld bedeutet jeden Port. Eine Portweiterleitung ohne Port leitet jeden Port ihres Protokolls weiter, außer dem Port der Weboberfläche und, solange der Fernzugriff an ist, dessen Port.',
        },
        {
          term: 'Schutz',
          text: 'Ungültige Pakete verwerfen, TCP-MSS anpassen, Schutz vor SYN-Flut (25 neue Verbindungen pro Sekunde und Absender) und Ping-Begrenzung (5 pro Sekunde), alle standardmäßig an. „Nur globales Limit“ oder „Auf diesem System nicht verfügbar“ heißt, dem Host-Kernel fehlt ein Modul; siehe Systemprüfungen.',
        },
        {
          term: 'Trefferzähler',
          text: 'Wie viele neue Verbindungen eine Regel seit ihrer letzten Änderung erfasst hat; „–“, solange die Regel aus ist. Sie fehlen, wenn dem Kernel `xt_comment` fehlt.',
        },
      ],
    },
    {
      type: 'paragraph',
      text: 'Der Port der Weboberfläche lässt sich nie zum Tunnel öffnen, und der Fernzugriffs-Port ist reserviert. Portweiterleitungen und ausgehende Regeln brauchen IP-Weiterleitung auf dem Host (Prüfung `ip-forward`).',
    },
    {
      type: 'link',
      target: 'linux',
      text: 'Firewall-Konzepte und IPsec-Beispiel (Linux-Anleitung, Abschnitt 10)',
    },
  ],
  'remote-access': [
    {
      type: 'paragraph',
      text: 'Der Fernzugriff macht diese Weboberfläche durch das VPN erreichbar, nur über HTTPS (Standardport 8443, frei wählbar). Der HTTP-Port 8194 bleibt am Tunnel geschlossen. Sie schalten ihn unter System → Fernzugriff ein.',
    },
    {
      type: 'list',
      items: [
        'Behalten Sie das selbstsignierte Zertifikat oder laden Sie ein eigenes Zertifikat mit Schlüssel hoch (PEM).',
        'Beim ersten Aufruf warnt der Browser vor dem selbstsignierten Zertifikat. Vergleichen Sie dessen SHA-256-Fingerabdruck mit dem auf der System-Seite und fahren Sie nur fort, wenn beide übereinstimmen.',
        'Die Anmeldeseite wird aus dem Internet erreichbar: Verwenden Sie ein langes Administratorpasswort.',
        'Der Fernzugriff gilt nur für diese Weboberfläche. Andere Ports brauchen eine Regel auf der Firewall-Seite.',
      ],
    },
    { type: 'subheading', text: 'Öffentliche Adresse, nicht die Adresse des VPN-Servers' },
    {
      type: 'paragraph',
      text: 'Eine häufige Verwechslung: Die Serveradresse im Profil (zum Beispiel `vpn.example.net`) ist das Ziel, mit dem sich dieses Gerät verbindet. Sie führt nicht zu diesem Gerät zurück. Der Fernzugriff nutzt die Adresse dieses Tunnelendes: die öffentliche Adresse aus dem Profil; ohne sie die durch den Tunnel erkannte öffentliche IP; und ohne diese die VPN-Adresse aus der Übersicht. Die System-Seite zeigt die vollständige URL.',
    },
  ],
  'system-checks': [
    {
      type: 'paragraph',
      text: 'Die System-Seite listet die Selbstprüfung, die bei jedem Start läuft. OK: vorhanden. Warnung: Ein optionales Modul fehlt, nur die genannte Funktion ist eingeschränkt, die Firewall arbeitet weiter. Fehler: Eine Voraussetzung fehlt; beheben Sie sie zuerst. Starten Sie den Container neu, nachdem Sie ein Kernelmodul geladen haben.',
    },
    {
      type: 'terms',
      items: [
        { term: 'TUN-Gerät (`tun-device`)', text: 'Erforderlich. Ohne es startet kein Tunnel.' },
        {
          term: 'iptables (`iptables`)',
          text: 'Erforderlich. Ohne es gibt es keine Firewall und keinen Kill-Switch.',
        },
        { term: 'ip-Werkzeug (`ip`)', text: 'Erforderlich. Ohne es kein Routing für den Tunnel.' },
        {
          term: 'NET_ADMIN-Berechtigung (`net-admin`)',
          text: 'Erforderlich. Ohne sie darf der Container weder Firewall noch Routen ändern.',
        },
        {
          term: 'IP-Weiterleitung (`ip-forward`)',
          text: 'Erforderlich für Regeln an andere Geräte und ausgehende Regeln; Regeln an dieses Gerät funktionieren ohne sie.',
        },
        {
          term: 'LAN-Subnetze (`lan-subnets`)',
          text: 'Erforderlich. Ohne sie haben eingehende Regeln an andere LAN-Geräte kein Ziel.',
        },
        {
          term: 'Trefferzähler (`rule-counters`)',
          text: 'Optional. Ohne `xt_comment` sind die Zähler aus.',
        },
        {
          term: 'Schutz vor SYN-Flut (`syn-flood-protection`)',
          text: 'Optional. Eine globale statt einer Rate pro Absender, oder er entfällt.',
        },
        {
          term: 'Ping-Begrenzung (`ping-limit`)',
          text: 'Optional. Entfällt nur, wenn beide Raten-Module fehlen.',
        },
        {
          term: 'TCP-MSS-Anpassung (`mss-clamp`)',
          text: 'Optional. Ohne `xt_TCPMSS` können große Übertragungen hängen.',
        },
        {
          term: 'REJECT-Ziel (`reject-target`)',
          text: 'Optional. Ablehnen-Regeln verwerfen stattdessen stillschweigend.',
        },
        {
          term: 'Antwort-Routing von Portweiterleitungen (`reply-routing`)',
          text: 'Optional. Ohne CONNMARK schickt ein Ziel einer Portweiterleitung, das dieses Gerät als Gateway nutzt, seinen gesamten Verkehr durch den Tunnel.',
        },
      ],
    },
    {
      type: 'link',
      target: 'system-checks',
      text: 'Alle Prüfungen im Detail, mit Abhilfe für Linux und DSM',
    },
  ],
  troubleshooting: [
    {
      type: 'paragraph',
      text: 'Beginnen Sie auf der Protokoll-Seite: Wählen Sie „Warnungen und Fehler“ und kopieren Sie die betreffenden Zeilen, wenn Sie um Hilfe bitten.',
    },
    {
      type: 'terms',
      items: [
        {
          term: 'Warnungen zu `cipher none`',
          text: 'OpenVPN warnt vor einem unverschlüsselten Datenkanal, wenn das Verfahren im Profil `none` ist. Bei Anbietern ohne Verschlüsselung ist das erwartet. Das Protokoll vermerkt, dass die Warnung von der Profileinstellung kommt; die Zeile „Data Channel:“ nennt das tatsächlich verwendete Verfahren.',
        },
        {
          term: '„Options error … [PUSH-OPTIONS]“',
          text: 'Ältere Versionen protokollierten das für jede Route und DNS-Option, die der Server übermittelte. Übermittelte Routen und DNS-Optionen werden jetzt gefiltert, die Meldung erscheint nicht mehr. Sehen Sie sie noch, aktualisieren Sie das Image.',
        },
        {
          term: 'Fehlende Kernelmodule',
          text: 'Warnungen oder Fehler auf der System-Seite nennen das Modul. Laden Sie es auf dem Host und starten Sie den Container neu; siehe die Anleitung zu den Systemprüfungen.',
        },
        {
          term: 'Hängende Verbindungen, MTU',
          text: 'Kleine Anfragen gehen, große Übertragungen hängen, oft wenn ein anderes VPN wie IPsec in diesem Tunnel läuft oder dieser Tunnel in einem anderen. Lassen Sie „TCP-MSS anpassen“ an und verringern Sie MTU oder TCP-MSS der inneren Verbindung, zum Beispiel am IPsec-Router. `tun-mtu` oder `mssfix` in den zusätzlichen Optionen nur setzen, wenn Ihr Anbieter es verlangt.',
        },
        {
          term: 'Routing-Warnung',
          text: '„Das Routing für weitergeleiteten Verkehr konnte nicht angewendet werden; neuer Versuch läuft …“ in der Übersicht: Der Tunnel bleibt bestehen, das Routing wird automatisch erneut versucht. Das Protokoll nennt den fehlgeschlagenen `ip`-Befehl. Bleibt die Warnung, prüfen Sie `ip` und `net-admin` auf der System-Seite.',
        },
        {
          term: 'Zugangsdaten abgelehnt',
          text: 'Die Verbindung bleibt ohne neue Versuche im Fehlerzustand. Korrigieren Sie Benutzername oder Passwort im Profil und verbinden Sie dann.',
        },
      ],
    },
    { type: 'link', target: 'issues', text: 'Problem auf GitHub melden' },
  ],
  'admin-reset': [
    {
      type: 'paragraph',
      text: 'Ist das Administratorpasswort verloren, setzen Sie das Administratorkonto zurück. Dabei werden das Konto entfernt und alle Sitzungen beendet; Profile, Firewall-Regeln, Einstellungen und Zertifikate bleiben, ein verbundener Tunnel bleibt verbunden. Beim nächsten Aufruf erscheint die Einrichtungsseite.',
    },
    {
      type: 'list',
      items: [
        'Mit einer Shell auf dem Docker-Host: `docker exec tunneldeck tunneldeck reset-admin`.',
        'Ohne Shell: Setzen Sie `TUNNELDECK_RESET_ADMIN: "1"` in der Compose-Datei, erstellen Sie den Container neu und legen Sie das neue Konto an. Entfernen Sie die Variable danach und erstellen Sie den Container erneut; sonst löscht jeder Neustart das Konto.',
      ],
    },
    {
      type: 'link',
      target: 'reset-admin',
      text: 'Administratorpasswort verloren: die ganze Anleitung',
    },
  ],
};
