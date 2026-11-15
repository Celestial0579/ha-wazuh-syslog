# ha-wazuh-syslog

Leitet sicherheitsrelevante Protokollzeilen von Home Assistant als Syslog an einen
Wazuh-Manager weiter.

## Warum

Fehlgeschlagene Anmeldungen stehen im Protokoll von Home Assistant — und sonst
nirgends. Wer alle anderen Sicherheitsquellen im SIEM korreliert, hat ausgerechnet
an der Haussteuerung einen blinden Fleck, obwohl die oft von aussen erreichbar ist.

## Warum eine Integration und kein `shell_command`

Auf einer HAOS-Anlage ohne Terminal-, Datei-Editor- oder SSH-Add-on kommt man an die
`configuration.yaml` nicht heran — und genau dort muessten `shell_command`,
`rest_command` oder `python_script` eingetragen werden. Eine Integration mit
Einrichtungsdialog laesst sich dagegen vollstaendig ueber HACS und die Oberflaeche
einrichten.

## Was sie tut

Ein `logging.Handler` haengt sich in die Protokollierung von Home Assistant und
schickt passende Eintraege als RFC-3164-Syslog per UDP weiter. Vorgabe sind die
Logger, die wirklich sicherheitsrelevant sind:

| Logger | was dort landet |
|---|---|
| `homeassistant.components.http.ban` | **jeder** fehlgeschlagene Anmeldeversuch, mit Quell-IP, angefragter URL und User-Agent |
| `homeassistant.components.auth` | Fehler der Anmeldung selbst |
| `homeassistant.components.cloud`, `hass_nabucasa` | Ausfaelle des Fernzugangs |

Dazu der Dienst `wazuh_syslog.senden` fuer eigene Meldungen aus Automatisierungen. Er ist nur fuer
Admins aufrufbar, und seine Zeilen beginnen mit `wazuh_syslog.senden: `. So kann niemand ueber den
Dienst eine fehlgeschlagene Anmeldung mit beliebiger Quell-IP vortaeuschen; Dekoder und Regeln
werten nur Zeilen, die mit `homeassistant.components.http.ban: ` beginnen.

**Nach dem Update auf 1.0.3 und auf 1.0.6** Dekoder und Regeln aus `wazuh/` in Wazuh neu einspielen.
1.0.6 bringt die Regeln 100535 und 100536 (Anmeldung mit nicht eindeutiger Quelladresse); vorher im
Bestand prüfen, dass die Nummern frei sind.

**Regelnummern.** Der Integration gehört der Block 100530–100549, belegt sind davon heute
100530–100536. Neue Regeln der Integration kommen in diesen Block. Eigene Regeln bitte außerhalb
davon nummerieren und in eine eigene Datei legen, nicht in `homeassistant_rules.xml`. Diese Datei wird
bei jedem Update ersetzt, und doppelte Nummern lassen die Regelprüfung beim Neustart scheitern.

**Welche Logger.** Das Feld nimmt Logger-Namen, kommagetrennt; Unter-Logger zählen mit. **Leer bedeutet
die Vorgabe** aus der Tabelle oben. Bis 1.0.5 bedeutete leer „alles“. Wer wirklich alles weiterleiten
will, trägt `*` ein. Das schickt aber auch Zeilen mit sensiblen Inhalten (Adressen, Namen, Token in
Fehlermeldungen von Integrationen) ins SIEM.

**Klartext über UDP.** Der Versand ist RFC-3164-Syslog über UDP: unverschlüsselt, ohne Anmeldung,
ohne Bestätigung. Jeder im Netz dazwischen kann mitlesen, und jeder, der Pakete mit der Absenderadresse
der HA-Anlage schicken kann, kann Zeilen einschleusen. Abgesichert ist der Weg nur auf der Wazuh-Seite
über `allowed-ips`. Die Strecke also nur durch ein vertrauenswürdiges Netz führen (gleiches LAN/VLAN,
oder ein VPN).

## Einrichtung

1. In HACS als eigenes Repositorium hinzufuegen, Art **Integration**, herunterladen,
   Home Assistant neu starten.
2. *Einstellungen → Geraete & Dienste → Integration hinzufuegen* →
   **Wazuh: Protokollweiterleitung**.
3. Adresse des Wazuh-Managers eintragen (am besten die IP-Adresse; ein Rechnername wird beim
   Einrichten und danach alle 30 Minuten aufgeloest, nie beim Senden). Port 514, Programmname `homeassistant`
   und Mindeststufe `WARNING` sind sinnvolle Vorgaben.

## Wazuh-Seite

Ohne diese beiden Schritte kommt nichts an:

**Freigabe.** In `ossec.conf` muss die Adresse der HA-Anlage unter `<allowed-ips>`
stehen. Fehlt sie, verwirft `wazuh-remoted` die Pakete **lautlos** — kein Fehler,
kein Eintrag, nichts.

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.0.2.10</allowed-ips>  <!-- Adresse der HA-Anlage eintragen -->
</remote>
```

**Dekoder und Regeln.** Ohne Dekoder landen die Zeilen unausgewertet im Archiv. Der
Dekoder greift am Programmnamen. Beispiele liegen unter `wazuh/`.

## Fallen

- **Der Handler darf niemals selbst protokollieren.** Eine Fehlermeldung beim Senden
  wuerde den naechsten Versand ausloesen und sich aufschaukeln. `_senden` schluckt
  deshalb jeden Fehler, und Eintraege der eigenen Integration werden uebersprungen.
- **UDP-Syslog bestaetigt nichts.** Kommt nichts an, merkt die sendende Seite es nicht.
  Der Nachweis muss auf dem Wazuh-Manager gefuehrt werden, nicht in Home Assistant.
- **Der Tag im Zeitstempel ist rechtsbuendig mit Leerzeichen aufgefuellt** (`Sep  9`,
  nicht `Sep 09`). Eine fuehrende Null laesst manche Dekoder scheitern.
- **Mindeststufe nicht auf INFO oder DEBUG stellen.** Home Assistant protokolliert
  reichlich; das SIEM ertraenkt sonst im Rauschen.

## Lizenz

MIT
