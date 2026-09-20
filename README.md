# ha-wazuh-syslog

Leitet sicherheitsrelevante Protokollzeilen von Home Assistant als Syslog an einen
Wazuh-Manager weiter.

## Warum

Fehlgeschlagene Anmeldungen stehen im Protokoll von Home Assistant — und sonst
nirgends. Wer alle anderen Sicherheitsquellen im SIEM korreliert, hat ausgerechnet
an der Haussteuerung einen blinden Fleck, obwohl die von aussen erreichbar ist.

Anlass war ein realer Fund am 20.09.2026: Ein Scanner unter `45.61.188.240` klapperte
Joomla-Pfade ab (`/media/system/js/core.js`, `/media/jui/js/bootstrap.min.js`) und
erreichte dabei Home Assistant. Im SIEM tauchte davon nichts auf.

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

Dazu der Dienst `wazuh_syslog.senden` fuer eigene Meldungen aus Automatisierungen.

## Einrichtung

1. In HACS als eigenes Repositorium hinzufuegen, Art **Integration**, herunterladen,
   Home Assistant neu starten.
2. *Einstellungen → Geraete & Dienste → Integration hinzufuegen* →
   **Wazuh: Protokollweiterleitung**.
3. Adresse des Wazuh-Managers eintragen. Port 514, Programmname `homeassistant`
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
  <allowed-ips>192.168.24.27</allowed-ips>
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
