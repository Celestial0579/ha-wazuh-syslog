"""Leitet sicherheitsrelevante Protokollzeilen von Home Assistant an Wazuh weiter.

WOZU: Fehlgeschlagene Anmeldungen stehen im HA-Protokoll und sonst nirgends. Wer alle
anderen Sicherheitsquellen im SIEM korreliert, hat ausgerechnet an der Haussteuerung
einen blinden Fleck - obwohl die von aussen erreichbar ist. Am 20.09.2026 fand sich
dort ein Scanner (45.61.188.240), der Joomla-Pfade abklapperte und HA erreichte.

WARUM EINE EIGENE INTEGRATION UND KEIN shell_command:
Auf einer HAOS-Anlage ohne Terminal-, Datei-Editor- oder SSH-Add-on kommt man an die
configuration.yaml nicht heran - und genau dort muessten shell_command, rest_command
oder python_script eingetragen werden. Eine Integration mit Einrichtungsdialog laesst
sich dagegen vollstaendig ueber HACS und die Oberflaeche einrichten.

WIE: Ein logging.Handler haengt sich in die Python-Protokollierung von Home Assistant
und schickt passende Eintraege als RFC-3164-Syslog per UDP an den Wazuh-Manager.
Zusaetzlich gibt es den Dienst wazuh_syslog.senden fuer eigene Meldungen aus
Automatisierungen.

WAZUH-SEITE (nicht Teil dieser Integration):
  - In ossec.conf muss die IP dieser Anlage unter <allowed-ips> stehen, sonst
    verwirft wazuh-remoted die Pakete LAUTLOS.
  - Ohne passenden Dekoder landen die Zeilen als unbekannt im Archiv. Der Dekoder
    greift am Programmnamen (Vorgabe: homeassistant).
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_HOST, CONF_KENNUNG, CONF_LOGGER, CONF_PORT, CONF_STUFE,
    DOMAIN, FACILITY_LOCAL0, SCHWERE, VORGABE_KENNUNG, VORGABE_LOGGER,
    VORGABE_PORT, VORGABE_STUFE,
)

_LOGGER = logging.getLogger(__name__)


def _logger_liste(wert) -> list[str]:
    """Nimmt Liste ODER kommagetrennte Zeichenkette.

    Der Einrichtungsdialog liefert eine Zeichenkette (siehe die Falle in
    config_flow._maske), aeltere Eintraege koennen noch eine Liste enthalten.
    """
    if isinstance(wert, str):
        return [t.strip() for t in wert.split(",") if t.strip()]
    return list(wert or [])


class SyslogWeiterleitung(logging.Handler):
    """Schickt passende Protokolleintraege als Syslog an den Wazuh-Manager.

    FALLE, DIE HIER VERMIEDEN WIRD: Ein Handler, der beim Senden selbst protokolliert,
    erzeugt eine Endlosschleife - seine eigene Fehlermeldung loest den naechsten Versand
    aus. Deshalb schluckt _senden JEDEN Fehler und schreibt nie ins Protokoll.
    """

    def __init__(self, host: str, port: int, kennung: str,
                 stufe: str, logger_liste: list[str]) -> None:
        super().__init__(level=getattr(logging, stufe, logging.WARNING))
        self._ziel = (host, port)
        self._kennung = kennung
        self._praefixe = tuple(logger_liste)
        self._eigener_name = __name__.rsplit(".", 1)[0]
        self._sock: socket.socket | None = None

    def _verbindung(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._sock

    def emit(self, satz: logging.LogRecord) -> None:
        # Niemals die eigenen Meldungen weiterleiten - sonst schaukelt es sich auf.
        if satz.name.startswith(self._eigener_name):
            return
        if self._praefixe and not satz.name.startswith(self._praefixe):
            return
        try:
            text = self.format(satz)
        except Exception:  # noqa: BLE001
            return
        self._senden(text, satz.levelname)

    def _senden(self, text: str, stufe: str) -> None:
        try:
            schwere = SCHWERE.get(stufe, 5)
            pri = FACILITY_LOCAL0 * 8 + schwere
            # RFC 3164: <PRI>MMM tt hh:mm:ss rechner programm: text
            # Der Tag im Zeitstempel ist rechtsbuendig mit Leerzeichen aufgefuellt -
            # ein fuehrender Nullstelle laesst manche Dekoder scheitern.
            jetzt = datetime.now()
            zeit = f"{jetzt.strftime('%b')} {jetzt.day:2d} {jetzt.strftime('%H:%M:%S')}"
            rechner = socket.gethostname().split(".")[0] or "homeassistant"
            einzeilig = " ".join(str(text).split())[:900]
            paket = f"<{pri}>{zeit} {rechner} {self._kennung}: {einzeilig}".encode("utf-8", "replace")
            self._verbindung().sendto(paket, self._ziel)
        except Exception:  # noqa: BLE001 - darf NIE protokollieren, siehe Klassenkopf
            pass

    def close(self) -> None:
        try:
            if self._sock is not None:
                self._sock.close()
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._sock = None
            super().close()


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Handler einhaengen und den Dienst anmelden."""
    d = {**entry.data, **entry.options}
    handler = SyslogWeiterleitung(
        host=d[CONF_HOST],
        port=int(d.get(CONF_PORT, VORGABE_PORT)),
        kennung=d.get(CONF_KENNUNG, VORGABE_KENNUNG),
        stufe=d.get(CONF_STUFE, VORGABE_STUFE),
        logger_liste=_logger_liste(d.get(CONF_LOGGER, VORGABE_LOGGER)),
    )
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    logging.getLogger().addHandler(handler)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = handler

    async def senden(aufruf: ServiceCall) -> None:
        """Eigene Meldung aus einer Automatisierung heraus."""
        handler._senden(aufruf.data["nachricht"], aufruf.data.get("stufe", "INFO"))

    if not hass.services.has_service(DOMAIN, "senden"):
        hass.services.async_register(
            DOMAIN, "senden", senden,
            schema=vol.Schema({
                vol.Required("nachricht"): cv.string,
                vol.Optional("stufe", default="INFO"): vol.In(list(SCHWERE)),
            }),
        )

    _LOGGER.info(
        "Protokollweiterleitung an %s:%s aktiv, ab Stufe %s, Logger %s",
        d[CONF_HOST], d.get(CONF_PORT, VORGABE_PORT),
        d.get(CONF_STUFE, VORGABE_STUFE), d.get(CONF_LOGGER, VORGABE_LOGGER),
    )
    entry.async_on_unload(entry.add_update_listener(_neu_laden))
    return True


async def _neu_laden(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Handler wieder aushaengen - sonst sendet er nach dem Entfernen weiter."""
    handler = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if handler is not None:
        logging.getLogger().removeHandler(handler)
        handler.close()
    if not hass.data.get(DOMAIN):
        hass.services.async_remove(DOMAIN, "senden")
    return True
