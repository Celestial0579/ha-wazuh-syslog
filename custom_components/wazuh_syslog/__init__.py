"""Leitet sicherheitsrelevante Protokollzeilen von Home Assistant an Wazuh weiter.

WOZU: Fehlgeschlagene Anmeldungen stehen im HA-Protokoll und sonst nirgends. Wer alle
anderen Sicherheitsquellen im SIEM korreliert, hat ausgerechnet an der Haussteuerung
einen blinden Fleck - obwohl die oft von aussen erreichbar ist.

WARUM EINE EIGENE INTEGRATION UND KEIN shell_command:
Auf einer HAOS-Anlage ohne Terminal-, Datei-Editor- oder SSH-Add-on kommt man an die
configuration.yaml nicht heran - und genau dort muessten shell_command, rest_command
oder python_script eingetragen werden. Eine Integration mit Einrichtungsdialog laesst
sich dagegen vollstaendig ueber HACS und die Oberflaeche einrichten.

WIE: Ein logging.Handler haengt sich in die Python-Protokollierung von Home Assistant
und schickt passende Eintraege als RFC-3164-Syslog per UDP an den Wazuh-Manager.
Zusaetzlich gibt es den Dienst wazuh_syslog.senden fuer eigene Meldungen aus
Automatisierungen.

SCHUTZMODELL: Das SIEM wertet Zeilen dieser Integration als Sicherheitsereignisse, vor allem
fehlgeschlagene Anmeldungen MIT Quell-IP. Eine solche Zeile darf deshalb nur von
homeassistant.components.http.ban stammen koennen. Jede weitergeleitete Zeile beginnt mit dem
Namen ihres Loggers; Dekoder und Regeln verankern sich genau dort. Der Dienst senden ist nur
fuer Admins und kennzeichnet seine Zeilen mit "wazuh_syslog.senden: ", kann also keine
Anmelderegel ausloesen. Der Versand laeuft im Thread, der protokolliert (oft die
Ereignisschleife): Er darf nie blockieren, also keine Namensaufloesung beim Senden.

WAZUH-SEITE (nicht Teil dieser Integration):
  - In ossec.conf muss die IP dieser Anlage unter <allowed-ips> stehen, sonst
    verwirft wazuh-remoted die Pakete LAUTLOS.
  - Ohne passenden Dekoder landen die Zeilen als unbekannt im Archiv. Der Dekoder
    greift am Programmnamen (Vorgabe: homeassistant).
"""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
import socket

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.service import async_register_admin_service

from .const import (
    CONF_HOST, CONF_KENNUNG, CONF_LOGGER, CONF_PORT, CONF_STUFE,
    DOMAIN, FACILITY_LOCAL0, SCHWERE, VORGABE_KENNUNG, VORGABE_LOGGER,
    VORGABE_PORT, VORGABE_STUFE,
)

_LOGGER = logging.getLogger(__name__)

AUFFRISCHEN = timedelta(minutes=30)
DIENST_KENNUNG = "wazuh_syslog.senden"


def _logger_liste(wert) -> list[str]:
    """Nimmt Liste ODER kommagetrennte Zeichenkette.

    Der Einrichtungsdialog liefert eine Zeichenkette (siehe die Falle in
    config_flow._maske), aeltere Eintraege koennen noch eine Liste enthalten.
    """
    if isinstance(wert, str):
        return [t.strip() for t in wert.split(",") if t.strip()]
    return list(wert or [])


def aufloesen(host: str, port: int) -> tuple[int, tuple]:
    """Adressfamilie und Zieladresse; blockierend, nur im Executor aufrufen."""
    family, _typ, _proto, _name, adresse = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    return family, adresse


class SyslogWeiterleitung(logging.Handler):
    """Schickt passende Protokolleintraege als Syslog an den Wazuh-Manager.

    FALLE, DIE HIER VERMIEDEN WIRD: Ein Handler, der beim Senden selbst protokolliert,
    erzeugt eine Endlosschleife - seine eigene Fehlermeldung loest den naechsten Versand
    aus. Deshalb werden Eintraege der eigenen Integration nie weitergeleitet.
    """

    def __init__(self, host: str, port: int, kennung: str,
                 stufe: str, logger_liste: list[str]) -> None:
        super().__init__(level=getattr(logging, stufe, logging.WARNING))
        self._host = host
        self._port = port
        self._ziel: tuple | None = None
        self._family: int | None = None
        self._kennung = kennung
        self._praefixe = tuple(logger_liste)
        self._eigener_name = __name__.rsplit(".", 1)[0]
        self._fehler_gemeldet = False
        self._rechner = "homeassistant"
        # Socket, Rechnername und Zieladresse entstehen im Executor (socket_anlegen),
        # nie beim Senden: Home Assistant meldet blockierende Aufrufe in der
        # Ereignisschleife, und eine Namensaufloesung je Zeile kann sie lahmlegen.
        self._sock: socket.socket | None = None

    def socket_anlegen(self) -> None:
        """Ziel aufloesen und Socket passend zur Adressfamilie anlegen. Im Executor aufrufen."""
        family, adresse = aufloesen(self._host, self._port)
        self._rechner = socket.gethostname().split(".")[0] or "homeassistant"
        if self._sock is None or family != self._family:
            alt, self._sock = self._sock, socket.socket(family, socket.SOCK_DGRAM)
            if alt is not None:
                alt.close()
        self._family, self._ziel = family, adresse

    def _gewuenscht(self, name: str) -> bool:
        return not self._praefixe or any(name == p or name.startswith(p + ".") for p in self._praefixe)

    def emit(self, satz: logging.LogRecord) -> None:
        # Niemals die eigenen Meldungen weiterleiten - sonst schaukelt es sich auf.
        if satz.name == self._eigener_name or satz.name.startswith(self._eigener_name + "."):
            return
        if not self._gewuenscht(satz.name):
            return
        try:
            text = self.format(satz)
        except Exception:  # noqa: BLE001
            return
        self._senden(text, satz.levelname)

    def paket(self, text: str, stufe: str, jetzt: datetime | None = None) -> bytes:
        """RFC 3164: <PRI>MMM tt hh:mm:ss rechner programm: text"""
        schwere = SCHWERE.get(stufe, 5)
        pri = FACILITY_LOCAL0 * 8 + schwere
        # Der Tag im Zeitstempel ist rechtsbuendig mit Leerzeichen aufgefuellt -
        # eine fuehrende Null laesst manche Dekoder scheitern.
        jetzt = jetzt or datetime.now()
        zeit = f"{jetzt.strftime('%b')} {jetzt.day:2d} {jetzt.strftime('%H:%M:%S')}"
        einzeilig = " ".join(str(text).split())[:900]
        return f"<{pri}>{zeit} {self._rechner} {self._kennung}: {einzeilig}".encode("utf-8", "replace")

    def _senden(self, text: str, stufe: str) -> None:
        try:
            if self._sock is None or self._ziel is None:
                raise OSError("Ziel noch nicht aufgeloest")
            self._sock.sendto(self.paket(text, stufe), self._ziel)
        except Exception as fehler:  # noqa: BLE001
            # EINMAL melden, dann schweigen. Protokollieren ist hier ungefaehrlich:
            # emit() ueberspringt Eintraege der eigenen Integration, die Schleife
            # kann also nicht entstehen. Ein vollstaendig stummes Schlucken hat
            # am 20.09.2026 eine Stunde Fehlersuche gekostet - das Paket kam nie
            # an, und niemand konnte sagen warum.
            if not self._fehler_gemeldet:
                self._fehler_gemeldet = True
                _LOGGER.error(
                    "Syslog-Versand an %s:%s schlug fehl (%s: %s). Weitere Fehler "
                    "werden nicht mehr gemeldet.",
                    self._host, self._port, type(fehler).__name__, fehler,
                )

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
        host=str(d[CONF_HOST]).strip(),
        port=int(d.get(CONF_PORT, VORGABE_PORT)),
        kennung=d.get(CONF_KENNUNG, VORGABE_KENNUNG),
        stufe=d.get(CONF_STUFE, VORGABE_STUFE),
        logger_liste=_logger_liste(d.get(CONF_LOGGER, VORGABE_LOGGER)),
    )
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    try:
        await hass.async_add_executor_job(handler.socket_anlegen)
    except OSError as err:
        handler.close()
        raise ConfigEntryNotReady(f"Wazuh-Manager {d[CONF_HOST]} nicht aufloesbar: {err}") from err
    logging.getLogger().addHandler(handler)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = handler

    async def _auffrischen(_jetzt: datetime) -> None:
        try:
            await hass.async_add_executor_job(handler.socket_anlegen)
        except OSError as err:
            _LOGGER.debug("Wazuh-Manager nicht neu aufgeloest, bleibe bei der alten Adresse: %s", err)

    entry.async_on_unload(async_track_time_interval(hass, _auffrischen, AUFFRISCHEN))

    async def senden(aufruf: ServiceCall) -> None:
        """Eigene Meldung aus einer Automatisierung heraus, eigens gekennzeichnet."""
        for h in hass.data.get(DOMAIN, {}).values():
            h._senden(f"{DIENST_KENNUNG}: {aufruf.data['nachricht']}", aufruf.data.get("stufe", "INFO"))

    if not hass.services.has_service(DOMAIN, "senden"):
        async_register_admin_service(
            hass, DOMAIN, "senden", senden,
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
