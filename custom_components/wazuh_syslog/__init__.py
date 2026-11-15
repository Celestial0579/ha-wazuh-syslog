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
import threading
import time

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
MELDE_ABSTAND = 300  # Sekunden: Ausfälle höchstens so oft melden


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
        # Zustand für Meldungen und Diagnose: jeder Wechsel von „geht“ auf „geht nicht“
        # wird gemeldet (höchstens alle MELDE_ABSTAND Sekunden), damit ein späterer Ausfall
        # nicht lautlos bleibt. Fällt ein Ausfall in den Meldeabstand, wird er beim nächsten
        # Fehler nach Ablauf nachgeholt („_gemeldet“ gilt je Ausfall, nicht je Zeitfenster).
        self.gestoert = False
        self._gemeldet = False
        self.fehler_zaehler = 0
        self.letzter_erfolg: float | None = None
        self.letzter_fehler: str | None = None
        self._zuletzt_gemeldet = float("-inf")  # monotonic beginnt nahe 0 (frisch gestarteter Rechner)
        self._sperre = threading.Lock()  # Socket und Ziel werden gemeinsam getauscht
        self._rechner = "homeassistant"
        # Socket, Rechnername und Zieladresse entstehen im Executor (socket_anlegen),
        # nie beim Senden: Home Assistant meldet blockierende Aufrufe in der
        # Ereignisschleife, und eine Namensaufloesung je Zeile kann sie lahmlegen.
        self._sock: socket.socket | None = None

    def socket_anlegen(self) -> None:
        """Ziel aufloesen und Socket passend zur Adressfamilie anlegen. Im Executor aufrufen."""
        family, adresse = aufloesen(self._host, self._port)
        self._rechner = socket.gethostname().split(".")[0] or "homeassistant"
        alt = None
        neu = socket.socket(family, socket.SOCK_DGRAM) if self._sock is None or family != self._family else None
        with self._sperre:
            if neu is not None:
                alt, self._sock = self._sock, neu
            self._family, self._ziel = family, adresse
        if alt is not None:
            alt.close()  # erst nach dem Tausch: ein laufender Versand nutzt schon den neuen

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
            with self._sperre:
                if self._sock is None or self._ziel is None:
                    raise OSError("Ziel noch nicht aufgeloest")
                self._sock.sendto(self.paket(text, stufe), self._ziel)
        except Exception as fehler:  # noqa: BLE001
            # Protokollieren ist hier ungefaehrlich: emit() ueberspringt Eintraege der
            # eigenen Integration, die Schleife kann also nicht entstehen. Ein vollstaendig
            # stummes Schlucken hat am 20.09.2026 eine Stunde Fehlersuche gekostet.
            self.fehler_zaehler += 1
            self.letzter_fehler = f"{type(fehler).__name__}: {str(fehler)[:100]}"
            jetzt = time.monotonic()
            if not self._gemeldet and jetzt - self._zuletzt_gemeldet >= MELDE_ABSTAND:
                self._zuletzt_gemeldet = jetzt
                self._gemeldet = True
                _LOGGER.error(
                    "Syslog-Versand an %s:%s schlug fehl (%s). Bis zum naechsten erfolgreichen "
                    "Versand werden weitere Fehler nicht gemeldet.",
                    self._host, self._port, self.letzter_fehler,
                )
            self.gestoert = True
            return
        self.letzter_erfolg = time.time()
        if self.gestoert:
            self.gestoert = False
            if self._gemeldet:  # „geht wieder“ nur nach einer Fehlermeldung
                self._gemeldet = False
                _LOGGER.warning("Syslog-Versand an %s:%s geht wieder", self._host, self._port)

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
