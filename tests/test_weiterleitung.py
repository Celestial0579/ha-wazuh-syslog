"""Paketaufbau, Filter, Dienst, Dialog und Wazuh-Ausdrücke ohne Wazuh."""

from __future__ import annotations

from datetime import datetime
import logging
from pathlib import Path
import re
import socket
import time
from unittest.mock import patch
import xml.etree.ElementTree as ET

from pytest_homeassistant_custom_component.common import MockConfigEntry, MockUser
import pytest

from homeassistant.core import Context, HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import Unauthorized
from homeassistant.helpers.http import current_request

from custom_components.wazuh_syslog import SyslogWeiterleitung, aufloesen, ban_zeile_eindeutig
from custom_components.wazuh_syslog.config_flow import pruefen
from custom_components.wazuh_syslog.const import DOMAIN

WAZUH = Path(__file__).parent.parent / "wazuh"
ECHT = (
    "homeassistant.components.http.ban: Login attempt or request with invalid authentication from "
    "scanner.example (203.0.113.7). Requested URL: '/auth/token'. (curl/8.0 (203.0.113.99))"
)


class Mitschnitt:
    def __init__(self) -> None:
        self.pakete: list[bytes] = []

    def sendto(self, paket: bytes, _ziel) -> None:
        self.pakete.append(paket)

    def close(self) -> None:
        return


def _handler(logger: list[str] | None = None) -> tuple[SyslogWeiterleitung, Mitschnitt]:
    handler = SyslogWeiterleitung("127.0.0.1", 514, "homeassistant", "WARNING", logger or ["*"])
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    mitschnitt = Mitschnitt()
    handler._sock, handler._ziel, handler._rechner = mitschnitt, ("127.0.0.1", 514), "ha"
    return handler, mitschnitt


def test_paket() -> None:
    handler, _ = _handler()
    paket = handler.paket("zwei\n  Zeilen", "WARNING", datetime(2026, 9, 9, 8, 5, 3))
    assert paket == b"<132>Sep  9 08:05:03 ha homeassistant: zwei Zeilen"
    assert len(handler.paket("x" * 2000, "ERROR")) < 1000


def test_logger_mit_punktgrenze() -> None:
    handler, mitschnitt = _handler(["homeassistant.components.cloud"])
    for name in ("homeassistant.components.cloud", "homeassistant.components.cloud.iot", "homeassistant.components.cloudflare"):
        handler.emit(logging.LogRecord(name, logging.WARNING, "", 0, "x", None, None))
    assert [p.split(b": ", 1)[1] for p in mitschnitt.pakete] == [
        b"homeassistant.components.cloud: x",
        b"homeassistant.components.cloud.iot: x",
    ]


def test_eigene_meldungen_werden_nie_weitergeleitet() -> None:
    handler, mitschnitt = _handler()
    handler.emit(logging.LogRecord("custom_components.wazuh_syslog", logging.ERROR, "", 0, "x", None, None))
    assert mitschnitt.pakete == []


def test_senden_loest_keinen_namen_auf() -> None:
    handler, mitschnitt = _handler()
    with patch("socket.getaddrinfo", side_effect=AssertionError("Namensauflösung beim Senden")):
        handler._senden("x", "WARNING")
    assert len(mitschnitt.pakete) == 1


def test_aufloesen_ipv6() -> None:
    family, adresse = aufloesen("::1", 514)
    assert family == socket.AF_INET6 and adresse[:2] == ("::1", 514)


@pytest.mark.parametrize(
    ("eingabe", "fehler"),
    [
        ({"host": "192.0.2.1", "port": 514, "kennung": "homeassistant"}, {}),
        ({"host": "  ", "port": 514, "kennung": "homeassistant"}, {"host": "ungueltige_adresse"}),
        ({"host": "192.0.2.1", "port": 70000, "kennung": "homeassistant"}, {"port": "ungueltiger_port"}),
        ({"host": "192.0.2.1", "port": 514, "kennung": "home assistant:"}, {"kennung": "ungueltige_kennung"}),
    ],
)
def test_pruefen(eingabe: dict, fehler: dict) -> None:
    assert pruefen(eingabe) == fehler


def _ausdruecke() -> dict[str, str]:
    """Die pcre2-Ausdrücke aus Dekoder und Regeln (Teilmenge, die auch Python versteht)."""
    dekoder = ET.fromstring("<w>" + (WAZUH / "0710-homeassistant_decoders.xml").read_text() + "</w>")
    regeln = ET.fromstring((WAZUH / "homeassistant_rules.xml").read_text().split("-->", 2)[2])
    login = dekoder.find("decoder[@name='homeassistant-login']")
    return {
        "prematch": login.findtext("prematch"),
        "dekoder": login.findtext("regex"),
        **{r.get("id"): r.findtext("regex") for r in regeln.iter("rule") if r.findtext("regex")},
    }


def test_wazuh_ausdruecke() -> None:
    a = _ausdruecke()
    treffer = re.search(a["dekoder"], ECHT)
    assert treffer and treffer.groups() == ("203.0.113.7", "/auth/token")
    assert re.search(a["prematch"], ECHT) and re.search(a["100531"], ECHT)
    # Über den Dienst gesendet, mit dem Wortlaut der echten Zeile: keine Anmelderegel.
    falsch = "wazuh_syslog.senden: " + ECHT.split(": ", 1)[1]
    assert not re.search(a["prematch"], falsch) and not re.search(a["100531"], falsch)
    assert re.search(a["100534"], falsch)
    assert re.search(a["100533"], "hass_nabucasa.iot: Verbindung verloren")
    assert not re.search(a["100533"], "homeassistant.components.cloudflare: x")


@pytest.mark.parametrize(
    "name",
    [
        "x (198.51.100.1). Requested URL: '/' y",  # GHSA-q7p9-34f8-phc3: Adresse im PTR-Namen
        "x (198.51.100.1). Requested URL: '/'. (z",  # dieselbe Fälschung, sauber fortgesetzt
        "x (198.51.100.1).",
        "a b",
        "(198.51.100.1)",
    ],
)
def test_gefaelschter_ptr_name_liefert_keine_srcip(name: str) -> None:
    """musl übernimmt PTR-Namen ungeprüft; ein Name mit Leerzeichen oder Klammern darf keine srcip bestimmen."""
    a = _ausdruecke()
    zeile = ECHT.replace("scanner.example", name)
    assert not re.search(a["dekoder"], zeile)
    assert not re.search(a["100531"], zeile)
    assert re.search(a["100535"], zeile) and re.search(a["prematch"], zeile)


@pytest.mark.parametrize(
    ("name", "adresse"),
    [("scanner.example", "203.0.113.7"), ("203.0.113.7", "203.0.113.7"), ("host-6.example", "2001:db8::7"), ("fe80--1", "fe80::1%eth0")],
)
def test_echte_namen_und_adressen(name: str, adresse: str) -> None:
    """Echte Zeilen behalten srcip, auch mit Klammern im User-Agent."""
    a = _ausdruecke()
    zeile = ECHT.replace("scanner.example (203.0.113.7)", f"{name} ({adresse})")
    treffer = re.search(a["dekoder"], zeile)
    assert treffer and treffer.group(1) == adresse
    assert re.search(a["100531"], zeile) and not re.search(a["100535"], zeile)


def test_mehrdeutige_zeile_ohne_srcip() -> None:
    """Steht die Adressfolge mehrfach in der Zeile (etwa im User-Agent), ist die Quelle nicht eindeutig."""
    a = _ausdruecke()
    zeile = ECHT.replace("curl/8.0 (203.0.113.99)", "x (198.51.100.1). Requested URL: '/'")
    assert not re.search(a["dekoder"], zeile) and not re.search(a["100531"], zeile)
    assert re.search(a["100535"], zeile)


class _Anfrage:
    """Attrappe einer aiohttp-Anfrage: nur die Gegenstelle."""

    def __init__(self, remote: str | None) -> None:
        self.remote = remote


def _ban_text(remote: str | None, zeile: str) -> str:
    """Schickt eine http.ban-Zeile durch emit(), mit oder ohne laufende Anfrage, und liefert den Text im Paket."""
    handler, mitschnitt = _handler(["homeassistant.components.http.ban"])
    marke = current_request.set(_Anfrage(remote) if remote is not None else None)
    try:
        nachricht = zeile.split(": ", 1)[1]
        handler.emit(logging.LogRecord("homeassistant.components.http.ban", logging.WARNING, "", 0, nachricht, None, None))
    finally:
        current_request.reset(marke)
    return mitschnitt.pakete[0].decode().split(" homeassistant: ", 1)[1]


@pytest.mark.parametrize(
    "zeile",
    [
        ECHT,
        ECHT.replace("curl/8.0 (203.0.113.99)", "x (198.51.100.1). Requested URL: '/'"),  # User-Agent
        ECHT.replace("curl/8.0 (203.0.113.99)", "x (198.51.100.1).   Requested\tURL:  '/"),  # dasselbe mit Leerraum
        ECHT.replace("scanner.example", "x (198.51.100.1). Requested URL: '/'. (z"),  # PTR-Name (GHSA-q7p9)
        ECHT.replace("curl/8.0 (203.0.113.99)", "x (203.0.113.7). Requested URL: '/'"),  # eigene Adresse doppelt
        ECHT.replace("/auth/token", "/" + "a" * 1200),  # lange URL: das Hochkomma bleibt im Paket
    ],
)
def test_srcip_aus_der_laufenden_anfrage(zeile: str) -> None:
    """Mit bekannter Anfrage bekommt jede Anmeldezeile genau die echte srcip (GHSA-39hx-rh84-fpmm)."""
    a = _ausdruecke()
    text = _ban_text("203.0.113.7", zeile)
    assert len(text) <= 900
    treffer = re.search(a["dekoder"], text)
    assert treffer and treffer.group(1) == "203.0.113.7"
    assert re.search(a["100531"], text) and not re.search(a["100535"], text)


@pytest.mark.parametrize("remote", [None, "192.0.2.50", "kein-ip"])
def test_ohne_passende_anfrage_bleibt_die_zeile(remote: str | None) -> None:
    """Ohne Anfrage, mit fremder oder unlesbarer Adresse bleibt die Zeile, wie sie ist: mehrdeutig, ohne srcip."""
    a = _ausdruecke()
    zeile = ECHT.replace("curl/8.0 (203.0.113.99)", "x (198.51.100.1). Requested URL: '/'")
    text = _ban_text(remote, zeile)
    assert text == zeile
    assert not re.search(a["dekoder"], text) and re.search(a["100535"], text)


def test_andere_zeilen_bleiben() -> None:
    """Nur die Anmeldezeile wird umgeschrieben; andere Zeilen von http.ban bleiben."""
    zeile = "homeassistant.components.http.ban: Banned IP 203.0.113.7 for too many login attempts"
    assert ban_zeile_eindeutig(zeile, "203.0.113.7") == zeile
    assert _ban_text("203.0.113.7", zeile) == zeile


def test_ipv6_aus_der_anfrage() -> None:
    a = _ausdruecke()
    zeile = ECHT.replace("scanner.example (203.0.113.7)", "host-6.example (2001:db8::7)").replace(
        "curl/8.0 (203.0.113.99)", "x (198.51.100.1). Requested URL: '/'"
    )
    text = _ban_text("2001:0db8:0:0::7", zeile)
    treffer = re.search(a["dekoder"], text)
    assert treffer and treffer.group(1) == "2001:db8::7"


async def test_dienst_nur_fuer_admins(hass: HomeAssistant, hass_admin_user: MockUser, hass_read_only_user: MockUser) -> None:
    eintrag = MockConfigEntry(domain=DOMAIN, data={"host": "127.0.0.1", "port": 514})
    eintrag.add_to_hass(hass)
    mitschnitt = Mitschnitt()

    def anlegen(self: SyslogWeiterleitung) -> None:
        self._sock, self._ziel = mitschnitt, ("127.0.0.1", 514)

    with patch.object(SyslogWeiterleitung, "socket_anlegen", anlegen):
        assert await hass.config_entries.async_setup(eintrag.entry_id)
    try:
        with pytest.raises(Unauthorized):
            await hass.services.async_call(
                DOMAIN, "senden", {"nachricht": "x"}, blocking=True, context=Context(user_id=hass_read_only_user.id)
            )
        await hass.services.async_call(
            DOMAIN, "senden", {"nachricht": "Tür offen"}, blocking=True, context=Context(user_id=hass_admin_user.id)
        )
        assert mitschnitt.pakete[-1].endswith("homeassistant: wazuh_syslog.senden: Tür offen".encode())
    finally:
        assert await hass.config_entries.async_unload(eintrag.entry_id)
    assert not hass.services.has_service(DOMAIN, "senden")


async def test_dialog_meldet_fehler(hass: HomeAssistant) -> None:
    ergebnis = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    ergebnis = await hass.config_entries.flow.async_configure(
        ergebnis["flow_id"], {"host": "", "port": 514, "kennung": "homeassistant", "stufe": "WARNING", "logger": "a"}
    )
    assert ergebnis["type"] is FlowResultType.FORM
    assert ergebnis["errors"] == {"host": "ungueltige_adresse"}


def test_jeder_neue_ausfall_wird_gemeldet(caplog: pytest.LogCaptureFixture) -> None:
    handler, mitschnitt = _handler()

    def kaputt(_paket: bytes, _ziel) -> None:
        raise OSError("Netz weg")

    gut = mitschnitt.sendto
    for _runde in range(2):
        mitschnitt.sendto = kaputt
        handler._senden("a", "WARNING")
        handler._senden("b", "WARNING")
        mitschnitt.sendto = gut
        handler._senden("c", "WARNING")
        handler._zuletzt_gemeldet -= 1000  # Meldeabstand verstrichen
    fehler = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(fehler) == 2  # zwei Ausfälle mit Erfolg dazwischen, je eine Meldung
    assert handler.fehler_zaehler == 4 and not handler.gestoert and handler.letzter_erfolg


def test_meldeabstand(caplog: pytest.LogCaptureFixture) -> None:
    handler, mitschnitt = _handler()
    gut = mitschnitt.sendto

    def kaputt(_paket: bytes, _ziel) -> None:
        raise OSError("Netz weg")

    for _runde in range(3):  # flatternde Verbindung ohne verstrichenen Abstand
        mitschnitt.sendto = kaputt
        handler._senden("a", "WARNING")
        mitschnitt.sendto = gut
        handler._senden("b", "WARNING")
    assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 1


def test_unterdrueckte_meldung_wird_nachgeholt(caplog: pytest.LogCaptureFixture) -> None:
    """#10: Fehler, Erfolg, Fehler im Meldeabstand, später weitere Fehler ergeben eine zweite Meldung."""
    handler, mitschnitt = _handler()
    gut = mitschnitt.sendto

    def kaputt(_paket: bytes, _ziel) -> None:
        raise OSError("Netz weg")

    def fehler() -> list[logging.LogRecord]:
        return [r for r in caplog.records if r.levelname == "ERROR"]

    mitschnitt.sendto = kaputt
    handler._senden("a", "WARNING")  # gemeldet
    mitschnitt.sendto = gut
    handler._senden("b", "WARNING")  # „geht wieder“
    mitschnitt.sendto = kaputt
    handler._senden("c", "WARNING")  # neuer Ausfall im Meldeabstand: noch still
    assert len(fehler()) == 1 and handler.gestoert
    handler._senden("d", "WARNING")
    assert len(fehler()) == 1
    handler._zuletzt_gemeldet -= 1000  # Meldeabstand verstrichen, Ausfall hält an
    handler._senden("e", "WARNING")
    assert len(fehler()) == 2
    handler._senden("f", "WARNING")
    assert len(fehler()) == 2  # je Ausfall nur einmal
    mitschnitt.sendto = gut
    handler._senden("g", "WARNING")
    assert len([r for r in caplog.records if "geht wieder" in r.getMessage()]) == 2


def test_geht_wieder_nur_nach_meldung(caplog: pytest.LogCaptureFixture) -> None:
    handler, mitschnitt = _handler()
    gut = mitschnitt.sendto

    def kaputt(_paket: bytes, _ziel) -> None:
        raise OSError("Netz weg")

    handler._zuletzt_gemeldet = time.monotonic()  # gerade erst gemeldet
    mitschnitt.sendto = kaputt
    handler._senden("a", "WARNING")
    mitschnitt.sendto = gut
    handler._senden("b", "WARNING")
    assert not [r for r in caplog.records if "geht wieder" in r.getMessage()]
    assert not handler.gestoert


def test_leere_loggerliste_bedeutet_vorgabe() -> None:
    """#12: leer heißt die sicherheitsrelevanten Logger, „*“ heißt alles."""
    from custom_components.wazuh_syslog import _logger_liste
    from custom_components.wazuh_syslog.const import VORGABE_LOGGER

    assert _logger_liste("") == VORGABE_LOGGER
    assert _logger_liste([]) == VORGABE_LOGGER
    assert _logger_liste(" , ") == VORGABE_LOGGER
    assert _logger_liste("a.b, c") == ["a.b", "c"]
    vorgabe, _ = _handler(_logger_liste(""))
    assert vorgabe._gewuenscht("homeassistant.components.http.ban")
    assert not vorgabe._gewuenscht("homeassistant.components.mqtt")
    alles, _ = _handler(["*"])
    assert alles._gewuenscht("homeassistant.components.mqtt")
