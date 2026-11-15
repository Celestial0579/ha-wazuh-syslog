"""Paketaufbau, Filter, Dienst, Dialog und Wazuh-Ausdrücke ohne Wazuh."""

from __future__ import annotations

from datetime import datetime
import logging
from pathlib import Path
import re
import socket
from unittest.mock import patch
import xml.etree.ElementTree as ET

from pytest_homeassistant_custom_component.common import MockConfigEntry, MockUser
import pytest

from homeassistant.core import Context, HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import Unauthorized

from custom_components.wazuh_syslog import SyslogWeiterleitung, aufloesen
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
    handler = SyslogWeiterleitung("127.0.0.1", 514, "homeassistant", "WARNING", logger or [])
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
