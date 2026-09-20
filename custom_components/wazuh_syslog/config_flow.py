"""Einrichtungsdialog der Wazuh-Protokollweiterleitung."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow, ConfigEntry
from homeassistant.core import callback

from .const import (
    CONF_HOST, CONF_KENNUNG, CONF_LOGGER, CONF_PORT, CONF_STUFE,
    DOMAIN, SCHWERE, VORGABE_KENNUNG, VORGABE_LOGGER, VORGABE_PORT, VORGABE_STUFE,
)

TITEL = "Wazuh: Protokollweiterleitung"


def _maske(vorgaben: dict[str, Any]) -> vol.Schema:
    return vol.Schema({
        vol.Required(CONF_HOST, default=vorgaben.get(CONF_HOST, "")): str,
        vol.Optional(CONF_PORT, default=vorgaben.get(CONF_PORT, VORGABE_PORT)): int,
        vol.Optional(CONF_KENNUNG, default=vorgaben.get(CONF_KENNUNG, VORGABE_KENNUNG)): str,
        vol.Optional(CONF_STUFE, default=vorgaben.get(CONF_STUFE, VORGABE_STUFE)): vol.In(list(SCHWERE)),
        vol.Optional(CONF_LOGGER, default=vorgaben.get(CONF_LOGGER, VORGABE_LOGGER)): vol.All(
            cv_liste, [str]
        ),
    })


def cv_liste(wert: Any) -> list[str]:
    """Nimmt eine Liste oder eine kommagetrennte Zeichenkette entgegen.

    Die Oberflaeche liefert je nach Eingabefeld das eine oder das andere; wer nur
    eine Liste erwartet, bekommt bei Eingabe von Hand einen Fehler, den niemand
    versteht.
    """
    if isinstance(wert, str):
        return [t.strip() for t in wert.split(",") if t.strip()]
    return list(wert)


class WazuhSyslogConfigFlow(ConfigFlow, domain=DOMAIN):
    """Fragt Ziel, Port, Kennung, Mindeststufe und die zu ueberwachenden Logger ab."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            user_input[CONF_LOGGER] = cv_liste(user_input.get(CONF_LOGGER, VORGABE_LOGGER))
            return self.async_create_entry(title=TITEL, data=user_input)
        return self.async_show_form(step_id="user", data_schema=_maske({}))

    @staticmethod
    @callback
    def async_get_options_flow(entry: ConfigEntry) -> OptionsFlow:
        return WazuhSyslogOptionsFlow()


class WazuhSyslogOptionsFlow(OptionsFlow):
    """Nachtraegliches Aendern, ohne den Eintrag zu loeschen."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            user_input[CONF_LOGGER] = cv_liste(user_input.get(CONF_LOGGER, VORGABE_LOGGER))
            return self.async_create_entry(title="", data=user_input)
        jetzt = {**self.config_entry.data, **self.config_entry.options}
        return self.async_show_form(step_id="init", data_schema=_maske(jetzt))
