"""Diagnose: Zustand der Weiterleitung."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:
    """Fehlerzähler und letzter Erfolg; Adresse und Logger nennt der Eintrag selbst."""
    handler = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if handler is None:
        return {"geladen": False}
    erfolg = handler.letzter_erfolg
    return {
        "geladen": True,
        "gestoert": handler.gestoert,
        "fehler_seit_start": handler.fehler_zaehler,
        "letzter_fehler": handler.letzter_fehler,
        "letzter_erfolg": datetime.fromtimestamp(erfolg, UTC).isoformat() if erfolg else None,
    }
