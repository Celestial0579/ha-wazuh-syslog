"""Feste Werte der Wazuh-Protokollweiterleitung."""

DOMAIN = "wazuh_syslog"

CONF_HOST = "host"
CONF_PORT = "port"
CONF_KENNUNG = "kennung"
CONF_STUFE = "stufe"
CONF_LOGGER = "logger"

# Voreinstellung: genau die Logger, die sicherheitsrelevant sind.
# homeassistant.components.http.ban schreibt JEDEN fehlgeschlagenen Anmeldeversuch
# und jede Anfrage mit ungueltiger Authentifizierung - das ist der Kern des Ganzen.
VORGABE_LOGGER = [
    "homeassistant.components.http.ban",
    "homeassistant.components.auth",
    "homeassistant.components.cloud",
    "hass_nabucasa",
]
VORGABE_STUFE = "WARNING"
VORGABE_PORT = 514
VORGABE_KENNUNG = "homeassistant"

# Syslog-Schweregrade nach RFC 3164
SCHWERE = {
    "CRITICAL": 2,
    "ERROR": 3,
    "WARNING": 4,
    "INFO": 6,
    "DEBUG": 7,
}
FACILITY_LOCAL0 = 16
