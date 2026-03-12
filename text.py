# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Centralized user-facing text strings (copy) for all modules.

Every print message, GUI label, PDF paragraph, and status string lives
here so that wording changes require editing only one file.  Constants
use ``str.format()``-style placeholders (``{name}``) rather than
f-string expressions so they can be defined at import time.
"""

# -- Monitor - Konsolenausgaben ------------------------------------------

MONITOR_INIT_PUBLIC_IP = "  Öffentl. IP : {ip}"
MONITOR_INIT_ISP = "  ISP         : {isp}"
MONITOR_INIT_LOCAL_IP = "  Lokale IP   : {ip}"
MONITOR_INIT_GATEWAY = "  Gateway     : {gw}"
MONITOR_INIT_TARGETS = "  Ziele       : {targets}"
MONITOR_INIT_DNS = "  DNS-Test    : {domain}"
MONITOR_INIT_SNMP_ENABLED = "  SNMP        : aktiviert"
MONITOR_INIT_LOG = "  Logdatei    : {filename}"

MONITOR_SNMP_AGENT_DISABLED = "  SNMP        : Agent antwortet nicht, wird deaktiviert"

MONITOR_LOG_WARNING = "  Warnung: Vorhandene Logdatei konnte nicht gelesen werden: {error}"
MONITOR_LOG_RESUMED = "  Aus heutigem Log fortgesetzt:"
MONITOR_LOG_RESUMED_DETAIL = (
    "    Ereignisse: {events}  "
    "Latenz-Messungen: {latency}  "
    "DNS-Messungen: {dns}  "
    "DNS-Fehler: {failures}  "
    "Ausfallzeit: {downtime}"
)

MONITOR_DISCONNECTED = (
    "[{ts}]  \u2717  Internet GETRENNT  "
    "(alle {count} Ziele nicht erreichbar, Ursache: {cause})"
)
MONITOR_RECONNECTED = (
    "[{ts}]  \u2713  Internet WIEDERVERBUNDEN  "
    "(Ausfall dauerte {duration}){changes}"
)

MONITOR_CAUSE_ISP = "ISP"
MONITOR_CAUSE_ROUTER = "Router/LAN"
MONITOR_CAUSE_UNKNOWN = "Unbekannt"
MONITOR_GATEWAY_NOT_DETECTED = "nicht erkannt"

MONITOR_IP_CHANGED = "IP -> {ip}"
MONITOR_ISP_CHANGED = "ISP -> {isp}"
MONITOR_LOCATION_CHANGED = "Standort -> {location}"

MONITOR_DAILY_SAVED = "[{ts}]Tagesbericht gespeichert: {path}"
MONITOR_DAILY_FAILED = "[{ts}]Bericht speichern fehlgeschlagen: {error}"

MONITOR_STARTING = (
    "Starte Internet-Monitor um {ts}\n"
    "Fenster schließen oder Strg+C drücken zum Beenden.\n"
)
MONITOR_STOP_SIGNAL = "\n\nStoppsignal empfangen - wird abgeschlossen ..."

# -- GUI - Fenster- und Widget-Texte -------------------------------------

GUI_WINDOW_TITLE = "Internetverbindungs-Monitor"

GUI_STATUS_CONNECTED = "VERBUNDEN"
GUI_STATUS_DISCONNECTED = "GETRENNT"
GUI_STATUS_CONNECTED_INIT = "VERBUNDEN"

GUI_LABEL_CONNECTED_TIME = "Verbundene Zeit:"
GUI_LABEL_DISCONNECTED_TIME = "Getrennte Zeit:"
GUI_LABEL_CONNECTIONS = "Verbindungen (#):"
GUI_LABEL_DISCONNECTIONS = "Trennungen (#):"
GUI_LABEL_AVG_LATENCY = "Ø-Latenz:"
GUI_LABEL_DNS_STATUS = "DNS-Status:"
GUI_LABEL_GATEWAY = "Gateway:"

GUI_DEFAULT_DURATION = "0s"
GUI_DEFAULT_COUNT = "0"
GUI_DEFAULT_DASH = "-"

GUI_BTN_SAVE = "Bericht jetzt speichern"
GUI_BTN_SAVING = "Speichert..."
GUI_BTN_SAVED = "Gespeichert!"
GUI_BTN_ERROR = "Fehler!"

GUI_ELAPSED = "Laufzeit: {elapsed}"
GUI_LATENCY_FMT = "{latency:.0f} ms"
GUI_DNS_OK = "OK ({latency:.0f}ms)"
GUI_DNS_FAILED = "FEHLGESCHLAGEN"
GUI_GATEWAY_OK = "{ip} OK{latency}"
GUI_GATEWAY_DOWN = "{ip} NICHT ERREICHBAR"

GUI_SAVE_ERROR = "PDF-Speicherfehler: {error}"

# -- PDF-Bericht - Titel, Beschreibungen, Bezeichnungen -----------------

PDF_TITLE = "Bericht über Internetverbindungsunterbrechungen"
PDF_SOURCE = (
    "Quelle: https://github.com/ThePineappleExpress/"
    "InternetConnectionInterruptionMonitor"
)

PDF_CONFIDENTIALITY = (
    "VERTRAULICHKEITSHINWEIS: Dieser Bericht enthält sensible "
    "Netzwerkinformationen, darunter öffentliche und lokale "
    "IP-Adressen, ISP-Identität, geografischer Standort und "
    "Systemmetadaten. Er ist ausschließlich für den Empfänger bestimmt "
    "und dient zur Verwendung im Zusammenhang mit "
    "Servicequalitätsbeschwerden oder rechtlichen Verfahren. "
    "Unbefugte Verbreitung, Vervielfältigung oder Veröffentlichung "
    "dieses Berichts oder seines Inhalts ist untersagt."
)

PDF_DESC_PARA1 = (
    "  Dieser Bericht dokumentiert Internetdienstunterbrechungen, die "
    "von einem automatisierten, unbeaufsichtigten Überwachungssystem "
    "erfasst wurden. Das System prüft die Konnektivität fortlaufend "
    "durch TCP-Handshake-Versuche zu drei unabhängigen, weltweit "
    "verteilten DNS-Servern (Cloudflare 1.1.1.1, Google 8.8.8.8, "
    "Quad9 9.9.9.9) und verifiziert die DNS-Auflösung über direkte "
    "UDP-Anfragen unter Umgehung jeglichen lokalen Cachings. Eine "
    "Unterbrechung wird nur dann erfasst, wenn ALLE drei Ziele "
    "gleichzeitig nicht erreichbar sind, wodurch Fehlalarme "
    "ausgeschlossen werden."
)

PDF_DESC_PARA2 = (
    "  Alle Zeitstempel werden maschinell aus der Systemuhr zum "
    "Zeitpunkt jedes Ereignisses generiert. Messdaten werden in "
    "Echtzeit in eine nur-anhängende JSONL-Logdatei geschrieben, "
    "was Absturzsicherheit gewährleistet und eine unabhängige, "
    "maschinenlesbare Beweisspur ermöglicht. Der Bericht enthält "
    "einen kryptografischen SHA-256-Hash seiner zugrunde liegenden "
    "Daten, der eine unabhängige Überprüfung der Berichtsintegrität "
    "ermöglicht. Keine manuelle Eingabe oder subjektive Bewertung "
    "ist an irgendeiner Messung beteiligt."
)

# Abschnittsüberschriften
PDF_SECTION_SUMMARY = "Zusammenfassung"
PDF_SECTION_CUSTOMER = "Kundeninformationen"
PDF_SECTION_METADATA = "Verbindungsmetadaten"
PDF_SECTION_LATENCY = "Latenzstatistik (TCP-Handshake)"
PDF_SECTION_DNS = "DNS-Auflösungsstatistik"
PDF_SECTION_SNMP = "Router-Diagnose (SNMP)"
PDF_SECTION_EVENTS = "Verbindungsereignisse"

# Zusammenfassungsbox - Bezeichnungen
PDF_LABEL_STARTED = "Überwachung gestartet:"
PDF_LABEL_ENDED = "Überwachung beendet:"
PDF_LABEL_TOTAL_TIME = "Gesamte Überwachungszeit:"
PDF_LABEL_TOTAL_DOWNTIME = "Gesamte Ausfallzeit:"
PDF_LABEL_UPTIME = "Verfügbarkeit:"
PDF_LABEL_NUM_OUTAGES = "Anzahl der Ausfälle:"

# Kundeninformationsbox - Bezeichnungen
PDF_LABEL_NAME = "Name:"
PDF_LABEL_ADDRESS = "Adresse:"
PDF_LABEL_ZIP_CITY = "PLZ/Ort:"
PDF_LABEL_PHONE = "Telefonnummer:"
PDF_LABEL_CUSTOMER_NR = "Kundennr.:"
PDF_LABEL_CONTRACT_NR = "Vertragsnr.:"

# Metadatenbox - Bezeichnungen
PDF_LABEL_PUBLIC_IP = "Öffentliche IP:"
PDF_LABEL_ISP = "ISP:"
PDF_LABEL_LOCATION = "Standort:"
PDF_LABEL_LOCAL_IP = "Lokale IP:"
PDF_LABEL_HOSTNAME = "Hostname:"
PDF_LABEL_OS = "Betriebssystem:"
PDF_LABEL_TARGETS = "Ziele:"
PDF_LABEL_DNS_DOMAIN = "DNS-Testdomäne:"
PDF_LABEL_CHECK_INTERVAL = "Prüfintervall:"

# Latenzbox - Bezeichnungen
PDF_LABEL_SAMPLES = "Messungen:"
PDF_LABEL_AVERAGE = "Durchschnitt:"
PDF_LABEL_MIN_MAX = "Min / Max:"
PDF_LABEL_P50_P95 = "P50 / P95:"
PDF_NO_LATENCY = "Keine Latenzdaten erfasst."

# DNS-Box - Bezeichnungen
PDF_LABEL_TEST_DOMAIN = "Testdomäne:"
PDF_LABEL_LOOKUPS = "Erfolgreiche Abfragen:"
PDF_LABEL_DNS_LATENCY = "Ø DNS-Latenz:"
PDF_LABEL_DNS_FAILURES = "DNS-Fehler (TCP OK):"

# SNMP-Box - Bezeichnungen
PDF_LABEL_ROUTER = "Router:"
PDF_LABEL_AGENT_REACHABLE = "Agent erreichbar:"
PDF_LABEL_SYS_UPTIME = "Systemlaufzeit:"
PDF_LABEL_WAN_IFACE = "WAN-Schnittstelle:"
PDF_LABEL_IFACE_STATUS = "Schnittstellenstatus:"
PDF_LABEL_TRAFFIC_IN = "Datenverkehr ein:"
PDF_LABEL_TRAFFIC_OUT = "Datenverkehr aus:"
PDF_LABEL_ERRORS_INOUT = "Fehler ein/aus:"
PDF_LABEL_DISCARDS_INOUT = "Verwürfe ein/aus:"

# SNMP ifOperStatus - Anzeigenamen
SNMP_OPER_STATUS = {
    1: "aktiv", 2: "inaktiv", 3: "Test", 4: "unbekannt",
    5: "ruhend", 6: "nicht vorhanden", 7: "untere Schicht inaktiv",
}

# Ereignistabelle
PDF_NO_OUTAGES = (
    "Keine Ausfälle aufgezeichnet - die Verbindung war "
    "während des gesamten Zeitraums stabil."
)
PDF_TBL_HEADERS = ["#", "Ereignis", "Zeit", "Dauer",
                   "DNS", "Ursache", "IP", "ISP", "Standort"]

PDF_EVENT_DOWN = "AUSFALL"
PDF_EVENT_UP = "WIEDER DA"
PDF_DNS_OK = "OK"
PDF_DNS_FAIL = "FEHLER"
PDF_CAUSE_ISP = "ISP"
PDF_CAUSE_ROUTER = "Router"
PDF_CAUSE_UNKNOWN = "-"

# Gemeinsame Kurztexte
PDF_YES = "Ja"
PDF_NO = "Nein"
PDF_NA = "k. A."

# Fußzeile
PDF_FOOTER = (
    "Bericht erstellt am {date}  |  "
    "Ziele: {targets}  |  "
    "Intervall: {interval}s"
)
PDF_HASH_LABEL = "SHA-256: {hash}"

# Konsolenausgabe nach PDF-Speicherung
PDF_SAVE_SEPARATOR = "-" * 60
PDF_SAVE_MSG = "  PDF-Bericht gespeichert -> {filename}"
PDF_SAVE_HASH = "  SHA-256: {hash}"

# -- Netzwerk - TLS-Pinning-Meldungen -----------------------------------

NET_TLS_PIN_LEARNED = "  TLS-Pin   : gelernt ({hash}...)"
NET_TLS_PIN_MISMATCH = (
    "Öffentlicher Schlüssel des ipinfo.io-Zertifikats hat sich geändert! "
    "Erwartet: {expected}, erhalten: {actual}. "
    "Falls erwartet (Schlüsselrotation), "
    "'{pin_file}' löschen zum Neulernen."
)
NET_USER_AGENT = "InternetMonitor/1.0"
