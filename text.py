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

# ── Monitor - console output ────────────────────────────────────────────

MONITOR_INIT_PUBLIC_IP = "  Public IP : {ip}"
MONITOR_INIT_ISP = "  ISP       : {isp}"
MONITOR_INIT_LOCAL_IP = "  Local IP  : {ip}"
MONITOR_INIT_GATEWAY = "  Gateway   : {gw}"
MONITOR_INIT_TARGETS = "  Targets   : {targets}"
MONITOR_INIT_DNS = "  DNS test  : {domain}"
MONITOR_INIT_SNMP_ENABLED = "  SNMP      : enabled"
MONITOR_INIT_LOG = "  Log file  : {filename}"

MONITOR_SNMP_AGENT_DISABLED = "  SNMP      : agent not responding, disabling"

MONITOR_LOG_WARNING = "  Warning: could not read existing log: {error}"
MONITOR_LOG_RESUMED = "  Resumed from today's log:"
MONITOR_LOG_RESUMED_DETAIL = (
    "    Events: {events}  "
    "Latency samples: {latency}  "
    "DNS samples: {dns}  "
    "DNS failures: {failures}  "
    "Downtime: {downtime}"
)

MONITOR_DISCONNECTED = (
    "[{ts}]  \u2717  Internet DISCONNECTED  "
    "(all {count} targets unreachable, cause: {cause})"
)
MONITOR_RECONNECTED = (
    "[{ts}]  \u2713  Internet RECONNECTED  "
    "(outage lasted {duration}){changes}"
)

MONITOR_CAUSE_ISP = "ISP"
MONITOR_CAUSE_ROUTER = "Router/LAN"
MONITOR_CAUSE_UNKNOWN = "Unknown"
MONITOR_GATEWAY_NOT_DETECTED = "not detected"

MONITOR_IP_CHANGED = "IP -> {ip}"
MONITOR_ISP_CHANGED = "ISP -> {isp}"
MONITOR_LOCATION_CHANGED = "Location -> {location}"

MONITOR_DAILY_SAVED = "[{ts}]Daily report saved : {path}"
MONITOR_DAILY_FAILED = "[{ts}]Report save failed: {error}"

MONITOR_STARTING = (
    "Starting internet monitor at {ts}\n"
    "Close the window or press Ctrl+C to stop.\n"
)
MONITOR_STOP_SIGNAL = "\n\nReceived stop signal - finishing up ..."

# ── GUI - window and widget text ────────────────────────────────────────

GUI_WINDOW_TITLE = "Internet Connection Monitor"

GUI_STATUS_CONNECTED = "\u25cf  CONNECTED"
GUI_STATUS_DISCONNECTED = "\u25cf  DISCONNECTED"
GUI_STATUS_CONNECTED_INIT = "\u25cf CONNECTED"

GUI_LABEL_CONNECTED_TIME = "Connected time:"
GUI_LABEL_DISCONNECTED_TIME = "Disconnected time:"
GUI_LABEL_CONNECTIONS = "Connections (#):"
GUI_LABEL_DISCONNECTIONS = "Disconnections (#):"
GUI_LABEL_AVG_LATENCY = "Avg latency:"
GUI_LABEL_DNS_STATUS = "DNS status:"
GUI_LABEL_GATEWAY = "Gateway:"

GUI_DEFAULT_DURATION = "0s"
GUI_DEFAULT_COUNT = "0"
GUI_DEFAULT_DASH = "-"

GUI_BTN_SAVE = "Save Report Now"
GUI_BTN_SAVING = "Saving..."
GUI_BTN_SAVED = "Saved!"
GUI_BTN_ERROR = "Error!"

GUI_ELAPSED = "Elapsed: {elapsed}"
GUI_LATENCY_FMT = "{latency:.0f} ms"
GUI_DNS_OK = "OK ({latency:.0f}ms)"
GUI_DNS_FAILED = "FAILED"
GUI_GATEWAY_OK = "{ip} OK{latency}"
GUI_GATEWAY_DOWN = "{ip} DOWN"

GUI_SAVE_ERROR = "PDF save error: {error}"

# ── PDF report - titles, descriptions, labels ───────────────────────────

PDF_TITLE = "Internet Connection Interruption Report"
PDF_SOURCE = (
    "Source: https://github.com/ThePineappleExpress/"
    "InternetConnectionInterruptionMonitor"
)

PDF_CONFIDENTIALITY = (
    "CONFIDENTIALITY NOTICE: This report contains sensitive network "
    "information including public and local IP addresses, ISP identity, "
    "geographic location, and system metadata. It is intended solely for "
    "the recipient and for use in connection with service quality "
    "complaints or legal proceedings. Unauthorized distribution, "
    "reproduction, or publication of this report or its contents is "
    "prohibited."
)

PDF_DESC_PARA1 = (
    "  This report documents internet service interruptions recorded by "
    "an automated, unattended monitoring system. The system continuously "
    "tests connectivity by performing TCP handshake attempts to three "
    "independent, globally distributed DNS servers (Cloudflare 1.1.1.1, "
    "Google 8.8.8.8, Quad9 9.9.9.9) and verifies DNS resolution via "
    "direct UDP queries, bypassing any local caching. A disconnection is "
    "recorded only when ALL three targets are simultaneously unreachable, "
    "eliminating the possibility of false positives."
)

PDF_DESC_PARA2 = (
    "  All timestamps are machine-generated from the system clock at the "
    "moment of each event. Measurement data is written in real time to "
    "an append-only JSONL log file, ensuring crash-safety and providing "
    "an independent, machine-readable evidence trail. The report "
    "includes a SHA-256 cryptographic hash of its underlying data, "
    "allowing independent verification of report integrity. No manual "
    "input or subjective assessment is involved in any measurement."
)

# Section headers
PDF_SECTION_SUMMARY = "Summary"
PDF_SECTION_CUSTOMER = "Customer Information"
PDF_SECTION_METADATA = "Connection Metadata"
PDF_SECTION_LATENCY = "Latency Statistics (TCP handshake)"
PDF_SECTION_DNS = "DNS Resolution Statistics"
PDF_SECTION_SNMP = "Router Diagnostics (SNMP)"
PDF_SECTION_EVENTS = "Connection Events"

# Summary box labels
PDF_LABEL_STARTED = "Monitoring started:"
PDF_LABEL_ENDED = "Monitoring ended:"
PDF_LABEL_TOTAL_TIME = "Total monitoring time:"
PDF_LABEL_TOTAL_DOWNTIME = "Total downtime:"
PDF_LABEL_UPTIME = "Uptime:"
PDF_LABEL_NUM_OUTAGES = "Number of outages:"

# Customer info box labels
PDF_LABEL_NAME = "Name:"
PDF_LABEL_ADDRESS = "Address:"
PDF_LABEL_ZIP_CITY = "ZIP/City:"
PDF_LABEL_PHONE = "Phone number:"
PDF_LABEL_CUSTOMER_NR = "Customer nr:"
PDF_LABEL_CONTRACT_NR = "Contract nr:"

# Metadata box labels
PDF_LABEL_PUBLIC_IP = "Public IP:"
PDF_LABEL_ISP = "ISP:"
PDF_LABEL_LOCATION = "Location:"
PDF_LABEL_LOCAL_IP = "Local IP:"
PDF_LABEL_HOSTNAME = "Hostname:"
PDF_LABEL_OS = "OS:"
PDF_LABEL_TARGETS = "Targets:"
PDF_LABEL_DNS_DOMAIN = "DNS test domain:"
PDF_LABEL_CHECK_INTERVAL = "Check interval:"

# Latency box labels
PDF_LABEL_SAMPLES = "Samples:"
PDF_LABEL_AVERAGE = "Average:"
PDF_LABEL_MIN_MAX = "Min / Max:"
PDF_LABEL_P50_P95 = "P50 / P95:"
PDF_NO_LATENCY = "No latency data collected."

# DNS box labels
PDF_LABEL_TEST_DOMAIN = "Test domain:"
PDF_LABEL_LOOKUPS = "Successful lookups:"
PDF_LABEL_DNS_LATENCY = "Avg DNS latency:"
PDF_LABEL_DNS_FAILURES = "DNS failures (TCP OK):"

# SNMP box labels
PDF_LABEL_ROUTER = "Router:"
PDF_LABEL_AGENT_REACHABLE = "Agent reachable:"
PDF_LABEL_SYS_UPTIME = "System uptime:"
PDF_LABEL_WAN_IFACE = "WAN interface:"
PDF_LABEL_IFACE_STATUS = "Interface status:"
PDF_LABEL_TRAFFIC_IN = "Traffic in:"
PDF_LABEL_TRAFFIC_OUT = "Traffic out:"
PDF_LABEL_ERRORS_INOUT = "Errors in/out:"
PDF_LABEL_DISCARDS_INOUT = "Discards in/out:"

# SNMP ifOperStatus display names
SNMP_OPER_STATUS = {
    1: "up", 2: "down", 3: "testing", 4: "unknown",
    5: "dormant", 6: "notPresent", 7: "lowerLayerDown",
}

# Event table
PDF_NO_OUTAGES = (
    "No outages recorded - connection was stable "
    "for the entire period."
)
PDF_TBL_HEADERS = ["#", "Event", "Time", "Duration",
                   "DNS", "Cause", "IP", "ISP", "Location"]

PDF_EVENT_DOWN = "DOWN"
PDF_EVENT_UP = "UP"
PDF_DNS_OK = "OK"
PDF_DNS_FAIL = "FAIL"
PDF_CAUSE_ISP = "ISP"
PDF_CAUSE_ROUTER = "Router"
PDF_CAUSE_UNKNOWN = "-"

# Shared short strings
PDF_YES = "Yes"
PDF_NO = "No"
PDF_NA = "N/A"

# Footer
PDF_FOOTER = (
    "Report generated on {date}  |  "
    "Targets: {targets}  |  "
    "Interval: {interval}s"
)
PDF_HASH_LABEL = "SHA-256: {hash}"

# Console output after PDF save
PDF_SAVE_SEPARATOR = "-" * 60
PDF_SAVE_MSG = "  PDF report saved -> {filename}"
PDF_SAVE_HASH = "  SHA-256: {hash}"

# ── Network - TLS pinning messages ──────────────────────────────────────

NET_TLS_PIN_LEARNED = "  TLS pin   : learned ({hash}...)"
NET_TLS_PIN_MISMATCH = (
    "ipinfo.io certificate public key changed! "
    "Expected {expected}, got {actual}. "
    "If this is expected (key rotation), "
    "delete '{pin_file}' to re-learn."
)
NET_USER_AGENT = "InternetMonitor/1.0"
