# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Configuration constants for the Internet Connection Interruption Monitor."""

CHECK_INTERVAL = 5              # seconds between connectivity checks
PING_TARGETS = [                # multiple targets for robust detection
    ("1.1.1.1", 53),            # Cloudflare DNS
    ("8.8.8.8", 53),            # Google DNS
    ("9.9.9.9", 53),            # Quad9 DNS
]
PING_TIMEOUT = 3                # seconds
DNS_TEST_DOMAIN = "google.com"
PDF_FILENAME = "internet_report.pdf"
LOG_FILENAME = "connection_log.jsonl"
LOG_CHECK_EVERY = 12            # log a "check" entry every N checks (60s at 5s interval)

# --- Gateway / Router diagnostics -------------------------------------------
GATEWAY_CHECK_ENABLED = True    # check gateway reachability on each cycle
GATEWAY_IP = ""                 # auto-detect if empty; set manually e.g. "192.168.178.1"
GATEWAY_TIMEOUT = 2             # seconds

# --- SNMP router monitoring (optional) --------------------------------------
SNMP_ENABLED = False            # set True to poll router via SNMP
SNMP_HOST = "192.168.178.1"     # router IP (FRITZ!Box default)
SNMP_PORT = 161                 # standard SNMP port
# SNMPv2c community string: loaded from SNMP_COMMUNITY env var, default "public".
# NOTE: SNMPv2c transmits this in cleartext on the wire - this is a protocol
# limitation. Consider SNMPv3 for encrypted authentication if available.
import os as _os
SNMP_COMMUNITY = _os.environ.get("SNMP_COMMUNITY", "public")
SNMP_TIMEOUT = 2                # seconds
SNMP_INTERFACE_INDEX = 1        # ifIndex of the WAN interface to monitor

# --- PDF report formatting --------------------------------------------------
PDF_FONT_FAMILY = "Times"
PDF_FONT_MONO = "Courier"
PDF_PAGE_MARGIN = 25            # bottom margin for auto page break
PDF_FOOTER_OFFSET = -18         # y position for footer

# Font tuples: (family, style, size)
PDF_FONT_TITLE = (PDF_FONT_FAMILY, "B", 22)
PDF_FONT_SECTION = (PDF_FONT_FAMILY, "B", 10)
PDF_FONT_BODY = (PDF_FONT_FAMILY, "",  8)
PDF_FONT_BODY_BOLD = (PDF_FONT_FAMILY, "B", 8)
PDF_FONT_BODY_ITALIC = (PDF_FONT_FAMILY, "I", 8)
PDF_FONT_TABLE = (PDF_FONT_FAMILY, "",  7)
PDF_FONT_TABLE_HDR = (PDF_FONT_FAMILY, "B", 7)
PDF_FONT_SOURCE = (PDF_FONT_FAMILY, "I", 7)
PDF_FONT_FOOTER = (PDF_FONT_FAMILY, "I", 8)
PDF_FONT_HASH = (PDF_FONT_MONO, "", 7)

# RGB color tuples
PDF_COLOR_TEXT = (30, 30, 30)
PDF_COLOR_TEXT_DESC = (60, 60, 60)
PDF_COLOR_TEXT_SOURCE = (100, 100, 100)
PDF_COLOR_TEXT_FOOTER = (140, 140, 140)
PDF_COLOR_TEXT_HASH = (120, 120, 120)
PDF_COLOR_TEXT_OK = (60, 140, 60)
PDF_COLOR_TEXT_WHITE = (255, 255, 255)

PDF_COLOR_BOX_FILL = (240, 240, 245)
PDF_COLOR_BOX_BORDER = (180, 180, 190)
PDF_COLOR_TBL_HDR = (50, 50, 70)
PDF_COLOR_TBL_ALT = (245, 245, 250)
PDF_COLOR_TBL_WHITE = (255, 255, 255)

# Box layout
PDF_BOX_X = 15
PDF_BOX_W = 180
PDF_SUMMARY_H = 42

# Event table layout
PDF_TBL_COL_W_NUM = 7
PDF_TBL_COL_W_EVENT = 18
PDF_TBL_COL_W_TIME = 18
PDF_TBL_COL_W_DURATION = 18
PDF_TBL_COL_W_DNS = 18
PDF_TBL_COL_W_CAUSE = 10
PDF_TBL_COL_W_IP = 22
PDF_TBL_COL_W_ISP = 38
PDF_TBL_COL_W_LOCATION = 38
PDF_TBL_HDR_H = 6    # header row height
PDF_TBL_ROW_H = 6    # data row height
