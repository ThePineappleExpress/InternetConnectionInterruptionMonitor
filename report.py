# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""PDF report generation and SHA-256 integrity hashing."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from fpdf import FPDF

from config import (
    CHECK_INTERVAL, DNS_TEST_DOMAIN, PDF_BOX_W, PDF_BOX_X, PDF_COLOR_BOX_BORDER,
    PDF_COLOR_BOX_FILL, PDF_COLOR_TBL_ALT, PDF_COLOR_TBL_HDR, PDF_COLOR_TBL_WHITE,
    PDF_COLOR_TEXT, PDF_COLOR_TEXT_DESC, PDF_COLOR_TEXT_FOOTER, PDF_COLOR_TEXT_HASH,
    PDF_COLOR_TEXT_OK, PDF_COLOR_TEXT_SOURCE, PDF_COLOR_TEXT_WHITE, PDF_FILENAME,
    PDF_FONT_BODY, PDF_FONT_BODY_BOLD, PDF_FONT_BODY_ITALIC, PDF_FONT_FOOTER,
    PDF_FONT_HASH, PDF_FONT_SECTION, PDF_FONT_SOURCE, PDF_FONT_TABLE,
    PDF_FONT_TABLE_HDR, PDF_FONT_TITLE, PDF_FOOTER_OFFSET, PDF_PAGE_MARGIN,
    PDF_TBL_COL_W_CAUSE, PDF_TBL_COL_W_DNS, PDF_TBL_COL_W_DURATION,
    PDF_TBL_COL_W_EVENT, PDF_TBL_COL_W_IP, PDF_TBL_COL_W_ISP, PDF_TBL_COL_W_LOCATION,
    PDF_TBL_COL_W_NUM, PDF_TBL_COL_W_TIME, PDF_TBL_HDR_H, PDF_TBL_ROW_H,
    PING_TARGETS, SNMP_HOST, SNMP_INTERFACE_INDEX,
)
from text import (
    PDF_CAUSE_ISP,
    PDF_CAUSE_ROUTER,
    PDF_CAUSE_UNKNOWN,
    PDF_CONFIDENTIALITY,
    PDF_DESC_PARA1,
    PDF_DESC_PARA2,
    PDF_DNS_FAIL,
    PDF_DNS_OK,
    PDF_EVENT_DOWN,
    PDF_EVENT_UP,
    PDF_FOOTER,
    PDF_HASH_LABEL,
    PDF_LABEL_ADDRESS,
    PDF_LABEL_ZIP_CITY,
    PDF_LABEL_AGENT_REACHABLE,
    PDF_LABEL_AVERAGE,
    PDF_LABEL_CHECK_INTERVAL,
    PDF_LABEL_CONTRACT_NR,
    PDF_LABEL_CUSTOMER_NR,
    PDF_LABEL_DISCARDS_INOUT,
    PDF_LABEL_DNS_DOMAIN,
    PDF_LABEL_DNS_FAILURES,
    PDF_LABEL_DNS_LATENCY,
    PDF_LABEL_ENDED,
    PDF_LABEL_ERRORS_INOUT,
    PDF_LABEL_HOSTNAME,
    PDF_LABEL_IFACE_STATUS,
    PDF_LABEL_ISP,
    PDF_LABEL_LOCAL_IP,
    PDF_LABEL_LOCATION,
    PDF_LABEL_LOOKUPS,
    PDF_LABEL_MIN_MAX,
    PDF_LABEL_NAME,
    PDF_LABEL_NUM_OUTAGES,
    PDF_LABEL_OS,
    PDF_LABEL_P50_P95,
    PDF_LABEL_PHONE,
    PDF_LABEL_PUBLIC_IP,
    PDF_LABEL_ROUTER,
    PDF_LABEL_SAMPLES,
    PDF_LABEL_STARTED,
    PDF_LABEL_SYS_UPTIME,
    PDF_LABEL_TARGETS,
    PDF_LABEL_TEST_DOMAIN,
    PDF_LABEL_TOTAL_DOWNTIME,
    PDF_LABEL_TOTAL_TIME,
    PDF_LABEL_TRAFFIC_IN,
    PDF_LABEL_TRAFFIC_OUT,
    PDF_LABEL_UPTIME,
    PDF_LABEL_WAN_IFACE,
    PDF_NA,
    PDF_NO,
    PDF_NO_LATENCY,
    PDF_NO_OUTAGES,
    PDF_SAVE_HASH,
    PDF_SAVE_MSG,
    PDF_SAVE_SEPARATOR,
    PDF_SECTION_CUSTOMER,
    PDF_SECTION_DNS,
    PDF_SECTION_EVENTS,
    PDF_SECTION_LATENCY,
    PDF_SECTION_METADATA,
    PDF_SECTION_SNMP,
    PDF_SECTION_SUMMARY,
    PDF_SOURCE,
    PDF_TBL_HEADERS,
    PDF_TITLE,
    PDF_YES,
    SNMP_OPER_STATUS,
)
from utils import format_duration, pdf_safe, snmp_safe
from user import (
    ADDRESS,
    CONTRACT_NR,
    CUSTOMER_NR,
    NAME,
    PHONE_NUMBER,
    ZIP_CITY,
)

if TYPE_CHECKING:
    from monitor import InternetMonitor


def compute_report_hash(monitor: InternetMonitor, end_time: datetime,
                        events: list[dict], total_downtime) -> str:
    """Compute SHA-256 hash of the report data for integrity verification."""
    hash_data = json.dumps({
        "start": monitor.start_time.isoformat(),
        "end": end_time.isoformat(),
        "downtime_s": total_downtime.total_seconds(),
        "events": [
            {
                "disconnect": e["disconnect"].isoformat(),
                "reconnect": e["reconnect"].isoformat() if e["reconnect"] else None,
                "duration_s": e["duration"].total_seconds(),
            }
            for e in events
        ],
        "metadata": monitor.metadata,
        "latency_count": len(monitor.latency_samples),
        "dns_failure_count": len(monitor.dns_failures),
    }, sort_keys=True)
    return hashlib.sha256(hash_data.encode()).hexdigest()


def generate_pdf(monitor: InternetMonitor, end_time: datetime | None = None,
                 events: list[dict] | None = None,
                 total_downtime=None, tag: str = "final") -> str:
    """Build and write the PDF report, returning the output filename."""
    end_time = end_time or monitor.end_time
    events = events if events is not None else monitor.events
    total_downtime = total_downtime if total_downtime is not None else monitor.total_downtime

    monitoring_duration = end_time - monitor.start_time
    uptime = monitoring_duration - total_downtime
    uptime_pct = (
        (uptime.total_seconds() / monitoring_duration.total_seconds()) * 100
        if monitoring_duration.total_seconds() > 0
        else 100
    )

    sha256 = compute_report_hash(monitor, end_time, events, total_downtime)

    local_start = monitor.start_time.astimezone()
    local_end = end_time.astimezone()

    # -- Subclass for automatic page footer ----------------------------
    targets_str = ", ".join(f"{h}:{p}" for h, p in PING_TARGETS)
    local_now = datetime.now(timezone.utc).astimezone()

    class _ReportPDF(FPDF):
        def footer(self):
            self.set_y(PDF_FOOTER_OFFSET)
            self.set_font(*PDF_FONT_FOOTER)
            self.set_text_color(*PDF_COLOR_TEXT_FOOTER)
            self.cell(
                0, 6,
                PDF_FOOTER.format(
                    date=f"{local_now:%Y-%m-%d %H:%M:%S}",
                    targets=targets_str,
                    interval=CHECK_INTERVAL),
                align="C", new_x="LMARGIN", new_y="NEXT",
            )
            self.set_font(*PDF_FONT_HASH)
            self.set_text_color(*PDF_COLOR_TEXT_HASH)
            self.cell(0, 5, PDF_HASH_LABEL.format(hash=sha256), align="C",
                      new_x="LMARGIN", new_y="NEXT")

    pdf = _ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=PDF_PAGE_MARGIN)
    pdf.add_page()

    # -- helpers for repetitive box drawing -------------------------------
    def _set_box_style():
        pdf.set_fill_color(*PDF_COLOR_BOX_FILL)
        pdf.set_draw_color(*PDF_COLOR_BOX_BORDER)

    def _draw_kv_box(items, label_w=42, x=None, w=None, restore_y=True):
        """Draw a bordered box with label: value rows.

        *x* / *w* override the default page-wide position and width.
        When *restore_y* is False the cursor is NOT moved past the box
        (useful for drawing a second box on the same row).
        """
        _set_box_style()
        bx = x if x is not None else PDF_BOX_X
        bw = w if w is not None else PDF_BOX_W
        by = pdf.get_y()
        bh = 6 + len(items) * 5
        pdf.rect(bx, by, bw, bh, style="DF")
        pdf.set_xy(bx + 5, by + 3)
        pdf.set_font(*PDF_FONT_BODY)
        for lbl, val in items:
            pdf.set_x(bx + 8)
            pdf.set_font(*PDF_FONT_BODY_BOLD)
            pdf.cell(label_w, 5, lbl)
            pdf.set_font(*PDF_FONT_BODY)
            pdf.cell(0, 5, pdf_safe(val), new_x="LMARGIN", new_y="NEXT")
        if restore_y:
            pdf.set_y(by + bh + 4)

    # -- Title ------------------------------------------------------------
    pdf.set_font(*PDF_FONT_TITLE)
    pdf.set_text_color(*PDF_COLOR_TEXT)
    pdf.cell(0, 14, PDF_TITLE,
             new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(1)
    pdf.set_font(*PDF_FONT_SOURCE)
    pdf.set_text_color(*PDF_COLOR_TEXT_SOURCE)
    pdf.cell(
        0, 4, PDF_SOURCE,
        new_x="LMARGIN", new_y="NEXT", align="C",
    )
    pdf.ln(2)

    # -- Description header -----------------------------------------------
    pdf.set_font(*PDF_FONT_BODY_BOLD)
    pdf.set_text_color(*PDF_COLOR_TEXT)
    pdf.multi_cell(0, 4.5, PDF_CONFIDENTIALITY, align="J")
    pdf.ln(1)
    pdf.set_font(*PDF_FONT_BODY)
    pdf.set_text_color(*PDF_COLOR_TEXT_DESC)
    pdf.multi_cell(0, 4.5, PDF_DESC_PARA1, align="J")
    pdf.ln(1)
    pdf.multi_cell(0, 4.5, PDF_DESC_PARA2, align="J")
    pdf.ln(3)

    # -- Summary + Customer boxes (side by side) -------------------------
    half_w = (PDF_BOX_W - 4) // 2        # 4 px gap between boxes
    left_x = PDF_BOX_X
    right_x = PDF_BOX_X + half_w + 4

    summary_items = [
        (PDF_LABEL_STARTED, f"{local_start:%Y-%m-%d %H:%M:%S}"),
        (PDF_LABEL_ENDED, f"{local_end:%Y-%m-%d %H:%M:%S}"),
        (PDF_LABEL_TOTAL_TIME, format_duration(monitoring_duration)),
        (PDF_LABEL_TOTAL_DOWNTIME, format_duration(total_downtime)),
        (PDF_LABEL_UPTIME, f"{uptime_pct:.2f}%"),
        (PDF_LABEL_NUM_OUTAGES, str(len(events))),
    ]

    customer_items = [
        (PDF_LABEL_NAME, NAME),
        (PDF_LABEL_ADDRESS, ADDRESS),
        (PDF_LABEL_ZIP_CITY, ZIP_CITY),
        (PDF_LABEL_PHONE, PHONE_NUMBER),
        (PDF_LABEL_CUSTOMER_NR, CUSTOMER_NR),
        (PDF_LABEL_CONTRACT_NR, CONTRACT_NR),
    ]

    # Section headers
    row_y = pdf.get_y()
    pdf.set_font(*PDF_FONT_SECTION)
    pdf.set_xy(left_x, row_y)
    pdf.cell(half_w, 7, PDF_SECTION_SUMMARY)
    pdf.set_xy(right_x, row_y)
    pdf.cell(half_w, 7, PDF_SECTION_CUSTOMER)
    pdf.set_y(row_y + 7)

    # Draw left box (summary), keep cursor at its top-left y
    box_y = pdf.get_y()
    _draw_kv_box(summary_items, label_w=42, x=left_x, w=half_w,
                 restore_y=False)

    # Draw right box (customer) at the same y
    pdf.set_y(box_y)
    _draw_kv_box(customer_items, label_w=32, x=right_x, w=half_w,
                 restore_y=False)

    # Advance past the taller of the two boxes
    left_h = 6 + len(summary_items) * 5
    right_h = 6 + len(customer_items) * 5
    pdf.set_y(box_y + max(left_h, right_h) + 4)

    # -- Metadata box -----------------------------------------------------
    meta = monitor.metadata
    meta_items = [
        (PDF_LABEL_PUBLIC_IP, meta["public_ip"]),
        (PDF_LABEL_ISP,       meta["isp"]),
        (PDF_LABEL_LOCATION,  meta["location"] or PDF_NA),
        (PDF_LABEL_LOCAL_IP,  meta["local_ip"]),
        (PDF_LABEL_HOSTNAME,  meta["hostname"]),
        (PDF_LABEL_OS,        meta["os"]),
        (PDF_LABEL_TARGETS,   ", ".join(meta["targets"])),
        (PDF_LABEL_DNS_DOMAIN, meta["dns_test_domain"]),
        (PDF_LABEL_CHECK_INTERVAL,
         f"{meta['check_interval']}s  (timeout {meta['ping_timeout']}s)"),
    ]

    pdf.set_font(*PDF_FONT_SECTION)
    pdf.cell(0, 7, PDF_SECTION_METADATA, new_x="LMARGIN", new_y="NEXT")
    _draw_kv_box(meta_items)

    # -- Latency statistics -----------------------------------------------
    pdf.set_font(*PDF_FONT_SECTION)
    pdf.set_text_color(*PDF_COLOR_TEXT)
    pdf.cell(0, 7, PDF_SECTION_LATENCY, new_x="LMARGIN", new_y="NEXT")

    if monitor.latency_samples:
        sorted_lat = sorted(list(monitor.latency_samples))
        avg_lat = sum(sorted_lat) / len(sorted_lat)
        min_lat = sorted_lat[0]
        max_lat = sorted_lat[-1]
        p50 = sorted_lat[len(sorted_lat) // 2]
        p95_idx = min(int(len(sorted_lat) * 0.95), len(sorted_lat) - 1)
        p95 = sorted_lat[p95_idx]

        _draw_kv_box([
            (PDF_LABEL_SAMPLES, str(len(sorted_lat))),
            (PDF_LABEL_AVERAGE, f"{avg_lat:.1f} ms"),
            (PDF_LABEL_MIN_MAX, f"{min_lat:.1f} ms / {max_lat:.1f} ms"),
            (PDF_LABEL_P50_P95, f"{p50:.1f} ms / {p95:.1f} ms"),
        ], label_w=30)
    else:
        pdf.set_font(*PDF_FONT_BODY_ITALIC)
        pdf.cell(0, 8, PDF_NO_LATENCY, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # -- DNS statistics ---------------------------------------------------
    pdf.set_font(*PDF_FONT_SECTION)
    pdf.set_text_color(*PDF_COLOR_TEXT)
    pdf.cell(0, 7, PDF_SECTION_DNS, new_x="LMARGIN", new_y="NEXT")

    dns_items = [
        (PDF_LABEL_TEST_DOMAIN, DNS_TEST_DOMAIN),
    ]
    dns_sample_list = list(monitor.dns_samples)
    if dns_sample_list:
        dns_avg = sum(dns_sample_list) / len(dns_sample_list)
        dns_items.append((PDF_LABEL_LOOKUPS, str(len(dns_sample_list))))
        dns_items.append((PDF_LABEL_DNS_LATENCY, f"{dns_avg:.1f} ms"))
    dns_items.append((PDF_LABEL_DNS_FAILURES, str(len(monitor.dns_failures))))
    _draw_kv_box(dns_items, label_w=52)

    # -- SNMP Router Diagnostics (when enabled) ---------------------------
    if getattr(monitor, 'snmp_enabled', False) and monitor.last_snmp_result:
        snmp = monitor.last_snmp_result

        pdf.set_font(*PDF_FONT_SECTION)
        pdf.set_text_color(*PDF_COLOR_TEXT)
        pdf.cell(0, 7, PDF_SECTION_SNMP, new_x="LMARGIN", new_y="NEXT")

        # Format sysUpTime (hundredths of a second -> human-readable)
        raw_uptime = snmp.get("sysUpTime")
        if isinstance(raw_uptime, int):
            up_secs = raw_uptime // 100
            days, rem = divmod(up_secs, 86400)
            hours, rem = divmod(rem, 3600)
            minutes, secs = divmod(rem, 60)
            uptime_str = f"{days}d {hours}h {minutes}m {secs}s"
        else:
            uptime_str = PDF_NA

        # Format ifOperStatus
        raw_status = snmp.get("ifOperStatus")
        if isinstance(raw_status, int):
            status_str = SNMP_OPER_STATUS.get(
                raw_status, f"unknown ({raw_status})")
        else:
            status_str = PDF_NA

        # Format byte counters
        def _fmt_bytes(val: int | str | None) -> str:
            if not isinstance(val, int):
                return PDF_NA
            if val >= 1_073_741_824:
                return f"{val / 1_073_741_824:.2f} GB ({val:,} bytes)"
            if val >= 1_048_576:
                return f"{val / 1_048_576:.2f} MB ({val:,} bytes)"
            if val >= 1_024:
                return f"{val / 1_024:.2f} KB ({val:,} bytes)"
            return f"{val:,} bytes"

        snmp_items = [
            (PDF_LABEL_ROUTER,
             f"{SNMP_HOST} (ifIndex {SNMP_INTERFACE_INDEX})"),
            (PDF_LABEL_AGENT_REACHABLE,
             PDF_YES if snmp.get("reachable") else PDF_NO),
            (PDF_LABEL_SYS_UPTIME,    uptime_str),
            (PDF_LABEL_WAN_IFACE,     snmp_safe(snmp.get("ifDescr"))),
            (PDF_LABEL_IFACE_STATUS,  status_str),
            (PDF_LABEL_TRAFFIC_IN,    _fmt_bytes(snmp.get("ifInOctets"))),
            (PDF_LABEL_TRAFFIC_OUT,   _fmt_bytes(snmp.get("ifOutOctets"))),
            (PDF_LABEL_ERRORS_INOUT,
             f"{snmp_safe(snmp.get('ifInErrors'))} / "
             f"{snmp_safe(snmp.get('ifOutErrors'))}"),
            (PDF_LABEL_DISCARDS_INOUT,
             f"{snmp_safe(snmp.get('ifInDiscards'))} / "
             f"{snmp_safe(snmp.get('ifOutDiscards'))}"),
        ]
        _draw_kv_box(snmp_items, label_w=42)

    # -- Page 2: Event log ------------------------------------------------
    pdf.add_page()

    # -- Outage table -----------------------------------------------------
    pdf.set_font(*PDF_FONT_SECTION)
    pdf.set_text_color(*PDF_COLOR_TEXT)
    pdf.cell(0, 10, PDF_SECTION_EVENTS, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    if not events:
        pdf.set_font(*PDF_FONT_BODY_ITALIC)
        pdf.set_text_color(*PDF_COLOR_TEXT_OK)
        pdf.cell(0, 10, PDF_NO_OUTAGES,
                 new_x="LMARGIN", new_y="NEXT")
    else:
        col_widths = [
            PDF_TBL_COL_W_NUM, PDF_TBL_COL_W_EVENT, PDF_TBL_COL_W_TIME,
            PDF_TBL_COL_W_DURATION, PDF_TBL_COL_W_DNS, PDF_TBL_COL_W_CAUSE,
            PDF_TBL_COL_W_IP, PDF_TBL_COL_W_ISP, PDF_TBL_COL_W_LOCATION,
        ]

        pdf.set_font(*PDF_FONT_TABLE_HDR)
        pdf.set_fill_color(*PDF_COLOR_TBL_HDR)
        pdf.set_text_color(*PDF_COLOR_TEXT_WHITE)
        for w, h in zip(col_widths, PDF_TBL_HEADERS):
            pdf.cell(w, PDF_TBL_HDR_H, h, border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_font(*PDF_FONT_TABLE)
        pdf.set_text_color(*PDF_COLOR_TEXT)
        row_num = 0
        for idx, event in enumerate(events, start=1):
            # -- Disconnect row -------------------------------------------
            row_num += 1
            fill = row_num % 2 == 0
            pdf.set_fill_color(
                *(PDF_COLOR_TBL_ALT if fill else PDF_COLOR_TBL_WHITE))

            disc_time = event["disconnect"].astimezone().strftime("%H:%M:%S")
            disc_dns = event.get("disconnect_dns_result", {})
            disc_dns_str = PDF_DNS_OK if disc_dns.get("resolved") else PDF_DNS_FAIL
            duration_str = format_duration(event["duration"])

            gw_up = event.get("gateway_reachable_at_disconnect")
            if gw_up is True:
                cause = PDF_CAUSE_ISP
            elif gw_up is False:
                cause = PDF_CAUSE_ROUTER
            else:
                cause = PDF_CAUSE_UNKNOWN

            row = [str(idx), PDF_EVENT_DOWN, disc_time, duration_str,
                   disc_dns_str, cause, "", "", ""]
            for w, val in zip(col_widths, row):
                pdf.cell(w, PDF_TBL_ROW_H, val, border=1, fill=fill, align="C")
            pdf.ln()

            # -- Reconnect row (if recovered) -----------------------------
            if event["reconnect"]:
                row_num += 1
                fill = row_num % 2 == 0
                pdf.set_fill_color(
                    *(PDF_COLOR_TBL_ALT if fill else PDF_COLOR_TBL_WHITE))

                recon_time = event["reconnect"].astimezone().strftime(
                    "%H:%M:%S")
                recon_dns = event.get("reconnect_dns_result", {})
                recon_dns_str = (PDF_DNS_OK if recon_dns.get("resolved")
                                 else PDF_DNS_FAIL) if recon_dns else PDF_CAUSE_UNKNOWN

                # Duration until next disconnect (or end of monitoring)
                next_disc = None
                if idx < len(events):
                    next_disc = events[idx]["disconnect"]
                if next_disc:
                    up_dur = format_duration(next_disc - event["reconnect"])
                else:
                    up_end = end_time or event["reconnect"]
                    up_dur = format_duration(up_end - event["reconnect"])

                # Show IP/ISP/Location on reconnect
                ip_str = pdf_safe(
                    event.get("public_ip_at_reconnect") or "")
                isp_str = pdf_safe(
                    event.get("isp_at_reconnect") or "")
                loc_str = pdf_safe(
                    event.get("location_at_reconnect") or "")

                row = [str(idx), PDF_EVENT_UP, recon_time, up_dur,
                       recon_dns_str, "", ip_str, isp_str, loc_str]
                for w, val in zip(col_widths, row):
                    pdf.cell(w, PDF_TBL_ROW_H, val, border=1, fill=fill, align="C")
                pdf.ln()

    # -- Write file -------------------------------------------------------
    date_str = local_now.strftime("%Y%m%d")
    filename = PDF_FILENAME.format(date=date_str)
    pdf.output(filename)
    os.chmod(filename, 0o600)
    print(f"\n{PDF_SAVE_SEPARATOR}")
    print(PDF_SAVE_MSG.format(filename=filename))
    print(PDF_SAVE_HASH.format(hash=sha256))
    print(PDF_SAVE_SEPARATOR)
    return filename
