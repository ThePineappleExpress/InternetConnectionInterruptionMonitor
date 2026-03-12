# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Tkinter GUI dashboard for the Internet Connection Monitor."""

from __future__ import annotations

import tkinter as tk
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from text import (
    GUI_BTN_ERROR,
    GUI_BTN_SAVE,
    GUI_BTN_SAVED,
    GUI_BTN_SAVING,
    GUI_DEFAULT_COUNT,
    GUI_DEFAULT_DASH,
    GUI_DEFAULT_DURATION,
    GUI_DNS_FAILED,
    GUI_DNS_OK,
    GUI_ELAPSED,
    GUI_GATEWAY_DOWN,
    GUI_GATEWAY_OK,
    GUI_LABEL_AVG_LATENCY,
    GUI_LABEL_CONNECTED_TIME,
    GUI_LABEL_CONNECTIONS,
    GUI_LABEL_DISCONNECTED_TIME,
    GUI_LABEL_DISCONNECTIONS,
    GUI_LABEL_DNS_STATUS,
    GUI_LABEL_GATEWAY,
    GUI_LATENCY_FMT,
    GUI_SAVE_ERROR,
    GUI_STATUS_CONNECTED,
    GUI_STATUS_CONNECTED_INIT,
    GUI_STATUS_DISCONNECTED,
    GUI_WINDOW_TITLE,
)
from utils import format_duration

if TYPE_CHECKING:
    from monitor import InternetMonitor


class MonitorGUI:
    """Tkinter dashboard that shows live connection statistics."""

    BG        = "#1e1e2e"
    FG        = "#cdd6f4"
    GREEN     = "#a6e3a1"
    RED       = "#f38ba8"
    DIM       = "#6c7086"
    ACCENT_BG = "#313244"

    def __init__(self, monitor: InternetMonitor):
        self.monitor = monitor
        self.root = tk.Tk()
        self.root.title(GUI_WINDOW_TITLE)
        self.root.configure(bg=self.BG)
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # -- Status banner ------------------------------------------------
        self.status_var = tk.StringVar(value=GUI_STATUS_CONNECTED_INIT)
        self.status_label = tk.Label(
            self.root, textvariable=self.status_var,
            font=("Helvetica", 20, "bold"), bg=self.BG, fg=self.GREEN,
            pady=12,
        )
        self.status_label.pack(fill="x")

        # -- Stats frame --------------------------------------------------
        frame = tk.Frame(self.root, bg=self.ACCENT_BG, padx=20, pady=14)
        frame.pack(fill="x", padx=16, pady=(0, 10))

        self._labels: dict[str, tk.Label] = {}
        stats = [
            (GUI_LABEL_CONNECTED_TIME,    "connected_time",  GUI_DEFAULT_DURATION),
            (GUI_LABEL_DISCONNECTED_TIME, "disconnected_time", GUI_DEFAULT_DURATION),
            (GUI_LABEL_CONNECTIONS,       "connections",     GUI_DEFAULT_COUNT),
            (GUI_LABEL_DISCONNECTIONS,    "disconnections",  GUI_DEFAULT_COUNT),
            (GUI_LABEL_AVG_LATENCY,       "avg_latency",     GUI_DEFAULT_DASH),
            (GUI_LABEL_DNS_STATUS,        "dns_status",      GUI_DEFAULT_DASH),
            (GUI_LABEL_GATEWAY,           "gateway_status",  GUI_DEFAULT_DASH),
        ]
        for row, (title, key, default) in enumerate(stats):
            tk.Label(
                frame, text=title, font=("Helvetica", 12, "bold"),
                bg=self.ACCENT_BG, fg=self.FG, anchor="w",
            ).grid(row=row, column=0, sticky="w", pady=3)
            val_label = tk.Label(
                frame, text=default, font=("Helvetica", 12),
                bg=self.ACCENT_BG, fg=self.FG, anchor="e", width=14,
            )
            val_label.grid(row=row, column=1, sticky="e", pady=3, padx=(20, 0))
            self._labels[key] = val_label

        # -- Save button --------------------------------------------------
        self.save_btn = tk.Button(
            self.root, text=GUI_BTN_SAVE,
            font=("Helvetica", 12, "bold"),
            bg=self.ACCENT_BG, fg=self.FG,
            activebackground=self.DIM, activeforeground=self.FG,
            relief="flat", padx=16, pady=6,
            command=self._on_save,
        )
        self.save_btn.pack(pady=(0, 8))

        # -- Elapsed bar --------------------------------------------------
        self.elapsed_var = tk.StringVar(value=GUI_ELAPSED.format(elapsed="0s"))
        tk.Label(
            self.root, textvariable=self.elapsed_var,
            font=("Helvetica", 9), bg=self.BG, fg=self.DIM,
        ).pack(pady=(0, 10))

        self._schedule_refresh()

    # -- periodic refresh -------------------------------------------------
    def _schedule_refresh(self):
        self._refresh()
        self.root.after(1000, self._schedule_refresh)

    def _refresh(self):
        m = self.monitor
        now = datetime.now(timezone.utc)

        with m._lock:
            # live downtime includes any ongoing outage
            live_downtime = m.total_downtime
            if not m.is_connected and m.outage_start:
                live_downtime += now - m.outage_start

            elapsed = now - m.start_time
            connected_time = elapsed - live_downtime
            if connected_time < timedelta():
                connected_time = timedelta()

            # count reconnections = finished outages
            reconnections = sum(1 for e in m.events if e["reconnect"] is not None)
            disconnections = len(m.events)
            if not m.is_connected and m.outage_start and not any(
                e["reconnect"] is None for e in m.events
            ):
                disconnections += 1

            # Latency snapshot
            recent_latency = list(m.latency_samples)[-20:] if m.latency_samples else []

            # DNS snapshot
            last_dns = m.last_dns_result
            is_connected = m.is_connected

            # Gateway snapshot
            last_gateway = getattr(m, "last_gateway_result", None)

        self._labels["connected_time"].config(text=format_duration(connected_time))
        self._labels["disconnected_time"].config(text=format_duration(live_downtime))
        self._labels["connections"].config(text=str(reconnections))
        self._labels["disconnections"].config(text=str(disconnections))
        self.elapsed_var.set(GUI_ELAPSED.format(elapsed=format_duration(elapsed)))

        # Latency display (recent average)
        if recent_latency:
            avg_lat = sum(recent_latency) / len(recent_latency)
            self._labels["avg_latency"].config(
                text=GUI_LATENCY_FMT.format(latency=avg_lat))
        else:
            self._labels["avg_latency"].config(text=GUI_DEFAULT_DASH)

        # DNS display
        if last_dns:
            if last_dns["resolved"]:
                self._labels["dns_status"].config(
                    text=GUI_DNS_OK.format(latency=last_dns['latency_ms']),
                    fg=self.GREEN,
                )
            else:
                self._labels["dns_status"].config(
                    text=GUI_DNS_FAILED, fg=self.RED)
        else:
            self._labels["dns_status"].config(
                text=GUI_DEFAULT_DASH, fg=self.FG)

        # Gateway display
        if last_gateway and last_gateway.get("reachable") is not None:
            gw_ip = last_gateway.get("gateway_ip", "?")
            if last_gateway["reachable"]:
                lat = last_gateway.get("latency_ms")
                lat_str = f" ({lat:.0f}ms)" if lat else ""
                self._labels["gateway_status"].config(
                    text=GUI_GATEWAY_OK.format(ip=gw_ip, latency=lat_str),
                    fg=self.GREEN)
            else:
                self._labels["gateway_status"].config(
                    text=GUI_GATEWAY_DOWN.format(ip=gw_ip), fg=self.RED)
        else:
            self._labels["gateway_status"].config(
                text=GUI_DEFAULT_DASH, fg=self.DIM)

        if is_connected:
            self.status_var.set(GUI_STATUS_CONNECTED)
            self.status_label.config(fg=self.GREEN)
        else:
            self.status_var.set(GUI_STATUS_DISCONNECTED)
            self.status_label.config(fg=self.RED)

    def _on_save(self):
        """Save a snapshot PDF without stopping the monitor."""
        self.save_btn.config(state="disabled", text=GUI_BTN_SAVING)
        self.root.update_idletasks()
        try:
            path = self.monitor.save_snapshot()
            self.save_btn.config(text=GUI_BTN_SAVED, fg=self.GREEN)
        except Exception as e:
            self.save_btn.config(text=GUI_BTN_ERROR, fg=self.RED)
            print(GUI_SAVE_ERROR.format(error=e))
        self.root.after(2000, lambda: self.save_btn.config(
            state="normal", text=GUI_BTN_SAVE, fg=self.FG,
        ))

    def _on_close(self):
        """User closed the window - finish monitoring."""
        self.monitor._finish()
        self.root.destroy()

    def mainloop(self):
        self.root.mainloop()
