# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Core monitoring logic: connectivity checks, event recording, JSONL logging."""

import collections
import json
import os
import re
import signal
import threading
from datetime import date, datetime, timedelta, timezone

from config import (
    CHECK_INTERVAL,
    DNS_TEST_DOMAIN,
    GATEWAY_CHECK_ENABLED,
    GATEWAY_IP,
    LOG_CHECK_EVERY,
    LOG_FILENAME,
    PING_TARGETS,
    PING_TIMEOUT,
    SNMP_ENABLED,
)
from text import (
    MONITOR_CAUSE_ISP,
    MONITOR_CAUSE_ROUTER,
    MONITOR_CAUSE_UNKNOWN,
    MONITOR_DAILY_FAILED,
    MONITOR_DAILY_SAVED,
    MONITOR_DISCONNECTED,
    MONITOR_GATEWAY_NOT_DETECTED,
    MONITOR_INIT_DNS,
    MONITOR_INIT_GATEWAY,
    MONITOR_INIT_ISP,
    MONITOR_INIT_LOCAL_IP,
    MONITOR_INIT_LOG,
    MONITOR_INIT_PUBLIC_IP,
    MONITOR_INIT_SNMP_ENABLED,
    MONITOR_INIT_TARGETS,
    MONITOR_IP_CHANGED,
    MONITOR_ISP_CHANGED,
    MONITOR_LOCATION_CHANGED,
    MONITOR_LOG_RESUMED,
    MONITOR_LOG_RESUMED_DETAIL,
    MONITOR_LOG_WARNING,
    MONITOR_RECONNECTED,
    MONITOR_SNMP_AGENT_DISABLED,
    MONITOR_STARTING,
    MONITOR_STOP_SIGNAL,
)
from dns import check_dns
from gui import MonitorGUI
from network import (
    check_all_targets,
    check_gateway,
    collect_metadata,
    detect_gateway,
    get_local_ip,
    get_public_ip,
)
from report import generate_pdf
from utils import format_duration


class InternetMonitor:
    """Monitors connectivity and records outage events."""

    # Max raw samples to keep in memory (~3 days at 5 s interval)
    _MAX_SAMPLES = 50_000

    def __init__(self):
        self.start_time: datetime = datetime.now(timezone.utc)
        self.end_time: datetime | None = None
        self.is_connected: bool = True
        self.outage_start: datetime | None = None
        self.events: collections.deque[dict] = collections.deque(maxlen=10_000)
        self.total_downtime: timedelta = timedelta()
        self._finished: bool = False
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self.metadata: dict = collect_metadata()

        # Latency tracking (bounded)
        self.latency_samples: collections.deque[float] = collections.deque(
            maxlen=self._MAX_SAMPLES,
        )
        self.last_check_results: list[dict] = []

        # DNS tracking (bounded)
        self.last_dns_result: dict | None = None
        self.dns_failures: collections.deque[dict] = collections.deque(
            maxlen=self._MAX_SAMPLES,
        )
        self.dns_samples: collections.deque[float] = collections.deque(
            maxlen=self._MAX_SAMPLES,
        )

        # JSON log file - one per calendar day, resume-aware
        today_str = self.start_time.astimezone().strftime("%Y%m%d")
        raw_name = LOG_FILENAME.format(date=today_str)
        # Ensure the filename stays in the current directory (no path traversal)
        self._log_filename = os.path.basename(raw_name)
        if not re.match(r'^[\w.\-]+$', self._log_filename):
            self._log_filename = f"connection_log_{today_str}.jsonl"
        self._check_counter = 0

        # Restore state from today's existing log (if any)
        self._load_today_log()

        self._init_log()

        # Track last-known public identity for change detection
        self._last_known_ip: str = self.metadata["public_ip"]
        self._last_known_isp: str = self.metadata["isp"]
        self._last_known_location: str = self.metadata.get("location", "")

        # Daily report tracking (local time for midnight detection)
        self._last_daily_report_date: date = self.start_time.astimezone().date()

        # Gateway reachability
        if GATEWAY_CHECK_ENABLED:
            self.gateway_ip: str | None = (
                GATEWAY_IP if GATEWAY_IP else detect_gateway()
            )
        else:
            self.gateway_ip = None
        self.last_gateway_result: dict | None = None
        if self.gateway_ip:
            self.metadata["gateway_ip"] = self.gateway_ip

        # SNMP (disabled by default)
        self.snmp_enabled: bool = SNMP_ENABLED
        self.last_snmp_result: dict | None = None
        if self.snmp_enabled:
            try:
                from snmp import snmp_available
                if not snmp_available():
                    print(MONITOR_SNMP_AGENT_DISABLED)
                    self.snmp_enabled = False
            except Exception:
                self.snmp_enabled = False

        print(MONITOR_INIT_PUBLIC_IP.format(ip=self.metadata['public_ip']))
        print(MONITOR_INIT_ISP.format(isp=self.metadata['isp']))
        print(MONITOR_INIT_LOCAL_IP.format(ip=self.metadata['local_ip']))
        print(MONITOR_INIT_GATEWAY.format(
            gw=self.gateway_ip or MONITOR_GATEWAY_NOT_DETECTED))
        print(MONITOR_INIT_TARGETS.format(
            targets=', '.join(self.metadata['targets'])))
        print(MONITOR_INIT_DNS.format(domain=self.metadata['dns_test_domain']))
        if self.snmp_enabled:
            print(MONITOR_INIT_SNMP_ENABLED)
        print(MONITOR_INIT_LOG.format(filename=self._log_filename))
        print()

    # -- JSON log ---------------------------------------------------------
    def _load_today_log(self):
        """Parse today's existing JSONL and restore accumulated state."""
        if not os.path.exists(self._log_filename):
            return

        pending_disconnect: dict | None = None
        earliest_start: datetime | None = None
        restored_events = 0
        restored_latency = 0
        restored_dns = 0

        try:
            with open(self._log_filename) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    etype = entry.get("type")

                    if etype == "session_start":
                        ts = datetime.fromisoformat(entry["timestamp"])
                        if earliest_start is None or ts < earliest_start:
                            earliest_start = ts

                    elif etype == "disconnect":
                        pending_disconnect = entry

                    elif etype == "reconnect" and pending_disconnect:
                        disc_ts = datetime.fromisoformat(
                            pending_disconnect["timestamp"])
                        recon_ts = datetime.fromisoformat(
                            entry["timestamp"])
                        duration = timedelta(
                            seconds=entry.get("outage_duration_s", 0))

                        event = {
                            "disconnect": disc_ts,
                            "reconnect": recon_ts,
                            "duration": duration,
                            "local_ip_at_disconnect":
                                pending_disconnect.get("local_ip", ""),
                            "public_ip_at_reconnect":
                                entry.get("public_ip", ""),
                            "isp_at_reconnect":
                                entry.get("isp", ""),
                            "location_at_reconnect":
                                entry.get("location", ""),
                            "ip_changed":
                                entry.get("ip_changed", False),
                            "isp_changed":
                                entry.get("isp_changed", False),
                            "location_changed":
                                entry.get("location_changed", False),
                            "gateway_reachable_at_disconnect":
                                entry.get(
                                    "gateway_reachable_at_disconnect",
                                    pending_disconnect.get(
                                        "gateway_reachable")),
                            "disconnect_check_results":
                                pending_disconnect.get(
                                    "check_results", []),
                            "disconnect_dns_result":
                                pending_disconnect.get(
                                    "dns_result", {}),
                            "reconnect_check_results":
                                entry.get("check_results", []),
                            "reconnect_dns_result":
                                entry.get("dns_result", {}),
                        }
                        self.events.append(event)
                        self.total_downtime += duration
                        restored_events += 1

                        # Update last-known identity
                        if entry.get("public_ip"):
                            self._last_known_ip = entry["public_ip"]
                        if entry.get("isp"):
                            self._last_known_isp = entry["isp"]
                        if entry.get("location"):
                            self._last_known_location = entry["location"]

                        pending_disconnect = None

                    elif etype == "check":
                        for r in entry.get("check_results", []):
                            if r.get("reachable") and r.get("latency_ms"):
                                self.latency_samples.append(
                                    r["latency_ms"])
                                restored_latency += 1
                        dr = entry.get("dns_result", {})
                        if dr.get("resolved") and dr.get("latency_ms"):
                            self.dns_samples.append(dr["latency_ms"])
                            restored_dns += 1

                    elif etype == "dns_failure":
                        self.dns_failures.append({
                            "timestamp": entry.get("timestamp"),
                            "dns_result": entry.get("dns_result", {}),
                            "check_results":
                                entry.get("check_results", []),
                        })

        except OSError as e:
            print(MONITOR_LOG_WARNING.format(error=e))
            return

        # Use earliest session start so total duration spans the full day
        if earliest_start and earliest_start < self.start_time:
            self.start_time = earliest_start

        if restored_events or restored_latency or restored_dns:
            print(MONITOR_LOG_RESUMED)
            print(MONITOR_LOG_RESUMED_DETAIL.format(
                events=restored_events,
                latency=restored_latency,
                dns=restored_dns,
                failures=len(self.dns_failures),
                downtime=format_duration(self.total_downtime)))

    def _init_log(self):
        """Write the log header."""
        self._log_entry({
            "type": "session_start",
            "timestamp": self.start_time.isoformat(),
            "metadata": self.metadata,
        })

    def _log_entry(self, entry: dict):
        """Append a JSON line to the log file (owner-only permissions)."""
        fd = os.open(self._log_filename,
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    # -- event helpers ----------------------------------------------------
    def _record_disconnect(self, ts: datetime, check_results: list[dict],
                           dns_result: dict, gateway_result: dict):
        self.is_connected = False
        self.outage_start = ts
        self._outage_local_ip = get_local_ip()
        self._outage_check_results = check_results
        self._outage_dns_result = dns_result
        self._outage_gateway_result = gateway_result
        gw_up = gateway_result.get("reachable")
        if gw_up:
            cause = MONITOR_CAUSE_ISP
        elif gw_up is False:
            cause = MONITOR_CAUSE_ROUTER
        else:
            cause = MONITOR_CAUSE_UNKNOWN
        local_ts = ts.astimezone()
        print(MONITOR_DISCONNECTED.format(
            ts=f"{local_ts:%Y-%m-%d %H:%M:%S}",
            count=len(PING_TARGETS),
            cause=cause))
        self._log_entry({
            "type": "disconnect",
            "timestamp": ts.isoformat(),
            "local_ip": self._outage_local_ip,
            "check_results": check_results,
            "dns_result": dns_result,
            "gateway_reachable": gw_up,
            "cause": cause,
        })

    def _record_reconnect(self, ts: datetime, check_results: list[dict],
                          dns_result: dict, gateway_result: dict):
        duration = ts - self.outage_start
        self.total_downtime += duration
        pub = get_public_ip()

        new_ip = pub["ip"]
        new_isp = pub["isp"]
        new_location = ", ".join(
            filter(None, [pub["city"], pub["region"], pub["country"]]),
        )

        # Detect changes vs last-known values
        ip_changed = new_ip != self._last_known_ip
        isp_changed = new_isp != self._last_known_isp
        location_changed = new_location != self._last_known_location

        # Determine outage cause from gateway state at disconnect
        gw_up = getattr(
            self, "_outage_gateway_result", {},
        ).get("reachable")

        event = {
            "disconnect": self.outage_start,
            "reconnect": ts,
            "duration": duration,
            "local_ip_at_disconnect": self._outage_local_ip,
            "public_ip_at_reconnect": new_ip,
            "isp_at_reconnect": new_isp,
            "location_at_reconnect": new_location,
            "ip_changed": ip_changed,
            "isp_changed": isp_changed,
            "location_changed": location_changed,
            "gateway_reachable_at_disconnect": gw_up,
            "disconnect_check_results": self._outage_check_results,
            "disconnect_dns_result": self._outage_dns_result,
            "reconnect_check_results": check_results,
            "reconnect_dns_result": dns_result,
        }
        self.events.append(event)

        # Update last-known values
        self._last_known_ip = new_ip
        self._last_known_isp = new_isp
        self._last_known_location = new_location

        # Refresh metadata so report/GUI reflect current state
        self.metadata["public_ip"] = new_ip
        self.metadata["isp"] = new_isp
        self.metadata["location"] = new_location
        self.metadata["local_ip"] = get_local_ip()

        self.is_connected = True
        self.outage_start = None
        local_ts = ts.astimezone()

        change_parts = []
        if ip_changed:
            change_parts.append(MONITOR_IP_CHANGED.format(ip=new_ip))
        if isp_changed:
            change_parts.append(MONITOR_ISP_CHANGED.format(isp=new_isp))
        if location_changed:
            change_parts.append(
                MONITOR_LOCATION_CHANGED.format(location=new_location))
        change_note = f"  [{', '.join(change_parts)}]" if change_parts else ""

        print(MONITOR_RECONNECTED.format(
            ts=f"{local_ts:%Y-%m-%d %H:%M:%S}",
            duration=format_duration(duration),
            changes=change_note))
        self._log_entry({
            "type": "reconnect",
            "timestamp": ts.isoformat(),
            "outage_duration_s": duration.total_seconds(),
            "public_ip": new_ip,
            "isp": new_isp,
            "location": new_location,
            "ip_changed": ip_changed,
            "isp_changed": isp_changed,
            "location_changed": location_changed,
            "gateway_reachable_at_disconnect": gw_up,
            "check_results": check_results,
            "dns_result": dns_result,
        })

    # -- main loop --------------------------------------------------------
    def _monitor_loop(self):
        """Background thread: check connectivity every CHECK_INTERVAL."""
        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)
            self._check_counter += 1

            # Multi-target connectivity check with latency (concurrent)
            is_online, check_results = check_all_targets()

            # DNS resolution check
            dns_result = check_dns()

            # Gateway reachability check
            gateway_result = check_gateway(self.gateway_ip)

            # SNMP poll (periodic, outside lock)
            if (self.snmp_enabled
                    and self._check_counter % LOG_CHECK_EVERY == 0):
                try:
                    from snmp import poll_router
                    snmp_result = poll_router()
                except Exception:
                    snmp_result = None
            else:
                snmp_result = None

            with self._lock:
                self.last_check_results = check_results
                self.last_gateway_result = gateway_result
                if snmp_result is not None:
                    self.last_snmp_result = snmp_result

                # Collect latency samples from successful checks
                for r in check_results:
                    if r["reachable"] and r["latency_ms"] is not None:
                        self.latency_samples.append(r["latency_ms"])

                self.last_dns_result = dns_result
                if dns_result["resolved"] and dns_result["latency_ms"] is not None:
                    self.dns_samples.append(dns_result["latency_ms"])
                elif not dns_result["resolved"] and is_online:
                    self.dns_failures.append({
                        "timestamp": now.isoformat(),
                        "dns_result": dns_result,
                        "check_results": check_results,
                    })
                    self._log_entry({
                        "type": "dns_failure",
                        "timestamp": now.isoformat(),
                        "dns_result": dns_result,
                        "check_results": check_results,
                    })

                # Log periodic check (every LOG_CHECK_EVERY cycles)
                if self._check_counter % LOG_CHECK_EVERY == 0:
                    log_entry = {
                        "type": "check",
                        "timestamp": now.isoformat(),
                        "online": is_online,
                        "check_results": check_results,
                        "dns_result": dns_result,
                        "gateway_result": gateway_result,
                    }
                    if snmp_result:
                        log_entry["snmp_result"] = snmp_result
                    self._log_entry(log_entry)

                # State transitions
                if self.is_connected and not is_online:
                    self._record_disconnect(now, check_results, dns_result,
                                            gateway_result)
                elif not self.is_connected and is_online:
                    self._record_reconnect(now, check_results, dns_result,
                                           gateway_result)

            # Check for daily report (outside lock - generates PDF)
            self._check_daily_report(now)

            self._stop_event.wait(CHECK_INTERVAL)

    def _check_daily_report(self, now: datetime):
        """Auto-save a report at midnight (local time) each day."""
        local_now = now.astimezone()
        today = local_now.date()
        if today > self._last_daily_report_date:
            self._last_daily_report_date = today
            try:
                path = self.save_snapshot(tag="daily")
                print(MONITOR_DAILY_SAVED.format(
                    ts=f"{local_now:%Y-%m-%d %H:%M:%S}", path=path))
            except Exception as e:
                print(MONITOR_DAILY_FAILED.format(
                    ts=f"{local_now:%Y-%m-%d %H:%M:%S}", error=e))

    def run(self):
        """Run the monitor with a GUI."""
        local_start = self.start_time.astimezone()
        print(MONITOR_STARTING.format(
            ts=f"{local_start:%Y-%m-%d %H:%M:%S}"))

        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        worker = threading.Thread(target=self._monitor_loop, daemon=True)
        worker.start()

        self._gui = MonitorGUI(self)
        self._gui.mainloop()

    def _handle_signal(self, signum, frame):
        """Set stop flag and schedule GUI close from the main thread."""
        print(MONITOR_STOP_SIGNAL)
        self._stop_event.set()
        if hasattr(self, "_gui"):
            self._gui.root.after_idle(self._gui._on_close)

    def _finish(self):
        """Close any open outage and generate the PDF."""
        if self._finished:
            return
        self._finished = True
        self._stop_event.set()
        self.end_time = datetime.now(timezone.utc)

        with self._lock:
            if not self.is_connected and self.outage_start:
                duration = self.end_time - self.outage_start
                self.total_downtime += duration
                self.events.append({
                    "disconnect": self.outage_start,
                    "reconnect": None,
                    "duration": duration,
                    "local_ip_at_disconnect": getattr(
                        self, "_outage_local_ip", "unknown",
                    ),
                    "public_ip_at_reconnect": None,
                    "isp_at_reconnect": None,
                    "location_at_reconnect": None,
                    "ip_changed": False,
                    "isp_changed": False,
                    "location_changed": False,
                    "gateway_reachable_at_disconnect": getattr(
                        self, "_outage_gateway_result", {},
                    ).get("reachable"),
                    "disconnect_check_results": getattr(
                        self, "_outage_check_results", [],
                    ),
                    "disconnect_dns_result": getattr(
                        self, "_outage_dns_result", {},
                    ),
                    "reconnect_check_results": [],
                    "reconnect_dns_result": {},
                })

            self._log_entry({
                "type": "session_end",
                "timestamp": self.end_time.isoformat(),
                "total_downtime_s": self.total_downtime.total_seconds(),
                "total_events": len(self.events),
                "total_dns_failures": len(self.dns_failures),
            })

        generate_pdf(self)

    # -- snapshot (save without stopping) ---------------------------------
    def save_snapshot(self, tag: str = "snapshot") -> str:
        """Generate a PDF snapshot of the current state without stopping."""
        now = datetime.now(timezone.utc)
        with self._lock:
            snapshot_events = list(self.events)
            snapshot_downtime = self.total_downtime
            if not self.is_connected and self.outage_start:
                ongoing = now - self.outage_start
                snapshot_downtime += ongoing
                snapshot_events.append({
                    "disconnect": self.outage_start,
                    "reconnect": None,
                    "duration": ongoing,
                    "local_ip_at_disconnect": getattr(
                        self, "_outage_local_ip", "unknown",
                    ),
                    "public_ip_at_reconnect": None,
                    "isp_at_reconnect": None,
                    "location_at_reconnect": None,
                    "ip_changed": False,
                    "isp_changed": False,
                    "location_changed": False,
                    "gateway_reachable_at_disconnect": getattr(
                        self, "_outage_gateway_result", {},
                    ).get("reachable"),
                    "disconnect_check_results": getattr(
                        self, "_outage_check_results", [],
                    ),
                    "disconnect_dns_result": getattr(
                        self, "_outage_dns_result", {},
                    ),
                    "reconnect_check_results": [],
                    "reconnect_dns_result": {},
                })
        return generate_pdf(
            self,
            end_time=now,
            events=snapshot_events,
            total_downtime=snapshot_downtime,
            tag=tag,
        )
