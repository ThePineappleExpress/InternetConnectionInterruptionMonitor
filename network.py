# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Network connectivity checks and metadata collection."""

import hashlib
import http.client
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import time
import urllib.request
import concurrent.futures

from config import CHECK_INTERVAL, GATEWAY_TIMEOUT, PING_TARGETS, PING_TIMEOUT, DNS_TEST_DOMAIN
from text import NET_TLS_PIN_LEARNED, NET_TLS_PIN_MISMATCH, NET_USER_AGENT

# Rate-limit cache for ipinfo.io requests (at most once per 60 s)
_IP_INFO_CACHE: dict = {}
_IP_INFO_CACHE_TTL = 60  # seconds

# --- TLS certificate pinning (TOFU) for ipinfo.io ---------------------------
# Pins the SHA-256 hash of the server certificate's Subject Public Key Info
# (SPKI).  SPKI pinning survives normal certificate renewals as long as the
# same key pair is reused.  On first successful connection the pin is learned
# and saved to disk; subsequent connections reject mismatched keys.
_CERT_PIN_FILE = ".ipinfo_cert_pin"


def _der_read_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read a DER-encoded length field.  Returns (length, offset_past_length)."""
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    num_bytes = b & 0x7F
    if num_bytes == 0 or offset + 1 + num_bytes > len(data):
        raise ValueError("Invalid DER length")
    length = int.from_bytes(data[offset + 1:offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def _der_element_end(data: bytes, offset: int) -> int:
    """Return the byte offset just past a single DER element at *offset*."""
    length, content_start = _der_read_length(data, offset + 1)
    return content_start + length


def _extract_spki(cert_der: bytes) -> bytes | None:
    """Extract the raw DER-encoded SubjectPublicKeyInfo from an X.509 cert.

    Parses just enough of the TBSCertificate structure (RFC 5280 s4.1) to
    locate the 7th field.  Returns *None* on any parse failure.
    """
    try:
        # Certificate ::= SEQUENCE { tbsCertificate, sigAlg, sig }
        if cert_der[0] != 0x30:
            return None
        # TBSCertificate is the first child SEQUENCE
        _, outer_off = _der_read_length(cert_der, 1)
        if cert_der[outer_off] != 0x30:
            return None
        _, pos = _der_read_length(cert_der, outer_off + 1)

        # 1. version  [0] EXPLICIT  (optional, present in v2/v3)
        if pos < len(cert_der) and cert_der[pos] == 0xA0:
            pos = _der_element_end(cert_der, pos)
        # 2. serialNumber       INTEGER
        pos = _der_element_end(cert_der, pos)
        # 3. signature          AlgorithmIdentifier
        pos = _der_element_end(cert_der, pos)
        # 4. issuer             Name
        pos = _der_element_end(cert_der, pos)
        # 5. validity           Validity
        pos = _der_element_end(cert_der, pos)
        # 6. subject            Name
        pos = _der_element_end(cert_der, pos)
        # 7. subjectPublicKeyInfo  <-- target
        spki_start = pos
        spki_end = _der_element_end(cert_der, pos)
        return cert_der[spki_start:spki_end]
    except (IndexError, ValueError):
        return None


def _compute_spki_hash(cert_der: bytes) -> str | None:
    """Compute ``sha256:<hex>`` hash of the certificate's SPKI."""
    spki = _extract_spki(cert_der)
    if spki is None:
        return None
    return "sha256:" + hashlib.sha256(spki).hexdigest()


def _load_cert_pin() -> str | None:
    """Load the saved SPKI pin from disk, or *None* if absent."""
    try:
        with open(_CERT_PIN_FILE) as f:
            pin = f.read().strip()
            return pin if pin.startswith("sha256:") else None
    except OSError:
        return None


def _save_cert_pin(pin_hash: str) -> None:
    """Persist an SPKI pin to disk with owner-only permissions."""
    try:
        fd = os.open(_CERT_PIN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pin_hash + "\n")
    except OSError:
        pass


class _PinningHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that verifies a TOFU SPKI pin after TLS handshake."""

    def connect(self):
        super().connect()
        cert_der = self.sock.getpeercert(binary_form=True)
        if not cert_der:
            return  # no cert - standard TLS check still applies

        current_hash = _compute_spki_hash(cert_der)
        if current_hash is None:
            return  # couldn't parse cert - fall through to std TLS

        saved_pin = _load_cert_pin()
        if saved_pin is None:
            # First use - learn and persist the pin (TOFU)
            _save_cert_pin(current_hash)
            print(NET_TLS_PIN_LEARNED.format(hash=current_hash[:30]))
        elif saved_pin != current_hash:
            self.close()
            raise ssl.SSLCertVerificationError(
                NET_TLS_PIN_MISMATCH.format(
                    expected=saved_pin,
                    actual=current_hash,
                    pin_file=_CERT_PIN_FILE)
            )


class _PinningHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS handler that routes connections through pinning verification."""

    def https_open(self, req):
        return self.do_open(_PinningHTTPSConnection, req)


_pinning_opener = urllib.request.build_opener(_PinningHTTPSHandler)


def get_local_ip() -> str:
    """Return the machine's local/LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "unknown"


def _validate_ip(ip: str) -> bool:
    """Check that *ip* looks like a valid IPv4 or IPv6 address."""
    return bool(re.match(
        r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)$', ip,
    ))


def get_public_ip() -> dict:
    """Fetch public IP and ISP info from ipinfo.io (best-effort).

    Results are cached for ``_IP_INFO_CACHE_TTL`` seconds to avoid
    hammering the external service during rapid reconnect cycles.
    """
    # Return cached result if still fresh
    cached = _IP_INFO_CACHE.get("result")
    if cached:
        age = time.monotonic() - _IP_INFO_CACHE.get("ts", 0)
        if age < _IP_INFO_CACHE_TTL:
            return cached

    _EMPTY = {"ip": "unknown", "isp": "unknown", "city": "", "region": "", "country": ""}
    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"User-Agent": NET_USER_AGENT},
        )
        with _pinning_opener.open(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())

        # Validate response to guard against malformed / MITM'd data
        ip = data.get("ip", "unknown")
        if ip != "unknown" and not _validate_ip(ip):
            ip = "unknown"

        result = {
            "ip": ip,
            "isp": str(data.get("org", "unknown"))[:200],
            "city": str(data.get("city", ""))[:100],
            "region": str(data.get("region", ""))[:100],
            "country": str(data.get("country", ""))[:10],
        }
        _IP_INFO_CACHE["result"] = result
        _IP_INFO_CACHE["ts"] = time.monotonic()
        return result
    except Exception:
        return _EMPTY


def collect_metadata() -> dict:
    """Gather system and network metadata for the report."""
    pub = get_public_ip()
    return {
        "hostname": socket.gethostname(),
        "local_ip": get_local_ip(),
        "public_ip": pub["ip"],
        "isp": pub["isp"],
        "location": ", ".join(filter(None, [pub["city"], pub["region"], pub["country"]])),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "targets": [f"{h}:{p}" for h, p in PING_TARGETS],
        "check_interval": CHECK_INTERVAL,
        "ping_timeout": PING_TIMEOUT,
        "dns_test_domain": DNS_TEST_DOMAIN,
    }


def check_target(host: str, port: int, timeout: float = PING_TIMEOUT) -> dict:
    """Check a single target. Returns dict with reachable bool and latency_ms."""
    try:
        start = time.monotonic()
        sock = socket.create_connection((host, port), timeout=timeout)
        latency = (time.monotonic() - start) * 1000
        try:
            sock.close()
        except OSError:
            pass
        return {"host": host, "port": port, "reachable": True, "latency_ms": round(latency, 1)}
    except OSError:
        return {"host": host, "port": port, "reachable": False, "latency_ms": None}


def check_all_targets() -> tuple[bool, list[dict]]:
    """
    Check all configured targets concurrently. Returns (is_online, results).
    Considered online if ANY target is reachable.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PING_TARGETS)) as pool:
        futures = {
            pool.submit(check_target, host, port): (host, port)
            for host, port in PING_TARGETS
        }
        results = [f.result() for f in futures]
    is_online = any(r["reachable"] for r in results)
    return is_online, results


def detect_gateway() -> str | None:
    """Auto-detect the default gateway IP address."""
    try:
        system = platform.system()
        gw = None
        if system == "Linux":
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True, timeout=5, stderr=subprocess.DEVNULL,
            )
            for line in out.strip().splitlines():
                parts = line.split()
                if "via" in parts:
                    gw = parts[parts.index("via") + 1]
                    break
        elif system == "Darwin":
            out = subprocess.check_output(
                ["route", "-n", "get", "default"],
                text=True, timeout=5, stderr=subprocess.DEVNULL,
            )
            for line in out.strip().splitlines():
                if "gateway:" in line:
                    gw = line.split("gateway:")[-1].strip()
                    break
        elif system == "Windows":
            out = subprocess.check_output(
                ["ipconfig"], text=True, timeout=5, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                if "Default Gateway" in line and ":" in line:
                    candidate = line.split(":")[-1].strip()
                    if candidate:
                        gw = candidate
                        break
        # Validate that the extracted value looks like a real IP address
        if gw and _validate_ip(gw):
            return gw
    except Exception:
        pass
    return None


def check_gateway(gateway_ip: str | None,
                  timeout: float = GATEWAY_TIMEOUT) -> dict:
    """
    Check if the default gateway is reachable.

    Tries TCP to common router ports (80, 443, 53). A ConnectionRefusedError
    (RST) still counts as reachable since the host answered.
    Returns dict with reachable (bool|None), latency_ms, gateway_ip.
    """
    if not gateway_ip:
        return {"reachable": None, "latency_ms": None, "gateway_ip": None}
    for port in (80, 443, 53):
        start = time.monotonic()
        try:
            sock = socket.create_connection((gateway_ip, port), timeout=timeout)
            elapsed_ms = (time.monotonic() - start) * 1000
            sock.close()
            return {"reachable": True, "latency_ms": round(elapsed_ms, 1),
                    "gateway_ip": gateway_ip}
        except ConnectionRefusedError:
            # RST received = host is alive, port just closed
            elapsed_ms = (time.monotonic() - start) * 1000
            return {"reachable": True, "latency_ms": round(elapsed_ms, 1),
                    "gateway_ip": gateway_ip}
        except OSError:
            continue
    return {"reachable": False, "latency_ms": None, "gateway_ip": gateway_ip}
