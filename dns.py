# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Raw DNS query construction, parsing, and resolution testing."""

import secrets
import socket
import struct
import time

from config import DNS_TEST_DOMAIN, PING_TARGETS, PING_TIMEOUT


def _build_dns_query(domain: str) -> tuple[bytes, int]:
    """Build a minimal DNS A-record query packet (no external libs).

    Returns (packet_bytes, txn_id) so the caller can verify the response.
    """
    txn_id = secrets.randbelow(0x10000)
    # Header: ID, flags=0x0100 (standard query, recursion desired),
    # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)
    # Question section
    question = b""
    for part in domain.split("."):
        question += bytes([len(part)]) + part.encode()
    question += b"\x00"  # root label
    question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question, txn_id


def _parse_dns_response(data: bytes, expected_txn_id: int | None = None) -> str | None:
    """Extract the first A-record IP from a DNS response, or None.

    If *expected_txn_id* is given, the response is rejected when the
    transaction ID does not match (guards against spoofed replies).
    """
    if len(data) < 12:
        return None
    # Verify transaction ID matches the query we sent
    resp_txn_id = struct.unpack("!H", data[0:2])[0]
    if expected_txn_id is not None and resp_txn_id != expected_txn_id:
        return None
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount == 0:
        return None
    # Skip header (12 bytes) and question section
    offset = 12
    dlen = len(data)
    # Skip QNAME
    while offset < dlen:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length >= 192:  # pointer
            offset += 2
            break
        offset += 1 + length
    else:
        return None
    if offset + 4 > dlen:
        return None
    offset += 4  # skip QTYPE + QCLASS
    # Parse first answer
    for _ in range(ancount):
        if offset >= dlen:
            return None
        # Skip NAME (may be pointer)
        if data[offset] >= 192:
            offset += 2
        else:
            while offset < dlen and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1
        if offset + 10 > dlen:
            return None
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > dlen:
            return None
        if rtype == 1 and rdlength == 4:  # A record
            return ".".join(str(b) for b in data[offset:offset + 4])
        offset += rdlength
    return None


def check_dns(domain: str = DNS_TEST_DOMAIN, timeout: float = PING_TIMEOUT) -> dict:
    """
    Test DNS resolution by sending a raw UDP query to 1.1.1.1.
    Bypasses the OS DNS cache entirely so results are always live.
    """
    dns_server = PING_TARGETS[0][0]  # use first target (1.1.1.1) as DNS resolver
    try:
        query, txn_id = _build_dns_query(domain)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            start = time.monotonic()
            sock.sendto(query, (dns_server, 53))
            data, _ = sock.recvfrom(512)
            latency = (time.monotonic() - start) * 1000
        finally:
            sock.close()
        ip = _parse_dns_response(data, expected_txn_id=txn_id)
        if ip:
            return {"domain": domain, "resolved": True, "ip": ip,
                    "latency_ms": round(latency, 1), "server": dns_server}
        return {"domain": domain, "resolved": False, "ip": None,
                "latency_ms": None, "server": dns_server}
    except OSError:
        return {"domain": domain, "resolved": False, "ip": None,
                "latency_ms": None, "server": dns_server}
