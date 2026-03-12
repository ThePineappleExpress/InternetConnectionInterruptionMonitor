# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
Raw SNMPv2c GET implementation using only stdlib (socket + struct).

Builds and parses BER/ASN.1-encoded SNMP packets to query router counters
without requiring any external SNMP libraries.  Falls back gracefully when
the router does not respond (SNMP disabled / not supported).
"""

import secrets
import socket
import struct
import time

from config import (
    SNMP_COMMUNITY,
    SNMP_HOST,
    SNMP_INTERFACE_INDEX,
    SNMP_PORT,
    SNMP_TIMEOUT,
)

# -- ASN.1 / BER tag constants -----------------------------------------------
_INTEGER        = 0x02
_OCTET_STRING   = 0x04
_NULL           = 0x05
_OID            = 0x06
_SEQUENCE       = 0x30
_GET_REQUEST    = 0xA0
_GET_RESPONSE   = 0xA2
_COUNTER32      = 0x41
_GAUGE32        = 0x42
_TIMETICKS      = 0x43
_COUNTER64      = 0x46
_NO_SUCH_OBJECT = 0x80
_NO_SUCH_INSTANCE = 0x81

# -- Well-known OIDs (IF-MIB / SNMPv2-MIB) -----------------------------------
# {oid_suffix} is replaced with the interface index at runtime.
OIDS = {
    "sysUpTime":     "1.3.6.1.2.1.1.3.0",
    "ifDescr":       "1.3.6.1.2.1.2.2.1.2.{idx}",
    "ifOperStatus":  "1.3.6.1.2.1.2.2.1.8.{idx}",
    "ifInOctets":    "1.3.6.1.2.1.2.2.1.10.{idx}",
    "ifOutOctets":   "1.3.6.1.2.1.2.2.1.16.{idx}",
    "ifInErrors":    "1.3.6.1.2.1.2.2.1.14.{idx}",
    "ifOutErrors":   "1.3.6.1.2.1.2.2.1.20.{idx}",
    "ifInDiscards":  "1.3.6.1.2.1.2.2.1.13.{idx}",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19.{idx}",
}


# -- BER encoding helpers ----------------------------------------------------

def _encode_length(length: int) -> bytes:
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    # Long form
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _encode_tlv(tag: int, value: bytes) -> bytes:
    """Wrap a value in a TLV (tag-length-value) structure."""
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(val: int) -> bytes:
    """Encode an ASN.1 INTEGER."""
    if val == 0:
        return _encode_tlv(_INTEGER, b"\x00")
    # Determine number of bytes needed (signed)
    byte_len = (val.bit_length() + 8) // 8  # +8 for sign bit safety
    data = val.to_bytes(byte_len, "big", signed=(val < 0))
    # Strip leading zero bytes that aren't needed for sign
    while len(data) > 1 and data[0] == 0 and not (data[1] & 0x80):
        data = data[1:]
    return _encode_tlv(_INTEGER, data)


def _encode_oid(oid_str: str) -> bytes:
    """Encode a dotted-decimal OID string as ASN.1 OID."""
    parts = [int(p) for p in oid_str.split(".")]
    if len(parts) < 2:
        raise ValueError(f"OID too short: {oid_str}")
    # First two components are encoded as 40*X + Y
    data = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        if p < 128:
            data.append(p)
        else:
            # Multi-byte encoding (base-128)
            chunks = []
            val = p
            while val > 0:
                chunks.append(val & 0x7F)
                val >>= 7
            chunks.reverse()
            for i, c in enumerate(chunks):
                if i < len(chunks) - 1:
                    data.append(c | 0x80)
                else:
                    data.append(c)
    return _encode_tlv(_OID, bytes(data))


def _encode_null() -> bytes:
    """Encode ASN.1 NULL."""
    return _encode_tlv(_NULL, b"")


def _encode_octet_string(val: str) -> bytes:
    """Encode an ASN.1 OCTET STRING."""
    return _encode_tlv(_OCTET_STRING, val.encode("ascii"))


# -- BER decoding helpers ----------------------------------------------------

def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a BER length field. Returns (length, new_offset)."""
    if offset >= len(data):
        raise ValueError("Truncated length")
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    num_bytes = b & 0x7F
    if num_bytes == 0 or offset + 1 + num_bytes > len(data):
        raise ValueError("Invalid length encoding")
    length = int.from_bytes(data[offset + 1: offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def _decode_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Decode one TLV. Returns (tag, value_bytes, new_offset)."""
    if offset >= len(data):
        raise ValueError("Truncated TLV")
    tag = data[offset]
    length, off = _decode_length(data, offset + 1)
    if off + length > len(data):
        raise ValueError("TLV value exceeds data")
    value = data[off: off + length]
    return tag, value, off + length


def _decode_integer(data: bytes) -> int:
    """Decode an ASN.1 INTEGER value."""
    return int.from_bytes(data, "big", signed=True)


def _decode_oid(data: bytes) -> str:
    """Decode an ASN.1 OID value to dotted-decimal string."""
    if not data:
        return ""
    parts = [data[0] // 40, data[0] % 40]
    i = 1
    while i < len(data):
        val = 0
        while i < len(data):
            b = data[i]
            val = (val << 7) | (b & 0x7F)
            i += 1
            if not (b & 0x80):
                break
        parts.append(val)
    return ".".join(str(p) for p in parts)


# -- SNMP packet construction ------------------------------------------------

def _build_get_request(community: str, oid_str: str, request_id: int) -> bytes:
    """Build an SNMPv2c GET request packet."""
    # Varbind: OID + NULL
    varbind = _encode_tlv(_SEQUENCE, _encode_oid(oid_str) + _encode_null())
    varbind_list = _encode_tlv(_SEQUENCE, varbind)

    # PDU: request-id, error-status(0), error-index(0), varbind-list
    pdu_body = (
        _encode_integer(request_id)
        + _encode_integer(0)   # error-status
        + _encode_integer(0)   # error-index
        + varbind_list
    )
    pdu = _encode_tlv(_GET_REQUEST, pdu_body)

    # Message: version(1 = SNMPv2c), community, PDU
    message_body = (
        _encode_integer(1)  # version SNMPv2c
        + _encode_octet_string(community)
        + pdu
    )
    return _encode_tlv(_SEQUENCE, message_body)


def _parse_get_response(data: bytes, *,
                        expected_request_id: int | None = None,
                        ) -> tuple[str, int | str | None]:
    """
    Parse an SNMPv2c GET response.
    Returns (oid_str, value) where value is int, str, or None on error.

    If *expected_request_id* is given, the response is rejected when the
    request-id does not match (guards against spoofed replies).
    """
    try:
        # Outer SEQUENCE
        tag, seq_data, _ = _decode_tlv(data, 0)
        if tag != _SEQUENCE:
            return "", None

        off = 0
        # version
        _, _, off = _decode_tlv(seq_data, off)
        # community
        _, _, off = _decode_tlv(seq_data, off)
        # PDU (GET-RESPONSE)
        pdu_tag, pdu_data, _ = _decode_tlv(seq_data, off)
        if pdu_tag != _GET_RESPONSE:
            return "", None

        poff = 0
        # request-id
        _, rid_data, poff = _decode_tlv(pdu_data, poff)
        resp_request_id = _decode_integer(rid_data)
        if (expected_request_id is not None
                and resp_request_id != expected_request_id):
            return "", None
        # error-status
        _, err_data, poff = _decode_tlv(pdu_data, poff)
        error_status = _decode_integer(err_data)
        # error-index
        _, _, poff = _decode_tlv(pdu_data, poff)

        if error_status != 0:
            return "", None

        # varbind-list (SEQUENCE of SEQUENCE)
        _, vbl_data, _ = _decode_tlv(pdu_data, poff)
        # first varbind
        _, vb_data, _ = _decode_tlv(vbl_data, 0)

        voff = 0
        # OID
        _, oid_bytes, voff = _decode_tlv(vb_data, voff)
        oid_str = _decode_oid(oid_bytes)

        # Value
        val_tag, val_bytes, _ = _decode_tlv(vb_data, voff)

        if val_tag in (_NO_SUCH_OBJECT, _NO_SUCH_INSTANCE):
            return oid_str, None
        if val_tag == _INTEGER:
            return oid_str, _decode_integer(val_bytes)
        if val_tag in (_COUNTER32, _GAUGE32, _TIMETICKS):
            return oid_str, int.from_bytes(val_bytes, "big")
        if val_tag == _COUNTER64:
            return oid_str, int.from_bytes(val_bytes, "big")
        if val_tag == _OCTET_STRING:
            try:
                return oid_str, val_bytes.decode("utf-8", errors="replace")
            except Exception:
                return oid_str, val_bytes.hex()
        # Unknown type - return raw hex
        return oid_str, val_bytes.hex()

    except (ValueError, IndexError):
        return "", None


# -- Public API ---------------------------------------------------------------

def snmp_get(oid_str: str, host: str = SNMP_HOST, port: int = SNMP_PORT,
             community: str = SNMP_COMMUNITY,
             timeout: float = SNMP_TIMEOUT) -> tuple[str, int | str | None]:
    """
    Send an SNMPv2c GET request and return (oid, value).
    Returns ("", None) on any failure (timeout, SNMP not enabled, etc.).
    """
    request_id = secrets.randbelow(0x7FFFFFFF) + 1
    packet = _build_get_request(community, oid_str, request_id)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        return _parse_get_response(data, expected_request_id=request_id)
    except OSError:
        return "", None


def poll_router(idx: int = SNMP_INTERFACE_INDEX) -> dict:
    """
    Poll a set of standard MIB counters from the router.

    Returns a dict with keys matching OIDS names. Values are ints/strings
    or None if the OID was not available. An extra key "reachable" indicates
    whether the SNMP agent responded at all.

    Interface status values (ifOperStatus):
        1 = up, 2 = down, 3 = testing, 4 = unknown, 5 = dormant,
        6 = notPresent, 7 = lowerLayerDown
    """
    result: dict = {"reachable": False}
    got_any = False

    for name, oid_template in OIDS.items():
        oid = oid_template.replace("{idx}", str(idx))
        _, value = snmp_get(oid)
        result[name] = value
        if value is not None:
            got_any = True

    result["reachable"] = got_any
    return result


def snmp_available() -> bool:
    """Quick probe: can we reach the SNMP agent at all?"""
    _, val = snmp_get(OIDS["sysUpTime"])
    return val is not None
