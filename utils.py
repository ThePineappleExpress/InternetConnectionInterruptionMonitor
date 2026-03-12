# Internet Connection Interruption Monitor
# Copyright (C) 2026 ThePineappleExpress and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""General-purpose utility functions."""

from datetime import timedelta


def format_duration(td: timedelta) -> str:
    """Convert a timedelta into a human-readable 'Xh Ym Zs' string."""
    total_secs = int(td.total_seconds())
    hours, remainder = divmod(total_secs, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def pdf_safe(text: str) -> str:
    """Replace characters unsupported by fpdf2 built-in fonts (Latin-1)."""
    return text.replace("\u2014", "-").replace("\u2013", "-").replace("\u2026", "...")


def snmp_safe(value: int | str | None, max_len: int = 200) -> str:
    """Sanitize an SNMP response value for safe inclusion in a PDF.

    SNMP OCTET STRING values arrive from the network and could contain
    arbitrary bytes (spoofed responses, malformed data, etc.).  This
    helper strips control characters, enforces a length cap, and ensures
    the result is safe for Latin-1 PDF rendering.
    """
    if value is None:
        return "N/A"
    if isinstance(value, int):
        return str(value)
    # Coerce to str, strip non-printable / control chars
    text = str(value)
    text = "".join(ch for ch in text if ch.isprintable())
    text = text[:max_len]
    return pdf_safe(text)
