"""Application protocol detection using transport hints and payload signatures."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .parsers.dns import is_dns_message
from .parsers.payload import payload_to_bytes
from .parsers.smtp import is_smtp_message


HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8081, 8888})
HTTP_METHODS = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT"}
)
REQUEST_LINE = re.compile(rb"^[A-Z][A-Z0-9-]* [^\r\n ]+ HTTP/1\.[01]$")
RESPONSE_LINE = re.compile(rb"^HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?$")


def detect_application(
    transport: Mapping[str, Any] | None,
    payload: Mapping[str, Any],
) -> str:
    """Identify supported application protocols from payload and port hints.

    Payload signatures work on non-standard ports. A port alone never labels
    arbitrary bytes as a supported protocol.
    """

    if transport is None:
        return "UNKNOWN"

    raw = payload_to_bytes(payload)
    if not raw:
        return "UNKNOWN"

    transport_protocol = str(transport.get("protocol", ""))
    if transport_protocol in {"TCP", "UDP"} and is_dns_message(
        raw, transport_protocol
    ):
        return "DNS"
    if transport_protocol != "TCP":
        return "UNKNOWN"

    first_line = raw.split(b"\n", 1)[0].rstrip(b"\r")
    if len(first_line) > 8192:
        return "UNKNOWN"
    if RESPONSE_LINE.fullmatch(first_line):
        return "HTTP"
    if REQUEST_LINE.fullmatch(first_line):
        method = first_line.split(b" ", 1)[0]
        ports = {transport.get("source_port"), transport.get("destination_port")}
        if method in HTTP_METHODS or ports & HTTP_PORTS:
            return "HTTP"
    if is_smtp_message(raw):
        return "SMTP"
    return "UNKNOWN"
