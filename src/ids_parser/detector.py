"""Application protocol detection using transport hints and payload signatures."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .parsers.payload import payload_to_bytes


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
    """Identify HTTP/1.x without requiring a standard port.

    A known method or response prefix works on any TCP port. On common HTTP
    ports, a syntactically valid request line with an extension method is also
    accepted. Arbitrary port-80 bytes are not labeled HTTP.
    """

    if transport is None or transport.get("protocol") != "TCP":
        return "UNKNOWN"

    raw = payload_to_bytes(payload)
    if not raw:
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
    return "UNKNOWN"

