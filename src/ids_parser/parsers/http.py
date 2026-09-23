"""HTTP/1.x request and response parser for one TCP payload."""

from __future__ import annotations

import re
from typing import Any

from .payload import normalize_payload


REQUEST_LINE = re.compile(rb"^([A-Z][A-Z0-9-]*) ([^\r\n ]+) (HTTP/1\.[01])$")
RESPONSE_LINE = re.compile(rb"^(HTTP/1\.[01]) ([1-5][0-9]{2})(?: (.*))?$")


def _split_message(raw: bytes) -> tuple[list[bytes], bytes, bool]:
    if b"\r\n\r\n" in raw:
        header_block, body = raw.split(b"\r\n\r\n", 1)
        lines = header_block.split(b"\r\n")
        headers_complete = True
    elif b"\n\n" in raw:
        header_block, body = raw.split(b"\n\n", 1)
        lines = [line.rstrip(b"\r") for line in header_block.split(b"\n")]
        headers_complete = True
    else:
        body = b""
        lines = [line.rstrip(b"\r") for line in raw.split(b"\n")]
        if lines and lines[-1] == b"":
            lines.pop()
        headers_complete = False
    if not lines or not lines[0]:
        raise ValueError("HTTP start line is missing")
    return lines, body, headers_complete


def _parse_headers(lines: list[bytes]) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for line in lines:
        if not line:
            continue
        if line[:1] in {b" ", b"\t"}:
            raise ValueError("Folded HTTP headers are not supported")
        name, separator, value = line.partition(b":")
        if not separator or not name or b" " in name or b"\t" in name:
            raise ValueError("Malformed HTTP header")
        key = name.decode("ascii", errors="strict").lower()
        headers.setdefault(key, []).append(value.strip().decode("iso-8859-1"))
    return headers


def _first_header(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name)
    return values[0] if values else None


def parse_http(raw: bytes) -> dict[str, Any]:
    """Parse an HTTP message wholly present in one TCP segment.

    This parser deliberately does not claim to perform TCP stream reassembly.
    A declared body longer than the received bytes is marked incomplete.
    """

    lines, body, headers_complete = _split_message(raw)
    request = REQUEST_LINE.fullmatch(lines[0])
    response = RESPONSE_LINE.fullmatch(lines[0])
    if not request and not response:
        raise ValueError("Invalid HTTP/1.x start line")

    headers = _parse_headers(lines[1:])
    content_length = _first_header(headers, "content-length")
    declared_length: int | None = None
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as error:
            raise ValueError("Invalid HTTP Content-Length") from error
        if declared_length < 0:
            raise ValueError("Invalid HTTP Content-Length")

    fields: dict[str, Any] = {
        "headers": headers,
        "content_type": _first_header(headers, "content-type"),
        "content_length": declared_length,
        "body": normalize_payload(body),
        "headers_complete": headers_complete,
        "body_complete": declared_length is None or len(body) >= declared_length,
    }
    if request:
        fields.update(
            {
                "message_type": "request",
                "method": request.group(1).decode("ascii"),
                "target": request.group(2).decode("iso-8859-1"),
                "http_version": request.group(3).decode("ascii"),
                "host": _first_header(headers, "host"),
            }
        )
    else:
        assert response is not None
        fields.update(
            {
                "message_type": "response",
                "http_version": response.group(1).decode("ascii"),
                "status_code": int(response.group(2)),
                "reason": (response.group(3) or b"").decode("iso-8859-1"),
            }
        )
    return fields
