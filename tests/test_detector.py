from __future__ import annotations

import pytest

from ids_parser.detector import detect_application
from ids_parser.parsers.payload import normalize_payload


def tcp(source_port: int, destination_port: int) -> dict:
    return {
        "protocol": "TCP",
        "source_port": source_port,
        "destination_port": destination_port,
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        b"POST /submit HTTP/1.0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    ],
)
def test_detect_http_from_payload_on_non_standard_port(raw: bytes) -> None:
    assert detect_application(tcp(49152, 12345), normalize_payload(raw)) == "HTTP"


def test_detect_extension_method_with_standard_port_hint() -> None:
    raw = b"PURGE /cache HTTP/1.1\r\nHost: example.test\r\n\r\n"

    assert detect_application(tcp(49152, 8080), normalize_payload(raw)) == "HTTP"
    assert detect_application(tcp(49152, 12345), normalize_payload(raw)) == "UNKNOWN"


@pytest.mark.parametrize(
    "raw",
    [b"", b"\x16\x03\x01\xff", b"not http", b"GET / without-version\r\n"],
)
def test_http_port_does_not_override_invalid_payload(raw: bytes) -> None:
    assert detect_application(tcp(49152, 80), normalize_payload(raw)) == "UNKNOWN"


def test_udp_payload_is_not_classified_as_http() -> None:
    transport = {"protocol": "UDP", "source_port": 1, "destination_port": 80}
    raw = b"GET / HTTP/1.1\r\n\r\n"

    assert detect_application(transport, normalize_payload(raw)) == "UNKNOWN"

