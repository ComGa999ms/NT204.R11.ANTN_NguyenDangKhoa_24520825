from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.parsers.http import parse_http
from ids_parser.pipeline import PacketPipeline


def test_parse_http_marks_incomplete_headers() -> None:
    fields = parse_http(b"GET / HTTP/1.1\r\nHost: example.test\r\n")

    assert fields["headers_complete"] is False


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
        b"NOT A VALID START LINE\r\n\r\n",
    ],
)
def test_parse_http_rejects_malformed_message(raw: bytes) -> None:
    with pytest.raises(ValueError):
        parse_http(raw)


def test_pipeline_preserves_transport_when_http_headers_are_malformed() -> None:
    packet = IP() / TCP(dport=80) / Raw(
        b"GET / HTTP/1.1\r\nMalformedHeader\r\n\r\n"
    )
    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="live", source="Wi-Fi")
    )

    assert event["network"]["protocol"] == "IPv4"
    assert event["transport"]["protocol"] == "TCP"
    assert event["application"]["protocol"] == "HTTP"
    assert event["status"] == "partial"
    assert any("HTTP parsing failed" in error for error in event["errors"])

