from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.parsers.http import parse_http
from ids_parser.pipeline import PacketPipeline


def test_parse_http_post_request_with_body() -> None:
    body = b"name=Khoa&role=student"
    raw = (
        b"POST /form HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"\r\n"
        + body
    )

    fields = parse_http(raw)

    assert fields["method"] == "POST"
    assert fields["target"] == "/form"
    assert fields["content_length"] == len(body)
    assert fields["content_type"] == "application/x-www-form-urlencoded"
    assert fields["body"] == {
        "length": len(body),
        "encoding": "utf-8",
        "data": body.decode(),
    }
    assert fields["body_complete"] is True


def test_parse_http_marks_truncated_post_body() -> None:
    fields = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab")

    assert fields["headers_complete"] is True
    assert fields["body_complete"] is False


def test_pipeline_marks_incomplete_http_post_partial() -> None:
    packet = IP() / TCP(dport=80) / Raw(
        b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhello"
    )
    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="live", source="Wi-Fi")
    )

    assert event["application"]["protocol"] == "HTTP"
    assert event["application"]["fields"]["body_complete"] is False
    assert event["status"] == "partial"

