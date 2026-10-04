from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def _response(body: bytes, source_port: int) -> IP:
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )
    packet = (
        IP(src="198.51.100.20", dst="192.0.2.10")
        / TCP(sport=source_port, dport=50000, seq=100, flags="PA")
        / Raw(raw)
    )
    return packet


def test_t04_invalid_utf8_is_partial_and_next_packet_is_processed() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="assignment-2.pcap")
    invalid = pipeline.process_packet(_response(b"\xffbroken", 8080), context)
    valid = pipeline.process_packet(_response(b"still running", 8081), context)

    invalid_fields = invalid["application"]["fields"]
    assert invalid_fields["decoded_body"] == {
        "length": 7,
        "encoding": "hex",
        "data": "ff62726f6b656e",
    }
    assert invalid_fields["decode_status"] == "partial"
    assert invalid["status"] == "partial"
    assert any("Invalid utf-8 byte sequence" in error for error in invalid["errors"])

    assert valid["packet_id"] == 2
    assert valid["application"]["fields"]["decoded_body"]["data"] == "still running"
    assert valid["status"] == "parsed"
