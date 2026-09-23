from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def segment(sequence: int, data: bytes) -> IP:
    return (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=12345, seq=sequence, flags="PA")
        / Raw(data)
    )


def test_pipeline_reassembles_http_split_across_tcp_segments() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="split-http.pcap")
    first_data = b"GET /split HTTP/1.1\r\nHost: ex"
    second_data = b"ample.test\r\n\r\n"

    first = pipeline.process_packet(segment(1000, first_data), context)
    second = pipeline.process_packet(
        segment(1000 + len(first_data), second_data), context
    )

    assert first["application"]["protocol"] == "HTTP"
    assert first["status"] == "partial"
    assert second["application"]["protocol"] == "HTTP"
    assert second["application"]["fields"]["target"] == "/split"
    assert second["application"]["fields"]["host"] == "example.test"
    assert second["status"] == "parsed"
    assert second["transport"]["reassembly"]["buffered_bytes"] == (
        len(first_data) + len(second_data)
    )


def test_pipeline_reassembles_out_of_order_http_segments() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="live", source="Wi-Fi")
    first_data = b"GET /ordered HTTP/1.1\r\n"
    second_data = b"Host: example.test\r\n\r\n"

    early_second = pipeline.process_packet(
        segment(2000 + len(first_data), second_data), context
    )
    completed = pipeline.process_packet(segment(2000, first_data), context)

    assert early_second["application"]["protocol"] == "UNKNOWN"
    assert completed["application"]["protocol"] == "HTTP"
    assert completed["application"]["fields"]["host"] == "example.test"
    assert completed["transport"]["reassembly"]["out_of_order"] is True

