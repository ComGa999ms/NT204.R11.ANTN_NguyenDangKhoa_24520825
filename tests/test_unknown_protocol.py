from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def test_unknown_tcp_application_preserves_binary_payload() -> None:
    packet = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
        sport=49152,
        dport=31337,
        seq=100,
        flags="PA",
    ) / Raw(b"\xff\x00\x80\x01")
    packet.time = 1_700_000_000

    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="pcap", source="unknown.pcap")
    )

    assert event["status"] == "parsed"
    assert event["network"]["protocol"] == "IPv4"
    assert event["transport"]["protocol"] == "TCP"
    assert event["application"] == {"protocol": "UNKNOWN", "fields": {}}
    assert event["payload"] == {
        "length": 4,
        "encoding": "hex",
        "data": "ff008001",
    }
    assert event["errors"] == []


def test_unsupported_transport_protocol_does_not_crash_pipeline() -> None:
    packet = IP(src="192.0.2.10", dst="198.51.100.20") / ICMP()
    packet.time = 1_700_000_001

    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="live", source="Ethernet")
    )

    assert event["network"]["protocol"] == "IPv4"
    assert event["transport"] is None
    assert event["application"] == {"protocol": "UNKNOWN", "fields": {}}
    assert event["status"] == "partial"
    assert event["errors"] == []
