from __future__ import annotations

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


class MalformedPacket:
    time = 1_700_000_000

    def __bytes__(self) -> bytes:
        return b"\x45\x00\x00"

    def haslayer(self, layer: object) -> bool:
        raise ValueError("truncated IPv4 header")


class UnreadablePacket:
    def __bytes__(self) -> bytes:
        raise RuntimeError("packet bytes are unavailable")


def test_malformed_packet_becomes_partial_event_without_crashing() -> None:
    event = PacketPipeline().process_packet(
        MalformedPacket(), CaptureContext(mode="pcap", source="truncated.pcap")
    )

    assert event["packet_length"] == 3
    assert event["network"] is None
    assert event["transport"] is None
    assert event["application"] == {"protocol": "UNKNOWN", "fields": {}}
    assert event["status"] == "partial"
    assert any("Protocol parsing failed" in error for error in event["errors"])


def test_unreadable_packet_becomes_error_event_without_crashing() -> None:
    event = PacketPipeline().process_packet(
        UnreadablePacket(), CaptureContext(mode="live", source="Ethernet")
    )

    assert event["packet_length"] == 0
    assert event["network"] is None
    assert event["transport"] is None
    assert event["status"] == "error"
    assert "Packet length could not be determined" in event["errors"]


def test_pipeline_continues_after_malformed_packet() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="mixed.pcap")

    malformed_event = pipeline.process_packet(MalformedPacket(), context)
    valid_packet = IP(src="203.0.113.1", dst="203.0.113.2") / UDP(
        sport=50000, dport=50001
    ) / Raw(b"ok")
    valid_packet.time = 1_700_000_001
    valid_event = pipeline.process_packet(valid_packet, context)

    assert malformed_event["packet_id"] == 1
    assert valid_event["packet_id"] == 2
    assert valid_event["status"] == "parsed"
    assert valid_event["transport"]["protocol"] == "UDP"
    assert valid_event["payload"]["data"] == "ok"
    assert valid_event["errors"] == []


def test_empty_transport_payload_is_normalized_without_error() -> None:
    packet = IP() / UDP(sport=50000, dport=50001)
    packet.time = 1_700_000_002

    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="live", source="Wi-Fi")
    )

    assert event["status"] == "parsed"
    assert event["application"]["protocol"] == "UNKNOWN"
    assert event["payload"] == {"length": 0, "encoding": None, "data": None}
    assert event["errors"] == []
