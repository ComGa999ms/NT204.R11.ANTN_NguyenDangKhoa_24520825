from __future__ import annotations

from scapy.layers.inet import IP, TCP

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def test_pipeline_assigns_ids_and_forwards_events() -> None:
    written_events: list[dict] = []
    pipeline = PacketPipeline(sink=written_events.append)
    context = CaptureContext(mode="pcap", source="sample.pcap")
    first_packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80)
    second_packet = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80)
    first_packet.time = 1_700_000_000
    second_packet.time = 1_700_000_001

    first_event = pipeline.process_packet(first_packet, context)
    second_event = pipeline.process_packet(second_packet, context)

    assert first_event["packet_id"] == 1
    assert second_event["packet_id"] == 2
    assert first_event["timestamp"] == "2023-11-14T22:13:20.000000Z"
    assert first_event["packet_length"] == len(bytes(first_packet))
    assert first_event["capture"] == {"mode": "pcap", "source": "sample.pcap"}
    assert first_event["network"]["source_ip"] == "10.0.0.1"
    assert first_event["network"]["destination_ip"] == "10.0.0.2"
    assert first_event["transport"]["protocol"] == "TCP"
    assert first_event["transport"]["flags"]["syn"] is True
    assert first_event["status"] == "parsed"
    assert written_events == [first_event, second_event]


class PacketWithoutMetadata:
    def __bytes__(self) -> bytes:
        raise ValueError("broken packet")


def test_pipeline_keeps_running_when_base_metadata_is_missing() -> None:
    pipeline = PacketPipeline()
    event = pipeline.process_packet(
        PacketWithoutMetadata(), CaptureContext(mode="live", source="eth0")
    )

    assert event["packet_length"] == 0
    assert event["status"] == "error"
    assert len(event["errors"]) == 2
