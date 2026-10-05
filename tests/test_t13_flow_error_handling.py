from __future__ import annotations

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from ids_parser.flow import FlowTracker
from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline
from ids_parser.preprocessor import PreprocessConfig


def test_t13_flow_tracker_ignores_events_without_valid_tuple() -> None:
    tracker = FlowTracker()

    malformed = tracker.process(
        {
            "timestamp": "bad timestamp",
            "processing_action": "process",
            "network": None,
            "transport": {"protocol": "TCP"},
        }
    )

    assert malformed["flow"] is None
    assert malformed["expired_flows"] == []
    assert tracker.active_count == 0


def test_t13_skipped_event_does_not_create_flow_or_stop_pipeline() -> None:
    written_events: list[dict] = []
    pipeline = PacketPipeline(
        sink=written_events.append,
        preprocess_config=PreprocessConfig(unsupported_policy="skip"),
    )
    context = CaptureContext(mode="pcap", source="skip-flow.pcap")
    unsupported_packet = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / UDP(sport=40000, dport=40001)
        / Raw(b"unsupported")
    )
    valid_packet = IP(src="192.0.2.10", dst="198.51.100.20") / UDP(
        sport=40000,
        dport=40001,
    )
    unsupported_packet.time = 1_700_000_000
    valid_packet.time = 1_700_000_001

    skipped = pipeline.process_packet(unsupported_packet, context)
    kept = pipeline.process_packet(valid_packet, context)

    assert skipped["processing_action"] == "skip"
    assert skipped["flow"] is None
    assert kept["processing_action"] == "process"
    assert kept["flow"]["packet_count"] == 1
    assert written_events == [kept]
