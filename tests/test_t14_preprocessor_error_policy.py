from __future__ import annotations

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline
from ids_parser.preprocessor import EventPreprocessor, PreprocessConfig


def test_t14_preprocessor_marks_invalid_event_without_crashing() -> None:
    malformed = {
        "packet_id": 0,
        "timestamp": "not-a-time",
        "capture": {"mode": "pcap", "source": "bad.pcap"},
        "packet_length": -1,
        "network": {
            "protocol": "IPv4",
            "source_ip": "999.999.999.999",
            "destination_ip": "198.51.100.20",
        },
        "transport": {
            "protocol": "TCP",
            "source_port": 12345,
            "destination_port": 70000,
            "payload_length": 0,
            "flags": {"ack": True},
        },
        "application": {"protocol": "HTTP", "fields": {"headers": {}}},
        "payload": {"length": 1, "encoding": "hex", "data": "zz"},
        "status": "BROKEN",
        "errors": "parser returned a string by mistake",
    }

    normalized = EventPreprocessor().process(malformed)

    assert normalized["preprocess_status"] == "invalid"
    assert normalized["processing_action"] == "mark"
    assert "packet_id" in normalized["reason"]
    assert "timestamp" in normalized["reason"]
    assert "destination_port" in normalized["reason"]
    assert "payload.data" in normalized["reason"]
    assert normalized["errors"] == ["parser returned a string by mistake"]


def test_t14_invalid_policy_can_skip_invalid_event() -> None:
    normalized = EventPreprocessor(
        PreprocessConfig(invalid_policy="skip")
    ).process({"packet_id": "bad"})

    assert normalized["preprocess_status"] == "invalid"
    assert normalized["processing_action"] == "skip"


def test_t14_unsupported_policy_skips_sink_but_keeps_pipeline_running() -> None:
    written_events: list[dict] = []
    pipeline = PacketPipeline(
        sink=written_events.append,
        preprocess_config=PreprocessConfig(unsupported_policy="skip"),
    )
    context = CaptureContext(mode="pcap", source="unsupported.pcap")
    unsupported_packet = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / UDP(sport=40000, dport=40001)
        / Raw(b"\x01\x02\x03\x04")
    )
    valid_packet = IP(src="192.0.2.10", dst="198.51.100.20") / UDP(
        sport=40000,
        dport=40001,
    )
    unsupported_packet.time = 1_700_000_000
    valid_packet.time = 1_700_000_001

    skipped = pipeline.process_packet(unsupported_packet, context)
    kept = pipeline.process_packet(valid_packet, context)

    assert skipped["preprocess_status"] == "partial"
    assert skipped["processing_action"] == "skip"
    assert "unsupported application protocol" in skipped["reason"]
    assert kept["preprocess_status"] == "valid"
    assert kept["processing_action"] == "process"
    assert written_events == [kept]
