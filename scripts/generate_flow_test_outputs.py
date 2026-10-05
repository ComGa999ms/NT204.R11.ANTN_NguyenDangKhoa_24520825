"""Generate JSONL outputs for assignment 2 flow tracker test cases."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIRECTORY = PROJECT_ROOT / "src"
if str(SRC_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SRC_DIRECTORY))

from ids_parser.flow import FlowTracker, FlowTrackerConfig  # noqa: E402
from ids_parser.models import CaptureContext  # noqa: E402
from ids_parser.pipeline import PacketPipeline  # noqa: E402
from ids_parser.preprocessor import PreprocessConfig  # noqa: E402


TEST_DIRECTORY = PROJECT_ROOT / "TEST"


def _write_jsonl(path: Path, events: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            f"{json.dumps(event, ensure_ascii=False, separators=(',', ':'))}\n"
            for event in events
        ),
        encoding="utf-8",
    )


def _run_packets(
    packets: list[Packet],
    source: str,
    *,
    pipeline: PacketPipeline | None = None,
) -> list[dict[str, Any]]:
    pipeline = pipeline or PacketPipeline()
    context = CaptureContext(mode="pcap", source=source)
    events: list[dict[str, Any]] = []
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index
        events.append(pipeline.process_packet(packet, context))
    return events


def t07() -> list[dict[str, Any]]:
    return _run_packets(
        [
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=80, seq=100, flags="S"),
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=50000, seq=900, ack=101, flags="SA"),
        ],
        "t07-flow-id.pcap",
    )


def t08() -> list[dict[str, Any]]:
    return _run_packets(
        [
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=80, seq=100, flags="S"),
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=50000, seq=900, ack=101, flags="SA"),
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=80, seq=101, ack=901, flags="A"),
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=80, seq=101, ack=901, flags="FA"),
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=50000, seq=901, ack=102, flags="FA"),
        ],
        "t08-tcp-state.pcap",
    )


def t09() -> list[dict[str, Any]]:
    return _run_packets(
        [
            IP(src="192.0.2.10", dst="198.51.100.53")
            / UDP(sport=53000, dport=53)
            / Raw(b"query"),
            IP(src="198.51.100.53", dst="192.0.2.10")
            / UDP(sport=53, dport=53000)
            / Raw(b"answer"),
        ],
        "t09-udp-flow.pcap",
    )


def t10() -> list[dict[str, Any]]:
    return _run_packets(
        [
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=8080, seq=1, flags="PA")
            / Raw(b"hello"),
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=8080, dport=50000, seq=1, ack=6, flags="PA")
            / Raw(b"world!!"),
        ],
        "t10-flow-stats.pcap",
    )


def _timeout_event(
    packet_id: int,
    timestamp: str,
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
) -> dict[str, Any]:
    return {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "packet_length": 40,
        "network": {
            "protocol": "IPv4",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
        },
        "transport": {
            "protocol": "TCP",
            "source_port": source_port,
            "destination_port": destination_port,
            "payload_length": 0,
            "flags": {"syn": True, "ack": False},
        },
        "payload": {"length": 0, "encoding": None, "data": None},
        "processing_action": "process",
    }


def t11() -> list[dict[str, Any]]:
    tracker = FlowTracker(FlowTrackerConfig(idle_timeout_seconds=10))
    return [
        tracker.process(
            _timeout_event(
                1,
                "2024-01-01T00:00:00Z",
                "10.0.0.1",
                50000,
                "10.0.0.2",
                80,
            )
        ),
        tracker.process(
            _timeout_event(
                2,
                "2024-01-01T00:00:11Z",
                "10.0.0.3",
                50001,
                "10.0.0.4",
                443,
            )
        ),
    ]


def t12() -> list[dict[str, Any]]:
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=80, seq=100, flags="S"),
        IP(src="10.0.0.3", dst="10.0.0.4")
        / TCP(sport=50001, dport=443, seq=200, flags="S"),
    ]
    packets[0].time = 1_700_000_000
    packets[1].time = 1_700_000_010
    pipeline = PacketPipeline(flow_config=FlowTrackerConfig(idle_timeout_seconds=5))
    context = CaptureContext(mode="pcap", source="t12-flow-timeout.pcap")
    return [pipeline.process_packet(packet, context) for packet in packets]


def t13() -> list[dict[str, Any]]:
    tracker = FlowTracker()
    malformed = tracker.process(
        {
            "timestamp": "bad timestamp",
            "processing_action": "process",
            "network": None,
            "transport": {"protocol": "TCP"},
        }
    )
    pipeline = PacketPipeline(
        preprocess_config=PreprocessConfig(unsupported_policy="skip")
    )
    context = CaptureContext(mode="pcap", source="t13-skip-flow.pcap")
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
    return [
        malformed,
        pipeline.process_packet(unsupported_packet, context),
        pipeline.process_packet(valid_packet, context),
    ]


def main() -> int:
    TEST_DIRECTORY.mkdir(exist_ok=True)
    cases = {
        "t07-flow-bidirectional-id.jsonl": t07(),
        "t08-tcp-connection-states.jsonl": t08(),
        "t09-udp-flow-tracking.jsonl": t09(),
        "t10-flow-statistics.jsonl": t10(),
        "t11-flow-timeout-export.jsonl": t11(),
        "t12-pipeline-flow-metadata.jsonl": t12(),
        "t13-flow-error-handling.jsonl": t13(),
    }
    for filename, events in cases.items():
        _write_jsonl(TEST_DIRECTORY / filename, events)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
