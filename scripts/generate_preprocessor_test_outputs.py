"""Generate JSONL outputs for assignment 2 preprocessor test cases."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIRECTORY = PROJECT_ROOT / "src"
if str(SRC_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SRC_DIRECTORY))

from ids_parser.models import CaptureContext  # noqa: E402
from ids_parser.pipeline import PacketPipeline  # noqa: E402
from ids_parser.preprocessor import EventPreprocessor, PreprocessConfig  # noqa: E402


TEST_DIRECTORY = PROJECT_ROOT / "TEST"


def _write_jsonl(path: Path, events: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            f"{json.dumps(event, ensure_ascii=False, separators=(',', ':'))}\n"
            for event in events
        ),
        encoding="utf-8",
    )


def t05_event() -> dict[str, Any]:
    return {
        "packet_id": "1",
        "timestamp": "2024-01-02T03:04:05+07:00",
        "capture": {"mode": "PCAP", "source": " sample.pcap "},
        "packet_length": "128",
        "network": {
            "protocol": "ipv4",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
        },
        "transport": {
            "protocol": "tcp",
            "source_port": "49152",
            "destination_port": "80",
            "payload_length": "20",
            "flags": {"SYN": "0", "ACK": "true"},
        },
        "application": {
            "protocol": "http",
            "fields": {
                "message_type": "REQUEST",
                "method": "get",
                "target": "/A/%7euser/%2fkeep?Q=%41%2f%252e",
                "http_version": "http/1.1",
                "headers": {
                    "Host": "Example.COM.",
                    "Content-Type": "Text/HTML; Charset=UTF-8",
                    "Content-Length": "0",
                },
                "content_type": "Text/HTML; Charset=UTF-8",
                "content_length": "0",
                "body": {"length": 0, "encoding": None, "data": None},
                "headers_complete": "true",
                "body_complete": "true",
                "message_length": 20,
                "remaining_bytes": 0,
            },
        },
        "payload": {"length": 20, "encoding": "utf-8", "data": "GET / HTTP/1.1"},
        "status": "PARSED",
        "errors": [],
    }


def t06_events() -> list[dict[str, Any]]:
    return [
        {
            "packet_id": 1,
            "timestamp": "2024-01-02T03:04:05Z",
            "capture": {"mode": "pcap", "source": "missing-fields.pcap"},
            "packet_length": 54,
            "network": {
                "protocol": "IPv4",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
            },
            "transport": {
                "protocol": "TCP",
                "source_port": 50000,
                "destination_port": 80,
                "payload_length": 0,
                "flags": {"ack": True},
            },
            "application": {
                "protocol": "HTTP",
                "fields": {
                    "message_type": "request",
                    "method": "GET",
                    "target": "/",
                    "headers": {"Host": ["Example.COM."]},
                },
            },
            "payload": {"length": 0, "encoding": None, "data": None},
            "status": "partial",
            "errors": [],
        },
        {
            "packet_id": 2,
            "timestamp": "2024-01-02T03:04:06Z",
            "capture": {"mode": "pcap", "source": "missing-dns.pcap"},
            "packet_length": 70,
            "network": {
                "protocol": "IPv4",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.53",
            },
            "transport": {
                "protocol": "UDP",
                "source_port": 53000,
                "destination_port": 53,
                "payload_length": 28,
            },
            "application": {
                "protocol": "DNS",
                "fields": {"message_type": "query", "transaction_id": 1},
            },
            "payload": {"length": 28, "encoding": "hex", "data": "00" * 28},
            "status": "parsed",
            "errors": [],
        },
    ]


def t14_events() -> list[dict[str, Any]]:
    invalid = {
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
    skipped_events: list[dict[str, Any]] = []
    pipeline = PacketPipeline(
        sink=skipped_events.append,
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
    return [
        EventPreprocessor().process(invalid),
        EventPreprocessor(PreprocessConfig(invalid_policy="skip")).process(invalid),
        pipeline.process_packet(unsupported_packet, context),
        pipeline.process_packet(valid_packet, context),
    ]


def main() -> int:
    TEST_DIRECTORY.mkdir(exist_ok=True)
    _write_jsonl(
        TEST_DIRECTORY / "t05-preprocessor-normalization.jsonl",
        [EventPreprocessor().process(t05_event())],
    )
    _write_jsonl(
        TEST_DIRECTORY / "t06-preprocessor-missing-fields.jsonl",
        [EventPreprocessor().process(event) for event in t06_events()],
    )
    _write_jsonl(TEST_DIRECTORY / "t14-preprocessor-error-policy.jsonl", t14_events())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
