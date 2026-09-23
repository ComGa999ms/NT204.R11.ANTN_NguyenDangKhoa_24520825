from __future__ import annotations

import json
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from ids_parser import cli
from ids_parser.models import CaptureContext
from ids_parser.parsers.http import parse_http
from ids_parser.pipeline import PacketPipeline


def test_parse_http_get_request() -> None:
    raw = (
        b"GET /index.html?q=1 HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Accept: text/html\r\n"
        b"\r\n"
    )

    fields = parse_http(raw)

    assert fields["message_type"] == "request"
    assert fields["method"] == "GET"
    assert fields["target"] == "/index.html?q=1"
    assert fields["http_version"] == "HTTP/1.1"
    assert fields["host"] == "example.test"
    assert fields["headers"]["accept"] == ["text/html"]
    assert fields["headers_complete"] is True
    assert fields["body_complete"] is True


def test_pipeline_parses_http_get_on_non_standard_port() -> None:
    packet = (
        IP(src="192.0.2.1", dst="192.0.2.2")
        / TCP(sport=50000, dport=12345)
        / Raw(b"GET /demo HTTP/1.1\r\nHost: example.test\r\n\r\n")
    )
    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="pcap", source="http.pcap")
    )

    assert event["status"] == "parsed"
    assert event["application"]["protocol"] == "HTTP"
    assert event["application"]["fields"]["method"] == "GET"
    assert event["application"]["fields"]["host"] == "example.test"


def test_pcap_cli_writes_http_get_application_fields(tmp_path: Path) -> None:
    pcap_path = tmp_path / "http.pcap"
    output_path = tmp_path / "http.jsonl"
    packet = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=12345)
        / Raw(b"GET /demo HTTP/1.1\r\nHost: example.test\r\n\r\n")
    )
    wrpcap(str(pcap_path), [packet])

    assert cli.main(["--pcap", str(pcap_path), "--output", str(output_path)]) == 0

    event = json.loads(output_path.read_text(encoding="utf-8"))
    assert event["application"]["protocol"] == "HTTP"
    assert event["application"]["fields"]["method"] == "GET"
    assert event["application"]["fields"]["target"] == "/demo"
    assert event["status"] == "parsed"

