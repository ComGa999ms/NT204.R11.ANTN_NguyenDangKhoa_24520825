from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.parsers.smtp import parse_smtp
from ids_parser.pipeline import PacketPipeline


def test_parse_multiline_smtp_response() -> None:
    raw = b"250-mail.example Hello\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n"

    fields = parse_smtp(raw)

    assert fields["message_type"] == "response"
    assert fields["responses"] == [
        {"status_code": 250, "continuation": True, "message": "mail.example Hello"},
        {"status_code": 250, "continuation": True, "message": "SIZE 10240000"},
        {"status_code": 250, "continuation": False, "message": "STARTTLS"},
    ]


def test_pipeline_parses_smtp_response() -> None:
    packet = (
        IP(src="198.51.100.25", dst="192.0.2.10")
        / TCP(sport=25, dport=50000, seq=1)
        / Raw(b"220 mail.example ESMTP ready\r\n")
    )
    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="pcap", source="smtp.pcap")
    )

    assert event["application"]["protocol"] == "SMTP"
    assert event["application"]["fields"]["responses"][0]["status_code"] == 220
    assert event["status"] == "parsed"

