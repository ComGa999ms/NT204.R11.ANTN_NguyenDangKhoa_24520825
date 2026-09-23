from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.detector import detect_application
from ids_parser.models import CaptureContext
from ids_parser.parsers.payload import normalize_payload
from ids_parser.parsers.smtp import parse_smtp
from ids_parser.pipeline import PacketPipeline


def test_parse_smtp_commands() -> None:
    raw = (
        b"EHLO client.example\r\n"
        b"MAIL FROM:<sender@example.com>\r\n"
        b"RCPT TO:<recipient@example.net>\r\n"
    )

    fields = parse_smtp(raw)

    assert fields["message_type"] == "command"
    assert fields["commands"][0] == {
        "command": "EHLO",
        "argument": "client.example",
        "domain": "client.example",
    }
    assert fields["commands"][1]["path"] == "<sender@example.com>"
    assert fields["commands"][2]["path"] == "<recipient@example.net>"


def test_detect_smtp_command_on_non_standard_port() -> None:
    transport = {
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 12345,
    }

    assert detect_application(
        transport, normalize_payload(b"HELO client.example\r\n")
    ) == "SMTP"


def test_pipeline_reassembles_split_smtp_command() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="live", source="Wi-Fi")
    first_data = b"EH"
    second_data = b"LO client.example\r\n"

    first = pipeline.process_packet(
        IP() / TCP(sport=50000, dport=2525, seq=100, flags="PA") / Raw(first_data),
        context,
    )
    second = pipeline.process_packet(
        IP()
        / TCP(sport=50000, dport=2525, seq=100 + len(first_data), flags="PA")
        / Raw(second_data),
        context,
    )

    assert first["application"]["protocol"] == "UNKNOWN"
    assert second["application"]["protocol"] == "SMTP"
    assert second["application"]["fields"]["commands"][0]["command"] == "EHLO"
