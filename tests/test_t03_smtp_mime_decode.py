from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


CONTEXT = CaptureContext(mode="pcap", source="assignment-2.pcap")


def _smtp_event(raw: bytes, source_port: int) -> dict:
    packet = (
        IP(src="192.0.2.10", dst="198.51.100.25")
        / TCP(sport=source_port, dport=2525, seq=100, flags="PA")
        / Raw(raw)
    )
    packet.time = 1_700_000_000 + source_port
    return PacketPipeline().process_packet(packet, CONTEXT)


def test_t03_decodes_smtp_base64_and_quoted_printable_bodies() -> None:
    base64_event = _smtp_event(
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=ascii\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"SGVsbG8gSURT\r\n.\r\n",
        50003,
    )
    quoted_printable_event = _smtp_event(
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        b"Xin ch=C3=A0o IDS\r\n.\r\n",
        50004,
    )

    base64_fields = base64_event["application"]["fields"]
    assert base64_fields["body"]["data"] == "SGVsbG8gSURT"
    assert base64_fields["decoded_body"] == {
        "length": 9,
        "encoding": "ascii",
        "data": "Hello IDS",
    }
    assert base64_fields["decode_status"] == "decoded"

    quoted_fields = quoted_printable_event["application"]["fields"]
    assert quoted_fields["decoded_body"]["encoding"] == "utf-8"
    assert quoted_fields["decoded_body"]["data"] == "Xin chào IDS"
    assert quoted_fields["decode_status"] == "decoded"
    assert base64_event["status"] == "parsed"
    assert quoted_printable_event["status"] == "parsed"

