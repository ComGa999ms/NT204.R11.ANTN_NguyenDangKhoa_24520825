from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def test_t02_decodes_html_entities_while_preserving_raw_body() -> None:
    body = b"&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )
    packet = (
        IP(src="198.51.100.20", dst="192.0.2.10")
        / TCP(sport=8080, dport=50000, seq=100, flags="PA")
        / Raw(raw)
    )
    packet.time = 1_700_000_001

    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="pcap", source="assignment-2.pcap")
    )
    fields = event["application"]["fields"]

    assert fields["body"]["data"] == body.decode("ascii")
    assert fields["decoded_body"] == '<script>alert("x")</script>'
    assert "html_entity" in fields["decode_operations"]
    assert fields["decode_status"] == "decoded"
