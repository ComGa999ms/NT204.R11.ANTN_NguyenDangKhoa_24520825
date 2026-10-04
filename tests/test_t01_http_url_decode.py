from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def test_t01_decodes_http_url_and_form_while_preserving_raw_values() -> None:
    body = b"username=admin&query=%27+OR+1%3D1"
    raw = (
        b"POST /search?q=%27%20OR%201%3D1 HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )
    packet = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=8080, seq=100, flags="PA")
        / Raw(raw)
    )
    packet.time = 1_700_000_000

    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="pcap", source="assignment-2.pcap")
    )
    fields = event["application"]["fields"]

    assert fields["target"] == "/search?q=%27%20OR%201%3D1"
    assert fields["raw_target"] == fields["target"]
    assert fields["decoded_target"] == "/search?q=' OR 1=1"
    assert fields["decoded_query_parameters"] == {"q": ["' OR 1=1"]}
    assert fields["body"] == {
        "length": len(body),
        "encoding": "utf-8",
        "data": body.decode("ascii"),
    }
    assert fields["decoded_body"] == "username=admin&query=' OR 1=1"
    assert fields["decoded_form_fields"] == {
        "username": ["admin"],
        "query": ["' OR 1=1"],
    }
    assert fields["decode_status"] == "decoded"

