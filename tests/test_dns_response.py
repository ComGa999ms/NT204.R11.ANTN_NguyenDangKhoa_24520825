from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.parsers.dns import parse_dns
from ids_parser.pipeline import PacketPipeline


def dns_response_bytes() -> bytes:
    return bytes(
        DNS(
            id=0x1234,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(
                rrname="example.com",
                type="A",
                ttl=60,
                rdata="203.0.113.7",
            ),
        )
    )


def test_parse_dns_response_with_answer() -> None:
    fields = parse_dns(dns_response_bytes(), "UDP")

    assert fields["message_type"] == "response"
    assert fields["rcode_name"] == "NOERROR"
    assert fields["flags"]["authoritative_answer"] is True
    assert fields["answers"] == [
        {
            "name": "example.com",
            "type": 1,
            "type_name": "A",
            "class": 1,
            "class_name": "IN",
            "ttl": 60,
            "data": "203.0.113.7",
        }
    ]


def test_pipeline_parses_udp_dns_response() -> None:
    packet = (
        IP(src="198.51.100.53", dst="192.0.2.1")
        / UDP(sport=53, dport=40000)
        / Raw(dns_response_bytes())
    )
    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="pcap", source="dns-response.pcap")
    )

    assert event["application"]["protocol"] == "DNS"
    assert event["application"]["fields"]["answers"][0]["data"] == "203.0.113.7"
    assert event["status"] == "parsed"


def test_malformed_dns_payload_does_not_crash_pipeline() -> None:
    packet = IP() / UDP(sport=53, dport=40000) / Raw(b"not-a-dns-message")

    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="live", source="Wi-Fi")
    )

    assert event["application"]["protocol"] == "UNKNOWN"
    assert event["transport"]["protocol"] == "UDP"


def test_large_tls_payload_is_not_dissected_as_dns() -> None:
    tls_like = b"\x17\x03\x03\x10\x00" + bytes(range(256)) * 50
    packet = IP() / TCP(sport=443, dport=50000, seq=1, flags="PA") / Raw(tls_like)

    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="live", source="Wi-Fi")
    )

    assert event["application"]["protocol"] == "UNKNOWN"
    assert event["errors"] == []
    assert event["status"] == "parsed"
